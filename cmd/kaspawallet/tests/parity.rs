//! Validation parity harness (Go vs Rust kaspawallet) -- offline
//! subset.
//!
//! Mirrors the spec's sec.6.10 harness contract. The full per-subcommand
//! matrix the Validator runs spans both an offline (no-kaspad) subset
//! and an online (tn-10 / simnet) subset that requires running daemons
//! and a live kaspad. This file lands the offline subset Implementor
//! can ship + verify in CI; the online subset is scaffolded as
//! `#[ignore]`-gated tests so the same module hosts the eventual full
//! matrix without a second cross-cutting reorganization.
//!
//! Subcommands actually exercisable in standalone-binary mode today
//! (per `cmd/kaspawallet/src/main.rs` -- the offline subset that the
//! binary's own `main` dispatches without daemon/coin-sel/sign
//! plumbing):
//!
//! - `version` -- both binaries print a one-line version banner; we
//!   normalize the version literal per sec.6.10.2 and compare framing.
//! - `parse` -- both binaries decode a Go-emitted unsigned PSTX hex
//!   plus a fixture keyfile and emit a plaintext transcript; spec
//!   says byte-identity holds (raw `cmp`).
//!
//! Subcommands that need the daemon-client wiring (or sign-flow) the
//! standalone CLI does not yet wire (`balance`, `show-addresses`,
//! `new-address`, `send`, `create-unsigned-transaction`, `broadcast`,
//! `sign`, `dump-unencrypted-data`, `sweep`, `start-daemon`'s gRPC
//! liveness probe, `create`) are scaffolded below as `#[ignore]`-gated
//! tests. Each carries the spec's normalization rule and the diff
//! invocation; the ignore lifts when the corresponding standalone
//! invocation is wired (sibling task or B7 tn-10).
//!
//! Skip semantics: when the Go binary is missing AND the default path
//! (`/home/dima/work/kaspa/kaspad/bin/kaspawallet`) does not resolve
//! to an executable file, EVERY parity test prints a one-line warning
//! and exits 0. This is "skip-with-warning" per sec.6.10.1; the Validator
//! treats a no-Go-binary closure as a HIGH-severity FINDING under
//! Mission sec.S4 (the AC explicitly demands Go-vs-Rust evidence on
//! tn-10), but the Implementor's harness is not the place to enforce
//! that policy -- the closure-report attestation is.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Default path to the Go `kaspawallet` binary on the lead's
/// workstation. Overridable via the `KASPAWALLET_GO_BIN` env var
/// (see sec.6.10.1). Recorded here as the canonical fallback so a
/// fresh checkout can run the parity tests without env-var setup.
const DEFAULT_GO_BIN: &str = "/home/dima/work/kaspa/kaspad/bin/kaspawallet";

/// Environment variable the Validator (or developer) sets to point
/// the harness at a non-default Go binary build. Mirrors sec.6.10.1.
const ENV_GO_BIN: &str = "KASPAWALLET_GO_BIN";

/// Environment variable the Validator (or developer) sets to point
/// the harness at a non-default Rust binary build. Defaults to the
/// workspace `target/debug/kaspawallet` resolved from `CARGO_TARGET_DIR`
/// (or the workspace's default `target/`).
const ENV_RUST_BIN: &str = "KASPAWALLET_RUST_BIN";

/// Path to the singlekey fixture keyfile committed under
/// `cmd/kaspawallet/tests/fixtures/`. Both `parse` and the future
/// daemon-client-driven `show-addresses` parity tests consume it.
fn fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    p
}

/// Resolve the Go-binary path. Returns `None` when neither the env
/// override nor the default path points at an executable file --
/// callers print the skip-with-warning line and exit 0.
fn locate_go_binary() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var(ENV_GO_BIN) {
        let candidate = PathBuf::from(env_path);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    let default = PathBuf::from(DEFAULT_GO_BIN);
    if is_executable_file(&default) {
        return Some(default);
    }
    None
}

/// Resolve the Rust-binary path. Defaults to
/// `<CARGO_TARGET_DIR or workspace target>/debug/kaspawallet` --
/// matches what `cargo test` produces in the same workspace pass.
fn locate_rust_binary() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var(ENV_RUST_BIN) {
        let candidate = PathBuf::from(env_path);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    let target_dir = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| {
        let mut workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // CARGO_MANIFEST_DIR is .../cmd/kaspawallet; the workspace
        // root is two levels up.
        workspace_root.pop();
        workspace_root.pop();
        workspace_root.push("target");
        workspace_root
    });
    let mut candidate = target_dir;
    candidate.push("debug");
    candidate.push("kaspawallet");
    if is_executable_file(&candidate) { Some(candidate) } else { None }
}

fn is_executable_file(path: &Path) -> bool {
    // Cross-platform "this is a regular file we can run". The
    // executable-bit check is Unix-only; on Windows we rely on the
    // file-extension matching `.exe`. The harness runs on the
    // Linux primary (per sec.6.12.4) so the Unix branch is the
    // load-bearing path; the Windows branch keeps the helper
    // syntactically reachable on the cross-compile.
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(meta) => meta.permissions().mode() & 0o111 != 0,
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
    }
}

/// Acquire (go_bin, rust_bin) or skip the test with a warning. The
/// returned `Option` is `Some` only when both binaries resolve;
/// otherwise the caller logs the skip-with-warning per sec.6.10.1 and
/// returns early so the test passes (`exit 0`).
fn resolve_binaries(test_name: &str) -> Option<(PathBuf, PathBuf)> {
    let go = match locate_go_binary() {
        Some(p) => p,
        None => {
            eprintln!(
                "parity::{test_name}: SKIPPED -- Go binary not found. Set {ENV_GO_BIN} or place the binary at {DEFAULT_GO_BIN}."
            );
            return None;
        }
    };
    let rust = match locate_rust_binary() {
        Some(p) => p,
        None => {
            eprintln!(
                "parity::{test_name}: SKIPPED -- Rust binary not found. Run `cargo build --bin kaspawallet` first or set {ENV_RUST_BIN}."
            );
            return None;
        }
    };
    Some((go, rust))
}

/// Capture stdout + stderr from a binary invocation as a single
/// byte stream. Mirrors the Go reference's `2>&1` semantics so
/// the parity diff covers both streams. Panics on process-spawn
/// failure (the test should fail loudly when the binary path
/// resolved but cannot be exec'd).
fn run_capture(bin: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new(bin).args(args).output().expect("process spawn");
    let mut combined = output.stdout;
    combined.extend_from_slice(&output.stderr);
    combined
}

/// Apply the sec.6.10.2 `version` normalization rule to a captured
/// version banner. Both Go (`kaspawallet version 0.12.22`) and
/// Rust (`kaspawallet v1.1.0`) collapse to a common prefix
/// `kaspawallet <NORM>` so the framing diff exercises the wire
/// shape without coupling to the binary's build metadata.
fn normalize_version_banner(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim_end_matches(['\r', '\n']);
    // Strip every word after the first (`kaspawallet`); the rest
    // is build metadata that differs between binaries.
    let after_first_word = trimmed.split_whitespace().next().unwrap_or("");
    format!("{after_first_word} <NORM>")
}

#[test]
fn version_framing_parity() {
    let Some((go, rust)) = resolve_binaries("version_framing_parity") else {
        return;
    };
    let go_out = run_capture(&go, &["version"]);
    let rust_out = run_capture(&rust, &["version"]);
    let go_norm = normalize_version_banner(&go_out);
    let rust_norm = normalize_version_banner(&rust_out);
    assert_eq!(go_norm, rust_norm, "version banner framing diverges between Go and Rust binaries");
    assert_eq!(go_norm, "kaspawallet <NORM>", "framing prefix unexpectedly missing from normalized output");
}

#[test]
fn parse_offline_byte_identity() {
    let Some((go, rust)) = resolve_binaries("parse_offline_byte_identity") else {
        return;
    };
    let pstx_path = fixture("go_emitted_pst.hex");
    let pstx_hex = std::fs::read_to_string(&pstx_path).expect("read pstx fixture");
    let pstx_hex = pstx_hex.trim();
    let keys_path = fixture("legacy_go_v1_singlekey.json");
    let keys_arg = keys_path.to_str().expect("ascii path");

    let go_out = run_capture(&go, &["parse", "--keys-file", keys_arg, "--transaction", pstx_hex]);
    let rust_out = run_capture(&rust, &["parse", "--keys-file", keys_arg, "--transaction", pstx_hex]);
    assert_eq!(
        go_out,
        rust_out,
        "parse output diverges between Go and Rust binaries (Go {} bytes vs Rust {} bytes)",
        go_out.len(),
        rust_out.len()
    );
}

// --------------------------------------------------------------
// Scaffolded parity tests for subcommands the standalone CLI does
// not yet wire (daemon-client / sign / coin-selection paths). Each
// carries the sec.6.10.2 normalization-rule comment and a
// `#[ignore = "..."]` reason so `cargo nextest run --ignored` (or
// `cargo test -- --ignored`) lists them. The Validator un-ignores
// these as the corresponding wiring lands (sibling cycle or B7
// tn-10) and re-runs the harness against the live binaries.
// --------------------------------------------------------------

#[test]
#[ignore = "needs daemon-spawn topology + tn-10 funded wallet; standalone CLI daemon-client wiring landed in dispatch::run_show_addresses, but the harness needs two daemons against one kaspad to compare outputs"]
fn show_addresses_byte_identity() {
    // sec.6.10.2 row `show-addresses`: byte-identical, raw cmp. Two
    // daemons (Go + Rust) on parallel ports against the same
    // kaspad; client-side `show-addresses` against each.
    unreachable!("scaffold");
}

#[test]
#[ignore = "needs daemon-spawn topology + tn-10 funded wallet; standalone CLI daemon-client wiring landed in dispatch::run_new_address, but the harness needs two daemons against one kaspad with controlled keyfile post-state for the jq-normalized cmp"]
fn new_address_byte_identity_with_jq_keyfile_normalize() {
    // sec.6.10.2 row `new-address`: address line raw cmp; keyfile
    // post-state through `jq -S` then cmp.
    unreachable!("scaffold");
}

#[test]
#[ignore = "needs daemon-spawn topology + tn-10 funded wallet; standalone CLI daemon-client wiring landed in dispatch::run_balance, but the harness needs two daemons against one kaspad with deterministic UTXO snapshot for the cmp"]
fn balance_byte_identity_with_retry() {
    // sec.6.10.2 row `balance`: track-I deterministic snapshot raw
    // cmp; track-II parallel-daemon-read with up-to-3x retry on
    // mid-frame block drift, then cmp on the latest stable pair.
    unreachable!("scaffold");
}

#[test]
#[ignore = "needs daemon-spawn topology + tn-10 funded wallet; standalone CLI daemon-client wiring + sign-flow landed in dispatch::run_send, but the harness needs two daemons against one kaspad with a funded single-UTXO wallet for the signed-tx-hex + tx-ID cmp"]
fn send_byte_identity_single_utxo() {
    // sec.6.10.2 row `send`: byte-identical signed tx hex + tx ID
    // under Path A coin selection + Schnorr deterministic.
    unreachable!("scaffold");
}

#[test]
#[ignore = "needs daemon-spawn topology + tn-10 funded wallet; standalone CLI daemon-client wiring + sign-flow landed in dispatch::run_create_unsigned_transaction, but the harness needs two daemons against one kaspad for the Path-A coin-selected hex cmp"]
fn create_unsigned_byte_identity() {
    // sec.6.10.2 row `create-unsigned-transaction`: byte-identical
    // hex under Path A coin selection.
    unreachable!("scaffold");
}

#[test]
#[ignore = "needs an unsigned-ECDSA PSTX fixture paired with the ECDSA singlekey keyfile; standalone CLI sign is now wired and exercised by the dump-unencrypted-data row + the in-crate sign-module ECDSA RFC-6979 byte-identity unit test, but a Go-vs-Rust binary-level cmp requires the matching unsigned input that fixturegen has not produced yet"]
fn sign_ecdsa_byte_identity_and_schnorr_validity() {
    // sec.6.10.2 row `sign`:
    // - Schnorr (BIP-340): sig BYTES non-deterministic; verify
    //   under the cosigner's derived x-only pubkey instead.
    // - ECDSA (RFC 6979): sig BYTES byte-identical; raw cmp.
    unreachable!("scaffold");
}

#[test]
#[ignore = "needs daemon-spawn topology + tn-10 funded wallet; standalone CLI daemon-client wiring landed in dispatch::run_broadcast, but the harness needs two daemons against one kaspad with a pre-signed tx for the tx-ID-list cmp"]
fn broadcast_byte_identity() {
    // sec.6.10.2 row `broadcast`: byte-identical tx ID list.
    unreachable!("scaffold");
}

#[test]
fn dump_unencrypted_data_byte_identity() {
    // sec.6.10.2 row `dump-unencrypted-data`: byte-identical, raw cmp.
    // Both binaries take the legacy Go-format singlekey fixture, decrypt
    // with the canonical fixture passphrase, and dump mnemonic +
    // extended-public-key + minimum-signatures lines. The output is
    // deterministic on the same input (no salt/nonce in the
    // plaintext dump path) so a raw cmp is the right verifier.
    let Some((go, rust)) = resolve_binaries("dump_unencrypted_data_byte_identity") else {
        return;
    };
    let keys_path = fixture("legacy_go_v1_singlekey.json");
    let keys_arg = keys_path.to_str().expect("ascii path");
    let go_out = run_capture(
        &go,
        &["--testnet", "dump-unencrypted-data", "--keys-file", keys_arg, "--password", "test fixture passphrase", "--yes"],
    );
    let rust_out = run_capture(
        &rust,
        &["--testnet", "dump-unencrypted-data", "--keys-file", keys_arg, "--password", "test fixture passphrase", "--yes"],
    );
    assert_eq!(
        go_out,
        rust_out,
        "dump-unencrypted-data output diverges between Go and Rust binaries (Go {} bytes vs Rust {} bytes)\nGo: {}\nRust: {}",
        go_out.len(),
        rust_out.len(),
        String::from_utf8_lossy(&go_out),
        String::from_utf8_lossy(&rust_out),
    );
}

#[test]
#[ignore = "needs daemon-spawn topology + tn-10; un-ignore for B7 tn-10 closure run"]
fn daemon_grpc_liveness_parity() {
    // sec.6.10.2 row `start-daemon`: gRPC liveness probe on both
    // daemons within the 5-second startup window; no cmp.
    unreachable!("scaffold");
}

#[test]
#[ignore = "sec.3.5.1 cross-wallet multisig MUST; needs sign + broadcast wiring + tn-10; un-ignore for B7 tn-10 closure"]
fn cross_wallet_multisig_2of3_both_directions() {
    // sec.6.10.3: Go-create -> Rust-sign -> Go-sign -> broadcast,
    // and the reverse Rust-create -> Go-sign -> Rust-sign ->
    // broadcast. Envelope bytes raw cmp at every handoff;
    // Schnorr-sig positions verify_schnorr; ECDSA-sig positions
    // raw cmp.
    unreachable!("scaffold");
}

#[test]
#[ignore = "sec.3.5.1 cross-wallet multisig MUST (3-of-5); needs sign + broadcast wiring + tn-10; un-ignore for B7 closure"]
fn cross_wallet_multisig_3of5_both_directions() {
    // sec.6.10.3: longer alternating cosigner-handoff chain. Same
    // diff rules as the 2-of-3 case.
    unreachable!("scaffold");
}
