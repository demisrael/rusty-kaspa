//! Generate Rust message + service types from the vendored proto files.
//!
//! `wallet.proto` carries the on-disk / on-wire partial-signed-transaction
//! schema and ships as messages-only -- the consumer is the in-process
//! serialization layer, not a transport. `kaspawalletd.proto` defines the
//! daemon gRPC service surface; this build emits both server and client
//! stubs so the daemon binary can host the service and client subcommands
//! can dial it.

fn main() {
    let walletpst_proto = "./proto/wallet.proto";
    let daemon_proto = "./proto/kaspawalletd.proto";
    let proto_dir = "./proto";

    tonic_prost_build::configure()
        .build_server(false)
        .build_client(false)
        .compile_protos(&[walletpst_proto], &[proto_dir])
        .unwrap_or_else(|e| panic!("protobuf compile error (wallet.proto): {e}"));

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[daemon_proto], &[proto_dir])
        .unwrap_or_else(|e| panic!("protobuf compile error (kaspawalletd.proto): {e}"));

    println!("cargo:rerun-if-changed={walletpst_proto}");
    println!("cargo:rerun-if-changed={daemon_proto}");
}
