//! `version` subcommand. Prints the binary's semantic version on
//! its own line.

/// Compile-time version pulled from the crate's `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Print the binary's version line on stdout in the form
/// `kaspawallet v<semver>`.
pub fn print() {
    println!("kaspawallet v{VERSION}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_matches_pkg_semver() {
        // Sanity-check: the framing regex from the parity matrix
        // (`^kaspawallet v\d+\.\d+\.\d+(\S*)?\s*$`) must accept
        // our version line.
        let line = format!("kaspawallet v{VERSION}");
        let re = regex_lite_match(&line);
        assert!(re, "version line failed framing match: {line:?}");
    }

    // Minimal regex-lite check kept dependency-free: the spec
    // regex is anchored, prefixed with the literal `kaspawallet v`,
    // followed by three dot-separated numeric components and an
    // optional non-whitespace tail. A regex crate is overkill for
    // this single shape.
    fn regex_lite_match(s: &str) -> bool {
        let Some(rest) = s.strip_prefix("kaspawallet v") else { return false };
        let rest = rest.trim_end();
        let mut parts = rest.split('.');
        let major = parts.next();
        let minor = parts.next();
        let patch_and_tail = parts.next();
        if major.is_none() || minor.is_none() || patch_and_tail.is_none() || parts.next().is_some() {
            return false;
        }
        if !major.unwrap().bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if !minor.unwrap().bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        let patch = patch_and_tail.unwrap();
        let mut digits = 0usize;
        for b in patch.bytes() {
            if b.is_ascii_digit() {
                digits += 1;
            } else {
                break;
            }
        }
        digits > 0
    }
}
