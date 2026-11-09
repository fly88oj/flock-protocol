//! showroom compatibility utility surface (docs/design.md §1.3.2
//! "utilities" list).
//!
//! When showroom migrates to thin re-exports over this crate, the following
//! former showroom-common pub items are preserved verbatim (signatures
//! byte-for-byte unchanged, showroom-analysis §2):
//! - [`Result`]: alias for `Result<T, Box<dyn Error>>` (the uniform error
//!   for key-file read/write/parse-style operations);
//! - [`write_private`]: 0600 persistence (tightens overly permissive
//!   permissions of pre-existing files), parent directories created lazily —
//!   unix-only (wasm32 has no filesystem semantics; the Windows native
//!   target has no POSIX permission bits, so it is not provided);
//! - [`names`]: name validation for projects / auxiliary names / docker
//!   tags (showroom SPEC §4 + §11 v1.4).
//!
//! Version discipline (§1.2): this module is part of the protocol
//! library's compatibility surface with a single implementation source —
//! showroom-common re-exports it and no longer carries its own copy.

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::path::Path;

/// showroom compatibility error alias: the uniform error for key-file
/// read/write/parse-style operations (seal/open use `std::io::Result`
/// separately; verify uses `AuthError`).
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// 0600 persistence (tightens overly permissive permissions of pre-existing
/// files), parent directories created lazily. All credential/key files go
/// through here.
///
/// Platform boundary: unix-only (POSIX permission bits); wasm32 has no
/// filesystem semantics and native Windows has no 0600 semantics.
#[cfg(unix)]
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    // Tighten possibly overly permissive old permissions on existing files
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

// ———— Name validation (showroom SPEC §4 + §11 v1.4: relaxed project regex,
// random project names; auxiliary names keep the old regex) ————

pub mod names {
    /// Project regex (§11 relaxation): `^[a-zA-Z0-9][a-zA-Z0-9-]{0,30}$`
    /// (total length 1..=31, ASCII, hand-written to avoid a regex
    /// dependency). Allowing uppercase enlarges the random-name space
    /// (62^8) and raises the bar for dictionary walks.
    pub fn valid_project(s: &str) -> bool {
        let b = s.as_bytes();
        !b.is_empty()
            && b.len() <= 31
            && b[0].is_ascii_alphanumeric()
            && b.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-')
    }

    /// Auxiliary names (user etc.) keep the old regex:
    /// `^[a-z0-9][a-z0-9-]{0,30}$`. user flows into registry image paths
    /// and htpasswd, so it stays lowercase (docker repository names forbid
    /// uppercase).
    pub fn valid_aux(s: &str) -> bool {
        let b = s.as_bytes();
        !b.is_empty()
            && b.len() <= 31
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter()
                .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    }

    /// docker tag rules: first char [A-Za-z0-9_], the rest [A-Za-z0-9_.-],
    /// total length <=128.
    pub fn valid_tag(s: &str) -> bool {
        let b = s.as_bytes();
        !b.is_empty()
            && b.len() <= 128
            && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
            && b.iter()
                .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
    }

    pub const RESERVED: [&str; 4] = ["v2", "_api", "_bootstrap", "_console"];

    /// Auxiliary names (user etc.): regex only (reserved names do not
    /// apply).
    pub fn check_aux(s: &str) -> Result<(), String> {
        if valid_aux(s) {
            Ok(())
        } else {
            Err(format!(
                "invalid name '{s}': must match ^[a-z0-9][a-z0-9-]{{0,30}}$"
            ))
        }
    }

    /// project = §11 relaxed regex + reserved names.
    pub fn check_project(s: &str) -> Result<(), String> {
        if !valid_project(s) {
            return Err(format!(
                "invalid project '{s}': must match ^[a-zA-Z0-9][a-zA-Z0-9-]{{0,30}}$"
            ));
        }
        if RESERVED.contains(&s) {
            return Err(format!("project '{s}' is a reserved name"));
        }
        Ok(())
    }

    /// Random project name (§11 publish-entry default prefill):
    /// `[a-zA-Z0-9]{8}`.
    pub fn random_project() -> String {
        use rand::distr::Alphanumeric;
        use rand::Rng;
        rand::rng()
            .sample_iter(Alphanumeric)
            .take(8)
            .map(char::from)
            .collect()
    }

    pub fn check_tag(s: &str) -> Result<(), String> {
        if valid_tag(s) {
            Ok(())
        } else {
            Err(format!(
                "invalid tag '{s}': first char alphanumeric/_, only [A-Za-z0-9_.-] allowed, <=128 chars"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Name rules (SPEC §4 + §11 v1.4, ported from showroom lib.rs tests):
    /// project relaxed regex (uppercase/hyphen) + reserved names; auxiliary
    /// names (user etc.) keep the old lowercase regex. Tag rules unchanged.
    #[test]
    fn names_project_regex_relaxed_and_reserved() {
        assert!(names::check_project("demo").is_ok());
        assert!(
            names::check_project("Demo42").is_ok(),
            "§11 relaxation: uppercase is legal"
        );
        assert!(names::check_project("A-b-9").is_ok());
        assert!(names::check_project("0").is_ok());
        assert!(names::check_project(&"a".repeat(31)).is_ok());
        for r in names::RESERVED {
            assert!(
                names::check_project(r).is_err(),
                "reserved project names must be rejected: {r}"
            );
        }
        for bad in [
            "",
            "-a",
            "a_b",
            "a b",
            "a.b",
            "a/b",
            "café",
            &_c(32),
            "_x",
            "-demo",
        ] {
            assert!(
                names::check_project(bad).is_err(),
                "project must be rejected: {bad}"
            );
        }
        // Auxiliary names: old lowercase regex (user flows into registry
        // paths, so the lowercase constraint stays)
        assert!(names::check_aux("alice-2").is_ok());
        assert!(names::check_aux("pr42").is_ok());
        assert!(
            names::check_aux("v2").is_ok(),
            "auxiliary names are not bound by reserved names"
        );
        for bad in ["", "-a", "Aa", "a_", "a b", "a.b", "a/b", "café", &_c(32)] {
            assert!(
                names::check_aux(bad).is_err(),
                "auxiliary name must be rejected: {bad}"
            );
        }
        for t in ["v1", "1.0.0", "latest", "a_b.c-d", "0", &"a".repeat(128)] {
            assert!(names::check_tag(t).is_ok(), "tag must be legal: {t}");
        }
        for t in ["", ".x", "-x", "a b", "a/b", "é", &"a".repeat(129)] {
            assert!(names::check_tag(t).is_err(), "tag must be rejected: {t}");
        }
    }

    fn _c(n: usize) -> String {
        "a".repeat(n)
    }

    // Random project name (§11 publish-entry default prefill): always 8
    // chars, charset [A-Za-z0-9], samples differ from each other
    #[test]
    fn random_project_shape() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let p = names::random_project();
            assert_eq!(p.len(), 8, "length is always 8");
            assert!(
                p.bytes().all(|b| b.is_ascii_alphanumeric()),
                "charset [a-zA-Z0-9]: {p}"
            );
            assert!(
                names::check_project(&p).is_ok(),
                "random names must pass project validation"
            );
            seen.insert(p);
        }
        // 62^8 space: 64 samples must contain a differing pair (collision
        // probability ~1e-11)
        assert!(
            seen.len() > 1,
            "randomness: 64 samples produced {}/64 distinct names",
            seen.len()
        );
    }

    // write_private: 0600, contents, tightening after covering overly
    // permissive permissions (unix platform)
    #[cfg(unix)]
    #[test]
    fn write_private_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("flock-compat-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("priv.bin");
        write_private(&p, b"secret").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"secret");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&p, b"again").unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Parent directories created lazily
        let nested = dir.join("a/b/c.txt");
        write_private(&nested, b"x").unwrap();
        assert_eq!(fs::read(&nested).unwrap(), b"x");
        let _ = fs::remove_dir_all(&dir);
    }
}
