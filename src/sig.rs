//! SR-SIG1 request signing + key profiles (docs/design.md §1.3.2
//! compatibility surface / §1.3.3g / §3.3, P2-12).
//!
//! Compatibility contract (showroom-common lib.rs:222-340, byte-for-byte
//! unchanged, §1.3.2):
//! - canonical seven fields: `SR-SIG1\n<user>\n<ts>\n<nonce>\n<METHOD>\n<path_with_query>\n<sha256_hex(body)>`;
//! - wire format: `SR-SIG1 <user>:<ts>:<nonce>:<sig_b64url>` (sig is
//!   base64url without padding);
//! - [`SIG_WINDOW_SECS`] = 300 (showroom-common lib.rs:48 original value).
//!
//! This module interoperates byte-for-byte with the showroom 3.0
//! ecosystem's Ed25519 signatures (RFC 8032 deterministic signing); the
//! dependency generation is upgraded ed25519-dalek 2.2 → 3.0 (§1.3.2,
//! P1-6).
//!
//! Upgrade tier (§1.3.3g): [`KeyProfile`] dispatches the verification
//! algorithm by kid — Ed25519 as the primary tier plus an ML-DSA-65 slot
//! under the `pq-sign` feature (placeholder; ml-dsa 0.1.1 is unaudited,
//! crypto-2026 §5).

use core::fmt;

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::engine::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::KEY_LEN;

/// SR-SIG1 timestamp tolerance: |now − ts| ≤ 300s (§1.3.2, showroom-common
/// lib.rs:48 original value preserved).
pub const SIG_WINDOW_SECS: i64 = 300;

/// `sha256_hex`: 32B digest → 64 lowercase hex chars.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Streaming sha256 (64KiB buffer): hash large files first, then sign
/// (`sign_prehashed`), avoiding loading whole files into memory (same
/// semantics as showroom-common lib.rs:62-72).
pub fn sha256_hex_stream(mut r: impl std::io::Read) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Ok(hex::encode(h.finalize()));
        }
        h.update(&buf[..n]);
    }
}

/// SR-SIG1 nonce: 16 random bytes → 32 hex chars (P2-13: the
/// implementation is authoritative — 16B/32hex).
pub fn nonce_hex() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b); // rand 0.9 ThreadRng (infallible RngCore)
    hex::encode(b)
}

// ———— SR-SIG1 five functions (§1.3.2 compatibility surface, signatures
// unchanged) ————

/// Ed25519 user signing key (counterpart of showroom `UserKey`).
pub struct UserKey(SigningKey);

impl UserKey {
    /// Generate randomly (seeded from rand 0.9 ThreadRng).
    pub fn generate() -> Self {
        let mut seed = [0u8; KEY_LEN];
        rand::rng().fill_bytes(&mut seed);
        UserKey(SigningKey::from_bytes(&seed))
    }

    /// Construct from a raw 32B seed (the showroom `id_ed25519` file
    /// format; file I/O is the caller's responsibility — the 0600
    /// persistence utility belongs to the native platform layer and joins
    /// the compatibility surface in a later batch).
    pub fn from_seed(seed: &[u8; KEY_LEN]) -> Self {
        UserKey(SigningKey::from_bytes(seed))
    }

    /// Raw 32B seed.
    pub fn to_seed(&self) -> [u8; KEY_LEN] {
        self.0.to_bytes()
    }

    /// Read a raw 32B seed file (the format written by
    /// [`UserKey::save_seed`]; showroom `id_ed25519`).
    pub fn from_seed_file(path: &std::path::Path) -> crate::compat::Result<Self> {
        let seed = std::fs::read(path)?;
        let seed: [u8; KEY_LEN] = seed.as_slice().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "seed file must be exactly 32 bytes",
            )
        })?;
        Ok(UserKey(SigningKey::from_bytes(&seed)))
    }

    /// Write the raw 32B seed (0600; unix-only — wasm32 has no filesystem
    /// semantics).
    #[cfg(unix)]
    pub fn save_seed(&self, path: &std::path::Path) -> crate::compat::Result<()> {
        crate::compat::write_private(path, &self.0.to_bytes())?;
        Ok(())
    }

    /// `"ed25519:<base64(pubkey)>"` (base64 without padding; byte-for-byte
    /// the showroom format).
    pub fn pub_string(&self) -> String {
        format!(
            "ed25519:{}",
            STANDARD_NO_PAD.encode(self.0.verifying_key().as_bytes())
        )
    }

    /// Parse `"ed25519:<base64(pubkey)>"` (same format as showroom). Error
    /// type = `Box<dyn Error>` (§1.3.2 compatibility surface signature
    /// unchanged: showroom originally returned `Result<VerifyingKey>`,
    /// i.e. `Result<_, Box<dyn Error>>`).
    pub fn from_pub_string(s: &str) -> crate::compat::Result<VerifyingKey> {
        let raw = STANDARD_NO_PAD.decode(
            s.strip_prefix("ed25519:")
                .ok_or("missing ed25519: prefix")?,
        )?;
        let raw: [u8; KEY_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| "public key must be exactly 32 bytes")?;
        Ok(VerifyingKey::from_bytes(&raw)?)
    }
}

impl fmt::Debug for UserKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserKey(ed25519:…)") // do not leak key material
    }
}

/// Canonical seven fields:
/// `SR-SIG1\n<user>\n<ts>\n<nonce>\n<METHOD>\n<path_with_query>\n<sha256_hex(body)>`
/// (showroom-common lib.rs:222-231, byte-for-byte unchanged).
#[allow(clippy::too_many_arguments)]
pub fn build_canonical(
    user: &str,
    ts: i64,
    nonce: &str,
    method: &str,
    path_with_query: &str,
    body_sha256_hex: &str,
) -> String {
    format!("SR-SIG1\n{user}\n{ts}\n{nonce}\n{method}\n{path_with_query}\n{body_sha256_hex}")
}

/// Produce the complete Authorization value `SR-SIG1
/// <user>:<ts>:<nonce>:<sig_b64url>` (sig is base64url without padding;
/// the nonce is generated by the caller — `nonce_hex`; pass method
/// uppercase).
pub fn sign(
    user: &str,
    key: &UserKey,
    method: &str,
    path_with_query: &str,
    body: &[u8],
    now_unix: i64,
    nonce: &str,
) -> String {
    sign_prehashed(
        user,
        key,
        method,
        path_with_query,
        &sha256_hex(body),
        now_unix,
        nonce,
    )
}

/// Pre-hashed signing: the body hash is already computed by the caller
/// (`sha256_hex` / `sha256_hex_stream`); same format as [`sign`] — hash
/// large streaming uploads first, then sign, avoiding loading whole files
/// into memory.
pub fn sign_prehashed(
    user: &str,
    key: &UserKey,
    method: &str,
    path_with_query: &str,
    body_sha256_hex: &str,
    ts: i64,
    nonce: &str,
) -> String {
    let canonical = build_canonical(user, ts, nonce, method, path_with_query, body_sha256_hex);
    let sig = key.0.sign(canonical.as_bytes()).to_bytes();
    format!(
        "SR-SIG1 {user}:{ts}:{nonce}:{}",
        URL_SAFE_NO_PAD.encode(sig)
    )
}

/// Successful verification result: the matched identity plus
/// timestamp/nonce (nonce deduplication is done by the caller using
/// `Verified.nonce`; §1.3.2 "deliberately left to the caller" boundary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub user: String,
    pub ts: i64,
    pub nonce: String,
}

/// SR-SIG1 verification error (showroom's three states preserved verbatim:
/// Format/Stale/BadSignature).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    Format,
    Stale,
    BadSignature,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AuthError::Format => "E_AUTH: malformed SR-SIG1 header",
            AuthError::Stale => "E_AUTH: timestamp outside ±300s window",
            AuthError::BadSignature => "E_AUTH: signature verification failed",
        })
    }
}

impl std::error::Error for AuthError {}

/// Verify SR-SIG1: format parsing → ±300s time window → try each
/// registered public key in turn (a user may have several; any hit
/// passes).
pub fn verify(
    auth_value: &str,
    pubkeys: &[VerifyingKey],
    method: &str,
    path_with_query: &str,
    body: &[u8],
    now_unix: i64,
) -> Result<Verified, AuthError> {
    verify_with_hash(
        auth_value,
        pubkeys,
        method,
        path_with_query,
        &sha256_hex(body),
        now_unix,
    )
}

/// Pre-computed-hash verification: exactly the same semantics as
/// [`verify`] (format → ±300s → any registered key hits); accepts only
/// `sha256_hex` for the body — for callers like import that only persist +
/// hash and never keep the body itself.
pub fn verify_with_hash(
    auth_value: &str,
    pubkeys: &[VerifyingKey],
    method: &str,
    path_q: &str,
    body_sha_hex: &str,
    now: i64,
) -> Result<Verified, AuthError> {
    let rest = auth_value
        .strip_prefix("SR-SIG1 ")
        .ok_or(AuthError::Format)?;
    let mut parts = rest.splitn(4, ':');
    let (user, ts, nonce, sig_b64) = match (parts.next(), parts.next(), parts.next(), parts.next())
    {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        _ => return Err(AuthError::Format),
    };
    if user.is_empty() || nonce.is_empty() {
        return Err(AuthError::Format);
    }
    let ts: i64 = ts.parse().map_err(|_| AuthError::Format)?;
    let raw = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| AuthError::Format)?;
    let sig_arr: [u8; 64] = raw.try_into().map_err(|_| AuthError::Format)?;
    let sig = Signature::from_bytes(&sig_arr);
    if (now - ts).abs() > SIG_WINDOW_SECS {
        return Err(AuthError::Stale);
    }
    let canonical = build_canonical(user, ts, nonce, method, path_q, body_sha_hex);
    for vk in pubkeys {
        if vk.verify(canonical.as_bytes(), &sig).is_ok() {
            return Ok(Verified {
                user: user.to_owned(),
                ts,
                nonce: nonce.to_owned(),
            });
        }
    }
    Err(AuthError::BadSignature)
}

// ———— KeyProfile: kid → algorithm dispatch (§1.3.3g / §3.3, P2-12) ————

/// kid derivation: first 8 hex chars of `sha256(ed25519 public key 32B)`
/// (same-origin convention as showroomctl state.rs:695-697, matching the
/// `tokens/<user>/<kid>.pub` filename).
pub fn kid_of(vk: &VerifyingKey) -> String {
    sha256_hex(&vk.to_bytes())[..8].to_string()
}

/// A single profile key: an algorithm dispatch slot. Extending to a new
/// algorithm = adding a variant, zero caller changes (§3.3 seam).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileKey {
    /// Ed25519 primary tier (ed25519-dalek 3.0.0).
    Ed25519(VerifyingKey),
    /// Placeholder (unimplemented): the ML-DSA-65 parallel public-key
    /// tier. Exclusive to the `pq-sign` feature; ml-dsa 0.1.1 is unaudited
    /// (crypto-2026 §5), so this batch only reserves the slot — fill in
    /// real verification when wiring it up.
    #[cfg(feature = "pq-sign")]
    MlDsa65Placeholder,
}

impl ProfileKey {
    /// Verify with this key (primitive layer: message + signature, no
    /// SR-SIG1 header parsing).
    fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> Result<(), DispatchError> {
        match self {
            ProfileKey::Ed25519(vk) => {
                let sig: [u8; 64] = sig.try_into().map_err(|_| DispatchError::BadSignature)?;
                vk.verify(msg, &Signature::from_bytes(&sig))
                    .map_err(|_| DispatchError::BadSignature)
            }
            #[cfg(feature = "pq-sign")]
            ProfileKey::MlDsa65Placeholder => Err(DispatchError::UnsupportedAlgorithm),
        }
    }
}

/// kid dispatch failure, three states: kid not registered / verification
/// failed / algorithm tier unimplemented (placeholder slot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchError {
    UnknownKid,
    BadSignature,
    /// Placeholder algorithm tier (e.g. ML-DSA-65 not yet wired under
    /// `pq-sign`).
    UnsupportedAlgorithm,
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DispatchError::UnknownKid => "sig: kid not registered in profile",
            DispatchError::BadSignature => "E_AUTH: signature verification failed",
            DispatchError::UnsupportedAlgorithm => {
                "sig: algorithm slot not implemented (placeholder)"
            }
        })
    }
}

impl std::error::Error for DispatchError {}

/// Key profile: kid → [`ProfileKey`] dispatch table (Ed25519 primary tier;
/// the ML-DSA-65 slot under `pq-sign`).
///
/// Caller convention (§1.3.2): any hit among all of a user's public keys
/// passes — that is [`verify`]'s semantics; `KeyProfile` serves the
/// single-key re-verification path where the kid is already known (e.g.
/// located via `tokens/<user>/<kid>.pub`).
#[derive(Debug, Clone, Default)]
pub struct KeyProfile {
    keys: Vec<(String, ProfileKey)>,
}

impl KeyProfile {
    /// An empty profile.
    pub fn new() -> Self {
        KeyProfile { keys: Vec::new() }
    }

    /// Register an Ed25519 public key and return its kid (idempotent:
    /// re-registering the same key does not duplicate the slot).
    pub fn insert_ed25519(&mut self, vk: VerifyingKey) -> String {
        let kid = kid_of(&vk);
        if !self.keys.iter().any(|(k, _)| *k == kid) {
            self.keys.push((kid.clone(), ProfileKey::Ed25519(vk)));
        }
        kid
    }

    /// Look up a key by kid.
    pub fn get(&self, kid: &str) -> Option<&ProfileKey> {
        self.keys.iter().find(|(k, _)| k == kid).map(|(_, v)| v)
    }

    /// kid-dispatched verification: locate the key by kid → verify per its
    /// algorithm tier (raw message/signature, not an SR-SIG1 header).
    pub fn verify_dispatch(&self, kid: &str, msg: &[u8], sig: &[u8]) -> Result<(), DispatchError> {
        let key = self.get(kid).ok_or(DispatchError::UnknownKid)?;
        key.verify_raw(msg, sig)
    }

    /// All kids (in registration order).
    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|(k, _)| k.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1. sign→verify round trip (non-empty body / empty)
    #[test]
    fn sign_verify_roundtrip() {
        let k = UserKey::generate();
        let vk = [k.0.verifying_key()];
        for body in [b"{\"project\":\"demo\"}".as_slice(), b""] {
            let auth = sign(
                "alice",
                &k,
                "POST",
                "/_api/publish",
                body,
                1_000_000,
                "0123456789abcdef",
            );
            let v = verify(&auth, &vk, "POST", "/_api/publish", body, 1_000_000).unwrap();
            assert_eq!(
                (v.user.as_str(), v.ts, v.nonce.as_str()),
                ("alice", 1_000_000, "0123456789abcdef")
            );
        }
    }

    // 2. Tamper one body byte → BadSignature
    #[test]
    fn tampered_body_rejected() {
        let k = UserKey::generate();
        let auth = sign(
            "alice",
            &k,
            "POST",
            "/_api/publish",
            b"body-0",
            1_000_000,
            "0123456789abcdef",
        );
        assert_eq!(
            verify(
                &auth,
                &[k.0.verifying_key()],
                "POST",
                "/_api/publish",
                b"body-1",
                1_000_000
            ),
            Err(AuthError::BadSignature)
        );
    }

    // 3. ts outside the window (now±301) → Stale; ±300 boundary passes
    #[test]
    fn stale_ts_rejected() {
        let k = UserKey::generate();
        let vk = [k.0.verifying_key()];
        let auth = sign(
            "alice",
            &k,
            "POST",
            "/_api/publish",
            b"",
            1_000_000,
            "0123456789abcdef",
        );
        for now in [1_000_000 + 301, 1_000_000 - 301] {
            assert_eq!(
                verify(&auth, &vk, "POST", "/_api/publish", b"", now),
                Err(AuthError::Stale)
            );
        }
        for now in [1_000_000 + 300, 1_000_000 - 300] {
            assert!(verify(&auth, &vk, "POST", "/_api/publish", b"", now).is_ok());
        }
    }

    // 4. Wrong public key → BadSignature; with multiple keys, a hit on the
    // second passes
    #[test]
    fn wrong_key_and_multi_key() {
        let k = UserKey::generate();
        let auth = sign(
            "alice",
            &k,
            "GET",
            "/_api/logs?project=demo&tail=100",
            b"",
            5,
            "aabbccddeeff0011",
        );
        let wrong = UserKey::generate();
        assert_eq!(
            verify(
                &auth,
                &[wrong.0.verifying_key()],
                "GET",
                "/_api/logs?project=demo&tail=100",
                b"",
                5
            ),
            Err(AuthError::BadSignature)
        );
        verify(
            &auth,
            &[wrong.0.verifying_key(), k.0.verifying_key()],
            "GET",
            "/_api/logs?project=demo&tail=100",
            b"",
            5,
        )
        .unwrap();
    }

    // 5. Pre-hashed signing / streaming hash: same-semantics round trip
    // with sign/verify + a known sha256 vector
    #[test]
    fn prehashed_sign_verify_and_stream_hash() {
        let hash = sha256_hex_stream(std::io::Cursor::new(b"stream-me")).unwrap();
        assert_eq!(hash, sha256_hex(b"stream-me"));
        assert_eq!(
            sha256_hex_stream(std::io::Cursor::new(b"")).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let k = UserKey::generate();
        let pq = "/_api/import?project=demo&tag=v1";
        let auth = sign_prehashed("alice", &k, "POST", pq, &hash, 7, "aabb0011ccdd2233");
        let vk = [k.0.verifying_key()];
        let v = verify_with_hash(&auth, &vk, "POST", pq, &hash, 7).unwrap();
        assert_eq!(
            (v.user.as_str(), v.nonce.as_str()),
            ("alice", "aabb0011ccdd2233")
        );
        assert_eq!(
            verify_with_hash(&auth, &vk, "POST", pq, &sha256_hex(b"other"), 7),
            Err(AuthError::BadSignature)
        );
    }

    // 6. Exact byte shape of the canonical seven fields and the wire
    // format (§1.3.2 compatibility contract)
    #[test]
    fn canonical_and_wire_format_exact() {
        let c = build_canonical("alice", 42, "deadbeef", "GET", "/x?y=1", &sha256_hex(b"z"));
        assert_eq!(
            c,
            format!(
                "SR-SIG1\nalice\n42\ndeadbeef\nGET\n/x?y=1\n{}",
                sha256_hex(b"z")
            )
        );
        let k = UserKey::from_seed(&[7u8; 32]);
        let auth = sign_prehashed(
            "alice",
            &k,
            "GET",
            "/x?y=1",
            &sha256_hex(b"z"),
            42,
            "deadbeef",
        );
        assert!(auth.starts_with("SR-SIG1 alice:42:deadbeef:"));
        let sig_b64 = auth.rsplit(':').next().unwrap();
        assert_eq!(
            sig_b64.len(),
            86,
            "64B signature base64url unpadded = 86 chars"
        );
        assert!(
            !sig_b64.contains(['+', '/', '=']),
            "base64url unpadded charset"
        );
    }

    // 7. UserKey seed / pub_string round trip
    #[test]
    fn user_key_seed_and_pub_string() {
        let k = UserKey::from_seed(&[9u8; 32]);
        assert_eq!(k.to_seed(), [9u8; 32]);
        let vk = UserKey::from_pub_string(&k.pub_string()).unwrap();
        assert_eq!(vk.to_bytes(), *k.0.verifying_key().as_bytes());
        assert!(UserKey::from_pub_string("no-prefix").is_err());
        assert!(UserKey::from_pub_string("ed25519:AAAA").is_err());
    }

    // 8. kid derivation: sha256(pub)[..8], deterministic, distinct across
    // keys
    #[test]
    fn kid_derivation() {
        let k = UserKey::generate();
        let vk = k.0.verifying_key();
        let kid = kid_of(&vk);
        assert_eq!(kid.len(), 8);
        assert!(kid.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(kid, sha256_hex(&vk.to_bytes())[..8]);
        assert_ne!(kid, kid_of(&UserKey::generate().0.verifying_key()));
    }

    // 9. KeyProfile: register → dispatch-verify; unknown kid rejected;
    // another key's kid rejected
    #[test]
    fn key_profile_dispatch() {
        let k = UserKey::generate();
        let msg = b"canonical-bytes";
        let sig = k.0.sign(msg).to_bytes();

        let mut p = KeyProfile::new();
        let kid = p.insert_ed25519(k.0.verifying_key());
        assert_eq!(
            p.get(&kid).cloned(),
            Some(ProfileKey::Ed25519(k.0.verifying_key()))
        );
        p.verify_dispatch(&kid, msg, &sig)
            .expect("registered key verifies");
        assert_eq!(
            p.verify_dispatch("00000000", msg, &sig),
            Err(DispatchError::UnknownKid)
        );

        // Different kid: another key's signature must fail under the
        // original kid
        let k2 = UserKey::generate();
        let sig2 = k2.0.sign(msg).to_bytes();
        assert_eq!(
            p.verify_dispatch(&kid, msg, &sig2),
            Err(DispatchError::BadSignature)
        );
        // Wrong signature length → BadSignature
        assert_eq!(
            p.verify_dispatch(&kid, msg, b"short"),
            Err(DispatchError::BadSignature)
        );

        // Register a second key: kids stay idempotent
        let kid2 = p.insert_ed25519(k2.0.verifying_key());
        assert_ne!(kid, kid2);
        p.verify_dispatch(&kid2, msg, &sig2)
            .expect("second key passes under its own kid");
        p.insert_ed25519(k2.0.verifying_key());
        assert_eq!(
            p.kids().count(),
            2,
            "re-registering the same key does not duplicate the slot"
        );
    }

    // 10. Cross-ecosystem fixed vectors (generated with showroom-common
    //     ed25519-dalek 2.2; RFC 8032 deterministic signing ⇒ must
    //     reproduce byte-for-byte under this crate's 3.0): covered by the
    //     tests/sig_showroom_vector.rs integration test.

    // 11. Seed file save/from round trip + 0600 (unix file seam; ported
    // from showroom lib.rs:607-619)
    #[cfg(unix)]
    #[test]
    fn user_key_seed_file_roundtrip() {
        use std::os::unix::fs::PermissionsExt;

        let k = UserKey::generate();
        let dir = std::env::temp_dir().join(format!("flock-sig-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("id_ed25519");
        k.save_seed(&p).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let k2 = UserKey::from_seed_file(&p).unwrap();
        assert_eq!(k2.to_seed(), k.to_seed());
        assert_eq!(k2.pub_string(), k.pub_string());
        // Non-32B seed file → Err
        std::fs::write(&p, b"short").unwrap();
        assert!(UserKey::from_seed_file(&p).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
