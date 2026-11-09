//! File envelope v2 (hybrid encapsulation + segment-index AAD)
//! (docs/design.md §1.3.3b / §3.2, P0-1, P0-3).
//!
//! v2 byte layout:
//!
//! ```text
//! header: [1B ver=2][16B envelope_id][32B eph_x25519][1088B ml_kem_ct]   = 1137B
//! segment: [12B nonce][AES-256-GCM ct‖16B tag], segment plaintext = 4MiB (last may be shorter)
//! AAD: ver ‖ envelope_id ‖ seg_idx(u64 LE) ‖ is_final(u8 0/1)        = 26B
//! ```
//!
//! - The one-time k is derived by the hybrid KEM (fresh ephemeral X25519 +
//!   ML-KEM shares per envelope ⇒ one-time envelopes gain forward secrecy,
//!   verdict §3.3); k is exactly the 32B HKDF output of
//!   [`crate::kem::SealedShared`].
//! - **Documented security premise** (§1.3.3b, verdict §3.4): one-time k +
//!   fresh random 96-bit nonce per segment — messages per key = n/4MiB ≪
//!   2^32, within the SP 800-38D random-IV bound; counter-nonce discipline
//!   for long-lived session traffic belongs to the tunnel profile (the
//!   session module); the two profiles stay separate.
//! - The AAD binds segment index + envelope ID + final flag into
//!   authentication: segment reordering (seg_idx), cross-envelope splicing
//!   (envelope_id), and tail truncation (is_final) are all rejected on the
//!   decrypt side (v1 lacked this — verified this round at showroom-common
//!   lib.rs:396-411).
//! - Streaming with constant memory (following the showroom seal/open
//!   buffer model, showroom-analysis §4.1): seal ≈ 1×SEG buffer + 1 probe
//!   byte; open ≈ BufReader(SEG+28) + 1×(SEG+16) ciphertext buffer.
//! - Length invariant: `total = 1137 + n + ceil(n/SEG) × (12+16)` (n =
//!   plaintext bytes).
//! - Empty input is legal: just the 1137B header (0 plaintext bytes, 0
//!   segments). Note: an empty envelope has no segment to authenticate and
//!   header recipient-match cannot be verified (0 plaintext bytes present
//!   no leak surface); overall integrity follows the showroom EtM
//!   convention and is carried by the caller's outer SR-SIG1 hash (same
//!   idea as security.md:84).
//! - Inherent truncation-tolerance boundary (same as showroom): decryption
//!   proceeds segment by segment; earlier segments already written are not
//!   rolled back when a later segment fails.
//!
//! v1 read-only compatibility (`legacy` feature): [`open_v1_legacy`]
//! decodes `[384B RSA-OAEP-SHA256(k)] || segments{[12B nonce][ct+tag]}`
//! (no AAD; showroom-common lib.rs:376-461 layout unchanged).

use std::io::{self, BufReader, Read, Write};

use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aead::{AeadCore, AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};

/// Build an AES-256-GCM key from the 32B raw key (length is always 32;
/// try_from only checks length).
fn key_of(raw: &[u8; KEY_LEN]) -> Key<Aes256Gcm> {
    Key::<Aes256Gcm>::try_from(&raw[..]).expect("32B AES-256 key")
}
use rand::RngCore;

use crate::kem::{self, HybridCt, HybridKeypair, HybridPubkey};

/// AES-256 key length (v1 compatibility constant, §1.3.2).
pub const KEY_LEN: usize = 32;
/// AES-GCM 96-bit nonce length (v1 compatibility constant, §1.3.2).
pub const NONCE_LEN: usize = 12;
/// GCM authentication tag length (v1 compatibility constant, §1.3.2).
pub const TAG_LEN: usize = 16;
/// Per-segment plaintext 4MiB (v1 compatibility constant, §1.3.2).
pub const SEG: usize = 4 * 1024 * 1024;

/// v2 header version byte.
pub const V2_VER: u8 = 2;
/// v2 header length: 1 + 16 + 32 + 1088 = 1137B.
pub const V2_HEADER_LEN: usize = 1 + 16 + kem::X25519_PUB_LEN + kem::ML_KEM_CT_LEN;
/// Segment AAD length: ver(1) + id(16) + seg_idx(8) + is_final(1).
pub const SEG_AAD_LEN: usize = 1 + 16 + 8 + 1;

/// `legacy`: v1 encapsulation header length (RSA-3072 modulus length,
/// §1.3.2).
#[cfg(feature = "legacy")]
pub const WRAP_LEN: usize = 384;

/// Summary of a [`seal_v2`] result: envelope ID / segment count / total
/// bytes written (including the 1137B header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealInfo {
    /// 16B envelope ID (also bound into every segment's AAD).
    pub envelope_id: [u8; 16],
    /// Segment count (empty envelope = 0).
    pub segments: u64,
    /// Total bytes written (including the header) =
    /// `1137 + n + segments × 28`.
    pub total_bytes: u64,
}

/// Segment AAD: `ver ‖ envelope_id ‖ seg_idx(u64 LE) ‖ is_final` (§1.3.3b;
/// construction is an internal implementation detail, §3.2).
fn seg_aad(ver: u8, envelope_id: &[u8; 16], seg_idx: u64, is_final: bool) -> [u8; SEG_AAD_LEN] {
    let mut a = [0u8; SEG_AAD_LEN];
    a[0] = ver;
    a[1..17].copy_from_slice(envelope_id);
    a[17..25].copy_from_slice(&seg_idx.to_le_bytes());
    a[25] = u8::from(is_final);
    a
}

/// v2 sealing (streaming, constant memory). Randomness: envelope_id /
/// hybrid KEM ephemeral shares / per-segment nonce all from OsRng.
pub fn seal_v2<W: Write>(
    recipient: &HybridPubkey,
    mut plain: impl Read,
    mut out: W,
) -> io::Result<SealInfo> {
    let mut rng = rand::rng();
    let mut envelope_id = [0u8; 16];
    rng.fill_bytes(&mut envelope_id);

    // One-time k: hybrid encapsulation (fresh ephemeral shares per envelope
    // ⇒ forward secrecy)
    let (shared, ct) = kem::encapsulate(recipient, &mut rng);
    let cipher = Aes256Gcm::new(&key_of(shared.as_bytes()));

    // Header 1137B: ver | envelope_id | HybridCt (= eph_x25519 32B ‖
    // ml_kem_ct 1088B, order per §1.3.3b)
    out.write_all(&[V2_VER])?;
    out.write_all(&envelope_id)?;
    out.write_all(&ct.to_bytes())?;
    let mut total_bytes = V2_HEADER_LEN as u64;

    let mut buf = vec![0u8; SEG];
    let mut seg_idx: u64 = 0;
    let mut segments: u64 = 0;
    // 1 probe byte: after a full segment, probe-read 1B to decide
    // is_final, avoiding a second 4MiB buffer (constant memory)
    let mut carry: u8 = 0;
    let mut carry_len: usize = 0;
    loop {
        let n = if carry_len == 1 {
            buf[0] = carry;
            1 + read_full(&mut plain, &mut buf[1..])?
        } else {
            read_full(&mut plain, &mut buf)?
        };
        if n == 0 {
            break; // clean finish (the previous write was already the last
                   // segment; a 0 first read = empty envelope)
        }
        let is_final = if n < SEG {
            true
        } else {
            let mut probe = [0u8; 1];
            match read_full(&mut plain, &mut probe)? {
                0 => true,
                _ => {
                    carry = probe[0];
                    carry_len = 1;
                    false
                }
            }
        };
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let aad = seg_aad(V2_VER, &envelope_id, seg_idx, is_final);
        let tag = cipher
            .encrypt_inout_detached(
                &Nonce::<<Aes256Gcm as AeadCore>::NonceSize>::from(nonce),
                &aad,
                InOutBuf::from(&mut buf[..n]),
            )
            .map_err(|_| io::Error::other("envelope v2: aes-gcm encrypt segment"))?;
        out.write_all(&nonce)?;
        out.write_all(&buf[..n])?;
        out.write_all(tag.as_slice())?;
        total_bytes += (NONCE_LEN + n + TAG_LEN) as u64;
        seg_idx += 1;
        segments += 1;
        if is_final {
            break;
        }
    }
    Ok(SealInfo {
        envelope_id,
        segments,
        total_bytes,
    })
}

/// v2 opening (streaming, constant memory). Returns total plaintext bytes
/// written; any ver/header-length/segment authentication failure returns
/// Err (no panic). An empty envelope (1137B header only) is legal and
/// returns 0.
pub fn open_v2(sk: &HybridKeypair, sealed: impl Read, mut out: impl Write) -> io::Result<u64> {
    let mut r = BufReader::with_capacity(SEG + NONCE_LEN + TAG_LEN, sealed);

    let mut header = [0u8; V2_HEADER_LEN];
    if read_full(&mut r, &mut header)? != V2_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "envelope: truncated 1137-byte v2 header",
        ));
    }
    if header[0] != V2_VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "envelope: unsupported version {} (expect {V2_VER})",
                header[0]
            ),
        ));
    }
    let envelope_id: [u8; 16] = header[1..17].try_into().expect("1137B split");
    let ct_bytes: [u8; kem::HYBRID_CT_LEN] = header[17..].try_into().expect("1137B split");
    let shared = kem::decapsulate(sk, &HybridCt::from_bytes(&ct_bytes)).ok_or_else(|| {
        io::Error::other("envelope v2: hybrid decapsulation rejected (non-contributory)")
    })?;
    let cipher = Aes256Gcm::new(&key_of(shared.as_bytes()));

    let mut nonce = [0u8; NONCE_LEN];
    let mut next_nonce = [0u8; NONCE_LEN];
    let mut ct = vec![0u8; SEG + TAG_LEN];
    let mut seg_idx: u64 = 0;
    let mut total: u64 = 0;

    match read_full(&mut r, &mut nonce)? {
        0 => return Ok(0), // empty envelope: clean EOF at a segment boundary
        NONCE_LEN => {}
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "envelope: truncated nonce",
            ))
        }
    }
    loop {
        let n = read_full(&mut r, &mut ct)?;
        if n < TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "envelope: truncated segment",
            ));
        }
        // Final-segment decision: look ahead to the next nonce (EOF ⇒ this
        // segment is final; is_final is bound into the AAD ⇒ tail
        // truncation is rejected)
        let is_final = match read_full(&mut r, &mut next_nonce)? {
            0 => true,
            NONCE_LEN => false,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "envelope: truncated nonce",
                ))
            }
        };
        let (msg, tag_bytes) = ct[..n].split_at_mut(n - TAG_LEN);
        let tag_arr: [u8; TAG_LEN] = tag_bytes.try_into().expect("16B tag");
        let aad = seg_aad(V2_VER, &envelope_id, seg_idx, is_final);
        cipher
            .decrypt_inout_detached(
                &Nonce::<<Aes256Gcm as AeadCore>::NonceSize>::from(nonce),
                &aad,
                InOutBuf::from(&mut *msg),
                &Tag::<<Aes256Gcm as AeadCore>::TagSize>::from(tag_arr),
            )
            .map_err(|_| {
                io::Error::other(
                    "envelope v2: aes-gcm segment auth failed \
                     (tag mismatch / tampered / reordered / spliced / truncated)",
                )
            })?;
        out.write_all(msg)?;
        total += msg.len() as u64;
        seg_idx += 1;
        if is_final {
            return Ok(total);
        }
        nonce = next_nonce;
    }
}

/// `legacy`: v1 read-only opening (product of showroom `seal`; layout per
/// §1.3.2, `[384B RSA-OAEP-SHA256(k)] || segments{[12B nonce][ct+16B
/// tag]}`, **no AAD** — precisely the defect the v2 segment AAD fixes,
/// P0-3). Returns total plaintext bytes written; an empty envelope (384B
/// header only) is legal and returns 0.
#[cfg(feature = "legacy")]
pub fn open_v1_legacy(
    platform_priv: &rsa::RsaPrivateKey,
    sealed: impl Read,
    mut out: impl Write,
) -> io::Result<u64> {
    let mut r = BufReader::with_capacity(SEG + NONCE_LEN + TAG_LEN, sealed);
    let mut wrap = [0u8; WRAP_LEN];
    if read_full(&mut r, &mut wrap)? != WRAP_LEN {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "sealed: truncated 384-byte header",
        ));
    }
    let k = platform_priv
        .decrypt(rsa::Oaep::new::<rsa::sha2::Sha256>(), &wrap)
        .map_err(|e| io::Error::other(format!("rsa-oaep unwrap key: {e}")))?;
    let k: [u8; KEY_LEN] = k
        .as_slice()
        .try_into()
        .map_err(|_| io::Error::other("unwrapped key not 32 bytes"))?;
    let cipher = Aes256Gcm::new(&key_of(&k));

    let mut nonce = [0u8; NONCE_LEN];
    let mut ct = vec![0u8; SEG + TAG_LEN];
    let mut total: u64 = 0;
    loop {
        match read_full(&mut r, &mut nonce)? {
            0 => return Ok(total), // clean finish (EOF at a segment boundary)
            NONCE_LEN => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sealed: truncated nonce",
                ))
            }
        }
        let n = read_full(&mut r, &mut ct)?;
        if n < TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "sealed: truncated segment",
            ));
        }
        let (msg, tag_bytes) = ct[..n].split_at_mut(n - TAG_LEN);
        let tag_arr: [u8; TAG_LEN] = tag_bytes.try_into().expect("16B tag");
        cipher
            .decrypt_inout_detached(
                &Nonce::<<Aes256Gcm as AeadCore>::NonceSize>::from(nonce),
                b"", // v1 has no AAD (kept byte-for-byte compatible)
                InOutBuf::from(&mut *msg),
                &Tag::<<Aes256Gcm as AeadCore>::TagSize>::from(tag_arr),
            )
            .map_err(|_| {
                io::Error::other("aes-gcm segment auth failed (tag mismatch / tampered data)")
            })?;
        out.write_all(msg)?;
        total += msg.len() as u64;
    }
}

// ———— v1 write side + platform RSA keypair (`legacy`; §1.3.2 compatibility
// surface, showroom keeps writing v1 during the migration window) ————

/// Private rand 0.9 (this library's RNG surface) → rsa 0.9.10's rand_core
/// 0.6 generation bridge (for the `CryptoRngCore` parameters of rsa
/// keygen / OAEP padding; same idea as the pake module's RngBridge08).
/// Entropy-source failure panics directly (same semantics as this
/// library's other bridges).
#[cfg(feature = "legacy")]
struct Rng06<'a, R: rand::TryRngCore + ?Sized>(&'a mut R);

#[cfg(feature = "legacy")]
impl<R: rand::TryRngCore + ?Sized> rsa::rand_core::RngCore for Rng06<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.0
            .try_next_u32()
            .expect("flock-protocol: entropy source failed")
    }
    fn next_u64(&mut self) -> u64 {
        self.0
            .try_next_u64()
            .expect("flock-protocol: entropy source failed")
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0
            .try_fill_bytes(dst)
            .expect("flock-protocol: entropy source failed");
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.0.try_fill_bytes(dst).map_err(|_| {
            rsa::rand_core::Error::from(std::num::NonZeroU32::new(1).expect("nonzero"))
        })
    }
}

#[cfg(feature = "legacy")]
impl<R: rand::TryRngCore + ?Sized> rsa::rand_core::CryptoRng for Rng06<'_, R> {}

/// `legacy`: v1 sealing (verbatim showroom `seal`, §1.3.2 signature
/// unchanged). Layout `[384B RSA-OAEP-SHA256-wrapped k] || per segment [12B
/// nonce][ct+16B tag]`, segment = 4MiB plaintext, **no AAD** (the inherent
/// v1 defect is fixed by the v2 segment-index AAD, P0-3; kept
/// byte-for-byte compatible here, unchanged). Returns total bytes written
/// (including the 384B encapsulation header). During the migration window
/// showroom keeps writing v1 (§1.3.3a: the real transition = keep writing
/// v1, always able to read v1). zstd compression is not in this crate
/// (callers compose their own pipeline).
#[cfg(feature = "legacy")]
pub fn seal_v1_legacy<W: Write>(
    platform_pub: &rsa::RsaPublicKey,
    mut plain: impl Read,
    mut out: W,
) -> io::Result<u64> {
    let mut rng = rand::rng();
    let mut k = [0u8; KEY_LEN];
    rng.fill_bytes(&mut k);
    let wrapped = platform_pub
        .encrypt(
            &mut Rng06(&mut rng),
            rsa::Oaep::new::<rsa::sha2::Sha256>(),
            &k,
        )
        .map_err(|e| io::Error::other(format!("rsa-oaep wrap key: {e}")))?;
    if wrapped.len() != WRAP_LEN {
        return Err(io::Error::other(format!(
            "expected 384-byte rsa-3072 wrap, got {}",
            wrapped.len()
        )));
    }
    out.write_all(&wrapped)?;
    let mut total = wrapped.len() as u64;
    let cipher = Aes256Gcm::new(&key_of(&k));
    let mut buf = vec![0u8; SEG];
    loop {
        let n = read_full(&mut plain, &mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let tag = cipher
            .encrypt_inout_detached(
                &Nonce::<<Aes256Gcm as AeadCore>::NonceSize>::from(nonce),
                b"", // v1 has no AAD (kept byte-for-byte compatible)
                InOutBuf::from(&mut buf[..n]),
            )
            .map_err(|_| io::Error::other("aes-gcm encrypt segment"))?;
        out.write_all(&nonce)?;
        out.write_all(&buf[..n])?;
        out.write_all(tag.as_slice())?;
        total += (NONCE_LEN + n + TAG_LEN) as u64;
    }
}

/// `legacy`: platform RSA-3072 keypair (verbatim showroom `PlatformKeys`,
/// §1.3.2). The recipient key of v1 envelopes (seal with the public key /
/// open with the private key).
#[cfg(feature = "legacy")]
pub struct PlatformKeys(rsa::RsaPrivateKey);

#[cfg(feature = "legacy")]
impl PlatformKeys {
    /// Generate an RSA-3072 (modulus length 384B = the v1 encapsulation
    /// header length contract).
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        PlatformKeys(rsa::RsaPrivateKey::new(&mut Rng06(&mut rng), 3072).expect("rsa-3072 keygen"))
    }

    /// The private key (passed to [`open_v1_legacy`]; showroom callers also
    /// construct it themselves from PEM via the re-exported rsa crate).
    pub fn private(&self) -> &rsa::RsaPrivateKey {
        &self.0
    }

    /// The public key (passed to [`seal_v1_legacy`]).
    pub fn public(&self) -> rsa::RsaPublicKey {
        self.0.to_public_key()
    }

    /// Write `<dir>/platform_rsa` (PKCS#8 PEM, 0600) and
    /// `<dir>/platform_rsa.pub`; returns the private key path. Unix-only
    /// (0600 permission semantics; wasm32 has no filesystem).
    #[cfg(unix)]
    pub fn save_pem(&self, dir: &std::path::Path) -> crate::compat::Result<std::path::PathBuf> {
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};

        let priv_path = dir.join("platform_rsa");
        let pem = self.0.to_pkcs8_pem(LineEnding::LF)?;
        crate::compat::write_private(&priv_path, pem.as_bytes())?;
        std::fs::write(dir.join("platform_rsa.pub"), self.public_pem().as_bytes())?;
        Ok(priv_path)
    }

    /// Read `<dir>/platform_rsa` (PKCS#8 PEM).
    pub fn load_pem(dir: &std::path::Path) -> crate::compat::Result<Self> {
        use rsa::pkcs8::DecodePrivateKey;

        let pem = std::fs::read_to_string(dir.join("platform_rsa"))?;
        Ok(PlatformKeys(rsa::RsaPrivateKey::from_pkcs8_pem(&pem)?))
    }

    /// Public key PEM (SPKI, `-----BEGIN PUBLIC KEY-----`).
    pub fn public_pem(&self) -> String {
        use rsa::pkcs8::{EncodePublicKey, LineEnding};

        self.0
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode public pem")
            .as_str()
            .to_owned()
    }
}

/// Read in a loop until buf is full or EOF; returns bytes read (safe
/// against short pipe reads; same as showroom lib.rs:464-473).
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..])? {
            0 => break,
            n => off += n,
        }
    }
    Ok(off)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use V2_HEADER_LEN as HDR;

    fn keypair() -> HybridKeypair {
        HybridKeypair::generate(&mut rand::rngs::OsRng)
    }

    fn seal(plain: &[u8], pk: &HybridPubkey) -> (Vec<u8>, SealInfo) {
        let mut sealed = Vec::new();
        let info = seal_v2(pk, Cursor::new(plain), &mut sealed).unwrap();
        (sealed, info)
    }

    // 5. seal→open round trip: empty / exactly 4MiB / >8MiB (multi
    // segment), plus the total-length invariant (§3.2 length-invariant
    // test)
    #[test]
    fn v2_roundtrip_and_length_invariant() {
        let sk = keypair();
        let pk = sk.public();
        for len in [0usize, SEG, SEG * 2 + 1234] {
            let plain: Vec<u8> = (0..len as u32).map(|i| (i % 251) as u8).collect();
            let (sealed, info) = seal(&plain, &pk);
            let segs = len.div_ceil(SEG) as u64;
            assert_eq!(
                info.total_bytes as usize,
                HDR + len + (segs as usize) * (NONCE_LEN + TAG_LEN),
                "v2 length invariant: 1137 + n + ceil(n/4MiB)*28"
            );
            assert_eq!(info.segments, segs);
            assert_eq!(
                &sealed[1..17],
                &info.envelope_id,
                "SealInfo.id matches the header"
            );
            assert_eq!(sealed[0], V2_VER);
            let mut out = Vec::new();
            let m = open_v2(&sk, Cursor::new(sealed.as_slice()), &mut out).unwrap();
            assert_eq!(m as usize, len);
            assert_eq!(out, plain);
        }
    }

    // Exactly 2×SEG (last segment is a full segment) — is_final must be
    // decided by the lookahead/probe, not by "short segment = final"
    #[test]
    fn v2_full_multiple_roundtrip() {
        let sk = keypair();
        let plain = vec![0xABu8; SEG * 2];
        let (sealed, info) = seal(&plain, &sk.public());
        assert_eq!(info.segments, 2);
        assert_eq!(sealed.len(), HDR + SEG * 2 + 2 * (NONCE_LEN + TAG_LEN));
        let mut out = Vec::new();
        assert_eq!(
            open_v2(&sk, Cursor::new(sealed.as_slice()), &mut out).unwrap() as usize,
            SEG * 2
        );
        assert_eq!(out, plain);
    }

    // 6. Tampering: header ciphertext region / segment ciphertext region →
    // error, no panic
    #[test]
    fn v2_tamper_rejected() {
        let sk = keypair();
        let plain = vec![7u8; SEG + 100];
        let (sealed, _) = seal(&plain, &sk.public());

        let mut t = sealed.clone();
        t[HDR + NONCE_LEN + 10] ^= 1; // first segment's ciphertext region
        let mut out = Vec::new();
        assert!(open_v2(&sk, Cursor::new(t.as_slice()), &mut out).is_err());
        assert!(
            out.is_empty(),
            "no written content after a first-segment failure"
        );

        let mut t2 = sealed;
        t2[100] ^= 1; // header ml_kem_ct region ⇒ wrong k derived ⇒ segment auth fails
        let mut out2 = Vec::new();
        assert!(open_v2(&sk, Cursor::new(t2.as_slice()), &mut out2).is_err());
    }

    // Version byte dispatch: headers with ver=1 / ver=3 → rejected (§3.2
    // seam: the ver byte dispatches v1/v2)
    #[test]
    fn v2_version_dispatch() {
        let sk = keypair();
        let (mut sealed, _) = seal(b"x", &sk.public());
        sealed[0] = 1;
        let mut out = Vec::new();
        let err = open_v2(&sk, Cursor::new(sealed.as_slice()), &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        sealed[0] = 3;
        assert!(open_v2(&sk, Cursor::new(sealed.as_slice()), &mut out).is_err());
        // truncated header
        let (s2, _) = seal(b"x", &sk.public());
        assert!(open_v2(&sk, Cursor::new(&s2[..1136]), &mut out).is_err());
    }

    // P0-3 gate case: segment reordering must fail (seg_idx bound into the
    // AAD)
    #[test]
    fn v2_segment_reorder_rejected() {
        let sk = keypair();
        let plain: Vec<u8> = (0..(SEG as u32 * 3)).map(|i| (i % 251) as u8).collect(); // 3 full segments
        let (sealed, info) = seal(&plain, &sk.public());
        assert_eq!(info.segments, 3);
        let blk = SEG + NONCE_LEN + TAG_LEN; // per-segment wire block length (full)
                                             // swap segment 0 and segment 1
        let mut t = sealed.clone();
        let (a, b) = (HDR..HDR + blk, HDR + blk..HDR + 2 * blk);
        let sa: Vec<u8> = sealed[a.clone()].to_vec();
        let sb: Vec<u8> = sealed[b.clone()].to_vec();
        t[a].copy_from_slice(&sb);
        t[b].copy_from_slice(&sa);
        let mut out = Vec::new();
        assert!(
            open_v2(&sk, Cursor::new(t.as_slice()), &mut out).is_err(),
            "segment reordering must be rejected by AAD(seg_idx)"
        );
    }

    // P0-3 gate case: tail truncation must fail on the decrypt side
    // (is_final bound into the AAD)
    #[test]
    fn v2_truncation_rejected() {
        let sk = keypair();
        let plain = vec![5u8; SEG * 2 + 1234]; // 3 segments: 2 full + 1 short
        let (sealed, info) = seal(&plain, &sk.public());
        assert_eq!(info.segments, 3);
        // Truncate at the 2nd segment boundary (dropping the last
        // segment): the final flag mismatches ⇒ rejected
        let cut = HDR + 2 * (SEG + NONCE_LEN + TAG_LEN);
        let mut out = Vec::new();
        assert!(
            open_v2(&sk, Cursor::new(&sealed[..cut]), &mut out).is_err(),
            "tail truncation must be rejected by AAD(is_final)"
        );
        // Incidentally: truncation off a segment boundary (half a nonce
        // read) must also error
        assert!(open_v2(&sk, Cursor::new(&sealed[..cut + 5]), &mut out).is_err());
    }

    // P0-3 gate case: cross-envelope splicing must fail (envelope_id bound
    // into the AAD) — two envelopes to the same recipient, segments spliced
    #[test]
    fn v2_splice_rejected() {
        let sk = keypair();
        let (env_a, info_a) = seal(&vec![1u8; SEG], &sk.public());
        let (env_b, _) = seal(&vec![2u8; SEG], &sk.public());
        assert_ne!(
            info_a.envelope_id,
            {
                let mut b = [0u8; 16];
                b.copy_from_slice(&env_b[1..17]);
                b
            },
            "the two envelope ids must differ"
        );
        let blk = SEG + NONCE_LEN + TAG_LEN;
        // Replace A's segment with B's (same recipient, same seg_idx, same
        // is_final — only the id differs)
        let mut t = env_a.clone();
        t[HDR..HDR + blk].copy_from_slice(&env_b[HDR..HDR + blk]);
        let mut out = Vec::new();
        assert!(
            open_v2(&sk, Cursor::new(t.as_slice()), &mut out).is_err(),
            "cross-envelope splicing must be rejected by AAD(envelope_id)"
        );
    }

    // A non-recipient cannot open: wrong hybrid private key ⇒ segment auth
    // fails
    #[test]
    fn v2_wrong_recipient_rejected() {
        let (sk, other) = (keypair(), keypair());
        let (sealed, _) = seal(b"secret-bytes", &sk.public());
        let mut out = Vec::new();
        assert!(open_v2(&other, Cursor::new(sealed.as_slice()), &mut out).is_err());
    }

    // One-time semantics: sealing the same plaintext twice ⇒ different
    // ciphertext (fresh ephemeral shares + random id/nonce)
    #[test]
    fn v2_freshness() {
        let sk = keypair();
        let (a, _) = seal(b"same-plaintext", &sk.public());
        let (b, _) = seal(b"same-plaintext", &sk.public());
        assert_ne!(a, b);
    }
}

// ———— v1 write side (`legacy`; seal_v1_legacy / PlatformKeys) ————
#[cfg(all(test, feature = "legacy"))]
mod v1_tests {
    use super::*;
    use std::io::Cursor;

    fn platform() -> &'static PlatformKeys {
        static K: std::sync::OnceLock<PlatformKeys> = std::sync::OnceLock::new();
        K.get_or_init(PlatformKeys::generate)
    }

    // seal_v1_legacy → open_v1_legacy round trip: empty / exactly 4MiB /
    // >8MiB (multi segment), plus the encapsulation total length (length
    // invariant: 384 + n + ceil(n/4MiB)×28; idea ported from showroom
    // lib.rs:578 test)
    #[test]
    fn v1_seal_open_roundtrip_and_length_invariant() {
        let p = platform();
        for len in [0usize, SEG, SEG * 2 + 1234] {
            let plain: Vec<u8> = (0..len as u32).map(|i| (i % 251) as u8).collect();
            let mut sealed = Vec::new();
            let n =
                seal_v1_legacy(&p.public(), Cursor::new(plain.as_slice()), &mut sealed).unwrap();
            let segs = len.div_ceil(SEG);
            assert_eq!(n as usize, WRAP_LEN + segs * (NONCE_LEN + TAG_LEN) + len);
            let mut out = Vec::new();
            let m = open_v1_legacy(p.private(), Cursor::new(sealed.as_slice()), &mut out).unwrap();
            assert_eq!(m as usize, len);
            assert_eq!(out, plain);
        }
    }

    // Flip one byte of the sealed input (ciphertext region / encapsulation
    // header region) → error, no panic (ported from showroom lib.rs:587-604
    // tampered_envelope_rejected)
    #[test]
    fn v1_tampered_envelope_rejected() {
        let p = platform();
        let plain = vec![7u8; SEG + 100];
        let mut sealed = Vec::new();
        seal_v1_legacy(&p.public(), Cursor::new(plain.as_slice()), &mut sealed).unwrap();

        let mut t = sealed.clone();
        t[WRAP_LEN + NONCE_LEN + 10] ^= 1; // inside the first segment's ciphertext
        let mut out = Vec::new();
        let e = open_v1_legacy(p.private(), Cursor::new(t.as_slice()), &mut out);
        assert!(e.is_err(), "flipped ciphertext byte must error");
        assert!(out.is_empty());

        let mut t2 = sealed;
        t2[10] ^= 1; // inside the 384B encapsulation header
        let mut out2 = Vec::new();
        assert!(open_v1_legacy(p.private(), Cursor::new(t2.as_slice()), &mut out2).is_err());
    }

    // PlatformKeys::save_pem/load_pem/public_pem round trip (unix file
    // seam)
    #[cfg(unix)]
    #[test]
    fn v1_platform_pem_roundtrip() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("flock-v1-pem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let priv_path = platform().save_pem(&dir).unwrap();
        assert_eq!(priv_path, dir.join("platform_rsa"));
        assert!(dir.join("platform_rsa.pub").exists());
        assert_eq!(
            std::fs::metadata(&priv_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let loaded = PlatformKeys::load_pem(&dir).unwrap();
        assert_eq!(loaded.public_pem(), platform().public_pem());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
