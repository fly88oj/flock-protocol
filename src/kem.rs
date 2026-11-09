//! Hybrid KEM: X25519 + ML-KEM-768 (docs/design.md §1.3.3a / §3.1, P0-1,
//! P0-7).
//!
//! Combination rule: `shared = HKDF-SHA256(x25519_ss ‖ ml_kem_ss)` (the TLS
//! hybrid idea, RFC 10024; design basis verdict §3.3 review-round live
//! runs: ek=1184B/ct=1088B, hybrid ciphertext 1120B, hybrid public key
//! 1216B). Implemented with ml-kem 0.3.3 (pure-Rust FIPS 203) +
//! x25519-dalek 3.0.0; liboqs is not used (crypto-2026 §5).
//!
//! Wire-size constants:
//! - [`HybridPubkey`]: 1216B = 32(X25519) ‖ 1184(ML-KEM-768 ek);
//! - [`HybridCt`]: 1120B = 32(ephemeral X25519 public key) ‖ 1088(ML-KEM-768
//!   ct).
//!
//! HKDF parameters (pinned by this library; agreement between both sides
//! makes them byte-for-byte deterministic): salt=None (HKDF zero padding),
//! info=`flock-protocol/hybrid-kem/x25519+ml-kem-768/v1`, OKM=32B.
//!
//! RNG surface: public functions accept rand 0.9's `TryCryptoRng` (OsRng /
//! StdRng can be passed directly); ml-kem / x25519-dalek 3.0 internally use
//! the rand_core 0.10 generation, bridged by the private [`RngBridge`],
//! invisibly to callers.

use core::convert::Infallible;
use core::fmt;

use ml_kem::ml_kem_768::MlKem768;
use ml_kem::{
    Ciphertext, Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Kem, Key, KeyExport,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize as _;

/// rand_core 0.10 (the RNG generation of ml-kem / x25519-dalek 3.0).
/// Library-internal bridging only; not part of the public API surface.
use rand_core as rc010;

/// Wire length of an X25519 public key (bytes).
pub const X25519_PUB_LEN: usize = 32;
/// Wire length of an ML-KEM-768 encapsulation key (FIPS 203: ek=1184B).
pub const ML_KEM_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length (FIPS 203: ct=1088B).
pub const ML_KEM_CT_LEN: usize = 1088;
/// Hybrid public key wire length: 32 + 1184 = 1216B.
pub const HYBRID_PUB_LEN: usize = X25519_PUB_LEN + ML_KEM_EK_LEN;
/// Hybrid ciphertext length: 32 + 1088 = 1120B.
pub const HYBRID_CT_LEN: usize = X25519_PUB_LEN + ML_KEM_CT_LEN;
/// Hybrid shared secret length (HKDF-SHA256 OKM).
pub const SHARED_LEN: usize = 32;
/// Secret key serialization length: 32(X25519 sk) + 64(ML-KEM seed d‖z) =
/// 96B.
pub const HYBRID_SK_LEN: usize = X25519_PUB_LEN + 64;

/// HKDF info label: domain separation (changing the algorithm or the
/// combination rule requires changing the label).
const HKDF_INFO: &[u8] = b"flock-protocol/hybrid-kem/x25519+ml-kem-768/v1";

/// Re-derivation label for seed_material's z (domain separation: z is used
/// only for FIPS 203 implicit rejection of bogus ciphertexts).
const L_SEED_Z: &[u8] = b"flock-protocol/hybrid-kem/seed-z/v1";

/// KEM error: public key/ciphertext deserialization or validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemError {
    /// Malformed hybrid public key (wrong length, or ML-KEM ek failed FIPS
    /// 203 validation).
    InvalidPubkey,
    /// Malformed hybrid ciphertext length.
    InvalidCiphertext,
    /// Malformed secret key seed length.
    InvalidSecret,
}

impl fmt::Display for KemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KemError::InvalidPubkey => "kem: invalid hybrid public key",
            KemError::InvalidCiphertext => "kem: invalid hybrid ciphertext",
            KemError::InvalidSecret => "kem: invalid hybrid secret key bytes",
        })
    }
}

impl std::error::Error for KemError {}

/// Hybrid shared secret (the 32B OKM after HKDF-SHA256 confluence).
/// Usable directly as an AES-256 key (envelope v2 does exactly this,
/// §1.3.3b).
///
/// Secret-material discipline (§1.3.3c zeroization commitment): **`Copy`
/// is deliberately not implemented** (blocking accidental paths that copy
/// key bytes by value; by-reference passing and explicit `clone` are
/// unaffected); zeroized explicitly on Drop ([`zeroize::Zeroize`], the same
/// implementation as [`SealedShared::zeroize`]).
#[derive(Clone, PartialEq, Eq)]
pub struct SealedShared([u8; SHARED_LEN]);

impl SealedShared {
    /// Raw 32B (the caller is responsible for usage domain separation; use
    /// a separate HKDF pass for cross-purpose derivation).
    pub fn as_bytes(&self) -> &[u8; SHARED_LEN] {
        &self.0
    }
}

impl zeroize::Zeroize for SealedShared {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SealedShared {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for SealedShared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not leak key contents
        f.write_str("SealedShared(***)")
    }
}

/// Hybrid keypair: X25519 static + ML-KEM-768 decapsulation key.
///
/// Serialization ([`HybridKeypair::to_bytes`]) = 32B X25519 secret key ‖ 64B
/// ML-KEM seed (d‖z); persisting the secret key file with 0600 is the
/// caller's responsibility.
pub struct HybridKeypair {
    x25519: StaticSecret,
    ml_kem: DecapsulationKey<MlKem768>,
}

impl HybridKeypair {
    /// Generate a new hybrid keypair (all randomness drawn from `rng`).
    pub fn generate(rng: &mut impl rand::TryCryptoRng) -> Self {
        let x = StaticSecret::random_from_rng(&mut bridge(rng));
        let dk = MlKem768::generate_keypair_from_rng(&mut bridge(rng)).0;
        HybridKeypair {
            x25519: x,
            ml_kem: dk,
        }
    }

    /// Restore from the 96B produced by [`HybridKeypair::to_bytes`].
    pub fn from_bytes(bytes: &[u8; HYBRID_SK_LEN]) -> Result<Self, KemError> {
        let (x, seed) = bytes.split_at(X25519_PUB_LEN);
        let x: [u8; 32] = x.try_into().expect("96B split");
        let seed: [u8; 64] = seed.try_into().expect("96B split");
        Ok(HybridKeypair {
            x25519: StaticSecret::from(x),
            ml_kem: DecapsulationKey::from_seed(seed.into()),
        })
    }

    /// 96B serialization (32B X25519 sk ‖ 64B ML-KEM seed). Key material —
    /// mind the on-disk permissions.
    pub fn to_bytes(&self) -> [u8; HYBRID_SK_LEN] {
        let mut out = [0u8; HYBRID_SK_LEN];
        out[..32].copy_from_slice(&self.x25519.to_bytes());
        out[32..].copy_from_slice(&self.ml_kem.to_bytes());
        out
    }

    /// The corresponding hybrid public key (1216B).
    pub fn public(&self) -> HybridPubkey {
        let mut bytes = [0u8; HYBRID_PUB_LEN];
        let x_pub = PublicKey::from(&self.x25519);
        bytes[..32].copy_from_slice(&x_pub.to_bytes());
        bytes[32..].copy_from_slice(&self.ml_kem.encapsulation_key().to_bytes());
        HybridPubkey {
            x25519: x_pub,
            ml_kem: self.ml_kem.encapsulation_key().clone(),
            bytes,
        }
    }

    /// Reference to the static X25519 secret key. The session handshake's
    /// split mode (§1.3.3c: X25519(e,s_srv) and ML-KEM ct carried
    /// separately) needs to take the X25519 share alone for DH, hence the
    /// read-only access.
    ///
    /// **Will converge** (later phase of the flock-sync migration): the
    /// access surface for the split mode will be unified onto
    /// [`HybridKeypair::seed_material`]/
    /// [`HybridKeypair::from_seed_material`] with the handshake
    /// internalized; this accessor stays `pub` unchanged in the interim to
    /// keep the transition compatible.
    pub fn x25519_secret(&self) -> &StaticSecret {
        &self.x25519
    }

    /// Reference to the ML-KEM-768 decapsulation key (as above, direct
    /// access for the split mode; **will converge** — see the convergence
    /// note on [`HybridKeypair::x25519_secret`]).
    pub fn ml_kem_decapsulation(&self) -> &DecapsulationKey<MlKem768> {
        &self.ml_kem
    }

    /// Split-mode seed material (64B = X25519 secret key 32B ‖ ML-KEM d
    /// 32B).
    ///
    /// **Split mode only** (§1.3.3c: the handshake uses the server's static
    /// hybrid key with X25519(e,s_srv) and ML-KEM ct carried separately):
    /// flock-sync's static key distribution/migration uses these 64B as the
    /// carrier (the full 96B secret key serialization remains
    /// [`HybridKeypair::to_bytes`] — the complete form including ML-KEM's
    /// z).
    ///
    /// Round-trip semantics: [`HybridKeypair::from_seed_material`]
    /// consuming this output yields an **equivalent** keypair — public key
    /// byte-for-byte identical, decapsulation of legitimate ciphertexts
    /// byte-for-byte identical; ML-KEM's z (which in FIPS 203 participates
    /// only in implicit rejection of bogus ciphertexts and never enters the
    /// public key or the legitimate decapsulation path) is re-derived
    /// deterministically from the seed, differing from the original key's
    /// random z.
    pub fn seed_material(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x25519.to_bytes());
        let ml = self.ml_kem.to_bytes(); // 64B = d‖z
        out[32..].copy_from_slice(&ml[..32]);
        out
    }

    /// Inverse of [`HybridKeypair::seed_material`] (see its docs for the
    /// equivalent-keypair semantics). Deterministic: the same seed always
    /// rebuilds the same keypair.
    pub fn from_seed_material(seed: &[u8; 64]) -> Self {
        let x: [u8; 32] = seed[..32].try_into().expect("64B seed split");
        let d: [u8; 32] = seed[32..].try_into().expect("64B seed split");
        // Deterministic re-derivation of z (domain separation label): the
        // legitimate paths (public key, decapsulation of legitimate
        // ciphertexts) are determined entirely by d.
        let mut h = Sha256::new();
        h.update(L_SEED_Z);
        h.update(seed);
        let z: [u8; 32] = h.finalize().into();
        let mut ml_seed = [0u8; 64];
        ml_seed[..32].copy_from_slice(&d);
        ml_seed[32..].copy_from_slice(&z);
        HybridKeypair {
            x25519: StaticSecret::from(x),
            ml_kem: DecapsulationKey::from_seed(ml_seed.into()),
        }
    }
}

impl fmt::Debug for HybridKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridKeypair")
            .field("public", &fingerprint(&self.public()))
            .finish()
    }
}

/// Hybrid public key: 1216B on the wire = 32(X25519) ‖ 1184(ML-KEM-768 ek).
///
/// [`HybridPubkey::from_bytes`] runs the FIPS 203 ek validation (ml-kem
/// `EncapsulationKey::new`) and rejects malformed public keys.
#[derive(Clone)]
pub struct HybridPubkey {
    x25519: PublicKey,
    ml_kem: EncapsulationKey<MlKem768>,
    bytes: [u8; HYBRID_PUB_LEN],
}

impl HybridPubkey {
    /// Restore from the 1216 wire bytes (including ML-KEM ek structural
    /// validation).
    pub fn from_bytes(bytes: &[u8; HYBRID_PUB_LEN]) -> Result<Self, KemError> {
        let (x, ek) = bytes.split_at(X25519_PUB_LEN);
        let ek_arr: [u8; ML_KEM_EK_LEN] = ek.try_into().expect("1216B split");
        let key = Key::<EncapsulationKey<MlKem768>>::try_from(ek_arr.as_slice()).expect("1184B ek");
        let ml_kem =
            EncapsulationKey::<MlKem768>::new(&key).map_err(|_| KemError::InvalidPubkey)?;
        // Any 32B is a valid X25519 public key (low-order points are caught
        // after diffie_hellman by the was_contributory backstop)
        let x_arr: [u8; X25519_PUB_LEN] = x.try_into().expect("1216B split");
        Ok(HybridPubkey {
            x25519: PublicKey::from(x_arr),
            ml_kem,
            bytes: *bytes,
        })
    }

    /// The 1216 wire bytes (canonical layout, directly sendable).
    pub fn to_bytes(&self) -> [u8; HYBRID_PUB_LEN] {
        self.bytes
    }

    /// The X25519 public key portion (the counterpart of the first 32B of
    /// the 1216B). Used by the session handshake split mode (§1.3.3c).
    pub fn x25519_public(&self) -> &PublicKey {
        &self.x25519
    }

    /// The ML-KEM-768 encapsulation key portion. Used by the session
    /// handshake to encapsulate a 1088B ct against the server's static
    /// ML-KEM public key.
    pub fn ml_kem_encapsulation(&self) -> &EncapsulationKey<MlKem768> {
        &self.ml_kem
    }
}

impl fmt::Debug for HybridPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridPubkey(")?;
        for b in fingerprint(self).as_bytes().iter().take(4) {
            write!(f, "{b:02x}")?;
        }
        f.write_str("…)")
    }
}

/// Hybrid ciphertext: 1120B = 32(ephemeral X25519 public key) ‖
/// 1088(ML-KEM-768 ct).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HybridCt([u8; HYBRID_CT_LEN]);

impl HybridCt {
    /// Restore from the 1120 wire bytes (length check only; any 1088B is
    /// legitimate ML-KEM ct input — implicit rejection semantics).
    pub fn from_bytes(bytes: &[u8; HYBRID_CT_LEN]) -> Self {
        HybridCt(*bytes)
    }

    /// The 1120 wire bytes.
    pub fn to_bytes(&self) -> [u8; HYBRID_CT_LEN] {
        self.0
    }
}

impl fmt::Debug for HybridCt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HybridCt").field(&"..1120B..").finish()
    }
}

/// Public key fingerprint: SHA-256(1216B canonical public key). For pinning
/// and display (§3.8 display format = 8 hex groups).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Construct from an existing 32B digest (the session side reuses the
    /// same display format for fingerprints of cluster-root/identity
    /// Ed25519 public keys).
    pub fn from_digest(bytes: [u8; 32]) -> Self {
        Fingerprint(bytes)
    }
}

impl Fingerprint {
    /// Raw 32B.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    /// Display format: 8 groups of 8 hex characters, colon-separated (§3.8
    /// "8 hex groups" pinning display convention).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hexs = hex::encode(self.0);
        for i in 0..8 {
            if i > 0 {
                f.write_str(":")?;
            }
            f.write_str(&hexs[i * 8..i * 8 + 8])?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

/// Encapsulation: produce a one-time shared secret and hybrid ciphertext
/// for `pk` (all randomness drawn from `rng`).
///
/// The correct way to use this for one-time envelope/handshake sharing:
/// call once per envelope/handshake and discard the `SealedShared` after
/// use.
pub fn encapsulate(
    pk: &HybridPubkey,
    rng: &mut impl rand::TryCryptoRng,
) -> (SealedShared, HybridCt) {
    let eph = EphemeralSecret::random_from_rng(&mut bridge(rng));
    let eph_pub = PublicKey::from(&eph);
    let (ml_ct, ml_ss) = pk.ml_kem.encapsulate_with_rng(&mut bridge(rng));
    let x_ss = eph.diffie_hellman(&pk.x25519);

    let mut ct_bytes = [0u8; HYBRID_CT_LEN];
    ct_bytes[..32].copy_from_slice(&eph_pub.to_bytes());
    ct_bytes[32..].copy_from_slice(ml_ct.as_slice());

    let shared = combine(x_ss.as_bytes(), ml_ss.as_slice());
    (shared, HybridCt(ct_bytes))
}

/// Decapsulation. `None` only when the X25519 side is non-contributory
/// (small-subgroup attack surface; never occurs in honest traffic) — the
/// ML-KEM side returns a pseudo-random key per FIPS 203 implicit rejection,
/// backstopped by the upper-layer AEAD authentication.
pub fn decapsulate(sk: &HybridKeypair, ct: &HybridCt) -> Option<SealedShared> {
    let (eph, ml_ct) = ct.0.split_at(X25519_PUB_LEN);
    let eph_arr: [u8; X25519_PUB_LEN] = eph.try_into().expect("1120B split");
    let eph_pub = PublicKey::from(eph_arr);
    let x_ss = sk.x25519.diffie_hellman(&eph_pub);
    if !x_ss.was_contributory() {
        return None;
    }
    let ml_ct: Ciphertext<MlKem768> = ml_ct.try_into().ok()?;
    let ml_ss = sk.ml_kem.decapsulate(&ml_ct);
    Some(combine(x_ss.as_bytes(), ml_ss.as_slice()))
}

/// Public key fingerprint (SHA-256 over the 1216B canonical public key).
pub fn fingerprint(pk: &HybridPubkey) -> Fingerprint {
    Fingerprint(Sha256::digest(pk.to_bytes()).into())
}

/// HKDF-SHA256 confluence: ikm = x25519_ss ‖ ml_kem_ss (fixed order,
/// §1.3.3a). The ikm is the concatenation of both shared secrets — wrapped
/// in `Zeroizing`, zeroized on Drop (§1.3.3c key discipline).
fn combine(x_ss: &[u8], ml_ss: &[u8]) -> SealedShared {
    use hkdf::Hkdf;
    let mut ikm = zeroize::Zeroizing::new(Vec::with_capacity(x_ss.len() + ml_ss.len()));
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(ml_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm[..]);
    let mut okm = [0u8; SHARED_LEN];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("32B OKM is always valid");
    SealedShared(okm)
}

/// Private rand 0.9 → rand_core 0.10 bridge (the RNG generation of ml-kem /
/// x25519-dalek 3.0). The target side requires infallibility (rc010
/// CryptoRng ⇒ Error=Infallible), so an inner entropy-source failure panics
/// directly (same semantics as rand_core's `UnwrapErr` adapter).
pub(crate) struct RngBridge<'a, R: rand::TryRngCore + ?Sized>(&'a mut R);

pub(crate) fn bridge<R: rand::TryRngCore + ?Sized>(rng: &mut R) -> RngBridge<'_, R> {
    RngBridge(rng)
}

impl<R: rand::TryRngCore + ?Sized> rc010::TryRng for RngBridge<'_, R> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self
            .0
            .try_next_u32()
            .expect("flock-protocol: entropy source failed"))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self
            .0
            .try_next_u64()
            .expect("flock-protocol: entropy source failed"))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.0
            .try_fill_bytes(dst)
            .expect("flock-protocol: entropy source failed");
        Ok(())
    }
}

// rc010's TryCryptoRng is a marker trait with no methods and no blanket
// impl — the explicit declaration is required
impl<R: rand::TryRngCore + ?Sized> rc010::TryCryptoRng for RngBridge<'_, R> {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn keypair() -> HybridKeypair {
        HybridKeypair::generate(&mut OsRng) // OsRng: TryCryptoRng, passable directly
    }

    #[test]
    fn roundtrip_and_sizes() {
        let sk = keypair();
        let pk = sk.public();
        assert_eq!(
            pk.to_bytes().len(),
            1216,
            "hybrid public key is 1216B on the wire"
        );
        let (ss1, ct) = encapsulate(&pk, &mut OsRng);
        assert_eq!(ct.to_bytes().len(), 1120, "hybrid ciphertext is 1120B");
        let ss2 = decapsulate(&sk, &ct).expect("decapsulate");
        assert_eq!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "both sides derive the same shared secret"
        );
    }

    #[test]
    fn keypair_serialization_roundtrip() {
        let sk = keypair();
        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), 96, "secret key is 96B = 32 + 64(d‖z)");
        let sk2 = HybridKeypair::from_bytes(&bytes).expect("restore");
        let (ss1, ct) = encapsulate(&sk.public(), &mut OsRng);
        let ss2 = decapsulate(&sk2, &ct).expect("decapsulate");
        assert_eq!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "restored secret key can decapsulate"
        );
    }

    #[test]
    fn pubkey_from_bytes_rejects_malformed_ek() {
        // All-0xFF fill: every 12-bit t coefficient = 4095 > q-1=3328 ⇒
        // decodeAndCheck must reject (deterministic)
        assert!(
            HybridPubkey::from_bytes(&[0xFFu8; 1216]).is_err(),
            "out-of-range t coefficients must be rejected by FIPS 203 ek validation"
        );
        let sk = keypair();
        let good = HybridPubkey::from_bytes(&sk.public().to_bytes()).expect("valid pk");
        assert_eq!(
            good.to_bytes(),
            sk.public().to_bytes(),
            "legitimate public key round-trips byte-for-byte"
        );
    }

    #[test]
    fn ct_tamper_gives_different_shared() {
        let sk = keypair();
        let (ss1, ct) = encapsulate(&sk.public(), &mut OsRng);
        let mut b = ct.to_bytes();
        b[32 + 100] ^= 0x01; // flip inside the ML-KEM ct region
        let ss2 = decapsulate(&sk, &HybridCt::from_bytes(&b))
            .expect("implicit rejection still returns a pseudo-random key");
        assert_ne!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "tampered ciphertext must yield a different shared secret"
        );
    }

    #[test]
    fn ephemeral_freshness() {
        // Two encapsulations against the same public key: differing
        // ephemeral shares ⇒ different shared secrets and different
        // ciphertexts (premise of one-time semantics)
        let sk = keypair();
        let (ss1, ct1) = encapsulate(&sk.public(), &mut OsRng);
        let (ss2, ct2) = encapsulate(&sk.public(), &mut OsRng);
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
        assert_ne!(ct1.to_bytes(), ct2.to_bytes());
    }

    #[test]
    fn fingerprint_stable_and_display() {
        let sk = keypair();
        let fp1 = fingerprint(&sk.public());
        assert_eq!(
            fp1,
            fingerprint(&sk.public()),
            "fingerprint is deterministic"
        );
        let pk2 = HybridPubkey::from_bytes(&sk.public().to_bytes()).unwrap();
        assert_eq!(
            fp1,
            fingerprint(&pk2),
            "fingerprint unchanged after public key serialization round-trip"
        );
        let s = fp1.to_string();
        assert_eq!(s.split(':').count(), 8, "8-group display");
        assert!(s
            .split(':')
            .all(|g| g.len() == 8 && g.bytes().all(|b| b.is_ascii_hexdigit())));
        let sk3 = keypair();
        assert_ne!(
            fp1,
            fingerprint(&sk3.public()),
            "different keys have different fingerprints"
        );
    }

    #[test]
    fn cross_keypair_shared_mismatch() {
        let (sk_a, sk_b) = (keypair(), keypair());
        let (ss, ct) = encapsulate(&sk_a.public(), &mut OsRng);
        let ss_b = decapsulate(&sk_b, &ct).expect("implicit-rejection pseudo-random key");
        assert_ne!(
            ss.as_bytes(),
            ss_b.as_bytes(),
            "a third party cannot obtain the same shared secret"
        );
    }

    /// Zeroization discipline (§1.3.3c): after explicit zeroize, all 32B of
    /// SealedShared are zero (the Drop path uses the same implementation).
    #[test]
    fn sealed_shared_zeroize_clears_material() {
        let sk = keypair();
        let (mut ss, _ct) = encapsulate(&sk.public(), &mut OsRng);
        assert!(
            ss.as_bytes().iter().any(|&b| b != 0),
            "precondition: encapsulation output is not all-zero (otherwise the assertion is vacuous)"
        );
        zeroize::Zeroize::zeroize(&mut ss);
        assert!(
            ss.as_bytes().iter().all(|&b| b == 0),
            "zeroize must cover all 32B of shared secret material"
        );
    }

    /// seed_material round-trip (split mode only, the flock-sync migration
    /// carrier): equivalent keypair — public key byte-for-byte identical,
    /// legitimate ciphertext decapsulation identical; rebuild is
    /// deterministic; different seeds give different public keys.
    #[test]
    fn seed_material_roundtrip_equivalent_and_deterministic() {
        let sk = keypair();
        let seed = sk.seed_material();
        let sk2 = HybridKeypair::from_seed_material(&seed);
        assert_eq!(
            sk2.public().to_bytes(),
            sk.public().to_bytes(),
            "equivalent: public key byte-for-byte identical"
        );
        let (ss1, ct) = encapsulate(&sk.public(), &mut OsRng);
        let ss2 = decapsulate(&sk2, &ct).expect("equivalent key can decapsulate");
        assert_eq!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "equivalent: legitimate ciphertext decapsulation identical"
        );

        // Determinism: rebuilding twice from the same seed gives the same
        // public key.
        let sk3 = HybridKeypair::from_seed_material(&seed);
        assert_eq!(sk3.public().to_bytes(), sk2.public().to_bytes());

        // Different seed ⇒ different public key (flip a mid-range byte bit:
        // X25519 scalar clamping erases the low 3 bits of the first byte, a
        // bit0 flip would be swallowed by clamping — choose a byte position
        // that always survives).
        let mut other = seed;
        other[10] ^= 0x01;
        assert_ne!(
            HybridKeypair::from_seed_material(&other)
                .public()
                .to_bytes(),
            sk2.public().to_bytes()
        );

        // 96B to_bytes/from_bytes remains the full lossless serialization
        // (coexisting with the 64B seed carrier).
        let full = HybridKeypair::from_bytes(&sk.to_bytes()).expect("full serialization");
        assert_eq!(full.public().to_bytes(), sk.public().to_bytes());
    }
}
