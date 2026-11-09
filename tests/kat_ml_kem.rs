//! ml-kem official KAT replay (M1 completion criteria: hybrid KEM round
//! trip + ml-kem official KAT replay, §7-M1; P0-1).
//!
//! Data file [`kat_ml_kem_data`] (first 5 keyGen + first 5 encapsulation
//! entries; NIST ACVP FIPS203 official vectors, via the official test
//! data of RustCrypto/KEMs ml-kem 0.3.3). The replay has three layers:
//!
//! 1. **keyGen**: `DecapsulationKey::from_seed(d‖z)` → ek byte-for-byte
//!    equal to the official ek (1184B);
//! 2. **encapsulation**: `EncapsulationKey::new(ek)` +
//!    `encapsulate_deterministic(m)` → (ct, k) byte-for-byte equal to
//!    the official (c, k);
//! 3. **decapsulation**: the expanded-form dk (2400B, the ACVP record
//!    form) → `from_expanded` + `decapsulate(c)` → k equal to the
//!    official k. `from_expanded` is already deprecated in ml-kem 0.3.3
//!    (from_seed recommended), but the expanded form is the official ACVP
//!    record form and the replay must go through it — a local
//!    `#[allow(deprecated)]`.
//!
//! The same KAT also validates the correctness premise of the hybrid KEM
//! encapsulation: the official ek/ct sizes = 1184/1088, consistent with
//! the X25519 (32B) concatenation layout of `kem::HybridPubkey`
//! (1216B)/`kem::HybridCt` (1120B) (§1.3.3a).

// The official ACVP record form is the 2400B expanded dk; the replay must
// go through the ExpandedKeyEncoding interface that ml-kem 0.3.3 has
// already deprecated — file-level exemption (the from_seed path in
// production code in kem.rs never uses the expanded form).
#![allow(deprecated)]

#[path = "kat_ml_kem_data.rs"]
mod kat_ml_kem_data;

use flock_protocol::kem;
use flock_protocol::ml_kem::ExpandedKeyEncoding;
use flock_protocol::ml_kem::{
    ml_kem_768::MlKem768, Decapsulate, DecapsulationKey, EncapsulationKey, Key, KeyExport,
};

/// keyGen: seed(d‖z) → ek reproduces the official vectors
/// byte-for-byte.
#[test]
fn kat_keygen() {
    for (i, (d, z, ek_hex)) in kat_ml_kem_data::KEYGEN.iter().enumerate() {
        let mut seed = [0u8; 64];
        let dv = hex::decode(d).unwrap();
        let zv = hex::decode(z).unwrap();
        seed[..32].copy_from_slice(&dv);
        seed[32..].copy_from_slice(&zv);
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed.into());
        let ek = dk.encapsulation_key();
        let ek_bytes = ek.to_bytes();
        assert_eq!(ek_bytes.len(), 1184, "tc{i}: ek size");
        assert_eq!(
            hex::encode(ek_bytes.as_slice()),
            *ek_hex.to_ascii_lowercase(),
            "tc{i}: ek byte-for-byte reproduction failed"
        );
        // The expanded dk size (2400B) is strongly constrained by the
        // dk_arr: [u8; 2400] decode in kat_encap_and_decap
    }
}

/// encapsulation/decapsulation: official ek/m → (c,k) byte-for-byte
/// reproduction; expanded dk → decapsulate(c)=k.
#[test]
fn kat_encap_and_decap() {
    for (i, (ek_hex, dk_hex, m_hex, c_hex, k_hex)) in kat_ml_kem_data::ENCAP.iter().enumerate() {
        let ek_arr: [u8; 1184] = hex::decode(ek_hex).unwrap().try_into().unwrap();
        let ek = EncapsulationKey::<MlKem768>::new(
            &Key::<EncapsulationKey<MlKem768>>::try_from(ek_arr.as_slice()).unwrap(),
        )
        .unwrap();
        let m: [u8; 32] = hex::decode(m_hex).unwrap().try_into().unwrap();
        // encapsulate_deterministic is the deterministic entry point for
        // the official KAT replay (a doc(hidden) public API)
        let (ct, k) = ek.encapsulate_deterministic(&m.into());
        assert_eq!(ct.as_slice().len(), 1088, "tc{i}: ct size");
        assert_eq!(
            hex::encode(ct.as_slice()),
            c_hex.to_ascii_lowercase(),
            "tc{i}: ct reproduction"
        );
        assert_eq!(
            hex::encode(k.as_slice()),
            k_hex.to_ascii_lowercase(),
            "tc{i}: k reproduction"
        );

        // decap: expanded-form dk (the ACVP record form)
        let dk_arr: [u8; 2400] = hex::decode(dk_hex).unwrap().try_into().unwrap();
        let dk = <DecapsulationKey<MlKem768> as ExpandedKeyEncoding>::from_expanded_bytes(
            &dk_arr.into(),
        )
        .unwrap();
        let k2 = dk.decapsulate(&ct);
        assert_eq!(
            hex::encode(k2.as_slice()),
            k_hex.to_ascii_lowercase(),
            "tc{i}: decap k reproduction"
        );
    }
}

/// Hybrid KEM vs KAT size consistency: the official ek/ct sizes embedded
/// into the hybrid layout = 1216B public key / 1120B ciphertext, and
/// `HybridPubkey::from_bytes` accepts the official vector ek (passes
/// FIPS 203 validation).
#[test]
fn hybrid_sizes_match_kat() {
    assert_eq!(kem::ML_KEM_EK_LEN, 1184);
    assert_eq!(kem::ML_KEM_CT_LEN, 1088);
    assert_eq!(kem::HYBRID_PUB_LEN, 1216);
    assert_eq!(kem::HYBRID_CT_LEN, 1120);
    // An official vector ek passes hybrid public-key validation (X25519
    // side filled with a 32B constant placeholder)
    let ek_arr: [u8; 1184] = hex::decode(kat_ml_kem_data::ENCAP[0].0)
        .unwrap()
        .try_into()
        .unwrap();
    let mut hybrid = [0u8; 1216];
    hybrid[32..].copy_from_slice(&ek_arr);
    kem::HybridPubkey::from_bytes(&hybrid).expect("the official ek must pass FIPS 203 validation");
    // The hybrid encapsulation/decapsulation round trip is covered by the
    // src/kem.rs unit test roundtrip_and_sizes (the official vectors have
    // no companion X25519 private keys; ACVP covers only ML-KEM itself) —
    // here we only guard "an official ek fits the hybrid layout".
}
