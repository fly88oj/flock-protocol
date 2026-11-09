//! showroom 3.0.0 fixed-vector interop (**M1 hard gate**, §7-M1 / §3.4 /
//! P1-6 / P0-1 compatibility tier).
//!
//! Vector file [`tests/vectors/showroom-3.0.0.json`] (committed with the
//! library): real showroom-common 3.0.0 artifacts (generated once inside
//! a Linux container; dependency generations opaque-ke 3.0.0 / rsa
//! 0.9.10 / aes-gcm 0.10.3 / ed25519-dalek 2.2.0 / rand 0.8.8).
//!
//! **OPAQUE** (P1-6): 4.0.1 must decrypt 3.0.0 registration records and
//! complete the login — `server_setup_migrate_v3` (the dummy sk→pk
//! layout migration; OPRF seed/KE sk preserved byte-for-byte) +
//! `server_record_from_b64` (record layout unchanged) + the full
//! ke1→ke2→ke3 flow; and it asserts that rwd (P2-11 profile parameters)
//! is byte-for-byte identical to showroom's.
//!
//! The sig/envelope v1 segments test the same assertion classes as the
//! inline fixtures of [`tests/showroom_vectors.rs`] (3.0.0 sample
//! verification / unsealing of seal outputs) and have been merged into
//! that file (ponytail dedup); the sig/envelope_v1 fields in the JSON
//! are kept as generation records.

use flock_protocol::pake;
use rand::rngs::OsRng;

const VECTOR: &str = include_str!("vectors/showroom-3.0.0.json");

fn v() -> serde_json::Value {
    serde_json::from_str(VECTOR).expect("vector JSON parse")
}

/// P1-6 hard gate: a showroom 3.0.0 registration record + opaque.key
/// complete a full login under 4.0.1.
#[test]
fn opaque_3_0_0_record_login_under_4_0_1() {
    let j = v();
    let (user, password) = (
        j["opaque"]["user"].as_str().unwrap(),
        j["opaque"]["password"].as_str().unwrap(),
    );
    let setup_b64 = j["opaque"]["server_setup_b64"].as_str().unwrap();
    let record_b64 = j["opaque"]["record_b64"].as_str().unwrap();
    let rwd_hex = j["opaque"]["rwd_hex"].as_str().unwrap();

    // rwd profile parameters byte-for-byte identical to showroom (P2-11:
    // Profile::Owasp19MiB compatibility default)
    let r = pake::rwd(password, user, pake::Profile::Owasp19MiB).unwrap();
    assert_eq!(
        hex::encode(r),
        rwd_hex,
        "rwd(pw,user,Owasp19MiB) must match showroom 3.0.0"
    );

    // ServerSetup 3.0.0 → 4.0.1 migration (dummy segment sk→pk; OPRF
    // seed/KE sk preserved)
    let setup = pake::server_setup_migrate_v3(setup_b64)
        .expect("the 3.0.0 opaque.key must be migratable (P1-6)");

    // The 3.0.0 registration record loads directly (layout unchanged)
    let record = pake::server_record_from_b64(record_b64)
        .expect("the 3.0.0 pass.opaque must deserialize under 4.0.1 (P1-6 hard gate)");

    // Full login: ke1 → ke2 (against the 3.0.0 record) → ke3 → server
    // verification
    let mut rng = OsRng;
    let (lstate, ke1) = pake::login_start(&mut rng, password, user).unwrap();
    let (ke2, sstate) =
        pake::server_login_start(&mut rng, &setup, Some(&record), &ke1, user).unwrap();
    let ke3 = pake::login_finish(lstate, password, user, &ke2).expect(
        "the 4.0.1 client must complete the login against the 3.0.0 record (P1-6 hard gate)",
    );
    pake::server_login_finish(&sstate, &ke3).expect("ke3 must pass 4.0.1 server verification");
}

/// Negative vector: the same 3.0.0 record + wrong password ⇒ the
/// client's local finish fails (a decryptable record ≠ a guessable
/// password).
#[test]
fn opaque_3_0_0_record_wrong_password_rejected() {
    let j = v();
    let user = j["opaque"]["user"].as_str().unwrap();
    let setup =
        pake::server_setup_migrate_v3(j["opaque"]["server_setup_b64"].as_str().unwrap()).unwrap();
    let record = pake::server_record_from_b64(j["opaque"]["record_b64"].as_str().unwrap()).unwrap();
    let mut rng = OsRng;
    let (lstate, ke1) = pake::login_start(&mut rng, "wrong-password", user).unwrap();
    let (ke2, _s) = pake::server_login_start(&mut rng, &setup, Some(&record), &ke1, user).unwrap();
    assert!(pake::login_finish(lstate, "wrong-password", user, &ke2).is_err());
}
