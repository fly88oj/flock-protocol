//! The wasm C-ABI shim for the M8b Web UI (docs/design.md §7-M8.6
//! contract verbatim; the showroom `wasm_shim.rs` technique — no
//! wasm-bindgen, JS glue calls straight through the C-ABI).
//!
//! Compilation gate (one explicit extension of the design §M8.6's literal
//! `wasm + wasm32`): the `wasm` **and** `anchor` features (login_finish's
//! anchor verification depends on the `pake::anchor` surface), target
//! `wasm32` **or** `test` (native unit tests call the shim functions
//! directly to run the full OPAQUE flow — with injected fixed entropy;
//! see mod tests). Build profile (§M8.1):
//! `cargo build -p flock-protocol --target wasm32-unknown-unknown
//!  --no-default-features --features wasm,anchor` (no zstd ⇒ zero C
//! dependencies).
//!
//! Contract (§M8.6 verbatim):
//! ```text
//! sr_wasm_inject_entropy(ptr: *const u8, len: usize)
//! sr_wasm_alloc(len: usize) -> *mut u8 / sr_wasm_free(ptr, len)
//! sr_web_login_begin(user_ptr, user_len, pw_ptr, pw_len, out_ptr, out_cap) -> i32
//! sr_web_login_finish(ke2_ptr, ke2_len, server_id_ptr(16B), identity_pub_ptr(32B),
//!                     bind_token_ptr(16B), anchor_sig_ptr(64B), out_ptr, out_cap) -> i32
//! sr_web_pw_begin(user_ptr, user_len, pw_ptr, pw_len, out_ptr, out_cap) -> i32
//! sr_web_pw_finish(m2_ptr, m2_len, out_ptr, out_cap) -> i32
//! error codes: -1 no entropy injected; -2 pake failure (wrong password/bad message share the code);
//!              -3 anchor verification rejected; -4 out capacity insufficient. 0 = ok;
//! out receives the b64 message (NUL-terminated).
//! ```
//!
//! Entropy pool: this module holds its own `Mutex<Option<StdRng>>` (same
//! folding algorithm as [`crate::wasm_bridge`]), driving the explicit
//! RNG of login_start/reg_start; under wasm32,
//! `sr_wasm_inject_entropy` **writes both pools** — the wasm_bridge pool
//! serves the getrandom surface (the `rand::rng()` inside
//! `pake::login_finish` draws entropy via the custom backend on wasm32).
//! On native (test), getrandom uses the OS entropy source and only the
//! shim pool participates in the fixed-injected-entropy assertions.
//!
//! Single state slot (§M8.6): ClientLogin/ClientRegistration live in a
//! module-level single slot; a later begin overwrites the earlier one;
//! finish consumes (take) and reuses the user/pw cached at begin time
//! (rwd needs both, and the C-ABI finish signature does not re-pass them
//! — the same tradeoff as showroom).

use std::sync::Mutex;

use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::pake::{self, Profile, Suite};

// ============================================================================
// Error codes (fixed by §M8.6)
// ============================================================================

/// -1: no entropy injected.
pub const ERR_NO_ENTROPY: i32 = -1;
/// -2: pake failure (wrong password/bad message share the code — no
/// reason leaked).
pub const ERR_PAKE: i32 = -2;
/// -3: anchor verification rejected (fake server / wrong-cluster
/// response mix-up).
pub const ERR_ANCHOR: i32 = -3;
/// -4: out capacity insufficient.
pub const ERR_CAPACITY: i32 = -4;

// ============================================================================
// Entropy pool (shim-owned; seeded into both pools at once together with
// the wasm_bridge pool under wasm32)
// ============================================================================

static POOL: Mutex<Option<StdRng>> = Mutex::new(None);

/// Fold entropy into a 32B seed (same algorithm as
/// [`crate::wasm_bridge::inject_entropy`] — position-dependent rotation;
/// every byte of an over-long input influences the seed).
fn pool_inject(bytes: &[u8]) {
    let mut seed = [0u8; 32];
    for (i, b) in bytes.iter().enumerate() {
        seed[i % 32] ^= b.rotate_left(((i / 32) % 8) as u32);
    }
    *POOL.lock().expect("webauth_shim pool lock") = Some(StdRng::from_seed(seed));
}

/// Run with the pool's RNG (no entropy injected ⇒ -1; the lock is held
/// for the duration — single-threaded wasm has no contention surface,
/// and native tests make no concurrent shim calls either).
fn with_pool<T>(f: impl FnOnce(&mut StdRng) -> Result<T, i32>) -> Result<T, i32> {
    let mut g = POOL.lock().expect("webauth_shim pool lock");
    match g.as_mut() {
        Some(rng) => f(rng),
        None => Err(ERR_NO_ENTROPY),
    }
}

// ============================================================================
// Single state slot (a later begin overwrites the earlier one; finish
// consumes)
// ============================================================================

struct LoginSlot {
    state: crate::opaque_ke::ClientLogin<Suite>,
    user: String,
    pw: String,
}

struct RegSlot {
    state: crate::opaque_ke::ClientRegistration<Suite>,
    user: String,
    pw: String,
}

static LOGIN_SLOT: Mutex<Option<LoginSlot>> = Mutex::new(None);
static REG_SLOT: Mutex<Option<RegSlot>> = Mutex::new(None);

// ============================================================================
// C-ABI surface (all #[no_mangle] pub extern "C"; exports taking raw
// pointers are uniformly unsafe fn — the caller (JS glue/native tests)
// guarantees valid buffers per the contract; symbol names/ABI unaffected)
// ============================================================================

/// Entropy injection (JS calls it at startup: crypto.getRandomValues
/// with at least 32B). Under wasm32 also seeds the wasm_bridge pool at
/// the same moment (the getrandom custom backend — the entropy path
/// inside `rand::rng()`).
///
/// # Safety
///
/// `ptr` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn sr_wasm_inject_entropy(ptr: *const u8, len: usize) {
    // SAFETY: JS glue contract — ptr points to len readable bytes
    // (allocated by sr_wasm_alloc or a wasm linear-memory segment written
    // by TextEncoder).
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    pool_inject(bytes);
    #[cfg(target_arch = "wasm32")]
    crate::wasm_bridge::inject_entropy(bytes);
}

/// Buffer allocation for JS to write arguments into and read returns
/// from (zero-capacity semantics: uninitialized allocation; paired with
/// [`sr_wasm_free`]).
#[no_mangle]
pub extern "C" fn sr_wasm_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::with_capacity(len);
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ptr
}

/// Free a buffer from [`sr_wasm_alloc`] (ptr/len must match the
/// allocation).
///
/// # Safety
///
/// ptr must come from [`sr_wasm_alloc`] (same len); no double frees.
#[no_mangle]
pub unsafe extern "C" fn sr_wasm_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: caller contract — ptr came from sr_wasm_alloc(len)
    // (capacity=len); here the Vec is rebuilt with the same parameters
    // and dropped (len=0: the allocation surface is uninitialized, its
    // contents are not read).
    drop(Vec::from_raw_parts(ptr, 0, len));
}

/// Login step 1: user+pw → ke1_b64 (sent as POST /api/login-begin);
/// state goes into the single slot.
///
/// # Safety
///
/// user/pw argument pointers point to their own len readable bytes;
/// out_ptr points to out_cap writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sr_web_login_begin(
    user_ptr: *const u8,
    user_len: usize,
    pw_ptr: *const u8,
    pw_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i32 {
    // SAFETY: unsafe fn body — the contract is carried by the
    // function-level # Safety doc.
    let user = str_from_raw(user_ptr, user_len);
    let pw = str_from_raw(pw_ptr, pw_len);
    let r = with_pool(|rng| {
        let (state, ke1) = pake::login_start(rng, &pw, &user).map_err(|_| ERR_PAKE)?;
        *LOGIN_SLOT.lock().expect("login slot") = Some(LoginSlot { state, user, pw });
        write_out(out_ptr, out_cap, &ke1)?;
        Ok(())
    });
    flatten(r)
}

/// Login finish: ke2 + anchor material → ke3_b64 (anchor verification
/// happens inside wasm — preventing wrong-cluster response mix-ups;
/// identity_pub comes from GET /api/bootstrap). Consumes the login
/// single slot.
///
/// # Safety
///
/// ke2 points to ke2_len readable bytes; server_id/identity_pub/
/// bind_token/anchor_sig point to 16/32/16/64 readable bytes
/// respectively; out_ptr points to out_cap writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sr_web_login_finish(
    ke2_ptr: *const u8,
    ke2_len: usize,
    server_id_ptr: *const u8,
    identity_pub_ptr: *const u8,
    bind_token_ptr: *const u8,
    anchor_sig_ptr: *const u8,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i32 {
    // SAFETY: unsafe fn body — the contract is carried by the
    // function-level # Safety doc.
    let ke2 = str_from_raw(ke2_ptr, ke2_len);
    let server_id = fixed::<16>(server_id_ptr);
    let identity_pub = fixed::<32>(identity_pub_ptr);
    let bind_token = fixed::<16>(bind_token_ptr);
    let anchor_sig = fixed::<64>(anchor_sig_ptr);

    let Some(LoginSlot { state, user, pw }) = LOGIN_SLOT.lock().expect("login slot").take() else {
        return ERR_PAKE; // no in-flight begin (never begun/already consumed) — same code as the pake surface
    };

    // Anchor verification (same canonical as login_finish_anchored:
    // label‖server_id‖len(user)‖user‖ke2‖bind_token). Verified once up
    // front, independently, to distinguish -3 (anchor rejected) from -2
    // (pake rejected) — login_finish_anchored then verifies again
    // internally (same bytes, same key); the success path pays one extra
    // Ed25519 verify for the double check (~50µs magnitude,
    // negligible).
    use crate::ed25519_dalek::Verifier as _;
    let (verifying, signature) = match (
        crate::ed25519_dalek::VerifyingKey::from_bytes(&identity_pub),
        crate::ed25519_dalek::Signature::from_slice(&anchor_sig),
    ) {
        (Ok(v), Ok(s)) => (v, s),
        _ => return ERR_ANCHOR, // bad key/bad signature length classified as verification rejection (no detail leaked)
    };
    let canonical = pake::anchor_canonical_bytes(&server_id, &user, &ke2, &bind_token);
    if verifying.verify(&canonical, &signature).is_err() {
        return ERR_ANCHOR;
    }

    let expect = pake::AnchorExpectation {
        server_id,
        identity_pub: verifying,
        bind_token,
    };
    match pake::login_finish_anchored(
        state,
        &pw,
        &user,
        &ke2,
        Profile::default(), // the Web login client always uses Owasp19MiB (=default, §M8.3)
        &expect,
        &anchor_sig,
    ) {
        Ok(ke3) => match write_out(out_ptr, out_cap, &ke3) {
            Ok(()) => 0,
            Err(c) => c,
        },
        Err(_) => ERR_PAKE,
    }
}

/// Registration step 1 (shared with the password bootstrap flow):
/// user+pw → m1_b64 (sent as POST /api/pw-begin).
/// # Safety
///
/// user/pw argument pointers point to their own len readable bytes;
/// out_ptr points to out_cap writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sr_web_pw_begin(
    user_ptr: *const u8,
    user_len: usize,
    pw_ptr: *const u8,
    pw_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i32 {
    // SAFETY: unsafe fn body — the contract is carried by the
    // function-level # Safety doc.
    let user = str_from_raw(user_ptr, user_len);
    let pw = str_from_raw(pw_ptr, pw_len);
    let r = with_pool(|rng| {
        let (state, m1) = pake::reg_start(rng, &pw, &user).map_err(|_| ERR_PAKE)?;
        *REG_SLOT.lock().expect("reg slot") = Some(RegSlot { state, user, pw });
        write_out(out_ptr, out_cap, &m1)?;
        Ok(())
    });
    flatten(r)
}

/// Registration finish: m2_b64 → record_b64 (sent as POST
/// /api/pw-commit). Consumes the pw single slot.
///
/// # Safety
///
/// m2 points to m2_len readable bytes; out_ptr points to out_cap
/// writable bytes.
/// # Safety
///
/// m2 points to m2_len readable bytes; out_ptr points to out_cap
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sr_web_pw_finish(
    m2_ptr: *const u8,
    m2_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i32 {
    // SAFETY: unsafe fn body — the contract is carried by the
    // function-level # Safety doc.
    let m2 = str_from_raw(m2_ptr, m2_len);
    let Some(RegSlot { state, user, pw }) = REG_SLOT.lock().expect("reg slot").take() else {
        return ERR_PAKE;
    };
    let r = with_pool(|rng| {
        let record = pake::reg_finish(rng, state, &pw, &user, &m2).map_err(|_| ERR_PAKE)?;
        write_out(out_ptr, out_cap, &record)?;
        Ok(())
    });
    flatten(r)
}

// ============================================================================
// Internal helpers (not part of the ABI surface)
// ============================================================================

/// Raw pointer → lossy UTF-8 string (b64/passwords/usernames are all
/// ASCII surfaces; lossy decoding forms no failure path).
///
/// # Safety
///
/// `ptr` must point to `len` readable bytes.
unsafe fn str_from_raw(ptr: *const u8, len: usize) -> String {
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(ptr, len) }).into_owned()
}

/// Raw pointer → fixed-length array (the 16/32/64B surfaces of anchor
/// material/signatures).
///
/// # Safety
///
/// `ptr` must point to `N` readable bytes.
unsafe fn fixed<const N: usize>(ptr: *const u8) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(unsafe { std::slice::from_raw_parts(ptr, N) });
    out
}

/// Write the b64 message + NUL terminator to out; insufficient capacity
/// ⇒ -4.
///
/// # Safety
///
/// `out_ptr` must point to `out_cap` writable bytes.
unsafe fn write_out(out_ptr: *mut u8, out_cap: usize, s: &str) -> Result<(), i32> {
    let bytes = s.as_bytes();
    if bytes.len() + 1 > out_cap {
        return Err(ERR_CAPACITY);
    }
    // SAFETY: capacity verified above; the whole segment is overwritten
    // and never reads uninitialized bytes.
    let buf = unsafe { std::slice::from_raw_parts_mut(out_ptr, bytes.len() + 1) };
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0;
    Ok(())
}

fn flatten(r: Result<(), i32>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(c) => c,
    }
}

// ============================================================================
// Native shim unit tests (§M8.9 wasm surface — "native calls the shim
// functions directly to run the full OPAQUE flow, with injected fixed
// entropy"; the server side uses real pake::server_* to build the peer)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519_dalek::{Signature, Signer, SigningKey};
    use crate::pake::{
        anchor_sign, login_start, reg_finish, reg_start, server_login_finish, server_login_start,
        server_record_from_b64, server_reg_canonical, server_reg_start, server_setup_load,
        server_setup_new,
    };
    use crate::rand;

    const SEED: &[u8] = &[0x5f_u8; 64];
    /// Out-buffer capacity, same value as the JS glue.
    const OUT_CAP: usize = 64 * 1024;
    /// Serialization lock for the global state (entropy pool/slots) in
    /// tests — the shim state is a process-level singleton; parallel
    /// tests would interfere.
    static SERIAL: Mutex<()> = Mutex::new(());
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Raw-pointer call helper: write bytes into a shim-allocated buffer
    /// then call f(ptr, len).
    fn with_buf(bytes: &[u8], f: impl FnOnce(*const u8, usize)) {
        let ptr = sr_wasm_alloc(bytes.len());
        // SAFETY: ptr was just allocated by
        // sr_wasm_alloc(bytes.len()) (len writable bytes).
        unsafe { std::slice::from_raw_parts_mut(ptr, bytes.len()) }.copy_from_slice(bytes);
        f(ptr, bytes.len());
        // SAFETY: paired free with the same ptr/len.
        unsafe { sr_wasm_free(ptr, bytes.len()) };
    }

    fn alloc_out() -> *mut u8 {
        sr_wasm_alloc(OUT_CAP)
    }
    /// Read the C string written by the shim (NUL-terminated).
    fn read_out(ptr: *mut u8) -> String {
        // SAFETY: the out buffer was allocated by
        // sr_wasm_alloc(OUT_CAP); write_out guarantees the NUL
        // terminator.
        let m = unsafe { std::slice::from_raw_parts(ptr, OUT_CAP) };
        let n = m.iter().position(|&b| b == 0).unwrap_or(m.len());
        String::from_utf8_lossy(&m[..n]).into_owned()
    }
    fn free_out(ptr: *mut u8) {
        // SAFETY: paired free of alloc_out.
        unsafe { sr_wasm_free(ptr, OUT_CAP) };
    }

    fn inject(seed: &[u8]) {
        with_buf(seed, |p, l| {
            // SAFETY: with_buf provides a valid (ptr, len).
            unsafe { sr_wasm_inject_entropy(p, l) }
        });
    }

    /// Shim login_begin (native direct call).
    fn shim_login_begin(user: &str, pw: &str) -> (i32, String) {
        let out = alloc_out();
        let rc = 0;
        let _ = rc;
        let ret = std::cell::Cell::new(0i32);
        with_buf(pw.as_bytes(), |pp, pl| {
            with_buf(user.as_bytes(), |up, ul| {
                // SAFETY: with_buf provides valid buffers.
                ret.set(unsafe { sr_web_login_begin(up, ul, pp, pl, out, OUT_CAP) });
            })
        });
        let s = if ret.get() == 0 {
            read_out(out)
        } else {
            String::new()
        };
        free_out(out);
        (ret.get(), s)
    }

    /// Shim login_finish (native direct call; ke2 + the anchor
    /// four-piece set).
    #[allow(clippy::too_many_arguments)]
    fn shim_login_finish(
        ke2: &str,
        server_id: &[u8; 16],
        identity_pub: &[u8; 32],
        bind_token: &[u8; 16],
        sig: &Signature,
    ) -> (i32, String) {
        let out = alloc_out();
        let ret = std::cell::Cell::new(0i32);
        with_buf(sig.to_bytes().as_slice(), |sp, _sl| {
            with_buf(bind_token.as_slice(), |bp, _bl| {
                with_buf(identity_pub.as_slice(), |ip, _il| {
                    with_buf(server_id.as_slice(), |s2, _l2| {
                        with_buf(ke2.as_bytes(), |kp, kl| {
                            // SAFETY: the C-ABI contract's arguments are
                            // all present (every buffer inside the test
                            // is valid).
                            ret.set(unsafe {
                                sr_web_login_finish(kp, kl, s2, ip, bp, sp, out, OUT_CAP)
                            });
                        })
                    })
                })
            })
        });
        let s = if ret.get() == 0 {
            read_out(out)
        } else {
            String::new()
        };
        free_out(out);
        (ret.get(), s)
    }

    /// Server-side material (OPRF setup + registration record + identity
    /// key); returns (setup, record, sk, server_id).
    struct ServerSide {
        setup: crate::opaque_ke::ServerSetup<Suite>,
        record: crate::opaque_ke::ServerRegistration<Suite>,
        sk: SigningKey,
        server_id: [u8; 16],
    }

    fn server_side(user: &str, pw: &str) -> ServerSide {
        let mut rng = rand::rngs::OsRng;
        let setup = server_setup_load(&server_setup_new(&mut rng)).unwrap();
        let (cstate, m1) = reg_start(&mut rng, pw, user).unwrap();
        let m2 = server_reg_start(&setup, &m1, user).unwrap();
        let record =
            server_reg_canonical(&reg_finish(&mut rng, cstate, pw, user, &m2).unwrap()).unwrap();
        ServerSide {
            setup,
            record: server_record_from_b64(&record).unwrap(),
            sk: SigningKey::from_bytes(&rand::random::<[u8; 32]>()),
            server_id: rand::random(),
        }
    }

    /// Full round trip (injected fixed entropy): login_begin →
    /// server_login_start+anchor_sign → login_finish →
    /// server_login_finish verifying ke3.
    #[test]
    fn full_login_roundtrip_via_shim() {
        let _guard = serial();
        let srv = server_side("shim-user", "shim-pw");
        inject(SEED);
        let (rc, ke1) = shim_login_begin("shim-user", "shim-pw");
        assert_eq!(rc, 0, "login_begin rc");
        assert!(ke1.len() > 100, "ke1 b64 shape ({}B)", ke1.len());

        let mut rng = rand::rngs::OsRng;
        let (ke2, pending) =
            server_login_start(&mut rng, &srv.setup, Some(&srv.record), &ke1, "shim-user")
                .expect("server accept ke1");
        let bind_token: [u8; 16] = rand::random();
        let sig = anchor_sign(&srv.sk, &srv.server_id, "shim-user", &ke2, &bind_token);

        let (rc, ke3) = shim_login_finish(
            &ke2,
            &srv.server_id,
            srv.sk.verifying_key().as_bytes(),
            &bind_token,
            &sig,
        );
        assert_eq!(rc, 0, "login_finish rc (anchor verification passed)");
        assert!(
            server_login_finish(&pending, &ke3).is_ok(),
            "ke3 verified by the server"
        );
    }

    /// -1 no entropy: begin rejected on an empty pool.
    #[test]
    fn err_no_entropy_before_inject() {
        let _guard = serial();
        *POOL.lock().unwrap() = None; // empty state (the dual face of the repeatable-inject semantics)
        let (rc, _) = shim_login_begin("u", "pw");
        assert_eq!(rc, ERR_NO_ENTROPY);
        // Reset the pool for subsequent tests (tests share the global
        // pool — making it order-insensitive).
        inject(SEED);
    }

    /// -2 pake failure: wrong password (the client's local finish
    /// rejects) and an empty-slot finish share the code.
    #[test]
    fn err_pake_wrong_password_and_empty_slot() {
        let _guard = serial();
        inject(SEED);
        let srv = server_side("alice", "right");
        // Empty-slot finish (finish without begin) — explicit slot clear
        // (residue of a previous test's begin).
        LOGIN_SLOT.lock().unwrap().take();
        // Empty-slot finish (finish without begin).
        let (rc, _) = shim_login_finish(
            "x",
            &[0u8; 16],
            &[0u8; 32],
            &[0u8; 16],
            &Signature::from_bytes(&[0u8; 64]),
        );
        assert_eq!(rc, ERR_PAKE, "empty slot = -2");

        // Wrong password: begin("wrong") then finish with the correct
        // ke2 ⇒ rwd mismatch ⇒ -2.
        let (rc, ke1) = shim_login_begin("alice", "wrong");
        assert_eq!(rc, 0);
        let mut rng = rand::rngs::OsRng;
        let (ke2, _) =
            server_login_start(&mut rng, &srv.setup, Some(&srv.record), &ke1, "alice").unwrap();
        let bind_token: [u8; 16] = rand::random();
        let sig = anchor_sign(&srv.sk, &srv.server_id, "alice", &ke2, &bind_token);
        let (rc, ke3) = shim_login_finish(
            &ke2,
            &srv.server_id,
            srv.sk.verifying_key().as_bytes(),
            &bind_token,
            &sig,
        );
        assert_eq!(rc, ERR_PAKE, "wrong password = -2");
        assert!(ke3.is_empty(), "ke3 not produced");
    }

    /// -3 anchor verification rejected: an anchor signed with an
    /// attacker's key (the fake-server surface).
    #[test]
    fn err_anchor_forged_signature() {
        let _guard = serial();
        inject(SEED);
        let mut rng = rand::rngs::OsRng;
        let setup = server_setup_load(&server_setup_new(&mut rng)).unwrap();
        let (rc, ke1) = shim_login_begin("carol", "carol-pw");
        assert_eq!(rc, 0);
        let (ke2, _) = server_login_start(&mut rng, &setup, None, &ke1, "carol").unwrap();
        let honest = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let attacker = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let server_id: [u8; 16] = rand::random();
        let bind_token: [u8; 16] = rand::random();
        let forged = anchor_sign(&attacker, &server_id, "carol", &ke2, &bind_token);
        let (rc, ke3) = shim_login_finish(
            &ke2,
            &server_id,
            honest.verifying_key().as_bytes(),
            &bind_token,
            &forged,
        );
        assert_eq!(rc, ERR_ANCHOR, "forged anchor = -3 (ke3 not produced)");
        assert!(ke3.is_empty());
    }

    /// -4 out capacity insufficient.
    #[test]
    fn err_capacity_too_small() {
        let _guard = serial();
        inject(SEED);
        let small = sr_wasm_alloc(8);
        let ret = std::cell::Cell::new(0i32);
        with_buf(b"pw".as_slice(), |pp, pl| {
            with_buf(b"user".as_slice(), |up, ul| {
                // SAFETY: with_buf provides valid buffers.
                ret.set(unsafe { sr_web_login_begin(up, ul, pp, pl, small, 8) });
            })
        });
        // SAFETY: paired free.
        unsafe { sr_wasm_free(small, 8) };
        assert_eq!(ret.get(), ERR_CAPACITY);
    }

    /// Full registration flow via the shim: pw_begin → server_reg_start
    /// → pw_finish → the record is acceptable to the server, and closes
    /// the loop with the login surface.
    #[test]
    fn full_pw_bootstrap_roundtrip_via_shim() {
        let _guard = serial();
        inject(SEED);
        let mut rng = rand::rngs::OsRng;
        let setup = server_setup_load(&server_setup_new(&mut rng)).unwrap();

        let m1_out = alloc_out();
        let rc_m1 = std::cell::Cell::new(0i32);
        with_buf(b"NewPw-9x".as_slice(), |pp, pl| {
            with_buf(b"newbie".as_slice(), |up, ul| {
                // SAFETY: with_buf provides valid buffers.
                rc_m1.set(unsafe { sr_web_pw_begin(up, ul, pp, pl, m1_out, OUT_CAP) });
            })
        });
        assert_eq!(rc_m1.get(), 0, "pw_begin rc");
        let m1 = read_out(m1_out);
        free_out(m1_out);

        let m2 = server_reg_start(&setup, &m1, "newbie").unwrap();
        let rec_out = alloc_out();
        let rc_rec = std::cell::Cell::new(0i32);
        with_buf(m2.as_bytes(), |mp, ml| {
            // SAFETY: the C-ABI contract's arguments are all present.
            rc_rec.set(unsafe { sr_web_pw_finish(mp, ml, rec_out, OUT_CAP) });
        });
        assert_eq!(rc_rec.get(), 0, "pw_finish rc");
        let record = read_out(rec_out);
        free_out(rec_out);
        let record = server_reg_canonical(&record).unwrap();
        let rec = server_record_from_b64(&record).unwrap();

        // Closed loop: the record over the full login flow (the shim's
        // login surface).
        let (rc, ke1) = shim_login_begin("newbie", "NewPw-9x");
        assert_eq!(rc, 0);
        let (ke2, pending) =
            server_login_start(&mut rng, &setup, Some(&rec), &ke1, "newbie").unwrap();
        let sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let server_id: [u8; 16] = rand::random();
        let bind_token: [u8; 16] = rand::random();
        let sig = anchor_sign(&sk, &server_id, "newbie", &ke2, &bind_token);
        let (rc, ke3) = shim_login_finish(
            &ke2,
            &server_id,
            sk.verifying_key().as_bytes(),
            &bind_token,
            &sig,
        );
        assert_eq!(rc, 0);
        assert!(server_login_finish(&pending, &ke3).is_ok());
    }

    /// Fixed injected entropy ⇒ determinism: two login_begins with the
    /// same seed produce the same ke1 (proving the shim's RNG is driven
    /// by the injected entropy, not OS entropy).
    #[test]
    fn injected_entropy_drives_deterministic_ke1() {
        let _guard = serial();
        inject(SEED);
        let (_, a) = shim_login_begin("det", "pw");
        inject(SEED); // re-inject the same seed (reset semantics)
        let (_, b) = shim_login_begin("det", "pw");
        assert_eq!(a, b, "same seed ⇒ same ke1 (deterministic)");
        inject(&[0xAB; 64]); // different seed
        let (_, c) = shim_login_begin("det", "pw");
        assert_ne!(a, c, "different seed ⇒ different ke1");
    }

    /// Single-slot overwrite: a later begin overwrites the earlier one
    /// (u1 begin → u2 begin → finishing with u2's ke2 succeeds; u1's
    /// state is unreachable).
    #[test]
    fn login_slot_last_begin_wins() {
        let _guard = serial();
        inject(SEED);
        let srv = server_side("u2", "pw2");
        LOGIN_SLOT.lock().unwrap().take(); // clear prior residue
        let _ = shim_login_begin("u1", "pw1"); // overwritten
        let (rc, ke1_u2) = shim_login_begin("u2", "pw2");
        assert_eq!(rc, 0);
        let (ke2, pending) = server_login_start(
            &mut rand::rngs::OsRng,
            &srv.setup,
            Some(&srv.record),
            &ke1_u2,
            "u2",
        )
        .unwrap();
        let bind_token: [u8; 16] = rand::random();
        let sig = anchor_sign(&srv.sk, &srv.server_id, "u2", &ke2, &bind_token);
        let (rc, ke3) = shim_login_finish(
            &ke2,
            &srv.server_id,
            srv.sk.verifying_key().as_bytes(),
            &bind_token,
            &sig,
        );
        assert_eq!(
            rc, 0,
            "the last begin's state is usable (u2's flow finishes successfully)"
        );
        assert!(server_login_finish(&pending, &ke3).is_ok());
    }

    /// The server-side signer and the shim's verify share the same
    /// canonical (guarding against the shim drifting into its own format
    /// — byte-for-byte agreement with pake::anchor_canonical_bytes is
    /// indirectly proven by the full login round trip; here a direct
    /// sign/verify round trip over the canonical).
    #[test]
    fn anchor_canonical_shim_matches_server() {
        let _guard = serial();
        let sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let server_id: [u8; 16] = rand::random();
        let bind: [u8; 16] = rand::random();
        let canonical = pake::anchor_canonical_bytes(&server_id, "u", "ke2-b64", &bind);
        let sig: Signature = sk.sign(&canonical);
        use crate::ed25519_dalek::Verifier as _;
        assert!(sk.verifying_key().verify(&canonical, &sig).is_ok());
        // A different ke2 ⇒ verification rejected (transcript bound).
        let other = pake::anchor_canonical_bytes(&server_id, "u", "ke2-b6d", &bind);
        assert!(sk.verifying_key().verify(&other, &sig).is_err());
    }

    // One direct login_start call (independent-use evidence beyond
    // server_side: the native OsRng path and the shim pool path are
    // interchangeable — same protocol surface).
    #[test]
    fn native_login_start_remains_compatible() {
        let _guard = serial();
        let (state, ke1) = login_start(&mut rand::rngs::OsRng, "pw", "u").unwrap();
        assert!(!ke1.is_empty());
        drop(state);
    }
}
