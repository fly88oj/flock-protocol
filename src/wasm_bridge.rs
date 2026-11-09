//! wasm32 getrandom custom backend bridge (docs/design.md §1.3.1 `wasm`
//! feature; a library-level adaptation of the same idea as showroom's
//! `wasm_shim.rs`, reference this round: showroom-common/src/wasm_shim.rs:133-169).
//!
//! wasm32-unknown-unknown has no OS entropy source, and §8.3 (showroom
//! constraints) forbids pulling in wasm-bindgen — both getrandom generations
//! are routed to the same entropy pool in this module:
//! - getrandom 0.3 (rand 0.9 generation): via `--cfg getrandom_backend="custom"`
//!   (workspace `.cargo/config.toml` `[target.wasm32-unknown-unknown]
//!   rustflags`) it calls back into the exported symbol
//!   `__getrandom_v03_custom` (the getrandom-0.3.4/src/backends/custom.rs
//!   contract);
//! - getrandom 0.2 (rand_core 0.6 ← the opaque-ke path): `custom` feature +
//!   `register_custom_getrandom!` in lib.rs (same approach as the showroom
//!   wasm_shim).
//!
//! Entropy is injected by the host (JS `crypto.getRandomValues`) via
//! [`inject_entropy`], which drives a global StdRng (ChaCha12, a CSPRNG);
//! **without injected entropy the bridge fails explicitly**
//! (`Error::UNSUPPORTED`) — failing explicitly beats silently degraded
//! pseudo-randomness. May be called repeatedly (resets).
//!
//! This module performs raw-pointer access (the getrandom contract) and is
//! the library's only `unsafe`: lib.rs exempts the `wasm` + wasm32
//! combination from `forbid(unsafe_code)`.

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::sync::Mutex;

static GLOBAL_RNG: Mutex<Option<StdRng>> = Mutex::new(None);

/// Inject entropy (host JS: crypto.getRandomValues, >=32B; xor-rotate folded
/// into a 32B seed). May be called repeatedly (resets the global RNG).
pub fn inject_entropy(bytes: &[u8]) {
    let mut seed = [0u8; 32];
    for (i, b) in bytes.iter().enumerate() {
        // Position-dependent rotation: every byte of an over-long input
        // influences the seed, preventing same-position byte cancellation
        // (same algorithm as the showroom wasm_shim sr_entropy).
        seed[i % 32] ^= b.rotate_left(((i / 32) % 8) as u32);
    }
    *GLOBAL_RNG.lock().expect("wasm bridge rng lock") = Some(StdRng::from_seed(seed));
}

/// Shared fill: no injected entropy => explicit failure (Error::UNSUPPORTED
/// semantics).
fn fill(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    let mut g = GLOBAL_RNG.lock().expect("wasm bridge rng lock");
    match g.as_mut() {
        Some(r) => {
            r.fill_bytes(buf);
            Ok(())
        }
        None => Err(getrandom::Error::UNSUPPORTED),
    }
}

/// getrandom 0.3 custom backend callback (symbol name/signature per the
/// backends/custom.rs contract).
#[no_mangle]
pub extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    // SAFETY: getrandom contract — dest points to len bytes of writable,
    // possibly uninitialized buffer; this implementation overwrites the
    // whole slice (fill_bytes writes everything) and never reads
    // uninitialized bytes.
    let buf = unsafe { std::slice::from_raw_parts_mut(dest, len) };
    fill(buf)
}

/// getrandom 0.2 custom backend entry (registered via lib.rs
/// register_custom_getrandom!; same approach as showroom wasm_shim::
/// custom_getrandom). Both generations share one entropy pool.
pub fn custom_getrandom_02(buf: &mut [u8]) -> Result<(), getrandom02::Error> {
    match fill(buf) {
        Ok(()) => Ok(()),
        // Both generations' Error are internal codes u32/u16: propagate with
        // UNSUPPORTED semantics (no entropy injected).
        Err(_) => Err(getrandom02::Error::UNSUPPORTED),
    }
}
