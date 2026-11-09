//! # flock-protocol
//!
//! The protocol contract layer shared between the flock main repository and
//! showroom (docs/design.md §1). This batch (M1 session/mux) delivers:
//!
//! - [`kem`]: X25519 + ML-KEM-768 hybrid KEM (§1.3.3a / §3.1, P0-1, P0-7);
//! - [`envelope`]: file envelope v2 (§1.3.3b / §3.2, P0-3; v1 read-only
//!   compatibility under the `legacy` feature);
//! - [`sig`]: SR-SIG1-compatible five functions + `KeyProfile` kid dispatch
//!   (§1.3.2 / §1.3.3g / §3.3, P2-12);
//! - [`pake`]: OPAQUE (RFC 9807 / opaque-ke 4.0.1) + rwd profile
//!   (§1.3.3h / §3.4, P2-11);
//! - [`compress`]: compression levels and frame format (§1.3.3e / §3.7,
//!   P0-4/P1-7);
//! - [`session`]: tunnel sessions — dual handshake forms (pinned 1-RTT
//!   Noise-IK structure / TOFU first-connect 2-RTT), record-layer
//!   counter-nonce AEAD, anti-replay, dual-threshold rekey, forged-link
//!   teardown (§1.3.3c / §3.5, P0-2/P1-8/P1-10);
//! - [`mux`]: yamux 0.14.1 multiplexing + explicit FIN + PacketChannel
//!   (§1.3.3d / §3.6, P1-9/VPN-14);
//! - [`trust`]: first-login trust anchors — PinStore (cluster-root-level
//!   pinning), ClusterDirectory (root-signed directory with endpoints and
//!   entries co-signed, monotonically increasing dir_version), InviteFile v3
//!   (§1.3.3f / §3.8, P0-5);
//! - [`roster`]: M7 roster and control-plane shared contracts (PeerInfo/
//!   PeerKind, the ticket wire format TicketWire, CtrlRequest/CtrlResponse
//!   messages and the key-bind canonical — lifted up from flock-server/
//!   flock-sync so both sides share one type with no second source of truth,
//!   §7-M7.4/§7-M7.7);
//! - [`compat`]: showroom compatibility utility surface (§1.3.2 "utilities"
//!   list — `Result` alias / `write_private` 0600 persistence / `names`
//!   name validation; the seam where showroom migrates to thin re-exports).
//!
//! Feature matrix (§1.3.1): default = full VPN profile; `legacy` / `anchor` /
//! `pq-sign` / `wasm` are off by default (`anchor` / `pq-sign` / `wasm` are
//! placeholders only in this batch — see each feature's comment).
//!
//! Dependency generations (§1.3.2, P1-6): aes-gcm 0.11.1 / ed25519-dalek
//! 3.0.0 / rand 0.9 for new code; ml-kem 0.3.3 + x25519-dalek 3.0.0
//! (§1.3.3a); yamux 0.14.1 (§1.3.3d).
//!
//! Version lockdown (§1.2): this crate re-exports its pinned
//! `ed25519_dalek` / `x25519_dalek` / `ml_kem` / `rand` (plus `rsa` under
//! `legacy`); neither project may pull another version — downstream code
//! reuses these directly to avoid type incompatibilities.

// The wasm32 getrandom bridge (src/wasm_bridge.rs) and the M8b wasm C-ABI
// shim (src/webauth_shim.rs) need raw pointers (the getrandom custom
// backend / C-ABI contracts); all other targets keep forbid(unsafe_code)
// (same exemption as showroom-common lib.rs:4-5; the shim's native unit
// test surface is covered by its module header — the `test` cfg gets the
// same exemption).
#![cfg_attr(
    not(all(feature = "wasm", any(target_arch = "wasm32", test))),
    forbid(unsafe_code)
)]

pub mod compat;
pub mod compress;
pub mod envelope;
pub mod kem;
pub mod mux;
pub mod pake;
pub mod roster;
pub mod session;
pub mod sig;
pub mod trust;

/// wasm32 getrandom custom backend bridge (`wasm` feature + wasm32 target;
/// §1.3.1).
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub mod wasm_bridge;

/// wasm C-ABI shim for the M8b Web UI (`wasm`+`anchor` features; wasm32
/// target, also compiled under the native `test` cfg — unit tests call the
/// shim directly to run the full OPAQUE flow, §7-M8.6/§M8.9).
#[cfg(all(
    feature = "wasm",
    feature = "anchor",
    any(target_arch = "wasm32", test)
))]
pub mod webauth_shim;

// Custom backend registration for getrandom 0.2 (the opaque-ke →
// rand_core 0.6 path), same approach as showroom-common lib.rs:41-42.
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
getrandom02::register_custom_getrandom!(wasm_bridge::custom_getrandom_02);

// Compatibility constants (§1.3.2 utility/constants surface; original
// values from showroom-common lib.rs:51-55)
#[cfg(feature = "legacy")]
pub use envelope::WRAP_LEN;
pub use envelope::{KEY_LEN, NONCE_LEN, SEG, TAG_LEN};

// Compatibility utilities (§1.3.2; same semantics as showroom-common
// lib.rs:57-79)
pub use sig::{nonce_hex, sha256_hex, sha256_hex_stream};

// SR-SIG1 time window (§1.3.2; original value from showroom-common
// lib.rs:48)
pub use sig::SIG_WINDOW_SECS;

#[cfg(feature = "legacy")]
pub use rsa;
/// Version-lockdown re-exports (§1.2).
pub use {aes_gcm, ed25519_dalek, ml_kem, opaque_ke, rand, x25519_dalek};
