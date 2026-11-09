//! Tunnel session layer (docs/design.md §1.3.3c / §3.5, carrying P0-2,
//! P1-8, P1-10).
//!
//! Deep-module contract: callers see only [`Tunnel`]; handshake, record
//! layer, anti-replay, rekey, keepalive, and the forgery limit are all
//! built in.
//!
//! # Dual handshake forms (§1.3.3c / §3.8)
//!
//! - **Pinned form (steady-state 1-RTT, Noise IK structure)**:
//!   `I1 = ver ‖ algorithm set ‖ expected server identity public key ‖
//!   X25519 ephemeral ‖ ML-KEM-768 ct (1088B, encapsulated to the target
//!   server's static ML-KEM public key) ‖ AEAD(HKDF(x25519(e,s_srv) ‖
//!   mlkem_ss); device static X25519 public key + device Ed25519 public
//!   key + device signature)`; `R1 = server X25519 ephemeral ‖ server
//!   identity's signature over the transcript ‖ two-way key confirmation
//!   tag`. The first frame after the handshake can carry data.
//! - **TOFU first-connect form (once only, 2-RTT)**: `I0 = ver ‖
//!   algorithm set` (no server static material, plaintext) → `R0 = the
//!   join credential chain (full ServerEntry + cluster root public key +
//!   root signature) + the server identity's signature over I0‖R0` → the
//!   client verifies the credential chain, displays the root fingerprint,
//!   and after confirmation sends `I1`/`R1` in the pinned form. TOFU does
//!   not defend against an online MITM at first login (residual risk,
//!   §1.3.3f/§2.5-3) — organizational settings use the strong invite-file
//!   path.
//!
//! # Signature coverage contract (anti-UKS, §1.3.3c / §3.5)
//!
//! The device signature covers **all sent fields** of I1 plus the
//! protocol context (cluster_id, expected server identity public key,
//! purpose label); the server identity signature covers the full
//! I1‖R1 transcript. Tampering with the context or swapping the server
//! identity ⇒ verification necessarily fails (M1 failure vectors in
//! tests/session_mux.rs).
//!
//! # Record layer (P0-2)
//!
//! `[u32 LE len ≤1MiB][type][AEAD(payload)]`; nonce = 32 bits of zeros ‖
//! 64-bit LE counter (WireGuard shape; 12B for GCM/GCM-SIV, the XChaCha
//! tier 24B = 16B zeros ‖ counter); independent keys and counters per
//! direction. **The counter never goes on the wire** — TCP is ordered ⇒
//! the receiving side rebuilds the implicit counter as "previous + 1";
//! any mismatch (including byte-level replays and rollbacks) manifests
//! as an authentication failure ⇒ rejected and counted as forgery.
//! Random 96-bit nonces are forbidden for long sessions (the two
//! profiles stay separate, §1.3.3b/verdict §3.4).
//!
//! # rekey (dual threshold)
//!
//! (2^60 messages, 120s) — whichever comes first triggers;
//! REKEY_INIT/RESP travel as control records (a fresh hybrid KEM: INIT
//! carries a 1216B ephemeral hybrid public key, RESP carries a 1120B
//! hybrid ciphertext); after the epoch switch the counters reset with
//! the new keys; the old receive key is retained until the first record
//! under the new key arrives (the grace path for in-flight old records
//! under TCP ordering); at (2^64−2^13−1 messages, 180s) the hard reject
//! zeroes keys and tears down. The clock is injectable
//! ([`SessionClock`]).
//!
//! rekey switch points (race-fix note, finalized after the blocking
//! review): INIT handling (seal RESP + switch) happens in the **write
//! pump** (the single sealing point: sealing order = wire order =
//! counter order); RESP application (the switch) runs **synchronously in
//! the read pump** — otherwise the read pump would read a new-epoch
//! record before the RESP is applied, misjudge the old key opening the
//! new key as forgery and silently drop it, and after K drops the
//! implicit counter is permanently misaligned (a single hit kills the
//! tunnel). Additionally a desync fuse: [`AUTH_FAIL_STREAK`]
//! consecutive authentication failures ⇒ explicit Protocol teardown
//! (fail-loud; no half-dead state that silently drops data).
//!
//! # Heartbeats (implementation note for §1.3.3d "keepalive = yamux ping
//! 10s", stated honestly)
//!
//! yamux 0.14.1's public API exposes no ping initiation (verified
//! against source this round); the 10s heartbeat is carried by encrypted
//! PING/PONG records in this layer (crypto-2026 §6.4 shape: keepalive
//! frames are themselves encrypted frames); silent dead-link verdict =
//! 3×keepalive with no inbound ⇒ teardown (A9 semantics).

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use futures::future::BoxFuture;
use hkdf::Hkdf;
use ml_kem::ml_kem_768::MlKem768;
use ml_kem::{Ciphertext, Decapsulate, Encapsulate};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot, watch};
use x25519_dalek::{PublicKey as XPub, StaticSecret};
use zeroize::{Zeroize as _, Zeroizing};

use crate::kem::{self, bridge, Fingerprint, HybridKeypair, HybridPubkey};
use crate::mux::{MuxIo, PacketChannel, Prio, Stream};

// ============================================================================
// Constants and frame types
// ============================================================================

/// Session protocol version (carried by I0/I1; mismatch is rejected).
pub const PROTOCOL_VERSION: u8 = 1;

/// Single record/handshake-message cap: `len ≤ 1MiB` (§1.3.3c).
pub const MAX_FRAME: usize = 1024 * 1024;

/// Default rekey counter threshold 2^60 (WireGuard RekeyAfterMessages,
/// crypto-2026 §6).
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// Default hard-reject counter threshold 2^64 − 2^13 − 1 (WireGuard
/// RejectAfterMessages).
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - 8192;

/// Default rekey time threshold 120s.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// Default hard-reject time threshold 180s.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// Default keepalive 10s (§1.3.3c / VPN-16).
pub const KEEPALIVE: Duration = Duration::from_secs(10);
/// Default forgery-attempt limit 100 (P0-2).
pub const FORGE_LIMIT: u32 = 100;
/// REKEY_INIT retry interval when no RESP arrives (wireguard-go
/// RekeyTimeout cadence, crypto-2026 §6).
const REKEY_RETRY: Duration = Duration::from_secs(5);
/// Desync fuse threshold: this many consecutive authentication failures
/// (without a single successful insert) verdicts a Protocol teardown.
const AUTH_FAIL_STREAK: u64 = 16;
/// Session timer tick (real time; threshold verdicts use the injected
/// clock).
const TIMER_TICK: Duration = Duration::from_millis(50);

/// Handshake message type bytes (wire contract, used by interop/test
/// vectors).
pub const RT_I0: u8 = 0x01;
pub const RT_R0: u8 = 0x02;
pub const RT_I1: u8 = 0x03;
pub const RT_R1: u8 = 0x04;
/// Control records (encrypted onto the record layer).
pub const RT_REKEY_INIT: u8 = 0x10;
pub const RT_REKEY_RESP: u8 = 0x11;
/// Data records (yamux carrier) and heartbeats.
pub const RT_DATA: u8 = 0x20;
pub const RT_PING: u8 = 0x21;
pub const RT_PONG: u8 = 0x22;

// Domain-separation labels (HKDF info / signature contexts / transcript
// contexts).
const L_I1_K1: &[u8] = b"flock-protocol/session/i1-k1/v1";
const L_I1_ENC: &[u8] = b"flock-protocol/session/i1-enc/v1";
const L_TRAFFIC: &[u8] = b"flock-protocol/session/traffic/v1";
const L_REKEY_TRAFFIC: &[u8] = b"flock-protocol/session/rekey-traffic/v1";
const L_REKEY_TH: &[u8] = b"flock-protocol/session/rekey-th/v1";
const L_TH: &[u8] = b"flock-protocol/session/transcript/v1";
const L_CONFIRM: &[u8] = b"flock-protocol/session/confirm/v1";
const SIG_I1: &[u8] = b"flock-protocol/session/i1-device-sig/v1";
const SIG_R1: &[u8] = b"flock-protocol/session/r1-server-sig/v1";
const SIG_R0: &[u8] = b"flock-protocol/session/r0-server-sig/v1";
const SIG_ENTRY: &[u8] = b"flock-protocol/trust/server-entry/v1";

// ============================================================================
// Errors
// ============================================================================

/// Session termination reason (observable via stats).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Forgery attempts reached [`TunnelConfig::forge_limit`] (P0-2
    /// teardown discipline).
    ForgeLimit,
    /// Hard reject of the rekey dual threshold at (2^64−2^13−1, 180s).
    RejectAfter,
    /// 3×keepalive with no inbound (silent dead link, A9).
    DeadLink,
    /// Protocol violation (oversized frame/unknown type).
    Protocol,
    /// Underlying IO error.
    Io,
    /// Peer closed (EOF).
    PeerClosed,
    /// Locally initiated close ([`Tunnel::shutdown`] / Drop).
    SessionClosed,
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CloseReason::ForgeLimit => "forge-limit",
            CloseReason::RejectAfter => "reject-after",
            CloseReason::DeadLink => "dead-link",
            CloseReason::Protocol => "protocol",
            CloseReason::Io => "io",
            CloseReason::PeerClosed => "peer-closed",
            CloseReason::SessionClosed => "session-closed",
        };
        f.write_str(s)
    }
}

/// Session-layer error.
#[derive(Debug)]
pub enum SessionError {
    /// Underlying IO.
    Io(io::Error),
    /// Handshake verification failed (the stage label: signature/
    /// decryption/version/identity etc.).
    Handshake(&'static str),
    /// Device rejected (NotFound/Revoked/public-key mismatch —
    /// **indistinguishable**, preventing online probing enumeration,
    /// §1.3.3c).
    DeviceRejected,
    /// No AEAD intersection in negotiation (P1-8).
    AeadMismatch,
    /// The state machine received an unexpected message type (the byte
    /// is the received type).
    UnexpectedMessage(u8),
    /// Protocol violation.
    Protocol(&'static str),
    /// Record authentication failed (already counted as forgery).
    RecordAuth,
    /// Session already terminated.
    Closed(CloseReason),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Io(e) => write!(f, "session: io: {e}"),
            SessionError::Handshake(s) => write!(f, "session: handshake: {s}"),
            SessionError::DeviceRejected => {
                write!(f, "session: device rejected (not-found/revoked/mismatch)")
            }
            SessionError::AeadMismatch => write!(f, "session: no common AEAD suite"),
            SessionError::UnexpectedMessage(t) => {
                write!(f, "session: unexpected message type 0x{t:02x}")
            }
            SessionError::Protocol(s) => write!(f, "session: protocol: {s}"),
            SessionError::RecordAuth => write!(f, "session: record authentication failed"),
            SessionError::Closed(r) => write!(f, "session: closed ({r})"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<io::Error> for SessionError {
    fn from(e: io::Error) -> Self {
        SessionError::Io(e)
    }
}

// ============================================================================
// Clock injection
// ============================================================================

/// Session monotonic-clock seam: all rekey/hard-reject/keepalive
/// threshold verdicts go through it (tests inject [`ManualClock`]).
pub trait SessionClock: Send + Sync + 'static {
    /// Current monotonic instant.
    fn now(&self) -> tokio::time::Instant;
}

/// The system clock (default).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SessionClock for SystemClock {
    fn now(&self) -> tokio::time::Instant {
        tokio::time::Instant::now()
    }
}

/// A manually adjustable clock (for test/benchmark injection).
pub struct ManualClock {
    now: StdMutex<tokio::time::Instant>,
}

impl ManualClock {
    /// Starts at the current real instant.
    pub fn new() -> Self {
        ManualClock {
            now: StdMutex::new(tokio::time::Instant::now()),
        }
    }

    /// Advance forward by `d` (rekey/hard-reject threshold verdicts see
    /// it immediately).
    pub fn advance(&self, d: Duration) {
        let mut g = self.now.lock().expect("ManualClock poisoned");
        let cur: std::time::Instant = (*g).into_std();
        *g = tokio::time::Instant::from_std(cur + d);
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionClock for ManualClock {
    fn now(&self) -> tokio::time::Instant {
        *self.now.lock().expect("ManualClock poisoned")
    }
}

// ============================================================================
// AEAD tiers and negotiation (P1-8)
// ============================================================================

/// Record-layer AEAD algorithm (primary AES-256-GCM; fallbacks
/// XChaCha20-Poly1305 / AES-256-GCM-SIV).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AeadChoice {
    /// Primary tier: AES-256-GCM (aes-gcm 0.11.1; fastest with AES-NI
    /// hardware, verdict §0).
    Aes256Gcm,
    /// Fallback: XChaCha20-Poly1305 (for ends without AES hardware).
    XChaCha20Poly1305,
    /// Fallback: AES-256-GCM-SIV (misuse-resistant / duplication-sensitive
    /// settings).
    Aes256GcmSiv,
}

impl AeadChoice {
    /// Wire code byte.
    pub fn code(self) -> u8 {
        match self {
            AeadChoice::Aes256Gcm => 1,
            AeadChoice::XChaCha20Poly1305 => 2,
            AeadChoice::Aes256GcmSiv => 3,
        }
    }

    fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(AeadChoice::Aes256Gcm),
            2 => Some(AeadChoice::XChaCha20Poly1305),
            3 => Some(AeadChoice::Aes256GcmSiv),
            _ => None,
        }
    }
}

/// Ordered preference list; negotiation = the server takes, in its own
/// order, the first tier that also appears in the client's list (the
/// intersection).
#[derive(Debug, Clone)]
pub struct AeadPreference {
    /// Ordered preferences (at least one entry, deduplicated).
    pub order: Vec<AeadChoice>,
}

impl Default for AeadPreference {
    fn default() -> Self {
        AeadPreference {
            order: vec![
                AeadChoice::Aes256Gcm,
                AeadChoice::XChaCha20Poly1305,
                AeadChoice::Aes256GcmSiv,
            ],
        }
    }
}

impl AeadPreference {
    /// Single-tier preference (for tests/pinned deployments).
    pub fn only(c: AeadChoice) -> Self {
        AeadPreference { order: vec![c] }
    }

    /// Encode as the wire form `[n][codes]`.
    fn encode(&self) -> Vec<u8> {
        let mut v = vec![self.order.len() as u8];
        v.extend(self.order.iter().map(|c| c.code()));
        v
    }
}

/// Negotiation: server preference order × client list → the first
/// intersection entry.
fn negotiate(server: &AeadPreference, client: &[AeadChoice]) -> Option<AeadChoice> {
    server.order.iter().copied().find(|c| client.contains(c))
}

fn parse_aead_list(b: &[u8]) -> Result<Vec<AeadChoice>, SessionError> {
    let (&n, rest) = b.split_first().ok_or(SessionError::Protocol("aead list"))?;
    if n as usize != rest.len() || n == 0 || n as usize > 3 {
        return Err(SessionError::Protocol("aead list length"));
    }
    let mut out = Vec::with_capacity(n as usize);
    for &c in rest {
        let choice = AeadChoice::from_code(c).ok_or(SessionError::Protocol("aead code"))?;
        if out.contains(&choice) {
            return Err(SessionError::Protocol("aead duplicate"));
        }
        out.push(choice);
    }
    Ok(out)
}

// —— Unified record cipher (counter-nonce construction internalized) ——

/// Record-cipher seam: seal/open build the nonce from the implicit
/// counter.
trait RecordCipher: Send {
    fn seal(&self, counter: u64, aad: &[u8], pt: &[u8]) -> Vec<u8>;
    fn open(&self, counter: u64, aad: &[u8], ct: &[u8]) -> Option<Vec<u8>>;
}

/// 12B nonce = 4B zeros ‖ 8B LE counter (WireGuard shape, §1.3.3c).
fn nonce12(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

/// XChaCha-tier 24B nonce = 16B zeros ‖ 8B LE counter.
fn nonce24(counter: u64) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[16..].copy_from_slice(&counter.to_le_bytes());
    n
}

struct AesGcmCipher(aes_gcm::Aes256Gcm);

impl RecordCipher for AesGcmCipher {
    fn seal(&self, counter: u64, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        use aes_gcm::aead::inout::InOutBuf;
        use aes_gcm::aead::{AeadCore, AeadInOut};
        let mut buf = pt.to_vec();
        let tag = self
            .0
            .encrypt_inout_detached(
                &aes_gcm::Nonce::<<aes_gcm::Aes256Gcm as AeadCore>::NonceSize>::from(nonce12(
                    counter,
                )),
                aad,
                InOutBuf::from(&mut buf[..]),
            )
            .expect("aes-gcm: 32B key/counter nonce invariants hold");
        buf.extend_from_slice(tag.as_slice());
        buf
    }

    fn open(&self, counter: u64, aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
        use aes_gcm::aead::inout::InOutBuf;
        use aes_gcm::aead::{AeadCore, AeadInOut};
        if ct.len() < 16 {
            return None;
        }
        let (body, tag) = ct.split_at(ct.len() - 16);
        let tag_arr: [u8; 16] = tag.try_into().ok()?;
        let mut buf = body.to_vec();
        self.0
            .decrypt_inout_detached(
                &aes_gcm::Nonce::<<aes_gcm::Aes256Gcm as AeadCore>::NonceSize>::from(nonce12(
                    counter,
                )),
                aad,
                InOutBuf::from(&mut buf[..]),
                &aes_gcm::Tag::from(tag_arr),
            )
            .ok()?;
        Some(buf)
    }
}

struct XChaChaCipher(chacha20poly1305::XChaCha20Poly1305);

impl RecordCipher for XChaChaCipher {
    fn seal(&self, counter: u64, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        use chacha20poly1305::aead::inout::InOutBuf;
        use chacha20poly1305::aead::AeadInOut;
        let mut buf = pt.to_vec();
        let tag = self
            .0
            .encrypt_inout_detached(
                &chacha20poly1305::XNonce::from(nonce24(counter)),
                aad,
                InOutBuf::from(&mut buf[..]),
            )
            .expect("xchacha: invariants hold");
        buf.extend_from_slice(tag.as_slice());
        buf
    }

    fn open(&self, counter: u64, aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
        use chacha20poly1305::aead::inout::InOutBuf;
        use chacha20poly1305::aead::AeadInOut;
        if ct.len() < 16 {
            return None;
        }
        let (body, tag) = ct.split_at(ct.len() - 16);
        let tag_arr: [u8; 16] = tag.try_into().ok()?;
        let mut buf = body.to_vec();
        self.0
            .decrypt_inout_detached(
                &chacha20poly1305::XNonce::from(nonce24(counter)),
                aad,
                InOutBuf::from(&mut buf[..]),
                &chacha20poly1305::Tag::from(tag_arr),
            )
            .ok()?;
        Some(buf)
    }
}

struct GcmSivCipher(aes_gcm_siv::Aes256GcmSiv);

impl RecordCipher for GcmSivCipher {
    fn seal(&self, counter: u64, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        use aes_gcm_siv::aead::inout::InOutBuf;
        use aes_gcm_siv::aead::AeadInOut;
        let mut buf = pt.to_vec();
        let tag = self
            .0
            .encrypt_inout_detached(
                &aes_gcm_siv::Nonce::from(nonce12(counter)),
                aad,
                InOutBuf::from(&mut buf[..]),
            )
            .expect("gcm-siv: invariants hold");
        buf.extend_from_slice(tag.as_slice());
        buf
    }

    fn open(&self, counter: u64, aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
        use aes_gcm_siv::aead::inout::InOutBuf;
        use aes_gcm_siv::aead::AeadInOut;
        if ct.len() < 16 {
            return None;
        }
        let (body, tag) = ct.split_at(ct.len() - 16);
        let tag_arr: [u8; 16] = tag.try_into().ok()?;
        let mut buf = body.to_vec();
        self.0
            .decrypt_inout_detached(
                &aes_gcm_siv::Nonce::from(nonce12(counter)),
                aad,
                InOutBuf::from(&mut buf[..]),
                &aes_gcm_siv::Tag::from(tag_arr),
            )
            .ok()?;
        Some(buf)
    }
}

fn make_cipher(choice: AeadChoice, key: &[u8; 32]) -> Box<dyn RecordCipher + Send> {
    use aes_gcm::aead::KeyInit as _;
    let k = *key;
    match choice {
        AeadChoice::Aes256Gcm => {
            let key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(k);
            Box::new(AesGcmCipher(aes_gcm::Aes256Gcm::new(&key)))
        }
        AeadChoice::XChaCha20Poly1305 => {
            let key = chacha20poly1305::Key::from(k);
            Box::new(XChaChaCipher(chacha20poly1305::XChaCha20Poly1305::new(
                &key,
            )))
        }
        AeadChoice::Aes256GcmSiv => {
            let key = aes_gcm_siv::Key::<aes_gcm_siv::Aes256GcmSiv>::from(k);
            Box::new(GcmSivCipher(aes_gcm_siv::Aes256GcmSiv::new(&key)))
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Tunnel configuration (§1.3.3c).
pub struct TunnelConfig {
    /// AEAD tiers and preference order (negotiation takes the
    /// intersection, P1-8).
    pub aead: AeadPreference,
    /// keepalive period (default 10s; silent dead-link verdict =
    /// 3×keepalive).
    pub keepalive: Duration,
    /// rekey dual threshold (default (2^60, 120s)).
    pub rekey_after: (u64, Duration),
    /// hard-reject dual threshold (default (2^64−2^13−1, 180s)).
    pub reject_after: (u64, Duration),
    /// forgery-attempt limit (default 100; reaching it tears down).
    pub forge_limit: u32,
    /// Clock (default system clock; tests inject [`ManualClock`]).
    pub clock: Arc<dyn SessionClock>,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        TunnelConfig {
            aead: AeadPreference::default(),
            keepalive: KEEPALIVE,
            rekey_after: (REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME),
            reject_after: (REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME),
            forge_limit: FORGE_LIMIT,
            clock: Arc::new(SystemClock),
        }
    }
}

impl Clone for TunnelConfig {
    fn clone(&self) -> Self {
        TunnelConfig {
            aead: self.aead.clone(),
            keepalive: self.keepalive,
            rekey_after: self.rekey_after,
            reject_after: self.reject_after,
            forge_limit: self.forge_limit,
            clock: self.clock.clone(),
        }
    }
}

impl fmt::Debug for TunnelConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelConfig")
            .field("aead", &self.aead)
            .field("keepalive", &self.keepalive)
            .field("rekey_after", &self.rekey_after)
            .field("reject_after", &self.reject_after)
            .field("forge_limit", &self.forge_limit)
            .finish_non_exhaustive()
    }
}

/// Session statistics (§1.3.3c `stats()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStats {
    /// Current key epoch (handshake = 0; +1 per completed rekey).
    pub epoch: u64,
    /// Completed rekey count.
    pub rekeys: u64,
    /// Records sent (including control/heartbeat).
    pub sent_records: u64,
    /// Records received (including control/heartbeat).
    pub received_records: u64,
    /// Cumulative forgery attempts (including replays; reaching
    /// [`TunnelConfig::forge_limit`] tears down).
    pub forge_attempts: u64,
    /// Of those, the count verdicted as byte-level duplicates (replays).
    pub replay_rejected: u64,
    /// The negotiated AEAD tier.
    pub aead: AeadChoice,
    /// Termination reason (alive = None).
    pub closed: Option<CloseReason>,
}

// ============================================================================
// Identities and the device directory (§1.3.3c lookup seam)
// ============================================================================

/// Cluster identifier (bound into invite files/directories/handshake
/// contexts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClusterId(pub [u8; 16]);

/// Server identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServerId(pub [u8; 16]);

/// Device identifier = fingerprint of the device's Ed25519 public key
/// (SHA-256, §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub [u8; 32]);

impl DeviceId {
    /// Derived from the device's Ed25519 public key.
    pub fn from_ed25519(vk: &VerifyingKey) -> Self {
        DeviceId(Sha256::digest(vk.as_bytes()).into())
    }

    /// Raw 32B.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0.iter().take(8) {
            write!(f, "{b:02x}")?;
        }
        f.write_str("…")
    }
}

/// A device record in the registry (static public keys, §2.2).
#[derive(Debug, Clone)]
pub struct DeviceRecord {
    /// Device static X25519 public key (session indexing/roaming, §2.4).
    pub device_x25519: XPub,
    /// Device Ed25519 public key (identity).
    pub device_ed25519: VerifyingKey,
}

/// Directory lookup three-state verdict (§1.3.3c).
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // Active carries a 64B device record, far below stack-pressure thresholds; boxing would add directory-side burden
pub enum LookupVerdict {
    /// Not registered.
    NotFound,
    /// Revoked (since_epoch = revocation epoch, advancing with Raft
    /// apply).
    Revoked { since_epoch: u64 },
    /// Registered and active.
    Active(DeviceRecord),
}

/// Device-directory seam: the server injects registry/revocation lookups
/// into the protocol library (one of the permission points of the
/// multi-primary deployment).
///
/// Must be async (`BoxFuture`): linearizable reads through the Raft
/// leader are a network round trip (§4); `NotFound` and `Revoked` must
/// both reject the handshake **with aligned timing** (preventing online
/// probing of device enumeration) — this implementation's guarantee:
/// both verdicts, after completing the same batch of handshake
/// cryptographic work (decrypting I1, verifying the device signature),
/// return **the same** opaque error
/// [`SessionError::DeviceRejected`].
pub trait DeviceDirectory: Send + Sync + 'static {
    /// Look up a device.
    fn lookup(&self, id: &DeviceId) -> BoxFuture<'static, LookupVerdict>;
}

/// Closure-style directory implementation (`Fn(&DeviceId) ->
/// BoxFuture<...>` works directly).
impl<F> DeviceDirectory for F
where
    F: Fn(&DeviceId) -> BoxFuture<'static, LookupVerdict> + Send + Sync + 'static,
{
    fn lookup(&self, id: &DeviceId) -> BoxFuture<'static, LookupVerdict> {
        self(id)
    }
}

/// In-memory directory (for tests / the single-server form to start
/// with).
#[derive(Debug, Clone, Default)]
pub struct InMemoryDirectory {
    devices: HashMap<[u8; 32], DeviceRecord>,
    revoked: HashMap<[u8; 32], u64>,
}

impl InMemoryDirectory {
    /// Empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register/update a device.
    pub fn register(&mut self, rec: DeviceRecord) {
        let id: [u8; 32] = Sha256::digest(rec.device_ed25519.as_bytes()).into();
        self.revoked.remove(&id);
        self.devices.insert(id, rec);
    }

    /// Revoke a device.
    pub fn revoke(&mut self, id: &DeviceId, since_epoch: u64) {
        self.devices.remove(id.as_bytes());
        self.revoked.insert(*id.as_bytes(), since_epoch);
    }
}

impl DeviceDirectory for InMemoryDirectory {
    fn lookup(&self, id: &DeviceId) -> BoxFuture<'static, LookupVerdict> {
        let verdict = if let Some(since) = self.revoked.get(id.as_bytes()) {
            LookupVerdict::Revoked {
                since_epoch: *since,
            }
        } else if let Some(rec) = self.devices.get(id.as_bytes()) {
            LookupVerdict::Active(rec.clone())
        } else {
            LookupVerdict::NotFound
        };
        Box::pin(async move { verdict })
    }
}

// ============================================================================
// Device / server identity material
// ============================================================================

/// Device static keys (X25519 for sessions + Ed25519 for identity;
/// client-generated, never leaves the machine, §2.4).
pub struct DeviceStaticKeys {
    x25519: StaticSecret,
    ed25519: SigningKey,
}

impl DeviceStaticKeys {
    /// Generate randomly.
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        DeviceStaticKeys {
            x25519: StaticSecret::random_from_rng(&mut bridge(&mut rng)),
            ed25519: SigningKey::from_bytes(&rand::random::<[u8; 32]>()),
        }
    }

    /// Device static X25519 public key (32B).
    pub fn x25519_public(&self) -> XPub {
        XPub::from(&self.x25519)
    }

    /// Device Ed25519 public key.
    pub fn ed25519_public(&self) -> VerifyingKey {
        self.ed25519.verifying_key()
    }

    /// Internal signing-key reference (handshake signing only).
    fn signing(&self) -> &SigningKey {
        &self.ed25519
    }

    /// Serialization: 32B X25519 secret key ‖ 32B Ed25519 seed (key
    /// material; 0600 persistence is the caller's responsibility).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x25519.to_bytes());
        out[32..].copy_from_slice(&self.ed25519.to_bytes());
        out
    }

    /// Restore from [].
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let x: [u8; 32] = bytes[..32].try_into().expect("32B");
        let seed: [u8; 32] = bytes[32..].try_into().expect("32B");
        DeviceStaticKeys {
            x25519: StaticSecret::from(x),
            ed25519: SigningKey::from_bytes(&seed),
        }
    }
}

impl fmt::Debug for DeviceStaticKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceStaticKeys")
            .field(
                "device_id",
                &DeviceId::from_ed25519(&self.ed25519.verifying_key()),
            )
            .finish_non_exhaustive()
    }
}

/// Server access material (= the public part of the §4 join credential;
/// covered by the root signature, §1.3.3f/§3.8).
#[derive(Debug, Clone)]
pub struct ServerEntry {
    /// Server identifier.
    pub server_id: ServerId,
    /// The corresponding relay user port (frps host:port).
    pub relay_endpoint: String,
    /// Server identity Ed25519 public key (the R1 signature verification
    /// anchor).
    pub identity_pub: VerifyingKey,
    /// Server static hybrid public key (1216B; I1's ML-KEM ct is
    /// encapsulated to it).
    pub static_hybrid_pub: HybridPubkey,
}

impl ServerEntry {
    /// Canonical bytes covered by the root signature (`SIG_ENTRY ‖
    /// cluster_id ‖ server_id ‖ endpoint ‖ identity ‖ hybrid`).
    pub fn canonical_bytes(&self, cluster_id: &ClusterId) -> Vec<u8> {
        let mut v = Vec::with_capacity(SIG_ENTRY.len() + 1300);
        v.extend_from_slice(SIG_ENTRY);
        v.extend_from_slice(&cluster_id.0);
        v.extend_from_slice(&self.server_id.0);
        v.extend_from_slice(&(self.relay_endpoint.len() as u16).to_le_bytes());
        v.extend_from_slice(self.relay_endpoint.as_bytes());
        v.extend_from_slice(self.identity_pub.as_bytes());
        v.extend_from_slice(&self.static_hybrid_pub.to_bytes());
        v
    }
}

/// The cluster root key's signature over a ServerEntry (the join
/// credential; the `trust` module reuses the same canonical bytes).
pub fn sign_server_entry(
    root: &SigningKey,
    cluster_id: &ClusterId,
    entry: &ServerEntry,
) -> Signature {
    root.sign(&entry.canonical_bytes(cluster_id))
}

/// Verify a join-credential signature.
pub fn verify_server_entry(
    root_pub: &VerifyingKey,
    cluster_id: &ClusterId,
    entry: &ServerEntry,
    sig: &Signature,
) -> bool {
    root_pub
        .verify(&entry.canonical_bytes(cluster_id), sig)
        .is_ok()
}

/// Ed25519 public-key fingerprint (SHA-256; display format same as
/// [`Fingerprint`]).
pub fn fingerprint_ed25519(vk: &VerifyingKey) -> Fingerprint {
    Fingerprint::from_digest(Sha256::digest(vk.as_bytes()).into())
}

/// Pinning material held by the client: cluster root public key + the
/// target endpoint's ServerEntry (§1.3.3c `ServerPin`).
#[derive(Debug, Clone)]
pub struct ServerPin {
    /// Expected cluster.
    pub cluster_id: ClusterId,
    /// Cluster root public key (established via TOFU/invite; the R0
    /// verification anchor).
    pub cluster_root_pub: VerifyingKey,
    /// Target endpoint access material.
    pub entry: ServerEntry,
}

/// Server identity material (respond side).
pub struct ServerIdentity {
    /// Owning cluster.
    pub cluster_id: ClusterId,
    /// This server's identifier.
    pub server_id: ServerId,
    /// Identity signing key (R0/R1 transcript signatures, P0-5 tunnel
    /// side).
    pub identity: SigningKey,
    /// Static hybrid key (the KEM encapsulation target of I1).
    pub static_hybrid: HybridKeypair,
    /// The corresponding ServerEntry (consistent with
    /// identity/static_hybrid; presented in R0).
    pub entry: ServerEntry,
    /// Cluster root public key (presented in the TOFU R0; what the client
    /// pins).
    pub root_pub: VerifyingKey,
    /// The root's signature over this ServerEntry (the join credential,
    /// presented in R0).
    pub entry_sig: Signature,
}

impl ServerIdentity {
    /// Enrolled by the root key (test/ops assembly path: the root key is
    /// kept offline, §4).
    pub fn enroll(
        root: &SigningKey,
        cluster_id: ClusterId,
        server_id: ServerId,
        relay_endpoint: &str,
    ) -> Self {
        let identity = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let static_hybrid = HybridKeypair::generate(&mut rand::rng());
        let entry = ServerEntry {
            server_id,
            relay_endpoint: relay_endpoint.to_string(),
            identity_pub: identity.verifying_key(),
            static_hybrid_pub: static_hybrid.public(),
        };
        let entry_sig = sign_server_entry(root, &cluster_id, &entry);
        ServerIdentity {
            cluster_id,
            server_id,
            identity,
            static_hybrid,
            entry,
            root_pub: root.verifying_key(),
            entry_sig,
        }
    }
}

impl fmt::Debug for ServerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerIdentity")
            .field("cluster_id", &self.cluster_id)
            .field("server_id", &self.server_id)
            .field("entry", &self.entry)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Frames and small codec pieces
// ============================================================================

fn frame_header(body_len: usize) -> [u8; 4] {
    ((body_len + 1) as u32).to_le_bytes() // len = type(1) + body
}

fn push_frame(out: &mut Vec<u8>, rtype: u8, body: &[u8]) {
    out.extend_from_slice(&frame_header(body.len()));
    out.push(rtype);
    out.extend_from_slice(body);
}

async fn send_frame<S: AsyncWrite + Unpin>(
    io: &mut S,
    rtype: u8,
    payload: &[u8],
) -> Result<(), SessionError> {
    if payload.len() + 1 > MAX_FRAME {
        return Err(SessionError::Protocol("frame too large"));
    }
    let mut buf = Vec::with_capacity(5 + payload.len());
    push_frame(&mut buf, rtype, payload);
    io.write_all(&buf).await?;
    io.flush().await?;
    Ok(())
}

async fn recv_frame<S: AsyncRead + Unpin>(io: &mut S) -> Result<(u8, Vec<u8>), SessionError> {
    let mut hdr = [0u8; 5];
    io.read_exact(&mut hdr).await?;
    let len = u32::from_le_bytes(hdr[..4].try_into().expect("4B")) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(SessionError::Protocol("frame length"));
    }
    let mut body = vec![0u8; len - 1];
    io.read_exact(&mut body).await?;
    Ok((hdr[4], body))
}

/// Parse cursor.
/// Decode out-of-bounds/length errors (shared error of the Rd cursor;
/// session/trust each provide a From conversion so call sites pass
/// through with `?`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RdErr(pub &'static str);

impl From<RdErr> for SessionError {
    fn from(e: RdErr) -> Self {
        SessionError::Protocol(e.0)
    }
}

/// Parse cursor (shared by session/trust; ponytail: removes trust's
/// field-for-field duplicate).
pub(crate) struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Rd { b, pos: 0 }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], RdErr> {
        if self.pos + n > self.b.len() {
            return Err(RdErr("truncated message"));
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, RdErr> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, RdErr> {
        let b: [u8; 2] = self.take(2)?.try_into().expect("2B");
        Ok(u16::from_le_bytes(b))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, RdErr> {
        let b: [u8; 8] = self.take(8)?.try_into().expect("8B");
        Ok(u64::from_le_bytes(b))
    }
    pub(crate) fn arr32(&mut self) -> Result<[u8; 32], RdErr> {
        self.take(32)?.try_into().map_err(|_| RdErr("32B"))
    }
    pub(crate) fn arr16(&mut self) -> Result<[u8; 16], RdErr> {
        self.take(16)?.try_into().map_err(|_| RdErr("16B"))
    }
    pub(crate) fn arr64(&mut self) -> Result<[u8; 64], RdErr> {
        self.take(64)?.try_into().map_err(|_| RdErr("64B"))
    }
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        &self.b[self.pos..]
    }
    pub(crate) fn done(&self) -> bool {
        self.pos == self.b.len()
    }
}

fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, okm)
        .expect("HKDF-SHA256 output length valid");
}

/// Handshake k1 confluence (ikm = x25519_ss ‖ ml_kem_ss, wrapped in
/// `Zeroizing` for Drop zeroization; the return value k1 is likewise
/// Zeroizing — this is the k1/k_enc secret-material discipline of the
/// handshake, §1.3.3c).
fn k1_from_shares(x_ss: &[u8], ml_ss: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(x_ss.len() + ml_ss.len()));
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(ml_ss);
    let mut k1 = Zeroizing::new([0u8; 32]);
    hkdf_sha256(&[], &ikm[..], L_I1_K1, &mut k1[..]);
    k1
}

/// Final handshake key group (§1.3.3c initial record-layer keys).
///
/// Every field is key material: `ZeroizeOnDrop` — the whole struct is
/// zeroed on Drop (§1.3.3c zeroization commitment; the directional keys
/// derived into Core are governed by [`DirKeys`]' zeroization
/// discipline).
#[derive(zeroize::ZeroizeOnDrop)]
struct TrafficKeys {
    c2s: [u8; 32],
    s2c: [u8; 32],
    /// The in-R1 server→client key confirmation (client→server
    /// confirmation = the first encrypted record after the handshake,
    /// implicit).
    confirm_s: [u8; 32],
    rekey_seed: [u8; 32],
}

fn derive_traffic(k1: &[u8; 32], ee: &[u8], th: &[u8; 32], chosen: AeadChoice) -> TrafficKeys {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(k1);
    ikm.extend_from_slice(ee);
    let mut okm = Zeroizing::new([0u8; 160]);
    let mut info = L_TRAFFIC.to_vec();
    info.push(chosen.code());
    hkdf_sha256(th, &ikm[..], &info, &mut okm[..]);
    let sub = |r: std::ops::Range<usize>| okm[r].try_into().expect("32B slice");
    TrafficKeys {
        c2s: sub(0..32),
        s2c: sub(32..64),
        confirm_s: sub(96..128),
        rekey_seed: sub(128..160),
    }
}

fn transcript_hash(i1_bytes: &[u8], chosen: AeadChoice, eph_srv: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(L_TH);
    h.update(i1_bytes);
    h.update([chosen.code()]);
    h.update(eph_srv);
    h.finalize().into()
}

// ============================================================================
// Handshake messages
// ============================================================================

/// I1 sent fields (the coverage of the signature/key confirmation;
/// anti-UKS: includes both ephemeral shares and the algorithm set,
/// §1.3.3c).
struct I1Msg {
    ver: u8,
    aead_list: Vec<u8>,
    expected_identity: [u8; 32],
    e_pub: [u8; 32],
    ml_ct: [u8; kem::ML_KEM_CT_LEN],
    nonce: [u8; 12],
    enc: Vec<u8>, // ct||tag, pt = dev_x(32)‖dev_ed(32)‖dev_sig(64)
}

/// I1 construction inputs (gathered to avoid a long parameter list).
struct I1Parts<'a> {
    e_pub: &'a [u8; 32],
    ml_ct: &'a Ciphertext<MlKem768>,
    k_enc: &'a [u8; 32],
    dev_x: &'a [u8; 32],
    dev_ed: &'a [u8; 32],
    dev_sig_ctx: &'a [u8],
    device: &'a DeviceStaticKeys,
    aead_list: &'a [u8],
    expected_identity: &'a VerifyingKey,
}

fn build_i1(p: I1Parts<'_>, rng: &mut impl rand::TryRngCore) -> Vec<u8> {
    let I1Parts {
        e_pub,
        ml_ct,
        k_enc,
        dev_x,
        dev_ed,
        dev_sig_ctx,
        device,
        aead_list,
        expected_identity,
    } = p;
    let mut pt = Vec::with_capacity(128);
    pt.extend_from_slice(dev_x);
    pt.extend_from_slice(dev_ed);
    pt.extend_from_slice(&device.signing().sign(dev_sig_ctx).to_bytes());

    let mut nonce = [0u8; 12];
    rng.try_fill_bytes(&mut nonce).expect("entropy");
    // AAD = all sent fields of I1 (ver‖algorithm set‖expected
    // identity‖e_pub‖ml_ct)
    let mut aad = Vec::with_capacity(2 + aead_list.len() + 32 + 32 + kem::ML_KEM_CT_LEN);
    aad.push(PROTOCOL_VERSION);
    aad.extend_from_slice(aead_list);
    aad.extend_from_slice(expected_identity.as_bytes());
    aad.extend_from_slice(e_pub);
    aad.extend_from_slice(ml_ct.as_slice());

    let cipher = aes_gcm::Aes256Gcm::new(&aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(*k_enc));
    use aes_gcm::aead::inout::InOutBuf;
    use aes_gcm::aead::{AeadCore, AeadInOut, KeyInit as _};
    let mut buf = pt;
    let tag = cipher
        .encrypt_inout_detached(
            &aes_gcm::Nonce::<<aes_gcm::Aes256Gcm as AeadCore>::NonceSize>::from(nonce),
            &aad,
            InOutBuf::from(&mut buf[..]),
        )
        .expect("i1 payload seal");

    let mut out = Vec::with_capacity(aad.len() + 12 + buf.len() + 16);
    out.push(PROTOCOL_VERSION);
    out.extend_from_slice(aead_list);
    out.extend_from_slice(expected_identity.as_bytes());
    out.extend_from_slice(e_pub);
    out.extend_from_slice(ml_ct.as_slice());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    out.extend_from_slice(tag.as_slice());
    out
}

fn parse_i1(b: &[u8]) -> Result<I1Msg, SessionError> {
    let mut r = Rd::new(b);
    let ver = r.u8()?;
    if ver != PROTOCOL_VERSION {
        return Err(SessionError::Handshake("protocol version"));
    }
    // aead_list keeps the full "count byte + codes" shape (consistent
    // with encode()/the signature context)
    let list_len = r.u8()? as usize;
    if list_len == 0 || list_len > 3 {
        return Err(SessionError::Handshake("empty/oversized aead list"));
    }
    let mut aead_list = Vec::with_capacity(1 + list_len);
    aead_list.push(list_len as u8);
    aead_list.extend_from_slice(r.take(list_len)?);
    let expected_identity = r.arr32()?;
    let e_pub = r.arr32()?;
    let ml_ct: [u8; kem::ML_KEM_CT_LEN] = r.take(kem::ML_KEM_CT_LEN)?.try_into().expect("1088B");
    let nonce: [u8; 12] = r.take(12)?.try_into().expect("12B");
    let enc = r.rest().to_vec();
    if enc.len() != 128 + 16 {
        return Err(SessionError::Handshake("i1 payload length"));
    }
    Ok(I1Msg {
        ver,
        aead_list,
        expected_identity,
        e_pub,
        ml_ct,
        nonce,
        enc,
    })
}

/// Fields covered by the I1 signature (§1.3.3c: all sent fields —
/// including both ephemeral shares and the algorithm set).
struct I1SignedFields<'a> {
    ver: u8,
    aead_list: &'a [u8],
    e_pub: &'a [u8; 32],
    ml_ct: &'a [u8],
    dev_x: &'a [u8; 32],
    dev_ed: &'a [u8; 32],
}

struct R1Msg {
    chosen: u8,
    eph_srv: [u8; 32],
    srv_sig: [u8; 64],
    confirm: Vec<u8>,
}

fn parse_r1(b: &[u8]) -> Result<R1Msg, SessionError> {
    let mut r = Rd::new(b);
    let chosen = r.u8()?;
    let eph_srv = r.arr32()?;
    let srv_sig: [u8; 64] = r.take(64)?.try_into().expect("64B");
    let confirm = r.rest().to_vec();
    if confirm.len() != L_CONFIRM.len() + 16 {
        return Err(SessionError::Handshake("confirm length"));
    }
    Ok(R1Msg {
        chosen,
        eph_srv,
        srv_sig,
        confirm,
    })
}

fn r1_sig_context(
    cluster_id: &ClusterId,
    dev_ed: &[u8; 32],
    i1_bytes: &[u8],
    chosen: u8,
    eph_srv: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_R1.len() + i1_bytes.len() + 64);
    v.extend_from_slice(SIG_R1);
    v.extend_from_slice(&cluster_id.0);
    v.extend_from_slice(dev_ed);
    v.extend_from_slice(i1_bytes);
    v.push(chosen);
    v.extend_from_slice(eph_srv);
    v
}

fn i1_sig_context(
    cluster_id: &ClusterId,
    expected_identity: &[u8; 32],
    fields: I1SignedFields<'_>,
) -> Vec<u8> {
    let I1SignedFields {
        ver,
        aead_list,
        e_pub,
        ml_ct,
        dev_x,
        dev_ed,
    } = fields;
    let mut v = Vec::with_capacity(SIG_I1.len() + 1300);
    v.extend_from_slice(SIG_I1);
    v.extend_from_slice(&cluster_id.0);
    v.extend_from_slice(expected_identity);
    v.push(ver);
    v.extend_from_slice(aead_list);
    v.extend_from_slice(e_pub);
    v.extend_from_slice(ml_ct);
    v.extend_from_slice(dev_x);
    v.extend_from_slice(dev_ed);
    v
}

// ============================================================================
// Record-layer core state machine
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

/// Directional key group (record cipher + counter + key raw material).
///
/// Zeroization discipline (§1.3.3c): `key` keeps a 32B copy of the raw
/// material so it is deterministically zeroed with this struct's
/// lifetime (explicit wipe on `Drop`; the expanded key schedule inside
/// the cipher is upstream-crate-internal and unreachable — raw material
/// leaving no residue is the zeroization surface this layer can reach).
/// Old [`DirKeys`] replaced by a rekey rotation are zeroed with it.
struct DirKeys {
    cipher: Box<dyn RecordCipher + Send>,
    counter: u64,
    key: [u8; 32],
}

impl Drop for DirKeys {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

struct PendingRekey {
    eph: HybridKeypair,
    epoch: u64,
    at: tokio::time::Instant,
}

struct Inner {
    closed: Option<CloseReason>,
    epoch: u64,
    epoch_start: tokio::time::Instant,
    aead: AeadChoice,
    send: DirKeys,
    recv: DirKeys,
    /// Old receive key (the grace path for in-flight records after a
    /// rekey; dropped as soon as the first new-key record arrives).
    retained_recv: Option<DirKeys>,
    rekey_seed: [u8; 32],
    pending: Option<PendingRekey>,
    forge_attempts: u64,
    replay_rejected: u64,
    /// Consecutive-authentication-failure counter (reset on success): the
    /// desync fuse — armed only inside rekey windows (see open_record);
    /// AUTH_FAIL_STREAK consecutive failures without a single success ⇒
    /// key desync/implementation error; explicit teardown (fail-loud)
    /// beats silently dropping data or a half-dead tunnel.
    auth_fail_streak: u64,
    received: u64,
    rekeys: u64,
    last_inbound: tokio::time::Instant,
    last_ping: tokio::time::Instant,
    last_recv_ct: Option<[u8; 32]>,
    peer_device: Option<DeviceId>,
    peer_server: Option<ServerId>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Session-core teardown: rekey_seed explicitly zeroized (§1.3.3c);
        // directional key raw material zeroized via DirKeys::Drop of
        // send/recv/retained_recv.
        self.rekey_seed.zeroize();
    }
}

/// Explicit key zeroing on hard reject ([`CloseReason::RejectAfter`]) /
/// forgery teardown ([`CloseReason::ForgeLimit`]) (design §1.3.3c
/// "reject_after zeroes keys on trigger" commitment): key material is
/// wiped immediately once the close flag is set — not waiting for Core
/// teardown (an explicit path beyond the Drop backstop; after close,
/// seal/open both check `closed` first, so no residual key consumers).
fn zeroize_keys_on_close(inner: &mut Inner) {
    inner.rekey_seed.zeroize();
    inner.send.key.zeroize();
    inner.recv.key.zeroize();
    inner.retained_recv = None; // old receive key (zeroized by DirKeys::Drop)
}

/// Session core (shared by the pumps after the handshake).
pub(crate) struct Core {
    cfg: TunnelConfig,
    inner: StdMutex<Inner>,
    closed_tx: watch::Sender<bool>,
    /// Key-epoch observation (advances on rekey apply; the M5 A10
    /// epoch-increment observation surface).
    epoch_tx: watch::Sender<u64>,
}

impl Core {
    fn new(cfg: TunnelConfig, role: Role, aead: AeadChoice, tk: &TrafficKeys) -> Arc<Self> {
        let now = cfg.clock.now();
        let (send_key, recv_key) = match role {
            Role::Client => (tk.c2s, tk.s2c),
            Role::Server => (tk.s2c, tk.c2s),
        };
        let (closed_tx, _) = watch::channel(false);
        let (epoch_tx, _) = watch::channel(0u64);
        Arc::new(Core {
            cfg,
            inner: StdMutex::new(Inner {
                closed: None,
                epoch: 0,
                epoch_start: now,
                aead,
                send: DirKeys {
                    cipher: make_cipher(aead, &send_key),
                    counter: 0,
                    key: send_key,
                },
                recv: DirKeys {
                    cipher: make_cipher(aead, &recv_key),
                    counter: 0,
                    key: recv_key,
                },
                retained_recv: None,
                rekey_seed: tk.rekey_seed,
                pending: None,
                forge_attempts: 0,
                replay_rejected: 0,
                auth_fail_streak: 0,
                received: 0,
                rekeys: 0,
                last_inbound: now,
                last_ping: now,
                last_recv_ct: None,
                peer_device: None,
                peer_server: None,
            }),
            closed_tx,
            epoch_tx,
        })
    }

    /// Subscribe to key-epoch changes (starts at 0; advances +1 on each
    /// rekey apply).
    pub(crate) fn subscribe_epoch(&self) -> watch::Receiver<u64> {
        self.epoch_tx.subscribe()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("session core poisoned")
    }

    fn kill(&self, reason: CloseReason) {
        let mut inner = self.lock();
        if inner.closed.is_none() {
            inner.closed = Some(reason);
            let _ = self.closed_tx.send(true);
        }
    }

    fn subscribe_closed(&self) -> watch::Receiver<bool> {
        self.closed_tx.subscribe()
    }

    fn note_inbound(&self) {
        let now = self.cfg.clock.now();
        self.lock().last_inbound = now;
    }

    fn seal_frame(&self, rtype: u8, payload: &[u8]) -> Result<Vec<u8>, SessionError> {
        let mut inner = self.lock();
        Core::seal_locked(&self.cfg, &mut inner, rtype, payload)
    }

    fn seal_locked(
        cfg: &TunnelConfig,
        inner: &mut Inner,
        rtype: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        if let Some(r) = inner.closed {
            return Err(SessionError::Closed(r));
        }
        if payload.len() + 1 + 16 > MAX_FRAME {
            return Err(SessionError::Protocol("record too large"));
        }
        if inner.send.counter >= cfg.reject_after.0 {
            let reason = CloseReason::RejectAfter;
            inner.closed = Some(reason);
            zeroize_keys_on_close(inner); // §1.3.3c: reject_after zeroes keys on trigger
            return Err(SessionError::Closed(reason));
        }
        let ct = inner
            .send
            .cipher
            .seal(inner.send.counter, &[rtype], payload);
        inner.send.counter += 1;
        let mut out = Vec::with_capacity(5 + ct.len());
        push_frame(&mut out, rtype, &ct);
        Ok(out)
    }

    /// Open one record: current key (implicit counter = last+1) → old-key
    /// grace → failure counted as forgery.
    fn open_record(&self, rtype: u8, body: &[u8]) -> Result<Vec<u8>, SessionError> {
        let mut inner = self.lock();
        if let Some(r) = inner.closed {
            return Err(SessionError::Closed(r));
        }
        let aad = [rtype];
        if let Some(pt) = inner.recv.cipher.open(inner.recv.counter, &aad, body) {
            inner.last_recv_ct = Some(Sha256::digest(body).into());
            inner.recv.counter += 1;
            inner.received += 1;
            inner.auth_fail_streak = 0;
            // First record under the new key ⇒ the peer has switched;
            // under TCP ordering there are no more in-flight old-key
            // records.
            inner.retained_recv = None;
            return Ok(pt);
        }
        if let Some(ret) = inner.retained_recv.as_mut() {
            if let Some(pt) = ret.cipher.open(ret.counter, &aad, body) {
                ret.counter += 1;
                inner.received += 1;
                inner.auth_fail_streak = 0;
                return Ok(pt);
            }
        }
        inner.forge_attempts += 1;
        inner.auth_fail_streak += 1;
        // The desync fuse is armed only inside rekey windows (a pending
        // INIT or an unfinished retained old key): consecutive failures
        // inside a window = key desync/implementation error ⇒ explicit
        // Protocol teardown (fail-loud); consecutive failures outside a
        // window = forgery flood, whose semantics belong to forge_limit
        // (P0-2: teardown at 100).
        if inner.auth_fail_streak >= AUTH_FAIL_STREAK
            && (inner.pending.is_some() || inner.retained_recv.is_some())
        {
            let reason = CloseReason::Protocol;
            inner.closed = Some(reason);
            let _ = self.closed_tx.send(true);
            return Err(SessionError::Closed(reason));
        }
        if inner.last_recv_ct == Some(Sha256::digest(body).into()) {
            inner.replay_rejected += 1; // byte-level duplicate = replay vector (also counted as forgery)
        }
        if inner.forge_attempts >= self.cfg.forge_limit as u64 {
            let reason = CloseReason::ForgeLimit;
            inner.closed = Some(reason);
            zeroize_keys_on_close(&mut inner); // teardown discipline (P0-2): zero keys on hitting the limit
            let _ = self.closed_tx.send(true);
            return Err(SessionError::Closed(reason));
        }
        Err(SessionError::RecordAuth)
    }

    /// Timer tick: hard-reject/dead-link verdicts + rekey trigger/retry +
    /// heartbeat. Returns the frames to send (already sealed).
    fn timer_tick(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let now = self.cfg.clock.now();
        let mut inner = self.lock();
        if inner.closed.is_some() {
            return out;
        }
        let cfg = &self.cfg;
        // Hard reject (dual threshold: time/counter)
        if now.duration_since(inner.epoch_start) >= cfg.reject_after.1
            || inner.send.counter >= cfg.reject_after.0
        {
            inner.closed = Some(CloseReason::RejectAfter);
            zeroize_keys_on_close(&mut inner); // §1.3.3c: reject_after zeroes keys on trigger
            let _ = self.closed_tx.send(true);
            return out;
        }
        // Silent dead link: 3×keepalive with no inbound
        if now.duration_since(inner.last_inbound) > cfg.keepalive.mul_f64(3.0) {
            inner.closed = Some(CloseReason::DeadLink);
            let _ = self.closed_tx.send(true);
            return out;
        }
        // rekey: no pending and a dual threshold reached ⇒ initiate;
        // pending with no answer for 5s ⇒ retry with a fresh ephemeral
        // key
        let due = inner.send.counter >= cfg.rekey_after.0
            || now.duration_since(inner.epoch_start) >= cfg.rekey_after.1;
        let has_pending = inner.pending.is_some();
        let retry = matches!(&inner.pending, Some(p) if now.duration_since(p.at) >= REKEY_RETRY);
        if (!has_pending && due) || (has_pending && retry) {
            if let Ok(f) = Core::begin_rekey_locked(cfg, &mut inner, now) {
                out.push(f);
            }
        }
        // Heartbeat
        if now.duration_since(inner.last_ping) >= cfg.keepalive {
            if let Ok(f) = Core::seal_locked(cfg, &mut inner, RT_PING, b"") {
                out.push(f);
                inner.last_ping = now;
            }
        }
        out
    }

    /// Generate/regenerate the rekey ephemeral key and seal the
    /// REKEY_INIT (under the old key).
    fn begin_rekey_locked(
        cfg: &TunnelConfig,
        inner: &mut Inner,
        now: tokio::time::Instant,
    ) -> Result<Vec<u8>, SessionError> {
        // Deterministic tiebreak for dual REKEY_INIT collisions: the
        // lexicographically smaller ephemeral public key wins (both sides
        // compute the same; see implementation note).
        // OsRng: pump tasks need Send across awaits (ThreadRng is Rc and
        // not cross-thread)
        let eph = HybridKeypair::generate(&mut rand::rngs::OsRng);
        let epoch = inner.epoch;
        let mut payload = Vec::with_capacity(8 + kem::HYBRID_PUB_LEN);
        payload.extend_from_slice(&epoch.to_le_bytes());
        payload.extend_from_slice(&eph.public().to_bytes());
        let frame = Core::seal_locked(cfg, inner, RT_REKEY_INIT, &payload)?;
        inner.pending = Some(PendingRekey {
            eph,
            epoch,
            at: now,
        });
        Ok(frame)
    }

    /// Handle a peer REKEY_INIT: the RESP is sealed with the **old send
    /// key** and the switch happens immediately (the single
    /// serialization point = the write pump). Returns None = stale/
    /// collision yield (the peer's INIT won, or ours did).
    fn handle_rekey_init(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, SessionError> {
        let mut r = Rd::new(payload);
        let epoch = r.u64()?;
        let eph_bytes: [u8; kem::HYBRID_PUB_LEN] =
            r.take(kem::HYBRID_PUB_LEN)?.try_into().expect("1216B");

        let mut inner = self.lock();
        if let Some(r) = inner.closed {
            return Err(SessionError::Closed(r));
        }
        if epoch != inner.epoch {
            return Ok(None); // stale retransmission
        }
        if let Some(p) = &inner.pending {
            if p.eph.public().to_bytes() < eph_bytes {
                return Ok(None); // our INIT wins; drop the peer's
            }
        }
        let eph_pub =
            HybridPubkey::from_bytes(&eph_bytes).map_err(|_| SessionError::Protocol("rekey ek"))?;
        let (ss, ct) = kem::encapsulate(&eph_pub, &mut rand::rngs::OsRng);
        let mut resp = Vec::with_capacity(8 + kem::HYBRID_CT_LEN);
        resp.extend_from_slice(&epoch.to_le_bytes());
        resp.extend_from_slice(&ct.to_bytes());
        // The RESP must be sealed with the old send key (the peer
        // switches only upon receiving the RESP).
        let frame = Core::seal_locked(&self.cfg, &mut inner, RT_REKEY_RESP, &resp)?;
        // Switch: this end is the responder of this rekey.
        self.switch_locked(
            &mut inner,
            &ss,
            epoch,
            eph_bytes,
            ct.to_bytes(),
            false,
            self.cfg.clock.now(),
        );
        Ok(Some(frame))
    }

    /// Handle a peer REKEY_RESP (our pending INIT got its answer).
    fn handle_rekey_resp(&self, payload: &[u8]) -> Result<(), SessionError> {
        let mut r = Rd::new(payload);
        let epoch = r.u64()?;
        let ct_bytes: [u8; kem::HYBRID_CT_LEN] =
            r.take(kem::HYBRID_CT_LEN)?.try_into().expect("1120B");

        let mut inner = self.lock();
        if let Some(p) = &inner.pending {
            if p.epoch == epoch && epoch == inner.epoch {
                let ct = kem::HybridCt::from_bytes(&ct_bytes);
                if let Some(ss) = kem::decapsulate(&p.eph, &ct) {
                    let eph_pub = p.eph.public().to_bytes();
                    self.switch_locked(
                        &mut inner,
                        &ss,
                        epoch,
                        eph_pub,
                        ct_bytes,
                        true,
                        self.cfg.clock.now(),
                    );
                }
            }
        }
        Ok(())
    }

    /// Switch to the new epoch's keys. `we_are_initiator` = whether this
    /// end is the INIT initiator of this rekey.
    #[allow(clippy::too_many_arguments)]
    fn switch_locked(
        &self,
        inner: &mut Inner,
        ss: &kem::SealedShared,
        epoch: u64,
        eph_pub: [u8; kem::HYBRID_PUB_LEN],
        ct: [u8; kem::HYBRID_CT_LEN],
        we_are_initiator: bool,
        now: tokio::time::Instant,
    ) {
        // th = SHA256(L ‖ epoch ‖ eph_pub ‖ ct); ikm = ss ‖ th; salt = the
        // old rekey_seed
        let mut h = Sha256::new();
        h.update(L_REKEY_TH);
        h.update(epoch.to_le_bytes());
        h.update(eph_pub);
        h.update(ct);
        let th: [u8; 32] = h.finalize().into();
        // ikm/okm = key material (the source of ss and the directional
        // keys): wrapped in Zeroizing, zeroed on Drop (§1.3.3c).
        let mut ikm = Zeroizing::new(Vec::with_capacity(64));
        ikm.extend_from_slice(ss.as_bytes());
        ikm.extend_from_slice(&th);
        let mut okm = Zeroizing::new([0u8; 96]);
        hkdf_sha256(&inner.rekey_seed, &ikm[..], L_REKEY_TRAFFIC, &mut okm[..]);
        let init_key: [u8; 32] = okm[0..32].try_into().expect("32B");
        let resp_key: [u8; 32] = okm[32..64].try_into().expect("32B");

        let aead = inner.aead;
        // The initiator sends init_key and receives resp_key; the
        // responder sends resp_key and receives init_key.
        let (send_key, recv_key) = if we_are_initiator {
            (init_key, resp_key)
        } else {
            (resp_key, init_key)
        };
        let old_recv = std::mem::replace(
            &mut inner.recv,
            DirKeys {
                cipher: make_cipher(aead, &recv_key),
                counter: 0,
                key: recv_key,
            },
        );
        inner.send = DirKeys {
            cipher: make_cipher(aead, &send_key),
            counter: 0,
            key: send_key,
        };
        inner.retained_recv = Some(old_recv); // grace for in-flight old records (the old DirKeys' key is zeroized with its Drop)
        inner.rekey_seed = okm[64..96].try_into().expect("32B");
        inner.epoch = epoch + 1;
        inner.epoch_start = now;
        inner.rekeys += 1;
        inner.pending = None;
        let _ = self.epoch_tx.send(inner.epoch); // epoch observation surface (A10)
    }

    fn stats(&self) -> SessionStats {
        let inner = self.lock();
        SessionStats {
            epoch: inner.epoch,
            rekeys: inner.rekeys,
            sent_records: inner.send.counter,
            received_records: inner.received,
            forge_attempts: inner.forge_attempts,
            replay_rejected: inner.replay_rejected,
            aead: inner.aead,
            closed: inner.closed,
        }
    }
}

// ============================================================================
// Session pumps (read/write/mux drivers)
// ============================================================================

/// Control forwarding read-pump → write-pump (the single serialization
/// point = the write pump, keeping counter order = actual wire order).
/// Control forwarding read-pump → write-pump.
///
/// Sealing discipline (note on the race fixed in this batch): **INIT
/// handling (seal RESP + switch) stays in the write pump** — the write
/// pump is the single sealing point, guaranteeing "sealing order = wire
/// order = counter order"; **the RESP switch (handle_rekey_resp) runs
/// synchronously in the read pump** — if it were forwarded
/// asynchronously over a channel, the read pump would read new-epoch
/// records before the write pump applied the RESP, opening the new key
/// with the old key ⇒ misjudged as forgery and silently dropped, and
/// after K drops the counter is permanently misaligned (a single hit
/// kills the tunnel; independent review measured a single rekey losing
/// 128KiB+ across 18 forgery counts).
enum CtrlCmd {
    Pong,
    PeerInit(Vec<u8>),
}

async fn write_pump<W>(
    mut w: W,
    core: Arc<Core>,
    mut ctrl_rx: mpsc::Receiver<CtrlCmd>,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
) where
    W: AsyncWrite + Unpin + Send,
{
    let mut closed = core.subscribe_closed();
    let mut tick = tokio::time::interval(TIMER_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending_data: Option<Vec<u8>> = None;
    let mut ctrl_done = false;
    let mut data_done = false;

    loop {
        // Pending data lands first (preserving submission order), then
        // back to select.
        if let Some(p) = pending_data.take() {
            let frame = match core.seal_frame(RT_DATA, &p) {
                Ok(f) => f,
                Err(_) => break, // session terminated/hard reject
            };
            if let Err(e) = w.write_all(&frame).await {
                core.kill(CloseReason::Io);
                eprintln!("session: write(data) failed: {e}");
                break;
            }
        }
        tokio::select! {
            biased;
            _ = closed.changed() => break,
            _ = tick.tick() => {
                for frame in core.timer_tick() {
                    if let Err(e) = w.write_all(&frame).await {
                        core.kill(CloseReason::Io);
                        eprintln!("session: write(timer) failed: {e}");
                        break;
                    }
                }
                if core.stats().closed.is_some() { break; }
            }
            cmd = ctrl_rx.recv(), if !ctrl_done => {
                match cmd {
                    Some(CtrlCmd::Pong) => {
                        if let Ok(f) = core.seal_frame(RT_PONG, b"") {
                            if let Err(e) = w.write_all(&f).await {
                                core.kill(CloseReason::Io);
                                eprintln!("session: write(pong) failed: {e}");
                                break;
                            }
                        } else { break; }
                    }
                    Some(CtrlCmd::PeerInit(p)) => {
                        match core.handle_rekey_init(&p) {
                            Ok(Some(f)) => {
                                if let Err(e) = w.write_all(&f).await {
                                    core.kill(CloseReason::Io);
                                    eprintln!("session: write(rekey-resp) failed: {e}");
                                    break;
                                }
                            }
                            Ok(None) => {}
                            Err(_) => break,
                        }
                    }
                    None => ctrl_done = true,
                }
            }
            data = data_rx.recv(), if !data_done && pending_data.is_none() => {
                match data {
                    Some(p) => pending_data = Some(p),
                    None => data_done = true,
                }
            }
        }
        if ctrl_done && data_done {
            break;
        }
    }
    core.kill(CloseReason::SessionClosed);
}

async fn read_pump<R>(
    mut r: R,
    core: Arc<Core>,
    plain_tx: mpsc::Sender<Vec<u8>>,
    ctrl_tx: mpsc::Sender<CtrlCmd>,
) where
    R: AsyncRead + Unpin + Send,
{
    let mut closed = core.subscribe_closed();
    let mut hdr = [0u8; 5];
    loop {
        // Header (with the termination guard)
        let r0 = tokio::select! {
            biased;
            _ = closed.changed() => break,
            res = r.read_exact(&mut hdr) => res,
        };
        if r0.is_err() {
            core.kill(CloseReason::PeerClosed);
            break;
        }
        let len = u32::from_le_bytes(hdr[..4].try_into().expect("4B")) as usize;
        if len == 0 || len > MAX_FRAME {
            core.kill(CloseReason::Protocol);
            break;
        }
        let rtype = hdr[4];
        let mut body = vec![0u8; len - 1];
        let r1 = tokio::select! {
            biased;
            _ = closed.changed() => break,
            res = r.read_exact(&mut body) => res,
        };
        if r1.is_err() {
            core.kill(CloseReason::PeerClosed);
            break;
        }
        match core.open_record(rtype, &body) {
            Ok(payload) => match rtype {
                RT_DATA => {
                    let send = tokio::select! {
                        biased;
                        _ = closed.changed() => None,
                        res = plain_tx.send(payload) => Some(res),
                    };
                    if send.map(|s| s.is_err()).unwrap_or(true) {
                        core.kill(CloseReason::SessionClosed);
                        break;
                    }
                }
                RT_PING => {
                    // PONG is re-sent periodically; dropping on a full
                    // channel is harmless.
                    let _ = ctrl_tx.try_send(CtrlCmd::Pong);
                }
                RT_PONG => {}
                RT_REKEY_INIT => {
                    // The INIT must arrive (the RESP is sealed by the
                    // write pump; if lost, this end has already switched
                    // during the peer's 5s retry and the duplicate INIT is
                    // ignored by the stale check ⇒ the peer can only wait
                    // for the 180s hard reject). On a full channel, wait
                    // for the write pump to consume (the closed guard
                    // prevents hanging); under extreme bidirectional
                    // socket saturation this degrades to dead-link-detect
                    // teardown (fail-loud), never silently dropping data.
                    let sent = tokio::select! {
                        biased;
                        _ = closed.changed() => None,
                        res = ctrl_tx.send(CtrlCmd::PeerInit(payload)) => Some(res),
                    };
                    if sent.map(|r| r.is_err()).unwrap_or(true) {
                        core.kill(CloseReason::SessionClosed);
                        break;
                    }
                }
                RT_REKEY_RESP => {
                    // Apply the switch synchronously (no forwarding): see
                    // the sealing-discipline note in the CtrlCmd docs —
                    // new-epoch records read ahead of the switch must
                    // open immediately with the new key.
                    if core.handle_rekey_resp(&payload).is_err() {
                        core.kill(CloseReason::Protocol);
                        break;
                    }
                }
                _ => {
                    core.kill(CloseReason::Protocol);
                    break;
                }
            },
            Err(SessionError::Closed(_)) => break, // forgery teardown etc.
            Err(_) => {
                // The record authentication failure is already counted as
                // forgery; keep reading (the limit is verdicted by
                // timer/counter).
            }
        }
        core.note_inbound();
    }
    core.kill(CloseReason::PeerClosed);
}

/// Yamux driver command.
enum MuxCmd {
    Open {
        prio: Prio,
        resp: oneshot::Sender<io::Result<Stream>>,
    },
    Shutdown,
}

async fn mux_driver(
    mut conn: yamux::Connection<MuxIo>,
    mut cmd_rx: futures::channel::mpsc::Receiver<MuxCmd>,
    inbound_tx: mpsc::Sender<Stream>,
) {
    use futures::StreamExt;
    use std::task::Poll;
    let mut pending_open: Option<(Prio, oneshot::Sender<io::Result<Stream>>)> = None;
    let mut pending_inbound: Option<yamux::Stream> = None;
    let mut shutting = false;
    loop {
        let done = std::future::poll_fn(|cx| {
            loop {
                match cmd_rx.poll_next_unpin(cx) {
                    Poll::Ready(Some(MuxCmd::Open { prio, resp })) => {
                        if pending_open.is_some() {
                            let _ = resp.send(Err(io::Error::other("mux: open already pending")));
                        } else {
                            pending_open = Some((prio, resp));
                        }
                    }
                    Poll::Ready(Some(MuxCmd::Shutdown)) => shutting = true,
                    Poll::Ready(None) => return Poll::Ready(true),
                    Poll::Pending => break,
                }
            }
            if shutting {
                return match conn.poll_close(cx) {
                    Poll::Ready(_) => Poll::Ready(true),
                    Poll::Pending => Poll::Pending,
                };
            }
            if let Some((prio, resp)) = pending_open.take() {
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(Ok(s)) => {
                        let _ = resp.send(Ok(Stream::new(s, prio)));
                    }
                    Poll::Ready(Err(e)) => {
                        let _ = resp.send(Err(io::Error::other(format!("mux: open: {e}"))));
                    }
                    Poll::Pending => pending_open = Some((prio, resp)),
                }
            }
            // Inbound streams: drain in a loop (taking repeatedly within
            // the same poll_fn, avoiding the wakeup gap of "delivered,
            // returned Pending, but yamux still has buffered inbound
            // streams" — no new socket data would ever wake us again).
            loop {
                if pending_inbound.is_none() {
                    match conn.poll_next_inbound(cx) {
                        Poll::Ready(Some(Ok(s))) => pending_inbound = Some(s),
                        Poll::Ready(Some(Err(e))) => {
                            eprintln!("session: mux inbound error: {e}");
                            return Poll::Ready(true);
                        }
                        Poll::Ready(None) => return Poll::Ready(true),
                        Poll::Pending => break,
                    }
                }
                let s = match pending_inbound.take() {
                    Some(s) => s,
                    None => break,
                };
                match inbound_tx.try_send(Stream::new(s, Prio::Normal)) {
                    Ok(()) => continue,
                    Err(mpsc::error::TrySendError::Full(s)) => {
                        pending_inbound = Some(s.into_inner());
                        break; // inbound channel full: backpressure, wait for a consumer to take before rewaking
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => return Poll::Ready(true),
                }
            }
            Poll::Pending
        })
        .await;
        if done {
            break;
        }
    }
}

// ============================================================================
// Tunnel
// ============================================================================

/// The established tunnel session (deep module: handshake/record
// layer/anti-replay/rekey/heartbeat all built in).
pub struct Tunnel {
    core: Arc<Core>,
    cmd_tx: futures::channel::mpsc::Sender<MuxCmd>,
    inbound_rx: tokio::sync::Mutex<mpsc::Receiver<Stream>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Tunnel {
    /// Open an outbound logical stream (runs inside yamux; the encryption
    /// is invisible to the relay).
    pub async fn open_stream(&self, prio: Prio) -> io::Result<Stream> {
        let (tx, rx) = oneshot::channel();
        let mut cmd = self.cmd_tx.clone();
        futures::SinkExt::send(&mut cmd, MuxCmd::Open { prio, resp: tx })
            .await
            .map_err(|_| io::Error::other("mux: driver gone"))?;
        rx.await
            .map_err(|_| io::Error::other("mux: driver dropped open"))?
    }

    /// Open a TUN packet channel (`[u16 len][ip packet]` framing,
    /// VPN-14).
    pub async fn open_packet_channel(&self) -> io::Result<PacketChannel> {
        let s = self.open_stream(Prio::Normal).await?;
        Ok(PacketChannel::from_stream(s))
    }

    /// Accept a peer-opened logical stream (`None` = multiplexer
    /// terminated).
    pub async fn accept_stream(&self) -> Option<Stream> {
        self.inbound_rx.lock().await.recv().await
    }

    /// Session statistics.
    pub fn stats(&self) -> SessionStats {
        self.core.stats()
    }

    /// Subscribe to the key epoch (advances on each rekey apply; the A10
    /// observation surface for client assembly layers).
    pub fn epoch_watch(&self) -> tokio::sync::watch::Receiver<u64> {
        self.core.subscribe_epoch()
    }

    /// Peer device identifier (server side; `None` on the client side).
    pub fn peer_device_id(&self) -> Option<DeviceId> {
        self.core.lock().peer_device
    }

    /// Peer server identifier (client side; `None` on the server side).
    pub fn peer_server_id(&self) -> Option<ServerId> {
        self.core.lock().peer_server
    }

    /// Graceful shutdown: yamux GoAway/FIN → tear down the session (the
    /// peer observes EOF).
    pub async fn shutdown(mut self) {
        // Tunnel implements Drop (leak-proof pump termination), so self
        // cannot be destructured — graceful shutdown goes through cloned
        // handles.
        let mut cmd = self.cmd_tx.clone();
        let _ = futures::SinkExt::send(&mut cmd, MuxCmd::Shutdown).await;
        drop(cmd);
        let tasks = std::mem::take(&mut self.tasks);
        for t in tasks {
            let _ = tokio::time::timeout(Duration::from_secs(3), t).await;
        }
        drop(self); // Drop: kill(SessionClosed) terminates the pumps
    }
}

impl fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tunnel")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // A drop without an explicit shutdown likewise triggers pump
        // termination (watch broadcast).
        self.core.kill(CloseReason::SessionClosed);
    }
}

fn spawn_session<S>(io: S, core: Arc<Core>, client: bool) -> Tunnel
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (rd, wr): (ReadHalf<S>, WriteHalf<S>) = tokio::io::split(io);
    let (ctrl_tx, ctrl_rx) = mpsc::channel(64);
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
    let (plain_tx, plain_rx) = mpsc::channel::<Vec<u8>>(256);
    let (inbound_tx, inbound_rx) = mpsc::channel::<Stream>(64);

    let wr_task = tokio::spawn(write_pump(wr, core.clone(), ctrl_rx, data_rx));
    let rd_task = tokio::spawn(read_pump(rd, core.clone(), plain_tx, ctrl_tx));
    let mux_io = MuxIo::new(plain_rx, data_tx);
    let mode = if client {
        yamux::Mode::Client
    } else {
        yamux::Mode::Server
    };
    let conn = yamux::Connection::new(mux_io, yamux::Config::default(), mode);
    let (cmd_tx, cmd_rx) = futures::channel::mpsc::channel::<MuxCmd>(16);
    let mux_task = tokio::spawn(mux_driver(conn, cmd_rx, inbound_tx));

    Tunnel {
        core,
        cmd_tx,
        inbound_rx: tokio::sync::Mutex::new(inbound_rx),
        tasks: vec![wr_task, rd_task, mux_task],
    }
}

// ============================================================================
// Handshake: pinned 1-RTT
// ============================================================================

/// Pinned 1-RTT initiation (Noise IK structure + hybrid KEM, §1.3.3c).
///
/// UKS protection: the device signature covers all sent fields of I1
/// plus the protocol context (cluster_id/expected server identity).
pub async fn initiate<S>(
    mut io: S,
    device: &DeviceStaticKeys,
    expect_server: &ServerPin,
    cfg: TunnelConfig,
) -> Result<Tunnel, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // OsRng: the randomness source survives across awaits, must be
    // Send+Sync (ThreadRng is Rc)
    let mut rng = rand::rngs::OsRng;

    // 1) Hybrid shares: X25519(e, s_srv) + ML-KEM ct encapsulated to the
    // server's static hybrid public key (e is generated as a
    // StaticSecret: the same ephemeral key must do both the es and ee
    // DHs, and EphemeralSecret's diffie_hellman consumes by value and is
    // not reusable; here it is used once and destroyed at function end —
    // semantically equivalent)
    let e = StaticSecret::random_from_rng(&mut bridge(&mut rng));
    let e_pub: [u8; 32] = XPub::from(&e).to_bytes();
    let (ml_ct, ml_ss) = expect_server
        .entry
        .static_hybrid_pub
        .ml_kem_encapsulation()
        .encapsulate_with_rng(&mut bridge(&mut rng));
    let x_ss = e.diffie_hellman(expect_server.entry.static_hybrid_pub.x25519_public());
    if !x_ss.was_contributory() {
        return Err(SessionError::Handshake("non-contributory server key"));
    }
    let k1 = k1_from_shares(x_ss.as_bytes(), ml_ss.as_slice());
    // k1/k_enc = handshake key material: wrapped in Zeroizing, zeroed on
    // Drop (§1.3.3c).
    let mut k_enc = Zeroizing::new([0u8; 32]);
    hkdf_sha256(&[], &k1[..], L_I1_ENC, &mut k_enc[..]);

    // 2) I1: algorithm set = this end's preference order; expected
    // identity = the pin's entry.identity_pub
    let aead_list = cfg.aead.encode();
    let dev_x: [u8; 32] = device.x25519_public().to_bytes();
    let dev_ed: [u8; 32] = *device.ed25519_public().as_bytes();
    let sig_ctx = i1_sig_context(
        &expect_server.cluster_id,
        expect_server.entry.identity_pub.as_bytes(),
        I1SignedFields {
            ver: PROTOCOL_VERSION,
            aead_list: &aead_list,
            e_pub: &e_pub,
            ml_ct: ml_ct.as_slice(),
            dev_x: &dev_x,
            dev_ed: &dev_ed,
        },
    );
    let i1 = build_i1(
        I1Parts {
            e_pub: &e_pub,
            ml_ct: &ml_ct,
            k_enc: &k_enc,
            dev_x: &dev_x,
            dev_ed: &dev_ed,
            dev_sig_ctx: &sig_ctx,
            device,
            aead_list: &aead_list,
            expected_identity: &expect_server.entry.identity_pub,
        },
        &mut rng,
    );
    send_frame(&mut io, RT_I1, &i1).await?;

    // 3) R1
    let (t, r1) = recv_frame(&mut io).await?;
    if t != RT_R1 {
        return Err(SessionError::UnexpectedMessage(t));
    }
    let msg = parse_r1(&r1)?;
    let chosen = AeadChoice::from_code(msg.chosen).ok_or(SessionError::Handshake("aead code"))?;
    if !cfg.aead.order.contains(&chosen) {
        return Err(SessionError::Handshake("chosen aead not offered"));
    }
    // Server identity signature (P0-5 tunnel side): covers the I1‖R1
    // transcript
    let sig_ctx = r1_sig_context(
        &expect_server.cluster_id,
        &dev_ed,
        &i1,
        msg.chosen,
        &msg.eph_srv,
    );
    let sig = Signature::from_bytes(&msg.srv_sig);
    if expect_server
        .entry
        .identity_pub
        .verify(&sig_ctx, &sig)
        .is_err()
    {
        return Err(SessionError::Handshake("server signature"));
    }
    // Key confirmation: R1.confirm is sealed with confirm_s
    let ee = e.diffie_hellman(&XPub::from(msg.eph_srv));
    if !ee.was_contributory() {
        return Err(SessionError::Handshake("non-contributory eph"));
    }
    let th = transcript_hash(&i1, chosen, &msg.eph_srv);
    let tk = derive_traffic(&k1, ee.as_bytes(), &th, chosen);
    let confirm_cipher = make_cipher(chosen, &tk.confirm_s);
    match confirm_cipher.open(0, &th, &msg.confirm) {
        Some(pt) if pt == L_CONFIRM => {}
        _ => return Err(SessionError::Handshake("key confirmation")),
    }

    let core = Core::new(cfg, Role::Client, chosen, &tk);
    core.lock().peer_server = Some(expect_server.entry.server_id);
    Ok(spawn_session(io, core, true))
}

// ============================================================================
// Handshake: TOFU first-connect 2-RTT
// ============================================================================

impl<S> fmt::Debug for TofuBootstrap<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TofuBootstrap")
            .field("cluster_id", &self.pin.cluster_id)
            .field(
                "root_fingerprint",
                &fingerprint_ed25519(&self.pin.cluster_root_pub),
            )
            .finish_non_exhaustive()
    }
}

/// TOFU bootstrap intermediate state: R0 received and the credential
/// chain verified, waiting for the user to confirm the root fingerprint
/// before [`TofuBootstrap::confirm`].
///
/// **Residual risk stated plainly**: TOFU does not defend against an
/// online MITM at first login (§1.3.3f/§2.5-3); the root-fingerprint
/// confirmation UI must not be silent. Organizational settings use the
/// strong invite-file path.
pub struct TofuBootstrap<S> {
    io: S,
    device: DeviceStaticKeys,
    cfg: TunnelConfig,
    pin: ServerPin,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> TofuBootstrap<S> {
    /// Cluster root public-key fingerprint (the thing displayed for user
    /// confirmation).
    pub fn root_fingerprint(&self) -> Fingerprint {
        fingerprint_ed25519(&self.pin.cluster_root_pub)
    }

    /// The cluster root public key presented in R0 (what gets pinned into
    /// `trust::PinStore` after confirmation).
    pub fn root_pub(&self) -> &VerifyingKey {
        &self.pin.cluster_root_pub
    }

    /// Expected cluster.
    pub fn cluster_id(&self) -> ClusterId {
        self.pin.cluster_id
    }

    /// The server access material presented in R0 (the public part of
    /// the join credential).
    pub fn server_entry(&self) -> &ServerEntry {
        &self.pin.entry
    }

    /// After user confirmation: send I1/R1 in the pinned form (this
    /// connection is still 2-RTT total; **afterwards no endpoint ever
    /// produces I0 again**).
    pub async fn confirm(self) -> Result<Tunnel, SessionError> {
        initiate(self.io, &self.device, &self.pin, self.cfg).await
    }
}

/// TOFU first-connect initiation (I0 → R0; returns the bootstrap state
/// awaiting confirmation).
///
/// R0 verification: join credential = the root public key's signature
/// over the ServerEntry (a trustworthy material chain) + the server
/// identity's signature over I0‖R0. Note the root public key is
/// self-asserted by R0 — that is exactly where the TOFU residual risk
/// lands.
pub async fn initiate_tofu<S>(
    mut io: S,
    device: DeviceStaticKeys,
    cfg: TunnelConfig,
) -> Result<TofuBootstrap<S>, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut i0 = vec![PROTOCOL_VERSION];
    i0.extend_from_slice(&cfg.aead.encode());
    send_frame(&mut io, RT_I0, &i0).await?;

    let (t, r0) = recv_frame(&mut io).await?;
    if t != RT_R0 {
        return Err(SessionError::UnexpectedMessage(t));
    }
    let mut r = Rd::new(&r0);
    let ver = r.u8()?;
    if ver != PROTOCOL_VERSION {
        return Err(SessionError::Handshake("protocol version"));
    }
    let chosen_code = r.u8()?;
    let chosen = AeadChoice::from_code(chosen_code).ok_or(SessionError::Handshake("aead code"))?;
    if !cfg.aead.order.contains(&chosen) {
        return Err(SessionError::Handshake("chosen aead not offered"));
    }
    let cluster_id = ClusterId(r.arr16()?);
    let root_pub = VerifyingKey::from_bytes(&r.arr32()?)
        .map_err(|_| SessionError::Handshake("root pubkey"))?;
    let server_id = ServerId(r.arr16()?);
    let ep_len = u16::from_le_bytes([r.u8()?, r.u8()?]) as usize;
    let endpoint = String::from_utf8(r.take(ep_len)?.to_vec())
        .map_err(|_| SessionError::Handshake("endpoint encoding"))?;
    let identity_pub = VerifyingKey::from_bytes(&r.arr32()?)
        .map_err(|_| SessionError::Handshake("identity pubkey"))?;
    let hybrid_bytes: [u8; kem::HYBRID_PUB_LEN] =
        r.take(kem::HYBRID_PUB_LEN)?.try_into().expect("1216B");
    let static_hybrid_pub = HybridPubkey::from_bytes(&hybrid_bytes)
        .map_err(|_| SessionError::Handshake("static hybrid pubkey"))?;
    let entry_sig = Signature::from_bytes(r.take(64)?.try_into().expect("64B"));
    let srv_sig = Signature::from_bytes(r.take(64)?.try_into().expect("64B"));
    if !r.done() {
        return Err(SessionError::Protocol("r0 trailing bytes"));
    }

    let entry = ServerEntry {
        server_id,
        relay_endpoint: endpoint,
        identity_pub,
        static_hybrid_pub,
    };
    // Join credential: the root public key's signature over the
    // ServerEntry
    if !verify_server_entry(&root_pub, &cluster_id, &entry, &entry_sig) {
        return Err(SessionError::Handshake("enrollment signature"));
    }
    // The server identity's signature over I0‖R0 (all bytes except its
    // own sig)
    let sig_len = r0.len() - 64;
    let mut sig_ctx = Vec::with_capacity(SIG_R0.len() + i0.len() + sig_len);
    sig_ctx.extend_from_slice(SIG_R0);
    sig_ctx.extend_from_slice(&i0);
    sig_ctx.extend_from_slice(&r0[..sig_len]);
    if identity_pub.verify(&sig_ctx, &srv_sig).is_err() {
        return Err(SessionError::Handshake("server identity signature"));
    }

    Ok(TofuBootstrap {
        io,
        device,
        cfg,
        pin: ServerPin {
            cluster_id,
            cluster_root_pub: root_pub,
            entry,
        },
    })
}

// ============================================================================
// Handshake: server respond
// ============================================================================

/// Server respond: accepts I1 (pinned) or I0→R0→I1 (TOFU
/// first-connect).
///
/// Device-directory three states: NotFound/Revoked/public-key mismatch
/// → the same opaque [`SessionError::DeviceRejected`] (timing-aligned:
/// all three are verdicted after completing I1 decryption and device
/// signature verification).
pub async fn respond<S>(
    mut io: S,
    server: &ServerIdentity,
    dir: impl DeviceDirectory,
    cfg: TunnelConfig,
) -> Result<Tunnel, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (t, payload) = recv_frame(&mut io).await?;
    // Handshake-form observation surface (the M5 assertion A5/A16 "I0
    // must not appear" grep surface): the TOFU bootstrap path leaves an
    // explicit trace; the pinned 1-RTT (RT_I1 direct) prints at session
    // establishment.
    let mut via_tofu = false;
    let i1 = match t {
        RT_I1 => payload,
        RT_I0 => {
            // TOFU first-connect: R0 presents the join credential chain +
            // the cluster root public key, then waits for I1
            eprintln!("session: TOFU bootstrap (I0) received -- 2-RTT path");
            via_tofu = true;
            let mut r = Rd::new(&payload);
            let ver = r.u8()?;
            if ver != PROTOCOL_VERSION {
                return Err(SessionError::Handshake("protocol version"));
            }
            let client_list = parse_aead_list(r.rest())?;
            let chosen = negotiate(&cfg.aead, &client_list).ok_or(SessionError::AeadMismatch)?;

            let entry = server.entry.clone();
            let mut r0 = Vec::with_capacity(1450);
            r0.push(PROTOCOL_VERSION);
            r0.push(chosen.code());
            r0.extend_from_slice(&server.cluster_id.0);
            r0.extend_from_slice(server.root_pub.as_bytes());
            r0.extend_from_slice(&entry.server_id.0);
            r0.extend_from_slice(&(entry.relay_endpoint.len() as u16).to_le_bytes());
            r0.extend_from_slice(entry.relay_endpoint.as_bytes());
            r0.extend_from_slice(entry.identity_pub.as_bytes());
            r0.extend_from_slice(&entry.static_hybrid_pub.to_bytes());
            r0.extend_from_slice(&server.entry_sig.to_bytes());
            // The server identity's signature over I0‖R0 (minus the sig)
            let mut sig_ctx = Vec::with_capacity(SIG_R0.len() + payload.len() + r0.len());
            sig_ctx.extend_from_slice(SIG_R0);
            sig_ctx.extend_from_slice(&payload);
            sig_ctx.extend_from_slice(&r0);
            let sig = server.identity.sign(&sig_ctx);
            r0.extend_from_slice(&sig.to_bytes());
            send_frame(&mut io, RT_R0, &r0).await?;

            let (t2, p2) = recv_frame(&mut io).await?;
            if t2 != RT_I1 {
                return Err(SessionError::UnexpectedMessage(t2));
            }
            p2
        }
        other => return Err(SessionError::UnexpectedMessage(other)),
    };

    // —— I1 handling (shared by both forms) ——
    let msg = parse_i1(&i1)?;
    // Core UKS check: the expected identity carried by I1 must be this
    // machine (the client builds the signature context from the expected
    // identity)
    if msg.expected_identity != *server.identity.verifying_key().as_bytes() {
        return Err(SessionError::Handshake("expected-server-identity"));
    }
    let client_list = parse_aead_list(&msg.aead_list)?;

    // Hybrid decapsulation
    let ml_ct: Ciphertext<MlKem768> = Ciphertext::<MlKem768>::try_from(&msg.ml_ct[..])
        .map_err(|_| SessionError::Protocol("ml ct"))?;
    let ml_ss = server
        .static_hybrid
        .ml_kem_decapsulation()
        .decapsulate(&ml_ct);
    let x_ss = server
        .static_hybrid
        .x25519_secret()
        .diffie_hellman(&XPub::from(msg.e_pub));
    if !x_ss.was_contributory() {
        return Err(SessionError::Handshake("non-contributory e"));
    }
    let k1 = k1_from_shares(x_ss.as_bytes(), ml_ss.as_slice());
    // k1/k_enc = handshake key material: wrapped in Zeroizing, zeroed on
    // Drop (§1.3.3c).
    let mut k_enc = Zeroizing::new([0u8; 32]);
    hkdf_sha256(&[], &k1[..], L_I1_ENC, &mut k_enc[..]);

    // Decrypt the device identity payload (AAD = the sent-fields prefix
    // of I1)
    let aad_len = 1 + msg.aead_list.len() + 32 + 32 + kem::ML_KEM_CT_LEN;
    let aad = &i1[..aad_len];
    let (enc_body, tag) = msg.enc.split_at(msg.enc.len() - 16);
    let tag_arr: [u8; 16] = tag.try_into().expect("16B tag");
    let mut pt = enc_body.to_vec();
    use aes_gcm::aead::inout::InOutBuf;
    use aes_gcm::aead::{AeadCore, AeadInOut, KeyInit as _};
    let cipher = aes_gcm::Aes256Gcm::new(&aes_gcm::Key::<aes_gcm::Aes256Gcm>::from(*k_enc));
    let ok = cipher
        .decrypt_inout_detached(
            &aes_gcm::Nonce::<<aes_gcm::Aes256Gcm as AeadCore>::NonceSize>::from(msg.nonce),
            aad,
            InOutBuf::from(&mut pt[..]),
            &aes_gcm::Tag::from(tag_arr),
        )
        .is_ok();
    if !ok || pt.len() != 128 {
        return Err(SessionError::Handshake("i1 payload"));
    }
    let dev_x: [u8; 32] = pt[..32].try_into().expect("32B");
    let dev_ed: [u8; 32] = pt[32..64].try_into().expect("32B");
    let dev_sig = Signature::from_bytes(pt[64..128].try_into().expect("64B"));
    let dev_ed_vk =
        VerifyingKey::from_bytes(&dev_ed).map_err(|_| SessionError::Handshake("device ed key"))?;

    // Device signature coverage: all sent fields of I1 + the protocol
    // context (cluster_id/expected identity = this machine's identity)
    let sig_ctx = i1_sig_context(
        &server.cluster_id,
        server.identity.verifying_key().as_bytes(),
        I1SignedFields {
            ver: msg.ver,
            aead_list: &msg.aead_list,
            e_pub: &msg.e_pub,
            ml_ct: &msg.ml_ct,
            dev_x: &dev_x,
            dev_ed: &dev_ed,
        },
    );
    if dev_ed_vk.verify(&sig_ctx, &dev_sig).is_err() {
        return Err(SessionError::Handshake("device signature"));
    }

    // Device-directory three states (timing-aligned: the same opaque
    // error)
    let device_id = DeviceId::from_ed25519(&dev_ed_vk);
    match dir.lookup(&device_id).await {
        LookupVerdict::Active(rec) => {
            if *rec.device_ed25519.as_bytes() != dev_ed || rec.device_x25519.as_bytes() != &dev_x {
                return Err(SessionError::DeviceRejected);
            }
        }
        LookupVerdict::NotFound | LookupVerdict::Revoked { .. } => {
            return Err(SessionError::DeviceRejected);
        }
    }

    // Negotiate + R1
    let chosen = negotiate(&cfg.aead, &client_list).ok_or(SessionError::AeadMismatch)?;
    let mut rng = rand::rngs::OsRng; // as above: the Send constraint across awaits
    let eph_srv = StaticSecret::random_from_rng(&mut bridge(&mut rng));
    let eph_srv_pub: [u8; 32] = XPub::from(&eph_srv).to_bytes();
    let th = transcript_hash(&i1, chosen, &eph_srv_pub);
    let ee = eph_srv.diffie_hellman(&XPub::from(msg.e_pub));
    if !ee.was_contributory() {
        return Err(SessionError::Handshake("non-contributory eph"));
    }
    let tk = derive_traffic(&k1, ee.as_bytes(), &th, chosen);

    let sig_ctx = r1_sig_context(
        &server.cluster_id,
        &dev_ed,
        &i1,
        chosen.code(),
        &eph_srv_pub,
    );
    let srv_sig = server.identity.sign(&sig_ctx);

    // Key confirmation (server→client): confirm_s seals a fixed label,
    // AAD = transcript
    let confirm_cipher = make_cipher(chosen, &tk.confirm_s);
    let confirm = confirm_cipher.seal(0, &th, L_CONFIRM);

    let mut r1 = Vec::with_capacity(1 + 32 + 64 + confirm.len());
    r1.push(chosen.code());
    r1.extend_from_slice(&eph_srv_pub);
    r1.extend_from_slice(&srv_sig.to_bytes());
    r1.extend_from_slice(&confirm);
    send_frame(&mut io, RT_R1, &r1).await?;

    let core = Core::new(cfg, Role::Server, chosen, &tk);
    core.lock().peer_device = Some(device_id);
    eprintln!(
        "session: server handshake ok device={device_id} form={}",
        if via_tofu {
            "tofu-2rtt(I0)"
        } else {
            "pinned-1rtt(I1)"
        }
    );
    Ok(spawn_session(io, core, false))
}

// ============================================================================
// Unit tests (internal vectors: record layer/negotiation/key
// schedule/rekey state machine/timers)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn paired_cores(aead: AeadChoice, cfg: TunnelConfig) -> (Arc<Core>, Arc<Core>) {
        let tk = derive_traffic(&[7u8; 32], &[8u8; 32], &[9u8; 32], aead);
        let c = Core::new(cfg.clone(), Role::Client, aead, &tk);
        let s = Core::new(cfg, Role::Server, aead, &tk);
        (c, s)
    }

    #[test]
    fn aead_negotiation_intersection() {
        let server = AeadPreference::default();
        assert_eq!(
            negotiate(&server, &[AeadChoice::XChaCha20Poly1305]),
            Some(AeadChoice::XChaCha20Poly1305)
        );
        // The server's primary tier is in the client's list ⇒ take the
        // first intersection in server order
        assert_eq!(
            negotiate(&server, &[AeadChoice::Aes256GcmSiv, AeadChoice::Aes256Gcm]),
            Some(AeadChoice::Aes256Gcm)
        );
        // No intersection
        let only_gcm = AeadPreference::only(AeadChoice::Aes256Gcm);
        assert_eq!(negotiate(&only_gcm, &[AeadChoice::XChaCha20Poly1305]), None);
    }

    #[test]
    fn aead_list_codec_rejects_garbage() {
        let pref = AeadPreference::default();
        let list = parse_aead_list(&pref.encode()).expect("valid list");
        assert_eq!(list, pref.order);
        assert!(parse_aead_list(&[1, 9]).is_err(), "unknown algorithm code");
        assert!(parse_aead_list(&[2, 1, 1]).is_err(), "duplicate tier");
        assert!(parse_aead_list(&[0]).is_err(), "empty list");
        assert!(parse_aead_list(&[2, 1]).is_err(), "length mismatch");
    }

    #[test]
    fn record_roundtrip_all_three_aeads() {
        for aead in [
            AeadChoice::Aes256Gcm,
            AeadChoice::XChaCha20Poly1305,
            AeadChoice::Aes256GcmSiv,
        ] {
            let (c, s) = paired_cores(aead, TunnelConfig::default());
            let frame = c.seal_frame(RT_DATA, b"hello tunnel").expect("seal");
            let pt = s.open_record(RT_DATA, &frame[5..]).expect("open");
            assert_eq!(pt, b"hello tunnel", "{aead:?}");
            assert_eq!(s.stats().received_records, 1);
        }
    }

    #[test]
    fn record_type_flipped_fails_and_counts_forge() {
        let (c, s) = paired_cores(AeadChoice::Aes256Gcm, TunnelConfig::default());
        let frame = c.seal_frame(RT_DATA, b"x").expect("seal");
        let mut tampered = frame.clone();
        tampered[4] = RT_PING; // tamper the type byte (covered by the AAD)
        assert!(
            s.open_record(RT_PING, &tampered[5..]).is_err(),
            "type is in the AAD"
        );
        assert_eq!(s.stats().forge_attempts, 1, "counted as forgery");
    }

    #[test]
    fn replay_rejected_and_counted_as_forge() {
        let (c, s) = paired_cores(AeadChoice::Aes256Gcm, TunnelConfig::default());
        let frame = c.seal_frame(RT_DATA, b"first").expect("seal");
        let body = frame[5..].to_vec();
        assert!(s.open_record(RT_DATA, &body).is_ok(), "first receive");
        // Byte-level replay: implicit counter = last+1 ⇒ authentication
        // failure ⇒ counted as forgery + recorded as replay
        let err = s
            .open_record(RT_DATA, &body)
            .expect_err("replays must be rejected");
        assert!(matches!(err, SessionError::RecordAuth));
        let st = s.stats();
        assert_eq!(st.forge_attempts, 1);
        assert_eq!(st.replay_rejected, 1);
        // Normal subsequent records still arrive (the counter advanced)
        let f2 = c.seal_frame(RT_DATA, b"second").expect("seal");
        assert!(s.open_record(RT_DATA, &f2[5..]).is_ok());
    }

    #[test]
    fn forge_limit_kills_at_exactly_limit() {
        let cfg = TunnelConfig {
            forge_limit: 100,
            ..TunnelConfig::default()
        };
        let (c, s) = paired_cores(AeadChoice::Aes256Gcm, cfg);
        let _ = c;
        let mut junk = vec![0u8; 32];
        for i in 0..99 {
            junk[0] = i as u8;
            assert!(s.open_record(RT_DATA, &junk).is_err());
        }
        assert_eq!(s.stats().closed, None, "99 attempts do not tear down");
        junk[0] = 99;
        let err = s
            .open_record(RT_DATA, &junk)
            .expect_err("the 100th tears down");
        assert!(matches!(err, SessionError::Closed(CloseReason::ForgeLimit)));
        assert_eq!(s.stats().closed, Some(CloseReason::ForgeLimit));
        assert_eq!(s.stats().forge_attempts, 100);
    }

    #[test]
    fn rekey_handshake_key_agreement_and_counter_reset() {
        let clock = Arc::new(ManualClock::new());
        // Enlarge keepalive to isolate the dead-link verdict (unit tests
        // have no peer replies; the injected clock would trigger the
        // 3×keepalive silence)
        let cfg = TunnelConfig {
            clock: clock.clone(),
            keepalive: Duration::from_secs(3600),
            ..TunnelConfig::default()
        };
        let (c, s) = paired_cores(AeadChoice::Aes256Gcm, cfg);

        // First each side sends one record, delivered in order (the
        // premise of implicit counter = last+1: TCP-order emulation)
        let f1 = c.seal_frame(RT_DATA, b"a").unwrap();
        let f2 = s.seal_frame(RT_DATA, b"b").unwrap();
        open_with(&s, RT_DATA, &f1[5..]).expect("server opens data0");
        open_with(&c, RT_DATA, &f2[5..]).expect("client opens data0");

        // Client triggers a rekey (the injected clock crosses the 120s
        // threshold): the INIT is sealed with the old send key
        clock.advance(Duration::from_secs(121));
        let frames = c.timer_tick();
        let init = frames
            .iter()
            .find(|f| f[4] == RT_REKEY_INIT)
            .expect("REKEY_INIT sent");
        let payload = open_with(&s, RT_REKEY_INIT, &init[5..]).expect("server opens INIT");
        let resp_frame = s
            .handle_rekey_init(&payload)
            .expect("handle")
            .expect("RESP");
        assert_eq!(s.stats().epoch, 1, "the responder switches immediately");
        assert_eq!(s.stats().rekeys, 1);

        // The RESP is sealed with the old send key (this end still holds
        // the old receive key to open it); afterwards the new-key counter
        // starts at 0
        let resp_payload =
            open_with(&c, RT_REKEY_RESP, &resp_frame[5..]).expect("client opens RESP");
        c.handle_rekey_resp(&resp_payload).expect("switch");
        assert_eq!(c.stats().epoch, 1);
        assert_eq!(c.stats().rekeys, 1);

        // Bidirectional communication in the new epoch + the counter
        // resets with the new keys
        let f = c.seal_frame(RT_DATA, b"new epoch").unwrap();
        let pt = open_with(&s, RT_DATA, &f[5..]).expect("server opens new-key record");
        assert_eq!(pt, b"new epoch");
        let g = s.seal_frame(RT_DATA, b"ack").unwrap();
        let pt2 = open_with(&c, RT_DATA, &g[5..]).expect("client opens new-key record");
        assert_eq!(pt2, b"ack");
        // Old-key frames (sent before the rekey but not yet arrived) take
        // the retained grace path: covered by the replay/forge proxy
        // integration in tests/session_mux.rs (here the old key material
        // has been replaced, so old frames cannot be recreated).
    }

    fn open_with(core: &Core, rtype: u8, body: &[u8]) -> Option<Vec<u8>> {
        core.open_record(rtype, body).ok()
    }

    #[test]
    fn timer_triggers_rekey_at_injected_120s() {
        let clock = Arc::new(ManualClock::new());
        // Enlarge keepalive to avoid heartbeat interference with the
        // assertions inside the test
        let cfg = TunnelConfig {
            keepalive: Duration::from_secs(3600),
            clock: clock.clone(),
            ..TunnelConfig::default()
        };
        let (c, _s) = paired_cores(AeadChoice::Aes256Gcm, cfg);

        clock.advance(Duration::from_secs(119));
        assert!(
            !c.timer_tick().iter().any(|f| f[4] == RT_REKEY_INIT),
            "119s does not trigger"
        );
        clock.advance(Duration::from_secs(2));
        assert!(
            c.timer_tick().iter().any(|f| f[4] == RT_REKEY_INIT),
            "120s triggers rekey"
        );
    }

    #[test]
    fn timer_hard_reject_at_injected_180s() {
        let clock = Arc::new(ManualClock::new());
        // Enlarge keepalive to isolate the DeadLink verdict
        let cfg = TunnelConfig {
            keepalive: Duration::from_secs(3600),
            clock: clock.clone(),
            ..TunnelConfig::default()
        };
        let (c, _s) = paired_cores(AeadChoice::Aes256Gcm, cfg);

        clock.advance(Duration::from_secs(120));
        let _ = c.timer_tick(); // REKEY_INIT (no RESP)
        assert_eq!(c.stats().closed, None);
        clock.advance(Duration::from_secs(61)); // 181s: rekey unfinished
        let _ = c.timer_tick();
        assert_eq!(
            c.stats().closed,
            Some(CloseReason::RejectAfter),
            "180s hard reject"
        );
    }

    #[test]
    fn timer_deadlink_after_3x_keepalive_silence() {
        let clock = Arc::new(ManualClock::new());
        let cfg = TunnelConfig {
            keepalive: Duration::from_secs(1),
            clock: clock.clone(),
            ..TunnelConfig::default()
        };
        let (c, _s) = paired_cores(AeadChoice::Aes256Gcm, cfg);
        clock.advance(Duration::from_millis(3100));
        let _ = c.timer_tick();
        assert_eq!(
            c.stats().closed,
            Some(CloseReason::DeadLink),
            "3×keepalive silence tears down"
        );
    }

    #[test]
    fn transcript_and_traffic_keys_deterministic() {
        let a = derive_traffic(&[1; 32], &[2; 32], &[3; 32], AeadChoice::Aes256Gcm);
        let b = derive_traffic(&[1; 32], &[2; 32], &[3; 32], AeadChoice::Aes256Gcm);
        assert_eq!(a.c2s, b.c2s);
        assert_ne!(a.c2s, a.s2c, "directional keys are independent");
        let c = derive_traffic(&[9; 32], &[2; 32], &[3; 32], AeadChoice::Aes256Gcm);
        assert_ne!(a.c2s, c.c2s, "ikm change ⇒ key change");
        // chosen goes into the HKDF info ⇒ different algorithm tiers give
        // different keys
        let d = derive_traffic(&[1; 32], &[2; 32], &[3; 32], AeadChoice::XChaCha20Poly1305);
        assert_ne!(a.c2s, d.c2s);
    }

    #[test]
    fn server_entry_root_sig_tamper_detected() {
        let root = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let mut ident = ServerIdentity::enroll(
            &root,
            ClusterId([1; 16]),
            ServerId([2; 16]),
            "relay.example:23000",
        );
        assert!(
            verify_server_entry(
                &root.verifying_key(),
                &ident.cluster_id,
                &ident.entry,
                &ident.entry_sig
            ),
            "legitimate credential passes"
        );
        // Tamper the entry (swap relay_endpoint)
        ident.entry.relay_endpoint = "evil.example:9".into();
        assert!(
            !verify_server_entry(
                &root.verifying_key(),
                &ident.cluster_id,
                &ident.entry,
                &ident.entry_sig
            ),
            "entry tampered ⇒ root verification fails"
        );
        // Swap the root
        let other_root = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        ident.entry.relay_endpoint = "relay.example:23000".into();
        assert!(
            !verify_server_entry(
                &other_root.verifying_key(),
                &ident.cluster_id,
                &ident.entry,
                &ident.entry_sig
            ),
            "another root ⇒ verification fails"
        );
    }

    /// Compile-time assertion of the BoxFuture seam (§7-M1: async
    /// interface compile-time assertions).
    #[tokio::test]
    async fn device_directory_is_async_boxfuture() {
        fn take_boxfuture<D: DeviceDirectory>(
            d: &D,
            id: &DeviceId,
        ) -> BoxFuture<'static, LookupVerdict> {
            // Compile-time assertion of the BoxFuture seam: lookup must
            // be returnable as a 'static BoxFuture (§7-M1)
            let f: BoxFuture<'static, LookupVerdict> = d.lookup(id);
            f
        }
        let d = |_: &DeviceId| -> BoxFuture<'static, LookupVerdict> {
            Box::pin(async { LookupVerdict::NotFound })
        };
        let v = take_boxfuture(&d, &DeviceId([0; 32])).await;
        assert!(matches!(v, LookupVerdict::NotFound));
        let mem = InMemoryDirectory::new();
        let v = take_boxfuture(&mem, &DeviceId([1; 32])).await;
        assert!(matches!(v, LookupVerdict::NotFound));
    }
}
