//! M7 roster and control-plane shared contracts (docs/design.md §7-M7.4 /
//! §2.2 / §3.11).
//!
//! This module is the M7 client batch's **type lift-up** of the server
//! contracts (repaying architectural debt): `PeerInfo`/`PeerKind` and
//! `TicketWire` (the ticket wire format) were originally defined in
//! `flock-server`, but the client `flock-client` cannot depend on the
//! server crate (the dependency direction is server → client for
//! tun/route reuse), so the client half of OPAQUE login previously had to
//! be proxied by server tests. After the lift-up both ends consume the
//! same types — **no second source of truth**:
//!
//! - Roster contract (§7-M7.4, frozen verbatim): [`PeerKind`]/
//!   [`PeerInfo`] with `CtrlRequest::PeerListPull` →
//!   `CtrlResponse::PeerList`;
//! - Ticket wire format (minimal surface): [`SignedTicket`]/
//!   [`TicketWire`] — **only the wire shape is moved**; the ticket-root
//!   issuance/verification authority (`TicketAuthority`/`TicketIssuer`/
//!   nonce bookkeeping) is server-internal logic and stays out;
//! - Control-plane messages (§2.2/§3.11): [`CtrlRequest`]/
//!   [`CtrlResponse`] with the value types
//!   [`DevicePubs`]/[`SrAuth`]/[`DeviceOp`]/[`DeviceRowWire`]/
//!   [`CtrlError`], frame codec [`send_ctrl_msg`]/[`recv_ctrl_msg`], and
//!   the key-bind device-signature canonical ([`keybind_canonical`]) —
//!   the client's login/key-bind half shares bytes with the server;
//! - hostname normalization (§7-M7.1):
//!   [`normalize_hostname`]/[`HOSTNAME_MAX`]/[`HOSTNAME_UNKNOWN`]
//!   (lifted from `flock-sync` — the client's reporting side and the
//!   server's persistence side share the same truncation/empty-string
//!   semantics).
//!
//! Wire-format discipline: all types are pure data (serde/postcard), no
//! platform surface (wasm32 compiles the same); **postcard has no field
//! tags and encodes enum variants in declaration order** — both ends'
//! variant order and fields are the frozen contract; any change is a
//! breaking wire change (the same discipline as `flock-sync` snapshot
//! compatibility); `CtrlResponse`'s append-only discipline is documented
//! on it (new variants may only be appended after Err).
//!
//! `flock-server::{control,ticket}` and `flock-sync::proto` re-export
//! this module's types via `pub use` (existing reference paths
//! unchanged).

use serde::{Deserialize, Serialize};

// ============================================================================
// Roster contract (§7-M7.4 — contract frozen verbatim; assembly logic
// lives in flock-server, both ends share only the row types)
// ============================================================================

/// Roster entry kind (device / the server itself — the server is also a
/// peer, §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerKind {
    Device,
    Server,
}

/// Roster entry (§7-M7.4 verbatim contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub vip: [u8; 4],
    pub hostname: String,
    pub owner: String,
    pub kind: PeerKind,
    pub online: bool,
    pub last_seen_unix: u64,
    /// Device-perspective EWMA (bytes/s): tx = sent by the device, rx =
    /// received by the device.
    pub tx_bps: u64,
    pub rx_bps: u64,
}

// ============================================================================
// Ticket wire format (§2.2 — minimal surface: the wire shape; the
// issuance/verification authority is in the server's ticket.rs)
// ============================================================================

/// A signed ticket (wire shape; postcard carrier).
///
/// Opaque to the client: retrieved at login, presented again on
/// state-change/roster requests. `exp`/`iat` are readable (the client
/// schedules periodic re-login off them to keep the ticket fresh,
/// §7-M7.7); signature verification is the server's job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTicket {
    pub user: String,
    pub device: Vec<u8>,
    pub epoch: u64,
    pub iat: u64,
    pub exp: u64,
    pub sig: Vec<u8>,
}

/// The session ticket carried on the control stream (an opaque-to-client
/// blob: retrieved at login, presented again on state-change requests).
///
/// - [`TicketWire::Local`]: single-server shape — ticket root = the local
///   state-store seed ([`SignedTicket`]);
/// - [`TicketWire::Sync`]: multi-primary shape — the ticket root lives
///   inside Raft state (the `flock_sync::ticket::Ticket` wire format;
///   verifiable by any server — the closure precondition for the
///   SR-SIG1 cross-server replay surface, §2.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TicketWire {
    Local(SignedTicket),
    Sync(Vec<u8>),
}

impl TicketWire {
    /// Ticket TTL estimate (seconds): Local has readable iat/exp; Sync is
    /// opaque to the client ⇒ assume the §2.2 default hard cap of 60s
    /// (the re-login cadence errs on the conservative side — it merely
    /// re-logs in more often, correctness is unaffected).
    pub fn ttl_hint_secs(&self) -> u64 {
        match self {
            TicketWire::Local(t) => t.exp.saturating_sub(t.iat),
            TicketWire::Sync(_) => 60,
        }
    }
}

// ============================================================================
// hostname normalization (§7-M7.1 — the client's reporting side and the
// server's persistence side share the same semantics; lifted from
// flock-sync)
// ============================================================================

/// Persistence default for an empty reported hostname.
pub const HOSTNAME_UNKNOWN: &str = "(unknown)";
/// hostname length cap (bytes).
pub const HOSTNAME_MAX: usize = 64;

/// hostname normalization: trim + empty string ⇒ [`HOSTNAME_UNKNOWN`] +
/// over-length truncation (char-boundary safe).
pub fn normalize_hostname(raw: &str) -> String {
    let t = raw.trim();
    if t.is_empty() {
        return HOSTNAME_UNKNOWN.to_string();
    }
    if t.len() <= HOSTNAME_MAX {
        return t.to_string();
    }
    let mut cut = HOSTNAME_MAX;
    while !t.is_char_boundary(cut) {
        cut -= 1;
    }
    t[..cut].to_string()
}

// ============================================================================
// Control-plane messages (§2.2/§3.11 — shared by both ends;
// assembly/dispatch logic lives in each end)
// ============================================================================

/// Control protocol version (Hello exchange; mismatch is rejected —
/// versioned, §3.11).
pub const CTRL_PROTO_VERSION: u32 = 1;

/// Single control-message cap (defensive; far below the record layer's
/// 1MiB cap).
pub const MAX_CTRL_MSG: usize = 256 * 1024;

/// Device static public keys + the onboarding-reported hostname
/// (carried by key-bind/redeem; M7 — empty hostname ⇒ the server
/// persists "(unknown)", the client's reporting aligns via
/// [`normalize_hostname`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePubs {
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
    pub hostname: String,
}

/// SR-SIG1 authorization header (`SR-SIG1 user:ts:nonce:sig_b64url`,
/// §1.3.2 same format byte-for-byte).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrAuth {
    pub header: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceOp {
    Revoke {
        device: [u8; 32],
    },
    Disable {
        device: [u8; 32],
    },
    Enable {
        device: [u8; 32],
    },
    /// Device list under an owner (assertion/diagnostics surface).
    List,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CtrlRequest {
    Hello {
        ver: u32,
    },
    /// OPAQUE registration step 1 (set a password; only when the account
    /// has none yet).
    PwBegin {
        user: String,
        m1_b64: String,
    },
    /// OPAQUE registration finish (persists the pass.opaque record).
    PwCommit {
        record_b64: String,
        profile: u16,
    },
    LoginBegin {
        user: String,
        ke1_b64: String,
    },
    LoginFinish {
        ke3_b64: String,
    },
    /// Device public-key registration (state change: requires ticket +
    /// one-time bind_token + device signature).
    KeyBind {
        ticket: TicketWire,
        bind_token: [u8; 16],
        device: DevicePubs,
        sr_sig_pub: [u8; 32],
        device_sig: Vec<u8>,
    },
    /// Ticket renewal (state change: SR-SIG1 + ticket + nonce; `ticket:
    /// None` = no ticket ⇒ TicketMissing).
    TicketRenew {
        ticket: Option<TicketWire>,
        auth: SrAuth,
    },
    /// Invite redemption (state change: SR-SIG1 + ticket + nonce).
    RedeemInvite {
        ticket: Option<TicketWire>,
        auth: SrAuth,
        invite_b64: String,
        username: String,
        device: DevicePubs,
    },
    /// Registry operation (state change: SR-SIG1 + ticket + nonce).
    DeviceOp {
        ticket: Option<TicketWire>,
        auth: SrAuth,
        op: DeviceOp,
    },
    /// Directory pull (read-only, no ticket needed; the root-signed
    /// ClusterDirectory, §1.3.3f).
    DirPull {
        since_version: u64,
    },
    /// M7 (§7-M7.4): member roster pull (login-ticket protected —
    /// **ticket validation precedes roster assembly**; the contract order
    /// has a test assertion).
    PeerListPull {
        ticket: Option<TicketWire>,
    },
}

/// Control-plane response. **Variant-slot discipline (append-only)**:
/// postcard encodes discriminants in declaration order — everything
/// **before `Err` is a frozen zone** (no inserting/reordering/reusing
/// discriminants); new variants are always appended at the tail **after
/// `Err`**. `PeerList` migrating from before Err to after it was this
/// discipline's first application (session state has no persisted bytes
/// — control-plane messages are not persisted; both ends recompile from
/// the same source, no migration surface).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CtrlResponse {
    Hello {
        ver: u32,
        cluster_id: [u8; 16],
        server_id: [u8; 16],
    },
    PwChallenge {
        m2_b64: String,
    },
    Ok,
    LoginChallenge {
        ke2_b64: String,
        bind_token: [u8; 16],
        anchor_sig: Vec<u8>,
    },
    LoginOk {
        ticket: TicketWire,
        epoch: u64,
    },
    KeyBound {
        device_id: [u8; 32],
        vip: [u8; 4],
    },
    TicketRenewed {
        ticket: TicketWire,
    },
    Redeemed {
        device_id: [u8; 32],
        vip: [u8; 4],
    },
    DeviceList {
        rows: Vec<DeviceRowWire>,
    },
    /// dir_version unchanged ⇒ bytes is empty (the client keeps its
    /// existing directory).
    Directory {
        dir_version: u64,
        bytes: Vec<u8>,
    },
    Err {
        code: CtrlError,
        msg: String,
    },
    /// M7 (§7-M7.4): member roster (ascending by VIP; contract frozen
    /// verbatim in docs/design.md §7-M7.4).
    PeerList {
        peers: Vec<PeerInfo>,
    },
}

/// Wire shape of a registry row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRowWire {
    pub device_id: [u8; 32],
    pub owner: String,
    pub vip: [u8; 4],
    pub status: u8, // 1=Active 2=Disabled 3=Revoked 4=Expired
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CtrlError {
    ProtoVersion,
    NotAuthorized,
    PasswordExists,
    LoginFailed,
    TicketMissing,
    TicketBad,
    SigFormat,
    SigStale,
    SigBad,
    NonceReplay,
    BindTokenUsed,
    BindSigBad,
    DeviceUnknown,
    InviteUsed,
    InviteRevoked,
    InviteExpired,
    InviteUnknown,
    InviteBadSig,
    UserExists,
    DeviceExists,
    IpExhausted,
    InvalidState,
    Internal,
}

impl CtrlError {
    /// Default message text for an error code (the construction source of
    /// the wire `Err.msg`; shared by both ends' logs/display).
    pub fn msg(self) -> &'static str {
        match self {
            CtrlError::ProtoVersion => "control protocol version mismatch",
            CtrlError::NotAuthorized => "not authorized for this operation",
            CtrlError::PasswordExists => "password already set",
            CtrlError::LoginFailed => "opaque login rejected",
            CtrlError::TicketMissing => "state-changing request requires a valid ticket",
            CtrlError::TicketBad => "ticket rejected (signature/ttl/epoch/revocation)",
            CtrlError::SigFormat => "SR-SIG1 malformed",
            CtrlError::SigStale => "SR-SIG1 timestamp outside ±300s window",
            CtrlError::SigBad => "SR-SIG1 signature verification failed",
            CtrlError::NonceReplay => "nonce replayed",
            CtrlError::BindTokenUsed => "bind_token already consumed",
            CtrlError::BindSigBad => "key-bind device signature rejected",
            CtrlError::DeviceUnknown => "unknown device",
            CtrlError::InviteUsed => "invite already redeemed",
            CtrlError::InviteRevoked => "invite revoked",
            CtrlError::InviteExpired => "invite expired",
            CtrlError::InviteUnknown => "unknown invite",
            CtrlError::InviteBadSig => "invite root signature mismatch",
            CtrlError::UserExists => "username exists",
            CtrlError::DeviceExists => "device already registered",
            CtrlError::IpExhausted => "VIP pool exhausted",
            CtrlError::InvalidState => "invalid state transition",
            CtrlError::Internal => "internal error",
        }
    }
}

/// key-bind device-signature domain-separation label (public keys
/// registered via the login state, attested by the bind_token covered by
/// the server-identity signature).
pub const KEYBIND_LABEL: &[u8] = b"flock-server/control/key-bind/v1";

/// Canonical bytes covered by the key-bind device signature (§1.3.3f:
/// proof of possession; length-prefixed delimiting rules out splicing
/// ambiguity).
///
/// Shared between the client's signing side and the server's verification
/// side — the signature coverage is the contract, no second source of
/// truth.
#[allow(clippy::too_many_arguments)]
pub fn keybind_canonical(
    cluster_id: &[u8; 16],
    user: &str,
    bind_token: &[u8; 16],
    device: &DevicePubs,
    sr_sig_pub: &[u8; 32],
) -> Vec<u8> {
    let mut v =
        Vec::with_capacity(KEYBIND_LABEL.len() + 16 + 8 + user.len() + device.hostname.len() + 116);
    v.extend_from_slice(KEYBIND_LABEL);
    v.extend_from_slice(cluster_id);
    v.extend_from_slice(&(user.len() as u32).to_le_bytes());
    v.extend_from_slice(user.as_bytes());
    v.extend_from_slice(bind_token);
    v.extend_from_slice(&device.x25519);
    v.extend_from_slice(&device.ed25519);
    // M7: hostname enters the device-signature coverage (length-prefixed
    // delimiting — same discipline as owner, ruling out splicing
    // ambiguity).
    v.extend_from_slice(&(device.hostname.len() as u32).to_le_bytes());
    v.extend_from_slice(device.hostname.as_bytes());
    v.extend_from_slice(sr_sig_pub);
    v
}

// ============================================================================
// Frame codec (§3.11: `[u32 LE len][postcard]`, futures-io surface —
// implemented by mux::Stream)
// ============================================================================

/// Send one control message (`[u32 LE len][postcard]`).
pub async fn send_ctrl_msg<S: futures::io::AsyncWrite + Unpin, M: Serialize>(
    io: &mut S,
    msg: &M,
) -> std::io::Result<()> {
    use futures::io::AsyncWriteExt as _;
    let bytes = postcard::to_allocvec(msg).map_err(|e| std::io::Error::other(e.to_string()))?;
    if bytes.len() > MAX_CTRL_MSG {
        return Err(std::io::Error::other("ctrl msg too large"));
    }
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(&bytes);
    io.write_all(&frame).await?;
    io.flush().await
}

/// Receive one control message.
pub async fn recv_ctrl_msg<S: futures::io::AsyncRead + Unpin, M: for<'de> Deserialize<'de>>(
    io: &mut S,
) -> std::io::Result<M> {
    use futures::io::AsyncReadExt as _;
    let mut hdr = [0u8; 4];
    io.read_exact(&mut hdr).await?;
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 || len > MAX_CTRL_MSG {
        return Err(std::io::Error::other("ctrl frame length"));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    postcard::from_bytes(&buf).map_err(|e| std::io::Error::other(e.to_string()))
}

// ============================================================================
// Unit tests: pure-data contract round trips + frame-codec loopback
// (platform-independent; wasm32 compiles and runs the same)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Peer-entry postcard round trip (field by field — a regression
    /// anchor for the frozen wire shape).
    #[test]
    fn peer_info_roundtrip() {
        let p = PeerInfo {
            vip: [100, 64, 0, 2],
            hostname: "box-a".into(),
            owner: "alice".into(),
            kind: PeerKind::Device,
            online: true,
            last_seen_unix: 1_700_000_000,
            tx_bps: 12345,
            rx_bps: 678,
        };
        let bytes = postcard::to_allocvec(&p).unwrap();
        assert_eq!(postcard::from_bytes::<PeerInfo>(&bytes).unwrap(), p);
        // The Server variant gets its own encoding slot (the kind
        // discriminant does not collapse).
        let s = PeerInfo {
            kind: PeerKind::Server,
            vip: [100, 64, 0, 1],
            ..p.clone()
        };
        assert_ne!(
            postcard::to_allocvec(&s).unwrap(),
            bytes,
            "kind is part of the wire format"
        );
    }

    /// Ticket wire-format round trip + TTL hint (Local reads iat/exp;
    /// Sync conservatively 60s).
    #[test]
    fn ticket_wire_roundtrip_and_ttl_hint() {
        let t = TicketWire::Local(SignedTicket {
            user: "alice".into(),
            device: vec![1; 32],
            epoch: 3,
            iat: 1000,
            exp: 1060,
            sig: vec![7; 64],
        });
        let bytes = postcard::to_allocvec(&t).unwrap();
        assert_eq!(postcard::from_bytes::<TicketWire>(&bytes).unwrap(), t);
        assert_eq!(t.ttl_hint_secs(), 60);
        assert_eq!(TicketWire::Sync(vec![9]).ttl_hint_secs(), 60);
        // Inverted-window tolerance (exp < iat ⇒ 0, no panic).
        let odd = TicketWire::Local(SignedTicket {
            iat: 2000,
            exp: 1000,
            ..match t.clone() {
                TicketWire::Local(s) => s,
                _ => unreachable!(),
            }
        });
        assert_eq!(odd.ttl_hint_secs(), 0);
    }

    /// Control-message round trip (PeerListPull request/response — the M7
    /// contract anchor).
    #[test]
    fn ctrl_request_response_roundtrip() {
        let req = CtrlRequest::PeerListPull {
            ticket: Some(TicketWire::Sync(vec![1, 2, 3])),
        };
        let bytes = postcard::to_allocvec(&req).unwrap();
        assert_eq!(postcard::from_bytes::<CtrlRequest>(&bytes).unwrap(), req);

        let resp = CtrlResponse::PeerList {
            peers: vec![PeerInfo {
                vip: [100, 64, 0, 1],
                hostname: "ep".into(),
                owner: "1".into(),
                kind: PeerKind::Server,
                online: true,
                last_seen_unix: 5,
                tx_bps: 0,
                rx_bps: 0,
            }],
        };
        let bytes = postcard::to_allocvec(&resp).unwrap();
        assert_eq!(postcard::from_bytes::<CtrlResponse>(&bytes).unwrap(), resp);

        let err = CtrlResponse::Err {
            code: CtrlError::TicketMissing,
            msg: CtrlError::TicketMissing.msg().to_string(),
        };
        let bytes = postcard::to_allocvec(&err).unwrap();
        assert_eq!(postcard::from_bytes::<CtrlResponse>(&bytes).unwrap(), err);
    }

    /// Variant-slot discipline (append-only): everything before Err is the
    /// frozen zone, PeerList sits after Err (at the tail) — postcard
    /// encodes discriminants in declaration order (the first encoded byte
    /// is the discriminant), so inserting/reordering is a breaking change
    /// that re-codes every variant. Session state has no persisted bytes;
    /// both ends just recompile from the same source.
    #[test]
    fn ctrl_response_variant_order_discipline() {
        let err = CtrlResponse::Err {
            code: CtrlError::Internal,
            msg: String::new(),
        };
        let peers = CtrlResponse::PeerList { peers: vec![] };
        let e = postcard::to_allocvec(&err).unwrap();
        let p = postcard::to_allocvec(&peers).unwrap();
        assert!(
            e[0] < p[0],
            "Err discriminant < PeerList (PeerList after Err — append-only discipline)"
        );
        assert_eq!(
            p[0], 11,
            "PeerList = tail variant (12 variants, discriminant 11) — new variants may only be appended after it"
        );
    }

    /// key-bind canonical: a hostname change ⇒ coverage change (the
    /// signature anchors the hostname, M7).
    #[test]
    fn keybind_canonical_covers_hostname() {
        let dev = |hn: &str| DevicePubs {
            x25519: [1; 32],
            ed25519: [2; 32],
            hostname: hn.into(),
        };
        let a = keybind_canonical(&[9; 16], "alice", &[3; 16], &dev("box"), &[4; 32]);
        let b = keybind_canonical(&[9; 16], "alice", &[3; 16], &dev("box2"), &[4; 32]);
        assert_ne!(a, b);
        // Deterministic.
        let c = keybind_canonical(&[9; 16], "alice", &[3; 16], &dev("box"), &[4; 32]);
        assert_eq!(a, c);
    }

    /// hostname normalization (same semantics as flock-sync — the lift-up
    /// changes no behavior).
    #[test]
    fn hostname_normalize_semantics() {
        assert_eq!(normalize_hostname("  box-a \n"), "box-a");
        assert_eq!(normalize_hostname(""), HOSTNAME_UNKNOWN);
        assert_eq!(normalize_hostname("   "), HOSTNAME_UNKNOWN);
        // 64B truncation.
        let long = "x".repeat(80);
        assert_eq!(normalize_hostname(&long).len(), HOSTNAME_MAX);
        // char-boundary safety (multibyte characters are not split).
        let mbc = "€".repeat(30); // 90B
        let n = normalize_hostname(&mbc);
        assert_eq!(n.len(), 63, "63B = 21 three-byte characters (the 64B cut would split one, so it backs off to the boundary)");
        assert!(n.chars().all(|c| c == '€'));
    }

    /// Frame-codec loopback (in-memory futures-io: `[u32 LE
    /// len][postcard]` over the same path as production).
    #[tokio::test]
    async fn ctrl_frame_roundtrip_over_mem_io() {
        /// Minimal in-memory futures-io object (write collects → read
        /// replays; test-only, no concurrency surface).
        struct MemIo {
            buf: std::collections::VecDeque<u8>,
        }
        impl futures::io::AsyncWrite for MemIo {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                self.buf.extend(buf.iter().copied());
                std::task::Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_close(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        impl futures::io::AsyncRead for MemIo {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut [u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                let n = buf.len().min(self.buf.len());
                for slot in buf.iter_mut().take(n) {
                    *slot = self.buf.pop_front().expect("n ≤ len");
                }
                std::task::Poll::Ready(Ok(n))
            }
        }

        let mut io = MemIo {
            buf: std::collections::VecDeque::new(),
        };
        let resp = CtrlResponse::PeerList { peers: vec![] };
        send_ctrl_msg(&mut io, &CtrlRequest::PeerListPull { ticket: None })
            .await
            .unwrap();
        send_ctrl_msg(&mut io, &resp).await.unwrap();
        let req: CtrlRequest = recv_ctrl_msg(&mut io).await.unwrap();
        assert_eq!(req, CtrlRequest::PeerListPull { ticket: None });
        let got: CtrlResponse = recv_ctrl_msg(&mut io).await.unwrap();
        assert_eq!(got, resp);
        // Frame-header length field: `len=0` rejected (defensive-bit
        // behavior anchor).
        io.buf.clear();
        io.buf.extend(0u32.to_le_bytes());
        assert!(
            recv_ctrl_msg::<_, CtrlRequest>(&mut io).await.is_err(),
            "len=0 must be rejected"
        );
    }
}
