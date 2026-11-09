//! M7 名册与控制面共享契约（docs/design.md §7-M7.4 / §2.2 / §3.11）。
//!
//! 本模块是 M7 客户端批次对服务端契约的**类型上收**（偿还架构债）：`PeerInfo`/`PeerKind`
//! 与 `TicketWire`（票据线格式）原定义在 `flock-server`，客户端 `flock-client` 无法依赖
//! 服务端 crate（依赖方向是 server → client 的 tun/route 复用），此前 OPAQUE 登录的
//! 客户端半边只能由 server 测试代偿。上收后两端消费同一类型——**无第二真相源**：
//!
//! - 名册契约（§7-M7.4 逐字固化）：[`PeerKind`]/[`PeerInfo`] 与
//!   `CtrlRequest::PeerListPull` → `CtrlResponse::PeerList`；
//! - 票据线格式（最小面）：[`SignedTicket`]/[`TicketWire`]——**只搬线上形态**，票据
//!   根签发/校验权威（`TicketAuthority`/`TicketIssuer`/nonce 记账）是服务端内部逻辑，
//!   不在此列；
//! - 控制面消息（§2.2/§3.11）：[`CtrlRequest`]/[`CtrlResponse`] 与值类型
//!   [`DevicePubs`]/[`SrAuth`]/[`DeviceOp`]/[`DeviceRowWire`]/[`CtrlError`]、帧编解码
//!   [`send_ctrl_msg`]/[`recv_ctrl_msg`]、key-bind 设备签名 canonical
//!   （[`keybind_canonical`]）——客户端登录/key-bind 半边与服务端逐字节共享；
//! - hostname 规范化（§7-M7.1）：[`normalize_hostname`]/[`HOSTNAME_MAX`]/
//!   [`HOSTNAME_UNKNOWN`]（自 `flock-sync` 上收——客户端上报侧与服务端落库侧同一
//!   截断/空串语义）。
//!
//! 线格式纪律：全部类型为纯数据（serde/postcard），无平台面（wasm32 同编）；**postcard
//! 无字段标签、enum 变体按声明序编码**——两端变体顺序与字段即冻结契约，任何变动都是
//! 线上破坏性变更（与 `flock-sync` 快照兼容性同一纪律）；`CtrlResponse` 的追加位纪律
//! 见其文档（新变体只允许 Err 之后尾部追加）。
//!
//! `flock-server::{control,ticket}` 与 `flock-sync::proto` 以 `pub use` 再导出本模块
//! 类型（既有引用路径不变）。

use serde::{Deserialize, Serialize};

// ============================================================================
// 名册契约（§7-M7.4——契约逐字固化；装配逻辑在 flock-server，两端只共享行类型）
// ============================================================================

/// 名册条目类型（设备 / 服务器自身——服务器也是 peer，§2.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerKind {
    Device,
    Server,
}

/// 名册条目（§7-M7.4 逐字契约）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub vip: [u8; 4],
    pub hostname: String,
    pub owner: String,
    pub kind: PeerKind,
    pub online: bool,
    pub last_seen_unix: u64,
    /// 设备视角 EWMA（bytes/s）：tx = 设备发出、rx = 设备收到。
    pub tx_bps: u64,
    pub rx_bps: u64,
}

// ============================================================================
// 票据线格式（§2.2——最小面：线上形态；签发/校验权威在服务端 ticket.rs）
// ============================================================================

/// 已签名票据（线上形态；postcard 载体）。
///
/// 对客户端不透明：登录取回、状态变更/名册请求回呈。`exp`/`iat` 可读（客户端据此
/// 排周期重登保持票据新鲜，§7-M7.7）；签名校验是服务端职责。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTicket {
    pub user: String,
    pub device: Vec<u8>,
    pub epoch: u64,
    pub iat: u64,
    pub exp: u64,
    pub sig: Vec<u8>,
}

/// 控制流承载的会话票据（对客户端不透明 blob：登录取回、状态变更请求回呈）。
///
/// - [`TicketWire::Local`]：单服形态——票据根 = 本地状态库种子（[`SignedTicket`]）；
/// - [`TicketWire::Sync`]：多主形态——票据根在 Raft 状态内（`flock_sync::ticket::Ticket`
///   线格式；任何服务器都验得了——SR-SIG1 跨服重放面的闭合前提，§2.2）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TicketWire {
    Local(SignedTicket),
    Sync(Vec<u8>),
}

impl TicketWire {
    /// 票据 TTL 估算（秒）：Local 可读 iat/exp；Sync 对客户端不透明 ⇒ 按 §2.2 缺省
    /// 硬顶 60s 估（重登节奏保守侧成立——只是更频繁地重登，不影响正确性）。
    pub fn ttl_hint_secs(&self) -> u64 {
        match self {
            TicketWire::Local(t) => t.exp.saturating_sub(t.iat),
            TicketWire::Sync(_) => 60,
        }
    }
}

// ============================================================================
// hostname 规范化（§7-M7.1——客户端上报侧与服务端落库侧同一语义；自 flock-sync 上收）
// ============================================================================

/// 空上报 hostname 的落库默认值。
pub const HOSTNAME_UNKNOWN: &str = "(unknown)";
/// hostname 长度上限（字节）。
pub const HOSTNAME_MAX: usize = 64;

/// hostname 规范化：trim + 空串 ⇒ [`HOSTNAME_UNKNOWN`] + 超长截断（char 边界安全）。
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
// 控制面消息（§2.2/§3.11——两端共享；装配/分发逻辑在各端）
// ============================================================================

/// 控制协议版本（Hello 交换；不匹配即拒——版本化，§3.11）。
pub const CTRL_PROTO_VERSION: u32 = 1;

/// 单条控制消息上限（防御性；远小于记录层 1MiB 上限）。
pub const MAX_CTRL_MSG: usize = 256 * 1024;

/// 设备静态公钥集 + 入网上报主机名（key-bind/redeem 携带；M7——hostname 空串 ⇒
/// 服务端落 "(unknown)"，客户端上报经 [`normalize_hostname`] 对齐）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePubs {
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
    pub hostname: String,
}

/// SR-SIG1 授权头（`SR-SIG1 user:ts:nonce:sig_b64url`，§1.3.2 逐字节同格式）。
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
    /// owner 名下设备清单（断言/诊断面）。
    List,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CtrlRequest {
    Hello {
        ver: u32,
    },
    /// OPAQUE 注册第一步（设置口令；仅账号未设口令时）。
    PwBegin {
        user: String,
        m1_b64: String,
    },
    /// OPAQUE 注册收尾（落 pass.opaque 记录）。
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
    /// 设备公钥登记（状态变更：需票据 + bind_token 一次性 + 设备签名）。
    KeyBind {
        ticket: TicketWire,
        bind_token: [u8; 16],
        device: DevicePubs,
        sr_sig_pub: [u8; 32],
        device_sig: Vec<u8>,
    },
    /// 票据换发（状态变更：SR-SIG1 + 票据 + nonce；`ticket: None` = 无票据 ⇒ TicketMissing）。
    TicketRenew {
        ticket: Option<TicketWire>,
        auth: SrAuth,
    },
    /// 邀请兑换（状态变更：SR-SIG1 + 票据 + nonce）。
    RedeemInvite {
        ticket: Option<TicketWire>,
        auth: SrAuth,
        invite_b64: String,
        username: String,
        device: DevicePubs,
    },
    /// 注册表操作（状态变更：SR-SIG1 + 票据 + nonce）。
    DeviceOp {
        ticket: Option<TicketWire>,
        auth: SrAuth,
        op: DeviceOp,
    },
    /// 目录拉取（只读，无需票据；根签 ClusterDirectory，§1.3.3f）。
    DirPull {
        since_version: u64,
    },
    /// M7（§7-M7.4）：成员名册拉取（登录票据保护——**票据校验先于名册数据装配**，
    /// 契约序有测试断言）。
    PeerListPull {
        ticket: Option<TicketWire>,
    },
}

/// 控制面响应。**变体位纪律（append-only）**：postcard 按声明序编码判别位——`Err`
/// **之前为冻结区**（变体不得插入/重排/复用判别位），新增变体一律在 `Err` **之后**
/// 尾部追加。`PeerList` 自 Err 之前迁至其后是本纪律的第一次适用（会话态无持久
/// 字节——控制面消息不落盘，两端同源重编译即可，无迁移面）。
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
    /// dir_version 未变 ⇒ bytes 为空（客户端保留既有目录）。
    Directory {
        dir_version: u64,
        bytes: Vec<u8>,
    },
    Err {
        code: CtrlError,
        msg: String,
    },
    /// M7（§7-M7.4）：成员名册（按 VIP 升序；契约逐字固化于 docs/design.md §7-M7.4）。
    PeerList {
        peers: Vec<PeerInfo>,
    },
}

/// 注册表行的线上形态。
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
    /// 错误码的缺省文案（线上 `Err.msg` 的构造源；两端日志/展示共用）。
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

/// key-bind 设备签名域分离标签（公钥经登录态登记，受服务端身份签名覆盖的 bind_token 佐证）。
pub const KEYBIND_LABEL: &[u8] = b"flock-server/control/key-bind/v1";

/// key-bind 设备签名覆盖的规范化字节（§1.3.3f：占有证明；长度前缀定界杜绝拼接歧义）。
///
/// 客户端签名侧与服务端验签侧共享——签名覆盖面即契约，无第二真相源。
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
    // M7：hostname 进设备签名覆盖面（长度前缀定界——与 owner 同纪律，杜绝拼接歧义）。
    v.extend_from_slice(&(device.hostname.len() as u32).to_le_bytes());
    v.extend_from_slice(device.hostname.as_bytes());
    v.extend_from_slice(sr_sig_pub);
    v
}

// ============================================================================
// 帧编解码（§3.11：`[u32 LE len][postcard]`，futures-io 面——mux::Stream 实现之）
// ============================================================================

/// 发送一条控制消息（`[u32 LE len][postcard]`）。
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

/// 接收一条控制消息。
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
// 单元测试：纯数据契约往返 + 帧编解码回环（平台无关；wasm32 同编同测）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 名册条目 postcard 往返（字段逐项——线上形态冻结面的回归锚）。
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
        // Server 变体独立编码位（kind 判别不塌缩）。
        let s = PeerInfo {
            kind: PeerKind::Server,
            vip: [100, 64, 0, 1],
            ..p.clone()
        };
        assert_ne!(postcard::to_allocvec(&s).unwrap(), bytes, "kind 进线格式");
    }

    /// 票据线格式往返 + TTL hint（Local 读 iat/exp；Sync 保守 60s）。
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
        // 倒挂容错（exp < iat ⇒ 0，不 panic）。
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

    /// 控制消息往返（PeerListPull 请求/响应——M7 契约锚点）。
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

    /// 变体位纪律（append-only）：Err 之前为冻结区，PeerList 位于 Err 之后（尾部）——
    /// postcard 按声明序编码判别位（编码首字节即判别位），插入/重排即全体变体改码的
    /// 破坏性变更。会话态无持久字节，两端同源重编译即可。
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
            "Err 判别位 < PeerList（PeerList 在 Err 之后——追加位纪律）"
        );
        assert_eq!(
            p[0], 11,
            "PeerList = 尾变体（12 变体，判别位 11）——新变体只允许其后追加"
        );
    }

    /// key-bind canonical：hostname 变化 ⇒ 覆盖面变化（签名锚定 hostname，M7）。
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
        // 确定性。
        let c = keybind_canonical(&[9; 16], "alice", &[3; 16], &dev("box"), &[4; 32]);
        assert_eq!(a, c);
    }

    /// hostname 规范化（与 flock-sync 同语义——上收不改行为）。
    #[test]
    fn hostname_normalize_semantics() {
        assert_eq!(normalize_hostname("  box-a \n"), "box-a");
        assert_eq!(normalize_hostname(""), HOSTNAME_UNKNOWN);
        assert_eq!(normalize_hostname("   "), HOSTNAME_UNKNOWN);
        // 64B 截断。
        let long = "x".repeat(80);
        assert_eq!(normalize_hostname(&long).len(), HOSTNAME_MAX);
        // char 边界安全（多字节字符不劈开）。
        let cjk = "群".repeat(30); // 90B
        let n = normalize_hostname(&cjk);
        assert_eq!(n.len(), 63, "63B = 21 个三字节字符（64 处劈半回退到边界）");
        assert!(n.chars().all(|c| c == '群'));
    }

    /// 帧编解码回环（内存 futures-io：`[u32 LE len][postcard]` 与生产同路径）。
    #[tokio::test]
    async fn ctrl_frame_roundtrip_over_mem_io() {
        /// 最小 futures-io 内存对象（写收集 → 读回放；测试专用，无并发面）。
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
        // 帧头长度域：`len=0` 拒（防御位行为锚定）。
        io.buf.clear();
        io.buf.extend(0u32.to_le_bytes());
        assert!(
            recv_ctrl_msg::<_, CtrlRequest>(&mut io).await.is_err(),
            "len=0 必须拒绝"
        );
    }
}
