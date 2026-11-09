//! 隧道会话层（docs/design.md §1.3.3c / §3.5，P0-2、P1-8、P1-10 承载）。
//!
//! 深模块契约：调用方只见 [`Tunnel`]；握手、记录层、抗重放、rekey、keepalive、
//! 伪造限额全部内建。
//!
//! # 握手双形态（§1.3.3c / §3.8）
//!
//! - **已钉扎形态（常态 1-RTT，Noise IK 结构）**：
//!   `I1 = ver ‖ 算法集 ‖ 期望服务器身份公钥 ‖ X25519 临时 ‖ ML-KEM-768 ct(1088B，
//!   封给目标服务器静态 ML-KEM 公钥) ‖ AEAD(HKDF(x25519(e,s_srv)‖mlkem_ss); 设备静态
//!   X25519 公钥+设备 Ed25519 公钥+设备签名)`；`R1 = 服务器 X25519 临时 ‖ 服务器身份
//!   对 transcript 的签名 ‖ 双向密钥确认 tag`。握手后首帧即可承数据。
//! - **TOFU 首连形态（仅一次，2-RTT）**：`I0 = ver ‖ 算法集`（无服务器静态材料，明文）→
//!   `R0 = 入群凭证链（ServerEntry 全量 + 集群根公钥 + 根签名）+ 服务器身份对 I0‖R0
//!   的签名` → 客户端验证凭证链、展示根指纹、确认后按钉扎形态发 `I1`/`R1`。
//!   TOFU 不防首登在线 MITM（残余风险，§1.3.3f/§2.5-3）——组织场景走邀请文件强路径。
//!
//! # 签名覆盖契约（防 UKS，§1.3.3c / §3.5）
//!
//! 设备签名覆盖 I1 **全部已发字段** + 协议上下文（cluster_id、期望的服务器身份公钥、
//! 用途标签）；服务器身份签名覆盖 I1‖R1 全 transcript。篡改上下文/换服务器身份 ⇒
//! 验签必失败（M1 失败向量见 tests/session_mux.rs）。
//!
//! # 记录层（P0-2）
//!
//! `[u32 LE len ≤1MiB][type][AEAD(payload)]`；nonce = 32-bit 零 ‖ 64-bit LE 计数器
//! （WireGuard 形态；GCM/GCM-SIV 12B，XChaCha 档 24B = 16B 零 ‖ 计数器）；每方向独立
//! 密钥与计数器。**计数器不上线**——TCP 有序 ⇒ 接收侧以「上一条 +1」重建隐式计数；
//! 任何不匹配（含重放的字节重复、回退）表现为认证失败 ⇒ 拒绝并计入伪造。
//! 长会话禁随机 96-bit nonce（两档分立，§1.3.3b/verdict §3.4）。
//!
//! # rekey（双阈值）
//!
//! (2^60 包, 120s) 先到先触发，REKEY_INIT/RESP 走控制记录（新混合 KEM：
//! INIT 携 1216B 临时混合公钥，RESP 携 1120B 混合密文），epoch 切换后计数器随新密钥
//! 重置；旧接收密钥保留至新密钥首条记录到达（TCP 序下 in-flight 旧记录的宽限路径）；
//! (2^64−2^13−1 包, 180s) 硬拒绝即清零密钥断链。时钟可注入（[`SessionClock`]）。
//!
//! rekey 切换点（竞态修复注记，blocking 复核后定型）：INIT 处理（seal RESP + 切换）在
//! **写泵**（唯一密封点：密封序=上线序=计数器序）；RESP 应用（切换）在**读泵同步执行**——
//! 否则读泵会在 RESP 应用前抢先读入新纪元记录，旧钥解新钥被误判伪造并静默丢弃，且丢弃
//! K 条后隐式计数器永久错位（单次命中即隧道死亡）。另设失步保险丝：连续
//! [`AUTH_FAIL_STREAK`] 条认证失败 ⇒ 显式 Protocol 断链（fail-loud，不做静默丢数据的
//! 半死状态）。
//!
//! # 心跳（§1.3.3d「keepalive = yamux ping 10s」的实现注记，如实声明）
//!
//! yamux 0.14.1 公开 API 不暴露 ping 发起（本次源码核实），10s 心跳由本层加密
//! PING/PONG 记录承担（crypto-2026 §6.4 形态：保活帧本身也是加密帧），静默死链
//! 判定 = 3×keepalive 无入站 ⇒ 断链（A9 语义）。

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
// 常量与帧类型
// ============================================================================

/// 会话协议版本（I0/I1 携带，不匹配即拒）。
pub const PROTOCOL_VERSION: u8 = 1;

/// 单条记录/握手消息上限：`len ≤ 1MiB`（§1.3.3c）。
pub const MAX_FRAME: usize = 1024 * 1024;

/// rekey 触发计数阈值默认值 2^60（WireGuard RekeyAfterMessages，crypto-2026 §6）。
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// 硬拒绝计数阈值默认值 2^64 − 2^13 − 1（WireGuard RejectAfterMessages）。
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - 8192;

/// rekey 触发时间阈值默认 120s。
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// 硬拒绝时间阈值默认 180s。
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// keepalive 默认 10s（§1.3.3c / VPN-16）。
pub const KEEPALIVE: Duration = Duration::from_secs(10);
/// 伪造尝试限额默认 100（P0-2）。
pub const FORGE_LIMIT: u32 = 100;
/// REKEY_INIT 未获 RESP 的重试间隔（wireguard-go RekeyTimeout 节奏，crypto-2026 §6）。
const REKEY_RETRY: Duration = Duration::from_secs(5);
/// 失步保险丝阈值：连续认证失败达此数（且无一条成功插入）判 Protocol 断链。
const AUTH_FAIL_STREAK: u64 = 16;
/// 会话定时器节拍（真实时间；阈值判定用注入时钟）。
const TIMER_TICK: Duration = Duration::from_millis(50);

/// 握手消息类型字节（线上契约，interop/测试向量用）。
pub const RT_I0: u8 = 0x01;
pub const RT_R0: u8 = 0x02;
pub const RT_I1: u8 = 0x03;
pub const RT_R1: u8 = 0x04;
/// 控制记录（加密后走记录层）。
pub const RT_REKEY_INIT: u8 = 0x10;
pub const RT_REKEY_RESP: u8 = 0x11;
/// 数据记录（yamux 承载）与心跳。
pub const RT_DATA: u8 = 0x20;
pub const RT_PING: u8 = 0x21;
pub const RT_PONG: u8 = 0x22;

// 领域分离标签（HKDF info / 签名上下文 / transcript 上下文）。
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
// 错误
// ============================================================================

/// 会话终止原因（stats 可观测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// 伪造尝试达 [`TunnelConfig::forge_limit`]（P0-2 断链纪律）。
    ForgeLimit,
    /// rekey 双阈值之 (2^64−2^13−1, 180s) 硬拒绝。
    RejectAfter,
    /// 3×keepalive 无入站（静默死链，A9）。
    DeadLink,
    /// 协议违约（帧超限/未知类型）。
    Protocol,
    /// 底层 IO 错误。
    Io,
    /// 对端关闭（EOF）。
    PeerClosed,
    /// 本端主动关闭（[`Tunnel::shutdown`] / Drop）。
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

/// 会话层错误。
#[derive(Debug)]
pub enum SessionError {
    /// 底层 IO。
    Io(io::Error),
    /// 握手验证失败（stage 标注：签名/解密/版本/身份等）。
    Handshake(&'static str),
    /// 设备被拒（NotFound/Revoked/公钥不匹配——**不区分**，防在线探测枚举，§1.3.3c）。
    DeviceRejected,
    /// AEAD 协商无交集（P1-8）。
    AeadMismatch,
    /// 状态机收到非预期消息类型（字节为收到的 type）。
    UnexpectedMessage(u8),
    /// 协议违约。
    Protocol(&'static str),
    /// 记录认证失败（已计入伪造）。
    RecordAuth,
    /// 会话已终止。
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
// 时钟注入
// ============================================================================

/// 会话单调时钟接缝：rekey/硬拒绝/keepalive 的阈值判定全部走它（测试注入 [`ManualClock`]）。
pub trait SessionClock: Send + Sync + 'static {
    /// 当前单调时刻。
    fn now(&self) -> tokio::time::Instant;
}

/// 系统时钟（默认）。
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SessionClock for SystemClock {
    fn now(&self) -> tokio::time::Instant {
        tokio::time::Instant::now()
    }
}

/// 可手动拨动的时钟（测试/基准注入用）。
pub struct ManualClock {
    now: StdMutex<tokio::time::Instant>,
}

impl ManualClock {
    /// 以当前真实时刻起。
    pub fn new() -> Self {
        ManualClock {
            now: StdMutex::new(tokio::time::Instant::now()),
        }
    }

    /// 前拨 `d`（rekey/硬拒绝阈值判定即刻可见）。
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
// AEAD 档位与协商（P1-8）
// ============================================================================

/// 记录层 AEAD 算法（主 AES-256-GCM；后备 XChaCha20-Poly1305 / AES-256-GCM-SIV）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AeadChoice {
    /// 主档：AES-256-GCM（aes-gcm 0.11.1，有 AES-NI 硬件时最快，verdict §0）。
    Aes256Gcm,
    /// 后备：XChaCha20-Poly1305（无 AES 硬件端）。
    XChaCha20Poly1305,
    /// 后备：AES-256-GCM-SIV（抗误用/复制敏感场景）。
    Aes256GcmSiv,
}

impl AeadChoice {
    /// 线上代码字节。
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

/// 有序偏好列表；协商 = 服务器按自身顺序取第一个也出现在客户端列表中的档位（交集）。
#[derive(Debug, Clone)]
pub struct AeadPreference {
    /// 有序偏好（至少一项，去重）。
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
    /// 单档偏好（测试/钉死部署用）。
    pub fn only(c: AeadChoice) -> Self {
        AeadPreference { order: vec![c] }
    }

    /// 编码为线上 `[n][codes]`。
    fn encode(&self) -> Vec<u8> {
        let mut v = vec![self.order.len() as u8];
        v.extend(self.order.iter().map(|c| c.code()));
        v
    }
}

/// 协商：服务器偏好序 × 客户端列表 → 第一个交集项。
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

// —— 统一记录密码（计数器 nonce 构造内部化）——

/// 记录密码接缝：seal/open 以隐式计数器构造 nonce。
trait RecordCipher: Send {
    fn seal(&self, counter: u64, aad: &[u8], pt: &[u8]) -> Vec<u8>;
    fn open(&self, counter: u64, aad: &[u8], ct: &[u8]) -> Option<Vec<u8>>;
}

/// 12B nonce = 4B 零 ‖ 8B LE 计数器（WireGuard 形态，§1.3.3c）。
fn nonce12(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

/// XChaCha 档 24B nonce = 16B 零 ‖ 8B LE 计数器。
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
// 配置
// ============================================================================

/// 隧道配置（§1.3.3c）。
pub struct TunnelConfig {
    /// AEAD 档位与偏好序（协商取交集，P1-8）。
    pub aead: AeadPreference,
    /// keepalive 周期（默认 10s；静默死链判定 = 3×keepalive）。
    pub keepalive: Duration,
    /// rekey 双阈值（默认 (2^60, 120s)）。
    pub rekey_after: (u64, Duration),
    /// 硬拒绝双阈值（默认 (2^64−2^13−1, 180s)）。
    pub reject_after: (u64, Duration),
    /// 伪造尝试限额（默认 100，达限断链）。
    pub forge_limit: u32,
    /// 时钟（默认系统时钟；测试注入 [`ManualClock`]）。
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

/// 会话统计（§1.3.3c `stats()`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStats {
    /// 当前密钥纪元（握手 = 0，每完成一次 rekey +1）。
    pub epoch: u64,
    /// 已完成的 rekey 次数。
    pub rekeys: u64,
    /// 已发送记录数（含控制/心跳）。
    pub sent_records: u64,
    /// 已接收记录数（含控制/心跳）。
    pub received_records: u64,
    /// 伪造尝试累计（含重放，达 [`TunnelConfig::forge_limit`] 断链）。
    pub forge_attempts: u64,
    /// 其中判定为字节级重复（重放）的次数。
    pub replay_rejected: u64,
    /// 协商出的 AEAD 档。
    pub aead: AeadChoice,
    /// 终止原因（存活 = None）。
    pub closed: Option<CloseReason>,
}

// ============================================================================
// 身份与设备目录（§1.3.3c lookup 接缝）
// ============================================================================

/// 集群标识（邀请文件/目录/握手上下文绑定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClusterId(pub [u8; 16]);

/// 服务器标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServerId(pub [u8; 16]);

/// 设备标识 = 设备 Ed25519 公钥指纹（SHA-256，§2.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub [u8; 32]);

impl DeviceId {
    /// 由设备 Ed25519 公钥派生。
    pub fn from_ed25519(vk: &VerifyingKey) -> Self {
        DeviceId(Sha256::digest(vk.as_bytes()).into())
    }

    /// 原始 32B。
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

/// 注册表内的设备记录（静态公钥集，§2.2）。
#[derive(Debug, Clone)]
pub struct DeviceRecord {
    /// 设备静态 X25519 公钥（会话索引/漫游，§2.4）。
    pub device_x25519: XPub,
    /// 设备 Ed25519 公钥（身份）。
    pub device_ed25519: VerifyingKey,
}

/// 目录查询三态判定（§1.3.3c）。
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // Active 携带 64B 设备记录，远低于栈压阈值；盒化反增目录实现负担
pub enum LookupVerdict {
    /// 未注册。
    NotFound,
    /// 已吊销（since_epoch = 吊销纪元，随 Raft apply 推进）。
    Revoked { since_epoch: u64 },
    /// 在册有效。
    Active(DeviceRecord),
}

/// 设备目录接缝：服务端把注册表/吊销查询注入协议库（多主多活的权限点之一）。
///
/// 必须异步（`BoxFuture`）：线性一致读经 Raft leader 是网络往返（§4）；
/// `NotFound` 与 `Revoked` 都必须拒握手且**时序对齐**（防在线探测设备枚举）——
/// 本实现的保证：两种判定在完成同一批握手密码学工作（解密 I1、验设备签名）之后，
/// 返回**同一个**不透明错误 [`SessionError::DeviceRejected`]。
pub trait DeviceDirectory: Send + Sync + 'static {
    /// 查询设备。
    fn lookup(&self, id: &DeviceId) -> BoxFuture<'static, LookupVerdict>;
}

/// 闭包式目录实现（`Fn(&DeviceId) -> BoxFuture<...>` 直接可用）。
impl<F> DeviceDirectory for F
where
    F: Fn(&DeviceId) -> BoxFuture<'static, LookupVerdict> + Send + Sync + 'static,
{
    fn lookup(&self, id: &DeviceId) -> BoxFuture<'static, LookupVerdict> {
        self(id)
    }
}

/// 内存目录（测试/单服形态起步用）。
#[derive(Debug, Clone, Default)]
pub struct InMemoryDirectory {
    devices: HashMap<[u8; 32], DeviceRecord>,
    revoked: HashMap<[u8; 32], u64>,
}

impl InMemoryDirectory {
    /// 空目录。
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册/更新设备。
    pub fn register(&mut self, rec: DeviceRecord) {
        let id: [u8; 32] = Sha256::digest(rec.device_ed25519.as_bytes()).into();
        self.revoked.remove(&id);
        self.devices.insert(id, rec);
    }

    /// 吊销设备。
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
// 设备 / 服务器身份材料
// ============================================================================

/// 设备静态密钥（X25519 会话用 + Ed25519 身份用；客户端生成永不出机，§2.4）。
pub struct DeviceStaticKeys {
    x25519: StaticSecret,
    ed25519: SigningKey,
}

impl DeviceStaticKeys {
    /// 随机生成。
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        DeviceStaticKeys {
            x25519: StaticSecret::random_from_rng(&mut bridge(&mut rng)),
            ed25519: SigningKey::from_bytes(&rand::random::<[u8; 32]>()),
        }
    }

    /// 设备静态 X25519 公钥（32B）。
    pub fn x25519_public(&self) -> XPub {
        XPub::from(&self.x25519)
    }

    /// 设备 Ed25519 公钥。
    pub fn ed25519_public(&self) -> VerifyingKey {
        self.ed25519.verifying_key()
    }

    /// 内部签名钥引用（仅握手签名用）。
    fn signing(&self) -> &SigningKey {
        &self.ed25519
    }

    /// 序列化：32B X25519 私钥 ‖ 32B Ed25519 seed（密钥材料，落盘 0600 由调用方负责）。
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x25519.to_bytes());
        out[32..].copy_from_slice(&self.ed25519.to_bytes());
        out
    }

    /// 由 [] 恢复。
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

/// 服务器接入材料（= §4 入群凭证的公开部分；根签名覆盖，§1.3.3f/§3.8）。
#[derive(Debug, Clone)]
pub struct ServerEntry {
    /// 服务器标识。
    pub server_id: ServerId,
    /// 对应中转用户口（frps host:port）。
    pub relay_endpoint: String,
    /// 服务器身份 Ed25519 公钥（R1 签名验证锚）。
    pub identity_pub: VerifyingKey,
    /// 服务器静态混合公钥（1216B；I1 的 ML-KEM ct 封装给它）。
    pub static_hybrid_pub: HybridPubkey,
}

impl ServerEntry {
    /// 根签名覆盖的规范化字节（`SIG_ENTRY ‖ cluster_id ‖ server_id ‖ endpoint ‖ identity ‖ hybrid`）。
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

/// 集群根密钥对 ServerEntry 的签名（入群凭证；`trust` 模块复用同一规范字节）。
pub fn sign_server_entry(
    root: &SigningKey,
    cluster_id: &ClusterId,
    entry: &ServerEntry,
) -> Signature {
    root.sign(&entry.canonical_bytes(cluster_id))
}

/// 验证入群凭证签名。
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

/// Ed25519 公钥指纹（SHA-256；展示格式同 [`Fingerprint`]）。
pub fn fingerprint_ed25519(vk: &VerifyingKey) -> Fingerprint {
    Fingerprint::from_digest(Sha256::digest(vk.as_bytes()).into())
}

/// 客户端持有的钉扎材料：集群根公钥 + 目标端点的 ServerEntry（§1.3.3c `ServerPin`）。
#[derive(Debug, Clone)]
pub struct ServerPin {
    /// 期望集群。
    pub cluster_id: ClusterId,
    /// 集群根公钥（TOFU/邀请建立；R0 验签锚）。
    pub cluster_root_pub: VerifyingKey,
    /// 目标端点接入材料。
    pub entry: ServerEntry,
}

/// 服务器身份材料（respond 侧）。
pub struct ServerIdentity {
    /// 所属集群。
    pub cluster_id: ClusterId,
    /// 本机服务器标识。
    pub server_id: ServerId,
    /// 身份签名钥（R0/R1 transcript 签名，P0-5 隧道侧）。
    pub identity: SigningKey,
    /// 静态混合密钥（I1 的 KEM 封装目标）。
    pub static_hybrid: HybridKeypair,
    /// 对应 ServerEntry（与 identity/static_hybrid 一致；R0 出示）。
    pub entry: ServerEntry,
    /// 集群根公钥（TOFU R0 出示；客户端钉扎的本体）。
    pub root_pub: VerifyingKey,
    /// 根对本 ServerEntry 的签名（入群凭证，R0 出示）。
    pub entry_sig: Signature,
}

impl ServerIdentity {
    /// 由根密钥签发（测试/运维装配路径：根密钥离线保管，§4）。
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
// 帧与编解码小件
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

/// 解析游标。
/// 解码越界/长度错误（Rd 游标共用错误；session/trust 各自 From 转换，调用点 `?` 直通）。
#[derive(Debug, Clone, Copy)]
pub(crate) struct RdErr(pub &'static str);

impl From<RdErr> for SessionError {
    fn from(e: RdErr) -> Self {
        SessionError::Protocol(e.0)
    }
}

/// 解析游标（session/trust 共用；ponytail：消除 trust 侧逐一同构的复刻）。
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

/// 握手 k1 合流（ikm = x25519_ss ‖ ml_kem_ss，`Zeroizing` 包裹 Drop 清零；
/// 返回值 k1 同为 Zeroizing——调用方即握手 k1/k_enc 的秘密材料纪律，§1.3.3c）。
fn k1_from_shares(x_ss: &[u8], ml_ss: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(x_ss.len() + ml_ss.len()));
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(ml_ss);
    let mut k1 = Zeroizing::new([0u8; 32]);
    hkdf_sha256(&[], &ikm[..], L_I1_K1, &mut k1[..]);
    k1
}

/// 握手最终密钥组（§1.3.3c 记录层初始密钥）。
///
/// 全字段为密钥材料：`ZeroizeOnDrop`——结构体 Drop 时全部清零（§1.3.3c 清零承诺；
/// 派生进 Core 的方向密钥由 [`DirKeys`] 的清零纪律接管）。
#[derive(zeroize::ZeroizeOnDrop)]
struct TrafficKeys {
    c2s: [u8; 32],
    s2c: [u8; 32],
    /// R1 内的服务器→客户端密钥确认（客户端→服务器确认 = 握手后首条加密记录，隐式）。
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
// 握手消息
// ============================================================================

/// I1 已发字段（签名/密钥确认覆盖范围，防 UKS：含两个临时份额与算法集，§1.3.3c）。
struct I1Msg {
    ver: u8,
    aead_list: Vec<u8>,
    expected_identity: [u8; 32],
    e_pub: [u8; 32],
    ml_ct: [u8; kem::ML_KEM_CT_LEN],
    nonce: [u8; 12],
    enc: Vec<u8>, // ct||tag，pt = dev_x(32)‖dev_ed(32)‖dev_sig(64)
}

/// I1 构造入参（收拢避免长参数表）。
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
    // AAD = I1 全部已发字段（ver‖算法集‖期望身份‖e_pub‖ml_ct）
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
    // aead_list 保留「count 字节 + codes」完整形态（与 encode()/签名上下文一致）
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

/// I1 签名覆盖字段（§1.3.3c：全部已发字段——含两个临时份额与算法集）。
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
// 记录层核心状态机
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

/// 方向密钥组（记录密码 + 计数器 + 密钥原材料）。
///
/// 清零纪律（§1.3.3c）：`key` 保留 32B 原材料副本以随本结构体生命期确定性清零
/// （`Drop` 显式抹零；cipher 内的扩展密钥表属上游 crate 内部无法触达——原材料
/// 不残留是本层可达的清零面）。rekey 轮换被替换的旧 [`DirKeys`] 随之清零。
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
    /// 旧接收密钥（rekey 后在途记录的宽限路径；新密钥首条记录到达即弃）。
    retained_recv: Option<DirKeys>,
    rekey_seed: [u8; 32],
    pending: Option<PendingRekey>,
    forge_attempts: u64,
    replay_rejected: u64,
    /// 连续认证失败计数（成功即清零）：失步保险丝——仅在 rekey 窗口内武装（见
    /// open_record），连续 ≥AUTH_FAIL_STREAK 条且无一条成功 ⇒ 密钥失步/实现错误，
    /// 显式断链（fail-loud）优于静默丢数据或半死隧道。
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
        // 会话核心拆解：rekey_seed 显式清零（§1.3.3c）；方向密钥原材料随
        // send/recv/retained_recv 的 DirKeys::Drop 清零。
        self.rekey_seed.zeroize();
    }
}

/// 硬拒绝（[`CloseReason::RejectAfter`]）/伪造断链（[`CloseReason::ForgeLimit`]）的
/// 显式密钥清零（设计 §1.3.3c「reject_after 触发即清零密钥」承诺）：关闭置位后
/// 立即抹除密钥材料——不再等待 Core 拆解（Drop 兜底之外的显式路径；关闭后
/// seal/open 均先查 closed，无残余密钥消费者）。
fn zeroize_keys_on_close(inner: &mut Inner) {
    inner.rekey_seed.zeroize();
    inner.send.key.zeroize();
    inner.recv.key.zeroize();
    inner.retained_recv = None; // 旧接收密钥（DirKeys::Drop 清零）
}

/// 会话核心（握手后由各泵共享）。
pub(crate) struct Core {
    cfg: TunnelConfig,
    inner: StdMutex<Inner>,
    closed_tx: watch::Sender<bool>,
    /// 密钥纪元观测（rekey apply 时推进；M5 A10 的 epoch 递增观测面）。
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

    /// 订阅密钥纪元变化（初始 0；每次 rekey apply 推进 +1）。
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
            zeroize_keys_on_close(inner); // §1.3.3c：reject_after 触发即清零密钥
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

    /// 打开一条记录：当前密钥（隐式计数 = last+1）→ 旧密钥宽限 → 失败计入伪造。
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
            // 新密钥首条记录 ⇒ 对端已切换，TCP 序下不再有旧密钥在途记录。
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
        // 失步保险丝仅在 rekey 窗口（有 pending INIT 或 retained 旧钥未收尾）内武装：
        // 窗口内的连续失败 = 密钥失步/实现错误 ⇒ 显式 Protocol 断链（fail-loud）；
        // 窗口外的连续失败 = 伪造洪泛，语义归 forge_limit（P0-2：100 次断链）管。
        if inner.auth_fail_streak >= AUTH_FAIL_STREAK
            && (inner.pending.is_some() || inner.retained_recv.is_some())
        {
            let reason = CloseReason::Protocol;
            inner.closed = Some(reason);
            let _ = self.closed_tx.send(true);
            return Err(SessionError::Closed(reason));
        }
        if inner.last_recv_ct == Some(Sha256::digest(body).into()) {
            inner.replay_rejected += 1; // 字节级重复 = 重放向量（同时计入伪造）
        }
        if inner.forge_attempts >= self.cfg.forge_limit as u64 {
            let reason = CloseReason::ForgeLimit;
            inner.closed = Some(reason);
            zeroize_keys_on_close(&mut inner); // 断链纪律（P0-2）：达限即清零密钥
            let _ = self.closed_tx.send(true);
            return Err(SessionError::Closed(reason));
        }
        Err(SessionError::RecordAuth)
    }

    /// 定时器节拍：硬拒绝/死链判定 + rekey 触发/重试 + 心跳。返回待发（已封装）帧。
    fn timer_tick(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let now = self.cfg.clock.now();
        let mut inner = self.lock();
        if inner.closed.is_some() {
            return out;
        }
        let cfg = &self.cfg;
        // 硬拒绝（双阈值：时间/计数）
        if now.duration_since(inner.epoch_start) >= cfg.reject_after.1
            || inner.send.counter >= cfg.reject_after.0
        {
            inner.closed = Some(CloseReason::RejectAfter);
            zeroize_keys_on_close(&mut inner); // §1.3.3c：reject_after 触发即清零密钥
            let _ = self.closed_tx.send(true);
            return out;
        }
        // 静默死链：3×keepalive 无入站
        if now.duration_since(inner.last_inbound) > cfg.keepalive.mul_f64(3.0) {
            inner.closed = Some(CloseReason::DeadLink);
            let _ = self.closed_tx.send(true);
            return out;
        }
        // rekey：无 pending 且双阈值到点 ⇒ 发起；有 pending 且 5s 未应答 ⇒ 换临时钥重试
        let due = inner.send.counter >= cfg.rekey_after.0
            || now.duration_since(inner.epoch_start) >= cfg.rekey_after.1;
        let has_pending = inner.pending.is_some();
        let retry = matches!(&inner.pending, Some(p) if now.duration_since(p.at) >= REKEY_RETRY);
        if (!has_pending && due) || (has_pending && retry) {
            if let Ok(f) = Core::begin_rekey_locked(cfg, &mut inner, now) {
                out.push(f);
            }
        }
        // 心跳
        if now.duration_since(inner.last_ping) >= cfg.keepalive {
            if let Ok(f) = Core::seal_locked(cfg, &mut inner, RT_PING, b"") {
                out.push(f);
                inner.last_ping = now;
            }
        }
        out
    }

    /// 生成/重生成 rekey 临时密钥并封装 REKEY_INIT（旧密钥）。
    fn begin_rekey_locked(
        cfg: &TunnelConfig,
        inner: &mut Inner,
        now: tokio::time::Instant,
    ) -> Result<Vec<u8>, SessionError> {
        // 双 REKEY_INIT 碰撞的确定性裁决：临时公钥字典序小者胜（双方同算，§实现注记）。
        // OsRng：泵任务内跨 await 需 Send（ThreadRng 为 Rc 不可跨线程）
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

    /// 处理对端 REKEY_INIT：RESP 以**旧发送密钥**封装后立即切换（唯一串行点 = 写泵）。
    /// 返回 None = 过期/碰撞弃权（对端 INIT 胜出或我们胜出）。
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
            return Ok(None); // 陈旧重传
        }
        if let Some(p) = &inner.pending {
            if p.eph.public().to_bytes() < eph_bytes {
                return Ok(None); // 我们的 INIT 胜出，弃对端的
            }
        }
        let eph_pub =
            HybridPubkey::from_bytes(&eph_bytes).map_err(|_| SessionError::Protocol("rekey ek"))?;
        let (ss, ct) = kem::encapsulate(&eph_pub, &mut rand::rngs::OsRng);
        let mut resp = Vec::with_capacity(8 + kem::HYBRID_CT_LEN);
        resp.extend_from_slice(&epoch.to_le_bytes());
        resp.extend_from_slice(&ct.to_bytes());
        // RESP 必须用旧发送密钥封装（对端收到 RESP 才切换）。
        let frame = Core::seal_locked(&self.cfg, &mut inner, RT_REKEY_RESP, &resp)?;
        // 切换：本端为该次 rekey 的响应方。
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

    /// 处理对端 REKEY_RESP（本端 pending 的 INIT 得到应答）。
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

    /// 切换到新纪元密钥。`we_are_initiator` = 本端是否为该次 rekey 的 INIT 发起方。
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
        // th = SHA256(L ‖ epoch ‖ eph_pub ‖ ct)；ikm = ss ‖ th；salt = 旧 rekey_seed
        let mut h = Sha256::new();
        h.update(L_REKEY_TH);
        h.update(epoch.to_le_bytes());
        h.update(eph_pub);
        h.update(ct);
        let th: [u8; 32] = h.finalize().into();
        // ikm/okm = 密钥材料（ss 与方向密钥的来源）：Zeroizing 包裹，Drop 清零（§1.3.3c）。
        let mut ikm = Zeroizing::new(Vec::with_capacity(64));
        ikm.extend_from_slice(ss.as_bytes());
        ikm.extend_from_slice(&th);
        let mut okm = Zeroizing::new([0u8; 96]);
        hkdf_sha256(&inner.rekey_seed, &ikm[..], L_REKEY_TRAFFIC, &mut okm[..]);
        let init_key: [u8; 32] = okm[0..32].try_into().expect("32B");
        let resp_key: [u8; 32] = okm[32..64].try_into().expect("32B");

        let aead = inner.aead;
        // initiator 发 init_key 收 resp_key；responder 发 resp_key 收 init_key。
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
        inner.retained_recv = Some(old_recv); // 在途旧记录宽限（旧 DirKeys 的 key 随其 Drop 清零）
        inner.rekey_seed = okm[64..96].try_into().expect("32B");
        inner.epoch = epoch + 1;
        inner.epoch_start = now;
        inner.rekeys += 1;
        inner.pending = None;
        let _ = self.epoch_tx.send(inner.epoch); // 纪元观测面（A10）
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
// 会话泵（读/写/复用驱动）
// ============================================================================

/// 读泵→写泵的控制转发（唯一串行点 = 写泵，保计数器顺序 = 实际上线顺序）。
/// 读泵→写泵的控制转发。
///
/// 密封纪律（本批修复的竞态注记）：**INIT 的处理（seal RESP + 切换）留在写泵**——写泵是
/// 唯一密封点，保证「密封序 = 上线序 = 计数器序」；**RESP 的切换（handle_rekey_resp）在
/// 读泵同步执行**——若经通道异步转发，读泵会在写泵应用 RESP 前抢先读到新纪元记录，
/// 旧钥解新钥 ⇒ 误判伪造并静默丢弃，且丢弃 K 条后计数器永久错位（一次命中即隧道死亡，
/// 独立复核实测单次 rekey 丢 128KiB+ 计 18 次伪造）。
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
        // 待发数据优先落地（保持提交序），随后回到 select。
        if let Some(p) = pending_data.take() {
            let frame = match core.seal_frame(RT_DATA, &p) {
                Ok(f) => f,
                Err(_) => break, // 会话终止/硬拒绝
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
        // 头部（含终止守卫）
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
                    // PONG 周期性重发，通道满丢弃无害。
                    let _ = ctrl_tx.try_send(CtrlCmd::Pong);
                }
                RT_PONG => {}
                RT_REKEY_INIT => {
                    // INIT 必达（RESP 由写泵密封，若丢则对端 5s 重试期间本端已切换、
                    // 重复 INIT 被陈旧判定忽略 ⇒ 对端只能等 180s 硬拒绝）。通道满时等待
                    // 写泵消费（closed 守卫防挂）；极端双向 socket 饱和下退化为死链检测
                    // 断链（fail-loud），不会静默丢数据。
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
                    // 同步应用切换（不转发）：见 CtrlCmd 文档的密封纪律注记——
                    // 抢在切换前读入的新纪元记录必须能立刻用新钥解开。
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
            Err(SessionError::Closed(_)) => break, // 伪造断链等
            Err(_) => {
                // 记录认证失败已计入伪造；继续读（限额由 timer/计数判定）。
            }
        }
        core.note_inbound();
    }
    core.kill(CloseReason::PeerClosed);
}

/// yamux 驱动命令。
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
            // 入站流：循环抽干（同一 poll_fn 内连取，避免「投递后返回 Pending 但 yamux
            // 内部还有已缓冲的入站流」的唤醒缺口——之后不会再有新 socket 数据来唤醒）。
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
                        break; // 入站通道满：背压，等消费者取走再被唤醒
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

/// 建立后的隧道会话（深模块：握手/记录层/抗重放/rekey/心跳全部内藏）。
pub struct Tunnel {
    core: Arc<Core>,
    cmd_tx: futures::channel::mpsc::Sender<MuxCmd>,
    inbound_rx: tokio::sync::Mutex<mpsc::Receiver<Stream>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Tunnel {
    /// 打开一条出站逻辑流（yamux 内跑，加密对中转不可见）。
    pub async fn open_stream(&self, prio: Prio) -> io::Result<Stream> {
        let (tx, rx) = oneshot::channel();
        let mut cmd = self.cmd_tx.clone();
        futures::SinkExt::send(&mut cmd, MuxCmd::Open { prio, resp: tx })
            .await
            .map_err(|_| io::Error::other("mux: driver gone"))?;
        rx.await
            .map_err(|_| io::Error::other("mux: driver dropped open"))?
    }

    /// 打开 TUN 包通道（`[u16 len][ip packet]` 帧化，VPN-14）。
    pub async fn open_packet_channel(&self) -> io::Result<PacketChannel> {
        let s = self.open_stream(Prio::Normal).await?;
        Ok(PacketChannel::from_stream(s))
    }

    /// 接受一条对端打开的逻辑流（`None` = 复用器终止）。
    pub async fn accept_stream(&self) -> Option<Stream> {
        self.inbound_rx.lock().await.recv().await
    }

    /// 会话统计。
    pub fn stats(&self) -> SessionStats {
        self.core.stats()
    }

    /// 订阅密钥纪元（每次 rekey apply 推进；客户端装配层的 A10 观测面）。
    pub fn epoch_watch(&self) -> tokio::sync::watch::Receiver<u64> {
        self.core.subscribe_epoch()
    }

    /// 对端设备标识（服务端侧；客户端侧为 `None`）。
    pub fn peer_device_id(&self) -> Option<DeviceId> {
        self.core.lock().peer_device
    }

    /// 对端服务器标识（客户端侧；服务端侧为 `None`）。
    pub fn peer_server_id(&self) -> Option<ServerId> {
        self.core.lock().peer_server
    }

    /// 优雅关闭：yamux GoAway/FIN → 拆会话（对端观察到 EOF）。
    pub async fn shutdown(mut self) {
        // Tunnel 实现 Drop（防泄漏终止泵），不能解构 self——经克隆句柄做优雅关闭。
        let mut cmd = self.cmd_tx.clone();
        let _ = futures::SinkExt::send(&mut cmd, MuxCmd::Shutdown).await;
        drop(cmd);
        let tasks = std::mem::take(&mut self.tasks);
        for t in tasks {
            let _ = tokio::time::timeout(Duration::from_secs(3), t).await;
        }
        drop(self); // Drop：kill(SessionClosed) 终止各泵
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
        // 未显式 shutdown 的丢弃同样触发各泵终止（watch 广播）。
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
// 握手：已钉扎 1-RTT
// ============================================================================

/// 已钉扎 1-RTT 发起（Noise IK 结构 + 混合 KEM，§1.3.3c）。
///
/// UKS 防护：设备签名覆盖 I1 全部已发字段 + 协议上下文（cluster_id/期望服务器身份）。
pub async fn initiate<S>(
    mut io: S,
    device: &DeviceStaticKeys,
    expect_server: &ServerPin,
    cfg: TunnelConfig,
) -> Result<Tunnel, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // OsRng：随机源跨 await 存续，必须 Send+Sync（ThreadRng 是 Rc）
    let mut rng = rand::rngs::OsRng;

    // 1) 混合份额：X25519(e, s_srv) + ML-KEM ct 封给服务器静态混合公钥
    //（e 用 StaticSecret 生成：同一临时密钥要做 es 与 ee 两次 DH，EphemeralSecret 的
    //  diffie_hellman 按值消费不可复用；此处一次性使用后随函数结束销毁，语义等同）
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
    // k1/k_enc = 握手密钥材料：Zeroizing 包裹，Drop 清零（§1.3.3c）。
    let mut k_enc = Zeroizing::new([0u8; 32]);
    hkdf_sha256(&[], &k1[..], L_I1_ENC, &mut k_enc[..]);

    // 2) I1：算法集 = 本端偏好序；期望身份 = pin 的 entry.identity_pub
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
    // 服务器身份签名（P0-5 隧道侧）：覆盖 I1‖R1 transcript
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
    // 密钥确认：R1.confirm 以 confirm_s 封装
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
// 握手：TOFU 首连 2-RTT
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

/// TOFU 引导中间态：已收 R0 并验凭证链，等用户确认根指纹后 [`TofuBootstrap::confirm`]。
///
/// **残余风险明示**：TOFU 不防首登在线 MITM（§1.3.3f/§2.5-3）；根指纹确认 UI
/// 不得静默。组织场景走邀请文件强路径。
pub struct TofuBootstrap<S> {
    io: S,
    device: DeviceStaticKeys,
    cfg: TunnelConfig,
    pin: ServerPin,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> TofuBootstrap<S> {
    /// 集群根公钥指纹（展示给用户确认的本体）。
    pub fn root_fingerprint(&self) -> Fingerprint {
        fingerprint_ed25519(&self.pin.cluster_root_pub)
    }

    /// R0 出示的集群根公钥（确认后交 `trust::PinStore` 钉扎的本体）。
    pub fn root_pub(&self) -> &VerifyingKey {
        &self.pin.cluster_root_pub
    }

    /// 期望集群。
    pub fn cluster_id(&self) -> ClusterId {
        self.pin.cluster_id
    }

    /// R0 出示的服务器接入材料（入群凭证公开部分）。
    pub fn server_entry(&self) -> &ServerEntry {
        &self.pin.entry
    }

    /// 用户确认后：按钉扎形态发 I1/R1（此连接仍 2-RTT 总计；**此后任何端点不再出现 I0**）。
    pub async fn confirm(self) -> Result<Tunnel, SessionError> {
        initiate(self.io, &self.device, &self.pin, self.cfg).await
    }
}

/// TOFU 首连发起（I0 → R0，返回待确认引导态）。
///
/// R0 验证：入群凭证 = 根公钥对 ServerEntry 的签名（材料链可信）+ 服务器身份对
/// I0‖R0 的签名。注意根公钥是 R0 自assert 的——这正是 TOFU 残余风险的落点。
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
    // 入群凭证：根公钥对 ServerEntry 的签名
    if !verify_server_entry(&root_pub, &cluster_id, &entry, &entry_sig) {
        return Err(SessionError::Handshake("enrollment signature"));
    }
    // 服务器身份对 I0‖R0（除自身 sig 外的全部字节）的签名
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
// 握手：服务端 respond
// ============================================================================

/// 服务端应答：接受 I1（已钉扎）或 I0→R0→I1（TOFU 首连）。
///
/// 设备目录三态：NotFound/Revoked/公钥不匹配 → 同一不透明 [`SessionError::DeviceRejected`]
/// （时序对齐：三者均在完成 I1 解密与设备签名验证之后判定）。
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
    // 握手形态观测面（M5 断言 A5/A16 的「I0 不得出现」grep 面）：TOFU 引导路径
    // 显式留痕；钉扎 1-RTT（RT_I1 直达）在会话建立时打印。
    let mut via_tofu = false;
    let i1 = match t {
        RT_I1 => payload,
        RT_I0 => {
            // TOFU 首连：R0 出示入群凭证链 + 集群根公钥，随后等 I1
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
            // 服务器身份对 I0‖R0(除 sig 外) 的签名
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

    // —— I1 处理（两种形态共用）——
    let msg = parse_i1(&i1)?;
    // UKS 核心检查：I1 携带的期望身份必须是本机（签名上下文由客户端按期望身份构造）
    if msg.expected_identity != *server.identity.verifying_key().as_bytes() {
        return Err(SessionError::Handshake("expected-server-identity"));
    }
    let client_list = parse_aead_list(&msg.aead_list)?;

    // 混合解封
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
    // k1/k_enc = 握手密钥材料：Zeroizing 包裹，Drop 清零（§1.3.3c）。
    let mut k_enc = Zeroizing::new([0u8; 32]);
    hkdf_sha256(&[], &k1[..], L_I1_ENC, &mut k_enc[..]);

    // 解密设备身份载荷（AAD = I1 已发字段前缀）
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

    // 设备签名覆盖：I1 全部已发字段 + 协议上下文（cluster_id/期望身份=本机身份）
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

    // 设备目录三态（时序对齐：同一不透明错误）
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

    // 协商 + R1
    let chosen = negotiate(&cfg.aead, &client_list).ok_or(SessionError::AeadMismatch)?;
    let mut rng = rand::rngs::OsRng; // 同上：跨 await 的 Send 约束
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

    // 密钥确认（服务器→客户端）：confirm_s 封装固定标签，AAD = transcript
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
// 单元测试（内部向量：记录层/协商/密钥日程/rekey 状态机/定时器）
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
        // 服务器主档在客户端列表 ⇒ 取服务器序第一个交集
        assert_eq!(
            negotiate(&server, &[AeadChoice::Aes256GcmSiv, AeadChoice::Aes256Gcm]),
            Some(AeadChoice::Aes256Gcm)
        );
        // 无交集
        let only_gcm = AeadPreference::only(AeadChoice::Aes256Gcm);
        assert_eq!(negotiate(&only_gcm, &[AeadChoice::XChaCha20Poly1305]), None);
    }

    #[test]
    fn aead_list_codec_rejects_garbage() {
        let pref = AeadPreference::default();
        let list = parse_aead_list(&pref.encode()).expect("valid list");
        assert_eq!(list, pref.order);
        assert!(parse_aead_list(&[1, 9]).is_err(), "未知算法码");
        assert!(parse_aead_list(&[2, 1, 1]).is_err(), "重复档位");
        assert!(parse_aead_list(&[0]).is_err(), "空列表");
        assert!(parse_aead_list(&[2, 1]).is_err(), "长度不符");
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
        tampered[4] = RT_PING; // 篡改 type 字节（AAD 覆盖）
        assert!(
            s.open_record(RT_PING, &tampered[5..]).is_err(),
            "type 进 AAD"
        );
        assert_eq!(s.stats().forge_attempts, 1, "计入伪造");
    }

    #[test]
    fn replay_rejected_and_counted_as_forge() {
        let (c, s) = paired_cores(AeadChoice::Aes256Gcm, TunnelConfig::default());
        let frame = c.seal_frame(RT_DATA, b"first").expect("seal");
        let body = frame[5..].to_vec();
        assert!(s.open_record(RT_DATA, &body).is_ok(), "首收");
        // 字节级重放：隐式计数 = last+1 ⇒ 认证失败 ⇒ 计伪造 + 记重放
        let err = s.open_record(RT_DATA, &body).expect_err("重放必拒");
        assert!(matches!(err, SessionError::RecordAuth));
        let st = s.stats();
        assert_eq!(st.forge_attempts, 1);
        assert_eq!(st.replay_rejected, 1);
        // 正常后续记录仍可收（计数器前进）
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
        assert_eq!(s.stats().closed, None, "99 次不断");
        junk[0] = 99;
        let err = s.open_record(RT_DATA, &junk).expect_err("第 100 次断链");
        assert!(matches!(err, SessionError::Closed(CloseReason::ForgeLimit)));
        assert_eq!(s.stats().closed, Some(CloseReason::ForgeLimit));
        assert_eq!(s.stats().forge_attempts, 100);
    }

    #[test]
    fn rekey_handshake_key_agreement_and_counter_reset() {
        let clock = Arc::new(ManualClock::new());
        // keepalive 放大隔离死链判定（单测无对端回包，注入时钟会触发 3×keepalive 静默）
        let cfg = TunnelConfig {
            clock: clock.clone(),
            keepalive: Duration::from_secs(3600),
            ..TunnelConfig::default()
        };
        let (c, s) = paired_cores(AeadChoice::Aes256Gcm, cfg);

        // 先各发一条并按序投递对端（隐式计数 = last+1 的前提：TCP 序仿真）
        let f1 = c.seal_frame(RT_DATA, b"a").unwrap();
        let f2 = s.seal_frame(RT_DATA, b"b").unwrap();
        open_with(&s, RT_DATA, &f1[5..]).expect("server opens data0");
        open_with(&c, RT_DATA, &f2[5..]).expect("client opens data0");

        // client 触发 rekey（注入时钟越过 120s 阈值）：INIT 以旧发送密钥封装
        clock.advance(Duration::from_secs(121));
        let frames = c.timer_tick();
        let init = frames
            .iter()
            .find(|f| f[4] == RT_REKEY_INIT)
            .expect("REKEY_INIT 发出");
        let payload = open_with(&s, RT_REKEY_INIT, &init[5..]).expect("server opens INIT");
        let resp_frame = s
            .handle_rekey_init(&payload)
            .expect("handle")
            .expect("RESP");
        assert_eq!(s.stats().epoch, 1, "响应方立即切换");
        assert_eq!(s.stats().rekeys, 1);

        // RESP 以旧发送密钥封装（本端仍持旧接收密钥可开），随后新密钥计数从 0 起
        let resp_payload =
            open_with(&c, RT_REKEY_RESP, &resp_frame[5..]).expect("client opens RESP");
        c.handle_rekey_resp(&resp_payload).expect("switch");
        assert_eq!(c.stats().epoch, 1);
        assert_eq!(c.stats().rekeys, 1);

        // 新纪元双向通信 + 计数器随新密钥重置
        let f = c.seal_frame(RT_DATA, b"new epoch").unwrap();
        let pt = open_with(&s, RT_DATA, &f[5..]).expect("server opens new-key record");
        assert_eq!(pt, b"new epoch");
        let g = s.seal_frame(RT_DATA, b"ack").unwrap();
        let pt2 = open_with(&c, RT_DATA, &g[5..]).expect("client opens new-key record");
        assert_eq!(pt2, b"ack");
        // 旧密钥帧（rekey 前已发未达）走 retained 宽限路径：由 tests/session_mux.rs 的
        // replay/forge proxy 集成覆盖（此处旧密钥材料已被替换，无法再造旧帧）。
    }

    fn open_with(core: &Core, rtype: u8, body: &[u8]) -> Option<Vec<u8>> {
        core.open_record(rtype, body).ok()
    }

    #[test]
    fn timer_triggers_rekey_at_injected_120s() {
        let clock = Arc::new(ManualClock::new());
        // keepalive 放大避免测试内触发心跳干扰断言
        let cfg = TunnelConfig {
            keepalive: Duration::from_secs(3600),
            clock: clock.clone(),
            ..TunnelConfig::default()
        };
        let (c, _s) = paired_cores(AeadChoice::Aes256Gcm, cfg);

        clock.advance(Duration::from_secs(119));
        assert!(
            !c.timer_tick().iter().any(|f| f[4] == RT_REKEY_INIT),
            "119s 不触发"
        );
        clock.advance(Duration::from_secs(2));
        assert!(
            c.timer_tick().iter().any(|f| f[4] == RT_REKEY_INIT),
            "120s 触发 rekey"
        );
    }

    #[test]
    fn timer_hard_reject_at_injected_180s() {
        let clock = Arc::new(ManualClock::new());
        // keepalive 放大隔离 DeadLink 判定
        let cfg = TunnelConfig {
            keepalive: Duration::from_secs(3600),
            clock: clock.clone(),
            ..TunnelConfig::default()
        };
        let (c, _s) = paired_cores(AeadChoice::Aes256Gcm, cfg);

        clock.advance(Duration::from_secs(120));
        let _ = c.timer_tick(); // REKEY_INIT（无 RESP）
        assert_eq!(c.stats().closed, None);
        clock.advance(Duration::from_secs(61)); // 181s：rekey 未完成
        let _ = c.timer_tick();
        assert_eq!(
            c.stats().closed,
            Some(CloseReason::RejectAfter),
            "180s 硬拒绝"
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
            "3×keepalive 静默断链"
        );
    }

    #[test]
    fn transcript_and_traffic_keys_deterministic() {
        let a = derive_traffic(&[1; 32], &[2; 32], &[3; 32], AeadChoice::Aes256Gcm);
        let b = derive_traffic(&[1; 32], &[2; 32], &[3; 32], AeadChoice::Aes256Gcm);
        assert_eq!(a.c2s, b.c2s);
        assert_ne!(a.c2s, a.s2c, "方向密钥独立");
        let c = derive_traffic(&[9; 32], &[2; 32], &[3; 32], AeadChoice::Aes256Gcm);
        assert_ne!(a.c2s, c.c2s, "ikm 变化 ⇒ 密钥变化");
        // chosen 进 HKDF info ⇒ 算法档变化密钥不同
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
            "合法凭证通过"
        );
        // 篡改条目（换 relay_endpoint）
        ident.entry.relay_endpoint = "evil.example:9".into();
        assert!(
            !verify_server_entry(
                &root.verifying_key(),
                &ident.cluster_id,
                &ident.entry,
                &ident.entry_sig
            ),
            "条目被篡改 ⇒ 根验签失败"
        );
        // 换根
        let other_root = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        ident.entry.relay_endpoint = "relay.example:23000".into();
        assert!(
            !verify_server_entry(
                &other_root.verifying_key(),
                &ident.cluster_id,
                &ident.entry,
                &ident.entry_sig
            ),
            "另一根 ⇒ 验签失败"
        );
    }

    /// BoxFuture 接缝的编译期断言（§7-M1：异步接口编译期断言）。
    #[tokio::test]
    async fn device_directory_is_async_boxfuture() {
        fn take_boxfuture<D: DeviceDirectory>(
            d: &D,
            id: &DeviceId,
        ) -> BoxFuture<'static, LookupVerdict> {
            // BoxFuture 接缝的编译期断言：lookup 必须能以 'static BoxFuture 返回（§7-M1）
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
