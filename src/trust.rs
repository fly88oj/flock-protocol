//! 首登信任锚（docs/design.md §1.3.3(f) / §3.8，P0-5）。
//!
//! 钉扎模型（第三轮评审定型，方案②）：客户端锚定**集群根公钥**，持根签
//! [`ClusterDirectory`]（全套 [`ServerEntry`] = 入群凭证公开部分；端点列表与条目**同一份
//! 签名**覆盖，防「列表真、条目假」的拼接）。任意端点 1-RTT（I1 的 ML-KEM ct 封装给该端点
//! ServerEntry 的静态混合公钥）；单台换钥 = 根签新目录（dir_version 递增）+ 客户端
//! dir_pull 刷新；换端点/新服务器**不出现 I0**。
//!
//! - [`PinStore`]：钉扎粒度 = `cluster_id → 集群根公钥`（known_hosts 语义，集群根级；
//!   服务器级材料不单独 TOFU——由根签名背书）。根公钥变更 = [`PinVerdict::Mismatch`]
//!   （携带新旧两把公钥，显式告警数据源，**不可静默跳过**）。文件适配器首发
//!   （[`PinStore::save`]/[`PinStore::load`]，unix 下 0600）；钥匙库适配器给移动端（接缝）。
//! - [`InviteFile`] v3：根签 ClusterDirectory 全套服务器材料 + 一次性 invite_id + expiry
//!   （默认 7 天，§2.4）。**v1 指纹-only 与 v2 单服务器材料不再接受**——多服务器集群下
//!   无法支撑任意端点 1-RTT（§3.8）。invite_id 单次消费语义由本仓 sync crate 的 Raft 状态机
//!   保证（redeem_invite 查重，§4）；本模块只做结构校验。
//! - [`ClusterDirectory`]：dir_version 单调递增；`PinStore::record_directory` 是
//!   dir_pull 刷新的落地路径（根验签 + 钉扎比对 + 版本回退拒收）。
//!
//! # 残余风险声明（不可静默，§1.3.3f/§2.5-3）
//!
//! **TOFU 不防首登在线 MITM**：首连时攻击者可自签一套「根公钥+凭证链」，客户端把攻击者
//! 的根钉住（SSH known_hosts 同类限制，verdict §3.9 攻击只被部分关闭）。组织场景必须走
//! 邀请文件强路径；TOFU 首连的根指纹确认 UI 不得静默。

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

// 会话层已定义的接入材料类型（同一凭证两用：服务器互认 §4 / 客户端接入材料，§1.3.3f）
// 与共享解析游标 Rd（ponytail：消除与 session 逐一同构的复刻）
pub use crate::session::{
    fingerprint_ed25519, sign_server_entry, verify_server_entry, ClusterId, ServerEntry, ServerId,
    ServerPin,
};
use crate::session::{Rd, RdErr};

/// 邀请文件版本（v3；v1/v2 拒收）。
pub const INVITE_VERSION: u8 = 3;
/// 目录结构版本。
pub const DIRECTORY_VERSION: u8 = 1;
/// 邀请默认有效期：7 天（§1.3.3f「默认 7 天（可配）」）。
pub const INVITE_DEFAULT_TTL_SECS: u64 = 7 * 24 * 3600;

const SIG_DIRECTORY: &[u8] = b"flock-protocol/trust/cluster-directory/v1";
const SIG_INVITE: &[u8] = b"flock-protocol/trust/invite/v3";

/// 信任层错误。
#[derive(Debug)]
pub enum TrustError {
    /// 底层 IO。
    Io(io::Error),
    /// 根签名校验失败（根签名不匹配/条目被篡改/字节损坏）。
    BadSignature,
    /// 邀请文件版本不受支持（v1/v2 拒收；字节为文件内版本）。
    UnsupportedInviteVersion(u8),
    /// 邀请已过期。
    Expired { now_unix: u64, expiry_unix: u64 },
    /// 集群根公钥变更（显式告警路径：携带钉扎值与呈现值，不可静默）。
    /// 两把公钥盒装（Err 载荷尺寸纪律；内容为公钥，堆分配无敏感面）。
    RootChanged {
        cluster_id: ClusterId,
        pinned: Box<VerifyingKey>,
        presented: Box<VerifyingKey>,
    },
    /// 目录版本回退（dir_version 必须单调递增；stored=已见版本，got=本次版本）。
    DirVersionRollback { stored: u64, got: u64 },
    /// 编码违约（长度/字段缺失/尾随字节）。
    Encoding(&'static str),
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustError::Io(e) => write!(f, "trust: io: {e}"),
            TrustError::BadSignature => write!(f, "trust: root signature mismatch"),
            TrustError::UnsupportedInviteVersion(v) => {
                write!(f, "trust: invite version {v} unsupported (v3 only)")
            }
            TrustError::Expired {
                now_unix,
                expiry_unix,
            } => {
                write!(
                    f,
                    "trust: invite expired (now={now_unix}, expiry={expiry_unix})"
                )
            }
            TrustError::RootChanged { cluster_id, .. } => {
                write!(f, "trust: cluster root key changed for {cluster_id:?} (explicit re-confirmation required)")
            }
            TrustError::DirVersionRollback { stored, got } => {
                write!(
                    f,
                    "trust: directory version rollback (stored={stored}, got={got})"
                )
            }
            TrustError::Encoding(s) => write!(f, "trust: encoding: {s}"),
        }
    }
}
impl std::error::Error for TrustError {}
impl From<RdErr> for TrustError {
    fn from(e: RdErr) -> Self {
        TrustError::Encoding(e.0)
    }
}
impl From<io::Error> for TrustError {
    fn from(e: io::Error) -> Self {
        TrustError::Io(e)
    }
}

// ============================================================================
// ClusterDirectory（根签目录：端点列表与条目同签，§1.3.3f 方案②）
// ============================================================================

/// 根签集群目录：全套服务器接入材料 + 单调递增 dir_version。
///
/// 签名覆盖 `cluster_id ‖ dir_version ‖ 服务器数 ‖ 全部 ServerEntry 字段`——
/// 「列表真、条目假」的拼接在验签处失败。
#[derive(Debug, Clone)]
pub struct ClusterDirectory {
    /// 所属集群。
    pub cluster_id: ClusterId,
    /// 递增版本（单台换钥 ⇒ 根签新目录 ⇒ 客户端 dir_pull 刷新；回退拒收）。
    pub dir_version: u64,
    /// 全套服务器接入材料。
    pub servers: Vec<ServerEntry>,
    /// 集群根密钥对 canonical_bytes 的签名。
    pub root_sig: Signature,
}

/// ServerEntry 字段编码（不含域分离标签；目录/邀请内嵌用）。
fn entry_fields(e: &ServerEntry, out: &mut Vec<u8>) {
    out.extend_from_slice(&e.server_id.0);
    out.extend_from_slice(&(e.relay_endpoint.len() as u16).to_le_bytes());
    out.extend_from_slice(e.relay_endpoint.as_bytes());
    out.extend_from_slice(e.identity_pub.as_bytes());
    out.extend_from_slice(&e.static_hybrid_pub.to_bytes());
}

impl ClusterDirectory {
    /// 签名覆盖的规范化字节（不含 root_sig 本身）。
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SIG_DIRECTORY.len() + 24 + self.servers.len() * 1300);
        v.extend_from_slice(SIG_DIRECTORY);
        v.extend_from_slice(&self.cluster_id.0);
        v.extend_from_slice(&self.dir_version.to_le_bytes());
        v.extend_from_slice(&(self.servers.len() as u16).to_le_bytes());
        for e in &self.servers {
            entry_fields(e, &mut v);
        }
        v
    }

    /// 根密钥签发（运维/测试装配路径；根密钥离线保管，§4）。
    pub fn issue(
        root: &SigningKey,
        cluster_id: ClusterId,
        dir_version: u64,
        servers: Vec<ServerEntry>,
    ) -> Self {
        let mut dir = ClusterDirectory {
            cluster_id,
            dir_version,
            servers,
            root_sig: Signature::from_bytes(&[0; 64]),
        };
        dir.root_sig = root.sign(&dir.canonical_bytes());
        dir
    }

    /// 根公钥验签（条目被篡改 ⇒ 失败；换根 ⇒ 失败）。
    pub fn verify(&self, root_pub: &VerifyingKey) -> bool {
        root_pub
            .verify(&self.canonical_bytes(), &self.root_sig)
            .is_ok()
    }

    /// 按 server_id 查端点材料。
    pub fn find(&self, server_id: &ServerId) -> Option<&ServerEntry> {
        self.servers.iter().find(|e| &e.server_id == server_id)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(DIRECTORY_VERSION);
        out.extend_from_slice(&self.cluster_id.0);
        out.extend_from_slice(&self.dir_version.to_le_bytes());
        out.extend_from_slice(&(self.servers.len() as u16).to_le_bytes());
        for e in &self.servers {
            entry_fields(e, out);
        }
        out.extend_from_slice(&self.root_sig.to_bytes());
    }

    /// 序列化（dir_pull 下发线格式，§3.8/§3.11；`[ver][cluster][dir_version][n]{entries}
    /// [root_sig]`）。与 `InviteFile::to_bytes` 内嵌目录段同构。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(17 + self.servers.len() * 1300);
        self.encode(&mut v);
        v
    }

    /// 反序列化（结构级；根验签走 [`ClusterDirectory::verify`]）。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TrustError> {
        let mut rd = Rd::new(bytes);
        let dir = Self::decode(&mut rd)?;
        if !rd.done() {
            return Err(TrustError::Encoding("trailing bytes"));
        }
        Ok(dir)
    }

    fn decode(rd: &mut Rd<'_>) -> Result<Self, TrustError> {
        let ver = rd.u8()?;
        if ver != DIRECTORY_VERSION {
            return Err(TrustError::Encoding("directory version"));
        }
        let cluster_id = ClusterId(rd.arr16()?);
        let dir_version = rd.u64()?;
        let n = rd.u16()? as usize;
        if n > 4096 {
            return Err(TrustError::Encoding("directory too large"));
        }
        let mut servers = Vec::with_capacity(n);
        for _ in 0..n {
            let server_id = ServerId(rd.arr16()?);
            let ep_len = rd.u16()? as usize;
            if ep_len > 512 {
                return Err(TrustError::Encoding("endpoint too long"));
            }
            let endpoint = String::from_utf8(rd.take(ep_len)?.to_vec())
                .map_err(|_| TrustError::Encoding("endpoint encoding"))?;
            let identity_pub = VerifyingKey::from_bytes(&rd.arr32()?)
                .map_err(|_| TrustError::Encoding("identity pubkey"))?;
            let mut hybrid = [0u8; crate::kem::HYBRID_PUB_LEN];
            hybrid.copy_from_slice(rd.take(crate::kem::HYBRID_PUB_LEN)?);
            let static_hybrid_pub = crate::kem::HybridPubkey::from_bytes(&hybrid)
                .map_err(|_| TrustError::Encoding("static hybrid pubkey"))?;
            servers.push(ServerEntry {
                server_id,
                relay_endpoint: endpoint,
                identity_pub,
                static_hybrid_pub,
            });
        }
        let sig_arr = rd.arr64()?;
        let root_sig = Signature::from_bytes(&sig_arr);
        Ok(ClusterDirectory {
            cluster_id,
            dir_version,
            servers,
            root_sig,
        })
    }
}

// ============================================================================
// InviteFile v3
// ============================================================================

/// 邀请文件 v3（§1.3.3f）：根签 ClusterDirectory 全套服务器材料 + 一次性 invite_id +
/// expiry。持邀请客户端对任意端点（含切换/迁移）直接 1-RTT，完全避开 TOFU。
#[derive(Debug, Clone)]
pub struct InviteFile {
    /// 根签集群目录。
    pub directory: ClusterDirectory,
    /// 集群根公钥（信任锚本体；与签发根成对）。
    pub cluster_root_pub: VerifyingKey,
    /// 过期时刻（unix 秒；默认签发 +7 天）。
    pub expiry_unix: u64,
    /// 一次性消费凭据标识（进 Raft 状态机查重；库内仅结构校验）。
    pub invite_id: [u8; 16],
    /// 根密钥签名，覆盖 directory 规范字节 ‖ root_pub ‖ expiry ‖ invite_id。
    pub root_sig: Signature,
}

/// 当前 unix 秒。
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl InviteFile {
    /// 根密钥签发（expiry 建议 now + [`INVITE_DEFAULT_TTL_SECS`]）。
    pub fn issue(
        root: &SigningKey,
        cluster_id: ClusterId,
        dir_version: u64,
        servers: Vec<ServerEntry>,
        expiry_unix: u64,
        invite_id: [u8; 16],
    ) -> Self {
        let directory = ClusterDirectory::issue(root, cluster_id, dir_version, servers);
        let mut inv = InviteFile {
            directory,
            cluster_root_pub: root.verifying_key(),
            expiry_unix,
            invite_id,
            root_sig: Signature::from_bytes(&[0; 64]),
        };
        inv.root_sig = root.sign(&inv.canonical_bytes());
        inv
    }

    /// 签名覆盖的规范化字节（不含 root_sig 本身）。
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = self.directory.canonical_bytes();
        v.extend_from_slice(SIG_INVITE);
        v.extend_from_slice(self.cluster_root_pub.as_bytes());
        v.extend_from_slice(&self.expiry_unix.to_le_bytes());
        v.extend_from_slice(&self.invite_id);
        v
    }

    /// 结构自洽验签（root_sig 对 canonical_bytes；任何字段篡改 ⇒ 失败）。
    /// 防冒（根替换）需调用方比对钉扎/展示根指纹——见 [`InviteFile::verify_against`]。
    pub fn verify(&self) -> bool {
        self.cluster_root_pub
            .verify(&self.canonical_bytes(), &self.root_sig)
            .is_ok()
            && self.directory.verify(&self.cluster_root_pub)
    }

    /// 对照外部已知根公钥验签（已钉扎/管理员分发的根）。
    pub fn verify_against(&self, known_root: &VerifyingKey) -> bool {
        self.cluster_root_pub == *known_root && self.verify()
    }

    /// 版本/过期检查（now 由调用方注入，可测）。
    pub fn check(&self, now_unix: u64) -> Result<(), TrustError> {
        if self.expiry_unix <= now_unix {
            return Err(TrustError::Expired {
                now_unix,
                expiry_unix: self.expiry_unix,
            });
        }
        Ok(())
    }

    /// 序列化（邀请文件按一次性凭据管理：0600 落盘由 [`save_invite`] 承担）。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64 + self.directory.servers.len() * 1300);
        v.push(INVITE_VERSION);
        self.directory.encode(&mut v);
        v.extend_from_slice(self.cluster_root_pub.as_bytes());
        v.extend_from_slice(&self.expiry_unix.to_le_bytes());
        v.extend_from_slice(&self.invite_id);
        v.extend_from_slice(&self.root_sig.to_bytes());
        v
    }

    /// 反序列化（含 v3 版本检查与结构自洽验签：根签名不匹配/条目被篡改 ⇒ 拒）。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TrustError> {
        let mut rd = Rd::new(bytes);
        let ver = rd.u8()?;
        if ver != INVITE_VERSION {
            return Err(TrustError::UnsupportedInviteVersion(ver));
        }
        let directory = ClusterDirectory::decode(&mut rd)?;
        let cluster_root_pub = VerifyingKey::from_bytes(&rd.arr32()?)
            .map_err(|_| TrustError::Encoding("root pubkey"))?;
        let expiry_unix = rd.u64()?;
        let invite_id = rd.arr16()?;
        let sig_arr = rd.arr64()?;
        let root_sig = Signature::from_bytes(&sig_arr);
        if !rd.done() {
            return Err(TrustError::Encoding("trailing bytes"));
        }
        let inv = InviteFile {
            directory,
            cluster_root_pub,
            expiry_unix,
            invite_id,
            root_sig,
        };
        if !inv.verify() {
            return Err(TrustError::BadSignature);
        }
        Ok(inv)
    }
}

/// 凭据类文件 0600 落盘（compat::write_private 同款姿势）：unix 下以
/// `OpenOptions::mode(0o600)` **创建**——文件诞生即 0600，不存在「先写后收紧」
/// 的权限窗口（`fs::write` + `set_permissions` 之间存在偏宽窗口）。覆盖已存在
/// 文件偏宽旧权限时事后收紧。Windows 原生无 POSIX 权限位，退化为常规写。
fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.flush()?;
        // 覆盖已存在文件可能偏宽的旧权限（创建路径本身无窗口）。
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// 保存邀请文件（unix 下 0600——按一次性凭据管理，§1.3.3f 邀请一生）。
pub fn save_invite(path: &Path, invite: &InviteFile) -> Result<(), TrustError> {
    write_private_file(path, &invite.to_bytes())?;
    Ok(())
}

/// 加载邀请文件（§1.3.3f `load_invite(path)`：读盘 + v3 版本检查 + 结构验签；
/// 过期/外部根比对由调用方带上下文执行 [`InviteFile::check`]/[`InviteFile::verify_against`]）。
pub fn load_invite(path: &Path) -> Result<InviteFile, TrustError> {
    let bytes = std::fs::read(path)?;
    InviteFile::from_bytes(&bytes)
}

// ============================================================================
// PinStore（cluster_id → 集群根公钥）
// ============================================================================

/// 钉扎判定。Mismatch 载两把公钥（16+32+32B；判定枚举按值返回，尺寸可接受——
/// 盒装反使最常用的 Match 路径付出堆分配）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum PinVerdict {
    /// 呈现根与钉扎一致。
    Match,
    /// 集群根公钥**变更**——显式告警路径：携带钉扎值与呈现值，根公钥变更 = 显式告警 +
    /// 人工确认（§2.4 表）；确认后用 [`PinStore::pin`] 覆写。
    Mismatch {
        pinned: VerifyingKey,
        presented: VerifyingKey,
    },
    /// 该集群尚无钉扎（TOFU 首连路径：展示 [`Fingerprint`] 后 [`PinStore::pin`]）。
    NotPinned,
}

/// 钉扎存储（known_hosts 语义，集群根级；文件适配器首发）。
#[derive(Debug, Clone, Default)]
pub struct PinStore {
    pins: BTreeMap<[u8; 16], VerifyingKey>,
    /// 每集群已见最高 dir_version（dir_pull 回退检测）。
    dir_versions: BTreeMap<[u8; 16], u64>,
}

impl PinStore {
    /// 空存储。
    pub fn new() -> Self {
        Self::default()
    }

    /// 首钉（TOFU 确认后）或覆写（根变更经人工确认后）。返回写入前的判定
    /// （NotPinned = 首钉；Mismatch = 变更覆写——调用方必须已走告警流程）。
    pub fn pin(&mut self, cluster_id: &ClusterId, root_pub: &VerifyingKey) -> PinVerdict {
        let prev = self.verify_pinned(cluster_id, root_pub);
        self.pins.insert(cluster_id.0, *root_pub);
        prev
    }

    /// 比对钉扎（不写入）。**变更不可静默**：Mismatch 必须触发显式告警 UI（§3.8）。
    pub fn verify_pinned(&self, cluster_id: &ClusterId, root_pub: &VerifyingKey) -> PinVerdict {
        match self.pins.get(&cluster_id.0) {
            Some(pinned) if pinned == root_pub => PinVerdict::Match,
            Some(pinned) => PinVerdict::Mismatch {
                pinned: *pinned,
                presented: *root_pub,
            },
            None => PinVerdict::NotPinned,
        }
    }

    /// 取某集群的钉扎根公钥。
    pub fn pinned_root(&self, cluster_id: &ClusterId) -> Option<&VerifyingKey> {
        self.pins.get(&cluster_id.0)
    }

    /// 已见最高 dir_version。
    pub fn seen_dir_version(&self, cluster_id: &ClusterId) -> Option<u64> {
        self.dir_versions.get(&cluster_id.0).copied()
    }

    /// dir_pull 刷新落地（§3.8）：根验签 → 钉扎比对（变更 ⇒ [`TrustError::RootChanged`]
    /// 显式告警路径）→ dir_version 回退拒收 → 记录版本。
    /// 同版本重复分发（同内容幂等重放）放行。
    pub fn record_directory(
        &mut self,
        root_pub: &VerifyingKey,
        dir: &ClusterDirectory,
    ) -> Result<(), TrustError> {
        if !dir.verify(root_pub) {
            return Err(TrustError::BadSignature);
        }
        match self.verify_pinned(&dir.cluster_id, root_pub) {
            PinVerdict::Match => {}
            PinVerdict::Mismatch { pinned, presented } => {
                return Err(TrustError::RootChanged {
                    cluster_id: dir.cluster_id,
                    pinned: Box::new(pinned),
                    presented: Box::new(presented),
                })
            }
            PinVerdict::NotPinned => { /* 首次见目录：由邀请/TOFU 路径先 pin */ }
        }
        if let Some(&stored) = self.dir_versions.get(&dir.cluster_id.0) {
            if dir.dir_version < stored {
                return Err(TrustError::DirVersionRollback {
                    stored,
                    got: dir.dir_version,
                });
            }
        }
        self.dir_versions.insert(dir.cluster_id.0, dir.dir_version);
        Ok(())
    }

    /// 序列化（格式：`[ver=1][count u16]{ [16 cluster][32 root][8 dir_version] }`）。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![1u8];
        v.extend_from_slice(&(self.pins.len() as u16).to_le_bytes());
        for (id, root) in &self.pins {
            v.extend_from_slice(id);
            v.extend_from_slice(root.as_bytes());
            v.extend_from_slice(
                &self
                    .dir_versions
                    .get(id)
                    .copied()
                    .unwrap_or(0)
                    .to_le_bytes(),
            );
        }
        v
    }

    /// 反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TrustError> {
        let mut rd = Rd::new(bytes);
        let ver = rd.u8()?;
        if ver != 1 {
            return Err(TrustError::Encoding("pinstore version"));
        }
        let n = rd.u16()? as usize;
        let mut pins = BTreeMap::new();
        let mut dir_versions = BTreeMap::new();
        for _ in 0..n {
            let id = rd.arr16()?;
            let root = VerifyingKey::from_bytes(&rd.arr32()?)
                .map_err(|_| TrustError::Encoding("pin root pubkey"))?;
            let dv = rd.u64()?;
            pins.insert(id, root);
            if dv > 0 {
                dir_versions.insert(id, dv);
            }
        }
        if !rd.done() {
            return Err(TrustError::Encoding("trailing bytes"));
        }
        Ok(PinStore { pins, dir_versions })
    }

    /// 落盘（unix 0600——钉扎文件按凭据对待；创建即 0600，无「先写后收紧」窗口，
    /// 见 [`write_private_file`]）。
    pub fn save(&self, path: &Path) -> Result<(), TrustStoreError> {
        write_private_file(path, &self.to_bytes())?;
        Ok(())
    }

    /// 读盘。
    pub fn load(path: &Path) -> Result<Self, TrustStoreError> {
        let bytes = std::fs::read(path)?;
        Ok(PinStore::from_bytes(&bytes)?)
    }
}

/// PinStore 落盘错误（IO 或编码）。
#[derive(Debug)]
pub struct TrustStoreError(TrustError);

impl std::fmt::Display for TrustStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "trust: pin store: {}", self.0)
    }
}
impl std::error::Error for TrustStoreError {}
impl From<io::Error> for TrustStoreError {
    fn from(e: io::Error) -> Self {
        TrustStoreError(TrustError::Io(e))
    }
}
impl From<TrustError> for TrustStoreError {
    fn from(e: TrustError) -> Self {
        TrustStoreError(e)
    }
}

// ============================================================================
// TOFU → 钉扎 的会话落地
// ============================================================================

/// TOFU 引导确认 + 钉扎落地（§1.3.3c/§1.3.3f 闭环）：
/// 1. `verify_pinned`：NotPinned ⇒ `pin`（首钉，调用方已展示根指纹并确认）；
///    Mismatch ⇒ [`TrustError::RootChanged`]（**告警路径，不静默**）。
/// 2. 通过后执行 [`crate::session::TofuBootstrap::confirm`] 完成 I1/R1。
pub async fn confirm_tofu_and_pin<S>(
    boot: crate::session::TofuBootstrap<S>,
    pins: &mut PinStore,
) -> Result<crate::session::Tunnel, TrustTofuError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let cluster_id = boot.cluster_id();
    let root = *boot.root_pub();
    match pins.verify_pinned(&cluster_id, &root) {
        PinVerdict::Match => {}
        PinVerdict::NotPinned => {
            pins.pin(&cluster_id, &root);
        }
        PinVerdict::Mismatch { pinned, presented } => {
            return Err(TrustTofuError(TrustError::RootChanged {
                cluster_id,
                pinned: Box::new(pinned),
                presented: Box::new(presented),
            }))
        }
    }
    let tunnel = boot
        .confirm()
        .await
        .map_err(|e| TrustTofuError(TrustError::Io(io::Error::other(format!("{e}")))))?;
    Ok(tunnel)
}

/// TOFU 确认错误（信任层或握手层）。
#[derive(Debug)]
pub struct TrustTofuError(TrustError);

impl std::fmt::Display for TrustTofuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "trust: tofu confirm: {}", self.0)
    }
}
impl std::error::Error for TrustTofuError {}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u8) -> ServerEntry {
        let identity = SigningKey::from_bytes(&[n; 32]);
        let hybrid = crate::kem::HybridKeypair::generate(&mut crate::rand::rngs::OsRng);
        ServerEntry {
            server_id: ServerId([n; 16]),
            relay_endpoint: format!("relay-{n}.example:2300{n}"),
            identity_pub: identity.verifying_key(),
            static_hybrid_pub: hybrid.public(),
        }
    }

    fn fixture() -> (SigningKey, ClusterId) {
        (
            SigningKey::from_bytes(&crate::rand::random::<[u8; 32]>()),
            ClusterId([7; 16]),
        )
    }

    #[test]
    fn directory_tamper_detected() {
        let (root, cid) = fixture();
        let mut dir = ClusterDirectory::issue(&root, cid, 3, vec![entry(1), entry(2)]);
        assert!(dir.verify(&root.verifying_key()), "合法目录通过");
        // to_bytes/from_bytes 往返（dir_pull 线格式，§3.11）
        let back = ClusterDirectory::from_bytes(&dir.to_bytes()).expect("dir roundtrip");
        assert_eq!(back.dir_version, dir.dir_version);
        assert!(back.verify(&root.verifying_key()));
        let mut trailing = dir.to_bytes();
        trailing.push(0);
        assert!(
            ClusterDirectory::from_bytes(&trailing).is_err(),
            "尾随字节 ⇒ 拒"
        );
        // 条目被篡改（换 relay_endpoint）⇒ 验签失败
        dir.servers[0].relay_endpoint = "evil.example:9".into();
        assert!(!dir.verify(&root.verifying_key()), "条目被篡改 ⇒ 拒");
        // 换根 ⇒ 验签失败
        let dir2 = ClusterDirectory::issue(&root, cid, 4, vec![entry(1)]);
        let other = SigningKey::from_bytes(&[9; 32]);
        assert!(!dir2.verify(&other.verifying_key()), "另一根 ⇒ 拒");
        // dir_version 被改 ⇒ 验签失败（版本在签名覆盖内）
        let mut dir3 = ClusterDirectory::issue(&root, cid, 3, vec![entry(1)]);
        dir3.dir_version = 99;
        assert!(!dir3.verify(&root.verifying_key()), "版本篡改 ⇒ 拒");
    }

    #[test]
    fn invite_roundtrip_and_version_gate() {
        let (root, cid) = fixture();
        let inv = InviteFile::issue(
            &root,
            cid,
            1,
            vec![entry(1), entry(2)],
            now_unix() + 3600,
            [5; 16],
        );
        let bytes = inv.to_bytes();
        let back = InviteFile::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(back.invite_id, [5; 16]);
        assert!(back.verify());
        assert!(back.verify_against(&root.verifying_key()));
        // 根签名不匹配：篡改任意覆盖字段（invite_id）
        let mut tampered = bytes.clone();
        let id_off = bytes.len() - 64 - 16; // invite_id 在 root_sig 前 16B
        tampered[id_off] ^= 0x01;
        assert!(
            matches!(
                InviteFile::from_bytes(&tampered).unwrap_err(),
                TrustError::BadSignature
            ),
            "根签名不匹配 ⇒ 拒载入"
        );
        // v2 拒收
        let mut v2 = bytes;
        v2[0] = 2;
        assert!(matches!(
            InviteFile::from_bytes(&v2).unwrap_err(),
            TrustError::UnsupportedInviteVersion(2)
        ));
        // 过期
        let expired = InviteFile::issue(&root, cid, 1, vec![], 100, [5; 16]);
        assert!(matches!(
            expired.check(200).unwrap_err(),
            TrustError::Expired {
                now_unix: 200,
                expiry_unix: 100
            }
        ));
    }

    #[test]
    fn pinstore_verdicts_and_persistence() {
        let (root, cid) = fixture();
        let other = SigningKey::from_bytes(&[3; 32]);
        let mut pins = PinStore::new();
        assert_eq!(
            pins.verify_pinned(&cid, &root.verifying_key()),
            PinVerdict::NotPinned
        );
        // 首钉
        let prev = pins.pin(&cid, &root.verifying_key());
        assert_eq!(prev, PinVerdict::NotPinned);
        assert_eq!(
            pins.verify_pinned(&cid, &root.verifying_key()),
            PinVerdict::Match
        );
        // 变更告警路径（可测）：Mismatch 携带新旧两把公钥
        match pins.verify_pinned(&cid, &other.verifying_key()) {
            PinVerdict::Mismatch { pinned, presented } => {
                assert_eq!(pinned, root.verifying_key());
                assert_eq!(presented, other.verifying_key());
            }
            v => panic!("期望 Mismatch，got {v:?}"),
        }
        // 序列化往返
        let bytes = pins.to_bytes();
        let back = PinStore::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(
            back.verify_pinned(&cid, &root.verifying_key()),
            PinVerdict::Match
        );
    }

    // 落盘形态：save_invite / PinStore::save 往返 + unix 下 0600（创建即 0600，
    // 无「fs::write 后补收紧」的权限窗口——本测试同时守「写后可读回」不回归）。
    #[test]
    fn invite_and_pinstore_save_roundtrip_and_mode() {
        let (root, cid) = fixture();
        let inv = InviteFile::issue(&root, cid, 1, vec![entry(1)], now_unix() + 3600, [6; 16]);
        let dir = std::env::temp_dir().join(format!("flock-trust-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let ipath = dir.join("invite.bin");
        save_invite(&ipath, &inv).unwrap();
        assert_eq!(
            load_invite(&ipath).unwrap().invite_id,
            [6; 16],
            "邀请落盘可读回"
        );

        let mut pins = PinStore::new();
        pins.pin(&cid, &root.verifying_key());
        let ppath = dir.join("pins.bin");
        pins.save(&ppath).unwrap();
        assert_eq!(
            PinStore::load(&ppath)
                .unwrap()
                .verify_pinned(&cid, &root.verifying_key()),
            PinVerdict::Match,
            "钉扎落盘可读回"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&ipath).unwrap().permissions().mode() & 0o777,
                0o600,
                "invite 0600"
            );
            assert_eq!(
                std::fs::metadata(&ppath).unwrap().permissions().mode() & 0o777,
                0o600,
                "pins 0600"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_directory_rollback_rejected() {
        let (root, cid) = fixture();
        let mut pins = PinStore::new();
        pins.pin(&cid, &root.verifying_key());
        let v3 = ClusterDirectory::issue(&root, cid, 3, vec![entry(1)]);
        pins.record_directory(&root.verifying_key(), &v3)
            .expect("v3 收");
        assert_eq!(pins.seen_dir_version(&cid), Some(3));
        // 回退到 v2 ⇒ 拒
        let v2 = ClusterDirectory::issue(&root, cid, 2, vec![entry(1)]);
        assert!(
            matches!(
                pins.record_directory(&root.verifying_key(), &v2)
                    .unwrap_err(),
                TrustError::DirVersionRollback { stored: 3, got: 2 }
            ),
            "dir_version 回退 ⇒ 拒载入"
        );
        // v4 ⇒ 收
        let v4 = ClusterDirectory::issue(&root, cid, 4, vec![entry(1), entry(2)]);
        pins.record_directory(&root.verifying_key(), &v4)
            .expect("v4 收");
        assert_eq!(pins.seen_dir_version(&cid), Some(4));
        // 换根签发 ⇒ 告警路径错误
        let bad_root = SigningKey::from_bytes(&[9; 32]);
        let forged = ClusterDirectory::issue(&bad_root, cid, 5, vec![entry(1)]);
        assert!(
            matches!(
                pins.record_directory(&bad_root.verifying_key(), &forged)
                    .unwrap_err(),
                TrustError::RootChanged { .. }
            ),
            "根变更 ⇒ 显式告警路径"
        );
    }
}
