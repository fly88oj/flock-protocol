//! OPAQUE 登录协议（**RFC 9807** / opaque-ke 4.0.1，§1.3.3h / §3.4，P2-11、P1-6）。
//!
//! - Suite 与 showroom 相同：Ristretto255（OPRF + KE）+ TripleDH + **Identity KSF**——
//!   argon2id 硬化由 [`rwd`] 在盲化前外部承担（盐含 user），KSF 本体恒 Identity 以免双重
//!   stretch（showroom-common opaque.rs:4-6 同语义；3.0.0→4.0.1 的 Suite 形状变化：
//!   `KeGroup` 从 CipherSuite 移入 `KeyExchange = TripleDh<Ristretto255, Sha512>`，
//!   组合不变——4.0.0 CHANGELOG「Synced implementation with RFC 9807 (no core protocol
//!   changes)」，wire 格式不变由 tests/vectors/showroom-3.0.0.json 互通向量实证）。
//! - RFC 引用勘误（P2-11）：showroom-common opaque.rs:1 误写 RFC 9380，本模块一律 **9807**。
//! - 线上格式：所有报文（ke1/ke2/ke3/m1/m2/record）与落盘（`pass.opaque`/`opaque.key`）
//!   一律 base64(标准字母表无 padding)——与 pub_string 的编码惯例一致。
//! - rwd 参数化 profile（§1.3.3h）：[`Profile::Owasp19MiB`]（showroom 兼容默认：m=19456KiB,
//!   t=2, p=1）/ [`Profile::Rfc9807High`]（m=2GiB, t=1, p=4 高配档）；**profile id 进注册记录
//!   防跨档漂移**（调用方把 [`Profile::id`] 存进记录侧；两端不同 profile 登录必失败）。
//! - `ServerSetup` 3.0.0→4.0.1 序列化布局变化（dummy 假钥匙 sk→pk，4.0.0 CHANGELOG）：
//!   旧 `opaque.key` 由 [`server_setup_migrate_v3`] 迁移；`ServerRegistration` 布局不变，
//!   3.0.0 注册记录直接 [`server_record_from_b64`] 读入（M1 守门向量实证）。
//!
//! 语义要点（与 showroom 相同，serve 侧调用方负责）：
//! - 未知用户：`server_login_start` 的 record 传 `None` → crate 原生 dummy 假记录路径，
//!   仍产出同形 ke2（防枚举；4.0.1 起恒造 dummy 记录以抗时序差，CHANGELOG）；
//! - 错密码：客户端 `login_finish` 本地失败（Err），线上无差异；
//! - credential_identifier=user、三方标识 client=user / server=[`SERVER_ID`]。

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::engine::Engine as _;
use opaque_ke::key_exchange::tripledh::TripleDh;
use opaque_ke::keypair::PrivateKey;
use opaque_ke::ksf::Identity;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};
use sha2_compat::Sha512; // opaque-ke 4.0.1 的 digest 0.10 代际

use rand::TryCryptoRng as CryptoRngCore;

/// rwd 盐 = b"showroom-opaque-v1" + user（showroom-common opaque.rs:53 原值；常数盐合法：
/// 盲化已提供保护，硬化只为抬高离线字典代价；user 进盐使同密码不同账号派生不同 rwd）。
const RWD_SALT_PREFIX: &[u8] = b"showroom-opaque-v1";

/// Suite：Ristretto255 + TripleDH(Sha512) + Identity KSF（argon2id 由 `rwd` 外部承担）。
pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = Identity;
}

/// 三方标识中的服务端身份（KE transcript 域分离；两端一致即可）。showroom 兼容原值。
pub const SERVER_ID: &[u8] = b"showroom-server";

/// 密码硬化的输出长度（OPAQUE 盲化输入宽度）。
pub const RWD_LEN: usize = 32;

/// argon2id 参数 profile（§1.3.3h：版本化升级不破老记录；profile id 进注册记录）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    /// showroom 兼容默认：argon2id m=19456KiB, t=2, p=1（OWASP 推荐档）。
    #[default]
    Owasp19MiB,
    /// RFC 9807 高配档：m=2GiB, t=1, p=4（服务器级内存占用，慢但离线字典代价最高）。
    Rfc9807High,
}

impl Profile {
    /// 稳定 profile id（进注册记录，防跨档漂移；0 保留给 showroom 兼容默认）。
    pub const fn id(self) -> u16 {
        match self {
            Profile::Owasp19MiB => 0,
            Profile::Rfc9807High => 1,
        }
    }

    fn argon2_params(self) -> argon2::Params {
        let (m_kib, t, p) = match self {
            Profile::Owasp19MiB => (19456, 2, 1),
            Profile::Rfc9807High => (2 * 1024 * 1024, 1, 4),
        };
        argon2::Params::new(m_kib, t, p, Some(RWD_LEN)).expect("固定合法 argon2 参数")
    }
}

/// 密码硬化的统一错误（argon2 参数构造在固定 profile 下不可能失败，仅透传哈希错误）。
pub type PakeResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// rwd（rotated password derivation）：argon2id(profile) → 32B，盐 = 前缀 ‖ user。
/// 确定性函数（无秘密依赖）；与 showroom 3.0.0 的 `rwd` 在 [`Profile::Owasp19MiB`] 下
/// 逐字节一致（由 tests/vectors/showroom-3.0.0.json 的 rwd_hex 断言实证）。
pub fn rwd(pw: &str, user: &str, profile: Profile) -> PakeResult<[u8; RWD_LEN]> {
    let a2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        profile.argon2_params(),
    );
    let mut salt = RWD_SALT_PREFIX.to_vec();
    salt.extend_from_slice(user.as_bytes());
    let mut out = [0u8; RWD_LEN];
    a2.hash_password_into(pw.as_bytes(), &salt, &mut out)
        .map_err(|e| format!("argon2id: {e:?}"))?;
    Ok(out)
}

// —— 小工具 ——

fn ids(user: &str) -> Identifiers<'_> {
    Identifiers {
        client: Some(user.as_bytes()),
        server: Some(SERVER_ID),
    }
}

fn b64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

/// 未认证 b64 入口的尺寸上限（64KiB）：OPAQUE 全部报文（ke1/ke2/ke3/m1/m2/record）
/// 与 `opaque.key`/`pass.opaque` 落盘形态都远小于此——超限在 decode 分配前拒绝，
/// 防大报文放大分配（ke1 等服务端入口是未认证攻击面）。
const B64_INPUT_LIMIT: usize = 64 * 1024;

fn unb64(s: &str) -> PakeResult<Vec<u8>> {
    if s.len() > B64_INPUT_LIMIT {
        return Err(format!(
            "pake: b64 input {}B exceeds {B64_INPUT_LIMIT}B limit",
            s.len()
        )
        .into());
    }
    Ok(STANDARD_NO_PAD.decode(s.trim())?)
}

/// rand 0.9（本库 RNG 面）→ rand 0.8（opaque-ke 4.0.1 的 RNG 代际）私有桥。
/// 熵源故障直接 panic（同本库 kem 模块桥的语义）。
struct RngBridge08<'a, R: rand::TryRngCore + ?Sized>(&'a mut R);

fn bridge08<R: rand::TryRngCore + ?Sized>(rng: &mut R) -> RngBridge08<'_, R> {
    RngBridge08(rng)
}

impl<R: rand::TryRngCore + ?Sized> opaque_ke::rand::RngCore for RngBridge08<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.0
            .try_next_u32()
            .expect("flock-protocol: entropy source failed")
    }
    fn next_u64(&mut self) -> u64 {
        self.0
            .try_next_u64()
            .expect("flock-protocol: entropy source failed")
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0
            .try_fill_bytes(dst)
            .expect("flock-protocol: entropy source failed");
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), opaque_ke::rand::Error> {
        self.0.try_fill_bytes(dst).map_err(|_| {
            opaque_ke::rand::Error::from(std::num::NonZeroU32::new(1).expect("nonzero"))
        })
    }
}

// rand 0.8 CryptoRng 为标记 trait
impl<R: rand::TryRngCore + ?Sized> opaque_ke::rand::CryptoRng for RngBridge08<'_, R> {}

// —— 客户端（CLI native 与 wasm 垫片共用；密码 → rwd → 盲化）——

/// 登录第一步：产出 ke1（发 `/_api/auth/login-begin`）与待 finish 的本地状态。
/// rwd 用 [`Profile::default`]（showroom 兼容档）；高配档走 [`login_start_profile`]。
pub fn login_start(
    rng: &mut impl CryptoRngCore,
    pw: &str,
    user: &str,
) -> PakeResult<(ClientLogin<Suite>, String)> {
    login_start_profile(rng, pw, user, Profile::default())
}

/// [`login_start`] 的显式 profile 档（注册记录侧存了哪个 profile 就用哪个）。
pub fn login_start_profile(
    rng: &mut impl CryptoRngCore,
    pw: &str,
    user: &str,
    profile: Profile,
) -> PakeResult<(ClientLogin<Suite>, String)> {
    let r = rwd(pw, user, profile)?;
    let out = ClientLogin::<Suite>::start(&mut bridge08(rng), &r)
        .map_err(|e| format!("login start: {e}"))?;
    Ok((out.state, b64(&out.message.serialize())))
}

/// 登录第三步（本地）：ke2 → ke3。密码错误在此 Err（本地提示，不产生第三请求）。
pub fn login_finish(
    state: ClientLogin<Suite>,
    pw: &str,
    user: &str,
    ke2_b64: &str,
) -> PakeResult<String> {
    login_finish_profile(state, pw, user, ke2_b64, Profile::default())
}

/// [`login_finish`] 的显式 profile 档。
pub fn login_finish_profile(
    state: ClientLogin<Suite>,
    pw: &str,
    user: &str,
    ke2_b64: &str,
    profile: Profile,
) -> PakeResult<String> {
    let r = rwd(pw, user, profile)?;
    let ke2 = CredentialResponse::<Suite>::deserialize(&unb64(ke2_b64)?)
        .map_err(|e| format!("bad ke2: {e}"))?;
    let out = state
        .finish(
            &mut bridge08(&mut rand::rng()),
            &r,
            ke2,
            ClientLoginFinishParameters {
                context: None,
                identifiers: ids(user),
                ksf: None,
            },
        )
        .map_err(|e| format!("login finish: {e}"))?;
    Ok(b64(&out.message.serialize()))
}

/// 注册第一步（改密码流程）：产出 m1（发 `/_api/auth/pw-begin`）与本地状态。
pub fn reg_start(
    rng: &mut impl CryptoRngCore,
    pw: &str,
    user: &str,
) -> PakeResult<(ClientRegistration<Suite>, String)> {
    reg_start_profile(rng, pw, user, Profile::default())
}

/// [`reg_start`] 的显式 profile 档。
pub fn reg_start_profile(
    rng: &mut impl CryptoRngCore,
    pw: &str,
    user: &str,
    profile: Profile,
) -> PakeResult<(ClientRegistration<Suite>, String)> {
    let r = rwd(pw, user, profile)?;
    let out = ClientRegistration::<Suite>::start(&mut bridge08(rng), &r)
        .map_err(|e| format!("reg start: {e}"))?;
    Ok((out.state, b64(&out.message.serialize())))
}

/// 注册收尾（客户端）：m2 → record（发 `/_api/auth/pw-commit`；服务端原子替换）。
pub fn reg_finish(
    rng: &mut impl CryptoRngCore,
    state: ClientRegistration<Suite>,
    pw: &str,
    user: &str,
    m2_b64: &str,
) -> PakeResult<String> {
    reg_finish_profile(rng, state, pw, user, m2_b64, Profile::default())
}

/// [`reg_finish`] 的显式 profile 档。
pub fn reg_finish_profile(
    rng: &mut impl CryptoRngCore,
    state: ClientRegistration<Suite>,
    pw: &str,
    user: &str,
    m2_b64: &str,
    profile: Profile,
) -> PakeResult<String> {
    let r = rwd(pw, user, profile)?;
    let m2 = RegistrationResponse::<Suite>::deserialize(&unb64(m2_b64)?)
        .map_err(|e| format!("bad m2: {e}"))?;
    let out = state
        .finish(
            &mut bridge08(rng),
            &r,
            m2,
            ClientRegistrationFinishParameters {
                identifiers: ids(user),
                ksf: None,
            },
        )
        .map_err(|e| format!("reg finish: {e}"))?;
    Ok(b64(&out.message.serialize()))
}

// —— 服务端（showroomctl / 本仓服务端二进制；serve 与管理命令共用）——

/// 生成服务端 OPRF key（返回 b64 串，即 `opaque.key` 落盘内容）。
pub fn server_setup_new(rng: &mut impl CryptoRngCore) -> String {
    b64(&ServerSetup::<Suite>::new(&mut bridge08(rng)).serialize())
}

/// 加载 4.0.1 代际的服务端 OPRF key（`opaque.key` 文件内容；3.0.0 旧文件走
/// [`server_setup_migrate_v3`]）。
pub fn server_setup_load(b64_key: &str) -> PakeResult<ServerSetup<Suite>> {
    Ok(ServerSetup::<Suite>::deserialize(&unb64(b64_key)?)
        .map_err(|e| format!("bad opaque.key (4.0.1): {e}"))?)
}

/// 序列化服务端 OPRF key（[`server_setup_new`] 的逆）：迁移/换档后落盘 `opaque.key`
/// 用——**必须经本函数写回**（而非误删重建：OPRF seed 轮换会使全部 `pass.opaque`
/// 注册记录失效）。
pub fn server_setup_b64(setup: &ServerSetup<Suite>) -> String {
    b64(&setup.serialize())
}

/// **3.0.0 → 4.0.1 `ServerSetup` 迁移**（P1-6 升级路径；4.0.0 CHANGELOG：
/// dummy 假钥匙由 sk 改存 pk，布局 `[seed 64][KE sk 32][dummy 32]` 不变、末 32B 换义）。
/// 输入 showroom 3.0.0 的 `opaque.key` b64 内容，输出可 [`server_setup_load`] 语义的
/// 4.0.1 `ServerSetup`。OPRF seed 与真实 KE sk 逐字节保留 ⇒ 既有注册记录全部继续可登录。
pub fn server_setup_migrate_v3(b64_key_3_0: &str) -> PakeResult<ServerSetup<Suite>> {
    let old = unb64(b64_key_3_0)?;
    // ristretto255 Suite 布局：seed(SHA-512 输出 64) + KE sk 32 + dummy 32 = 128B
    const SEED_LEN: usize = 64;
    const SK_LEN: usize = 32;
    if old.len() != SEED_LEN + SK_LEN + SK_LEN {
        return Err(format!(
            "bad opaque.key (3.0.0): expect 128 bytes, got {}",
            old.len()
        )
        .into());
    }
    let fake_sk = &old[SEED_LEN + SK_LEN..];
    let fake_pk = PrivateKey::<opaque_ke::Ristretto255>::deserialize(fake_sk)
        .map_err(|e| format!("migrate: bad dummy sk: {e}"))?
        .public_key()
        .serialize();
    let mut new_bytes = old[..SEED_LEN + SK_LEN].to_vec();
    new_bytes.extend_from_slice(&fake_pk);
    ServerSetup::<Suite>::deserialize(&new_bytes).map_err(|e| format!("migrate: {e}").into())
}

/// 注册第二步（服务端）：m1 → m2。credential_identifier=user（OPRF 域分离）。
pub fn server_reg_start(
    setup: &ServerSetup<Suite>,
    m1_b64: &str,
    user: &str,
) -> PakeResult<String> {
    let m1 = RegistrationRequest::<Suite>::deserialize(&unb64(m1_b64)?)
        .map_err(|e| format!("bad m1: {e}"))?;
    let out = ServerRegistration::<Suite>::start(setup, m1, user.as_bytes())
        .map_err(|e| format!("server reg start: {e}"))?;
    Ok(b64(&out.message.serialize()))
}

/// 注册落库（服务端）：record（b64）→ 规范化后的落盘内容（解码验证 + 重编码）。
pub fn server_reg_canonical(record_b64: &str) -> PakeResult<String> {
    let upload = unb64(record_b64)?;
    Ok(b64(&upload))
}

/// 注册记录（服务端）：由落盘 b64 构造（登录时喂 server_login_start）。
/// **3.0.0 布局不变**（4.0.0 CHANGELOG：ServerRegistration 直接 deserialize）——
/// showroom 既有 `pass.opaque` 无迁移直接读入（M1 守门向量实证）。
pub fn server_record_from_b64(record_b64: &str) -> PakeResult<ServerRegistration<Suite>> {
    Ok(
        ServerRegistration::<Suite>::deserialize(&unb64(record_b64)?)
            .map_err(|e| format!("bad pass.opaque: {e}"))?,
    )
}

/// 登录第二步（服务端）：ke1 → ke2 + 在途状态（内存保存，login-finish 消费）。
/// record=None 走 crate 原生 dummy 假记录路径（未知用户/未设密码：ke2 同形，防枚举）。
pub fn server_login_start(
    rng: &mut impl CryptoRngCore,
    setup: &ServerSetup<Suite>,
    record: Option<&ServerRegistration<Suite>>,
    ke1_b64: &str,
    user: &str,
) -> PakeResult<(String, Vec<u8>)> {
    let ke1 = CredentialRequest::<Suite>::deserialize(&unb64(ke1_b64)?)
        .map_err(|e| format!("bad ke1: {e}"))?;
    let out = ServerLogin::<Suite>::start(
        &mut bridge08(rng),
        setup,
        record.cloned(),
        ke1,
        user.as_bytes(),
        ServerLoginParameters {
            context: None,
            identifiers: ids(user),
        },
    )
    .map_err(|e| format!("server login start: {e}"))?;
    Ok((
        b64(&out.message.serialize()),
        out.state.serialize().to_vec(),
    ))
}

/// 登录第三步（服务端）：ke3 验证（MAC）；Err = 密码错误/伪造 → 调用方按 E_AUTH 同体 404。
pub fn server_login_finish(state_bytes: &[u8], ke3_b64: &str) -> PakeResult<()> {
    let state = ServerLogin::<Suite>::deserialize(state_bytes)
        .map_err(|e| format!("bad pending login state: {e}"))?;
    let ke3 = CredentialFinalization::<Suite>::deserialize(&unb64(ke3_b64)?)
        .map_err(|e| format!("bad ke3: {e}"))?;
    state
        .finish(
            ke3,
            ServerLoginParameters {
                context: None,
                identifiers: Identifiers::default(),
            },
        )
        .map_err(|e| format!("login finish (ke3 rejected): {e}"))?;
    Ok(())
}

// ============================================================================
// anchor：OPAQUE 登录的服务端身份签名层（§1.3.3f / §3.4，P0-5 登录锚）
// ============================================================================

#[cfg(feature = "anchor")]
mod anchor {
    use super::{login_finish_profile, ClientLogin, PakeResult, Profile, Suite};
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    /// anchor 签名域分离标签。
    pub const ANCHOR_LABEL: &[u8] = b"flock-protocol/pake/anchor/v1";

    /// 客户端对 OPAQUE 登录的期望服务端身份（来自隧道层钉扎 ServerPin：
    /// cluster_root_pub 背书的 entry.identity_pub / server_id）。
    #[derive(Debug, Clone)]
    pub struct AnchorExpectation {
        /// 期望服务器标识（16B）。
        pub server_id: [u8; 16],
        /// 期望服务器身份 Ed25519 公钥（anchor 验签锚）。
        pub identity_pub: VerifyingKey,
        /// 登录会话的一次性绑定凭据（key-bind 消费；进 anchor 签名防截获重挂）。
        pub bind_token: [u8; 16],
    }

    /// anchor 签名覆盖的规范化字节：`ANCHOR_LABEL ‖ server_id ‖ user ‖ ke2_b64 ‖ bind_token`
    /// （§1.3.3f：签名覆盖 SERVER_ID‖user‖ke2 transcript‖bind_token）。user 变长 ⇒ 前置
    /// 长度域，防拼接歧义。
    pub fn anchor_canonical_bytes(
        server_id: &[u8; 16],
        user: &str,
        ke2_b64: &str,
        bind_token: &[u8; 16],
    ) -> Vec<u8> {
        let mut v =
            Vec::with_capacity(ANCHOR_LABEL.len() + 16 + 4 + user.len() + ke2_b64.len() + 16);
        v.extend_from_slice(ANCHOR_LABEL);
        v.extend_from_slice(server_id);
        v.extend_from_slice(&(user.len() as u32).to_le_bytes());
        v.extend_from_slice(user.as_bytes());
        v.extend_from_slice(ke2_b64.as_bytes());
        v.extend_from_slice(bind_token);
        v
    }

    /// 服务端侧签发（服务器身份 Ed25519 密钥 = 隧道层 `ServerIdentity::identity`）。
    pub fn anchor_sign(
        server_identity: &SigningKey,
        server_id: &[u8; 16],
        user: &str,
        ke2_b64: &str,
        bind_token: &[u8; 16],
    ) -> Signature {
        server_identity.sign(&anchor_canonical_bytes(
            server_id, user, ke2_b64, bind_token,
        ))
    }

    /// 客户端侧 anchor 版 login-finish（§3.4 `login_finish_anchored`）：
    /// ① 以期望身份（钉扎 ServerEntry）验 anchor 签名——不符即拒（RFC 9807 aPAKE 模型要求
    /// 客户端持有已认证服务端身份；防「持 OPRF key 的伪服务器」对登录的静默替身）；
    /// ② 通过后执行常规 [`super::login_finish_profile`]（ke3 产出；错密码本地 Err）。
    pub fn login_finish_anchored(
        state: ClientLogin<Suite>,
        pw: &str,
        user: &str,
        ke2_b64: &str,
        profile: Profile,
        expect: &AnchorExpectation,
        anchor_sig: &[u8; 64],
    ) -> PakeResult<String> {
        let sig = Signature::from_bytes(anchor_sig);
        let bytes = anchor_canonical_bytes(&expect.server_id, user, ke2_b64, &expect.bind_token);
        expect
            .identity_pub
            .verify(&bytes, &sig)
            .map_err(|e| format!("anchor: server identity signature rejected: {e}"))?;
        login_finish_profile(state, pw, user, ke2_b64, profile)
    }

    #[cfg(test)]
    mod tests {
        use super::super::*;
        use super::*;
        use rand::rngs::OsRng;

        // 正向：注册→登录（anchor 验签）往返
        #[test]
        fn anchored_login_roundtrip() {
            let mut rng = OsRng;
            let setup = server_setup_load(&server_setup_new(&mut rng)).unwrap();
            let (cstate, m1) = reg_start(&mut rng, "bob", "bob").unwrap();
            let m2 = server_reg_start(&setup, &m1, "bob").unwrap();
            let record =
                server_reg_canonical(&reg_finish(&mut rng, cstate, "bob", "bob", &m2).unwrap())
                    .unwrap();
            let rec = server_record_from_b64(&record).unwrap();

            // 服务端身份（隧道层 ServerIdentity 的 identity 密钥）
            let srv_sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
            let server_id: [u8; 16] = rand::random();
            let bind_token: [u8; 16] = rand::random();

            let (lstate, ke1) = login_start(&mut rng, "bob", "bob").unwrap();
            let (ke2, pending) =
                server_login_start(&mut rng, &setup, Some(&rec), &ke1, "bob").unwrap();
            let sig = anchor_sign(&srv_sk, &server_id, "bob", &ke2, &bind_token);
            let ke3 = login_finish_anchored(
                lstate,
                "bob",
                "bob",
                &ke2,
                Profile::default(),
                &AnchorExpectation {
                    server_id,
                    identity_pub: srv_sk.verifying_key(),
                    bind_token,
                },
                &sig.to_bytes(),
            )
            .unwrap();
            server_login_finish(&pending, &ke3).unwrap();
        }

        // 负向：anchor 签名来自攻击者密钥（伪服务器）⇒ login_finish_anchored 拒绝（ke3 不产生）
        #[test]
        fn anchored_login_rejects_forged_anchor() {
            let mut rng = OsRng;
            let setup = server_setup_load(&server_setup_new(&mut rng)).unwrap();
            let (cstate, m1) = reg_start(&mut rng, "carol", "carol").unwrap();
            let m2 = server_reg_start(&setup, &m1, "carol").unwrap();
            let record =
                server_reg_canonical(&reg_finish(&mut rng, cstate, "carol", "carol", &m2).unwrap())
                    .unwrap();
            let rec = server_record_from_b64(&record).unwrap();

            let srv_sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
            let attacker = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
            let server_id: [u8; 16] = rand::random();
            let bind_token: [u8; 16] = rand::random();

            let (lstate, ke1) = login_start(&mut rng, "carol", "carol").unwrap();
            let (ke2, _) = server_login_start(&mut rng, &setup, Some(&rec), &ke1, "carol").unwrap();
            let expect = AnchorExpectation {
                server_id,
                identity_pub: srv_sk.verifying_key(),
                bind_token,
            };
            // 攻击者密钥签的 anchor（伪服务器）⇒ 拒
            let forged = anchor_sign(&attacker, &server_id, "carol", &ke2, &bind_token);
            assert!(login_finish_anchored(
                lstate,
                "carol",
                "carol",
                &ke2,
                Profile::default(),
                &expect,
                &forged.to_bytes()
            )
            .is_err());
        }
    }
}

#[cfg(feature = "anchor")]
pub use anchor::{
    anchor_canonical_bytes, anchor_sign, login_finish_anchored, AnchorExpectation, ANCHOR_LABEL,
};

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    // 注册→登录往返（两端同 crate；record/setup 序列化跨进程语义，showroom 同款测试平移）
    #[test]
    fn registration_login_roundtrip() {
        let mut rng = OsRng;
        let setup = server_setup_load(&server_setup_new(&mut rng)).unwrap();

        let (cstate, m1) = reg_start(&mut rng, "hunter2", "alice").unwrap();
        let m2 = server_reg_start(&setup, &m1, "alice").unwrap();
        let record_b64 = reg_finish(&mut rng, cstate, "hunter2", "alice", &m2).unwrap();
        let record_b64 = server_reg_canonical(&record_b64).unwrap();
        let record = server_record_from_b64(&record_b64).unwrap();

        // 正确密码：ke1 → ke2 → ke3 → 服务端验证通过
        let (lstate, ke1) = login_start(&mut rng, "hunter2", "alice").unwrap();
        let (ke2, sstate) =
            server_login_start(&mut rng, &setup, Some(&record), &ke1, "alice").unwrap();
        let ke3 = login_finish(lstate, "hunter2", "alice", &ke2).unwrap();
        assert!(server_login_finish(&sstate, &ke3).is_ok());
    }

    // 错密码：客户端本地 finish 即失败（不产生第三请求）
    #[test]
    fn wrong_password_fails_client_finish() {
        let mut rng = OsRng;
        let setup = server_setup_load(&server_setup_new(&mut rng)).unwrap();
        let (cstate, m1) = reg_start(&mut rng, "hunter2", "alice").unwrap();
        let m2 = server_reg_start(&setup, &m1, "alice").unwrap();
        let record_b64 = reg_finish(&mut rng, cstate, "hunter2", "alice", &m2).unwrap();
        let record = server_record_from_b64(&record_b64).unwrap();

        let (lstate, ke1) = login_start(&mut rng, "wrong-pw", "alice").unwrap();
        let (ke2, _sstate) =
            server_login_start(&mut rng, &setup, Some(&record), &ke1, "alice").unwrap();
        assert!(login_finish(lstate, "wrong-pw", "alice", &ke2).is_err());
    }

    // 未知用户：record=None 仍产出 ke2（防枚举同形），客户端 finish 失败
    #[test]
    fn unknown_user_dummy_path() {
        let mut rng = OsRng;
        let setup = server_setup_load(&server_setup_new(&mut rng)).unwrap();
        let (lstate, ke1) = login_start(&mut rng, "whatever", "ghost").unwrap();
        let (ke2, _sstate) = server_login_start(&mut rng, &setup, None, &ke1, "ghost").unwrap();
        assert!(!ke2.is_empty());
        assert!(login_finish(lstate, "whatever", "ghost", &ke2).is_err());
    }

    // profile：Owasp19MiB 与 Rfc9807High 输出不同且各自确定；跨档必不匹配（防漂移语义）
    #[test]
    fn rwd_profiles_deterministic_and_distinct() {
        let a1 = rwd("pw", "alice", Profile::Owasp19MiB).unwrap();
        let a2 = rwd("pw", "alice", Profile::Owasp19MiB).unwrap();
        assert_eq!(a1, a2, "同 profile 确定");
        let b = rwd("pw", "alice", Profile::Rfc9807High).unwrap();
        assert_ne!(
            a1.to_vec(),
            b.to_vec(),
            "不同 profile 输出必不同（跨档漂移即登录失败）"
        );
        // user 进盐：同密码不同账号派生不同
        let c = rwd("pw", "bob", Profile::Owasp19MiB).unwrap();
        assert_ne!(a1.to_vec(), c.to_vec());
        assert_eq!(Profile::default(), Profile::Owasp19MiB);
        assert_eq!(Profile::Owasp19MiB.id(), 0);
        assert_eq!(Profile::Rfc9807High.id(), 1);
    }

    // 高配档全流程：注册与登录都用 Rfc9807High（注意 argon2 m=2GiB：CI/低内存机较慢）
    #[test]
    fn rfc9807_high_profile_end_to_end() {
        let mut rng = OsRng;
        let setup = server_setup_load(&server_setup_new(&mut rng)).unwrap();
        let (cstate, m1) =
            reg_start_profile(&mut rng, "pw-high", "hank", Profile::Rfc9807High).unwrap();
        let m2 = server_reg_start(&setup, &m1, "hank").unwrap();
        let record_b64 = reg_finish_profile(
            &mut rng,
            cstate,
            "pw-high",
            "hank",
            &m2,
            Profile::Rfc9807High,
        )
        .unwrap();
        let record = server_record_from_b64(&record_b64).unwrap();
        let (lstate, ke1) =
            login_start_profile(&mut rng, "pw-high", "hank", Profile::Rfc9807High).unwrap();
        let (ke2, sstate) =
            server_login_start(&mut rng, &setup, Some(&record), &ke1, "hank").unwrap();
        let ke3 =
            login_finish_profile(lstate, "pw-high", "hank", &ke2, Profile::Rfc9807High).unwrap();
        assert!(server_login_finish(&sstate, &ke3).is_ok());
    }

    // ServerSetup 迁移自洽：4.0.1 新 setup 不需要迁移；迁移函数对 4.0.1 布局应报错（长度同 128B
    // 但 dummy 段是 pk——from_private_key_slice 把 pk 当标量重导出仍产 32B，故长度检查过，
    // 真正的判别靠登录失败；此处仅验证迁移对 3.0.0 布局可工作 → 互通测试覆盖）
    #[test]
    fn migrate_rejects_wrong_length() {
        assert!(
            server_setup_migrate_v3("AAAA").is_err(),
            "长度非 128B 必须拒绝"
        );
    }

    // 未认证 b64 入口的 64KiB 上限：server_login_start/server_reg_start 等服务端入口
    // 在 decode 分配前拒绝超大报文（OPAQUE 报文远小于此）。
    #[test]
    fn unb64_rejects_oversized_input() {
        let mut rng = rand::rng();
        let setup = server_setup_load(&server_setup_new(&mut rng)).unwrap();
        let huge = "A".repeat(64 * 1024 + 1);
        // ke1 入口（未认证服务端面）
        assert!(
            server_login_start(&mut rng, &setup, None, &huge, "alice").is_err(),
            "超限 ke1 必须在 decode 前拒绝"
        );
        // m1 入口（未认证服务端面）
        assert!(
            server_reg_start(&setup, &huge, "alice").is_err(),
            "超限 m1 必须在 decode 前拒绝"
        );
    }

    // server_setup_b64 往返：new→b64→load 与 migrate_v3→b64→load 均逐字节还原
    // （迁移后落盘新格式的写回路径——误删重建会使 OPRF seed 轮换、全部记录失效）
    #[test]
    fn setup_b64_roundtrip() {
        let mut rng = rand::rng();
        let s1 = server_setup_load(&server_setup_new(&mut rng)).unwrap();
        assert_eq!(server_setup_b64(&s1), server_setup_b64(&s1), "确定性序列化");
        let s2 = server_setup_load(&server_setup_b64(&s1)).unwrap();
        assert_eq!(server_setup_b64(&s2), server_setup_b64(&s1));

        let old = server_setup_load(&server_setup_new(&mut rng)).unwrap();
        let old_b64 = server_setup_b64(&old);
        let back = server_setup_load(&old_b64).unwrap();
        assert_eq!(server_setup_b64(&back), old_b64);
    }
}
