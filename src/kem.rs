//! 混合 KEM：X25519 + ML-KEM-768（docs/design.md §1.3.3a / §3.1，P0-1、P0-7）。
//!
//! 组合规则：`shared = HKDF-SHA256(x25519_ss ‖ ml_kem_ss)`（TLS 混合思想，RFC 10024；
//! 设计依据 verdict §3.3 复核轮实跑：ek=1184B/ct=1088B、混合密文 1120B、混合公钥 1216B）。
//! 实现用 ml-kem 0.3.3（纯 Rust FIPS 203）+ x25519-dalek 3.0.0，不用 liboqs（crypto-2026 §5）。
//!
//! 线上尺寸常量：
//! - [`HybridPubkey`]：1216B = 32(X25519) ‖ 1184(ML-KEM-768 ek)；
//! - [`HybridCt`]：1120B = 32(临时 X25519 公钥) ‖ 1088(ML-KEM-768 ct)。
//!
//! HKDF 参数（本库钉死，双方一致即逐字节确定）：salt=None（HKDF 零填充），
//! info=`flock-protocol/hybrid-kem/x25519+ml-kem-768/v1`，OKM=32B。
//!
//! RNG 面：公开函数接受 rand 0.9 的 `TryCryptoRng`（OsRng / StdRng 直接可传）；
//! ml-kem / x25519-dalek 3.0 内部走 rand_core 0.10 代际，由私有 [`RngBridge`] 桥接，调用方无感。

use core::convert::Infallible;
use core::fmt;

use ml_kem::ml_kem_768::MlKem768;
use ml_kem::{
    Ciphertext, Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Kem, Key, KeyExport,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize as _;

/// rand_core 0.10（ml-kem / x25519-dalek 3.0 的 RNG 代际）。仅库内桥接用，非公开 API 面。
use rand_core as rc010;

/// X25519 公钥线上长度（字节）。
pub const X25519_PUB_LEN: usize = 32;
/// ML-KEM-768 封装公钥线上长度（FIPS 203：ek=1184B）。
pub const ML_KEM_EK_LEN: usize = 1184;
/// ML-KEM-768 密文长度（FIPS 203：ct=1088B）。
pub const ML_KEM_CT_LEN: usize = 1088;
/// 混合公钥线上长度：32 + 1184 = 1216B。
pub const HYBRID_PUB_LEN: usize = X25519_PUB_LEN + ML_KEM_EK_LEN;
/// 混合密文长度：32 + 1088 = 1120B。
pub const HYBRID_CT_LEN: usize = X25519_PUB_LEN + ML_KEM_CT_LEN;
/// 混合共享密钥长度（HKDF-SHA256 OKM）。
pub const SHARED_LEN: usize = 32;
/// 私钥序列化长度：32(X25519 sk) + 64(ML-KEM seed d‖z) = 96B。
pub const HYBRID_SK_LEN: usize = X25519_PUB_LEN + 64;

/// HKDF info 标签：域分离（换算法/换组合规则必须换标签）。
const HKDF_INFO: &[u8] = b"flock-protocol/hybrid-kem/x25519+ml-kem-768/v1";

/// seed_material 的 z 重派生标签（域分离：z 仅用于 FIPS 203 隐式拒绝伪钥）。
const L_SEED_Z: &[u8] = b"flock-protocol/hybrid-kem/seed-z/v1";

/// KEM 错误：公钥/密文反序列化或校验失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemError {
    /// 混合公钥不合法（长度错或 ML-KEM ek 未过 FIPS 203 校验）。
    InvalidPubkey,
    /// 混合密文长度不合法。
    InvalidCiphertext,
    /// 私钥种子长度不合法。
    InvalidSecret,
}

impl fmt::Display for KemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KemError::InvalidPubkey => "kem: invalid hybrid public key",
            KemError::InvalidCiphertext => "kem: invalid hybrid ciphertext",
            KemError::InvalidSecret => "kem: invalid hybrid secret key bytes",
        })
    }
}

impl std::error::Error for KemError {}

/// 混合共享密钥（HKDF-SHA256 合流后的 32B OKM）。
/// 可直接作 AES-256 钥匙（信封 v2 即此用法，§1.3.3b）。
///
/// 秘密材料纪律（§1.3.3c 清零承诺）：**不实现 `Copy`**（防按值复制扩散密钥字节的
/// 无意路径，按引用传递/显式 `clone` 不受影响）；Drop 时显式清零
/// （[`zeroize::Zeroize`]，与 [`SealedShared::zeroize`] 同一实现）。
#[derive(Clone, PartialEq, Eq)]
pub struct SealedShared([u8; SHARED_LEN]);

impl SealedShared {
    /// 原始 32B（调用方负责用途域分离；跨用途派生请另走 HKDF）。
    pub fn as_bytes(&self) -> &[u8; SHARED_LEN] {
        &self.0
    }
}

impl zeroize::Zeroize for SealedShared {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SealedShared {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for SealedShared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 不泄露密钥内容
        f.write_str("SealedShared(***)")
    }
}

/// 混合密钥对：X25519 静态 + ML-KEM-768 解封装钥。
///
/// 序列化（[`HybridKeypair::to_bytes`]）= 32B X25519 私钥 ‖ 64B ML-KEM seed（d‖z），
/// 私钥文件按 0600 落盘由调用方负责。
pub struct HybridKeypair {
    x25519: StaticSecret,
    ml_kem: DecapsulationKey<MlKem768>,
}

impl HybridKeypair {
    /// 生成新混合密钥对（随机性全部来自 `rng`）。
    pub fn generate(rng: &mut impl rand::TryCryptoRng) -> Self {
        let x = StaticSecret::random_from_rng(&mut bridge(rng));
        let dk = MlKem768::generate_keypair_from_rng(&mut bridge(rng)).0;
        HybridKeypair {
            x25519: x,
            ml_kem: dk,
        }
    }

    /// 由 [`HybridKeypair::to_bytes`] 的 96B 恢复。
    pub fn from_bytes(bytes: &[u8; HYBRID_SK_LEN]) -> Result<Self, KemError> {
        let (x, seed) = bytes.split_at(X25519_PUB_LEN);
        let x: [u8; 32] = x.try_into().expect("96B split");
        let seed: [u8; 64] = seed.try_into().expect("96B split");
        Ok(HybridKeypair {
            x25519: StaticSecret::from(x),
            ml_kem: DecapsulationKey::from_seed(seed.into()),
        })
    }

    /// 96B 序列化（32B X25519 sk ‖ 64B ML-KEM seed）。密钥材料，注意落盘权限。
    pub fn to_bytes(&self) -> [u8; HYBRID_SK_LEN] {
        let mut out = [0u8; HYBRID_SK_LEN];
        out[..32].copy_from_slice(&self.x25519.to_bytes());
        out[32..].copy_from_slice(&self.ml_kem.to_bytes());
        out
    }

    /// 对应混合公钥（1216B）。
    pub fn public(&self) -> HybridPubkey {
        let mut bytes = [0u8; HYBRID_PUB_LEN];
        let x_pub = PublicKey::from(&self.x25519);
        bytes[..32].copy_from_slice(&x_pub.to_bytes());
        bytes[32..].copy_from_slice(&self.ml_kem.encapsulation_key().to_bytes());
        HybridPubkey {
            x25519: x_pub,
            ml_kem: self.ml_kem.encapsulation_key().clone(),
            bytes,
        }
    }

    /// 静态 X25519 私钥引用。session 握手的 split 模式（§1.3.3c：X25519(e,s_srv) 与
    /// ML-KEM ct 分列）需要单独取 X25519 份额做 DH，故开放只读访问。
    ///
    /// **将收敛**（flock-sync 迁移的后续阶段）：split 模式的取用面将统一到
    /// [`HybridKeypair::seed_material`]/[`HybridKeypair::from_seed_material`] 与
    /// 握手内部化；本访问器在此期间保持 `pub` 不动以保兼容过渡。
    pub fn x25519_secret(&self) -> &StaticSecret {
        &self.x25519
    }

    /// ML-KEM-768 解封装钥引用（同上，split 模式直取；**将收敛**——见
    /// [`HybridKeypair::x25519_secret`] 的收敛注记）。
    pub fn ml_kem_decapsulation(&self) -> &DecapsulationKey<MlKem768> {
        &self.ml_kem
    }

    /// split 模式种子材料（64B = X25519 私钥 32B ‖ ML-KEM d 32B）。
    ///
    /// **split 模式专用**（§1.3.3c：握手按 X25519(e,s_srv) 与 ML-KEM ct 分列使用
    /// 服务器静态混合钥）：flock-sync 的静态密钥分发/迁移以本 64B 为载体（完整 96B
    /// 私钥序列化仍是 [`HybridKeypair::to_bytes`]——含 ML-KEM z 的全量形态）。
    ///
    /// 往返语义：[`HybridKeypair::from_seed_material`] 消费本产物得到**等效**密钥对——
    /// 公钥逐字节一致、合法密文解封逐字节一致；ML-KEM 的 z（FIPS 203 中仅参与隐式
    /// 拒绝伪钥，不进公钥与合法解封路径）由种子确定性重派生，与原钥的随机 z 不同。
    pub fn seed_material(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x25519.to_bytes());
        let ml = self.ml_kem.to_bytes(); // 64B = d‖z
        out[32..].copy_from_slice(&ml[..32]);
        out
    }

    /// [`HybridKeypair::seed_material`] 的逆（等效密钥对语义见其文档）。确定性：
    /// 同种子恒重建同一密钥对。
    pub fn from_seed_material(seed: &[u8; 64]) -> Self {
        let x: [u8; 32] = seed[..32].try_into().expect("64B seed split");
        let d: [u8; 32] = seed[32..].try_into().expect("64B seed split");
        // z 确定性重派生（域分离标签）：合法路径（公钥、合法密文解封）完全由 d 决定。
        let mut h = Sha256::new();
        h.update(L_SEED_Z);
        h.update(seed);
        let z: [u8; 32] = h.finalize().into();
        let mut ml_seed = [0u8; 64];
        ml_seed[..32].copy_from_slice(&d);
        ml_seed[32..].copy_from_slice(&z);
        HybridKeypair {
            x25519: StaticSecret::from(x),
            ml_kem: DecapsulationKey::from_seed(ml_seed.into()),
        }
    }
}

impl fmt::Debug for HybridKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridKeypair")
            .field("public", &fingerprint(&self.public()))
            .finish()
    }
}

/// 混合公钥：线上 1216B = 32(X25519) ‖ 1184(ML-KEM-768 ek)。
///
/// [`HybridPubkey::from_bytes`] 会走 FIPS 203 ek 校验（ml-kem `EncapsulationKey::new`），
/// 拒绝畸形公钥。
#[derive(Clone)]
pub struct HybridPubkey {
    x25519: PublicKey,
    ml_kem: EncapsulationKey<MlKem768>,
    bytes: [u8; HYBRID_PUB_LEN],
}

impl HybridPubkey {
    /// 从线上 1216B 恢复（含 ML-KEM ek 结构校验）。
    pub fn from_bytes(bytes: &[u8; HYBRID_PUB_LEN]) -> Result<Self, KemError> {
        let (x, ek) = bytes.split_at(X25519_PUB_LEN);
        let ek_arr: [u8; ML_KEM_EK_LEN] = ek.try_into().expect("1216B split");
        let key = Key::<EncapsulationKey<MlKem768>>::try_from(ek_arr.as_slice()).expect("1184B ek");
        let ml_kem =
            EncapsulationKey::<MlKem768>::new(&key).map_err(|_| KemError::InvalidPubkey)?;
        // X25519 公钥任意 32B 均可（小阶点在 diffie_hellman 后由 was_contributory 兜底）
        let x_arr: [u8; X25519_PUB_LEN] = x.try_into().expect("1216B split");
        Ok(HybridPubkey {
            x25519: PublicKey::from(x_arr),
            ml_kem,
            bytes: *bytes,
        })
    }

    /// 线上 1216B（规范化布局，直接可发）。
    pub fn to_bytes(&self) -> [u8; HYBRID_PUB_LEN] {
        self.bytes
    }

    /// X25519 公钥部分（1216B 的前 32B 对应物）。session 握手 split 模式用（§1.3.3c）。
    pub fn x25519_public(&self) -> &PublicKey {
        &self.x25519
    }

    /// ML-KEM-768 封装公钥部分。session 握手对服务器静态 ML-KEM 公钥封装 1088B ct 用。
    pub fn ml_kem_encapsulation(&self) -> &EncapsulationKey<MlKem768> {
        &self.ml_kem
    }
}

impl fmt::Debug for HybridPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridPubkey(")?;
        for b in fingerprint(self).as_bytes().iter().take(4) {
            write!(f, "{b:02x}")?;
        }
        f.write_str("…)")
    }
}

/// 混合密文：1120B = 32(临时 X25519 公钥) ‖ 1088(ML-KEM-768 ct)。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HybridCt([u8; HYBRID_CT_LEN]);

impl HybridCt {
    /// 从线上 1120B 恢复（仅查长度；ML-KEM ct 任意 1088B 均为合法输入——隐式拒绝语义）。
    pub fn from_bytes(bytes: &[u8; HYBRID_CT_LEN]) -> Self {
        HybridCt(*bytes)
    }

    /// 线上 1120B。
    pub fn to_bytes(&self) -> [u8; HYBRID_CT_LEN] {
        self.0
    }
}

impl fmt::Debug for HybridCt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HybridCt").field(&"..1120B..").finish()
    }
}

/// 公钥指纹：SHA-256(1216B 规范化公钥)。钉扎/展示用（§3.8 展示格式 = 8 组 hex）。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// 由既有 32B 摘要构造（session 侧对集群根/身份 Ed25519 公钥的指纹复用同一展示格式）。
    pub fn from_digest(bytes: [u8; 32]) -> Self {
        Fingerprint(bytes)
    }
}

impl Fingerprint {
    /// 原始 32B。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    /// 展示格式：8 组 8 hex 字符，冒号分隔（§3.8「8 组 hex」钉扎展示约定）。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hexs = hex::encode(self.0);
        for i in 0..8 {
            if i > 0 {
                f.write_str(":")?;
            }
            f.write_str(&hexs[i * 8..i * 8 + 8])?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

/// 封装：对 `pk` 生成一次性共享密钥与混合密文（随机性全部来自 `rng`）。
///
/// 一次性信封/握手共享的正确打开方式：每信封/每握手调用一次，`SealedShared` 用后即弃。
pub fn encapsulate(
    pk: &HybridPubkey,
    rng: &mut impl rand::TryCryptoRng,
) -> (SealedShared, HybridCt) {
    let eph = EphemeralSecret::random_from_rng(&mut bridge(rng));
    let eph_pub = PublicKey::from(&eph);
    let (ml_ct, ml_ss) = pk.ml_kem.encapsulate_with_rng(&mut bridge(rng));
    let x_ss = eph.diffie_hellman(&pk.x25519);

    let mut ct_bytes = [0u8; HYBRID_CT_LEN];
    ct_bytes[..32].copy_from_slice(&eph_pub.to_bytes());
    ct_bytes[32..].copy_from_slice(ml_ct.as_slice());

    let shared = combine(x_ss.as_bytes(), ml_ss.as_slice());
    (shared, HybridCt(ct_bytes))
}

/// 解封装。`None` 仅当 X25519 侧非贡献（小阶点攻击面；正常流量不会出现）——
/// ML-KEM 侧按 FIPS 203 隐式拒绝返回伪随机钥匙，由上层 AEAD 认证兜底。
pub fn decapsulate(sk: &HybridKeypair, ct: &HybridCt) -> Option<SealedShared> {
    let (eph, ml_ct) = ct.0.split_at(X25519_PUB_LEN);
    let eph_arr: [u8; X25519_PUB_LEN] = eph.try_into().expect("1120B split");
    let eph_pub = PublicKey::from(eph_arr);
    let x_ss = sk.x25519.diffie_hellman(&eph_pub);
    if !x_ss.was_contributory() {
        return None;
    }
    let ml_ct: Ciphertext<MlKem768> = ml_ct.try_into().ok()?;
    let ml_ss = sk.ml_kem.decapsulate(&ml_ct);
    Some(combine(x_ss.as_bytes(), ml_ss.as_slice()))
}

/// 公钥指纹（SHA-256 over 1216B 规范化公钥）。
pub fn fingerprint(pk: &HybridPubkey) -> Fingerprint {
    Fingerprint(Sha256::digest(pk.to_bytes()).into())
}

/// HKDF-SHA256 合流：ikm = x25519_ss ‖ ml_kem_ss（顺序固定，§1.3.3a）。
/// ikm 是双份共享秘密的拼接——`Zeroizing` 包裹，Drop 时清零（§1.3.3c 密钥纪律）。
fn combine(x_ss: &[u8], ml_ss: &[u8]) -> SealedShared {
    use hkdf::Hkdf;
    let mut ikm = zeroize::Zeroizing::new(Vec::with_capacity(x_ss.len() + ml_ss.len()));
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(ml_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm[..]);
    let mut okm = [0u8; SHARED_LEN];
    hk.expand(HKDF_INFO, &mut okm).expect("32B OKM 恒合法");
    SealedShared(okm)
}

/// rand 0.9 → rand_core 0.10 私有桥（ml-kem / x25519-dalek 3.0 的 RNG 代际）。
/// 目标侧要求不可失败（rc010 CryptoRng ⇒ Error=Infallible），故内层熵源故障直接 panic
/// （同 rand_core `UnwrapErr` 适配器语义）。
pub(crate) struct RngBridge<'a, R: rand::TryRngCore + ?Sized>(&'a mut R);

pub(crate) fn bridge<R: rand::TryRngCore + ?Sized>(rng: &mut R) -> RngBridge<'_, R> {
    RngBridge(rng)
}

impl<R: rand::TryRngCore + ?Sized> rc010::TryRng for RngBridge<'_, R> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self
            .0
            .try_next_u32()
            .expect("flock-protocol: entropy source failed"))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self
            .0
            .try_next_u64()
            .expect("flock-protocol: entropy source failed"))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.0
            .try_fill_bytes(dst)
            .expect("flock-protocol: entropy source failed");
        Ok(())
    }
}

// rc010 的 TryCryptoRng 是无方法标记 trait，无 blanket impl——需显式声明
impl<R: rand::TryRngCore + ?Sized> rc010::TryCryptoRng for RngBridge<'_, R> {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn keypair() -> HybridKeypair {
        HybridKeypair::generate(&mut OsRng) // OsRng: TryCryptoRng 直接可传
    }

    #[test]
    fn roundtrip_and_sizes() {
        let sk = keypair();
        let pk = sk.public();
        assert_eq!(pk.to_bytes().len(), 1216, "混合公钥线上 1216B");
        let (ss1, ct) = encapsulate(&pk, &mut OsRng);
        assert_eq!(ct.to_bytes().len(), 1120, "混合密文 1120B");
        let ss2 = decapsulate(&sk, &ct).expect("decapsulate");
        assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "双方共享密钥一致");
    }

    #[test]
    fn keypair_serialization_roundtrip() {
        let sk = keypair();
        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), 96, "私钥 96B = 32 + 64(d‖z)");
        let sk2 = HybridKeypair::from_bytes(&bytes).expect("restore");
        let (ss1, ct) = encapsulate(&sk.public(), &mut OsRng);
        let ss2 = decapsulate(&sk2, &ct).expect("decapsulate");
        assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "恢复的私钥可解封");
    }

    #[test]
    fn pubkey_from_bytes_rejects_malformed_ek() {
        // 0xFF 全填充：每个 12-bit t 系数 = 4095 > q-1=3328 ⇒ decodeAndCheck 必拒（确定性）
        assert!(
            HybridPubkey::from_bytes(&[0xFFu8; 1216]).is_err(),
            "越界 t 系数必须被 FIPS 203 ek 校验拒绝"
        );
        let sk = keypair();
        let good = HybridPubkey::from_bytes(&sk.public().to_bytes()).expect("valid pk");
        assert_eq!(
            good.to_bytes(),
            sk.public().to_bytes(),
            "合法公钥往返逐字节一致"
        );
    }

    #[test]
    fn ct_tamper_gives_different_shared() {
        let sk = keypair();
        let (ss1, ct) = encapsulate(&sk.public(), &mut OsRng);
        let mut b = ct.to_bytes();
        b[32 + 100] ^= 0x01; // ML-KEM ct 区翻转
        let ss2 = decapsulate(&sk, &HybridCt::from_bytes(&b)).expect("隐式拒绝仍返回伪随机钥匙");
        assert_ne!(ss1.as_bytes(), ss2.as_bytes(), "篡改后共享密钥必不相同");
    }

    #[test]
    fn ephemeral_freshness() {
        // 同一公钥两次封装：临时份额不同 ⇒ 共享密钥不同、密文不同（一次性语义的前提）
        let sk = keypair();
        let (ss1, ct1) = encapsulate(&sk.public(), &mut OsRng);
        let (ss2, ct2) = encapsulate(&sk.public(), &mut OsRng);
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());
        assert_ne!(ct1.to_bytes(), ct2.to_bytes());
    }

    #[test]
    fn fingerprint_stable_and_display() {
        let sk = keypair();
        let fp1 = fingerprint(&sk.public());
        assert_eq!(fp1, fingerprint(&sk.public()), "指纹确定性");
        let pk2 = HybridPubkey::from_bytes(&sk.public().to_bytes()).unwrap();
        assert_eq!(fp1, fingerprint(&pk2), "公钥序列化往返后指纹不变");
        let s = fp1.to_string();
        assert_eq!(s.split(':').count(), 8, "8 组展示");
        assert!(s
            .split(':')
            .all(|g| g.len() == 8 && g.bytes().all(|b| b.is_ascii_hexdigit())));
        let sk3 = keypair();
        assert_ne!(fp1, fingerprint(&sk3.public()), "不同密钥指纹不同");
    }

    #[test]
    fn cross_keypair_shared_mismatch() {
        let (sk_a, sk_b) = (keypair(), keypair());
        let (ss, ct) = encapsulate(&sk_a.public(), &mut OsRng);
        let ss_b = decapsulate(&sk_b, &ct).expect("隐式拒绝伪随机钥匙");
        assert_ne!(ss.as_bytes(), ss_b.as_bytes(), "第三方无法得到同一共享密钥");
    }

    /// 清零纪律（§1.3.3c）：SealedShared 显式 zeroize 后 32B 全零（Drop 路径同一实现）。
    #[test]
    fn sealed_shared_zeroize_clears_material() {
        let sk = keypair();
        let (mut ss, _ct) = encapsulate(&sk.public(), &mut OsRng);
        assert!(
            ss.as_bytes().iter().any(|&b| b != 0),
            "前置：封装产物非全零（否则断言空转）"
        );
        zeroize::Zeroize::zeroize(&mut ss);
        assert!(
            ss.as_bytes().iter().all(|&b| b == 0),
            "zeroize 必须覆盖全部 32B 共享密钥材料"
        );
    }

    /// seed_material 往返（split 模式专用，flock-sync 迁移载体）：等效密钥对——
    /// 公钥逐字节一致、合法密文解封一致；重建确定性；不同种子不同公钥。
    #[test]
    fn seed_material_roundtrip_equivalent_and_deterministic() {
        let sk = keypair();
        let seed = sk.seed_material();
        let sk2 = HybridKeypair::from_seed_material(&seed);
        assert_eq!(
            sk2.public().to_bytes(),
            sk.public().to_bytes(),
            "等效：公钥逐字节一致"
        );
        let (ss1, ct) = encapsulate(&sk.public(), &mut OsRng);
        let ss2 = decapsulate(&sk2, &ct).expect("等效钥可解封");
        assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "等效：合法密文解封一致");

        // 确定性：同种子重建两次公钥一致。
        let sk3 = HybridKeypair::from_seed_material(&seed);
        assert_eq!(sk3.public().to_bytes(), sk2.public().to_bytes());

        // 不同种子 ⇒ 不同公钥（翻转中段字节位：X25519 标量钳位会抹掉首字节低 3 位，
        // 翻 bit0 会被钳位吞掉——选取必然存活的字节位）。
        let mut other = seed;
        other[10] ^= 0x01;
        assert_ne!(
            HybridKeypair::from_seed_material(&other)
                .public()
                .to_bytes(),
            sk2.public().to_bytes()
        );

        // 96B to_bytes/from_bytes 仍是全量无损序列化（与 64B 种子载体并存）。
        let full = HybridKeypair::from_bytes(&sk.to_bytes()).expect("全量序列化");
        assert_eq!(full.public().to_bytes(), sk.public().to_bytes());
    }
}
