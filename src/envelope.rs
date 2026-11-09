//! 文件信封 v2（混合封装 + 段序号 AAD）（docs/design.md §1.3.3b / §3.2，P0-1、P0-3）。
//!
//! v2 字节布局：
//!
//! ```text
//! 头:  [1B ver=2][16B envelope_id][32B eph_x25519][1088B ml_kem_ct]   = 1137B
//! 段:  [12B nonce][AES-256-GCM ct‖16B tag]，段明文 = 4MiB（末段可短）
//! AAD: ver ‖ envelope_id ‖ seg_idx(u64 LE) ‖ is_final(u8 0/1)        = 26B
//! ```
//!
//! - 一次性 k 由混合 KEM 派生（每信封新临时 X25519 + ML-KEM 份额 ⇒ 一次性信封获得
//!   前向保密，verdict §3.3）；k 即 [`crate::kem::SealedShared`] 的 32B HKDF 输出。
//! - **文档化安全前提**（§1.3.3b，verdict §3.4）：一次性 k + 每段随机 96-bit nonce ——
//!   每密钥消息数 = n/4MiB ≪ 2^32，在 SP 800-38D 随机 IV 界内；长会话流量的计数器
//!   nonce 纪律属隧道档（session 模块），两档分立。
//! - AAD 把段序号+信封 ID+结束位绑进认证：段重排（seg_idx）、跨信封拼接（envelope_id）、
//!   删尾（is_final）全部在解密侧被拒（v1 缺失，showroom-common lib.rs:396-411 本次核实）。
//! - 流式恒定内存（沿用 showroom seal/open 缓冲模型，showroom-analysis §4.1）：
//!   seal ≈ 1×SEG 缓冲 + 1 字节探测；open ≈ BufReader(SEG+28) + 1×(SEG+16) 密文缓冲。
//! - 长度不变量：`total = 1137 + n + ceil(n/SEG) × (12+16)`（n = 明文字节数）。
//! - 空输入合法：仅 1137B 头（0 字节明文，段数 0）。注意：空信封无段可认证，
//!   头部收件人匹配性不可验证（0 字节明文无泄露面）；整体完整性按 showroom EtM 惯例
//!   由调用方外层 SR-SIG1 哈希承担（security.md:84 同思路）。
//! - 截断容错固有边界（showroom 同款）：解密逐段进行，前段已写出后段失败不回滚。
//!
//! v1 只读兼容（`legacy` feature）：[`open_v1_legacy`] 解 `[384B RSA-OAEP-SHA256(k)] ||
//! 段{[12B nonce][ct+tag]}`（无 AAD，showroom-common lib.rs:376-461 布局不变）。

use std::io::{self, BufReader, Read, Write};

use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aead::{AeadCore, AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};

/// 由 32B 原始钥构造 AES-256-GCM 钥匙（长度恒 32，try_from 仅查长度）。
fn key_of(raw: &[u8; KEY_LEN]) -> Key<Aes256Gcm> {
    Key::<Aes256Gcm>::try_from(&raw[..]).expect("32B AES-256 key")
}
use rand::RngCore;

use crate::kem::{self, HybridCt, HybridKeypair, HybridPubkey};

/// AES-256 钥匙长度（v1 兼容常量，§1.3.2）。
pub const KEY_LEN: usize = 32;
/// AES-GCM 96-bit nonce 长度（v1 兼容常量，§1.3.2）。
pub const NONCE_LEN: usize = 12;
/// GCM 认证标签长度（v1 兼容常量，§1.3.2）。
pub const TAG_LEN: usize = 16;
/// 每段明文 4MiB（v1 兼容常量，§1.3.2）。
pub const SEG: usize = 4 * 1024 * 1024;

/// v2 头版本字节。
pub const V2_VER: u8 = 2;
/// v2 头长度：1 + 16 + 32 + 1088 = 1137B。
pub const V2_HEADER_LEN: usize = 1 + 16 + kem::X25519_PUB_LEN + kem::ML_KEM_CT_LEN;
/// 段 AAD 长度：ver(1) + id(16) + seg_idx(8) + is_final(1)。
pub const SEG_AAD_LEN: usize = 1 + 16 + 8 + 1;

/// `legacy`：v1 封装头长度（RSA-3072 模长，§1.3.2）。
#[cfg(feature = "legacy")]
pub const WRAP_LEN: usize = 384;

/// [`seal_v2`] 产物摘要：信封 ID / 段数 / 写出总字节数（含 1137B 头）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealInfo {
    /// 16B 信封 ID（同时绑进每段 AAD）。
    pub envelope_id: [u8; 16],
    /// 段数（空信封 = 0）。
    pub segments: u64,
    /// 写出总字节数（含头），= `1137 + n + segments × 28`。
    pub total_bytes: u64,
}

/// 段 AAD：`ver ‖ envelope_id ‖ seg_idx(u64 LE) ‖ is_final`（§1.3.3b；构造为内部实现细节，§3.2）。
fn seg_aad(ver: u8, envelope_id: &[u8; 16], seg_idx: u64, is_final: bool) -> [u8; SEG_AAD_LEN] {
    let mut a = [0u8; SEG_AAD_LEN];
    a[0] = ver;
    a[1..17].copy_from_slice(envelope_id);
    a[17..25].copy_from_slice(&seg_idx.to_le_bytes());
    a[25] = u8::from(is_final);
    a
}

/// v2 加密封装（流式，恒定内存）。随机性：envelope_id / 混合 KEM 临时份额 / 每段 nonce 均 OsRng。
pub fn seal_v2<W: Write>(
    recipient: &HybridPubkey,
    mut plain: impl Read,
    mut out: W,
) -> io::Result<SealInfo> {
    let mut rng = rand::rng();
    let mut envelope_id = [0u8; 16];
    rng.fill_bytes(&mut envelope_id);

    // 一次性 k：混合封装（每信封新临时份额 ⇒ 前向保密）
    let (shared, ct) = kem::encapsulate(recipient, &mut rng);
    let cipher = Aes256Gcm::new(&key_of(shared.as_bytes()));

    // 头 1137B：ver | envelope_id | HybridCt（= eph_x25519 32B ‖ ml_kem_ct 1088B，顺序 §1.3.3b）
    out.write_all(&[V2_VER])?;
    out.write_all(&envelope_id)?;
    out.write_all(&ct.to_bytes())?;
    let mut total_bytes = V2_HEADER_LEN as u64;

    let mut buf = vec![0u8; SEG];
    let mut seg_idx: u64 = 0;
    let mut segments: u64 = 0;
    // 1 字节探测位：满段后探读 1B 判定 is_final，避免第二块 4MiB 缓冲（恒定内存）
    let mut carry: u8 = 0;
    let mut carry_len: usize = 0;
    loop {
        let n = if carry_len == 1 {
            buf[0] = carry;
            1 + read_full(&mut plain, &mut buf[1..])?
        } else {
            read_full(&mut plain, &mut buf)?
        };
        if n == 0 {
            break; // 干净收尾（上一次写入的已是末段；首读即 0 = 空信封）
        }
        let is_final = if n < SEG {
            true
        } else {
            let mut probe = [0u8; 1];
            match read_full(&mut plain, &mut probe)? {
                0 => true,
                _ => {
                    carry = probe[0];
                    carry_len = 1;
                    false
                }
            }
        };
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let aad = seg_aad(V2_VER, &envelope_id, seg_idx, is_final);
        let tag = cipher
            .encrypt_inout_detached(
                &Nonce::<<Aes256Gcm as AeadCore>::NonceSize>::from(nonce),
                &aad,
                InOutBuf::from(&mut buf[..n]),
            )
            .map_err(|_| io::Error::other("envelope v2: aes-gcm encrypt segment"))?;
        out.write_all(&nonce)?;
        out.write_all(&buf[..n])?;
        out.write_all(tag.as_slice())?;
        total_bytes += (NONCE_LEN + n + TAG_LEN) as u64;
        seg_idx += 1;
        segments += 1;
        if is_final {
            break;
        }
    }
    Ok(SealInfo {
        envelope_id,
        segments,
        total_bytes,
    })
}

/// v2 解封（流式，恒定内存）。返回写出明文总字节数；任何 ver/头长/段认证失败返回 Err（不 panic）。
/// 空信封（仅 1137B 头）合法，返回 0。
pub fn open_v2(sk: &HybridKeypair, sealed: impl Read, mut out: impl Write) -> io::Result<u64> {
    let mut r = BufReader::with_capacity(SEG + NONCE_LEN + TAG_LEN, sealed);

    let mut header = [0u8; V2_HEADER_LEN];
    if read_full(&mut r, &mut header)? != V2_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "envelope: truncated 1137-byte v2 header",
        ));
    }
    if header[0] != V2_VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "envelope: unsupported version {} (expect {V2_VER})",
                header[0]
            ),
        ));
    }
    let envelope_id: [u8; 16] = header[1..17].try_into().expect("1137B split");
    let ct_bytes: [u8; kem::HYBRID_CT_LEN] = header[17..].try_into().expect("1137B split");
    let shared = kem::decapsulate(sk, &HybridCt::from_bytes(&ct_bytes)).ok_or_else(|| {
        io::Error::other("envelope v2: hybrid decapsulation rejected (non-contributory)")
    })?;
    let cipher = Aes256Gcm::new(&key_of(shared.as_bytes()));

    let mut nonce = [0u8; NONCE_LEN];
    let mut next_nonce = [0u8; NONCE_LEN];
    let mut ct = vec![0u8; SEG + TAG_LEN];
    let mut seg_idx: u64 = 0;
    let mut total: u64 = 0;

    match read_full(&mut r, &mut nonce)? {
        0 => return Ok(0), // 空信封：段边界上的干净 EOF
        NONCE_LEN => {}
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "envelope: truncated nonce",
            ))
        }
    }
    loop {
        let n = read_full(&mut r, &mut ct)?;
        if n < TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "envelope: truncated segment",
            ));
        }
        // 末段判定：前瞻探读下一 nonce（EOF ⇒ 本段为末段；AAD 绑 is_final ⇒ 删尾被拒）
        let is_final = match read_full(&mut r, &mut next_nonce)? {
            0 => true,
            NONCE_LEN => false,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "envelope: truncated nonce",
                ))
            }
        };
        let (msg, tag_bytes) = ct[..n].split_at_mut(n - TAG_LEN);
        let tag_arr: [u8; TAG_LEN] = tag_bytes.try_into().expect("16B tag");
        let aad = seg_aad(V2_VER, &envelope_id, seg_idx, is_final);
        cipher
            .decrypt_inout_detached(
                &Nonce::<<Aes256Gcm as AeadCore>::NonceSize>::from(nonce),
                &aad,
                InOutBuf::from(&mut *msg),
                &Tag::<<Aes256Gcm as AeadCore>::TagSize>::from(tag_arr),
            )
            .map_err(|_| {
                io::Error::other(
                    "envelope v2: aes-gcm segment auth failed \
                     (tag mismatch / tampered / reordered / spliced / truncated)",
                )
            })?;
        out.write_all(msg)?;
        total += msg.len() as u64;
        seg_idx += 1;
        if is_final {
            return Ok(total);
        }
        nonce = next_nonce;
    }
}

/// `legacy`：v1 只读解封（showroom `seal` 产物；布局 §1.3.2，`[384B RSA-OAEP-SHA256(k)] ||
/// 段{[12B nonce][ct+16B tag]}`，**无 AAD**——正是 v2 段 AAD 修的缺陷，P0-3）。
/// 返回写出明文总字节数；空信封（仅 384B 头）合法，返回 0。
#[cfg(feature = "legacy")]
pub fn open_v1_legacy(
    platform_priv: &rsa::RsaPrivateKey,
    sealed: impl Read,
    mut out: impl Write,
) -> io::Result<u64> {
    let mut r = BufReader::with_capacity(SEG + NONCE_LEN + TAG_LEN, sealed);
    let mut wrap = [0u8; WRAP_LEN];
    if read_full(&mut r, &mut wrap)? != WRAP_LEN {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "sealed: truncated 384-byte header",
        ));
    }
    let k = platform_priv
        .decrypt(rsa::Oaep::new::<rsa::sha2::Sha256>(), &wrap)
        .map_err(|e| io::Error::other(format!("rsa-oaep unwrap key: {e}")))?;
    let k: [u8; KEY_LEN] = k
        .as_slice()
        .try_into()
        .map_err(|_| io::Error::other("unwrapped key not 32 bytes"))?;
    let cipher = Aes256Gcm::new(&key_of(&k));

    let mut nonce = [0u8; NONCE_LEN];
    let mut ct = vec![0u8; SEG + TAG_LEN];
    let mut total: u64 = 0;
    loop {
        match read_full(&mut r, &mut nonce)? {
            0 => return Ok(total), // 干净收尾（段边界上的 EOF）
            NONCE_LEN => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sealed: truncated nonce",
                ))
            }
        }
        let n = read_full(&mut r, &mut ct)?;
        if n < TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "sealed: truncated segment",
            ));
        }
        let (msg, tag_bytes) = ct[..n].split_at_mut(n - TAG_LEN);
        let tag_arr: [u8; TAG_LEN] = tag_bytes.try_into().expect("16B tag");
        cipher
            .decrypt_inout_detached(
                &Nonce::<<Aes256Gcm as AeadCore>::NonceSize>::from(nonce),
                b"", // v1 无 AAD（保持逐字节兼容）
                InOutBuf::from(&mut *msg),
                &Tag::<<Aes256Gcm as AeadCore>::TagSize>::from(tag_arr),
            )
            .map_err(|_| {
                io::Error::other("aes-gcm segment auth failed (tag mismatch / tampered data)")
            })?;
        out.write_all(msg)?;
        total += msg.len() as u64;
    }
}

// ———— v1 写入侧 + 平台 RSA 密钥对（`legacy`；§1.3.2 兼容面，showroom 迁移窗口内继续写 v1）————

/// rand 0.9（本库 RNG 面）→ rsa 0.9.10 的 rand_core 0.6 代际私有桥
/// （rsa keygen / OAEP padding 的 `CryptoRngCore` 参数；pake 模块 RngBridge08 同思路）。
/// 熵源故障直接 panic（同本库其它桥的语义）。
#[cfg(feature = "legacy")]
struct Rng06<'a, R: rand::TryRngCore + ?Sized>(&'a mut R);

#[cfg(feature = "legacy")]
impl<R: rand::TryRngCore + ?Sized> rsa::rand_core::RngCore for Rng06<'_, R> {
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
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.0.try_fill_bytes(dst).map_err(|_| {
            rsa::rand_core::Error::from(std::num::NonZeroU32::new(1).expect("nonzero"))
        })
    }
}

#[cfg(feature = "legacy")]
impl<R: rand::TryRngCore + ?Sized> rsa::rand_core::CryptoRng for Rng06<'_, R> {}

/// `legacy`：v1 加密封装（showroom `seal` 原样，§1.3.2 签名不变）。
/// 布局 `[384B RSA-OAEP-SHA256 封装的 k] || 每段[12B nonce][密文+16B tag]`，段=4MiB 明文，
/// **无 AAD**（v1 固有缺陷由 v2 段序号 AAD 修，P0-3；此处保持逐字节兼容，不改）。
/// 返回写出的总字节数（含 384B 封装头）。迁移窗口内 showroom 继续写 v1（§1.3.3a：
/// 真正的过渡 = 继续写 v1、永远可读 v1）。zstd 压缩不在本 crate（调用方管道自行组合）。
#[cfg(feature = "legacy")]
pub fn seal_v1_legacy<W: Write>(
    platform_pub: &rsa::RsaPublicKey,
    mut plain: impl Read,
    mut out: W,
) -> io::Result<u64> {
    let mut rng = rand::rng();
    let mut k = [0u8; KEY_LEN];
    rng.fill_bytes(&mut k);
    let wrapped = platform_pub
        .encrypt(
            &mut Rng06(&mut rng),
            rsa::Oaep::new::<rsa::sha2::Sha256>(),
            &k,
        )
        .map_err(|e| io::Error::other(format!("rsa-oaep wrap key: {e}")))?;
    if wrapped.len() != WRAP_LEN {
        return Err(io::Error::other(format!(
            "expected 384-byte rsa-3072 wrap, got {}",
            wrapped.len()
        )));
    }
    out.write_all(&wrapped)?;
    let mut total = wrapped.len() as u64;
    let cipher = Aes256Gcm::new(&key_of(&k));
    let mut buf = vec![0u8; SEG];
    loop {
        let n = read_full(&mut plain, &mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let tag = cipher
            .encrypt_inout_detached(
                &Nonce::<<Aes256Gcm as AeadCore>::NonceSize>::from(nonce),
                b"", // v1 无 AAD（保持逐字节兼容）
                InOutBuf::from(&mut buf[..n]),
            )
            .map_err(|_| io::Error::other("aes-gcm encrypt segment"))?;
        out.write_all(&nonce)?;
        out.write_all(&buf[..n])?;
        out.write_all(tag.as_slice())?;
        total += (NONCE_LEN + n + TAG_LEN) as u64;
    }
}

/// `legacy`：平台 RSA-3072 密钥对（showroom `PlatformKeys` 原样，§1.3.2）。
/// v1 信封的收件人密钥（seal 用公钥 / open 用私钥）。
#[cfg(feature = "legacy")]
pub struct PlatformKeys(rsa::RsaPrivateKey);

#[cfg(feature = "legacy")]
impl PlatformKeys {
    /// 生成 RSA-3072（模长 384B = v1 封装头长度契约）。
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        PlatformKeys(rsa::RsaPrivateKey::new(&mut Rng06(&mut rng), 3072).expect("rsa-3072 keygen"))
    }

    /// 私钥（传给 [`open_v1_legacy`]；showroom 调用方亦经再导出的 rsa crate 从 PEM 自行构造）。
    pub fn private(&self) -> &rsa::RsaPrivateKey {
        &self.0
    }

    /// 公钥（传给 [`seal_v1_legacy`]）。
    pub fn public(&self) -> rsa::RsaPublicKey {
        self.0.to_public_key()
    }

    /// 写 `<dir>/platform_rsa`（PKCS#8 PEM，0600）与 `<dir>/platform_rsa.pub`，返回私钥路径。
    /// unix 平台专属（0600 权限语义；wasm32 无文件系统）。
    #[cfg(unix)]
    pub fn save_pem(&self, dir: &std::path::Path) -> crate::compat::Result<std::path::PathBuf> {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

        let priv_path = dir.join("platform_rsa");
        let pem = self.0.to_pkcs8_pem(LineEnding::LF)?;
        crate::compat::write_private(&priv_path, pem.as_bytes())?;
        std::fs::write(dir.join("platform_rsa.pub"), self.public_pem().as_bytes())?;
        Ok(priv_path)
    }

    /// 读 `<dir>/platform_rsa`（PKCS#8 PEM）。
    pub fn load_pem(dir: &std::path::Path) -> crate::compat::Result<Self> {
        use rsa::pkcs8::DecodePrivateKey;

        let pem = std::fs::read_to_string(dir.join("platform_rsa"))?;
        Ok(PlatformKeys(rsa::RsaPrivateKey::from_pkcs8_pem(&pem)?))
    }

    /// 公钥 PEM（SPKI，`-----BEGIN PUBLIC KEY-----`）。
    pub fn public_pem(&self) -> String {
        use rsa::pkcs8::{EncodePublicKey, LineEnding};

        self.0
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode public pem")
            .as_str()
            .to_owned()
    }
}

/// 循环 read 直至填满 buf 或 EOF，返回已读字节数（管道短读安全；showroom lib.rs:464-473 同款）。
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..])? {
            0 => break,
            n => off += n,
        }
    }
    Ok(off)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use V2_HEADER_LEN as HDR;

    fn keypair() -> HybridKeypair {
        HybridKeypair::generate(&mut rand::rngs::OsRng)
    }

    fn seal(plain: &[u8], pk: &HybridPubkey) -> (Vec<u8>, SealInfo) {
        let mut sealed = Vec::new();
        let info = seal_v2(pk, Cursor::new(plain), &mut sealed).unwrap();
        (sealed, info)
    }

    // 5. seal→open 往返：空 / 恰好 4MiB / >8MiB（跨多段），并核对总长不变量（§3.2 长度不变量测试）
    #[test]
    fn v2_roundtrip_and_length_invariant() {
        let sk = keypair();
        let pk = sk.public();
        for len in [0usize, SEG, SEG * 2 + 1234] {
            let plain: Vec<u8> = (0..len as u32).map(|i| (i % 251) as u8).collect();
            let (sealed, info) = seal(&plain, &pk);
            let segs = len.div_ceil(SEG) as u64;
            assert_eq!(
                info.total_bytes as usize,
                HDR + len + (segs as usize) * (NONCE_LEN + TAG_LEN),
                "v2 长度不变量: 1137 + n + ceil(n/4MiB)*28"
            );
            assert_eq!(info.segments, segs);
            assert_eq!(&sealed[1..17], &info.envelope_id, "SealInfo.id 与头一致");
            assert_eq!(sealed[0], V2_VER);
            let mut out = Vec::new();
            let m = open_v2(&sk, Cursor::new(sealed.as_slice()), &mut out).unwrap();
            assert_eq!(m as usize, len);
            assert_eq!(out, plain);
        }
    }

    // 恰好 2×SEG（末段为满段）——is_final 必须由前瞻/探针判定而非「短段即末段」
    #[test]
    fn v2_full_multiple_roundtrip() {
        let sk = keypair();
        let plain = vec![0xABu8; SEG * 2];
        let (sealed, info) = seal(&plain, &sk.public());
        assert_eq!(info.segments, 2);
        assert_eq!(sealed.len(), HDR + SEG * 2 + 2 * (NONCE_LEN + TAG_LEN));
        let mut out = Vec::new();
        assert_eq!(
            open_v2(&sk, Cursor::new(sealed.as_slice()), &mut out).unwrap() as usize,
            SEG * 2
        );
        assert_eq!(out, plain);
    }

    // 6. 篡改：头密文区 / 段密文区 → 报错不 panic
    #[test]
    fn v2_tamper_rejected() {
        let sk = keypair();
        let plain = vec![7u8; SEG + 100];
        let (sealed, _) = seal(&plain, &sk.public());

        let mut t = sealed.clone();
        t[HDR + NONCE_LEN + 10] ^= 1; // 第一段密文区
        let mut out = Vec::new();
        assert!(open_v2(&sk, Cursor::new(t.as_slice()), &mut out).is_err());
        assert!(out.is_empty(), "首段失败无已写出内容");

        let mut t2 = sealed;
        t2[100] ^= 1; // 头 ml_kem_ct 区 ⇒ 解出错误 k ⇒ 段认证失败
        let mut out2 = Vec::new();
        assert!(open_v2(&sk, Cursor::new(t2.as_slice()), &mut out2).is_err());
    }

    // 版本字节分派：ver=1 / ver=3 的头 → 拒（§3.2 接缝：ver 字节分派 v1/v2）
    #[test]
    fn v2_version_dispatch() {
        let sk = keypair();
        let (mut sealed, _) = seal(b"x", &sk.public());
        sealed[0] = 1;
        let mut out = Vec::new();
        let err = open_v2(&sk, Cursor::new(sealed.as_slice()), &mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        sealed[0] = 3;
        assert!(open_v2(&sk, Cursor::new(sealed.as_slice()), &mut out).is_err());
        // 头截断
        let (s2, _) = seal(b"x", &sk.public());
        assert!(open_v2(&sk, Cursor::new(&s2[..1136]), &mut out).is_err());
    }

    // P0-3 守门用例：段重排必须失败（seg_idx 绑 AAD）
    #[test]
    fn v2_segment_reorder_rejected() {
        let sk = keypair();
        let plain: Vec<u8> = (0..(SEG as u32 * 3)).map(|i| (i % 251) as u8).collect(); // 3 段全满
        let (sealed, info) = seal(&plain, &sk.public());
        assert_eq!(info.segments, 3);
        let blk = SEG + NONCE_LEN + TAG_LEN; // 每段线上块长（满段）
                                             // 交换段 0 与段 1
        let mut t = sealed.clone();
        let (a, b) = (HDR..HDR + blk, HDR + blk..HDR + 2 * blk);
        let sa: Vec<u8> = sealed[a.clone()].to_vec();
        let sb: Vec<u8> = sealed[b.clone()].to_vec();
        t[a].copy_from_slice(&sb);
        t[b].copy_from_slice(&sa);
        let mut out = Vec::new();
        assert!(
            open_v2(&sk, Cursor::new(t.as_slice()), &mut out).is_err(),
            "段重排必须被 AAD(seg_idx) 拒绝"
        );
    }

    // P0-3 守门用例：删尾必须在解密侧失败（is_final 绑 AAD）
    #[test]
    fn v2_truncation_rejected() {
        let sk = keypair();
        let plain = vec![5u8; SEG * 2 + 1234]; // 3 段：2 满 + 1 短
        let (sealed, info) = seal(&plain, &sk.public());
        assert_eq!(info.segments, 3);
        // 在第 2 段边界截断（丢掉末段）：末段位标记不匹配 ⇒ 拒
        let cut = HDR + 2 * (SEG + NONCE_LEN + TAG_LEN);
        let mut out = Vec::new();
        assert!(
            open_v2(&sk, Cursor::new(&sealed[..cut]), &mut out).is_err(),
            "删尾必须被 AAD(is_final) 拒绝"
        );
        // 顺带：非段边界截断（nonce 读半截）也必须报错
        assert!(open_v2(&sk, Cursor::new(&sealed[..cut + 5]), &mut out).is_err());
    }

    // P0-3 守门用例：跨信封拼接必须失败（envelope_id 绑 AAD）——同收件人两个信封互拼段
    #[test]
    fn v2_splice_rejected() {
        let sk = keypair();
        let (env_a, info_a) = seal(&vec![1u8; SEG], &sk.public());
        let (env_b, _) = seal(&vec![2u8; SEG], &sk.public());
        assert_ne!(
            info_a.envelope_id,
            {
                let mut b = [0u8; 16];
                b.copy_from_slice(&env_b[1..17]);
                b
            },
            "两信封 id 必不同"
        );
        let blk = SEG + NONCE_LEN + TAG_LEN;
        // 用 B 的段替换 A 的段（同收件人、同 seg_idx、同 is_final——只有 id 不同）
        let mut t = env_a.clone();
        t[HDR..HDR + blk].copy_from_slice(&env_b[HDR..HDR + blk]);
        let mut out = Vec::new();
        assert!(
            open_v2(&sk, Cursor::new(t.as_slice()), &mut out).is_err(),
            "跨信封拼接必须被 AAD(envelope_id) 拒绝"
        );
    }

    // 非收件人解不开：错误混合私钥 ⇒ 段认证失败
    #[test]
    fn v2_wrong_recipient_rejected() {
        let (sk, other) = (keypair(), keypair());
        let (sealed, _) = seal(b"secret-bytes", &sk.public());
        let mut out = Vec::new();
        assert!(open_v2(&other, Cursor::new(sealed.as_slice()), &mut out).is_err());
    }

    // 一次性语义：同明文两次封装 ⇒ 密文不同（新临时份额 + 随机 id/nonce）
    #[test]
    fn v2_freshness() {
        let sk = keypair();
        let (a, _) = seal(b"same-plaintext", &sk.public());
        let (b, _) = seal(b"same-plaintext", &sk.public());
        assert_ne!(a, b);
    }
}

// ———— v1 写入侧（`legacy`；seal_v1_legacy / PlatformKeys）————
#[cfg(all(test, feature = "legacy"))]
mod v1_tests {
    use super::*;
    use std::io::Cursor;

    fn platform() -> &'static PlatformKeys {
        static K: std::sync::OnceLock<PlatformKeys> = std::sync::OnceLock::new();
        K.get_or_init(PlatformKeys::generate)
    }

    // seal_v1_legacy → open_v1_legacy 往返：空 / 恰好 4MiB / >8MiB（跨多段），并核对封装总长
    // （长度不变量：384 + n + ceil(n/4MiB)×28；showroom lib.rs:578 测试思想平移）
    #[test]
    fn v1_seal_open_roundtrip_and_length_invariant() {
        let p = platform();
        for len in [0usize, SEG, SEG * 2 + 1234] {
            let plain: Vec<u8> = (0..len as u32).map(|i| (i % 251) as u8).collect();
            let mut sealed = Vec::new();
            let n =
                seal_v1_legacy(&p.public(), Cursor::new(plain.as_slice()), &mut sealed).unwrap();
            let segs = len.div_ceil(SEG);
            assert_eq!(n as usize, WRAP_LEN + segs * (NONCE_LEN + TAG_LEN) + len);
            let mut out = Vec::new();
            let m = open_v1_legacy(p.private(), Cursor::new(sealed.as_slice()), &mut out).unwrap();
            assert_eq!(m as usize, len);
            assert_eq!(out, plain);
        }
    }

    // sealed 输入翻转一个字节（密文区 / 封装头区）→ 报错不 panic
    // （showroom lib.rs:587-604 tampered_envelope_rejected 平移）
    #[test]
    fn v1_tampered_envelope_rejected() {
        let p = platform();
        let plain = vec![7u8; SEG + 100];
        let mut sealed = Vec::new();
        seal_v1_legacy(&p.public(), Cursor::new(plain.as_slice()), &mut sealed).unwrap();

        let mut t = sealed.clone();
        t[WRAP_LEN + NONCE_LEN + 10] ^= 1; // 第一段密文区内
        let mut out = Vec::new();
        let e = open_v1_legacy(p.private(), Cursor::new(t.as_slice()), &mut out);
        assert!(e.is_err(), "flipped ciphertext byte must error");
        assert!(out.is_empty());

        let mut t2 = sealed;
        t2[10] ^= 1; // 384B 封装头内
        let mut out2 = Vec::new();
        assert!(open_v1_legacy(p.private(), Cursor::new(t2.as_slice()), &mut out2).is_err());
    }

    // PlatformKeys::save_pem/load_pem/public_pem 往返（unix 文件接缝）
    #[cfg(unix)]
    #[test]
    fn v1_platform_pem_roundtrip() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("flock-v1-pem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let priv_path = platform().save_pem(&dir).unwrap();
        assert_eq!(priv_path, dir.join("platform_rsa"));
        assert!(dir.join("platform_rsa.pub").exists());
        assert_eq!(
            std::fs::metadata(&priv_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let loaded = PlatformKeys::load_pem(&dir).unwrap();
        assert_eq!(loaded.public_pem(), platform().public_pem());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
