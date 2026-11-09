//! SR-SIG1 请求签名 + 密钥档案（docs/design.md §1.3.2 兼容面 / §1.3.3g / §3.3，P2-12）。
//!
//! 兼容契约（showroom-common lib.rs:222-340 逐字节不变，§1.3.2）：
//! - canonical 七字段：`SR-SIG1\n<user>\n<ts>\n<nonce>\n<METHOD>\n<path_with_query>\n<sha256_hex(body)>`；
//! - 线上格式：`SR-SIG1 <user>:<ts>:<nonce>:<sig_b64url>`（sig 为 base64url 无 padding）；
//! - [`SIG_WINDOW_SECS`] = 300（showroom-common lib.rs:48 原值）。
//!
//! 本模块与 showroom 3.0 生态的 Ed25519 签名逐字节互通（RFC 8032 确定性签名），
//! 依赖代际升级 ed25519-dalek 2.2 → 3.0（§1.3.2，P1-6）。
//!
//! 升级档位（§1.3.3g）：[`KeyProfile`] 按 kid 分派验签算法——Ed25519 主档 +
//! `pq-sign` feature 下的 ML-DSA-65 槽位（占位，ml-dsa 0.1.1 未审计，crypto-2026 §5）。

use core::fmt;

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::engine::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::KEY_LEN;

/// SR-SIG1 时间戳容差：|now − ts| ≤ 300s（§1.3.2，showroom-common lib.rs:48 原值保留）。
pub const SIG_WINDOW_SECS: i64 = 300;

/// `sha256_hex`：32B 摘要 → 64 小写 hex。
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// 流式 sha256（64KiB 缓冲）：大文件先哈希再签名（`sign_prehashed`），
/// 避免整文件进内存（showroom-common lib.rs:62-72 同语义）。
pub fn sha256_hex_stream(mut r: impl std::io::Read) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Ok(hex::encode(h.finalize()));
        }
        h.update(&buf[..n]);
    }
}

/// SR-SIG1 nonce：16 随机字节 → 32 hex（P2-13：以实现为准 16B/32hex）。
pub fn nonce_hex() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b); // rand 0.9 ThreadRng（不可失败 RngCore）
    hex::encode(b)
}

// ———— SR-SIG1 五函数（§1.3.2 兼容面，签名不变）————

/// Ed25519 用户签名密钥（showroom `UserKey` 对应物）。
pub struct UserKey(SigningKey);

impl UserKey {
    /// 随机生成（rand 0.9 ThreadRng 种子）。
    pub fn generate() -> Self {
        let mut seed = [0u8; KEY_LEN];
        rand::rng().fill_bytes(&mut seed);
        UserKey(SigningKey::from_bytes(&seed))
    }

    /// 由裸 32B seed 构造（showroom `id_ed25519` 文件格式；文件读写由调用方负责，
    /// 0600 落盘工具属原生平台层，后续批次随兼容面补齐）。
    pub fn from_seed(seed: &[u8; KEY_LEN]) -> Self {
        UserKey(SigningKey::from_bytes(seed))
    }

    /// 裸 32B seed。
    pub fn to_seed(&self) -> [u8; KEY_LEN] {
        self.0.to_bytes()
    }

    /// 读取裸 32B seed 文件（[`UserKey::save_seed`] 写出的格式；showroom `id_ed25519`）。
    pub fn from_seed_file(path: &std::path::Path) -> crate::compat::Result<Self> {
        let seed = std::fs::read(path)?;
        let seed: [u8; KEY_LEN] = seed.as_slice().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "seed file must be exactly 32 bytes",
            )
        })?;
        Ok(UserKey(SigningKey::from_bytes(&seed)))
    }

    /// 写裸 32B seed（0600；unix 平台专属——wasm32 无文件系统语义）。
    #[cfg(unix)]
    pub fn save_seed(&self, path: &std::path::Path) -> crate::compat::Result<()> {
        crate::compat::write_private(path, &self.0.to_bytes())?;
        Ok(())
    }

    /// `"ed25519:<base64(pubkey)>"`（base64 无 padding；showroom 逐字节同格式）。
    pub fn pub_string(&self) -> String {
        format!(
            "ed25519:{}",
            STANDARD_NO_PAD.encode(self.0.verifying_key().as_bytes())
        )
    }

    /// 解析 `"ed25519:<base64(pubkey)>"`（showroom 同格式）。
    /// 错误类型 = `Box<dyn Error>`（§1.3.2 兼容面签名不变：showroom 原返回
    /// `Result<VerifyingKey>` 即 `Result<_, Box<dyn Error>>`）。
    pub fn from_pub_string(s: &str) -> crate::compat::Result<VerifyingKey> {
        let raw = STANDARD_NO_PAD.decode(
            s.strip_prefix("ed25519:")
                .ok_or("missing ed25519: prefix")?,
        )?;
        let raw: [u8; KEY_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| "public key must be exactly 32 bytes")?;
        Ok(VerifyingKey::from_bytes(&raw)?)
    }
}

impl fmt::Debug for UserKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserKey(ed25519:…)") // 不泄露密钥材料
    }
}

/// canonical 七字段：`SR-SIG1\n<user>\n<ts>\n<nonce>\n<METHOD>\n<path_with_query>\n<sha256_hex(body)>`
/// （showroom-common lib.rs:222-231 逐字节不变）。
#[allow(clippy::too_many_arguments)]
pub fn build_canonical(
    user: &str,
    ts: i64,
    nonce: &str,
    method: &str,
    path_with_query: &str,
    body_sha256_hex: &str,
) -> String {
    format!("SR-SIG1\n{user}\n{ts}\n{nonce}\n{method}\n{path_with_query}\n{body_sha256_hex}")
}

/// 生成完整 Authorization 值 `SR-SIG1 <user>:<ts>:<nonce>:<sig_b64url>`
/// （sig 为 base64url 无 padding；nonce 由调用方生成——`nonce_hex`；method 传大写）。
pub fn sign(
    user: &str,
    key: &UserKey,
    method: &str,
    path_with_query: &str,
    body: &[u8],
    now_unix: i64,
    nonce: &str,
) -> String {
    sign_prehashed(
        user,
        key,
        method,
        path_with_query,
        &sha256_hex(body),
        now_unix,
        nonce,
    )
}

/// 预哈希签名：body 哈希由调用方算好（`sha256_hex` / `sha256_hex_stream`），与 [`sign`] 同格式
/// ——大文件流式上传先哈希再签，避免整文件进内存。
pub fn sign_prehashed(
    user: &str,
    key: &UserKey,
    method: &str,
    path_with_query: &str,
    body_sha256_hex: &str,
    ts: i64,
    nonce: &str,
) -> String {
    let canonical = build_canonical(user, ts, nonce, method, path_with_query, body_sha256_hex);
    let sig = key.0.sign(canonical.as_bytes()).to_bytes();
    format!(
        "SR-SIG1 {user}:{ts}:{nonce}:{}",
        URL_SAFE_NO_PAD.encode(sig)
    )
}

/// 验签成功产物：命中身份与时间戳/nonce（nonce 查重由调用方按 `Verified.nonce` 自行完成，
/// §1.3.2「刻意留给调用方」边界）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub user: String,
    pub ts: i64,
    pub nonce: String,
}

/// SR-SIG1 验签错误（showroom 三态原样保留：Format/Stale/BadSignature）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    Format,
    Stale,
    BadSignature,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AuthError::Format => "E_AUTH: malformed SR-SIG1 header",
            AuthError::Stale => "E_AUTH: timestamp outside ±300s window",
            AuthError::BadSignature => "E_AUTH: signature verification failed",
        })
    }
}

impl std::error::Error for AuthError {}

/// 验证 SR-SIG1：格式解析 → ±300s 时间窗 → 依次尝试登记公钥（user 可多把，任一命中即过）。
pub fn verify(
    auth_value: &str,
    pubkeys: &[VerifyingKey],
    method: &str,
    path_with_query: &str,
    body: &[u8],
    now_unix: i64,
) -> Result<Verified, AuthError> {
    verify_with_hash(
        auth_value,
        pubkeys,
        method,
        path_with_query,
        &sha256_hex(body),
        now_unix,
    )
}

/// 预计算哈希版验签：与 [`verify`] 完全同语义（格式 → ±300s → 任一登记公钥命中），
/// body 只认 `sha256_hex`——import 等只落盘+哈希、不留 body 本体的调用方复用。
pub fn verify_with_hash(
    auth_value: &str,
    pubkeys: &[VerifyingKey],
    method: &str,
    path_q: &str,
    body_sha_hex: &str,
    now: i64,
) -> Result<Verified, AuthError> {
    let rest = auth_value
        .strip_prefix("SR-SIG1 ")
        .ok_or(AuthError::Format)?;
    let mut parts = rest.splitn(4, ':');
    let (user, ts, nonce, sig_b64) = match (parts.next(), parts.next(), parts.next(), parts.next())
    {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        _ => return Err(AuthError::Format),
    };
    if user.is_empty() || nonce.is_empty() {
        return Err(AuthError::Format);
    }
    let ts: i64 = ts.parse().map_err(|_| AuthError::Format)?;
    let raw = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| AuthError::Format)?;
    let sig_arr: [u8; 64] = raw.try_into().map_err(|_| AuthError::Format)?;
    let sig = Signature::from_bytes(&sig_arr);
    if (now - ts).abs() > SIG_WINDOW_SECS {
        return Err(AuthError::Stale);
    }
    let canonical = build_canonical(user, ts, nonce, method, path_q, body_sha_hex);
    for vk in pubkeys {
        if vk.verify(canonical.as_bytes(), &sig).is_ok() {
            return Ok(Verified {
                user: user.to_owned(),
                ts,
                nonce: nonce.to_owned(),
            });
        }
    }
    Err(AuthError::BadSignature)
}

// ———— KeyProfile：kid → 算法分派（§1.3.3g / §3.3，P2-12）————

/// kid 派生：`sha256(ed25519 公钥 32B)` 前 8 hex（showroomctl state.rs:695-697 同源约定，
/// 与 `tokens/<user>/<kid>.pub` 文件名一致）。
pub fn kid_of(vk: &VerifyingKey) -> String {
    sha256_hex(&vk.to_bytes())[..8].to_string()
}

/// 单把档案钥匙：算法分派槽位。扩展新算法 = 加变体，调用方零改动（§3.3 接缝）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileKey {
    /// Ed25519 主档（ed25519-dalek 3.0.0）。
    Ed25519(VerifyingKey),
    /// 占位（未实现）：ML-DSA-65 并行公钥档。`pq-sign` feature 专属；ml-dsa 0.1.1
    /// 未审计（crypto-2026 §5），本批次仅预留槽位，接入时填充真实验签。
    #[cfg(feature = "pq-sign")]
    MlDsa65Placeholder,
}

impl ProfileKey {
    /// 用该钥匙验签（原语层：消息+签名，不含 SR-SIG1 头解析）。
    fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> Result<(), DispatchError> {
        match self {
            ProfileKey::Ed25519(vk) => {
                let sig: [u8; 64] = sig.try_into().map_err(|_| DispatchError::BadSignature)?;
                vk.verify(msg, &Signature::from_bytes(&sig))
                    .map_err(|_| DispatchError::BadSignature)
            }
            #[cfg(feature = "pq-sign")]
            ProfileKey::MlDsa65Placeholder => Err(DispatchError::UnsupportedAlgorithm),
        }
    }
}

/// kid 分派失败三态：kid 未登记 / 验签失败 / 算法档未实现（占位槽位）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchError {
    UnknownKid,
    BadSignature,
    /// 占位算法档（如 `pq-sign` 未接入的 ML-DSA-65）。
    UnsupportedAlgorithm,
}

impl fmt::Display for DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DispatchError::UnknownKid => "sig: kid not registered in profile",
            DispatchError::BadSignature => "E_AUTH: signature verification failed",
            DispatchError::UnsupportedAlgorithm => {
                "sig: algorithm slot not implemented (placeholder)"
            }
        })
    }
}

impl std::error::Error for DispatchError {}

/// 密钥档案：kid → [`ProfileKey`] 分派表（Ed25519 主档；`pq-sign` 下 ML-DSA-65 位）。
///
/// 调用方约定（§1.3.2）：按 user 名下全部公钥任一命中即过——那是 [`verify`] 的语义；
/// `KeyProfile` 用于 kid 已知（如 `tokens/<user>/<kid>.pub` 定位）的单把复验路径。
#[derive(Debug, Clone, Default)]
pub struct KeyProfile {
    keys: Vec<(String, ProfileKey)>,
}

impl KeyProfile {
    /// 空档案。
    pub fn new() -> Self {
        KeyProfile { keys: Vec::new() }
    }

    /// 登记一把 Ed25519 公钥，返回其 kid（幂等：同钥重复登记不重复占位）。
    pub fn insert_ed25519(&mut self, vk: VerifyingKey) -> String {
        let kid = kid_of(&vk);
        if !self.keys.iter().any(|(k, _)| *k == kid) {
            self.keys.push((kid.clone(), ProfileKey::Ed25519(vk)));
        }
        kid
    }

    /// 按 kid 取钥匙。
    pub fn get(&self, kid: &str) -> Option<&ProfileKey> {
        self.keys.iter().find(|(k, _)| k == kid).map(|(_, v)| v)
    }

    /// kid 分派验签：按 kid 定位钥匙 → 按算法档验签（raw 消息/签名，非 SR-SIG1 头）。
    pub fn verify_dispatch(&self, kid: &str, msg: &[u8], sig: &[u8]) -> Result<(), DispatchError> {
        let key = self.get(kid).ok_or(DispatchError::UnknownKid)?;
        key.verify_raw(msg, sig)
    }

    /// 全部 kid（登记序）。
    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|(k, _)| k.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1. sign→verify 往返（body 非空 / 空）
    #[test]
    fn sign_verify_roundtrip() {
        let k = UserKey::generate();
        let vk = [k.0.verifying_key()];
        for body in [b"{\"project\":\"demo\"}".as_slice(), b""] {
            let auth = sign(
                "alice",
                &k,
                "POST",
                "/_api/publish",
                body,
                1_000_000,
                "0123456789abcdef",
            );
            let v = verify(&auth, &vk, "POST", "/_api/publish", body, 1_000_000).unwrap();
            assert_eq!(
                (v.user.as_str(), v.ts, v.nonce.as_str()),
                ("alice", 1_000_000, "0123456789abcdef")
            );
        }
    }

    // 2. 篡改 body 一个字节 → BadSignature
    #[test]
    fn tampered_body_rejected() {
        let k = UserKey::generate();
        let auth = sign(
            "alice",
            &k,
            "POST",
            "/_api/publish",
            b"body-0",
            1_000_000,
            "0123456789abcdef",
        );
        assert_eq!(
            verify(
                &auth,
                &[k.0.verifying_key()],
                "POST",
                "/_api/publish",
                b"body-1",
                1_000_000
            ),
            Err(AuthError::BadSignature)
        );
    }

    // 3. ts 超窗（now±301）→ Stale；±300 边界通过
    #[test]
    fn stale_ts_rejected() {
        let k = UserKey::generate();
        let vk = [k.0.verifying_key()];
        let auth = sign(
            "alice",
            &k,
            "POST",
            "/_api/publish",
            b"",
            1_000_000,
            "0123456789abcdef",
        );
        for now in [1_000_000 + 301, 1_000_000 - 301] {
            assert_eq!(
                verify(&auth, &vk, "POST", "/_api/publish", b"", now),
                Err(AuthError::Stale)
            );
        }
        for now in [1_000_000 + 300, 1_000_000 - 300] {
            assert!(verify(&auth, &vk, "POST", "/_api/publish", b"", now).is_ok());
        }
    }

    // 4. 错误公钥 → BadSignature；多把公钥时第二把命中可通过
    #[test]
    fn wrong_key_and_multi_key() {
        let k = UserKey::generate();
        let auth = sign(
            "alice",
            &k,
            "GET",
            "/_api/logs?project=demo&tail=100",
            b"",
            5,
            "aabbccddeeff0011",
        );
        let wrong = UserKey::generate();
        assert_eq!(
            verify(
                &auth,
                &[wrong.0.verifying_key()],
                "GET",
                "/_api/logs?project=demo&tail=100",
                b"",
                5
            ),
            Err(AuthError::BadSignature)
        );
        verify(
            &auth,
            &[wrong.0.verifying_key(), k.0.verifying_key()],
            "GET",
            "/_api/logs?project=demo&tail=100",
            b"",
            5,
        )
        .unwrap();
    }

    // 5. 预哈希签名 / 流式哈希：与 sign/verify 同语义往返 + 已知 sha256 向量
    #[test]
    fn prehashed_sign_verify_and_stream_hash() {
        let hash = sha256_hex_stream(std::io::Cursor::new(b"stream-me")).unwrap();
        assert_eq!(hash, sha256_hex(b"stream-me"));
        assert_eq!(
            sha256_hex_stream(std::io::Cursor::new(b"")).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let k = UserKey::generate();
        let pq = "/_api/import?project=demo&tag=v1";
        let auth = sign_prehashed("alice", &k, "POST", pq, &hash, 7, "aabb0011ccdd2233");
        let vk = [k.0.verifying_key()];
        let v = verify_with_hash(&auth, &vk, "POST", pq, &hash, 7).unwrap();
        assert_eq!(
            (v.user.as_str(), v.nonce.as_str()),
            ("alice", "aabb0011ccdd2233")
        );
        assert_eq!(
            verify_with_hash(&auth, &vk, "POST", pq, &sha256_hex(b"other"), 7),
            Err(AuthError::BadSignature)
        );
    }

    // 6. canonical 七字段与线上格式的逐字节形状（§1.3.2 兼容契约）
    #[test]
    fn canonical_and_wire_format_exact() {
        let c = build_canonical("alice", 42, "deadbeef", "GET", "/x?y=1", &sha256_hex(b"z"));
        assert_eq!(
            c,
            format!(
                "SR-SIG1\nalice\n42\ndeadbeef\nGET\n/x?y=1\n{}",
                sha256_hex(b"z")
            )
        );
        let k = UserKey::from_seed(&[7u8; 32]);
        let auth = sign_prehashed(
            "alice",
            &k,
            "GET",
            "/x?y=1",
            &sha256_hex(b"z"),
            42,
            "deadbeef",
        );
        assert!(auth.starts_with("SR-SIG1 alice:42:deadbeef:"));
        let sig_b64 = auth.rsplit(':').next().unwrap();
        assert_eq!(sig_b64.len(), 86, "64B 签名 base64url 无 padding = 86 字符");
        assert!(
            !sig_b64.contains(['+', '/', '=']),
            "base64url 无 padding 字符集"
        );
    }

    // 7. UserKey seed / pub_string 往返
    #[test]
    fn user_key_seed_and_pub_string() {
        let k = UserKey::from_seed(&[9u8; 32]);
        assert_eq!(k.to_seed(), [9u8; 32]);
        let vk = UserKey::from_pub_string(&k.pub_string()).unwrap();
        assert_eq!(vk.to_bytes(), *k.0.verifying_key().as_bytes());
        assert!(UserKey::from_pub_string("no-prefix").is_err());
        assert!(UserKey::from_pub_string("ed25519:AAAA").is_err());
    }

    // 8. kid 派生：sha256(pub)[..8]，确定性、异钥相异
    #[test]
    fn kid_derivation() {
        let k = UserKey::generate();
        let vk = k.0.verifying_key();
        let kid = kid_of(&vk);
        assert_eq!(kid.len(), 8);
        assert!(kid.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(kid, sha256_hex(&vk.to_bytes())[..8]);
        assert_ne!(kid, kid_of(&UserKey::generate().0.verifying_key()));
    }

    // 9. KeyProfile：登记→分派验签；未知 kid 拒；异 kid 钥匙拒
    #[test]
    fn key_profile_dispatch() {
        let k = UserKey::generate();
        let msg = b"canonical-bytes";
        let sig = k.0.sign(msg).to_bytes();

        let mut p = KeyProfile::new();
        let kid = p.insert_ed25519(k.0.verifying_key());
        assert_eq!(
            p.get(&kid).cloned(),
            Some(ProfileKey::Ed25519(k.0.verifying_key()))
        );
        p.verify_dispatch(&kid, msg, &sig)
            .expect("登记钥匙验签通过");
        assert_eq!(
            p.verify_dispatch("00000000", msg, &sig),
            Err(DispatchError::UnknownKid)
        );

        // 异 kid：另一把钥匙的签名在原 kid 下必须失败
        let k2 = UserKey::generate();
        let sig2 = k2.0.sign(msg).to_bytes();
        assert_eq!(
            p.verify_dispatch(&kid, msg, &sig2),
            Err(DispatchError::BadSignature)
        );
        // 签名长度错 → BadSignature
        assert_eq!(
            p.verify_dispatch(&kid, msg, b"short"),
            Err(DispatchError::BadSignature)
        );

        // 登记第二把：kids 幂等
        let kid2 = p.insert_ed25519(k2.0.verifying_key());
        assert_ne!(kid, kid2);
        p.verify_dispatch(&kid2, msg, &sig2)
            .expect("第二把钥匙按自己的 kid 通过");
        p.insert_ed25519(k2.0.verifying_key());
        assert_eq!(p.kids().count(), 2, "同钥重复登记不重复占位");
    }

    // 10. 跨生态固定向量（showroom-common ed25519-dalek 2.2 生成，RFC 8032 确定性签名
    //     ⇒ 本 crate 3.0 下必须逐字节复现）：tests/sig_showroom_vector.rs 集成测试覆盖。

    // 11. seed 文件 save/from 往返 + 0600（unix 文件接缝；showroom lib.rs:607-619 平移）
    #[cfg(unix)]
    #[test]
    fn user_key_seed_file_roundtrip() {
        use std::os::unix::fs::PermissionsExt;

        let k = UserKey::generate();
        let dir = std::env::temp_dir().join(format!("flock-sig-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("id_ed25519");
        k.save_seed(&p).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let k2 = UserKey::from_seed_file(&p).unwrap();
        assert_eq!(k2.to_seed(), k.to_seed());
        assert_eq!(k2.pub_string(), k.pub_string());
        // 非 32B seed 文件 → Err
        std::fs::write(&p, b"short").unwrap();
        assert!(UserKey::from_seed_file(&p).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
