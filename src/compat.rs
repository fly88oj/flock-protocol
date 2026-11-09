//! showroom 兼容工具面（docs/design.md §1.3.2「工具」清单）。
//!
//! showroom 迁移为对本 crate 的薄再导出时，以下原 showroom-common pub 项原样保留
//! （签名逐字节不变，showroom-analysis §2）：
//! - [`Result`]：`Result<T, Box<dyn Error>>` 别名（密钥文件读写/解析类操作统一错误）；
//! - [`write_private`]：0600 落盘（覆盖旧文件偏宽权限），父目录惰性创建——unix 平台专属
//!   （wasm32 无文件系统语义；Windows 原生目标无 POSIX 权限位，不提供）；
//! - [`names`]：project / 辅助名 / docker tag 的名字校验（showroom SPEC §4 + §11 v1.4）。
//!
//! 版本纪律（§1.2）：本模块是协议库兼容面的一部分，实现单一来源——showroom-common
//! 再导出，不再自带副本。

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::path::Path;

/// showroom 兼容错误别名：密钥文件读写/解析类操作的统一错误
/// （seal/open 另用 `std::io::Result`，verify 用 `AuthError`）。
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// 0600 落盘（覆盖旧文件偏宽权限），父目录惰性创建。凭据/密钥类文件统一走这里。
///
/// 平台边界：unix 专属（POSIX 权限位）；wasm32 无文件系统语义，Windows 原生无 0600 语义。
#[cfg(unix)]
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    // 覆盖已存在文件可能偏宽的旧权限
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

// ———— 名字校验（showroom SPEC §4 + §11 v1.4：project 正则放宽、随机项目名；辅助名沿用旧正则）————

pub mod names {
    /// project 正则（§11 放宽）：`^[a-zA-Z0-9][a-zA-Z0-9-]{0,30}$`（总长 1..=31，ASCII，
    /// 手写避免 regex 依赖）。大写放开提升随机名空间（62^8）与字典遍历门槛。
    pub fn valid_project(s: &str) -> bool {
        let b = s.as_bytes();
        !b.is_empty()
            && b.len() <= 31
            && b[0].is_ascii_alphanumeric()
            && b.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-')
    }

    /// 辅助名字（user 等）沿用旧正则：`^[a-z0-9][a-z0-9-]{0,30}$`。
    /// user 进 registry 镜像路径与 htpasswd，保持小写（docker 仓库名禁大写）。
    pub fn valid_aux(s: &str) -> bool {
        let b = s.as_bytes();
        !b.is_empty()
            && b.len() <= 31
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter()
                .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    }

    /// docker tag 规则：首字符 [A-Za-z0-9_]，其余 [A-Za-z0-9_.-]，总长 ≤128。
    pub fn valid_tag(s: &str) -> bool {
        let b = s.as_bytes();
        !b.is_empty()
            && b.len() <= 128
            && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
            && b.iter()
                .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
    }

    pub const RESERVED: [&str; 4] = ["v2", "_api", "_bootstrap", "_console"];

    /// 辅助名（user 等）仅正则（保留名不约束）。
    pub fn check_aux(s: &str) -> Result<(), String> {
        if valid_aux(s) {
            Ok(())
        } else {
            Err(format!(
                "非法名字 '{s}'：须匹配 ^[a-z0-9][a-z0-9-]{{0,30}}$"
            ))
        }
    }

    /// project = §11 放宽正则 + 保留名。
    pub fn check_project(s: &str) -> Result<(), String> {
        if !valid_project(s) {
            return Err(format!(
                "非法 project '{s}'：须匹配 ^[a-zA-Z0-9][a-zA-Z0-9-]{{0,30}}$"
            ));
        }
        if RESERVED.contains(&s) {
            return Err(format!("project '{s}' 是保留名"));
        }
        Ok(())
    }

    /// 随机项目名（§11 发布入口默认预填）：`[a-zA-Z0-9]{8}`。
    pub fn random_project() -> String {
        use rand::distr::Alphanumeric;
        use rand::Rng;
        rand::rng()
            .sample_iter(Alphanumeric)
            .take(8)
            .map(char::from)
            .collect()
    }

    pub fn check_tag(s: &str) -> Result<(), String> {
        if valid_tag(s) {
            Ok(())
        } else {
            Err(format!(
                "非法 tag '{s}'：首字符字母/数字/_，仅 [A-Za-z0-9_.-]，≤128 字符"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 名字规则（SPEC §4 + §11 v1.4，showroom lib.rs tests 平移）：project 放宽正则
    /// （大写/连字符）+ 保留名；辅助名（user 等）沿用旧小写正则。tag 规则不变。
    #[test]
    fn names_project_regex_relaxed_and_reserved() {
        assert!(names::check_project("demo").is_ok());
        assert!(names::check_project("Demo42").is_ok(), "§11 放宽：大写合法");
        assert!(names::check_project("A-b-9").is_ok());
        assert!(names::check_project("0").is_ok());
        assert!(names::check_project(&"a".repeat(31)).is_ok());
        for r in names::RESERVED {
            assert!(names::check_project(r).is_err(), "project 保留名应拒: {r}");
        }
        for bad in [
            "",
            "-a",
            "a_b",
            "a b",
            "a.b",
            "a/b",
            "中文",
            &_c(32),
            "_x",
            "-demo",
        ] {
            assert!(names::check_project(bad).is_err(), "project 应拒: {bad}");
        }
        // 辅助名：旧小写正则（user 进 registry 路径，保持小写约束）
        assert!(names::check_aux("alice-2").is_ok());
        assert!(names::check_aux("pr42").is_ok());
        assert!(names::check_aux("v2").is_ok(), "辅助名不受保留名约束");
        for bad in ["", "-a", "Aa", "a_", "a b", "a.b", "a/b", "中文", &_c(32)] {
            assert!(names::check_aux(bad).is_err(), "辅助名应拒: {bad}");
        }
        for t in ["v1", "1.0.0", "latest", "a_b.c-d", "0", &"a".repeat(128)] {
            assert!(names::check_tag(t).is_ok(), "tag 应合法: {t}");
        }
        for t in ["", ".x", "-x", "a b", "a/b", "中", &"a".repeat(129)] {
            assert!(names::check_tag(t).is_err(), "tag 应拒: {t}");
        }
    }

    fn _c(n: usize) -> String {
        "a".repeat(n)
    }

    // 随机项目名（§11 发布入口默认预填）：恒 8 位、字符集 [A-Za-z0-9]、样本间有差异
    #[test]
    fn random_project_shape() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let p = names::random_project();
            assert_eq!(p.len(), 8, "长度恒 8");
            assert!(
                p.bytes().all(|b| b.is_ascii_alphanumeric()),
                "字符集 [a-zA-Z0-9]: {p}"
            );
            assert!(
                names::check_project(&p).is_ok(),
                "随机名必须通过 project 校验"
            );
            seen.insert(p);
        }
        // 62^8 空间，64 个样本必有相异对（碰撞概率 ~1e-11）
        assert!(
            seen.len() > 1,
            "随机性：64 个样本出现 {}/64 个不同名字",
            seen.len()
        );
    }

    // write_private：0600、内容、覆盖偏宽权限后收紧（unix 平台）
    #[cfg(unix)]
    #[test]
    fn write_private_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("flock-compat-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("priv.bin");
        write_private(&p, b"secret").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"secret");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&p, b"again").unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // 父目录惰性创建
        let nested = dir.join("a/b/c.txt");
        write_private(&nested, b"x").unwrap();
        assert_eq!(fs::read(&nested).unwrap(), b"x");
        let _ = fs::remove_dir_all(&dir);
    }
}
