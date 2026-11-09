//! showroom 3.0.0 固定向量互通（**M1 硬门槛**，§7-M1 / §3.4 / P1-6 / P0-1 兼容档）。
//!
//! 向量文件 [`tests/vectors/showroom-3.0.0.json`]（随库入库）：真实 showroom-common 3.0.0
//! 产物（Linux 容器一次性生成，依赖代际 opaque-ke 3.0.0 / rsa 0.9.10 / aes-gcm 0.10.3 /
//! ed25519-dalek 2.2.0 / rand 0.8.8）。
//!
//! **OPAQUE**（P1-6）：4.0.1 必须解开 3.0.0 注册记录完成登录——
//! `server_setup_migrate_v3`（dummy sk→pk 布局迁移，OPRF seed/KE sk 逐字节保留）+
//! `server_record_from_b64`（记录布局不变）+ 完整 ke1→ke2→ke3 流程；
//! 并断言 rwd(P2-11 profile 参数) 与 showroom 逐字节一致。
//!
//! sig/envelope v1 段与 [`tests/showroom_vectors.rs`] 的内联 fixture 测同一断言类
//! （3.0.0 样本验签 / seal 产物解封），已合并到该文件（ponytail 去重）；JSON 中的
//! sig/envelope_v1 字段保留作生成记录。

use flock_protocol::pake;
use rand::rngs::OsRng;

const VECTOR: &str = include_str!("vectors/showroom-3.0.0.json");

fn v() -> serde_json::Value {
    serde_json::from_str(VECTOR).expect("向量 JSON 解析")
}

/// P1-6 硬门槛：showroom 3.0.0 注册记录 + opaque.key 在 4.0.1 下完成完整登录。
#[test]
fn opaque_3_0_0_record_login_under_4_0_1() {
    let j = v();
    let (user, password) = (
        j["opaque"]["user"].as_str().unwrap(),
        j["opaque"]["password"].as_str().unwrap(),
    );
    let setup_b64 = j["opaque"]["server_setup_b64"].as_str().unwrap();
    let record_b64 = j["opaque"]["record_b64"].as_str().unwrap();
    let rwd_hex = j["opaque"]["rwd_hex"].as_str().unwrap();

    // rwd profile 参数与 showroom 逐字节一致（P2-11：Profile::Owasp19MiB 兼容默认）
    let r = pake::rwd(password, user, pake::Profile::Owasp19MiB).unwrap();
    assert_eq!(
        hex::encode(r),
        rwd_hex,
        "rwd(pw,user,Owasp19MiB) 必须与 showroom 3.0.0 一致"
    );

    // ServerSetup 3.0.0 → 4.0.1 迁移（dummy 段 sk→pk；OPRF seed/KE sk 保留）
    let setup =
        pake::server_setup_migrate_v3(setup_b64).expect("3.0.0 opaque.key 必须可迁移（P1-6）");

    // 3.0.0 注册记录直接读入（布局不变）
    let record = pake::server_record_from_b64(record_b64)
        .expect("3.0.0 pass.opaque 必须可被 4.0.1 反序列化（P1-6 硬门槛）");

    // 完整登录：ke1 → ke2（对 3.0.0 记录）→ ke3 → 服务端验证
    let mut rng = OsRng;
    let (lstate, ke1) = pake::login_start(&mut rng, password, user).unwrap();
    let (ke2, sstate) =
        pake::server_login_start(&mut rng, &setup, Some(&record), &ke1, user).unwrap();
    let ke3 = pake::login_finish(lstate, password, user, &ke2)
        .expect("4.0.1 客户端必须完成对 3.0.0 记录的登录（P1-6 硬门槛）");
    pake::server_login_finish(&sstate, &ke3).expect("ke3 必须通过 4.0.1 服务端验证");
}

/// 负向量：同一 3.0.0 记录 + 错密码 → 客户端本地 finish 失败（记录可解 ≠ 密码可猜）。
#[test]
fn opaque_3_0_0_record_wrong_password_rejected() {
    let j = v();
    let user = j["opaque"]["user"].as_str().unwrap();
    let setup =
        pake::server_setup_migrate_v3(j["opaque"]["server_setup_b64"].as_str().unwrap()).unwrap();
    let record = pake::server_record_from_b64(j["opaque"]["record_b64"].as_str().unwrap()).unwrap();
    let mut rng = OsRng;
    let (lstate, ke1) = pake::login_start(&mut rng, "wrong-password", user).unwrap();
    let (ke2, _s) = pake::server_login_start(&mut rng, &setup, Some(&record), &ke1, user).unwrap();
    assert!(pake::login_finish(lstate, "wrong-password", user, &ke2).is_err());
}
