//! # flock-protocol
//!
//! flock 主仓与 showroom 共享的协议契约层（docs/design.md §1）。本批次（M1 session/mux）交付：
//!
//! - [`kem`]：X25519 + ML-KEM-768 混合 KEM（§1.3.3a / §3.1，P0-1、P0-7）；
//! - [`envelope`]：文件信封 v2（§1.3.3b / §3.2，P0-3；`legacy` feature 下 v1 只读兼容）；
//! - [`sig`]：SR-SIG1 兼容五函数 + `KeyProfile` kid 分派（§1.3.2 / §1.3.3g / §3.3，P2-12）；
//! - [`pake`]：OPAQUE（RFC 9807 / opaque-ke 4.0.1）+ rwd profile（§1.3.3h / §3.4，P2-11）；
//! - [`compress`]：压缩档位与帧格式（§1.3.3e / §3.7，P0-4/P1-7）；
//! - [`session`]：隧道会话——握手双形态（已钉扎 1-RTT Noise-IK 结构 / TOFU 首连 2-RTT）、
//!   记录层计数器 nonce AEAD、抗重放、双阈值 rekey、伪造断链（§1.3.3c / §3.5，P0-2/P1-8/P1-10）；
//! - [`mux`]：yamux 0.14.1 复用 + 显式 FIN + PacketChannel（§1.3.3d / §3.6，P1-9/VPN-14）；
//! - [`trust`]：首登信任锚——PinStore（集群根级钉扎）、ClusterDirectory（根签目录，端点与
//!   条目同签、dir_version 递增）、InviteFile v3（§1.3.3f / §3.8，P0-5）；
//! - [`roster`]：M7 名册与控制面共享契约（PeerInfo/PeerKind、票据线格式 TicketWire、
//!   CtrlRequest/CtrlResponse 消息与 key-bind canonical——自 flock-server/flock-sync
//!   上收，两端同类型无第二真相源，§7-M7.4/§7-M7.7）；
//! - [`compat`]：showroom 兼容工具面（§1.3.2「工具」清单——`Result` 别名 / `write_private`
//!   0600 落盘 / `names` 名字校验；showroom 迁移为薄再导出的接缝）。
//!
//! feature 矩阵（§1.3.1）：默认 = 全 VPN 档；`legacy` / `anchor` / `pq-sign` / `wasm` 默认关
//! （`anchor` / `pq-sign` / `wasm` 本批次仅占位，见各 feature 注释）。
//!
//! 依赖代际（§1.3.2，P1-6）：aes-gcm 0.11.1 / ed25519-dalek 3.0.0 / rand 0.9 新代码；
//! ml-kem 0.3.3 + x25519-dalek 3.0.0（§1.3.3a）；yamux 0.14.1（§1.3.3d）。
//!
//! 版本收口（§1.2）：本 crate 再导出其锁定的 `ed25519_dalek` / `x25519_dalek` / `ml_kem` /
//! `rand`（`legacy` 下另含 `rsa`），两项目不得另引版本——下游直接复用，避免类型不兼容。

// wasm32 getrandom 桥（src/wasm_bridge.rs）与 M8b wasm C-ABI 垫片
//（src/webauth_shim.rs）需裸指针（getrandom custom 后端/C-ABI 契约），其余目标
// 维持 forbid(unsafe_code)（showroom-common lib.rs:4-5 同款豁免；垫片的 native
// 单测面见该模块头注——`test` cfg 同豁免）。
#![cfg_attr(
    not(all(feature = "wasm", any(target_arch = "wasm32", test))),
    forbid(unsafe_code)
)]

pub mod compat;
pub mod compress;
pub mod envelope;
pub mod kem;
pub mod mux;
pub mod pake;
pub mod roster;
pub mod session;
pub mod sig;
pub mod trust;

/// wasm32 getrandom 自定义后端桥（`wasm` feature + wasm32 目标；§1.3.1）。
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub mod wasm_bridge;

/// M8b Web UI 的 wasm C-ABI 垫片（`wasm`+`anchor` feature；wasm32 目标，native
/// `test` cfg 亦编译——单测直调垫片跑通 OPAQUE 全程，§7-M8.6/§M8.9）。
#[cfg(all(
    feature = "wasm",
    feature = "anchor",
    any(target_arch = "wasm32", test)
))]
pub mod webauth_shim;

// getrandom 0.2（opaque-ke → rand_core 0.6 路径）的 custom 后端注册
// （showroom-common lib.rs:41-42 同法）。
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
getrandom02::register_custom_getrandom!(wasm_bridge::custom_getrandom_02);

// 兼容常量（§1.3.2 工具/常量面；showroom-common lib.rs:51-55 原值）
#[cfg(feature = "legacy")]
pub use envelope::WRAP_LEN;
pub use envelope::{KEY_LEN, NONCE_LEN, SEG, TAG_LEN};

// 兼容工具（§1.3.2；showroom-common lib.rs:57-79 同语义）
pub use sig::{nonce_hex, sha256_hex, sha256_hex_stream};

// SR-SIG1 时间窗（§1.3.2；showroom-common lib.rs:48 原值）
pub use sig::SIG_WINDOW_SECS;

#[cfg(feature = "legacy")]
pub use rsa;
/// 版本收口再导出（§1.2）。
pub use {aes_gcm, ed25519_dalek, ml_kem, opaque_ke, rand, x25519_dalek};
