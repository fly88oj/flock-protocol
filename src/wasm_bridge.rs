//! wasm32 getrandom 自定义后端桥（docs/design.md §1.3.1 `wasm` feature；
//! showroom `wasm_shim.rs` 同思路的库级适配，showroom-common/src/wasm_shim.rs:133-169 本次参照）。
//!
//! wasm32-unknown-unknown 无 OS 熵源，且 §8.3（showroom 约束）禁引 wasm-bindgen——
//! 两代 getrandom 都路由到本模块的同一熵池：
//! - getrandom 0.3（rand 0.9 代际）：经 `--cfg getrandom_backend="custom"`
//!   （workspace `.cargo/config.toml` 的 `[target.wasm32-unknown-unknown] rustflags`）
//!   回调导出符号 `__getrandom_v03_custom`（getrandom-0.3.4/src/backends/custom.rs 契约）；
//! - getrandom 0.2（rand_core 0.6 ← opaque-ke 路径）：`custom` feature +
//!   lib.rs 的 `register_custom_getrandom!`（showroom wasm_shim 同法）。
//!
//! 熵由宿主（JS `crypto.getRandomValues`）经 [`inject_entropy`] 注入，驱动全局 StdRng
//! （ChaCha12，CSPRNG）；**未注入熵则显式失败**（`Error::UNSUPPORTED`）——显式失败优于
//! 静默伪随机。可重复调用（重置）。
//!
//! 本模块含裸指针访问（getrandom 契约），是库内唯一 `unsafe`：lib.rs 的
//! `forbid(unsafe_code)` 对 `wasm` + `wasm32` 组合豁免。

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::sync::Mutex;

static GLOBAL_RNG: Mutex<Option<StdRng>> = Mutex::new(None);

/// 注入熵（宿主 JS：crypto.getRandomValues ≥32B；xor-rotate 折叠进 32B seed）。
/// 可重复调用（重置全局 RNG）。
pub fn inject_entropy(bytes: &[u8]) {
    let mut seed = [0u8; 32];
    for (i, b) in bytes.iter().enumerate() {
        // 位置相关旋转：超长输入的每个字节都影响 seed，避免同位置字节相消
        // （showroom wasm_shim sr_entropy 同算法）。
        seed[i % 32] ^= b.rotate_left(((i / 32) % 8) as u32);
    }
    *GLOBAL_RNG.lock().expect("wasm bridge rng lock") = Some(StdRng::from_seed(seed));
}

/// 共享填充：未注入熵 ⇒ 显式失败（Error::UNSUPPORTED 语义）。
fn fill(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    let mut g = GLOBAL_RNG.lock().expect("wasm bridge rng lock");
    match g.as_mut() {
        Some(r) => {
            r.fill_bytes(buf);
            Ok(())
        }
        None => Err(getrandom::Error::UNSUPPORTED),
    }
}

/// getrandom 0.3 custom 后端回调（符号名/签名按 backends/custom.rs 契约）。
#[no_mangle]
pub extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    // SAFETY：getrandom 契约——dest 指向 len 字节可写缓冲且可能未初始化，
    // 本实现整段覆写（fill_bytes 全量写入），不读未初始化字节。
    let buf = unsafe { std::slice::from_raw_parts_mut(dest, len) };
    fill(buf)
}

/// getrandom 0.2 custom 后端入口（lib.rs register_custom_getrandom! 注册；
/// showroom wasm_shim::custom_getrandom 同法）。两代共享同一熵池。
pub fn custom_getrandom_02(buf: &mut [u8]) -> Result<(), getrandom02::Error> {
    match fill(buf) {
        Ok(()) => Ok(()),
        // 两代 Error 均为内部码 u32/u16：以 UNSUPPORTED 语义透传（未注入熵）。
        Err(_) => Err(getrandom02::Error::UNSUPPORTED),
    }
}
