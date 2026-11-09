//! M8b Web UI 的 wasm C-ABI 垫片（docs/design.md §7-M8.6 契约逐字；showroom
//! `wasm_shim.rs` 手法——无 wasm-bindgen，JS 胶水按 C-ABI 直调）。
//!
//! 编译门（对设计 §M8.6 字面 `wasm + wasm32` 的一处显式扩展）：`wasm` **且**
//! `anchor` feature（login_finish 的 anchor 验签依赖 `pake::anchor` 面），目标
//! `wasm32` **或** `test`（native 单测直接调垫片函数跑通 OPAQUE 全程——注入熵
//! 固定；见 mod tests）。构建档（§M8.1）：
//! `cargo build -p flock-protocol --target wasm32-unknown-unknown
//!  --no-default-features --features wasm,anchor`（无 zstd ⇒ 零 C 依赖）。
//!
//! 契约（§M8.6 逐字）：
//! ```text
//! sr_wasm_inject_entropy(ptr: *const u8, len: usize)
//! sr_wasm_alloc(len: usize) -> *mut u8 / sr_wasm_free(ptr, len)
//! sr_web_login_begin(user_ptr, user_len, pw_ptr, pw_len, out_ptr, out_cap) -> i32
//! sr_web_login_finish(ke2_ptr, ke2_len, server_id_ptr(16B), identity_pub_ptr(32B),
//!                     bind_token_ptr(16B), anchor_sig_ptr(64B), out_ptr, out_cap) -> i32
//! sr_web_pw_begin(user_ptr, user_len, pw_ptr, pw_len, out_ptr, out_cap) -> i32
//! sr_web_pw_finish(m2_ptr, m2_len, out_ptr, out_cap) -> i32
//! 错误码：-1 未注入熵；-2 pake 失败（错口令/坏报文同码）；-3 anchor 验签拒；
//!         -4 out 容量不足。返回 0 = ok；out 写 b64 报文（NUL 结尾）。
//! ```
//!
//! 熵池：本模块自持 `Mutex<Option<StdRng>>`（与 [`crate::wasm_bridge`] 同折叠
//! 算法），驱动 login_start/reg_start 显式 RNG；wasm32 下 `sr_wasm_inject_entropy`
//! **双写两池**——wasm_bridge 池服务 getrandom 面（`pake::login_finish` 内部的
//! `rand::rng()` 在 wasm32 经 custom 后端取熵）。native（test）下 getrandom 走
//! OS 熵源，仅垫片池参与注入熵固定断言。
//!
//! 状态单槽（§M8.6）：ClientLogin/ClientRegistration 模块级单槽，后一次 begin
//! 覆盖前一次；finish 消费（take）并复用 begin 时缓存的 user/pw（rwd 需要二者，
//! C-ABI finish 签名不重复传——与 showroom 同取舍）。

use std::sync::Mutex;

use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::pake::{self, Profile, Suite};

// ============================================================================
// 错误码（§M8.6 定死）
// ============================================================================

/// -1：未注入熵。
pub const ERR_NO_ENTROPY: i32 = -1;
/// -2：pake 失败（错口令/坏报文同码——不泄漏原因）。
pub const ERR_PAKE: i32 = -2;
/// -3：anchor 验签拒（伪服务器/错集群响应混装）。
pub const ERR_ANCHOR: i32 = -3;
/// -4：out 容量不足。
pub const ERR_CAPACITY: i32 = -4;

// ============================================================================
// 熵池（垫片自持；wasm32 下与 wasm_bridge 池同刻双种）
// ============================================================================

static POOL: Mutex<Option<StdRng>> = Mutex::new(None);

/// 熵折叠进 32B seed（与 [`crate::wasm_bridge::inject_entropy`] 同算法——位置相关
/// 旋转，超长输入每字节都影响 seed）。
fn pool_inject(bytes: &[u8]) {
    let mut seed = [0u8; 32];
    for (i, b) in bytes.iter().enumerate() {
        seed[i % 32] ^= b.rotate_left(((i / 32) % 8) as u32);
    }
    *POOL.lock().expect("webauth_shim pool lock") = Some(StdRng::from_seed(seed));
}

/// 池内取 RNG 执行（未注入熵 ⇒ -1；调用期间持锁——单线程 wasm 无争用面，
/// native 测试亦无并发垫片调用）。
fn with_pool<T>(f: impl FnOnce(&mut StdRng) -> Result<T, i32>) -> Result<T, i32> {
    let mut g = POOL.lock().expect("webauth_shim pool lock");
    match g.as_mut() {
        Some(rng) => f(rng),
        None => Err(ERR_NO_ENTROPY),
    }
}

// ============================================================================
// 状态单槽（后一次 begin 覆盖前一次；finish 消费）
// ============================================================================

struct LoginSlot {
    state: crate::opaque_ke::ClientLogin<Suite>,
    user: String,
    pw: String,
}

struct RegSlot {
    state: crate::opaque_ke::ClientRegistration<Suite>,
    user: String,
    pw: String,
}

static LOGIN_SLOT: Mutex<Option<LoginSlot>> = Mutex::new(None);
static REG_SLOT: Mutex<Option<RegSlot>> = Mutex::new(None);

// ============================================================================
// C-ABI 面（全部 #[no_mangle] pub extern "C"；收裸指针的导出一律 unsafe fn——
// 调用方（JS 胶水/native 测试）按契约保证缓冲有效；符号名/ABI 不受影响）
// ============================================================================

/// 熵注入（JS 启动即调：crypto.getRandomValues ≥32B）。wasm32 下同刻种
/// wasm_bridge 池（getrandom custom 后端——`rand::rng()` 内部取熵路径）。
///
/// # Safety
///
/// `ptr` 须指向 `len` 字节可读内存。
#[no_mangle]
pub unsafe extern "C" fn sr_wasm_inject_entropy(ptr: *const u8, len: usize) {
    // SAFETY：JS 胶水契约——ptr 指向 len 字节可读缓冲（由 sr_wasm_alloc 分配或
    // TextEncoder 写入的 wasm 线性内存段）。
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    pool_inject(bytes);
    #[cfg(target_arch = "wasm32")]
    crate::wasm_bridge::inject_entropy(bytes);
}

/// JS 写参/读返回的缓冲分配（零容量语义：分配未初始化；配对 [`sr_wasm_free`]）。
#[no_mangle]
pub extern "C" fn sr_wasm_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::with_capacity(len);
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ptr
}

/// 释放 [`sr_wasm_alloc`] 的缓冲（ptr/len 须与分配一致）。
///
/// # Safety
///
/// ptr 必须来自 [`sr_wasm_alloc`]（同 len）；不得二次释放。
#[no_mangle]
pub unsafe extern "C" fn sr_wasm_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // SAFETY：调用方契约——ptr 来自 sr_wasm_alloc(len)（capacity=len），此处按
    // 同参数重建 Vec 并 drop（len=0：分配面未初始化，不读内容）。
    drop(Vec::from_raw_parts(ptr, 0, len));
}

/// 登录第一步：user+pw → ke1_b64（发 POST /api/login-begin）；状态入单槽。
///
/// # Safety
///
/// user/pw 入参指针指向各自 len 字节可读缓冲；out_ptr 指向 out_cap 字节可写缓冲。
#[no_mangle]
pub unsafe extern "C" fn sr_web_login_begin(
    user_ptr: *const u8,
    user_len: usize,
    pw_ptr: *const u8,
    pw_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i32 {
    // SAFETY：unsafe fn 体——契约由函数级 # Safety 文档承担。
    let user = str_from_raw(user_ptr, user_len);
    let pw = str_from_raw(pw_ptr, pw_len);
    let r = with_pool(|rng| {
        let (state, ke1) = pake::login_start(rng, &pw, &user).map_err(|_| ERR_PAKE)?;
        *LOGIN_SLOT.lock().expect("login slot") = Some(LoginSlot { state, user, pw });
        write_out(out_ptr, out_cap, &ke1)?;
        Ok(())
    });
    flatten(r)
}

/// 登录收尾：ke2 + anchor 材料 → ke3_b64（anchor 验签在 wasm 内——防错集群响应
/// 混装；identity_pub 来自 GET /api/bootstrap）。消费 login 单槽。
///
/// # Safety
///
/// ke2 指向 ke2_len 字节可读缓冲；server_id/identity_pub/bind_token/anchor_sig
/// 分别指向 16/32/16/64 字节可读缓冲；out_ptr 指向 out_cap 字节可写缓冲。
#[no_mangle]
pub unsafe extern "C" fn sr_web_login_finish(
    ke2_ptr: *const u8,
    ke2_len: usize,
    server_id_ptr: *const u8,
    identity_pub_ptr: *const u8,
    bind_token_ptr: *const u8,
    anchor_sig_ptr: *const u8,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i32 {
    // SAFETY：unsafe fn 体——契约由函数级 # Safety 文档承担。
    let ke2 = str_from_raw(ke2_ptr, ke2_len);
    let server_id = fixed::<16>(server_id_ptr);
    let identity_pub = fixed::<32>(identity_pub_ptr);
    let bind_token = fixed::<16>(bind_token_ptr);
    let anchor_sig = fixed::<64>(anchor_sig_ptr);

    let Some(LoginSlot { state, user, pw }) = LOGIN_SLOT.lock().expect("login slot").take() else {
        return ERR_PAKE; // 无在途 begin（未 begin/已消费）——pake 面同码
    };

    // anchor 验签（login_finish_anchored 同 canonical：label‖server_id‖len(user)‖
    // user‖ke2‖bind_token）。前置独立验一次以区分 -3（anchor 拒）与 -2（pake 拒）
    //——随后 login_finish_anchored 内部再验（同字节、同钥），成功路径双验代价为
    // 一次 Ed25519 verify（~50µs 量级，可忽略）。
    use crate::ed25519_dalek::Verifier as _;
    let (verifying, signature) = match (
        crate::ed25519_dalek::VerifyingKey::from_bytes(&identity_pub),
        crate::ed25519_dalek::Signature::from_slice(&anchor_sig),
    ) {
        (Ok(v), Ok(s)) => (v, s),
        _ => return ERR_ANCHOR, // 坏钥/坏签长度按验签拒归类（不泄漏细节）
    };
    let canonical = pake::anchor_canonical_bytes(&server_id, &user, &ke2, &bind_token);
    if verifying.verify(&canonical, &signature).is_err() {
        return ERR_ANCHOR;
    }

    let expect = pake::AnchorExpectation {
        server_id,
        identity_pub: verifying,
        bind_token,
    };
    match pake::login_finish_anchored(
        state,
        &pw,
        &user,
        &ke2,
        Profile::default(), // Web 登录客户端恒用 Owasp19MiB（=default，§M8.3）
        &expect,
        &anchor_sig,
    ) {
        Ok(ke3) => match write_out(out_ptr, out_cap, &ke3) {
            Ok(()) => 0,
            Err(c) => c,
        },
        Err(_) => ERR_PAKE,
    }
}

/// 注册第一步（口令引导流共用）：user+pw → m1_b64（发 POST /api/pw-begin）。
/// # Safety
///
/// user/pw 入参指针指向各自 len 字节可读缓冲；out_ptr 指向 out_cap 字节可写缓冲。
#[no_mangle]
pub unsafe extern "C" fn sr_web_pw_begin(
    user_ptr: *const u8,
    user_len: usize,
    pw_ptr: *const u8,
    pw_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i32 {
    // SAFETY：unsafe fn 体——契约由函数级 # Safety 文档承担。
    let user = str_from_raw(user_ptr, user_len);
    let pw = str_from_raw(pw_ptr, pw_len);
    let r = with_pool(|rng| {
        let (state, m1) = pake::reg_start(rng, &pw, &user).map_err(|_| ERR_PAKE)?;
        *REG_SLOT.lock().expect("reg slot") = Some(RegSlot { state, user, pw });
        write_out(out_ptr, out_cap, &m1)?;
        Ok(())
    });
    flatten(r)
}

/// 注册收尾：m2_b64 → record_b64（发 POST /api/pw-commit）。消费 pw 单槽。
///
/// # Safety
///
/// m2 指向 m2_len 字节可读缓冲；out_ptr 指向 out_cap 字节可写缓冲。
/// # Safety
///
/// m2 指向 m2_len 字节可读缓冲；out_ptr 指向 out_cap 字节可写缓冲。
#[no_mangle]
pub unsafe extern "C" fn sr_web_pw_finish(
    m2_ptr: *const u8,
    m2_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i32 {
    // SAFETY：unsafe fn 体——契约由函数级 # Safety 文档承担。
    let m2 = str_from_raw(m2_ptr, m2_len);
    let Some(RegSlot { state, user, pw }) = REG_SLOT.lock().expect("reg slot").take() else {
        return ERR_PAKE;
    };
    let r = with_pool(|rng| {
        let record = pake::reg_finish(rng, state, &pw, &user, &m2).map_err(|_| ERR_PAKE)?;
        write_out(out_ptr, out_cap, &record)?;
        Ok(())
    });
    flatten(r)
}

// ============================================================================
// 内部工具（非 ABI 面）
// ============================================================================

/// 裸指针 → 有损 UTF-8 字符串（b64/口令/用户名均 ASCII 面；有损解码不构成失败路径）。
///
/// # Safety
///
/// `ptr` 须指向 `len` 字节可读内存。
unsafe fn str_from_raw(ptr: *const u8, len: usize) -> String {
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(ptr, len) }).into_owned()
}

/// 裸指针 → 定长数组（anchor 材料/签名的 16/32/64B 面）。
///
/// # Safety
///
/// `ptr` 须指向 `N` 字节可读内存。
unsafe fn fixed<const N: usize>(ptr: *const u8) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(unsafe { std::slice::from_raw_parts(ptr, N) });
    out
}

/// out 写 b64 报文 + NUL 结尾；容量不足 ⇒ -4。
///
/// # Safety
///
/// `out_ptr` 须指向 `out_cap` 字节可写内存。
unsafe fn write_out(out_ptr: *mut u8, out_cap: usize, s: &str) -> Result<(), i32> {
    let bytes = s.as_bytes();
    if bytes.len() + 1 > out_cap {
        return Err(ERR_CAPACITY);
    }
    // SAFETY：上方已验容量；整段覆写不读未初始化字节。
    let buf = unsafe { std::slice::from_raw_parts_mut(out_ptr, bytes.len() + 1) };
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0;
    Ok(())
}

fn flatten(r: Result<(), i32>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(c) => c,
    }
}

// ============================================================================
// native 垫片单测（§M8.9 wasm 面——「native 直接调垫片函数跑通 OPAQUE 全程，
// 用注入熵固定」；服务器侧用真实 pake::server_* 构造对端）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519_dalek::{Signature, Signer, SigningKey};
    use crate::pake::{
        anchor_sign, login_start, reg_finish, reg_start, server_login_finish, server_login_start,
        server_record_from_b64, server_reg_canonical, server_reg_start, server_setup_load,
        server_setup_new,
    };
    use crate::rand;

    const SEED: &[u8] = &[0x5f_u8; 64];
    /// JS 胶水同值的 out 缓冲容量。
    const OUT_CAP: usize = 64 * 1024;
    /// 全局态（熵池/单槽）测试串行锁——垫片状态是进程级单例，并行测试互扰。
    static SERIAL: Mutex<()> = Mutex::new(());
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 裸指针调用辅助：把 bytes 写进垫片分配的缓冲再调 f(ptr, len)。
    fn with_buf(bytes: &[u8], f: impl FnOnce(*const u8, usize)) {
        let ptr = sr_wasm_alloc(bytes.len());
        // SAFETY：ptr 刚由 sr_wasm_alloc(bytes.len()) 分配（len 字节可写）。
        unsafe { std::slice::from_raw_parts_mut(ptr, bytes.len()) }.copy_from_slice(bytes);
        f(ptr, bytes.len());
        // SAFETY：同 ptr/len 配对释放。
        unsafe { sr_wasm_free(ptr, bytes.len()) };
    }

    fn alloc_out() -> *mut u8 {
        sr_wasm_alloc(OUT_CAP)
    }
    /// 读垫片写的 C 字符串（NUL 结尾）。
    fn read_out(ptr: *mut u8) -> String {
        // SAFETY：out 缓冲由 sr_wasm_alloc(OUT_CAP) 分配；write_out 保证 NUL 结尾。
        let m = unsafe { std::slice::from_raw_parts(ptr, OUT_CAP) };
        let n = m.iter().position(|&b| b == 0).unwrap_or(m.len());
        String::from_utf8_lossy(&m[..n]).into_owned()
    }
    fn free_out(ptr: *mut u8) {
        // SAFETY：alloc_out 的配对释放。
        unsafe { sr_wasm_free(ptr, OUT_CAP) };
    }

    fn inject(seed: &[u8]) {
        with_buf(seed, |p, l| {
            // SAFETY：with_buf 提供有效 (ptr, len)。
            unsafe { sr_wasm_inject_entropy(p, l) }
        });
    }

    /// 垫片 login_begin（native 直调）。
    fn shim_login_begin(user: &str, pw: &str) -> (i32, String) {
        let out = alloc_out();
        let rc = 0;
        let _ = rc;
        let ret = std::cell::Cell::new(0i32);
        with_buf(pw.as_bytes(), |pp, pl| {
            with_buf(user.as_bytes(), |up, ul| {
                // SAFETY：with_buf 提供有效缓冲。
                ret.set(unsafe { sr_web_login_begin(up, ul, pp, pl, out, OUT_CAP) });
            })
        });
        let s = if ret.get() == 0 {
            read_out(out)
        } else {
            String::new()
        };
        free_out(out);
        (ret.get(), s)
    }

    /// 垫片 login_finish（native 直调；ke2 + anchor 四件套）。
    #[allow(clippy::too_many_arguments)]
    fn shim_login_finish(
        ke2: &str,
        server_id: &[u8; 16],
        identity_pub: &[u8; 32],
        bind_token: &[u8; 16],
        sig: &Signature,
    ) -> (i32, String) {
        let out = alloc_out();
        let ret = std::cell::Cell::new(0i32);
        with_buf(sig.to_bytes().as_slice(), |sp, _sl| {
            with_buf(bind_token.as_slice(), |bp, _bl| {
                with_buf(identity_pub.as_slice(), |ip, _il| {
                    with_buf(server_id.as_slice(), |s2, _l2| {
                        with_buf(ke2.as_bytes(), |kp, kl| {
                            // SAFETY：C-ABI 契约参数齐（测试内缓冲均有效）。
                            ret.set(unsafe {
                                sr_web_login_finish(kp, kl, s2, ip, bp, sp, out, OUT_CAP)
                            });
                        })
                    })
                })
            })
        });
        let s = if ret.get() == 0 {
            read_out(out)
        } else {
            String::new()
        };
        free_out(out);
        (ret.get(), s)
    }

    /// 服务器侧材料（OPRF setup + 注册记录 + 身份钥），返回 (setup, record, sk,
    /// server_id)。
    struct ServerSide {
        setup: crate::opaque_ke::ServerSetup<Suite>,
        record: crate::opaque_ke::ServerRegistration<Suite>,
        sk: SigningKey,
        server_id: [u8; 16],
    }

    fn server_side(user: &str, pw: &str) -> ServerSide {
        let mut rng = rand::rngs::OsRng;
        let setup = server_setup_load(&server_setup_new(&mut rng)).unwrap();
        let (cstate, m1) = reg_start(&mut rng, pw, user).unwrap();
        let m2 = server_reg_start(&setup, &m1, user).unwrap();
        let record =
            server_reg_canonical(&reg_finish(&mut rng, cstate, pw, user, &m2).unwrap()).unwrap();
        ServerSide {
            setup,
            record: server_record_from_b64(&record).unwrap(),
            sk: SigningKey::from_bytes(&rand::random::<[u8; 32]>()),
            server_id: rand::random(),
        }
    }

    /// 全程往返（注入熵固定）：login_begin → server_login_start+anchor_sign →
    /// login_finish → server_login_finish 验 ke3。
    #[test]
    fn full_login_roundtrip_via_shim() {
        let _guard = serial();
        let srv = server_side("shim-user", "shim-pw");
        inject(SEED);
        let (rc, ke1) = shim_login_begin("shim-user", "shim-pw");
        assert_eq!(rc, 0, "login_begin rc");
        assert!(ke1.len() > 100, "ke1 b64 形态（{}B）", ke1.len());

        let mut rng = rand::rngs::OsRng;
        let (ke2, pending) =
            server_login_start(&mut rng, &srv.setup, Some(&srv.record), &ke1, "shim-user")
                .expect("server accept ke1");
        let bind_token: [u8; 16] = rand::random();
        let sig = anchor_sign(&srv.sk, &srv.server_id, "shim-user", &ke2, &bind_token);

        let (rc, ke3) = shim_login_finish(
            &ke2,
            &srv.server_id,
            srv.sk.verifying_key().as_bytes(),
            &bind_token,
            &sig,
        );
        assert_eq!(rc, 0, "login_finish rc（anchor 验签过）");
        assert!(
            server_login_finish(&pending, &ke3).is_ok(),
            "ke3 服务端验过"
        );
    }

    /// -1 未注入熵：begin 在空池上拒绝。
    #[test]
    fn err_no_entropy_before_inject() {
        let _guard = serial();
        *POOL.lock().unwrap() = None; // 空态（注入可重复语义的对偶面）
        let (rc, _) = shim_login_begin("u", "pw");
        assert_eq!(rc, ERR_NO_ENTROPY);
        // 池复位供后续测试（测试间共享全局池——顺序不敏感化）。
        inject(SEED);
    }

    /// -2 pake 失败：错口令（客户端本地 finish 拒）与空槽 finish 同码。
    #[test]
    fn err_pake_wrong_password_and_empty_slot() {
        let _guard = serial();
        inject(SEED);
        let srv = server_side("alice", "right");
        // 空槽 finish（未 begin 即 finish）——显式清槽（前序测试的 begin 残留面）。
        LOGIN_SLOT.lock().unwrap().take();
        // 空槽 finish（未 begin 即 finish）。
        let (rc, _) = shim_login_finish(
            "x",
            &[0u8; 16],
            &[0u8; 32],
            &[0u8; 16],
            &Signature::from_bytes(&[0u8; 64]),
        );
        assert_eq!(rc, ERR_PAKE, "空槽 = -2");

        // 错口令：begin("wrong") 后用正确 ke2 finish ⇒ rwd 不匹配 ⇒ -2。
        let (rc, ke1) = shim_login_begin("alice", "wrong");
        assert_eq!(rc, 0);
        let mut rng = rand::rngs::OsRng;
        let (ke2, _) =
            server_login_start(&mut rng, &srv.setup, Some(&srv.record), &ke1, "alice").unwrap();
        let bind_token: [u8; 16] = rand::random();
        let sig = anchor_sign(&srv.sk, &srv.server_id, "alice", &ke2, &bind_token);
        let (rc, ke3) = shim_login_finish(
            &ke2,
            &srv.server_id,
            srv.sk.verifying_key().as_bytes(),
            &bind_token,
            &sig,
        );
        assert_eq!(rc, ERR_PAKE, "错口令 = -2");
        assert!(ke3.is_empty(), "ke3 不产生");
    }

    /// -3 anchor 验签拒：攻击者密钥签的 anchor（伪服务器面）。
    #[test]
    fn err_anchor_forged_signature() {
        let _guard = serial();
        inject(SEED);
        let mut rng = rand::rngs::OsRng;
        let setup = server_setup_load(&server_setup_new(&mut rng)).unwrap();
        let (rc, ke1) = shim_login_begin("carol", "carol-pw");
        assert_eq!(rc, 0);
        let (ke2, _) = server_login_start(&mut rng, &setup, None, &ke1, "carol").unwrap();
        let honest = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let attacker = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let server_id: [u8; 16] = rand::random();
        let bind_token: [u8; 16] = rand::random();
        let forged = anchor_sign(&attacker, &server_id, "carol", &ke2, &bind_token);
        let (rc, ke3) = shim_login_finish(
            &ke2,
            &server_id,
            honest.verifying_key().as_bytes(),
            &bind_token,
            &forged,
        );
        assert_eq!(rc, ERR_ANCHOR, "伪 anchor = -3（ke3 不产生）");
        assert!(ke3.is_empty());
    }

    /// -4 out 容量不足。
    #[test]
    fn err_capacity_too_small() {
        let _guard = serial();
        inject(SEED);
        let small = sr_wasm_alloc(8);
        let ret = std::cell::Cell::new(0i32);
        with_buf(b"pw".as_slice(), |pp, pl| {
            with_buf(b"user".as_slice(), |up, ul| {
                // SAFETY：with_buf 提供有效缓冲。
                ret.set(unsafe { sr_web_login_begin(up, ul, pp, pl, small, 8) });
            })
        });
        // SAFETY：配对释放。
        unsafe { sr_wasm_free(small, 8) };
        assert_eq!(ret.get(), ERR_CAPACITY);
    }

    /// 注册全程经垫片：pw_begin → server_reg_start → pw_finish → record 可被
    /// 服务端接受，且与 login 面闭环。
    #[test]
    fn full_pw_bootstrap_roundtrip_via_shim() {
        let _guard = serial();
        inject(SEED);
        let mut rng = rand::rngs::OsRng;
        let setup = server_setup_load(&server_setup_new(&mut rng)).unwrap();

        let m1_out = alloc_out();
        let rc_m1 = std::cell::Cell::new(0i32);
        with_buf(b"NewPw-9x".as_slice(), |pp, pl| {
            with_buf(b"newbie".as_slice(), |up, ul| {
                // SAFETY：with_buf 提供有效缓冲。
                rc_m1.set(unsafe { sr_web_pw_begin(up, ul, pp, pl, m1_out, OUT_CAP) });
            })
        });
        assert_eq!(rc_m1.get(), 0, "pw_begin rc");
        let m1 = read_out(m1_out);
        free_out(m1_out);

        let m2 = server_reg_start(&setup, &m1, "newbie").unwrap();
        let rec_out = alloc_out();
        let rc_rec = std::cell::Cell::new(0i32);
        with_buf(m2.as_bytes(), |mp, ml| {
            // SAFETY：C-ABI 契约参数齐。
            rc_rec.set(unsafe { sr_web_pw_finish(mp, ml, rec_out, OUT_CAP) });
        });
        assert_eq!(rc_rec.get(), 0, "pw_finish rc");
        let record = read_out(rec_out);
        free_out(rec_out);
        let record = server_reg_canonical(&record).unwrap();
        let rec = server_record_from_b64(&record).unwrap();

        // 闭环：record 登录全程（垫片 login 面）。
        let (rc, ke1) = shim_login_begin("newbie", "NewPw-9x");
        assert_eq!(rc, 0);
        let (ke2, pending) =
            server_login_start(&mut rng, &setup, Some(&rec), &ke1, "newbie").unwrap();
        let sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let server_id: [u8; 16] = rand::random();
        let bind_token: [u8; 16] = rand::random();
        let sig = anchor_sign(&sk, &server_id, "newbie", &ke2, &bind_token);
        let (rc, ke3) = shim_login_finish(
            &ke2,
            &server_id,
            sk.verifying_key().as_bytes(),
            &bind_token,
            &sig,
        );
        assert_eq!(rc, 0);
        assert!(server_login_finish(&pending, &ke3).is_ok());
    }

    /// 注入熵固定 ⇒ 确定性：同 seed 两次 login_begin 产出相同 ke1（证明垫片 RNG
    /// 由注入熵驱动，非 OS 熵）。
    #[test]
    fn injected_entropy_drives_deterministic_ke1() {
        let _guard = serial();
        inject(SEED);
        let (_, a) = shim_login_begin("det", "pw");
        inject(SEED); // 重注入同 seed（重置语义）
        let (_, b) = shim_login_begin("det", "pw");
        assert_eq!(a, b, "同 seed ⇒ 同 ke1（确定性）");
        inject(&[0xAB; 64]); // 换 seed
        let (_, c) = shim_login_begin("det", "pw");
        assert_ne!(a, c, "异 seed ⇒ 异 ke1");
    }

    /// 单槽覆盖：后一次 begin 覆盖前一次（u1 begin → u2 begin → 用 u2 的 ke2
    /// finish 成功；u1 状态已不可达）。
    #[test]
    fn login_slot_last_begin_wins() {
        let _guard = serial();
        inject(SEED);
        let srv = server_side("u2", "pw2");
        LOGIN_SLOT.lock().unwrap().take(); // 前序残留清面
        let _ = shim_login_begin("u1", "pw1"); // 被覆盖
        let (rc, ke1_u2) = shim_login_begin("u2", "pw2");
        assert_eq!(rc, 0);
        let (ke2, pending) = server_login_start(
            &mut rand::rngs::OsRng,
            &srv.setup,
            Some(&srv.record),
            &ke1_u2,
            "u2",
        )
        .unwrap();
        let bind_token: [u8; 16] = rand::random();
        let sig = anchor_sign(&srv.sk, &srv.server_id, "u2", &ke2, &bind_token);
        let (rc, ke3) = shim_login_finish(
            &ke2,
            &srv.server_id,
            srv.sk.verifying_key().as_bytes(),
            &bind_token,
            &sig,
        );
        assert_eq!(rc, 0, "末次 begin 的状态可用（u2 流程收尾成功）");
        assert!(server_login_finish(&pending, &ke3).is_ok());
    }

    /// 服务器侧签名器与垫片 verify 同 canonical（防垫片自造格式漂移——与
    /// pake::anchor_canonical_bytes 逐字节一致由 login 全程往返间接实证，此处
    /// 直接对 canonical 做一次签名/验签往返）。
    #[test]
    fn anchor_canonical_shim_matches_server() {
        let _guard = serial();
        let sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let server_id: [u8; 16] = rand::random();
        let bind: [u8; 16] = rand::random();
        let canonical = pake::anchor_canonical_bytes(&server_id, "u", "ke2-b64", &bind);
        let sig: Signature = sk.sign(&canonical);
        use crate::ed25519_dalek::Verifier as _;
        assert!(sk.verifying_key().verify(&canonical, &sig).is_ok());
        // 异 ke2 ⇒ 验签拒（transcript 绑定）。
        let other = pake::anchor_canonical_bytes(&server_id, "u", "ke2-b6d", &bind);
        assert!(sk.verifying_key().verify(&other, &sig).is_err());
    }

    // login_start 直调一处（server_side 之外的独立用途实证：native OsRng 路径与
    // 垫片池路径可互换——协议面相同）。
    #[test]
    fn native_login_start_remains_compatible() {
        let _guard = serial();
        let (state, ke1) = login_start(&mut rand::rngs::OsRng, "pw", "u").unwrap();
        assert!(!ke1.is_empty());
        drop(state);
    }
}
