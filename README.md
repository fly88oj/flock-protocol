# flock-protocol

flock 加密协议库——Flock VPN 与其周边应用共享的密码学契约层，以独立 crate 形态发布。
核心能力：

- **混合 KEM**：X25519 + ML-KEM-768（FIPS 203）双栈封装，量子计算迁移期同时保住
  经典与后量子安全边界；
- **Noise-IK 式 1-RTT 隧道会话**（session）：已钉扎服务器即一次往返建立加密隧道，
  记录层计数器 nonce AEAD、抗重放、双阈值 rekey、伪造断链；
- **文件信封 v1/v2**（envelope）：流式恒定内存加密封装（v2 混合 KEM + 段序号 AAD；
  `legacy` feature 下 v1 RSA-OAEP 只读兼容）；
- **OPAQUE PAKE**（pake，RFC 9807 / opaque-ke 4.0.1）+ argon2id 口令 profile；
- **SR-SIG1 签名**（sig）：五函数兼容签名面 + `KeyProfile` kid 分派；
- **yamux 内嵌复用**（mux）：加密记录层之上的流复用、显式 FIN、PacketChannel；
- **压缩档位**（compress）：zstd-1 字典 / zstd-1 分块 / level-19 归档 / lz4 纯 Rust，
  非膨胀回退 MUST；
- **TOFU / 邀请信任锚**（trust）：PinStore 集群根级钉扎、ClusterDirectory 根签目录、
  InviteFile v3。

## 定位 / Positioning

flock-protocol 是**可嵌入的高性能加密协议库**（an embeddable, high-performance
cryptographic protocol library），按三层嵌入模型设计：

1. **传输层嵌入（transport embedding）**——tunnel 档（session/mux）泛型于
   `AsyncRead + AsyncWrite`，可寄生在任何**可靠有序字节流**内：直连 TCP、frp、
   ChmlFrp 中转、任意 QUIC stream 适配器——载体协议零改动（overlay 叠加，而非改写）。
   已在原版 frp v0.71.1 与 ChmlFrp v0.51.2 上完成字节级透传验证。
2. **应用层嵌入（application embedding）**——组件档按 feature 裁剪消费：
   envelope/sig/pake 可单独使用（如仅做文件加密或口令认证的嵌入方），showroom 以
   `legacy`+`wasm` 档嵌入即为实例。
3. **运行时嵌入（runtime embedding）**——wasm32 目标 + C-ABI 垫片
   （`webauth_shim`）将认证面嵌入浏览器等非 Rust 宿主。

**边界**：载波必须是可靠有序字节流——数据报载体未支持，抗重放依赖流的有序性。
核心原语（kem/envelope/sig/pake）为纯同步函数，仅 session/mux 为 async。

**Roadmap**：flock 应用面控制契约（roster 模块）与 kem 底层访问器的进一步收敛
（`seed_material` API 已就位）列入后续小版本。

## 模块与档位

| 模块 | 内容 |
|---|---|
| `kem` | X25519 + ML-KEM-768 混合 KEM（ek 1184B / ct 1088B / 混合公钥 1216B） |
| `envelope` | 文件信封 v2（混合封装 + 段序号 AAD）；`legacy` 下 v1 只读兼容 |
| `sig` | SR-SIG1 五函数兼容 + `KeyProfile` kid 分派 |
| `pake` | OPAQUE（RFC 9807 / opaque-ke 4.0.1）+ argon2id profile |
| `compress` | 压缩档位（<128B 直通；zstd-1 字典 / zstd-1 分块 / level-19 归档；非膨胀回退 MUST） |
| `session` | 隧道会话：握手双形态 + 记录层 + 抗重放 + rekey + 伪造断链 |
| `mux` | yamux 0.14.1（加密记录层内）+ 显式 FIN + PacketChannel |
| `trust` | PinStore（集群根级钉扎）/ ClusterDirectory（根签目录）/ InviteFile v3 |
| `roster` | 名册与控制面共享契约（PeerInfo/PeerKind、票据与控制消息线格式） |
| `compat` | 兼容工具面（`Result` 别名 / `write_private` 0600 落盘 / 名字校验） |

## Feature 矩阵

| feature | 默认 | 作用 |
|---|---|---|
| `default`（= `zstd`） | 开 | 全 VPN 档：sig / kem / envelope v2 / pake / compress / session / mux |
| `zstd` | 随默认开 | zstd 压缩档（zstd-sys 含 C 源；关掉后 compress 仅 lz4 纯 Rust 档，wasm32 构建零 C 依赖） |
| `legacy` | 关 | 信封 v1（RSA-OAEP）只读兼容，另再导出 `rsa` |
| `anchor` | 关 | OPAQUE 服务端身份签名层（登录锚） |
| `pq-sign` | 关 | ML-DSA-65 并行公钥档（ml-dsa 尚未审计，默认关） |
| `wasm` | 关 | wasm32 约束档（getrandom custom 后端桥 `src/wasm_bridge.rs` + `webauth_shim`） |

## 快速上手

`Cargo.toml`：

```toml
[dependencies]
flock-protocol = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] } # 仅隧道档需要
```

### 1. 混合 KEM：封装 / 解封装

```rust
use flock_protocol::kem::{self, HybridKeypair};

let mut rng = rand::rngs::OsRng; // flock_protocol 再导出的 rand 0.9
let sk = HybridKeypair::generate(&mut rng); // X25519 + ML-KEM-768 双栈密钥
let pk = sk.public();

let (shared, ct) = kem::encapsulate(&pk, &mut rng); // 一次性共享密钥 + 1120B 混合密文
let shared2 = kem::decapsulate(&sk, &ct).unwrap();
assert_eq!(shared.as_bytes(), shared2.as_bytes());
```

### 2. 文件信封 v2：seal / open（流式，恒定内存）

```rust
use std::io::Cursor;
use flock_protocol::envelope::{open_v2, seal_v2};
use flock_protocol::kem::HybridKeypair;

let sk = HybridKeypair::generate(&mut rand::rngs::OsRng);
let plain = b"any file content, streamed in 4 MiB segments".to_vec();

// 加密封装：1137B 头（ver | envelope_id | HybridCt）+ 分段 AEAD
let mut sealed = Vec::new();
let info = seal_v2(&sk.public(), Cursor::new(&plain), &mut sealed).unwrap();

// 解封：同一段序号 AAD 逐段校验，返回明文字节数
let mut out = Vec::new();
let n = open_v2(&sk, sealed.as_slice(), &mut out).unwrap();
assert_eq!(n as usize, plain.len());
```

### 3. 隧道会话：initiate（1-RTT）/ respond

session/mux 泛型于任何 `AsyncRead + AsyncWrite`——这里是内存 duplex，生产中是
TCP / 中转 / QUIC 流适配器，载体协议零改动。

```rust
use ed25519_dalek::SigningKey;
use flock_protocol::mux::Prio;
use flock_protocol::session::{
    initiate, respond, ClusterId, DeviceRecord, DeviceStaticKeys, InMemoryDirectory,
    ServerId, ServerIdentity, ServerPin, TunnelConfig,
};

#[tokio::main]
async fn main() {
    // 服务端身份：集群根（ed25519）签发一台服务器
    let root = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let cluster = ClusterId(rand::random());
    let server =
        ServerIdentity::enroll(&root, cluster, ServerId(rand::random()), "relay.example:23000");

    // 客户端设备密钥 + 服务端设备目录（生产中为持久化目录）
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    dir.register(DeviceRecord {
        device_x25519: device.x25519_public(),
        device_ed25519: device.ed25519_public(),
    });

    // 客户端钉扎（生产中来自 trust::PinStore / InviteFile v3）
    let pin = ServerPin {
        cluster_id: cluster,
        cluster_root_pub: root.verifying_key(),
        entry: server.entry.clone(),
    };

    // 对拨：任何 AsyncRead + AsyncWrite + Unpin + Send + 'static
    let (a, b) = tokio::io::duplex(64 * 1024);
    let srv = tokio::spawn(async move {
        respond(b, &server, dir, TunnelConfig::default()).await
    });
    let client = initiate(a, &device, &pin, TunnelConfig::default())
        .await
        .unwrap();
    let server_side = srv.await.unwrap().unwrap();

    // 隧道内 yamux 复用：开一条流，服务端 accept
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cstream = client.open_stream(Prio::Normal).await.unwrap();
    cstream.write_all(b"ping").await.unwrap();

    let mut sstream = server_side.accept_stream().await.unwrap();
    let mut buf = [0u8; 4];
    sstream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}
```

TOFU 首连（未钉扎时）：`initiate_tofu(...)` → 展示根指纹（`root_fingerprint`）→
`confirm()`；钉扎落地走 `trust::confirm_tofu_and_pin`。TOFU 不防首登在线 MITM
（SSH known_hosts 同类限制）——组织场景必须走邀请文件强路径（`trust::InviteFile` v3）。

## 安全契约：两档 nonce，不可混用

**信封档（envelope v2）——一次性 k + 每段随机 96-bit nonce**：k 为一次性混合 KEM
派生（每信封新临时份额），单信封段数 ≪ 2^32，随机 nonce 落在 SP 800-38D 随机 IV
界内。仅适用于离线文件/一次性载荷——复用 k 于大量消息或长寿命流即违约。

**隧道档（session 记录层）——计数器 nonce，禁随机**：nonce = 32-bit 零 ‖ 64-bit LE
计数器（WireGuard 形态），每方向独立密钥与计数；TCP 有序 ⇒ 接收侧以「上一条 +1」
隐式重建，重复/回退表现为认证失败并计入伪造（forge_limit 默认 100，达限断链）。
密钥寿命双阈值：rekey（2^60 包 / 120s）先到先换；硬上限（2^64−2^13−1 包 / 180s）
触发即清零密钥断链。

设备签名覆盖 I1 全部已发字段 + 协议上下文（cluster_id / 期望服务器身份）——
UKS 篡改向量必失败。

## 版本收口

本 crate 再导出锁定的 `ed25519_dalek` / `x25519_dalek` / `ml_kem` / `opaque_ke` /
`rand`（`legacy` 下另含 `rsa`），下游不得另引版本——直接复用，避免类型不兼容。

## 构建与验证

```sh
cargo test --all-features        # 全量测试
cargo check --no-default-features
cargo check --no-default-features --features wasm --target wasm32-unknown-unknown
cargo clippy --all-features -- -D warnings
cargo fmt --all -- --check
cargo bench --no-run             # bench 编译检查
```

wasm32 目标的 getrandom custom 后端 cfg 由仓库 `.cargo/config.toml` 提供，熵桥见
`src/wasm_bridge.rs`。全量（含 zstd）交叉 wasm32 需带 wasm 后端的 clang；仅
`--no-default-features --features wasm` 的核心协议面零 C 依赖。

## 安全公告

安全漏洞报告渠道与响应节奏见 [SECURITY.md](SECURITY.md)——请勿通过公开 issue
报告安全问题。

## 许可

双许可，任选其一：

- [LICENSE-APACHE-2.0](LICENSE-APACHE-2.0)（Apache License 2.0）
- [LICENSE-MIT](LICENSE-MIT)（MIT License）

除非你明确声明，否则你提交至本仓库的任何贡献（intentional contributions）均按
上述双许可授权，无附加条款。
