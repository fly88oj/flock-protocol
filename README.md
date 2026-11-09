# flock-protocol

The flock cryptographic protocol library — the cryptography contract
layer shared by Flock VPN and its surrounding applications, published as
a standalone crate. Core capabilities:

- **Hybrid KEM**: X25519 + ML-KEM-768 (FIPS 203) dual-stack
  encapsulation, holding both the classical and the post-quantum
  security boundary during the quantum-migration era;
- **Noise-IK-style 1-RTT tunnel sessions** (session): with a pinned
  server, one round trip establishes the encrypted tunnel — record-layer
  counter-nonce AEAD, anti-replay, dual-threshold rekey, forgery
  teardown;
- **File envelopes v1/v2** (envelope): streaming constant-memory sealing
  (v2 = hybrid KEM + segment-index AAD; v1 RSA-OAEP read-only
  compatibility under the `legacy` feature);
- **OPAQUE PAKE** (pake, RFC 9807 / opaque-ke 4.0.1) + argon2id password
  profiles;
- **SR-SIG1 signing** (sig): the five-function compatibility signing
  surface + `KeyProfile` kid dispatch;
- **Embedded yamux multiplexing** (mux): stream multiplexing over the
  encrypted record layer, explicit FIN, PacketChannel;
- **Compression tiers** (compress): zstd-1 dictionary / zstd-1 chunked /
  level-19 archive / pure-Rust lz4, with the non-expanding fallback as a
  MUST;
- **TOFU / invite trust anchors** (trust): PinStore cluster-root-level
  pinning, the root-signed ClusterDirectory, InviteFile v3.

## Positioning

flock-protocol is **an embeddable, high-performance cryptographic
protocol library**, designed around a three-layer embedding model:

1. **Transport embedding** — the tunnel tier (session/mux) is generic
   over `AsyncRead + AsyncWrite` and can live inside any **reliable,
   ordered byte stream**: direct TCP, frp, ChmlFrp relays, any QUIC
   stream adapter — with zero changes to the carrier protocol (an
   overlay, not a rewrite). Byte-level pass-through has been verified
   against stock frp v0.71.1 and ChmlFrp v0.51.2.
2. **Application embedding** — component tiers are consumed à la carte
   via features: envelope/sig/pake can be used standalone (e.g. by
   embedders doing only file encryption or password authentication);
   showroom embedding with the `legacy`+`wasm` tiers is a live example.
3. **Runtime embedding** — the wasm32 target + the C-ABI shim
   (`webauth_shim`) embed the authentication surface into non-Rust
   hosts such as browsers.

**Boundary**: the carrier must be a reliable ordered byte stream —
datagram carriers are unsupported; anti-replay depends on stream
ordering. The core primitives (kem/envelope/sig/pake) are purely
synchronous functions; only session/mux are async.

**Roadmap**: further convergence of the flock application-side control
contracts (the roster module) and of the low-level KEM accessors (the
`seed_material` API is already in place) is scheduled for subsequent
minor versions.

## Modules and tiers

| Module | Contents |
|---|---|
| `kem` | X25519 + ML-KEM-768 hybrid KEM (ek 1184B / ct 1088B / hybrid public key 1216B) |
| `envelope` | File envelope v2 (hybrid encapsulation + segment-index AAD); v1 read-only compat under `legacy` |
| `sig` | SR-SIG1 five-function compatibility + `KeyProfile` kid dispatch |
| `pake` | OPAQUE (RFC 9807 / opaque-ke 4.0.1) + argon2id profiles |
| `compress` | Compression tiers (<128B passthrough; zstd-1 dictionary / zstd-1 chunked / level-19 archive; non-expanding fallback MUST) |
| `session` | Tunnel sessions: dual-form handshake + record layer + anti-replay + rekey + forgery teardown |
| `mux` | yamux 0.14.1 (inside the encrypted record layer) + explicit FIN + PacketChannel |
| `trust` | PinStore (cluster-root-level pinning) / ClusterDirectory (root-signed directory) / InviteFile v3 |
| `roster` | Roster and control-plane shared contracts (PeerInfo/PeerKind, ticket and control-message wire formats) |
| `compat` | Compatibility utility surface (`Result` alias / `write_private` 0600 persistence / name validation) |

## Feature matrix

| feature | default | effect |
|---|---|---|
| `default` (= `zstd`) | on | Full VPN tier: sig / kem / envelope v2 / pake / compress / session / mux |
| `zstd` | on with default | zstd compression tier (zstd-sys carries C sources; disabled, compress keeps only the pure-Rust lz4 tier and wasm32 builds have zero C dependencies) |
| `legacy` | off | Envelope v1 (RSA-OAEP) read-only compatibility; also re-exports `rsa` |
| `anchor` | off | OPAQUE server-identity signature layer (login anchor) |
| `pq-sign` | off | ML-DSA-65 parallel public-key tier (ml-dsa is unaudited; off by default) |
| `wasm` | off | wasm32 constraint tier (getrandom custom-backend bridge `src/wasm_bridge.rs` + `webauth_shim`) |

## Quick start

`Cargo.toml`:

```toml
[dependencies]
flock-protocol = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] } # tunnel tier only
```

### 1. Hybrid KEM: encapsulate / decapsulate

```rust
use flock_protocol::kem::{self, HybridKeypair};

let mut rng = rand::rngs::OsRng; // the rand 0.9 re-exported by flock_protocol
let sk = HybridKeypair::generate(&mut rng); // X25519 + ML-KEM-768 dual-stack key
let pk = sk.public();

let (shared, ct) = kem::encapsulate(&pk, &mut rng); // one-time shared secret + 1120B hybrid ciphertext
let shared2 = kem::decapsulate(&sk, &ct).unwrap();
assert_eq!(shared.as_bytes(), shared2.as_bytes());
```

### 2. File envelope v2: seal / open (streaming, constant memory)

```rust
use std::io::Cursor;
use flock_protocol::envelope::{open_v2, seal_v2};
use flock_protocol::kem::HybridKeypair;

let sk = HybridKeypair::generate(&mut rand::rngs::OsRng);
let plain = b"any file content, streamed in 4 MiB segments".to_vec();

// Sealing: 1137B header (ver | envelope_id | HybridCt) + segmented AEAD
let mut sealed = Vec::new();
let info = seal_v2(&sk.public(), Cursor::new(&plain), &mut sealed).unwrap();

// Opening: per-segment validation with the same segment-index AAD;
// returns the plaintext byte count
let mut out = Vec::new();
let n = open_v2(&sk, sealed.as_slice(), &mut out).unwrap();
assert_eq!(n as usize, plain.len());
```

### 3. Tunnel session: initiate (1-RTT) / respond

session/mux is generic over any `AsyncRead + AsyncWrite` — this example
uses an in-memory duplex; in production it is TCP / a relay / a QUIC
stream adapter, with zero changes to the carrier protocol.

```rust
use ed25519_dalek::SigningKey;
use flock_protocol::mux::Prio;
use flock_protocol::session::{
    initiate, respond, ClusterId, DeviceRecord, DeviceStaticKeys, InMemoryDirectory,
    ServerId, ServerIdentity, ServerPin, TunnelConfig,
};

#[tokio::main]
async fn main() {
    // Server identity: the cluster root (ed25519) enrolls one server
    let root = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let cluster = ClusterId(rand::random());
    let server =
        ServerIdentity::enroll(&root, cluster, ServerId(rand::random()), "relay.example:23000");

    // Client device keys + the server device directory (a persistent
    // directory in production)
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    dir.register(DeviceRecord {
        device_x25519: device.x25519_public(),
        device_ed25519: device.ed25519_public(),
    });

    // Client pin (from trust::PinStore / InviteFile v3 in production)
    let pin = ServerPin {
        cluster_id: cluster,
        cluster_root_pub: root.verifying_key(),
        entry: server.entry.clone(),
    };

    // Dial: anything AsyncRead + AsyncWrite + Unpin + Send + 'static
    let (a, b) = tokio::io::duplex(64 * 1024);
    let srv = tokio::spawn(async move {
        respond(b, &server, dir, TunnelConfig::default()).await
    });
    let client = initiate(a, &device, &pin, TunnelConfig::default())
        .await
        .unwrap();
    let server_side = srv.await.unwrap().unwrap();

    // yamux multiplexing inside the tunnel: open a stream, the server
    // accepts
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cstream = client.open_stream(Prio::Normal).await.unwrap();
    cstream.write_all(b"ping").await.unwrap();

    let mut sstream = server_side.accept_stream().await.unwrap();
    let mut buf = [0u8; 4];
    sstream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}
```

TOFU first connect (when unpinned): `initiate_tofu(...)` → display the
root fingerprint (`root_fingerprint`) → `confirm()`; the pin lands via
`trust::confirm_tofu_and_pin`. TOFU does not defend against an online
MITM at first login (the same class of limitation as SSH known_hosts) —
organizational settings must use the strong invite-file path
(`trust::InviteFile` v3).

## Security contract: two nonce profiles, never interchangeable

**Envelope profile (envelope v2) — one-time k + fresh random 96-bit
nonce per segment**: k is derived by a one-time hybrid KEM (fresh
ephemeral shares per envelope); a single envelope's segment count ≪
2^32, so the random nonce stays within the SP 800-38D random-IV bound.
Suitable only for offline files/one-shot payloads — reusing k across
many messages or a long-lived stream is a violation.

**Tunnel profile (session record layer) — counter nonce, random
forbidden**: nonce = 32-bit zeros ‖ 64-bit LE counter (WireGuard shape),
independent keys and counters per direction; TCP is ordered ⇒ the
receiver rebuilds it implicitly as "previous + 1"; duplicates/rollbacks
manifest as authentication failures and count toward forgery
(forge_limit defaults to 100; reaching it tears down the link). Key
lifetime dual thresholds: rekey (2^60 messages / 120s) — whichever comes
first; the hard cap (2^64−2^13−1 messages / 180s) zeroes the keys and
tears down on trigger.

The device signature covers all sent fields of I1 plus the protocol
context (cluster_id / expected server identity) — UKS tampering vectors
necessarily fail.

## Version lockdown

This crate re-exports its pinned `ed25519_dalek` / `x25519_dalek` /
`ml_kem` / `opaque_ke` / `rand` (plus `rsa` under `legacy`); downstream
crates must not pull other versions — reuse these directly to avoid
type incompatibilities.

## Build and verification

```sh
cargo test --all-features        # full test suite
cargo check --no-default-features
cargo check --no-default-features --features wasm --target wasm32-unknown-unknown
cargo clippy --all-features -- -D warnings
cargo fmt --all -- --check
cargo bench --no-run             # bench compile check
```

The getrandom custom-backend cfg for the wasm32 target is provided by
the repository's `.cargo/config.toml`; the entropy bridge lives in
`src/wasm_bridge.rs`. Cross-building to wasm32 with everything (zstd
included) needs a clang with a wasm backend; the core protocol surface
at `--no-default-features --features wasm` has zero C dependencies.

## Security advisories

For the security-vulnerability reporting channel and response cadence,
see [SECURITY.md](SECURITY.md) — please do not report security issues
through public issues.

## License

Dual-licensed under either, at your option:

- [LICENSE-APACHE-2.0](LICENSE-APACHE-2.0) (Apache License 2.0)
- [LICENSE-MIT](LICENSE-MIT) (MIT License)

Unless you explicitly state otherwise, any intentional contribution you
submit to this repository is licensed under both licenses above, with no
additional terms.
