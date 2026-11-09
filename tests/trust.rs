//! trust 集成测试（docs/design.md §7-M1 完成标准，P0-5 守门用例）。
//!
//! - 邀请文件 v3 → **同一根下多端点 ServerEntry 各自完成 1-RTT 封装**（多服务器钉扎模型
//!   §1.3.3f 的守门用例）：逐端点 session::initiate + respond，proxy 断言客户端首帧
//!   必为 I1（0x03）——I0 不出现；
//! - load_invite/save_invite 文件路径：往返 + 根签名不匹配拒载入 + v2 拒收；
//! - TOFU → PinStore 落地闭环（trust::confirm_tofu_and_pin：首钉 + 二连钉扎比对）。

use std::time::Duration;

use flock_protocol::session::{
    initiate, initiate_tofu, respond, DeviceRecord, DeviceStaticKeys, InMemoryDirectory, ServerId,
    ServerIdentity, TunnelConfig, RT_I1,
};
use flock_protocol::trust::{
    confirm_tofu_and_pin, load_invite, save_invite, ClusterDirectory, InviteFile, PinStore,
    PinVerdict, TrustError, INVITE_DEFAULT_TTL_SECS,
};
use flock_protocol::{ed25519_dalek, rand};

use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn duplex_pair() -> (DuplexStream, DuplexStream) {
    tokio::io::duplex(256 * 1024)
}

/// 首帧窥探代理：记录客户端首个线上帧类型后双向透明转发。
async fn first_frame_probe(
    client_side: DuplexStream,
    server_side: DuplexStream,
) -> tokio::sync::oneshot::Receiver<u8> {
    let (mut c_rd, mut c_wr) = tokio::io::split(client_side);
    let (mut s_rd, mut s_wr) = tokio::io::split(server_side);
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        // c→s：读首帧记录类型并转发，随后透明
        let mut hdr = [0u8; 5];
        if c_rd.read_exact(&mut hdr).await.is_ok() {
            let len = u32::from_le_bytes(hdr[..4].try_into().expect("4B")) as usize;
            let mut body = vec![0u8; len - 1];
            if c_rd.read_exact(&mut body).await.is_ok() {
                let _ = tx.send(hdr[4]);
                let _ = s_wr.write_all(&hdr).await;
                let _ = s_wr.write_all(&body).await;
                let _ = tokio::io::copy(&mut c_rd, &mut s_wr).await;
            }
        }
    });
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut s_rd, &mut c_wr).await;
    });
    rx
}

struct Cluster {
    root: SigningKey,
    servers: Vec<ServerIdentity>,
    directory: ClusterDirectory,
}

fn cluster_of(n: usize) -> Cluster {
    let root = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let cluster_id = flock_protocol::session::ClusterId(rand::random());
    let mut servers = Vec::new();
    let mut entries = Vec::new();
    for i in 0..n {
        let s = ServerIdentity::enroll(
            &root,
            cluster_id,
            ServerId([i as u8 + 1; 16]),
            &format!("relay-{i}.example:2300{i}"),
        );
        entries.push(s.entry.clone());
        servers.push(s);
    }
    let directory = ClusterDirectory::issue(&root, cluster_id, 1, entries);
    Cluster {
        root,
        servers,
        directory,
    }
}

/// 单端点 1-RTT 对拨：pin 来自目录条目；断言首帧 == I1 且数据回显可用。
async fn endpoint_1rtt(
    cluster: &Cluster,
    idx: usize,
    device: &DeviceStaticKeys,
) -> flock_protocol::session::Tunnel {
    let entry = cluster.directory.servers[idx].clone();
    let server = &cluster.servers[idx];

    let mut dir = InMemoryDirectory::new();
    dir.register(DeviceRecord {
        device_x25519: device.x25519_public(),
        device_ed25519: device.ed25519_public(),
    });

    let (client_io, proxy_c) = duplex_pair();
    let (proxy_s, server_io) = duplex_pair();
    let probe = first_frame_probe(proxy_c, proxy_s).await;

    let server_ident = flock_protocol::session::ServerIdentity {
        cluster_id: server.cluster_id,
        server_id: server.server_id,
        identity: SigningKey::from_bytes(&server.identity.to_bytes()),
        static_hybrid: flock_protocol::kem::HybridKeypair::from_bytes(
            &server.static_hybrid.to_bytes(),
        )
        .expect("sk"),
        entry: server.entry.clone(),
        root_pub: server.root_pub,
        entry_sig: server.entry_sig,
    };
    let srv = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            respond(server_io, &server_ident, dir, TunnelConfig::default()),
        )
        .await
        .expect("respond timeout")
        .expect("respond")
    });
    let pin = flock_protocol::session::ServerPin {
        cluster_id: cluster.directory.cluster_id,
        cluster_root_pub: cluster.root.verifying_key(),
        entry,
    };
    let dev = DeviceStaticKeys::from_bytes(&device.to_bytes());
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(client_io, &dev, &pin, TunnelConfig::default()),
        )
        .await
        .expect("initiate timeout")
        .expect("initiate")
    });
    let client = cli.await.expect("cli task");
    let server_tunnel = srv.await.expect("srv task");

    // 守门断言 1：客户端首帧必为 I1（已钉扎形态；I0 不出现）
    let first = tokio::time::timeout(Duration::from_secs(5), probe)
        .await
        .expect("probe timeout")
        .expect("probe dropped");
    assert_eq!(first, RT_I1, "端点 {idx}：任意端点均 1-RTT，I0 不得出现");

    // 守门断言 2：握手后数据面可用
    let mut cs = client
        .open_stream(flock_protocol::mux::Prio::Normal)
        .await
        .expect("open");
    let msg = format!("endpoint-{idx}");
    cs.write_all(msg.as_bytes()).await.expect("write");
    let mut ss = tokio::time::timeout(Duration::from_secs(5), server_tunnel.accept_stream())
        .await
        .expect("accept timeout")
        .expect("stream");
    let mut buf = vec![0u8; msg.len()];
    ss.read_exact(&mut buf).await.expect("read");
    assert_eq!(buf, msg.as_bytes());

    server_tunnel.shutdown().await;
    client
}

#[tokio::test]
async fn invite_multi_endpoint_all_1rtt() {
    let cluster = cluster_of(3);
    let device = DeviceStaticKeys::generate();

    // 邀请文件 v3 落盘/读回
    let now = flock_protocol::trust::now_unix();
    let invite = InviteFile::issue(
        &cluster.root,
        cluster.directory.cluster_id,
        1,
        cluster.directory.servers.clone(),
        now + INVITE_DEFAULT_TTL_SECS,
        rand::random::<[u8; 16]>(),
    );
    let path = std::env::temp_dir().join(format!("flock-invite-{}.bin", rand::random::<u64>()));
    save_invite(&path, &invite).expect("save");
    let loaded = load_invite(&path).expect("load");
    let _ = std::fs::remove_file(&path);
    assert_eq!(loaded.directory.servers.len(), 3);
    assert!(
        loaded.verify_against(&cluster.root.verifying_key()),
        "对照签发根验签"
    );

    // 同一根下每个端点：从**目录条目**构造 pin，各自完成 1-RTT
    for i in 0..3 {
        let client = endpoint_1rtt(&cluster, i, &device).await;
        client.shutdown().await;
    }
}

#[tokio::test]
async fn invite_file_rejects_tampered_and_old_versions() {
    let cluster = cluster_of(1);
    let invite = InviteFile::issue(
        &cluster.root,
        cluster.directory.cluster_id,
        1,
        cluster.directory.servers.clone(),
        flock_protocol::trust::now_unix() + 3600,
        [7; 16],
    );
    let bytes = invite.to_bytes();

    // 条目被篡改：按内容定位第一 entry 的 relay_endpoint 串，翻转其中一个字节
    // （仍是合法 UTF-8/合法结构）⇒ 结构解析可过而根验签必拒。
    let ep = cluster.directory.servers[0].relay_endpoint.as_bytes();
    let pos = bytes
        .windows(ep.len())
        .position(|w| w == ep)
        .expect("端点串必在邀请字节中");
    let mut tampered = bytes.clone();
    tampered[pos] = if tampered[pos] == b'r' { b'R' } else { b'r' };
    let path = std::env::temp_dir().join(format!("flock-invite-bad-{}.bin", rand::random::<u64>()));
    std::fs::write(&path, &tampered).expect("write tampered");
    let err = load_invite(&path).expect_err("条目被篡改 ⇒ 拒载入");
    let _ = std::fs::remove_file(&path);
    assert!(matches!(err, TrustError::BadSignature), "got {err:?}");

    // v2 版本字节 ⇒ 拒收（v1/v2 不再接受）
    let mut v2 = bytes;
    v2[0] = 2;
    assert!(matches!(
        InviteFile::from_bytes(&v2).unwrap_err(),
        TrustError::UnsupportedInviteVersion(2)
    ));
}

#[tokio::test]
async fn tofu_bootstrap_lands_in_pinstore() {
    let cluster = cluster_of(1);
    let server = &cluster.servers[0];
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    dir.register(DeviceRecord {
        device_x25519: device.x25519_public(),
        device_ed25519: device.ed25519_public(),
    });

    // 首连 TOFU：confirm_tofu_and_pin 落钉扎
    let (a, b) = duplex_pair();
    let server_ident = flock_protocol::session::ServerIdentity {
        cluster_id: server.cluster_id,
        server_id: server.server_id,
        identity: SigningKey::from_bytes(&server.identity.to_bytes()),
        static_hybrid: flock_protocol::kem::HybridKeypair::from_bytes(
            &server.static_hybrid.to_bytes(),
        )
        .expect("sk"),
        entry: server.entry.clone(),
        root_pub: server.root_pub,
        entry_sig: server.entry_sig,
    };
    let srv = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            respond(b, &server_ident, dir, TunnelConfig::default()),
        )
        .await
        .expect("timeout")
        .expect("respond")
    });
    let boot = tokio::time::timeout(
        Duration::from_secs(10),
        initiate_tofu(a, device, TunnelConfig::default()),
    )
    .await
    .expect("timeout")
    .expect("bootstrap");
    let expected_fp = boot.root_fingerprint();

    let mut pins = PinStore::new();
    let client = confirm_tofu_and_pin(boot, &mut pins)
        .await
        .expect("confirm+pin");
    assert_eq!(
        pins.verify_pinned(&cluster.directory.cluster_id, &cluster.root.verifying_key()),
        PinVerdict::Match,
        "TOFU 确认后根公钥已钉扎"
    );
    assert_eq!(
        flock_protocol::session::fingerprint_ed25519(
            pins.pinned_root(&cluster.directory.cluster_id).unwrap()
        ),
        expected_fp,
        "钉扎的即展示指纹的本体"
    );
    let server_tunnel = srv.await.expect("srv");
    client.shutdown().await;
    server_tunnel.shutdown().await;

    // 二连：同根 ⇒ Match（不再 TOFU）；换根 ⇒ RootChanged 告警路径
    let bad = SigningKey::from_bytes(&[9; 32]);
    match pins.verify_pinned(&cluster.directory.cluster_id, &bad.verifying_key()) {
        PinVerdict::Mismatch { .. } => {}
        v => panic!("换根必须 Mismatch（显式告警路径），got {v:?}"),
    }
}
