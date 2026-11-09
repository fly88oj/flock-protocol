//! session/mux 集成测试（docs/design.md §7-M1 完成标准）。
//!
//! 覆盖向量：
//! - 握手双形态全向量：已钉扎 1-RTT（duplex + TcpStream 对拨）；TOFU 首连 2-RTT
//!   （I0→R0→I1/R1）状态机含负向（伪造入群凭证/伪造 R0 签名/错序消息）；
//! - UKS/绑定失败向量：篡改协议上下文（cluster_id）或换服务器身份 ⇒ 验签必失败（§1.3.3c）；
//! - DeviceDirectory 三态：NotFound/Revoked/Active（前两者拒且同一不透明错误）；
//! - AEAD 协商：交集取档 + 无交集拒；
//! - 抗重放（proxy 字节级重放已封记录）与伪造断链（100 次断链）；
//! - 时钟注入：120s 触发 rekey（双侧 epoch 推进 + rekey 后数据通）、180s 硬拒绝；
//! - mux：流回显、显式 finish()/FIN、禁隐式 shutdown、PacketChannel 帧边界、并发流。

use std::time::Duration;

use flock_protocol::mux::Prio;
use flock_protocol::session::{
    fingerprint_ed25519, initiate, initiate_tofu, respond, AeadChoice, AeadPreference, CloseReason,
    ClusterId, DeviceId, DeviceRecord, DeviceStaticKeys, InMemoryDirectory, ManualClock, ServerId,
    ServerIdentity, ServerPin, SessionError, Tunnel, TunnelConfig, RT_DATA, RT_I0, RT_I1, RT_R1,
    RT_REKEY_RESP,
};
use flock_protocol::{ed25519_dalek, rand};

use ed25519_dalek::SigningKey;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

// ============================================================================
// 装配
// ============================================================================

struct Fix {
    root: SigningKey,
    cluster: ClusterId,
    server: ServerIdentity,
}

fn fixture() -> Fix {
    let root = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let cluster = ClusterId(rand::random());
    let server = ServerIdentity::enroll(
        &root,
        cluster,
        ServerId(rand::random()),
        "relay.example:23000",
    );
    Fix {
        root,
        cluster,
        server,
    }
}

fn register(dir: &mut InMemoryDirectory, device: &DeviceStaticKeys) {
    dir.register(DeviceRecord {
        device_x25519: device.x25519_public(),
        device_ed25519: device.ed25519_public(),
    });
}

fn pin_of(fix: &Fix) -> ServerPin {
    ServerPin {
        cluster_id: fix.cluster,
        cluster_root_pub: fix.root.verifying_key(),
        entry: fix.server.entry.clone(),
    }
}

fn duplex_pair() -> (DuplexStream, DuplexStream) {
    tokio::io::duplex(256 * 1024)
}

/// 标准 1-RTT 会话对（duplex 对拨 + InMemory 目录）。
async fn session_pair() -> (Tunnel, Tunnel) {
    session_pair_cfg(TunnelConfig::default(), TunnelConfig::default()).await
}

async fn session_pair_cfg(client_cfg: TunnelConfig, server_cfg: TunnelConfig) -> (Tunnel, Tunnel) {
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);

    let (a, b) = duplex_pair();
    let pin = pin_of(&fix);
    let server = fix.server;
    let srv = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            respond(b, &server, dir, server_cfg),
        )
        .await
        .expect("respond timeout")
        .expect("respond")
    });
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(a, &device, &pin, client_cfg),
        )
        .await
        .expect("initiate timeout")
        .expect("initiate")
    });
    (cli.await.expect("cli task"), srv.await.expect("srv task"))
}

async fn read_frame(r: &mut DuplexStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr).await?;
    let len = u32::from_le_bytes(hdr[..4].try_into().expect("4B")) as usize;
    let mut body = vec![0u8; len - 1];
    r.read_exact(&mut body).await?;
    Ok((hdr[4], body))
}

async fn write_frame(w: &mut DuplexStream, rtype: u8, body: &[u8]) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(5 + body.len());
    buf.extend_from_slice(&((body.len() + 1) as u32).to_le_bytes());
    buf.push(rtype);
    buf.extend_from_slice(body);
    w.write_all(&buf).await?;
    w.flush().await
}

async fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("wait_until 超时: {what}");
}

/// 通用「首帧后驻留」代理：c→s 透明；s→c 只回放第一帧后停读（连接保持打开）。
async fn park_after_first_frame(client_side: DuplexStream, server_side: DuplexStream) {
    // 方向：c_rd（读客户端）→ s_wr（写服务端）；s_rd（读服务端）→ c_wr（写客户端）
    let (mut c_rd, mut c_wr) = tokio::io::split(client_side);
    let (mut s_rd, mut s_wr) = tokio::io::split(server_side);
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut c_rd, &mut s_wr).await;
    });
    tokio::spawn(async move {
        let mut hdr = [0u8; 5];
        let _ = s_rd.read_exact(&mut hdr).await;
        let len = u32::from_le_bytes(hdr[..4].try_into().expect("4B")) as usize;
        let mut body = vec![0u8; len - 1];
        let _ = s_rd.read_exact(&mut body).await;
        let _ = c_wr.write_all(&hdr).await;
        let _ = c_wr.write_all(&body).await;
        let _ = c_wr.flush().await;
        let _: () = std::future::pending().await; // 驻留：s→c 不再转发、不再读
    });
}

// ============================================================================
// 已钉扎 1-RTT 握手 + mux 数据面
// ============================================================================

#[tokio::test]
async fn pinned_1rtt_handshake_and_stream_echo() {
    let (client, server) = session_pair().await;

    // 1-RTT 佐证：握手本身不消耗记录层计数（yamux 启动引导帧 = 首批记录；
    // 客户端首条线上消息必为 I1 由 pinned_i1_tamper_rejected_by_aad 的 proxy 断言覆盖）
    let st = client.stats();
    assert_eq!(st.epoch, 0);
    assert!(st.closed.is_none());
    assert!(
        st.sent_records <= 2,
        "yamux 引导帧之外无多余记录: {}",
        st.sent_records
    );
    assert!(client.stats().closed.is_none());
    assert!(
        client.peer_server_id().is_some(),
        "客户端可索引对端服务器（漫游模型）"
    );
    assert!(server.peer_device_id().is_some());

    let mut cs = client.open_stream(Prio::Normal).await.expect("open_stream");
    cs.write_all(b"hello over yamux").await.expect("write");
    let mut ss = tokio::time::timeout(Duration::from_secs(5), server.accept_stream())
        .await
        .expect("accept timeout")
        .expect("stream");
    let mut buf = [0u8; 16];
    ss.read_exact(&mut buf).await.expect("read");
    assert_eq!(&buf, b"hello over yamux");
    ss.write_all(&buf).await.expect("echo");
    cs.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"hello over yamux");

    assert!(client.stats().sent_records >= 1);
    assert!(server.stats().received_records >= 1);

    // 显式 finish() ⇒ 对端观察到 FIN/EOF（禁半关闭：yamux FIN 是唯一单向结束路径）
    cs.finish().await.expect("client finish");
    let mut eof = [0u8; 4];
    let n = tokio::time::timeout(Duration::from_secs(5), ss.read_some(&mut eof))
        .await
        .expect("eof timeout");
    assert_eq!(n.expect("read_some"), 0, "对端观察到 FIN/EOF");

    client.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn pinned_handshake_over_tcp_pair() {
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let pin = pin_of(&fix);
    let server = fix.server;
    let srv = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.expect("accept");
        respond(sock, &server, dir, TunnelConfig::default())
            .await
            .expect("respond")
    });
    let cli = tokio::spawn(async move {
        let sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(sock, &device, &pin, TunnelConfig::default()),
        )
        .await
        .expect("timeout")
        .expect("initiate")
    });
    let (client, server) = (cli.await.expect("cli"), srv.await.expect("srv"));

    // TcpStream 对拨：PacketChannel 帧边界（§3.6 [u16 len][ip packet]）
    let mut cpc = client.open_packet_channel().await.expect("packet channel");
    cpc.send(&[0u8; 1]).await.expect("SYN 首包"); // yamux SYN 惰性：首帧携带
    let accepted = tokio::time::timeout(Duration::from_secs(5), server.accept_stream())
        .await
        .expect("accept timeout")
        .expect("stream");
    let mut spc = flock_protocol::mux::PacketChannel::from_stream(accepted);
    let mut first = true;
    for size in [1usize, 1280, 60000] {
        let pkt: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        if !first {
            cpc.send(&pkt).await.expect("send");
        }
        first = false;
        let got = spc.recv().await.expect("recv");
        assert_eq!(got.len(), size, "帧边界保持");
        assert_eq!(got, pkt);
    }
    client.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn packet_channel_recv_stream_and_finish() {
    use futures::StreamExt;
    let (client, server) = session_pair().await;
    let mut cpc = client.open_packet_channel().await.expect("client pc");
    cpc.send(&[1, 2, 3]).await.expect("c send（携 SYN）");
    let accepted = tokio::time::timeout(Duration::from_secs(5), server.accept_stream())
        .await
        .expect("accept")
        .expect("stream");
    let mut spc = flock_protocol::mux::PacketChannel::from_stream(accepted);

    // 双向包

    assert_eq!(spc.recv().await.expect("s recv"), vec![1, 2, 3]);
    spc.send(&[4, 5]).await.expect("s send");
    assert_eq!(cpc.recv().await.expect("c recv"), vec![4, 5]);

    // recv_stream 迭代：对端 finish 后以 None 收尾
    spc.finish().await.expect("s finish");
    let mut rx = cpc.recv_stream();
    let first = rx.next().await;
    assert!(first.is_none(), "对端 FIN ⇒ 流结束（无残包）");
    client.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn multiple_streams_and_prio_passthrough() {
    let (client, server) = session_pair().await;
    let mut s1 = client.open_stream(Prio::Control).await.expect("s1");
    let mut s2 = client.open_stream(Prio::Normal).await.expect("s2");
    assert_eq!(s1.prio(), Prio::Control);

    // yamux SYN 惰性（首帧携带）：先写再 accept
    s1.write_all(b"one").await.expect("w1");
    s2.write_all(b"two").await.expect("w2");
    let mut a1 = tokio::time::timeout(Duration::from_secs(5), server.accept_stream())
        .await
        .expect("t")
        .expect("a1");
    let mut a2 = tokio::time::timeout(Duration::from_secs(5), server.accept_stream())
        .await
        .expect("t")
        .expect("a2");
    let mut m = [0u8; 3];
    a2.read_exact(&mut m).await.expect("r2");
    assert_eq!(&m, b"two");
    a1.read_exact(&mut m).await.expect("r1");
    assert_eq!(&m, b"one");

    client.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn implicit_shutdown_disabled_on_stream() {
    let (client, _server) = session_pair().await;
    let mut s = client.open_stream(Prio::Normal).await.expect("stream");
    // futures AsyncWriteExt::close 映射 poll_close ⇒ 必须拒绝（禁半关闭：单向结束只有 finish()）
    let r = futures::AsyncWriteExt::close(&mut s).await;
    assert!(r.is_err(), "隐式 shutdown 必须被拒");
    drop(s);
    client.shutdown().await;
}

// ============================================================================
// UKS / 绑定失败向量（§1.3.3c 签名覆盖契约）
// ============================================================================

#[tokio::test]
async fn uks_wrong_server_identity_rejected() {
    // 客户端钉扎 server A，I1 却被交给 server B（MITM 改道）：
    // 设备签名覆盖「期望身份 = A」⇒ B 处必须失败。
    let root = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let cluster = ClusterId(rand::random());
    let server_a = ServerIdentity::enroll(&root, cluster, ServerId(rand::random()), "a.example:1");
    let server_b = ServerIdentity::enroll(&root, cluster, ServerId(rand::random()), "b.example:2");

    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);

    let (a, b) = duplex_pair();
    let srv =
        tokio::spawn(async move { respond(b, &server_b, dir, TunnelConfig::default()).await });
    let pin_a = ServerPin {
        cluster_id: cluster,
        cluster_root_pub: root.verifying_key(),
        entry: server_a.entry.clone(),
    };
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(a, &device, &pin_a, TunnelConfig::default()),
        )
        .await
    });
    let srv_err = srv.await.expect("task").expect_err("respond 必拒");
    let _ = cli.await.expect("cli task").expect("timeout");

    match &srv_err {
        SessionError::Handshake(stage) => {
            assert!(
                stage.contains("expected-server-identity") || stage.contains("device signature"),
                "UKS 向量失败于身份/签名检查，got {stage}"
            );
        }
        other => panic!("期望 Handshake 错误，got {other:?}"),
    }
}

#[tokio::test]
async fn uks_tampered_cluster_context_rejected() {
    // 篡改协议上下文：pin 的 cluster_id 与服务器不一致 ⇒ 设备签名覆盖失配。
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);

    let (a, b) = duplex_pair();
    let pin = pin_of(&fix);
    let server = fix.server;
    let srv = tokio::spawn(async move { respond(b, &server, dir, TunnelConfig::default()).await });

    let mut pin = pin;
    pin.cluster_id = ClusterId(rand::random()); // ← 篡改上下文
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(a, &device, &pin, TunnelConfig::default()),
        )
        .await
    });
    let srv_err = srv.await.expect("task").expect_err("必拒");
    let _ = cli.await.expect("cli task").expect("timeout");
    assert!(
        matches!(&srv_err, SessionError::Handshake(s) if s.contains("device signature")),
        "cluster_id 篡改 ⇒ 设备签名验签失败，got {srv_err:?}"
    );
}

#[tokio::test]
async fn pinned_i1_tamper_rejected_by_aad() {
    // I1 已发字段（ml_kem_ct）被字节级篡改 ⇒ AAD 失配 ⇒ 解密失败。
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);

    let (client_io, mut p_client) = duplex_pair();
    let (mut p_server, server_io) = duplex_pair();

    let pin = pin_of(&fix);
    let server = fix.server;
    let srv = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            respond(server_io, &server, dir, TunnelConfig::default()),
        )
        .await
        .expect("timeout")
    });
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(client_io, &device, &pin, TunnelConfig::default()),
        )
        .await
    });
    // 代理：读 I1（断言形态），翻转 ml_ct 首字节转发
    let (t, mut body) = read_frame(&mut p_client).await.expect("first frame");
    assert_eq!(t, RT_I1, "已钉扎形态首帧必为 I1（1-RTT 佐证）");
    assert!(body.len() > 70);
    body[69] ^= 0xFF; // ml_kem_ct 区首字节（AAD 覆盖字段）
    write_frame(&mut p_server, RT_I1, &body)
        .await
        .expect("forward tampered");
    // 双向后续吞掉（各读各的，丢弃即可）
    {
        let (mut cr, _) = tokio::io::split(p_client);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok(n) = cr.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        });
    }
    {
        let (mut sr, _) = tokio::io::split(p_server);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok(n) = sr.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        });
    }
    let srv_out = srv.await.expect("task");
    let srv_err = match srv_out {
        Ok(_) => panic!("篡改后 respond 必须拒绝"),
        Err(e) => e,
    };
    // 客户端侧必失败（EOF/超时皆可——proxy 不转发 EOF，不精确断言其形态）
    let _ = tokio::time::timeout(Duration::from_secs(3), cli).await;
    assert!(
        matches!(&srv_err, SessionError::Handshake(s) if s.contains("i1 payload")),
        "I1 字段篡改 ⇒ AAD 失配解密失败，got {srv_err:?}"
    );
}

// ============================================================================
// DeviceDirectory 三态 + AEAD 协商
// ============================================================================

#[tokio::test]
async fn directory_three_states() {
    // NotFound
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let (a, b) = duplex_pair();
    let pin = pin_of(&fix);
    let server = fix.server;
    let srv = tokio::spawn(async move {
        respond(
            b,
            &server,
            InMemoryDirectory::new(),
            TunnelConfig::default(),
        )
        .await
    });
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(a, &device, &pin, TunnelConfig::default()),
        )
        .await
    });
    let not_found = srv.await.expect("task").expect_err("NotFound 必拒");
    let _ = cli.await.expect("cli").expect("timeout");
    assert!(
        matches!(not_found, SessionError::DeviceRejected),
        "NotFound ⇒ {not_found:?}"
    );

    // Revoked（与 NotFound 同一错误变体——时序对齐/防枚举）
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);
    dir.revoke(&DeviceId::from_ed25519(&device.ed25519_public()), 7);
    let (a, b) = duplex_pair();
    let pin = pin_of(&fix);
    let server = fix.server;
    let srv = tokio::spawn(async move { respond(b, &server, dir, TunnelConfig::default()).await });
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(a, &device, &pin, TunnelConfig::default()),
        )
        .await
    });
    let revoked = srv.await.expect("task").expect_err("Revoked 必拒");
    let _ = cli.await.expect("cli").expect("timeout");
    assert!(
        matches!(revoked, SessionError::DeviceRejected),
        "Revoked ⇒ {revoked:?}"
    );
    assert_eq!(
        std::mem::discriminant(&not_found),
        std::mem::discriminant(&revoked),
        "三态拒绝对齐：NotFound 与 Revoked 不可区分"
    );

    // 公钥失配：注册记录的 X25519 公钥 ≠ 呈现材料 ⇒ 同一不透明拒绝
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);
    dir.register(DeviceRecord {
        device_x25519: DeviceStaticKeys::generate().x25519_public(), // ← 失配
        device_ed25519: device.ed25519_public(),
    });
    let (a, b) = duplex_pair();
    let pin = pin_of(&fix);
    let server = fix.server;
    let srv = tokio::spawn(async move { respond(b, &server, dir, TunnelConfig::default()).await });
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(a, &device, &pin, TunnelConfig::default()),
        )
        .await
    });
    let mismatch = srv.await.expect("task").expect_err("失配必拒");
    let _ = cli.await.expect("cli").expect("timeout");
    assert!(
        matches!(mismatch, SessionError::DeviceRejected),
        "公钥失配 ⇒ {mismatch:?}"
    );

    // Active：正常路径
    let (_c, _s) = session_pair().await;
}

#[tokio::test]
async fn aead_negotiation_intersection_and_failure() {
    // 客户端只持 XChaCha ⇒ 协商取交集为 XChaCha（双方 stats 一致）
    let c_cfg = TunnelConfig {
        aead: AeadPreference::only(AeadChoice::XChaCha20Poly1305),
        ..TunnelConfig::default()
    };
    let (client, server) = session_pair_cfg(c_cfg, TunnelConfig::default()).await;
    assert_eq!(client.stats().aead, AeadChoice::XChaCha20Poly1305);
    assert_eq!(server.stats().aead, AeadChoice::XChaCha20Poly1305);
    let mut cs = client.open_stream(Prio::Normal).await.expect("open");
    cs.write_all(b"xchacha").await.expect("w");
    let mut ss = tokio::time::timeout(Duration::from_secs(5), server.accept_stream())
        .await
        .expect("t")
        .expect("s");
    let mut buf = [0u8; 7];
    ss.read_exact(&mut buf).await.expect("r");
    assert_eq!(&buf, b"xchacha");
    client.shutdown().await;
    server.shutdown().await;

    // 无交集 ⇒ AeadMismatch（服务端 respond 拒）
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);
    let (a, b) = duplex_pair();
    let s_cfg = TunnelConfig {
        aead: AeadPreference::only(AeadChoice::XChaCha20Poly1305),
        ..TunnelConfig::default()
    };
    let pin = pin_of(&fix);
    let server = fix.server;
    let srv = tokio::spawn(async move { respond(b, &server, dir, s_cfg).await });
    let c_cfg = TunnelConfig {
        aead: AeadPreference::only(AeadChoice::Aes256Gcm),
        ..TunnelConfig::default()
    };
    let cli = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), initiate(a, &device, &pin, c_cfg)).await
    });
    let err = srv.await.expect("task").expect_err("无交集必拒");
    let _ = cli.await.expect("cli").expect("timeout");
    assert!(
        matches!(err, SessionError::AeadMismatch),
        "无交集 ⇒ {err:?}"
    );
}

// ============================================================================
// TOFU 首连 2-RTT 状态机
// ============================================================================

#[tokio::test]
async fn tofu_happy_path_i0_r0_i1_r1() {
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);

    let expected_sid = fix.server.entry.server_id;
    let (a, b) = duplex_pair();
    let server = fix.server;
    let srv = tokio::spawn(async move { respond(b, &server, dir, TunnelConfig::default()).await });

    let boot = tokio::time::timeout(
        Duration::from_secs(10),
        initiate_tofu(a, device, TunnelConfig::default()),
    )
    .await
    .expect("timeout")
    .expect("bootstrap");
    // 根指纹展示（用户确认 UI 的数据源）与集群/条目材料
    assert_eq!(
        boot.root_fingerprint(),
        fingerprint_ed25519(&fix.root.verifying_key())
    );
    assert_eq!(boot.cluster_id(), fix.cluster);
    assert_eq!(boot.server_entry().server_id, expected_sid);

    let (client, server_tunnel) = (
        boot.confirm().await.expect("confirm"),
        srv.await.expect("srv").expect("respond"),
    );
    let mut cs = client.open_stream(Prio::Normal).await.expect("open");
    cs.write_all(b"tofu ok").await.expect("w");
    let mut ss = tokio::time::timeout(Duration::from_secs(5), server_tunnel.accept_stream())
        .await
        .expect("t")
        .expect("s");
    let mut buf = [0u8; 7];
    ss.read_exact(&mut buf).await.expect("r");
    assert_eq!(&buf, b"tofu ok");
    client.shutdown().await;
    server_tunnel.shutdown().await;
}

#[tokio::test]
async fn tofu_rejects_forged_enrollment_chain() {
    // 伪造入群凭证：entry_sig 被篡改 ⇒ 根验签失败
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut bad = fix.server;
    let mut sig = bad.entry_sig.to_bytes();
    sig[0] ^= 0x01;
    bad.entry_sig = ed25519_dalek::Signature::from_bytes(&sig);

    let (a, b) = duplex_pair();
    tokio::spawn(async move {
        let _ = respond(b, &bad, InMemoryDirectory::new(), TunnelConfig::default()).await;
    });
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        initiate_tofu(a, device, TunnelConfig::default()),
    )
    .await
    .expect("timeout")
    .expect_err("伪造凭证必拒");
    assert!(
        matches!(&err, SessionError::Handshake(s) if s.contains("enrollment signature")),
        "伪造入群凭证 ⇒ {err:?}"
    );

    // 伪造 R0 身份签名：R0 用另一身份钥签 ⇒ entry.identity_pub 验签失败
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut bad2 = fix.server;
    bad2.identity = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let (a, b) = duplex_pair();
    tokio::spawn(async move {
        let _ = respond(b, &bad2, InMemoryDirectory::new(), TunnelConfig::default()).await;
    });
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        initiate_tofu(a, device, TunnelConfig::default()),
    )
    .await
    .expect("timeout")
    .expect_err("伪造 R0 签名必拒");
    assert!(
        matches!(&err, SessionError::Handshake(s) if s.contains("server identity signature")),
        "伪造 R0 身份签名 ⇒ {err:?}"
    );
}

#[tokio::test]
async fn tofu_state_machine_rejects_out_of_order() {
    // 客户端处于 TOFU（发 I0 等 R0），却收到 R1 ⇒ 状态机拒
    let device = DeviceStaticKeys::generate();
    let (a, mut fake) = duplex_pair();
    tokio::spawn(async move {
        let (t, _i0) = read_frame(&mut fake).await.expect("read I0");
        assert_eq!(t, RT_I0, "TOFU 首帧必为 I0");
        write_frame(&mut fake, RT_R1, &[0u8; 8])
            .await
            .expect("write R1");
        let mut buf = [0u8; 512];
        loop {
            match fake.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        initiate_tofu(a, device, TunnelConfig::default()),
    )
    .await
    .expect("timeout")
    .expect_err("TOFU 首步非 R0 必拒");
    assert!(
        matches!(err, SessionError::UnexpectedMessage(t) if t == RT_R1),
        "TOFU 状态机错序拒 ⇒ {err:?}"
    );

    // 服务端状态机：首帧非 I0/I1（如 DATA）⇒ 拒
    let fix = fixture();
    let (mut c, b) = duplex_pair();
    let srv = tokio::spawn(async move {
        let server = fix.server;
        respond(
            b,
            &server,
            InMemoryDirectory::new(),
            TunnelConfig::default(),
        )
        .await
    });
    write_frame(&mut c, RT_DATA, &[0u8; 32])
        .await
        .expect("write DATA");
    let err = srv.await.expect("task").expect_err("非握手首帧必拒");
    assert!(
        matches!(err, SessionError::UnexpectedMessage(t) if t == RT_DATA),
        "respond 状态机拒 ⇒ {err:?}"
    );
}

// ============================================================================
// 时钟注入：rekey（120s）/ 硬拒绝（180s）/ 死链（3×keepalive）
// ============================================================================

#[tokio::test]
async fn clock_injection_rekey_both_sides() {
    use std::sync::Arc;
    let clock = Arc::new(ManualClock::new());
    // keepalive 放大隔离死链判定：注入时钟一次前拨 119s，若 keepalive=10s 则
    // 3×keepalive 静默判定先于 rekey 触发（死链语义由 keepalive_deadlink_detection 覆盖）。
    let c_cfg = TunnelConfig {
        clock: clock.clone(),
        keepalive: Duration::from_secs(3600),
        ..TunnelConfig::default()
    };
    let s_cfg = TunnelConfig {
        clock: clock.clone(),
        keepalive: Duration::from_secs(3600),
        ..TunnelConfig::default()
    };

    let (client, server) = session_pair_cfg(c_cfg, s_cfg).await;
    assert_eq!(client.stats().epoch, 0);

    clock.advance(Duration::from_secs(119));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(client.stats().epoch, 0, "119s 不触发 rekey");

    clock.advance(Duration::from_secs(2));
    wait_until("双侧 epoch → 1", || {
        client.stats().epoch == 1 && server.stats().epoch == 1
    })
    .await;
    assert_eq!(client.stats().rekeys, 1);
    assert_eq!(server.stats().rekeys, 1);

    // rekey 后数据照常（计数器随新密钥重置）
    let mut cs = client
        .open_stream(Prio::Normal)
        .await
        .expect("open after rekey");
    cs.write_all(b"post-rekey").await.expect("w");
    let mut ss = tokio::time::timeout(Duration::from_secs(5), server.accept_stream())
        .await
        .expect("t")
        .expect("s");
    let mut buf = [0u8; 10];
    ss.read_exact(&mut buf).await.expect("r");
    assert_eq!(&buf, b"post-rekey");

    client.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn clock_injection_hard_reject_180s() {
    use std::sync::Arc;
    // client ⇄ park-proxy ⇄ server：REKEY_RESP 永远到不了客户端但连接不关 ⇒ 181s 注入
    // 时钟触发硬拒绝。
    let clock = Arc::new(ManualClock::new());
    let c_cfg = TunnelConfig {
        clock: clock.clone(),
        keepalive: Duration::from_secs(3600), // 隔离 DeadLink 判定
        ..TunnelConfig::default()
    };

    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);

    let (client_io, proxy_c) = duplex_pair();
    let (proxy_s, server_io) = duplex_pair();
    park_after_first_frame(proxy_c, proxy_s).await;

    let pin = pin_of(&fix);
    let server = fix.server;
    let srv = tokio::spawn(async move {
        respond(server_io, &server, dir, TunnelConfig::default())
            .await
            .expect("respond")
    });
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(client_io, &device, &pin, c_cfg),
        )
        .await
        .expect("timeout")
        .expect("initiate")
    });
    let client = cli.await.expect("cli task");

    clock.advance(Duration::from_secs(121)); // REKEY_INIT 发出（RESP 被吞）
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(client.stats().epoch, 0, "RESP 被吞 ⇒ 纪元不进");
    assert!(client.stats().closed.is_none());

    clock.advance(Duration::from_secs(60)); // 181s：硬拒绝
    wait_until("180s 硬拒绝", || client.stats().closed.is_some()).await;
    let st = client.stats();
    assert_eq!(st.closed, Some(CloseReason::RejectAfter), "硬拒绝原因");
    assert_eq!(st.epoch, 0);
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn keepalive_deadlink_detection() {
    use std::sync::Arc;
    // keepalive 1s（注入时钟）+ s→c 停读 ⇒ 3×keepalive 无入站判死链。
    let clock = Arc::new(ManualClock::new());
    let c_cfg = TunnelConfig {
        clock: clock.clone(),
        keepalive: Duration::from_secs(1),
        ..TunnelConfig::default()
    };

    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);

    let (client_io, proxy_c) = duplex_pair();
    let (proxy_s, server_io) = duplex_pair();
    park_after_first_frame(proxy_c, proxy_s).await;

    let pin = pin_of(&fix);
    let server = fix.server;
    let srv = tokio::spawn(async move {
        respond(server_io, &server, dir, TunnelConfig::default())
            .await
            .expect("respond")
    });
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(client_io, &device, &pin, c_cfg),
        )
        .await
        .expect("timeout")
        .expect("initiate")
    });
    let client = cli.await.expect("cli");

    clock.advance(Duration::from_millis(3400)); // > 3×1s 无入站
    wait_until("死链检测", || client.stats().closed.is_some()).await;
    assert_eq!(client.stats().closed, Some(CloseReason::DeadLink));
    drop(client);
    let _ = srv.await;
}

// ============================================================================
// 伪造断链与抗重放（注入已封记录）
// ============================================================================

/// c→s 侧：转发 I1 后注入 `garbage_n` 条合法帧长但密文随机的记录，其余透明。
async fn forge_proxy(client_side: DuplexStream, server_side: DuplexStream, garbage_n: u32) {
    let (mut c_rd, mut c_wr) = tokio::io::split(client_side);
    let (mut s_rd, mut s_wr) = tokio::io::split(server_side);
    // s→c 透明（读服务端 → 写客户端）
    {
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut s_rd, &mut c_wr).await;
        });
    }
    // c→s：I1 转发 + 伪造注入 + 余量透传
    tokio::spawn(async move {
        let mut hdr = [0u8; 5];
        if c_rd.read_exact(&mut hdr).await.is_err() {
            return;
        }
        let len = u32::from_le_bytes(hdr[..4].try_into().expect("4B")) as usize;
        let mut body = vec![0u8; len - 1];
        if c_rd.read_exact(&mut body).await.is_err() {
            return;
        }
        let _ = s_wr.write_all(&hdr).await;
        let _ = s_wr.write_all(&body).await;
        for i in 0..garbage_n {
            // 合法帧长（len=17 = type + 16B 密文）、认证必失败的记录
            let mut frame = Vec::with_capacity(21);
            frame.extend_from_slice(&17u32.to_le_bytes());
            frame.push(RT_DATA);
            let mut junk: [u8; 16] = rand::random();
            junk[0] = i as u8;
            frame.extend_from_slice(&junk);
            let _ = s_wr.write_all(&frame).await;
        }
        let _ = tokio::io::copy(&mut c_rd, &mut s_wr).await;
    });
}

async fn forge_session(garbage_n: u32) -> (Tunnel, Tunnel) {
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);

    let (client_io, proxy_c) = duplex_pair();
    let (proxy_s, server_io) = duplex_pair();
    forge_proxy(proxy_c, proxy_s, garbage_n).await;

    let pin = pin_of(&fix);
    let server = fix.server;
    let srv = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            respond(server_io, &server, dir, TunnelConfig::default()),
        )
        .await
        .expect("timeout")
        .expect("respond")
    });
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(client_io, &device, &pin, TunnelConfig::default()),
        )
        .await
        .expect("timeout")
        .expect("initiate")
    });
    (cli.await.expect("cli"), srv.await.expect("srv"))
}

#[tokio::test]
async fn forge_limit_breaks_link_at_100() {
    let (client, server) = forge_session(100).await;
    wait_until("100 次伪造断链", || server.stats().closed.is_some()).await;
    let st = server.stats();
    assert_eq!(st.closed, Some(CloseReason::ForgeLimit));
    assert_eq!(st.forge_attempts, 100, "恰好第 100 次断链");
    // 断链波及客户端（其后续写失败/EOF）
    drop(client);
    server.shutdown().await;
}

#[tokio::test]
async fn forged_records_below_limit_keep_link() {
    let (client, server) = forge_session(99).await;
    wait_until("伪造计数到位", || server.stats().forge_attempts >= 99).await;
    assert_eq!(server.stats().closed, None, "99 次不断链");
    let mut cs = client.open_stream(Prio::Normal).await.expect("open");
    cs.write_all(b"alive").await.expect("w");
    let mut ss = tokio::time::timeout(Duration::from_secs(5), server.accept_stream())
        .await
        .expect("t")
        .expect("s");
    let mut buf = [0u8; 5];
    ss.read_exact(&mut buf).await.expect("r");
    assert_eq!(&buf, b"alive");
    client.shutdown().await;
    server.shutdown().await;
}

/// c→s 侧：I1 之后的**第一条已封记录**被字节级重放一次（重放向量走全真路径）。
async fn replay_proxy(client_side: DuplexStream, server_side: DuplexStream) {
    let (mut c_rd, mut c_wr) = tokio::io::split(client_side);
    let (mut s_rd, mut s_wr) = tokio::io::split(server_side);
    // s→c 透明（读服务端 → 写客户端）
    {
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut s_rd, &mut c_wr).await;
        });
    }
    // c→s：逐帧转发，第 2 帧（i==1，首条已封记录）额外重放一次
    tokio::spawn(async move {
        for i in 0.. {
            let mut hdr = [0u8; 5];
            if c_rd.read_exact(&mut hdr).await.is_err() {
                return;
            }
            let len = u32::from_le_bytes(hdr[..4].try_into().expect("4B")) as usize;
            let mut body = vec![0u8; len - 1];
            if c_rd.read_exact(&mut body).await.is_err() {
                return;
            }
            let _ = s_wr.write_all(&hdr).await;
            let _ = s_wr.write_all(&body).await;
            if i == 1 {
                // ← 字节级重放同一条已封记录
                let _ = s_wr.write_all(&hdr).await;
                let _ = s_wr.write_all(&body).await;
            }
        }
    });
}

#[tokio::test]
async fn replayed_record_rejected_and_counted() {
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);

    let (client_io, proxy_c) = duplex_pair();
    let (proxy_s, server_io) = duplex_pair();
    replay_proxy(proxy_c, proxy_s).await;

    let pin = pin_of(&fix);
    let server = fix.server;
    let srv = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            respond(server_io, &server, dir, TunnelConfig::default()),
        )
        .await
        .expect("timeout")
        .expect("respond")
    });
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(client_io, &device, &pin, TunnelConfig::default()),
        )
        .await
        .expect("timeout")
        .expect("initiate")
    });
    let (client, server) = (cli.await.expect("cli"), srv.await.expect("srv"));

    // 客户端发流数据（其首条记录被 proxy 重放）
    let mut cs = client.open_stream(Prio::Normal).await.expect("open");
    cs.write_all(b"payload-under-replay-probe")
        .await
        .expect("w");
    let mut ss = tokio::time::timeout(Duration::from_secs(5), server.accept_stream())
        .await
        .expect("t")
        .expect("s");
    let mut buf = [0u8; 26];
    ss.read_exact(&mut buf).await.expect("r");
    assert_eq!(&buf, b"payload-under-replay-probe");

    wait_until("重放被计", || server.stats().replay_rejected >= 1).await;
    let st = server.stats();
    assert!(st.forge_attempts >= 1, "重放计入伪造（P0-2）");
    assert_eq!(st.replay_rejected, 1, "字节级重复识别为重放");
    assert!(st.closed.is_none(), "单次重放不断链");

    // 数据面继续可用（被拒的重复记录不影响后续真记录）
    cs.write_all(b"after replay").await.expect("w2");
    let mut buf2 = [0u8; 12];
    ss.read_exact(&mut buf2).await.expect("r2");
    assert_eq!(&buf2, b"after replay");

    client.shutdown().await;
    server.shutdown().await;
}

// ============================================================================
// 服务端目录接缝的异步性（BoxFuture，§7-M1）
// ============================================================================

// ============================================================================
// rekey 切换竞态回归向量（blocking 复核修复）
// ============================================================================

/// 帧感知批到达代理（复核实验的确定性复现形态）：s→c 逐帧转发，但 REKEY_RESP 帧与其后
/// 3 帧合并为**一次** write 到达（TCP 无帧边界，Nagle/内核缓冲合并合法且常见）；
/// c→s 透明。
async fn batch_resp_proxy(client_side: DuplexStream, server_side: DuplexStream) {
    let (mut c_rd, mut c_wr) = tokio::io::split(client_side);
    let (mut s_rd, mut s_wr) = tokio::io::split(server_side);
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut c_rd, &mut s_wr).await;
    });
    tokio::spawn(async move {
        let mut batched = false;
        loop {
            let mut hdr = [0u8; 5];
            if s_rd.read_exact(&mut hdr).await.is_err() {
                return;
            }
            let len = u32::from_le_bytes(hdr[..4].try_into().expect("4B")) as usize;
            let mut body = vec![0u8; len - 1];
            if s_rd.read_exact(&mut body).await.is_err() {
                return;
            }
            if !batched && hdr[4] == RT_REKEY_RESP {
                // RESP + 后续帧（至多 3 帧，每帧限时 100ms 到达）拼成一个缓冲一次写出
                // （同批到达）。限时是必须的：对端 bulk 已发尽时后续帧永不到来，
                // 无条件 read_exact 会把 RESP 永久扣住 ⇒ 发起方 epoch 卡 0（门禁 flake
                // 的实测签名）；100ms 窗口在持续流量下足以收齐、静默对端下退化为单帧。
                let mut buf = Vec::new();
                buf.extend_from_slice(&hdr);
                buf.extend_from_slice(&body);
                for _ in 0..3 {
                    let got = tokio::time::timeout(Duration::from_millis(100), async {
                        let mut h2 = [0u8; 5];
                        s_rd.read_exact(&mut h2).await?;
                        let l2 = u32::from_le_bytes(h2[..4].try_into().expect("4B")) as usize;
                        let mut b2 = vec![0u8; l2 - 1];
                        s_rd.read_exact(&mut b2).await?;
                        Ok::<Vec<u8>, std::io::Error>([&h2[..], &b2[..]].concat())
                    })
                    .await;
                    match got {
                        Ok(Ok(frame)) => buf.extend_from_slice(&frame),
                        _ => break,
                    }
                }
                let _ = c_wr.write_all(&buf).await;
                let _ = c_wr.flush().await;
                batched = true;
                continue;
            }
            let _ = c_wr.write_all(&hdr).await;
            let _ = c_wr.write_all(&body).await;
            let _ = c_wr.flush().await;
        }
    });
}

/// 双向数据泵：`total` 个 chunk（前 4B = LE 序号）。
async fn bulk_send(mut s: flock_protocol::mux::Stream, total: usize, chunk: usize) {
    for i in 0..total {
        let mut b = vec![(i % 251) as u8; chunk];
        b[..4].copy_from_slice(&(i as u32).to_le_bytes());
        s.write_all(&b).await.expect("bulk send");
    }
}

/// 收全 `total` 个 chunk：返回（收到字节数, 序号全覆盖）。
async fn bulk_recv(
    mut s: flock_protocol::mux::Stream,
    total: usize,
    chunk: usize,
) -> (usize, bool) {
    let mut seen = vec![false; total];
    let mut bytes = 0usize;
    for _ in 0..total {
        let mut b = vec![0u8; chunk];
        if s.read_exact(&mut b).await.is_err() {
            break;
        }
        bytes += chunk;
        let seq = u32::from_le_bytes(b[..4].try_into().expect("4B")) as usize;
        if seq < total {
            seen[seq] = true;
        }
    }
    (bytes, seen.iter().all(|&x| x))
}

const BULK_CHUNKS: usize = 24;
const BULK_CHUNK_LEN: usize = 16 * 1024;

#[tokio::test]
async fn rekey_resp_batched_with_new_epoch_records_no_loss() {
    // 复核实验的确定性复现：REKEY_RESP 与新纪元记录同批到达。修复前：读泵在写泵应用
    // RESP 前抢先读入新纪元记录 ⇒ 旧钥解新钥 ⇒ 误判伪造 + 静默丢数据 + 计数器错位。
    // 修复后（RESP 应用在读泵同步执行）：零伪造、零丢失、双向数据完整。
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);

    let clock = std::sync::Arc::new(ManualClock::new());
    let clock_for_cfg = clock.clone();
    let mk_cfg = move || TunnelConfig {
        clock: clock_for_cfg.clone(),
        keepalive: Duration::from_secs(3600), // 隔离死链判定（注入时钟一次前拨 121s）
        ..TunnelConfig::default()
    };

    let (client_io, proxy_c) = duplex_pair();
    let (proxy_s, server_io) = duplex_pair();
    batch_resp_proxy(proxy_c, proxy_s).await;

    let pin = pin_of(&fix);
    let server = fix.server;
    let s_cfg = mk_cfg();
    let srv = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(30),
            respond(server_io, &server, dir, s_cfg),
        )
        .await
        .expect("respond timeout")
        .expect("respond")
    });
    let c_cfg = mk_cfg();
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(30),
            initiate(client_io, &device, &pin, c_cfg),
        )
        .await
        .expect("initiate timeout")
        .expect("initiate")
    });
    let client = cli.await.expect("cli");
    let server = srv.await.expect("srv");

    // 双向流：bulk 首块即携 yamux SYN（SYN 惰性），accept 与发送并发
    let cs = client.open_stream(Prio::Normal).await.expect("c stream");
    let ss2 = server.open_stream(Prio::Normal).await.expect("s stream2");

    // 双向大流量写入（后台），中途触发 rekey
    let w1 = tokio::spawn(bulk_send(cs, BULK_CHUNKS, BULK_CHUNK_LEN));
    let w2 = tokio::spawn(bulk_send(ss2, BULK_CHUNKS, BULK_CHUNK_LEN));
    let ss = tokio::time::timeout(Duration::from_secs(10), server.accept_stream())
        .await
        .expect("t")
        .expect("s stream");
    let cs2 = tokio::time::timeout(Duration::from_secs(10), client.accept_stream())
        .await
        .expect("t2")
        .expect("c stream2");
    tokio::time::sleep(Duration::from_millis(300)).await; // 流量进行中
    clock.advance(Duration::from_secs(121)); // 触发 rekey（RESP 批到达竞态窗口）
    let (r1_bytes, r1_full) = tokio::time::timeout(
        Duration::from_secs(30),
        bulk_recv(ss, BULK_CHUNKS, BULK_CHUNK_LEN),
    )
    .await
    .expect("recv c→s timeout");
    let (r2_bytes, r2_full) = tokio::time::timeout(
        Duration::from_secs(30),
        bulk_recv(cs2, BULK_CHUNKS, BULK_CHUNK_LEN),
    )
    .await
    .expect("recv s→c timeout");
    w1.await.expect("w1");
    w2.await.expect("w2");

    // rekey 完成 + 竞态断言：零伪造、零重放误判、双向零丢失
    wait_until("双侧 epoch → 1", || {
        client.stats().epoch == 1 && server.stats().epoch == 1
    })
    .await;
    let cst = client.stats();
    let sst = server.stats();
    assert_eq!(cst.forge_attempts, 0, "客户端零伪造（RESP 批到达不得误判）");
    assert_eq!(sst.forge_attempts, 0, "服务端零伪造");
    assert_eq!(cst.replay_rejected, 0);
    assert_eq!(sst.replay_rejected, 0);
    assert!(cst.closed.is_none() && sst.closed.is_none(), "会话存活");
    assert_eq!(
        r1_bytes,
        BULK_CHUNKS * BULK_CHUNK_LEN,
        "c→s 全量到达（无静默丢弃）"
    );
    assert_eq!(r2_bytes, BULK_CHUNKS * BULK_CHUNK_LEN, "s→c 全量到达");
    assert!(r1_full && r2_full, "序号全覆盖（无乱序/丢失）");

    client.shutdown().await;
    server.shutdown().await;
}

// ============================================================================
// M5 A8：单隧道 100 并发 yamux 流持续 60s 无错（R11——单隧道多会话复用的承载上限）
// ============================================================================

/// 100 条并发 yamux 流在同一条会话隧道上持续收发（缺省 60s；`A8_SECS` 可调便于本地
/// 快跑，M5 断言按缺省 60s 执行）。通过标准：全部流建立、每条流双向字节数严格一致、
/// 隧道无错不断（epoch/rekey 不影响数据面）。
#[ignore = "M5 A8 断言入口（60s 持续档不进缺省套件）：deploy/e2e_assert.sh 以 --ignored 运行"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hundred_streams_sixty_seconds_sustained() {
    let secs: u64 = std::env::var("A8_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let streams: usize = 100;
    let chunk: usize = 4096;
    // 每流每秒发一轮（100 流 × 4KiB/s = ~400KiB/s 总量——持续而不过载）。
    let rounds_target = secs as usize;

    let (client, server) = session_pair().await;

    // 服务端：收 100 条流（accept 循环），每条流回显收到的每个 chunk。
    let srv = tokio::spawn(async move {
        let mut seen = 0usize;
        let mut echoers = Vec::new();
        while let Some(s) = server.accept_stream().await {
            seen += 1;
            echoers.push(tokio::spawn(async move {
                let mut s = s;
                let mut buf = vec![0u8; chunk];
                // 回显泵：读到即回写；读错/写错 = 流结束（对端 FIN/会话拆）。
                while s.read_exact(&mut buf).await.is_ok() && s.write_all(&buf).await.is_ok() {}
            }));
            if seen == streams {
                break;
            }
        }
        assert_eq!(seen, streams, "服务端应收到全部 {streams} 条流");
        for e in echoers {
            let _ = e.await;
        }
    });

    // 客户端：100 条流并发，每条按秒级节奏发 chunk、收回显、校验序号连续。
    let mut drivers = Vec::new();
    for i in 0..streams {
        let stream = client.open_stream(Prio::Normal).await.expect("open stream");
        drivers.push(tokio::spawn(async move {
            let mut s = stream;
            let mut sent_seq: u32 = 0;
            let mut recv_seq: u32 = 0;
            for round in 0..rounds_target {
                let mut b = vec![i as u8 % 251; chunk];
                b[..4].copy_from_slice(&sent_seq.to_le_bytes());
                s.write_all(&b).await.expect("write");
                let mut r = vec![0u8; chunk];
                s.read_exact(&mut r).await.expect("echo read");
                assert_eq!(u32::from_le_bytes(r[..4].try_into().unwrap()), recv_seq);
                sent_seq += 1;
                recv_seq += 1;
                if round + 1 < rounds_target {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            (sent_seq as usize * chunk, recv_seq == sent_seq)
        }));
    }
    let mut total_bytes = 0usize;
    for d in drivers {
        let (n, ok) = d.await.expect("driver");
        assert!(ok, "回显序号必须连续");
        total_bytes += n;
    }
    // 结束：拆会话（服务端 echo 任务随会话结束退出）。
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(10), srv).await;

    // 通过面：100 流 × {secs}s × 4KiB 双向全部完成、隧道未因错误断开。
    assert_eq!(
        total_bytes,
        streams * rounds_target * chunk,
        "总发送字节精确匹配（无丢失/无重复）"
    );
    eprintln!("A8: {streams} streams × {secs}s × {chunk}B 双向 = {total_bytes}B OK");
}
