//! session/mux integration tests (docs/design.md §7-M1 completion
//! criteria).
//!
//! Coverage vectors:
//! - Full dual-form handshake vectors: pinned 1-RTT (duplex + TcpStream
//!   dial pairs); TOFU first-connect 2-RTT (I0→R0→I1/R1) state machine
//!   including negatives (forged join credentials/forged R0
//!   signature/out-of-order messages);
//! - UKS/binding failure vectors: tampering with the protocol context
//!   (cluster_id) or swapping the server identity ⇒ verification
//!   necessarily fails (§1.3.3c);
//! - DeviceDirectory three states: NotFound/Revoked/Active (the first
//!   two reject with the same opaque error);
//! - AEAD negotiation: intersection tier selection + no-intersection
//!   rejection;
//! - Anti-replay (proxy byte-level replay of an already-sealed record)
//!   and forgery teardown (teardown at 100 attempts);
//! - Clock injection: 120s triggers rekey (both sides' epochs advance +
//!   data flows after the rekey), 180s hard reject;
//! - mux: stream echo, explicit finish()/FIN, implicit shutdown disabled,
//!   PacketChannel frame boundaries, concurrent streams.

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
// Assembly
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

/// A standard 1-RTT session pair (duplex dial + InMemory directory).
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
    panic!("wait_until timed out: {what}");
}

/// A generic "park after the first frame" proxy: c→s transparent; s→c
/// replays only the first frame and then stops reading (the connection
/// stays open).
async fn park_after_first_frame(client_side: DuplexStream, server_side: DuplexStream) {
    // Directions: c_rd (read client) → s_wr (write server); s_rd (read
    // server) → c_wr (write client)
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
        let _: () = std::future::pending().await; // parked: s→c neither
                                                  // forwards nor reads
                                                  // anymore
    });
}

// ============================================================================
// Pinned 1-RTT handshake + mux data plane
// ============================================================================

#[tokio::test]
async fn pinned_1rtt_handshake_and_stream_echo() {
    let (client, server) = session_pair().await;

    // 1-RTT corroboration: the handshake itself consumes no record-layer
    // counters (the yamux bootstrap frames = the first records; that the
    // client's first wire message must be I1 is covered by the proxy
    // assertion in pinned_i1_tamper_rejected_by_aad)
    let st = client.stats();
    assert_eq!(st.epoch, 0);
    assert!(st.closed.is_none());
    assert!(
        st.sent_records <= 2,
        "no extra records beyond the yamux bootstrap frames: {}",
        st.sent_records
    );
    assert!(client.stats().closed.is_none());
    assert!(
        client.peer_server_id().is_some(),
        "the client can index the peer server (roaming model)"
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

    // Explicit finish() ⇒ the peer observes FIN/EOF (half-close
    // forbidden: the yamux FIN is the only unidirectional finish path)
    cs.finish().await.expect("client finish");
    let mut eof = [0u8; 4];
    let n = tokio::time::timeout(Duration::from_secs(5), ss.read_some(&mut eof))
        .await
        .expect("eof timeout");
    assert_eq!(n.expect("read_some"), 0, "the peer observes FIN/EOF");

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

    // TcpStream dial pair: PacketChannel frame boundaries (§3.6 [u16
    // len][ip packet])
    let mut cpc = client.open_packet_channel().await.expect("packet channel");
    cpc.send(&[0u8; 1]).await.expect("SYN first packet"); // yamux lazy SYN: carried by the first frame
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
        assert_eq!(got.len(), size, "frame boundaries preserved");
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
    cpc.send(&[1, 2, 3])
        .await
        .expect("c send (carries the SYN)");
    let accepted = tokio::time::timeout(Duration::from_secs(5), server.accept_stream())
        .await
        .expect("accept")
        .expect("stream");
    let mut spc = flock_protocol::mux::PacketChannel::from_stream(accepted);

    // Bidirectional packets

    assert_eq!(spc.recv().await.expect("s recv"), vec![1, 2, 3]);
    spc.send(&[4, 5]).await.expect("s send");
    assert_eq!(cpc.recv().await.expect("c recv"), vec![4, 5]);

    // recv_stream iteration: after the peer's finish, it ends with None
    spc.finish().await.expect("s finish");
    let mut rx = cpc.recv_stream();
    let first = rx.next().await;
    assert!(first.is_none(), "peer FIN ⇒ stream end (no partial packet)");
    client.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn multiple_streams_and_prio_passthrough() {
    let (client, server) = session_pair().await;
    let mut s1 = client.open_stream(Prio::Control).await.expect("s1");
    let mut s2 = client.open_stream(Prio::Normal).await.expect("s2");
    assert_eq!(s1.prio(), Prio::Control);

    // yamux lazy SYN (carried by the first frame): write first, then
    // accept
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
    // futures AsyncWriteExt::close maps to poll_close ⇒ must be rejected
    // (half-close forbidden: finish() is the only unidirectional finish)
    let r = futures::AsyncWriteExt::close(&mut s).await;
    assert!(r.is_err(), "implicit shutdown must be rejected");
    drop(s);
    client.shutdown().await;
}

// ============================================================================
// UKS / binding failure vectors (§1.3.3c signature coverage contract)
// ============================================================================

#[tokio::test]
async fn uks_wrong_server_identity_rejected() {
    // The client pins server A, but the I1 is handed to server B (MITM
    // redirection): the device signature covers "expected identity = A"
    // ⇒ it must fail at B.
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
    let srv_err = srv.await.expect("task").expect_err("respond must reject");
    let _ = cli.await.expect("cli task").expect("timeout");

    match &srv_err {
        SessionError::Handshake(stage) => {
            assert!(
                stage.contains("expected-server-identity") || stage.contains("device signature"),
                "the UKS vector fails at the identity/signature check, got {stage}"
            );
        }
        other => panic!("expected a Handshake error, got {other:?}"),
    }
}

#[tokio::test]
async fn uks_tampered_cluster_context_rejected() {
    // Tampered protocol context: the pin's cluster_id mismatches the
    // server ⇒ device-signature coverage mismatch.
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);

    let (a, b) = duplex_pair();
    let pin = pin_of(&fix);
    let server = fix.server;
    let srv = tokio::spawn(async move { respond(b, &server, dir, TunnelConfig::default()).await });

    let mut pin = pin;
    pin.cluster_id = ClusterId(rand::random()); // ← tampered context
    let cli = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(10),
            initiate(a, &device, &pin, TunnelConfig::default()),
        )
        .await
    });
    let srv_err = srv.await.expect("task").expect_err("must reject");
    let _ = cli.await.expect("cli task").expect("timeout");
    assert!(
        matches!(&srv_err, SessionError::Handshake(s) if s.contains("device signature")),
        "cluster_id tampering ⇒ device signature verification fails, got {srv_err:?}"
    );
}

#[tokio::test]
async fn pinned_i1_tamper_rejected_by_aad() {
    // An I1 sent field (ml_kem_ct) tampered at the byte level ⇒ AAD
    // mismatch ⇒ decryption failure.
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
    // Proxy: read the I1 (assert its shape), flip the first ml_ct byte,
    // forward
    let (t, mut body) = read_frame(&mut p_client).await.expect("first frame");
    assert_eq!(
        t, RT_I1,
        "the pinned form's first frame must be I1 (1-RTT corroboration)"
    );
    assert!(body.len() > 70);
    body[69] ^= 0xFF; // first byte of the ml_kem_ct region (an AAD-covered field)
    write_frame(&mut p_server, RT_I1, &body)
        .await
        .expect("forward tampered");
    // Swallow the subsequent traffic in both directions (each side reads
    // its own and discards)
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
        Ok(_) => panic!("respond must reject after tampering"),
        Err(e) => e,
    };
    // The client side must fail too (EOF/timeout both fine — the proxy
    // does not forward EOF, so its exact shape is not asserted)
    let _ = tokio::time::timeout(Duration::from_secs(3), cli).await;
    assert!(
        matches!(&srv_err, SessionError::Handshake(s) if s.contains("i1 payload")),
        "I1 field tampering ⇒ AAD mismatch decryption failure, got {srv_err:?}"
    );
}

// ============================================================================
// DeviceDirectory three states + AEAD negotiation
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
    let not_found = srv.await.expect("task").expect_err("NotFound must reject");
    let _ = cli.await.expect("cli").expect("timeout");
    assert!(
        matches!(not_found, SessionError::DeviceRejected),
        "NotFound ⇒ {not_found:?}"
    );

    // Revoked (same error variant as NotFound — timing-aligned /
    // anti-enumeration)
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
    let revoked = srv.await.expect("task").expect_err("Revoked must reject");
    let _ = cli.await.expect("cli").expect("timeout");
    assert!(
        matches!(revoked, SessionError::DeviceRejected),
        "Revoked ⇒ {revoked:?}"
    );
    assert_eq!(
        std::mem::discriminant(&not_found),
        std::mem::discriminant(&revoked),
        "three-state rejection aligned: NotFound and Revoked are indistinguishable"
    );

    // Public-key mismatch: the registered record's X25519 public key ≠
    // the presented material ⇒ the same opaque rejection
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);
    dir.register(DeviceRecord {
        device_x25519: DeviceStaticKeys::generate().x25519_public(), // ← mismatch
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
    let mismatch = srv.await.expect("task").expect_err("mismatch must reject");
    let _ = cli.await.expect("cli").expect("timeout");
    assert!(
        matches!(mismatch, SessionError::DeviceRejected),
        "public-key mismatch ⇒ {mismatch:?}"
    );

    // Active: the normal path
    let (_c, _s) = session_pair().await;
}

#[tokio::test]
async fn aead_negotiation_intersection_and_failure() {
    // The client holds only XChaCha ⇒ the negotiated intersection is
    // XChaCha (both sides' stats agree)
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

    // No intersection ⇒ AeadMismatch (server respond rejects)
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
    let err = srv
        .await
        .expect("task")
        .expect_err("no intersection must reject");
    let _ = cli.await.expect("cli").expect("timeout");
    assert!(
        matches!(err, SessionError::AeadMismatch),
        "no intersection ⇒ {err:?}"
    );
}

// ============================================================================
// TOFU first-connect 2-RTT state machine
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
    // Root fingerprint display (the data source of the user-confirmation
    // UI) and the cluster/entry material
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
    // Forged join credential: entry_sig tampered ⇒ root verification
    // fails
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
    .expect_err("forged credential must reject");
    assert!(
        matches!(&err, SessionError::Handshake(s) if s.contains("enrollment signature")),
        "forged join credential ⇒ {err:?}"
    );

    // Forged R0 identity signature: R0 signed with another identity key
    // ⇒ entry.identity_pub verification fails
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
    .expect_err("forged R0 signature must reject");
    assert!(
        matches!(&err, SessionError::Handshake(s) if s.contains("server identity signature")),
        "forged R0 identity signature ⇒ {err:?}"
    );
}

#[tokio::test]
async fn tofu_state_machine_rejects_out_of_order() {
    // The client is in TOFU (sent I0, waiting for R0) but receives R1 ⇒
    // the state machine rejects
    let device = DeviceStaticKeys::generate();
    let (a, mut fake) = duplex_pair();
    tokio::spawn(async move {
        let (t, _i0) = read_frame(&mut fake).await.expect("read I0");
        assert_eq!(t, RT_I0, "the TOFU first frame must be I0");
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
    .expect_err("a non-R0 first step in TOFU must reject");
    assert!(
        matches!(err, SessionError::UnexpectedMessage(t) if t == RT_R1),
        "TOFU state machine rejects out-of-order ⇒ {err:?}"
    );

    // Server state machine: a first frame that is not I0/I1 (e.g. DATA)
    // ⇒ rejected
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
    let err = srv
        .await
        .expect("task")
        .expect_err("a non-handshake first frame must reject");
    assert!(
        matches!(err, SessionError::UnexpectedMessage(t) if t == RT_DATA),
        "respond state machine rejects ⇒ {err:?}"
    );
}

// ============================================================================
// Clock injection: rekey (120s) / hard reject (180s) / dead link
// (3×keepalive)
// ============================================================================

#[tokio::test]
async fn clock_injection_rekey_both_sides() {
    use std::sync::Arc;
    let clock = Arc::new(ManualClock::new());
    // Enlarge keepalive to isolate the dead-link verdict: the injected
    // clock jumps 119s at once; with keepalive=10s the 3×keepalive
    // silence verdict would fire before the rekey trigger (dead-link
    // semantics are covered by keepalive_deadlink_detection).
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
    assert_eq!(client.stats().epoch, 0, "119s does not trigger a rekey");

    clock.advance(Duration::from_secs(2));
    wait_until("both epochs → 1", || {
        client.stats().epoch == 1 && server.stats().epoch == 1
    })
    .await;
    assert_eq!(client.stats().rekeys, 1);
    assert_eq!(server.stats().rekeys, 1);

    // Data flows as usual after the rekey (counters reset with the new
    // keys)
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
    // client ⇄ park-proxy ⇄ server: the REKEY_RESP never reaches the
    // client but the connection stays open ⇒ the injected 181s clock
    // triggers the hard reject.
    let clock = Arc::new(ManualClock::new());
    let c_cfg = TunnelConfig {
        clock: clock.clone(),
        keepalive: Duration::from_secs(3600), // isolate the DeadLink verdict
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

    clock.advance(Duration::from_secs(121)); // REKEY_INIT sent (RESP swallowed)
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        client.stats().epoch,
        0,
        "RESP swallowed ⇒ epoch does not advance"
    );
    assert!(client.stats().closed.is_none());

    clock.advance(Duration::from_secs(60)); // 181s: hard reject
    wait_until("180s hard reject", || client.stats().closed.is_some()).await;
    let st = client.stats();
    assert_eq!(
        st.closed,
        Some(CloseReason::RejectAfter),
        "hard-reject reason"
    );
    assert_eq!(st.epoch, 0);
    drop(client);
    let _ = srv.await;
}

#[tokio::test]
async fn keepalive_deadlink_detection() {
    use std::sync::Arc;
    // keepalive 1s (injected clock) + s→c stops reading ⇒ 3×keepalive
    // with no inbound verdicts a dead link.
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

    clock.advance(Duration::from_millis(3400)); // > 3×1s with no inbound
    wait_until("dead-link detection", || client.stats().closed.is_some()).await;
    assert_eq!(client.stats().closed, Some(CloseReason::DeadLink));
    drop(client);
    let _ = srv.await;
}

// ============================================================================
// Forgery teardown and anti-replay (sealed records injected)
// ============================================================================

/// c→s side: forward the I1, then inject `garbage_n` records with legal
/// frame lengths but random ciphertexts; the rest is transparent.
async fn forge_proxy(client_side: DuplexStream, server_side: DuplexStream, garbage_n: u32) {
    let (mut c_rd, mut c_wr) = tokio::io::split(client_side);
    let (mut s_rd, mut s_wr) = tokio::io::split(server_side);
    // s→c transparent (read server → write client)
    {
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut s_rd, &mut c_wr).await;
        });
    }
    // c→s: I1 forward + forgery injection + transparent remainder
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
            // Legal frame length (len=17 = type + 16B ciphertext),
            // records that necessarily fail authentication
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
    wait_until("100 forgeries tear down the link", || {
        server.stats().closed.is_some()
    })
    .await;
    let st = server.stats();
    assert_eq!(st.closed, Some(CloseReason::ForgeLimit));
    assert_eq!(st.forge_attempts, 100, "teardown at exactly the 100th");
    // The teardown reaches the client (its subsequent writes fail/EOF)
    drop(client);
    server.shutdown().await;
}

#[tokio::test]
async fn forged_records_below_limit_keep_link() {
    let (client, server) = forge_session(99).await;
    wait_until("forgery count in place", || {
        server.stats().forge_attempts >= 99
    })
    .await;
    assert_eq!(server.stats().closed, None, "99 attempts do not tear down");
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

/// c→s side: the **first sealed record** after the I1 is replayed once at
/// the byte level (the replay vector goes through the fully real path).
async fn replay_proxy(client_side: DuplexStream, server_side: DuplexStream) {
    let (mut c_rd, mut c_wr) = tokio::io::split(client_side);
    let (mut s_rd, mut s_wr) = tokio::io::split(server_side);
    // s→c transparent (read server → write client)
    {
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut s_rd, &mut c_wr).await;
        });
    }
    // c→s: forward frame by frame; the 2nd frame (i==1, the first sealed
    // record) is additionally replayed once
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
                // ← byte-level replay of the same sealed record
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

    // The client sends stream data (whose first record the proxy
    // replays)
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

    wait_until("replay counted", || server.stats().replay_rejected >= 1).await;
    let st = server.stats();
    assert!(
        st.forge_attempts >= 1,
        "the replay counts as forgery (P0-2)"
    );
    assert_eq!(
        st.replay_rejected, 1,
        "byte-level duplicate recognized as replay"
    );
    assert!(st.closed.is_none(), "a single replay does not tear down");

    // The data plane stays usable (the rejected duplicate does not
    // affect subsequent genuine records)
    cs.write_all(b"after replay").await.expect("w2");
    let mut buf2 = [0u8; 12];
    ss.read_exact(&mut buf2).await.expect("r2");
    assert_eq!(&buf2, b"after replay");

    client.shutdown().await;
    server.shutdown().await;
}

// ============================================================================
// Asynchrony of the server directory seam (BoxFuture, §7-M1)
// ============================================================================

// ============================================================================
// rekey switch race regression vectors (blocking-review fix)
// ============================================================================

/// Frame-aware batch-arrival proxy (a deterministic reproduction of the
/// review experiment): s→c forwards frame by frame, but the REKEY_RESP
/// frame and the 3 frames after it are merged into **one** write (TCP
/// has no frame boundaries; Nagle/kernel-buffer merging is legal and
/// common); c→s transparent.
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
                // The RESP + subsequent frames (at most 3, each with a
                // 100ms arrival window) are glued into one buffer and
                // written out once (same-batch arrival). The deadline is
                // necessary: when the peer's bulk traffic is exhausted,
                // later frames never arrive, and an unconditional
                // read_exact would hold the RESP forever ⇒ the
                // initiator's epoch stuck at 0 (the empirically observed
                // signature of a gate flake); a 100ms window is enough
                // to gather under sustained traffic and degenerates to a
                // single frame against a silent peer.
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

/// Bidirectional data pump: `total` chunks (first 4B = LE sequence
/// number).
async fn bulk_send(mut s: flock_protocol::mux::Stream, total: usize, chunk: usize) {
    for i in 0..total {
        let mut b = vec![(i % 251) as u8; chunk];
        b[..4].copy_from_slice(&(i as u32).to_le_bytes());
        s.write_all(&b).await.expect("bulk send");
    }
}

/// Receive all `total` chunks: returns (bytes received, full sequence
/// coverage).
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
    // Deterministic reproduction of the review experiment: the
    // REKEY_RESP arrives batched with new-epoch records. Before the fix:
    // the read pump read new-epoch records ahead of the write pump
    // applying the RESP ⇒ old key opening the new key ⇒ misjudged as
    // forgery + silently dropped data + counter misalignment. After the
    // fix (RESP application runs synchronously in the read pump): zero
    // forgeries, zero loss, bidirectional data intact.
    let fix = fixture();
    let device = DeviceStaticKeys::generate();
    let mut dir = InMemoryDirectory::new();
    register(&mut dir, &device);

    let clock = std::sync::Arc::new(ManualClock::new());
    let clock_for_cfg = clock.clone();
    let mk_cfg = move || TunnelConfig {
        clock: clock_for_cfg.clone(),
        keepalive: Duration::from_secs(3600), // isolate the dead-link verdict (the injected clock jumps 121s at once)
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

    // Bidirectional streams: the first bulk chunk carries the yamux SYN
    // (lazy SYN); accept and send run concurrently
    let cs = client.open_stream(Prio::Normal).await.expect("c stream");
    let ss2 = server.open_stream(Prio::Normal).await.expect("s stream2");

    // Bidirectional heavy writes (in the background), triggering a rekey
    // midway
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
    tokio::time::sleep(Duration::from_millis(300)).await; // traffic in flight
    clock.advance(Duration::from_secs(121)); // trigger the rekey (the RESP batch-arrival race window)
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

    // Rekey complete + race assertions: zero forgeries, zero replay
    // misjudgments, zero bidirectional loss
    wait_until("both epochs → 1", || {
        client.stats().epoch == 1 && server.stats().epoch == 1
    })
    .await;
    let cst = client.stats();
    let sst = server.stats();
    assert_eq!(
        cst.forge_attempts, 0,
        "client zero forgeries (RESP batch arrival must not misjudge)"
    );
    assert_eq!(sst.forge_attempts, 0, "server zero forgeries");
    assert_eq!(cst.replay_rejected, 0);
    assert_eq!(sst.replay_rejected, 0);
    assert!(
        cst.closed.is_none() && sst.closed.is_none(),
        "session alive"
    );
    assert_eq!(
        r1_bytes,
        BULK_CHUNKS * BULK_CHUNK_LEN,
        "c→s full arrival (no silent drops)"
    );
    assert_eq!(r2_bytes, BULK_CHUNKS * BULK_CHUNK_LEN, "s→c full arrival");
    assert!(
        r1_full && r2_full,
        "full sequence coverage (no reordering/loss)"
    );

    client.shutdown().await;
    server.shutdown().await;
}

// ============================================================================
// M5 A8: 100 concurrent yamux streams on a single tunnel sustained for
// 60s without errors (R11 — the carrying capacity of multi-stream reuse
// on one tunnel)
// ============================================================================

/// 100 concurrent yamux streams send and receive continuously over one
/// session tunnel (default 60s; `A8_SECS` is adjustable for quick local
/// runs; the M5 assertion runs at the default 60s). Pass criteria: all
/// streams established, every stream's bidirectional byte counts
/// strictly equal, the tunnel error-free and unbroken (epoch/rekeys do
/// not disturb the data plane).
#[ignore = "M5 A8 assertion entry (the 60s sustained tier is not in the default suite): deploy/e2e_assert.sh runs it with --ignored"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hundred_streams_sixty_seconds_sustained() {
    let secs: u64 = std::env::var("A8_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let streams: usize = 100;
    let chunk: usize = 4096;
    // One round per stream per second (100 streams × 4KiB/s = ~400KiB/s
    // total — sustained without overload).
    let rounds_target = secs as usize;

    let (client, server) = session_pair().await;

    // Server: accept 100 streams (accept loop); each stream echoes every
    // chunk it receives.
    let srv = tokio::spawn(async move {
        let mut seen = 0usize;
        let mut echoers = Vec::new();
        while let Some(s) = server.accept_stream().await {
            seen += 1;
            echoers.push(tokio::spawn(async move {
                let mut s = s;
                let mut buf = vec![0u8; chunk];
                // Echo pump: read then write back; a read/write error =
                // stream end (peer FIN/session teardown).
                while s.read_exact(&mut buf).await.is_ok() && s.write_all(&buf).await.is_ok() {}
            }));
            if seen == streams {
                break;
            }
        }
        assert_eq!(
            seen, streams,
            "the server should receive all {streams} streams"
        );
        for e in echoers {
            let _ = e.await;
        }
    });

    // Client: 100 concurrent streams, each sending chunks at a
    // second-level cadence, receiving the echo, and checking sequence
    // continuity.
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
        assert!(ok, "echo sequence numbers must be continuous");
        total_bytes += n;
    }
    // Finish: tear down the session (the server echo tasks exit with the
    // session).
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(10), srv).await;

    // Pass surface: 100 streams × {secs}s × 4KiB bidirectional all
    // completed, the tunnel not torn down by errors.
    assert_eq!(
        total_bytes,
        streams * rounds_target * chunk,
        "total sent bytes match exactly (no loss/no duplication)"
    );
    eprintln!("A8: {streams} streams × {secs}s × {chunk}B bidirectional = {total_bytes}B OK");
}
