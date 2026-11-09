//! trust integration tests (docs/design.md §7-M1 completion criteria,
//! P0-5 gate cases).
//!
//! - Invite file v3 → **each of multiple endpoints' ServerEntry under
//!   the same root completes its own 1-RTT encapsulation** (the gate
//!   case of the multi-server pinning model §1.3.3f): session::initiate
//!   and respond per endpoint, with the proxy asserting the client's
//!   first frame is always I1 (0x03) — I0 never appears;
//! - load_invite/save_invite file paths: round trip + root-signature
//!   mismatch rejected at load + v2 rejected;
//! - TOFU → PinStore landing closed loop (trust::confirm_tofu_and_pin:
//!   first pin + second-connect pin comparison).

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

/// First-frame probe proxy: records the client's first wire frame type,
/// then forwards transparently in both directions.
async fn first_frame_probe(
    client_side: DuplexStream,
    server_side: DuplexStream,
) -> tokio::sync::oneshot::Receiver<u8> {
    let (mut c_rd, mut c_wr) = tokio::io::split(client_side);
    let (mut s_rd, mut s_wr) = tokio::io::split(server_side);
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        // c→s: read the first frame's record type and forward it, then
        // become transparent
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

/// Single-endpoint 1-RTT dial: the pin comes from the directory entry;
/// asserts the first frame == I1 and that the data plane echoes.
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

    // Gate assertion 1: the client's first frame must be I1 (pinned form;
    // I0 never appears)
    let first = tokio::time::timeout(Duration::from_secs(5), probe)
        .await
        .expect("probe timeout")
        .expect("probe dropped");
    assert_eq!(
        first, RT_I1,
        "endpoint {idx}: every endpoint is 1-RTT; I0 must not appear"
    );

    // Gate assertion 2: the data plane works after the handshake
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

    // Invite file v3 persisted/read back
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
        "verified against the issuing root"
    );

    // Every endpoint under the same root: build the pin from the
    // **directory entry** and complete 1-RTT each
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

    // Entry tampered: locate the first entry's relay_endpoint string by
    // content and flip one of its bytes (still valid UTF-8/valid
    // structure) ⇒ structural parsing passes but the root verification
    // necessarily rejects.
    let ep = cluster.directory.servers[0].relay_endpoint.as_bytes();
    let pos = bytes
        .windows(ep.len())
        .position(|w| w == ep)
        .expect("the endpoint string must be in the invite bytes");
    let mut tampered = bytes.clone();
    tampered[pos] = if tampered[pos] == b'r' { b'R' } else { b'r' };
    let path = std::env::temp_dir().join(format!("flock-invite-bad-{}.bin", rand::random::<u64>()));
    std::fs::write(&path, &tampered).expect("write tampered");
    let err = load_invite(&path).expect_err("entry tampered ⇒ load rejected");
    let _ = std::fs::remove_file(&path);
    assert!(matches!(err, TrustError::BadSignature), "got {err:?}");

    // v2 version byte ⇒ rejected (v1/v2 no longer accepted)
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

    // First connect TOFU: confirm_tofu_and_pin lands the pin
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
        "the root public key is pinned after TOFU confirmation"
    );
    assert_eq!(
        flock_protocol::session::fingerprint_ed25519(
            pins.pinned_root(&cluster.directory.cluster_id).unwrap()
        ),
        expected_fp,
        "what is pinned is exactly the thing whose fingerprint was displayed"
    );
    let server_tunnel = srv.await.expect("srv");
    client.shutdown().await;
    server_tunnel.shutdown().await;

    // Second connect: same root ⇒ Match (no more TOFU); swapped root ⇒
    // RootChanged alert path
    let bad = SigningKey::from_bytes(&[9; 32]);
    match pins.verify_pinned(&cluster.directory.cluster_id, &bad.verifying_key()) {
        PinVerdict::Mismatch { .. } => {}
        v => panic!("a swapped root must yield Mismatch (explicit alert path), got {v:?}"),
    }
}
