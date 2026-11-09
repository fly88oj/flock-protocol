//! AEAD throughput benchmark (docs/design.md §7-M1 completion criteria).
//!
//! - Official criterion benchmark: AES-256-GCM (aes-gcm 0.11.1) @4MiB
//!   segment-seal throughput;
//! - Machine-readable result line: after the run, the last line output
//!   is `BENCH_AESGCM_4M <value> GB/s` (§7-M1 gate >= 4 GB/s; the 2.3×
//!   expected lower bound of the verdict §0 re-run baseline; opt-level
//!   inherits release via the workspace [profile.bench]).
//!
//! Measurement methodology: the same call shape as envelope v2 segment
//! sealing (`encrypt_inout_detached`, in-place encryption + detached
//! tag), buffer warmed up, multiple rounds averaged over the total time.

use std::hint::black_box;
use std::time::Instant;

use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aead::{AeadCore, AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

const MIB: usize = 1024 * 1024;
const SEG: usize = 4 * MIB;

fn seal_4m(cipher: &Aes256Gcm, buf: &mut [u8], nonce: &Nonce<<Aes256Gcm as AeadCore>::NonceSize>) {
    let tag = cipher
        .encrypt_inout_detached(nonce, &[], InOutBuf::from(&mut buf[..]))
        .expect("bench seal");
    black_box(tag);
}

fn main() {
    let key = Key::<Aes256Gcm>::from([7u8; 32]);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::<<Aes256Gcm as AeadCore>::NonceSize>::from([0u8; 12]);
    let mut buf = vec![0xABu8; SEG];

    // —— official criterion benchmark ——
    {
        use criterion::Criterion;
        let mut c = Criterion::default().configure_from_args();
        let mut group = c.benchmark_group("aes256gcm_4m");
        group.throughput(criterion::Throughput::Bytes(SEG as u64));
        group.sample_size(20);
        group.bench_function("seal", |b| {
            b.iter(|| seal_4m(black_box(&cipher), &mut buf, black_box(&nonce)))
        });
        group.finish();
        c.final_summary();
    }

    // —— machine-readable result line (direct timing, independent of
    // criterion statistics) ——
    // Warm up 3 rounds, then time >= 8 rounds; report total throughput.
    for _ in 0..3 {
        seal_4m(&cipher, &mut buf, &nonce);
    }
    const ITERS: usize = 8;
    let t0 = Instant::now();
    for _ in 0..ITERS {
        seal_4m(&cipher, &mut buf, &nonce);
    }
    let secs = t0.elapsed().as_secs_f64();
    let gbps = (SEG as f64 * ITERS as f64) / secs / 1e9;
    println!("BENCH_AESGCM_4M {gbps:.2} GB/s");
}
