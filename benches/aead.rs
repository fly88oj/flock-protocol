//! AEAD 吞吐基准（docs/design.md §7-M1 完成标准）。
//!
//! - criterion 正式基准：AES-256-GCM（aes-gcm 0.11.1）@4MiB 分段加密吞吐；
//! - 机读结果行：跑完最后一行输出 `BENCH_AESGCM_4M <数值> GB/s`（§7-M1 门槛 ≥ 4 GB/s，
//!   verdict §0 复跑基线的 2.3× 预期下限；opt-level 见 workspace [profile.bench] 继承 release）。
//!
//! 实测口径：与 envelope v2 段加密同调用形态（`encrypt_inout_detached`，就地加密 + detached
//! tag），缓冲预热、多轮取总时均。

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

    // —— criterion 正式基准 ——
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

    // —— 机读结果行（直接计时，独立于 criterion 统计）——
    // 预热 3 轮后计时 ≥ 8 轮，取总吞吐。
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
