//! ml-kem 官方 KAT 复跑（M1 完成标准：混合 KEM 往返 + ml-kem 官方 KAT 复跑，§7-M1；P0-1）。
//!
//! 数据文件 [`kat_ml_kem_data`]（keygen 前 5 条 + encapsulation 前 5 条，NIST ACVP FIPS203
//! 官方向量，经 RustCrypto/KEMs ml-kem 0.3.3 官方测试数据）。复跑三层：
//!
//! 1. **keyGen**：`DecapsulationKey::from_seed(d‖z)` → ek 逐字节等于官方 ek（1184B）；
//! 2. **encapsulation**：`EncapsulationKey::new(ek)` + `encapsulate_deterministic(m)` →
//!    (ct, k) 逐字节等于官方 (c, k)；
//! 3. **decapsulation**：展开形 dk（2400B，ACVP 记录形态）→ `from_expanded` + `decapsulate(c)`
//!    → k 等于官方 k。`from_expanded` 在 ml-kem 0.3.3 已标 deprecated（推荐 from_seed），
//!    但展开形是 ACVP 官方记录形态，复跑必须走它——局部 `#[allow(deprecated)]`。
//!
//! 同一 KAT 亦验混合 KEM 封装的正确性前提：官方 ek/ct 尺寸 = 1184/1088，与
//! `kem::HybridPubkey`(1216B)/`kem::HybridCt`(1120B) 的 X25519(32B) 拼接布局一致（§1.3.3a）。

// ACVP 官方记录形态为 2400B 展开形 dk，复跑必经 ml-kem 0.3.3 已标 deprecated 的
// ExpandedKeyEncoding 接口——文件级豁免（from_seed 路径在 kem.rs 生产代码中未用展开形）。
#![allow(deprecated)]

#[path = "kat_ml_kem_data.rs"]
mod kat_ml_kem_data;

use flock_protocol::kem;
use flock_protocol::ml_kem::ExpandedKeyEncoding;
use flock_protocol::ml_kem::{
    ml_kem_768::MlKem768, Decapsulate, DecapsulationKey, EncapsulationKey, Key, KeyExport,
};

/// keyGen：seed(d‖z) → ek 逐字节复现官方向量。
#[test]
fn kat_keygen() {
    for (i, (d, z, ek_hex)) in kat_ml_kem_data::KEYGEN.iter().enumerate() {
        let mut seed = [0u8; 64];
        let dv = hex::decode(d).unwrap();
        let zv = hex::decode(z).unwrap();
        seed[..32].copy_from_slice(&dv);
        seed[32..].copy_from_slice(&zv);
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed.into());
        let ek = dk.encapsulation_key();
        let ek_bytes = ek.to_bytes();
        assert_eq!(ek_bytes.len(), 1184, "tc{i}: ek 尺寸");
        assert_eq!(
            hex::encode(ek_bytes.as_slice()),
            *ek_hex.to_ascii_lowercase(),
            "tc{i}: ek 逐字节复现失败"
        );
        // 展开形 dk 尺寸（2400B）由 kat_encap_and_decap 的 dk_arr: [u8; 2400] 解码强约束
    }
}

/// encapsulation/decapsulation：官方 ek/m → (c,k) 逐字节复现；展开 dk → decapsulate(c)=k。
#[test]
fn kat_encap_and_decap() {
    for (i, (ek_hex, dk_hex, m_hex, c_hex, k_hex)) in kat_ml_kem_data::ENCAP.iter().enumerate() {
        let ek_arr: [u8; 1184] = hex::decode(ek_hex).unwrap().try_into().unwrap();
        let ek = EncapsulationKey::<MlKem768>::new(
            &Key::<EncapsulationKey<MlKem768>>::try_from(ek_arr.as_slice()).unwrap(),
        )
        .unwrap();
        let m: [u8; 32] = hex::decode(m_hex).unwrap().try_into().unwrap();
        // encapsulate_deterministic 为官方 KAT 复跑的确定性入口（doc(hidden) 公共 API）
        let (ct, k) = ek.encapsulate_deterministic(&m.into());
        assert_eq!(ct.as_slice().len(), 1088, "tc{i}: ct 尺寸");
        assert_eq!(
            hex::encode(ct.as_slice()),
            c_hex.to_ascii_lowercase(),
            "tc{i}: ct 复现"
        );
        assert_eq!(
            hex::encode(k.as_slice()),
            k_hex.to_ascii_lowercase(),
            "tc{i}: k 复现"
        );

        // decap：展开形 dk（ACVP 记录形态）
        let dk_arr: [u8; 2400] = hex::decode(dk_hex).unwrap().try_into().unwrap();
        let dk = <DecapsulationKey<MlKem768> as ExpandedKeyEncoding>::from_expanded_bytes(
            &dk_arr.into(),
        )
        .unwrap();
        let k2 = dk.decapsulate(&ct);
        assert_eq!(
            hex::encode(k2.as_slice()),
            k_hex.to_ascii_lowercase(),
            "tc{i}: decap k 复现"
        );
    }
}

/// 混合 KEM 与 KAT 尺寸一致性：官方 ek/ct 尺寸嵌入混合布局后 = 1216B 公钥 / 1120B 密文，
/// 且 `HybridPubkey::from_bytes` 接受官方向量 ek（FIPS 203 校验通过）。
#[test]
fn hybrid_sizes_match_kat() {
    assert_eq!(kem::ML_KEM_EK_LEN, 1184);
    assert_eq!(kem::ML_KEM_CT_LEN, 1088);
    assert_eq!(kem::HYBRID_PUB_LEN, 1216);
    assert_eq!(kem::HYBRID_CT_LEN, 1120);
    // 官方向量 ek 过混合公钥校验（X25519 侧填 32B 常量占位）
    let ek_arr: [u8; 1184] = hex::decode(kat_ml_kem_data::ENCAP[0].0)
        .unwrap()
        .try_into()
        .unwrap();
    let mut hybrid = [0u8; 1216];
    hybrid[32..].copy_from_slice(&ek_arr);
    kem::HybridPubkey::from_bytes(&hybrid).expect("官方 ek 必须通过 FIPS 203 校验");
    // 混合封装/解封装往返由 src/kem.rs 单测 roundtrip_and_sizes 覆盖（官方向量无配套
    // X25519 私钥，ACVP 只覆盖 ML-KEM 本体）——此处仅守「官方 ek 可进混合布局」。
}
