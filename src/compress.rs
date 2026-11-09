//! Compression levels and frame format (§1.3.3e / §3.7, P0-4, P1-7).
//!
//! - **Off by default** (`Mode::Off`); enabled per-policy/per-stream — the
//!   VORACLE/CRIME/BREACH preconditions do hold in the flock main
//!   repository (the FRP relay is a length observation point,
//!   compression-2026 §3.2), so output padding accompanies it when
//!   enabled.
//! - Levels (compression-2026 §0/§2 measured mapping): `<128B` passes
//!   through (40B inflation 122.5%, 120B zero gain); Interactive/Bulk =
//!   zstd-1 (same codec at frame level; Bulk's chunking/context reuse
//!   belongs to the streaming layer, later batch); Archive = zstd-19,
//!   archive tier only; [`Algorithm::Lz4`] (lz4_flex 0.14) as the
//!   CPU-constrained fallback.
//! - **Non-expanding fallback is a MUST** (RFC 3173 §2.2): if a trial
//!   compression does not shrink, emit plaintext; "adaptive stop after
//!   consecutive failures" is stateful policy belonging to the streaming
//!   layer (this frame API is stateless and says so honestly).
//! - Compress-then-encrypt order unchanged (RFC 3173 §1); compression
//!   happens inside the record-layer payload (caller: `compress_frame`
//!   first, then into AEAD).
//! - Padding interplay: `PadPolicy::Multiple16` pads the total frame
//!   length to a multiple of 16B (starting value; tunable bucketing is
//!   upper-layer policy).
//! - dictID negotiation is a **placeholder**: the frame header reserves a
//!   `dict_id` slot (0 = no dictionary); dictionary training/distribution/
//!   dictID in a handshake extension belong to the handshake layer (§3.7
//!   seam) and are not wired in this batch.
//!
//! Frame format (13B header):
//!
//! ```text
//! [1B flags][4B dict_id LE][4B orig_len LE][4B payload_len LE][payload …len][pad 0x00…]
//! flags: bit0 = compressed; bits1..=2 = algorithm (0=zstd, 1=lz4); bits3..=7 = reserved 0
//! pad  : 0x00 padding at frame end (all bytes beyond payload_len must be zero; readers validate this)
//! ```

use core::fmt;

/// Passthrough threshold: plaintext < 128B is not trial-compressed
/// (compression-2026 §0 measured inflation/zero gain).
pub const PASSTHROUGH_MIN: usize = 128;
/// Frame header length.
pub const FRAME_HEADER_LEN: usize = 13;

/// Frame error: malformed format / non-zero trailing padding /
/// decompression failure (including length mismatch) / oversized input /
/// trimmed build missing a capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressError {
    /// Truncated header / out-of-range lengths / non-zero reserved bits.
    MalformedFrame(&'static str),
    /// Non-zero trailing padding bytes (frame tampered or spliced).
    BadPadding,
    /// Decompression failure or orig_len mismatch.
    DecompressFailed,
    /// Input exceeds the representable cap (orig_len/payload_len are u32;
    /// plain > u32::MAX is rejected rather than silently truncating the
    /// length field).
    InputTooLarge,
    /// Trimmed build missing the required capability (e.g. decoding an
    /// algorithm id 0 zstd frame with the `zstd` feature disabled).
    MissingFeature(&'static str),
}

impl fmt::Display for CompressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompressError::MalformedFrame(m) => write!(f, "compress frame: {m}"),
            CompressError::BadPadding => f.write_str("compress frame: non-zero padding bytes"),
            CompressError::DecompressFailed => f.write_str("compress frame: decompress failed"),
            CompressError::InputTooLarge => {
                f.write_str("compress frame: input exceeds u32 length domain")
            }
            CompressError::MissingFeature(m) => write!(f, "compress frame: {m}"),
        }
    }
}

impl std::error::Error for CompressError {}

/// Compression level (§1.3.3e).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Default: no compression, no padding, always passthrough.
    #[default]
    Off,
    /// Interactive streams: zstd-1 (low latency; the small-packet
    /// dictionary tier is a handshake-layer placeholder).
    Interactive,
    /// Bulk streams: zstd-1 (same as Interactive at frame level; 16–64KB
    /// chunking/flush/context reuse belong to the streaming layer).
    Bulk,
    /// Archive tier: zstd-19 (offline archival only; highest CPU/latency).
    Archive,
}

/// Output padding (length-observation-point mitigation; enabled alongside
/// compression levels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PadPolicy {
    /// No padding (default; the Off level never pads).
    #[default]
    Off,
    /// Pad the total frame length to a multiple of 16B (starting value;
    /// tunable bucketing belongs to upper layers).
    Multiple16,
}

/// Compression algorithm (lz4_flex 0.14 = CPU-constrained fallback,
/// compression-2026 §0).
///
/// With the `zstd` feature (on by default) disabled,
/// [`Algorithm::Zstd`] does not exist, the default algorithm becomes
/// [`Algorithm::Lz4`], and [`decompress_frame`] returns
/// [`CompressError::MissingFeature`] for frames with algorithm id 0 (zstd)
/// — for trimmed builds on targets without a C toolchain (wasm32 cross
/// needs clang to build zstd-sys).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// zstd (default tier; requires the `zstd` feature).
    #[cfg(feature = "zstd")]
    #[default]
    Zstd,
    /// lz4 block compression (no zstd hardware acceleration / CPU
    /// constrained; the default tier when the `zstd` feature is absent).
    #[cfg(not(feature = "zstd"))]
    #[default]
    Lz4,
    /// lz4 block compression (the fallback tier when the `zstd` feature is
    /// enabled).
    #[cfg(feature = "zstd")]
    Lz4,
}

/// Dictionary reference (**dictID negotiation placeholder**): `dict_id`
/// goes into the frame header slot for the handshake layer to compare
/// version consistency; dictionary content training and distribution
/// belong to the handshake layer (§3.7 seam) and are not wired into the
/// compression path in this batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DictRef {
    /// 0 = no dictionary; non-zero = dictionary version id negotiated by
    /// the handshake layer (passed through for comparison only).
    pub dict_id: u32,
}

/// Compression policy (§1.3.3e structure + padding interplay fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompressPolicy {
    pub mode: Mode,
    pub padding: PadPolicy,
    pub alg: Algorithm,
    pub dict: DictRef,
}

impl CompressPolicy {
    /// All-passthrough policy (`Mode::Off`).
    pub fn off() -> Self {
        Self::default()
    }
}

#[cfg(feature = "zstd")]
fn zstd_level(mode: Mode) -> i32 {
    match mode {
        Mode::Archive => 19,
        Mode::Interactive | Mode::Bulk | Mode::Off => 1,
    }
}

fn flags(compressed: bool, alg: Algorithm) -> u8 {
    let c = u8::from(compressed);
    let a = match alg {
        #[cfg(feature = "zstd")]
        Algorithm::Zstd => 0u8,
        Algorithm::Lz4 => 1u8,
    };
    c | (a << 1)
}

/// Compress one frame: trial-compress per policy; **if the trial does not
/// shrink, emit plaintext** (RFC 3173 §2.2 non-expanding fallback MUST).
/// `Mode::Off` or plaintext < [`PASSTHROUGH_MIN`] always passes through;
/// padding appends 0x00 per [`PadPolicy`].
///
/// Returns the complete frame bytes (including the 13B header). Same input
/// plus same policy gives deterministic output (no randomness).
/// `plain.len() > u32::MAX` ⇒ [`CompressError::InputTooLarge`] (length
/// field is u32 — explicit error rather than silent truncation).
pub fn compress_frame(policy: &CompressPolicy, plain: &[u8]) -> Result<Vec<u8>, CompressError> {
    if plain.len() > u32::MAX as usize {
        return Err(CompressError::InputTooLarge);
    }
    let passthrough = policy.mode == Mode::Off || plain.len() < PASSTHROUGH_MIN;
    let payload: Vec<u8>;
    let compressed: bool;

    if passthrough {
        payload = plain.to_vec();
        compressed = false;
    } else {
        let candidate = match policy.alg {
            #[cfg(feature = "zstd")]
            Algorithm::Zstd => zstd::bulk::compress(plain, zstd_level(policy.mode))
                .expect("zstd compress: always succeeds within the input length cap"),
            Algorithm::Lz4 => lz4_flex::block::compress(plain),
        };
        if candidate.len() < plain.len() {
            payload = candidate;
            compressed = true;
        } else {
            // Non-expanding fallback: trial compression did not shrink ⇒
            // plaintext (flags records 0; the decompress side takes it
            // directly)
            payload = plain.to_vec();
            compressed = false;
        }
    }

    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len() + 16);
    frame.push(flags(compressed, policy.alg));
    frame.extend_from_slice(&policy.dict.dict_id.to_le_bytes());
    frame.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);

    // Padding interplay: Off mode never pads; levels with compression
    // enabled pad the total frame length to a multiple of 16B
    if policy.mode != Mode::Off && policy.padding == PadPolicy::Multiple16 {
        while frame.len() % 16 != 0 {
            frame.push(0);
        }
    }
    Ok(frame)
}

/// Decompress one frame (inverse of [`compress_frame`]). Validates: header
/// lengths/reserved bits, orig_len ≤ session frame cap
/// ([`crate::session::MAX_FRAME`] — the 13B header could declare 4GiB;
/// this prevents the decompress side from being lured into huge
/// allocations), payload bounds, all-zero trailing padding, decompressed
/// output length == orig_len. Any mismatch returns [`CompressError`] (no
/// panic).
pub fn decompress_frame(frame: &[u8]) -> Result<Vec<u8>, CompressError> {
    if frame.len() < FRAME_HEADER_LEN {
        return Err(CompressError::MalformedFrame("truncated header"));
    }
    let fl = frame[0];
    if fl & 0xF8 != 0 {
        return Err(CompressError::MalformedFrame("reserved flag bits set"));
    }
    let compressed = fl & 1 != 0;
    let alg_id = (fl >> 1) & 0b11;
    if alg_id > 1 {
        return Err(CompressError::MalformedFrame("unknown algorithm id"));
    }
    #[cfg(not(feature = "zstd"))]
    if alg_id == 0 {
        // The wire-format slot is reserved (0=zstd); a trimmed build
        // without zstd reports the missing capability explicitly instead of
        // misreporting a format error.
        return Err(CompressError::MissingFeature(
            "algorithm zstd requires the `zstd` feature (this is a trimmed build)",
        ));
    }
    #[allow(unused_variables)]
    let alg = alg_id;
    let _dict_id = u32::from_le_bytes(frame[1..5].try_into().expect("13B header"));
    let orig_len = u32::from_le_bytes(frame[5..9].try_into().expect("13B header")) as usize;
    // An unauthenticated frame header can declare a 4GiB orig_len ⇒
    // zstd/lz4 capacity parameters pre-allocate based on it. Compressed
    // frames are record-layer payloads (§1.3.3c single record ≤ 1MiB) ⇒ a
    // legitimate orig_len is necessarily ≤ MAX_FRAME; reject over-cap
    // values before allocating.
    if orig_len > crate::session::MAX_FRAME {
        return Err(CompressError::MalformedFrame(
            "declared orig_len exceeds 1MiB session frame cap",
        ));
    }
    let payload_len = u32::from_le_bytes(frame[9..13].try_into().expect("13B header")) as usize;
    let payload_end = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(CompressError::MalformedFrame("payload length overflow"))?;
    if frame.len() < payload_end {
        return Err(CompressError::MalformedFrame("payload truncated"));
    }
    // Trailing padding must be all zero (every byte beyond the payload)
    if frame[payload_end..].iter().any(|&b| b != 0) {
        return Err(CompressError::BadPadding);
    }
    let payload = &frame[FRAME_HEADER_LEN..payload_end];

    let out = if compressed {
        match alg {
            #[cfg(feature = "zstd")]
            0 => zstd::bulk::decompress(payload, orig_len)
                .map_err(|_| CompressError::DecompressFailed)?,
            1 => lz4_flex::block::decompress(payload, orig_len)
                .map_err(|_| CompressError::DecompressFailed)?,
            _ => unreachable!("alg id was already validated ≤1 above"),
        }
    } else {
        payload.to_vec()
    };
    if out.len() != orig_len {
        return Err(CompressError::DecompressFailed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lorem(n: usize) -> Vec<u8> {
        // Compressible pattern text (repeated sentence), simulating real
        // payloads
        let sentence = b"the quick brown fox jumps over the lazy dog; ";
        (0..n).map(|i| sentence[i % sentence.len()]).collect()
    }

    fn policy(mode: Mode) -> CompressPolicy {
        CompressPolicy {
            mode,
            ..CompressPolicy::default()
        }
    }

    /// Algorithm set participating in loops (with the `zstd` feature
    /// disabled, lz4 only — the trimmed build still exercises the lz4 path
    /// fully).
    fn algs() -> Vec<Algorithm> {
        #[cfg(feature = "zstd")]
        return vec![Algorithm::Zstd, Algorithm::Lz4];
        #[cfg(not(feature = "zstd"))]
        return vec![Algorithm::Lz4];
    }

    // M1 gate: <128B passthrough
    #[test]
    fn small_input_passthrough() {
        for mode in [Mode::Interactive, Mode::Bulk, Mode::Archive] {
            for len in [0usize, 1, 40, 127] {
                let plain = lorem(len);
                let frame = compress_frame(&policy(mode), &plain).unwrap();
                assert_eq!(
                    frame[0] & 1,
                    0,
                    "mode={mode:?} len={len}: <128B must pass through"
                );
                let out = decompress_frame(&frame).unwrap();
                assert_eq!(out, plain);
            }
        }
    }

    // M1 gate: trial compression without shrink falls back to plaintext
    // (incompressible input)
    #[test]
    fn incompressible_falls_back_to_plaintext() {
        // Pseudo-random bytes (deterministic LCG): neither zstd nor lz4 can
        // compress them
        let mut x = 0x12345678u32;
        let plain: Vec<u8> = (0..64 * 1024)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 24) as u8
            })
            .collect();
        for alg in algs() {
            let p = CompressPolicy {
                mode: Mode::Bulk,
                alg,
                ..CompressPolicy::default()
            };
            let frame = compress_frame(&p, &plain).unwrap();
            assert_eq!(
                frame[0] & 1,
                0,
                "alg={alg:?}: an unshrunk trial must fall back to plaintext"
            );
            assert_eq!(decompress_frame(&frame).unwrap(), plain);
        }
    }

    // Compressible input: round-trip per level + compression flag
    #[test]
    fn compress_roundtrip_all_modes() {
        let plain = lorem(64 * 1024);
        for mode in [Mode::Interactive, Mode::Bulk, Mode::Archive] {
            for alg in algs() {
                let p = CompressPolicy {
                    mode,
                    alg,
                    ..CompressPolicy::default()
                };
                let frame = compress_frame(&p, &plain).unwrap();
                assert_eq!(
                    frame[0] & 1,
                    1,
                    "mode={mode:?} alg={alg:?}: compressible input should compress"
                );
                assert!(
                    frame.len() < plain.len() + FRAME_HEADER_LEN,
                    "compressed frame should be smaller than plaintext + header"
                );
                let out = decompress_frame(&frame).unwrap();
                assert_eq!(out, plain);
            }
        }
        // Archive(19) compresses to <= Interactive(1) (monotonicity spot
        // check on the same zstd codec)
        let f_i = compress_frame(&policy(Mode::Interactive), &plain).unwrap();
        let f_a = compress_frame(&policy(Mode::Archive), &plain).unwrap();
        assert!(f_a.len() <= f_i.len());
    }

    // Off level: never compresses, never pads
    #[test]
    fn off_mode_never_compresses_or_pads() {
        let plain = lorem(4096);
        let frame = compress_frame(
            &CompressPolicy {
                mode: Mode::Off,
                padding: PadPolicy::Multiple16,
                ..CompressPolicy::default()
            },
            &plain,
        )
        .unwrap();
        assert_eq!(
            frame[0],
            flags(false, Algorithm::default()),
            "Off level does not compress (algorithm bits follow the default tier)"
        );
        assert_eq!(
            frame.len(),
            FRAME_HEADER_LEN + plain.len(),
            "Off level does not pad"
        );
        assert_eq!(decompress_frame(&frame).unwrap(), plain);
    }

    // Padding interplay: multiple of 16B + trailing-zero validation
    #[test]
    fn padding_to_multiple_of_16() {
        let plain = lorem(300); // 300B compressible (repeated pattern)
        for mode in [Mode::Interactive, Mode::Bulk, Mode::Archive] {
            let p = CompressPolicy {
                mode,
                padding: PadPolicy::Multiple16,
                ..CompressPolicy::default()
            };
            let frame = compress_frame(&p, &plain).unwrap();
            assert_eq!(
                frame.len() % 16,
                0,
                "mode={mode:?}: total frame length is a multiple of 16B"
            );
            assert_eq!(decompress_frame(&frame).unwrap(), plain);
        }
        // Padding + passthrough fallback path (small input + padding on)
        let small = lorem(50);
        let p = CompressPolicy {
            mode: Mode::Interactive,
            padding: PadPolicy::Multiple16,
            ..CompressPolicy::default()
        };
        let frame = compress_frame(&p, &small).unwrap();
        assert_eq!(frame.len() % 16, 0);
        assert_eq!(decompress_frame(&frame).unwrap(), small);
    }

    // dictID placeholder: goes into the frame header, preserved on
    // round-trip
    #[test]
    fn dict_id_placeholder_passes_through() {
        let plain = lorem(1024);
        let p = CompressPolicy {
            mode: Mode::Interactive,
            dict: DictRef {
                dict_id: 0xDEADBEEF,
            },
            ..CompressPolicy::default()
        };
        let frame = compress_frame(&p, &plain).unwrap();
        assert_eq!(
            &frame[1..5],
            &0xDEADBEEF_u32.to_le_bytes(),
            "dictID slot passes through (negotiation placeholder)"
        );
        assert_eq!(decompress_frame(&frame).unwrap(), plain);
    }

    // Negative vectors: tampered header/padding/payload must error
    #[test]
    fn malformed_frames_rejected() {
        let plain = lorem(2048);
        let frame = compress_frame(&policy(Mode::Bulk), &plain).unwrap();

        assert_eq!(
            decompress_frame(&frame[..12]),
            Err(CompressError::MalformedFrame("truncated header"))
        );

        let mut t = frame.clone();
        t[0] |= 0x08; // reserved bit
        assert_eq!(
            decompress_frame(&t),
            Err(CompressError::MalformedFrame("reserved flag bits set"))
        );

        // Payload flip: the zstd frame carries an xxhash checksum and must
        // reject (lz4 block compression has no built-in checksum;
        // integrity is carried by the outer envelope/SR-SIG1 — an
        // algorithm capability difference, not a defect being concealed);
        // the equivalent negative vector for trimmed builds is the
        // orig_len tampering below
        #[cfg(feature = "zstd")]
        {
            let mut t2 = frame.clone();
            let last = t2.len() - 1;
            t2[last] ^= 0x01;
            assert!(matches!(
                decompress_frame(&t2),
                Err(CompressError::DecompressFailed)
            ));
        }
        // orig_len tampering (fails consistently across
        // algorithms/trimmed shapes: decompressed length mismatches the
        // header declaration)
        let mut t2b = frame.clone();
        let orig = u32::from_le_bytes(t2b[5..9].try_into().unwrap());
        t2b[5..9].copy_from_slice(&(orig + 1).to_le_bytes());
        assert!(matches!(
            decompress_frame(&t2b),
            Err(CompressError::DecompressFailed)
        ));

        // Non-zero byte written into the padding area
        let p = CompressPolicy {
            mode: Mode::Interactive,
            padding: PadPolicy::Multiple16,
            ..CompressPolicy::default()
        };
        let padded = compress_frame(&p, &plain).unwrap();
        let mut t3 = padded.clone();
        let last3 = t3.len() - 1;
        t3[last3] = 0x01;
        assert_eq!(decompress_frame(&t3), Err(CompressError::BadPadding));

        // orig_len tampering (passthrough frame)
        let mut t4 = compress_frame(&CompressPolicy::default(), b"plain-frame-bytes!").unwrap();
        t4[5] ^= 0x01;
        assert!(matches!(
            decompress_frame(&t4),
            Err(CompressError::DecompressFailed)
        ));
    }

    // Self-describing frame header: payload_len vs orig_len semantics
    #[test]
    fn header_fields_semantics() {
        let plain = lorem(512);
        let frame = compress_frame(&policy(Mode::Interactive), &plain).unwrap();
        let orig = u32::from_le_bytes(frame[5..9].try_into().unwrap()) as usize;
        let plen = u32::from_le_bytes(frame[9..13].try_into().unwrap()) as usize;
        assert_eq!(orig, plain.len());
        assert!(
            plen < orig,
            "payload for compressible input should be smaller than the original"
        );
        assert!(frame.len() >= FRAME_HEADER_LEN + plen);
    }

    // orig_len cap on unauthenticated frame headers: the 13B header could
    // declare 4GiB to lure the decompress side into a huge capacity
    // pre-allocation — exceeding the session frame cap (1MiB, §1.3.3c
    // single-record cap) must be rejected before allocation.
    #[test]
    fn oversized_declared_orig_len_rejected_before_alloc() {
        let cap_err =
            CompressError::MalformedFrame("declared orig_len exceeds 1MiB session frame cap");
        // Forged frame: flags=passthrough (all-zero reserved bits is
        // legal), dict=0, orig_len=u32::MAX, payload_len=0.
        let mut frame = vec![0u8; FRAME_HEADER_LEN];
        frame[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decompress_frame(&frame),
            Err(cap_err),
            "over-cap orig_len must be rejected before decompression allocation"
        );
        // Exactly at the cap (1MiB) does not take the cap-rejection path
        // (subsequently backstopped by payload/length validation — here it
        // reports a length mismatch).
        let mut edge = vec![0u8; FRAME_HEADER_LEN];
        edge[5..9].copy_from_slice(&(crate::session::MAX_FRAME as u32).to_le_bytes());
        assert_ne!(
            decompress_frame(&edge),
            Err(CompressError::MalformedFrame(
                "declared orig_len exceeds 1MiB session frame cap"
            )),
            "orig_len exactly at the cap is not rejected by the cap path"
        );
    }
}
