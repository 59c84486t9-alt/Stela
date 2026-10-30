//! Streaming SVE and SME extension recipes (VNNI byte dots, GFNI byte and
//! AVX-512 quadword shifts, AVX-512 integer conversions and table
//! permutes), compared with the reviewed SSE recipes on random Z, P, ZA and
//! selector state.
use super::execution::Native;
use crate::aarch64::floating::features::NumericalFeatures;
use crate::aarch64::scalable::{
    ScalableMode, VectorLength,
    features::{ScalableFeature, ScalableFeatures},
    profile::ScalableControls,
};
use crate::context::{ExecutionContext, ScalableStateView};
use crate::scalable_context::ScalableProfile;
use crate::{GuestAddress, GuestState, TargetCpu};
use alloc::{vec, vec::Vec};

const RET: u32 = 0xd65f_03c0;
/// llvm-mc encodings: SDOT and UDOT, by vector and indexed (streaming mode
/// has no SVE USDOT or SUDOT); SMOPA, UMOPA, USMOPA, SUMOPA and SMOPS on
/// ZA1.S with P1/P2; SME2 SDOT, UDOT and USDOT into ZA.S[W8, 1, VGx2] with a
/// single vector, SDOT with four vector pairs, indexed SDOT and SVDOT.
const WORDS: [u32; 15] = [
    0x4482_0023,
    0x4482_0423,
    0x44aa_0023,
    0x44ba_0423,
    0xa082_4421,
    0xa1a2_4421,
    0xa182_4421,
    0xa0a2_4421,
    0xa082_4431,
    0xc124_1441,
    0xc124_1451,
    0xc124_1449,
    0xc1a9_1480,
    0xc154_1860,
    0xc158_84a0,
];

/// Scalable storage beyond `GuestState`, large enough for any tested SVL.
#[derive(Clone, PartialEq, Eq)]
struct Banks {
    z_upper: Vec<u8>,
    predicates: Vec<u8>,
    ffr: Vec<u8>,
    za: Vec<u8>,
    zt0: Vec<u8>,
}

fn run(native: &Native, svl: usize, state: &mut GuestState, banks: &mut Banks) {
    let mut view = ScalableStateView {
        svl_bytes: svl as u16,
        reserved: [0; 6],
        svcr: ScalableMode::new(true, true).svcr(),
        tpidr2_el0: 0,
        fpmr: 0,
        z_upper: banks.z_upper.as_mut_ptr(),
        predicates: banks.predicates.as_mut_ptr(),
        ffr: banks.ffr.as_mut_ptr(),
        za: banks.za.as_mut_ptr(),
        zt0: banks.zt0.as_mut_ptr(),
    };
    let mut context = ExecutionContext {
        scalable: &mut view,
        ..ExecutionContext::default()
    };
    native.run(state, &mut context);
}

/// llvm-mc encodings of streaming SVE shifts on B and D elements: ASR, LSR
/// and LSL by immediate, unpredicated and merging; ASRD, SRSHR, URSHR, USRA,
/// SSRA and SRSRA; ASR by wide elements; LSR, ASR and LSL by vector and ASR.D
/// by vector; SQSHL and UQRSHL by vector; SLI and SRI; SHRNB and RSHRNT;
/// SQSHL, UQSHL and SQSHLU by immediate.
const SHIFTS: [u32; 27] = [
    0x042d_9023,
    0x0428_9423,
    0x042f_9c23,
    0x04bf_9023,
    0x0480_8403,
    0x0401_85c3,
    0x0403_85a3,
    0x0404_85a3,
    0x040c_85a3,
    0x048d_8703,
    0x450d_e423,
    0x45cf_e023,
    0x4509_e823,
    0x0422_8023,
    0x0411_8443,
    0x0410_8443,
    0x0413_8443,
    0x04d0_8443,
    0x4408_8443,
    0x440b_8443,
    0x450b_f423,
    0x45d7_f023,
    0x452d_1023,
    0x4528_1c23,
    0x0406_8563,
    0x04c7_8503,
    0x040f_8543,
];

/// Random vector contents.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Values {
    Bits,
    /// One kind of lane per sample: raw bits, Single pairs within ±4096 in
    /// eighths, Doubles in quarters of magnitude 2^-2 to 2^45, or small
    /// signed integers, with non-negative floats in half the samples, under a
    /// random FPCR rounding mode.
    Numbers,
    /// One B/H/S/D lane width per sample, each lane below 72, 40, 20 or 10,
    /// or raw bits in a fifth of the samples.
    Indices,
}

impl Values {
    fn lane(self, kind: u64, random: u64) -> u64 {
        match self {
            Self::Bits => return random,
            Self::Indices => {
                let width = kind % 5;
                if width == 4 {
                    return random;
                }
                let bound = [72, 40, 20, 10][width as usize];
                return (0..8 >> width).fold(0, |lane, element| {
                    let index = (random >> (element * 8) & 0xff) % bound;
                    lane | index << (element * (8 << width))
                });
            }
            Self::Numbers => {}
        }
        let single = |bits: u64| u64::from((bits as i16 as f32 / 8.0).to_bits());
        let signs = if kind & 1 == 0 { 0 } else { 1 << 63 | 1 << 31 };
        match kind >> 1 & 3 {
            0 => random,
            1 => (single(random >> 16) | single(random >> 40) << 32) & !signs,
            2 => {
                ((random as i64 >> (16 + (random >> 3) % 48)) as f64 / 4.0).to_bits()
                    & !(signs & 1 << 63)
            }
            _ => (random as i64 >> 40) as u64,
        }
    }
}

/// Compile each of `words` as a context block (which may exit to the
/// numerical runtime) for SVL 16, 32 and 64 in streaming mode with ZA,
/// under a declared SME2 profile (which requires PSTATE.DIT clear, so every
/// recipe is admitted), on x86-64-v3 and each host-supported candidate;
/// require `changed` words to emit different code and compare the complete
/// state after both from `values`.
fn compare(
    words: &[u32],
    candidates: &[TargetCpu],
    values: Values,
    changed: impl Fn(u32, usize) -> bool,
) {
    let host = TargetCpu::detect();
    let candidates: Vec<_> = candidates
        .iter()
        .copied()
        .filter(|target| host.supports(*target))
        .collect();
    if candidates.is_empty() {
        return;
    }
    let mut random = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        random
    };
    for svl in [16, 32, 64] {
        let length = VectorLength::from_bytes(svl).unwrap();
        let profile = ScalableProfile::new_with_features(
            length,
            ScalableMode::new(true, true),
            ScalableFeatures::of(ScalableFeature::Sme)
                .with(ScalableFeature::Sme2)
                .with(ScalableFeature::Sme2p1),
            ScalableControls::new(length, false),
        )
        .unwrap();
        for &word in words {
            let source: Vec<u8> = [word, RET].into_iter().flat_map(u32::to_le_bytes).collect();
            let compile = |target| {
                crate::testing::context_block(
                    &source,
                    GuestAddress(0x1000),
                    profile,
                    NumericalFeatures::default(),
                    target,
                )
                .unwrap()
                .native
                .x86_64_code
            };
            let baseline = compile(TargetCpu::X86_64_V3);
            for &candidate in &candidates {
                let extended = compile(candidate);
                if changed(word, svl) {
                    assert_ne!(baseline, extended, "{word:#010x} uses {candidate:?}");
                }
                let [baseline, extended] = [&baseline, &extended].map(|code| Native::new(code));
                for _ in 0..16 {
                    let mut state = GuestState::default();
                    let kind = next();
                    for vector in &mut state.v {
                        *vector = [values.lane(kind, next()), values.lane(kind, next())];
                    }
                    state.x = core::array::from_fn(|_| next());
                    if values == Values::Numbers {
                        state.fpcr = (next() as u32 & 3) << 22;
                    }
                    let z_upper = (0..4 * svl)
                        .flat_map(|_| values.lane(kind, next()).to_le_bytes())
                        .collect();
                    let mut bank =
                        |bytes: usize| -> Vec<u8> { (0..bytes).map(|_| next() as u8).collect() };
                    let mut banks = Banks {
                        z_upper,
                        predicates: bank(17 * svl / 8),
                        ffr: bank(svl / 8),
                        za: bank(svl * svl),
                        zt0: vec![0; 64],
                    };
                    let mut expected = (state.clone(), banks.clone());
                    run(&baseline, svl, &mut expected.0, &mut expected.1);
                    run(&extended, svl, &mut state, &mut banks);
                    assert!(
                        state == expected.0 && banks == expected.1,
                        "{word:#010x} svl={svl} {candidate:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn streaming_and_za_byte_dots_match_the_sse_recipes() {
    compare(
        &WORDS,
        &[
            TargetCpu::X86_64_V3.with_avx_vnni(),
            TargetCpu::X86_64_V4.with_avx512vnni(),
        ],
        Values::Bits,
        |_, _| true,
    );
}

/// The shifts above whose byte or signed quadword steps take GFNI or VPSRAQ.
const EXTENDED_SHIFTS: [u32; 14] = [
    0x042d_9023,
    0x0428_9423,
    0x042f_9c23,
    0x04bf_9023,
    0x0480_8403,
    0x0401_85c3,
    0x0403_85a3,
    0x040c_85a3,
    0x450d_e423,
    0x45cf_e023,
    0x4509_e823,
    0x0411_8443,
    0x0413_8443,
    0x450b_f423,
];

#[test]
fn streaming_byte_and_quadword_shifts_match_the_sse_recipes() {
    compare(
        &SHIFTS,
        &[TargetCpu::X86_64_V4.with_gfni()],
        Values::Bits,
        |word, _| EXTENDED_SHIFTS.contains(&word),
    );
}

/// llvm-mc encodings of SCVTF and UCVTF, then FCVTZS and FCVTZU, for Z3 from
/// Z1 under P1: S from W, S from X, D from W and D from X, then W from S, X
/// from S, W from D and X from D.
const CONVERSIONS: [u32; 16] = [
    0x6594_a423,
    0x6595_a423,
    0x65d4_a423,
    0x65d5_a423,
    0x65d0_a423,
    0x65d1_a423,
    0x65d6_a423,
    0x65d7_a423,
    0x659c_a423,
    0x659d_a423,
    0x65dc_a423,
    0x65dd_a423,
    0x65d8_a423,
    0x65d9_a423,
    0x65de_a423,
    0x65df_a423,
];

#[test]
fn streaming_integer_conversions_match_the_sse_recipes() {
    let signed_w = [0x6594_a423, 0x65d0_a423, 0x659c_a423, 0x65d8_a423];
    // Packed F, VL and DQ forms take every pair but signed W.
    compare(
        &CONVERSIONS,
        &[TargetCpu::X86_64_V4],
        Values::Numbers,
        |word, _| !signed_w.contains(&word),
    );
    // F alone has the scalar unsigned forms: from X, and to W or X.
    let scalar_unsigned = [
        0x65d5_a423,
        0x65d7_a423,
        0x659d_a423,
        0x65dd_a423,
        0x65d9_a423,
        0x65df_a423,
    ];
    compare(
        &CONVERSIONS,
        &[TargetCpu::X86_64_V3.with_avx512f()],
        Values::Numbers,
        |word, _| scalar_unsigned.contains(&word),
    );
}

/// llvm-mc encodings: TBL of B, H, S and D lanes from one register, then
/// from two (one pair wrapping Z31 to Z0, one indexing by its destination);
/// TBX of each lane, one in place; TBLQ on H and D and TBXQ on B and S.
const TABLES: [u32; 16] = [
    0x0525_3083,
    0x0565_3083,
    0x05a5_3083,
    0x05e5_3083,
    0x0526_2883,
    0x0566_2883,
    0x05a6_2be3,
    0x05e3_2883,
    0x0525_2c83,
    0x0565_2c83,
    0x05a5_2c63,
    0x05e5_2c83,
    0x4445_f883,
    0x44c5_f883,
    0x0525_3483,
    0x05a5_3483,
];

#[test]
fn streaming_table_lookups_match_the_baseline_recipes() {
    // Two-register tables of SVL 64 exceed the four chunks one permute reads.
    let two_registers = |word: u32| word & 0xff20_fc00 == 0x0520_2800;
    compare(
        &TABLES,
        &[TargetCpu::X86_64_V4.with_avx512vbmi()],
        Values::Indices,
        |word, svl| !two_registers(word) || svl < 64,
    );
}
