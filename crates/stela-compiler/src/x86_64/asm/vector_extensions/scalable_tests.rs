//! Streaming SVE and SME extension recipes (VNNI byte dots, GFNI byte and
//! AVX-512 quadword shifts), compared with the reviewed SSE recipes on random
//! Z, P, ZA and selector state.
use super::execution::Native;
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

/// Compile each of `words` for SVL 16, 32 and 64 in streaming mode with ZA,
/// under a declared SME2 profile (which requires PSTATE.DIT clear, so every
/// recipe is admitted), on x86-64-v3 and each host-supported candidate;
/// require `changed` words to emit different code and compare the complete
/// state after both.
fn compare(words: &[u32], candidates: &[TargetCpu], changed: impl Fn(u32) -> bool) {
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
            ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2),
            ScalableControls::new(length, false),
        )
        .unwrap();
        for &word in words {
            let source: Vec<u8> = [word, RET].into_iter().flat_map(u32::to_le_bytes).collect();
            let compile = |target| {
                crate::testing::context_leaf(&source, GuestAddress(0x1000), profile, target)
                    .unwrap()
                    .x86_64_code
            };
            let baseline = compile(TargetCpu::X86_64_V3);
            for &candidate in &candidates {
                let extended = compile(candidate);
                if changed(word) {
                    assert_ne!(baseline, extended, "{word:#010x} uses {candidate:?}");
                }
                let [baseline, extended] = [&baseline, &extended].map(|code| Native::new(code));
                for _ in 0..16 {
                    let mut state = GuestState::default();
                    for vector in &mut state.v {
                        *vector = [next(), next()];
                    }
                    state.x = core::array::from_fn(|_| next());
                    let mut bank =
                        |bytes: usize| -> Vec<u8> { (0..bytes).map(|_| next() as u8).collect() };
                    let mut banks = Banks {
                        z_upper: bank(32 * svl),
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
        |_| true,
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
    compare(&SHIFTS, &[TargetCpu::X86_64_V4.with_gfni()], |word| {
        EXTENDED_SHIFTS.contains(&word)
    });
}
