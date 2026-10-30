//! VNNI byte dot products in streaming SVE and SME, compared with the
//! reviewed SSE recipes on random Z, P, ZA and selector state.
use super::execution::Native;
use crate::aarch64::scalable::{ScalableMode, VectorLength};
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

#[test]
fn streaming_and_za_byte_dots_match_the_sse_recipes() {
    let host = TargetCpu::detect();
    let candidates: Vec<_> = [
        TargetCpu::X86_64_V3.with_avx_vnni(),
        TargetCpu::X86_64_V4.with_avx512vnni(),
    ]
    .into_iter()
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
        let profile = ScalableProfile::new(length, ScalableMode::new(true, true));
        for word in WORDS {
            let source: Vec<u8> = [word, RET].into_iter().flat_map(u32::to_le_bytes).collect();
            let compile = |target| {
                crate::testing::context_leaf(&source, GuestAddress(0x1000), profile, target)
                    .unwrap()
                    .x86_64_code
            };
            let baseline = compile(TargetCpu::X86_64_V3);
            for &candidate in &candidates {
                let extended = compile(candidate);
                assert_ne!(baseline, extended, "{word:#010x} uses VNNI");
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
