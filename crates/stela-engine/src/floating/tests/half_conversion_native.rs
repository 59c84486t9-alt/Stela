//! Emitted Half conversions against exact completion on each host recipe.
use super::super::*;
use crate::execution::platform::Mapping;
use stela_compiler::{
    GuestAddress, TargetCpu,
    aarch64::floating::*,
    block::{BlockProfile, CompilationPlan, ExitKind, Features},
};

const PC: u64 = 0x1000;
const PREFIX: u32 = 0x9100_0508; // ADD X8,X8,#1
const SUFFIX: u32 = 0x9100_0529; // ADD X9,X9,#1
const SOURCE: usize = 1;

/// llvm-mc encodings, Rd = 0 and Rn = 1: FCVTZS 8H and 4H, FCVTZU, FCVTNS,
/// FCVTMS, FCVTPU, FCVTAS, SCVTF 8H, UCVTF 4H; FCVTZS, FCVTZU, FCVTNS, SCVTF
/// and UCVTF H; FCVTZS W and X, FCVTZU W and X, FCVTNS W, FCVTMU X; SCVTF and
/// UCVTF from W and X; FCVTN, FCVTN2; FCVT from S and D; fixed-point FCVTZS
/// and SCVTF, which keep completion.
const FORMS: [u32; 30] = [
    0x4ef9_b820,
    0x0ef9_b820,
    0x6ef9_b820,
    0x4e79_a820,
    0x0e79_b820,
    0x6ef9_a820,
    0x4e79_c820,
    0x4e79_d820,
    0x2e79_d820,
    0x5ef9_b820,
    0x7ef9_b820,
    0x5e79_a820,
    0x5e79_d820,
    0x7e79_d820,
    0x1ef8_0020,
    0x9ef8_0020,
    0x1ef9_0020,
    0x9ef9_0020,
    0x1ee0_0020,
    0x9ef1_0020,
    0x1ee2_0020,
    0x9ee2_0020,
    0x1ee3_0020,
    0x9ee3_0020,
    0x0e21_6820,
    0x4e21_6820,
    0x1e23_c020,
    0x1e63_c020,
    0x4f1c_fc20,
    0x1ec2_f420,
];

fn compile(word: u32, target: TargetCpu) -> Mapping {
    let source: Vec<_> = [PREFIX, word, SUFFIX]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let block = CompilationPlan::new(
        &source,
        GuestAddress(PC),
        &stela_compiler::Options::new(BlockProfile::new(Features::SYSTEM_MODE), target),
    )
    .unwrap()
    .compile()
    .unwrap();
    Mapping::new(&block.native.x86_64_code).unwrap()
}

fn mxcsr() -> u32 {
    let mut value = 0;
    // SAFETY: valid writable output on this baseline SSE2 host.
    unsafe { core::arch::asm!("stmxcsr [{}]", in(reg) &raw mut value) };
    value
}

/// Run the block; the state must match exact completion, on the inline path
/// or after a helper exit that left only the prefix's effects.
fn check(mapping: &Mapping, operation: &FloatingPointOperation, state: GuestState) -> bool {
    let mut expected = state.clone();
    expected.x[8] += 1;
    let prefix = expected.clone();
    complete(&mut expected, operation).unwrap();
    let mut actual = state;
    let saved = mxcsr();
    // SAFETY: the owned block contains only non-memory instructions, compiled
    // for this host. State satisfies its ordinary one-pointer block ABI.
    let exit = unsafe { mapping.call_block(&mut actual) }.unwrap();
    assert_eq!(mxcsr(), saved, "MXCSR {operation:?}");
    let inline = exit.kind == ExitKind::Fallthrough as u64;
    if inline {
        assert_eq!(exit.next_pc, PC + 8, "{operation:?}");
    } else {
        assert_eq!(exit.kind, ExitKind::FloatingPoint as u64, "{operation:?}");
        assert_eq!(exit.next_pc, PC + 4, "{operation:?}");
        assert_eq!(actual, prefix, "helper exit {operation:?}");
        complete(&mut actual, operation).unwrap();
    }
    assert_eq!(actual, expected, "{operation:?} inline={inline}");
    inline
}

/// A random lane pattern for the input family `kind`.
fn limb(kind: u32, next: &mut impl FnMut() -> u64) -> u64 {
    let word = |next: &mut dyn FnMut() -> u64| next() & 0xffff;
    (0..4).fold(0, |limb, lane| match kind % 6 {
        // Half lanes: normal in integer range, then any class.
        0 => limb | (next() & 0x83ff | (8 + next() % 16) << 10) << (16 * lane),
        1 => limb | word(next) << (16 * lane),
        // Small signed integers, and raw ones.
        2 => limb | (next() & 63).wrapping_sub(32) << (16 * lane) & 0xffff << (16 * lane),
        // Single lanes in Half's range, or just past it.
        3 if lane % 2 == 0 => {
            limb | (next() & 0x807f_ffff | (113 + next() % 30) << 23) << (16 * lane)
        }
        // Double lanes.
        4 if lane == 0 => next() & 0x800f_ffff_ffff_ffff | (1008 + next() % 32) << 52,
        3 | 4 => limb,
        _ => next(),
    })
}

#[test]
fn half_conversions_match_completion_on_each_host_recipe() {
    let host = stela_compiler::x86_64::modeled::host();
    let mut random = 0x59f1_11f1_923f_82a4_u64;
    let mut next = move || {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        random
    };
    let targets = [
        TargetCpu::Baseline,
        TargetCpu::X86_64_V3,
        TargetCpu::X86_64_V4.with_avx512fp16(),
    ];
    for target in targets {
        if !host.supports(target) {
            continue;
        }
        let mut inline = 0;
        for word in FORMS {
            let operation = FloatingPointOperation::decode(word).unwrap().unwrap();
            let mapping = compile(word, target);
            for sample in 0..96u32 {
                let mut state = GuestState {
                    fpcr: (sample & 3) << FPCR_ROUNDING_SHIFT
                        | [0, FPCR_NEP, FPCR_FZ16, FPCR_DN, FPCR_AHP][(sample % 5) as usize],
                    fpsr: next() as u32 & EXCEPTIONS,
                    ..GuestState::default()
                };
                for limb_at in state.v.as_flattened_mut() {
                    *limb_at = next();
                }
                let kind = sample / 4;
                state.v[SOURCE] = [limb(kind, &mut next), limb(kind, &mut next)];
                state.x[SOURCE] = match kind % 3 {
                    0 => next() & 0xfff,
                    1 => (next() & 0xfff).wrapping_neg(),
                    _ => next() >> (next() % 64),
                };
                inline += u32::from(check(&mapping, &operation, state));
            }
        }
        std::println!("{} inline={inline}", target.id());
        assert_eq!(inline == 0, target == TargetCpu::Baseline, "{target:?}");
    }
}
