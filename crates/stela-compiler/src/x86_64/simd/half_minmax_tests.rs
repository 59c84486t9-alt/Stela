//! Half FMAX/FMIN/FMAXNM/FMINNM (scalar, 4H, 8H) against the Arm reference,
//! compiled as blocks for every tier this host has: every inline completion
//! matches the reference in every V register and FPSR, every exit leaves
//! the state unchanged, and inputs without a NaN (zeros, subnormals and
//! infinities included, FZ16 flushing) complete without an exit wherever
//! AH and the trap enables are clear.
use crate::{
    GuestAddress, GuestState, Options, TargetCpu,
    aarch64::floating::{
        self, FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FZ16, FPCR_NEP, Format,
        minmax::MinMaxOperation,
    },
    block::{BlockProfile, CompilationPlan},
    x86_64::native::run,
};
use alloc::vec::Vec;

const PC: GuestAddress = GuestAddress(0x1000_0000);
const RETURN: u64 = 0x4000;
const D: u32 = 3;
const N: u32 = 4;
const M: u32 = 17;

fn targets() -> Vec<TargetCpu> {
    let host = TargetCpu::detect();
    [
        TargetCpu::Baseline,
        TargetCpu::Sse41,
        TargetCpu::X86_64_V2,
        TargetCpu::X86_64_V3,
        TargetCpu::X86_64_V4,
        TargetCpu::X86_64_V4.with_data_independent_timing(),
        host,
    ]
    .into_iter()
    .filter(|target| host.supports(*target))
    .collect()
}

fn compile(word: u32, target: TargetCpu) -> Vec<u8> {
    let source = [word, 0xd65f_03c0].map(u32::to_le_bytes).concat();
    CompilationPlan::new(&source, PC, &Options::new(BlockProfile::ORDINARY, target))
        .unwrap()
        .compile()
        .unwrap()
        .native
        .x86_64_code
}

fn controls() -> [u32; 7] {
    [
        0,
        FPCR_FZ16,
        FPCR_DN,
        FPCR_NEP,
        FPCR_FZ16 | FPCR_NEP,
        FPCR_AH,
        FPCR_EXCEPTION_ENABLE_MASK,
    ]
}

/// Zeros, subnormals, normals, the largest finite value, infinities and
/// NaNs (both signs).
fn halves() -> Vec<u16> {
    let mut values = Vec::new();
    for exponent in [0u16, 1, 14, 15, 29, 30] {
        for fraction in [0u16, 1, 0x200, 0x3ff] {
            values.push(exponent << 10 | fraction);
        }
    }
    values.extend([0x7c00, 0x7e00, 0x7c01]);
    let positive = values.len();
    for index in 0..positive {
        values.push(values[index] | 0x8000);
    }
    values
}

fn word(operation: MinMaxOperation, lanes: u32) -> u32 {
    let registers = M << 16 | N << 5 | D;
    if lanes == 0 {
        let base = match operation {
            MinMaxOperation::Maximum => 0x1ee0_4800,
            MinMaxOperation::Minimum => 0x1ee0_5800,
            MinMaxOperation::MaximumNumber => 0x1ee0_6800,
            MinMaxOperation::MinimumNumber => 0x1ee0_7800,
        };
        return base | registers;
    }
    let base = match operation {
        MinMaxOperation::Maximum => 0x0e40_3400,
        MinMaxOperation::Minimum => 0x0ec0_3400,
        MinMaxOperation::MaximumNumber => 0x0e40_0400,
        MinMaxOperation::MinimumNumber => 0x0ec0_0400,
    };
    base | u32::from(lanes == 8) << 30 | registers
}

fn lane(vector: [u64; 2], index: usize) -> u64 {
    vector[index / 4] >> (16 * (index % 4)) & 0xffff
}

fn set_lane(vector: &mut [u64; 2], index: usize, bits: u64) {
    let shift = 16 * (index % 4);
    vector[index / 4] = vector[index / 4] & !(0xffff << shift) | bits << shift;
}

fn reference(operation: MinMaxOperation, lanes: u32, initial: &GuestState) -> Option<GuestState> {
    let n = initial.v[N as usize];
    let m = initial.v[M as usize];
    let mut expected = initial.clone();
    let mut result = if lanes == 0 && initial.fpcr & FPCR_NEP != 0 {
        n
    } else {
        [0; 2]
    };
    for index in 0..lanes.max(1) as usize {
        let outcome = floating::minmax::evaluate(
            Format::Half,
            operation,
            initial.fpcr,
            lane(n, index),
            lane(m, index),
        )
        .ok()?;
        expected.fpsr |= outcome.exceptions;
        set_lane(&mut result, index, outcome.bits);
    }
    expected.v[D as usize] = result;
    Some(expected)
}

#[test]
fn ordered_half_minmax_completes_inline() {
    use MinMaxOperation::*;
    let all = halves();
    let mut inline = 0usize;
    let mut runs = 0usize;
    for target in targets() {
        for operation in [Maximum, Minimum, MaximumNumber, MinimumNumber] {
            for lanes in [0, 4, 8] {
                let code = compile(word(operation, lanes), target);
                let count = lanes.max(1) as usize;
                for start in 0..all.len() {
                    let mut n = [0x5a5a_a5a5_3c3c_c3c3u64, 0x0123_4567_89ab_cdef];
                    let mut m = [0x7654_3210_fedc_ba98u64, 0xc3c3_3c3c_a5a5_5a5a];
                    for index in 0..count {
                        set_lane(&mut n, index, u64::from(all[(start + index) % all.len()]));
                        set_lane(
                            &mut m,
                            index,
                            u64::from(all[(start * 7 + index * 3 + 1) % all.len()]),
                        );
                    }
                    let ordered = (0..count).all(|index| {
                        [lane(n, index), lane(m, index)]
                            .iter()
                            .all(|bits| bits & 0x7fff <= 0x7c00)
                    });
                    for fpcr in controls() {
                        let mut initial = GuestState {
                            fpcr,
                            fpsr: 0x0800_0000,
                            ..GuestState::default()
                        };
                        initial.x[30] = RETURN;
                        initial.v[N as usize] = n;
                        initial.v[M as usize] = m;
                        initial.v[D as usize] = [0xdead_beef_0bad_f00d, 0xfeed_face_cafe_d00d];
                        let mut actual = initial.clone();
                        let exit = run(&code, &mut actual);
                        runs += 1;
                        let label = || {
                            alloc::format!(
                                "{operation:?} {lanes} {n:x?} {m:x?} {fpcr:#x} {target:?}"
                            )
                        };
                        if exit == PC.0 {
                            assert_eq!(actual, initial, "{}", label());
                            let must_inline = ordered
                                && fpcr & (FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK) == 0
                                && !target.data_independent_timing();
                            assert!(!must_inline, "exited: {}", label());
                            continue;
                        }
                        assert_eq!(exit, RETURN, "{}", label());
                        let expected =
                            reference(operation, lanes, &initial).expect("completed with traps");
                        assert_eq!(
                            actual,
                            expected,
                            "{} got fpsr {:#x} v {:x?} want {:#x} {:x?}",
                            label(),
                            actual.fpsr,
                            actual.v[D as usize],
                            expected.fpsr,
                            expected.v[D as usize]
                        );
                        inline += 1;
                    }
                }
            }
        }
    }
    assert!(inline > runs / 3, "{inline} of {runs}");
}
