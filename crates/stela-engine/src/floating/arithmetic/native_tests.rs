//! Full-state qualification of the emitted S/D full path and precise fallback.
use super::*;
use crate::execution::platform::Mapping;
use stela_compiler::{
    GuestAddress, TargetCpu,
    aarch64::{floating::*, simd::arithmetic::decode},
    block::{BlockProfile, CompilationPlan, ExitKind, Features},
};

const PC: u64 = 0x1000;
const PREFIX: u32 = 0x9100_0508; // ADD X8,X8,#1
const SUFFIX: u32 = 0x9100_0529; // ADD X9,X9,#1
const FORMAT_DOUBLE: u32 = 1 << 22;
const VECTOR_128: u32 = 1 << 30;

fn fraction_bits(format: Format) -> u32 {
    match format {
        Format::Half => 10,
        Format::Single => 23,
        Format::Double => 52,
    }
}
fn sign_mask(format: Format) -> u64 {
    1 << (format.bits() - 1)
}
fn exponent_mask(format: Format) -> u64 {
    (sign_mask(format) - 1) & !((1 << fraction_bits(format)) - 1)
}
fn one_bits(format: Format) -> u64 {
    match format {
        Format::Half => 0x3c00,
        Format::Single => 0x3f80_0000,
        Format::Double => 0x3ff0_0000_0000_0000,
    }
}

fn forms() -> Vec<u32> {
    let mut words = Vec::new();
    for format in [0, FORMAT_DOUBLE] {
        for base in [
            0x1e20_2800,
            0x1e20_3800,
            0x1e20_0800,
            0x1e20_1800,
            0x1e20_8800,
            0x7ea0_d400,
            0x5e20_dc00,
            0x7e30_d800,
        ] {
            words.push(base | format);
        }
    }
    for arrangement in [0, VECTOR_128, VECTOR_128 | FORMAT_DOUBLE] {
        for base in [
            0x0e20_d400,
            0x0ea0_d400,
            0x2e20_dc00,
            0x2e20_fc00,
            0x2ea0_d400,
            0x0e20_dc00,
            0x2e20_d400,
        ] {
            words.push(base | arrangement);
        }
    }
    for base in [0x5f80_9000, 0x0f80_9000, 0x4f80_9000] {
        for extended in [0, 1 << 29] {
            for lane in 0..4 {
                words.push(base | extended | (lane & 1) << 21 | (lane >> 1) << 11);
            }
            if base != 0x0f80_9000 {
                for lane in 0..2 {
                    words.push(base | extended | FORMAT_DOUBLE | lane << 11);
                }
            }
        }
    }
    words
}

fn input(operand: &Operand, a: u64, b: u64, fpcr: u32) -> GuestState {
    let format = operand.format;
    let poison = exponent_mask(format) | 1;
    let mut state = GuestState {
        x: std::array::from_fn(|i| 0x1234_5678_0000_0000 | i as u64),
        sp: 0x1234_0000,
        nzcv: 0xa000_0000,
        reserved: 0x9e71_a53c,
        v: [[0; 2]; 32],
        fpcr,
        // IXC starts clear, forcing the full path even under default FPCR.
        fpsr: FPSR_QC | INVALID | DIVIDE_BY_ZERO,
    };
    for vector in &mut state.v {
        for lane in 0..Shape::Vector128.lane_count(format) {
            write_lane(vector, format.bits(), lane, poison);
        }
    }
    let lanes = operand.shape.lane_count(format);
    match operand.inputs {
        Inputs::Elementwise { left, right } => {
            for lane in 0..lanes {
                write_lane(&mut state.v[usize::from(left)], format.bits(), lane, a);
                write_lane(&mut state.v[usize::from(right)], format.bits(), lane, b);
            }
        }
        Inputs::Indexed {
            left,
            right,
            right_lane,
        } => {
            for lane in 0..lanes {
                write_lane(&mut state.v[usize::from(left)], format.bits(), lane, a);
            }
            write_lane(
                &mut state.v[usize::from(right)],
                format.bits(),
                u32::from(right_lane),
                b,
            );
        }
        Inputs::Pairwise { left, right } => {
            for source in [left, right] {
                for lane in 0..lanes {
                    write_lane(
                        &mut state.v[usize::from(source)],
                        format.bits(),
                        lane,
                        if lane % 2 == 0 { a } else { b },
                    );
                }
            }
        }
        Inputs::PairwiseScalar { source } => {
            write_lane(&mut state.v[usize::from(source)], format.bits(), 0, a);
            write_lane(&mut state.v[usize::from(source)], format.bits(), 1, b);
        }
    }
    state
}

fn inputs(state: &GuestState, operand: &Operand, lane: u32) -> (u64, u64) {
    let bits = operand.format.bits();
    let get = |source: u8, lane| read_lane(&state.v[usize::from(source)], bits, lane);
    match operand.inputs {
        Inputs::Elementwise { left, right } => (get(left, lane), get(right, lane)),
        Inputs::Indexed {
            left,
            right,
            right_lane,
        } => (get(left, lane), get(right, u32::from(right_lane))),
        Inputs::Pairwise { left, right } => {
            let pairs = operand.shape.lane_count(operand.format) / 2;
            let (source, pair) = if lane < pairs {
                (left, lane)
            } else {
                (right, lane - pairs)
            };
            (get(source, pair * 2), get(source, pair * 2 + 1))
        }
        Inputs::PairwiseScalar { source } => (get(source, 0), get(source, 1)),
    }
}

fn native_domain(state: &GuestState, operand: &Operand) -> bool {
    if state.fpcr & FPCR_EXCEPTION_ENABLE_MASK != 0 {
        return false;
    }
    let format = operand.format;
    let exponent = |raw| (raw & exponent_mask(format)) >> fraction_bits(format);
    let maximum = exponent_mask(format) >> fraction_bits(format);
    let zero = |raw| raw & !sign_mask(format) == 0;
    let allows_zero = operand.operation != BinaryOperation::Divide;
    (0..operand.shape.lane_count(format)).all(|lane| {
        let (a, b) = inputs(state, operand, lane);
        let valid = |raw| (1..maximum).contains(&exponent(raw)) || allows_zero && zero(raw);
        if !valid(a) || !valid(b) {
            return false;
        }
        let outcome = evaluate(format, operand.operation, state.fpcr, a, b).unwrap();
        outcome.exceptions & !INEXACT == 0
            && ((2..maximum).contains(&exponent(outcome.bits)) || allows_zero && zero(outcome.bits))
    })
}

fn mxcsr() -> u32 {
    let mut value = 0;
    // SAFETY: valid writable storage on this baseline SSE2 host.
    unsafe {
        core::arch::asm!("stmxcsr [{p}]", p = in(reg) &mut value, options(nostack, preserves_flags));
    }
    value
}

fn set_mxcsr(value: u32) {
    // SAFETY: the test supplies only defined baseline SSE control/status bits.
    unsafe {
        core::arch::asm!("ldmxcsr [{p}]", p = in(reg) &value, options(nostack, preserves_flags));
    }
}

fn check(mapping: &Mapping, operand: &Operand, mut state: GuestState, caller: u32) -> bool {
    let fast = native_domain(&state, operand);
    let mut expected = state.clone();
    expected.x[8] += 1;
    if fast {
        complete(&mut expected, operand).unwrap();
        expected.x[9] += 1;
    }
    let saved = mxcsr();
    set_mxcsr(caller);
    // SAFETY: the owned block contains only non-memory instructions, compiled
    // for this host. State satisfies its ordinary one-pointer block ABI.
    let exit = unsafe { mapping.call_block(&mut state) };
    let actual_csr = mxcsr();
    set_mxcsr(saved);
    assert_eq!(actual_csr, caller, "MXCSR {operand:?}");
    let exit = exit.unwrap();
    assert_eq!(
        exit.next_pc,
        if fast { PC + 12 } else { PC + 4 },
        "{operand:?} fpcr={:#x} {state:?}",
        state.fpcr
    );
    assert_eq!(
        exit.kind,
        if fast {
            ExitKind::Fallthrough as u64
        } else {
            ExitKind::FloatingPoint as u64
        }
    );
    assert_eq!(state, expected, "{operand:?} native={fast}");
    fast
}

#[test]
fn full_path_zeros_rounding_aliases_and_host_environment_match_completion() {
    let mut native = 0;
    let mut helper = 0;
    for target in [TargetCpu::Baseline, TargetCpu::detect()] {
        for base in forms() {
            let initial = decode(base).unwrap().unwrap();
            for (d, n, m) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 31, 31)] {
                let word = base
                    | d
                    | n << 5
                    | if matches!(initial.inputs, Inputs::PairwiseScalar { .. }) {
                        0
                    } else {
                        m << 16
                    };
                let operand = decode(word).unwrap().unwrap();
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
                let mapping = Mapping::new(&block.native.x86_64_code).unwrap();
                let format = operand.format;
                let one = one_bits(format);
                let sign = sign_mask(format);
                let tiny_normal = 1 << fraction_bits(format);
                let maximum = exponent_mask(format) - 1;
                for (case, (a, b)) in [
                    (0, 0),
                    (0, sign),
                    (sign, 0),
                    (sign, sign),
                    (0, one),
                    (one | sign, 0),
                    (one, one | sign),
                    (one, one),
                    (one + 1, one + 1),
                    (0, tiny_normal),
                    (tiny_normal, tiny_normal),
                    (tiny_normal, one),
                    (maximum, maximum),
                    (1, 0),
                    (1 << 32, 0),
                    (exponent_mask(format), 0),
                    (exponent_mask(format) | 1, one),
                ]
                .into_iter()
                .enumerate()
                {
                    for rc in 0..4 {
                        for controls in [
                            0,
                            FPCR_FZ,
                            FPCR_FIZ,
                            FPCR_AH,
                            FPCR_AH | FPCR_FZ | FPCR_FIZ,
                            FPCR_NEP,
                            FPCR_NEP | FPCR_FZ,
                            FPCR_FZ | FPCR_DN | FPCR_AHP | FPCR_FZ16,
                        ] {
                            let state = input(&operand, a, b, controls | rc << FPCR_ROUNDING_SHIFT);
                            if check(
                                &mapping,
                                &operand,
                                state,
                                [0x1f80, 0, 0xffff, 0x8040][case % 4],
                            ) {
                                native += 1;
                            } else {
                                helper += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(
        native > 1000 && helper > 1000,
        "native={native} helper={helper}"
    );
}

#[test]
fn full_path_enabled_exceptions_keep_the_prefix_and_original_state() {
    for base in [0x1e22_2820, 0x1e62_0820, 0x4e22_d420, 0x6e62_dc20] {
        let operand = decode(base).unwrap().unwrap();
        let source: Vec<_> = [PREFIX, base, SUFFIX]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let block = CompilationPlan::new(
            &source,
            GuestAddress(PC),
            &stela_compiler::Options::new(
                BlockProfile::new(Features::SYSTEM_MODE),
                TargetCpu::Baseline,
            ),
        )
        .unwrap()
        .compile()
        .unwrap();
        let mapping = Mapping::new(&block.native.x86_64_code).unwrap();
        for bit in 0..32 {
            let enable = 1 << bit;
            if enable & FPCR_EXCEPTION_ENABLE_MASK == 0 {
                continue;
            }
            for controls in [0, FPCR_AH | FPCR_NEP | FPCR_FZ | FPCR_FIZ] {
                assert!(!check(
                    &mapping,
                    &operand,
                    input(&operand, 0, 0, controls | enable),
                    0xffff
                ));
            }
        }
    }
}

#[test]
fn full_path_mixed_lanes_preserve_distinct_pairs_and_reject_late_bad_inputs() {
    for word in [0x6e62_d420, 0x4e22_d420, 0x6e22_dc20] {
        let operand = decode(word).unwrap().unwrap();
        let source: Vec<_> = [PREFIX, word, SUFFIX]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let block = CompilationPlan::new(
            &source,
            GuestAddress(PC),
            &stela_compiler::Options::new(
                BlockProfile::new(Features::SYSTEM_MODE),
                TargetCpu::Baseline,
            ),
        )
        .unwrap()
        .compile()
        .unwrap();
        let mapping = Mapping::new(&block.native.x86_64_code).unwrap();
        let format = operand.format;
        let one = one_bits(format);
        let two = one + (1 << fraction_bits(format));
        let lanes = operand.shape.lane_count(format);
        let mut state = input(&operand, one, one, FPCR_FZ | FPCR_NEP);
        // Sticky IXC must not bypass the full path when FZ is enabled.
        state.fpsr = FPSR_QC | EXCEPTIONS;
        for lane in 0..lanes {
            let left = [0, one + 1, two, one][lane as usize];
            let right = [two, one + 1, one, two][lane as usize];
            write_lane(&mut state.v[1], format.bits(), lane, left);
            write_lane(&mut state.v[2], format.bits(), lane, right);
        }
        assert!(check(&mapping, &operand, state.clone(), 0xffff));
        for bad in [1, exponent_mask(format) | 1] {
            let mut rejected = state.clone();
            write_lane(&mut rejected.v[2], format.bits(), lanes - 1, bad);
            assert!(!check(&mapping, &operand, rejected, 0x8040));
        }
        if format == Format::Double {
            write_lane(&mut state.v[2], format.bits(), lanes - 1, 1 << 32);
            assert!(!check(&mapping, &operand, state, 0x1f80));
        }
    }
}
