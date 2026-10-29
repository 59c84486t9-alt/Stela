//! Real emitted Half FMA blocks against an independent fixed-point reference.
use super::*;
use crate::execution::platform::Mapping;
use stela_compiler::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{fused::FusedOperation, *},
        simd::fused::{Operand, decode},
    },
    block::{BlockProfile, CompilationPlan, ExitKind, Features},
};

const PC: u64 = 0x1000;
const PREFIX: u32 = 0x9100_0508; // ADD X8,X8,#1
const SUFFIX: u32 = 0x9100_0529; // ADD X9,X9,#1
const POISON: u64 = 0x7c01; // inactive signaling NaN

fn targets() -> Vec<TargetCpu> {
    let host = TargetCpu::detect();
    [
        TargetCpu::Baseline,
        TargetCpu::Baseline.with_fma(),
        TargetCpu::Baseline.with_f16c(),
        TargetCpu::Baseline.with_fma().with_f16c(),
    ]
    .into_iter()
    .filter(|target| host.supports(*target))
    .collect()
}

fn forms() -> Vec<u32> {
    let mut forms = vec![0x1fc0_0000, 0x1fc0_8000, 0x1fe0_0000, 0x1fe0_8000];
    for subtract in [0, 1 << 23] {
        for q in [0, 1 << 30] {
            forms.push(0x0e40_0c00 | subtract | q);
        }
    }
    for base in [0x5f00_1000, 0x0f00_1000, 0x4f00_1000] {
        for subtract in [0, 1 << 14] {
            for lane in 0..8 {
                forms.push(
                    base | subtract
                        | (lane & 1) << 20
                        | ((lane >> 1) & 1) << 21
                        | ((lane >> 2) & 1) << 11,
                );
            }
        }
    }
    assert_eq!(forms.len(), 56);
    forms
}

fn compile(word: u32, target: TargetCpu) -> (Operand, Mapping) {
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
    (operand, Mapping::new(&block.native.x86_64_code).unwrap())
}

fn input(operand: &Operand, values: [u64; 3], fpcr: u32) -> GuestState {
    let mut state = GuestState {
        x: std::array::from_fn(|i| 0x1234_5678_0000_0000 | i as u64),
        sp: 0x1234_0000,
        nzcv: 0xa000_0000,
        reserved: 0x9e71_a53c,
        v: [[POISON | POISON << 16 | POISON << 32 | POISON << 48; 2]; 32],
        fpcr,
        fpsr: 0,
    };
    for (source, value) in [(operand.addend, values[0]), (operand.left, values[1])] {
        for lane in 0..operand.shape.lane_count(Format::Half) {
            write_lane(&mut state.v[usize::from(source)], 16, lane, value);
        }
    }
    let right = &mut state.v[usize::from(operand.right)];
    if let Some(lane) = operand.right_lane {
        write_lane(right, 16, u32::from(lane), values[2]);
    } else {
        for lane in 0..operand.shape.lane_count(Format::Half) {
            write_lane(right, 16, lane, values[2]);
        }
    }
    state
}

fn exponent(bits: u64) -> i32 {
    ((bits >> 10) & 31) as i32
}

// Every finite normal Half triple is represented exactly on the 2^-48 lattice:
// P=(mL*mR) << (EL+ER-2), A=mA << (EA+23). At most81 bits are needed.
// This reference uses only integer arithmetic, independently of APFloat and the
// emitter's Double operations/packing. None denotes outside the native domain.
fn exact_lane(operation: FusedOperation, fpcr: u32, a: u64, n: u64, m: u64) -> Option<(u64, u32)> {
    let [ea, en, em] = [a, n, m].map(exponent);
    if [ea, en, em].into_iter().any(|e| !(1..31).contains(&e))
        || !(-31..=40).contains(&(en + em - ea - 15))
    {
        return None;
    }
    let signed = |bits: u64, negate: bool| {
        if (bits & 0x8000 != 0) ^ negate {
            -1i128
        } else {
            1
        }
    };
    let addend = i128::from((a & 1023) + 1024) << (ea + 23);
    let product = i128::from(((n & 1023) + 1024) * ((m & 1023) + 1024)) << (en + em - 2);
    let exact = signed(a, operation.negate_addend()) * addend
        + signed(n, operation.negate_left()) * signed(m, false) * product;
    if exact == 0 {
        return None;
    }
    let magnitude = exact.unsigned_abs();
    let leading = 127 - magnitude.leading_zeros();
    let mut result_exponent = leading as i32 - 33;
    if !(2..=30).contains(&result_exponent) {
        return None;
    }
    let shift = leading - 10;
    let remainder = magnitude & ((1 << shift) - 1);
    let mut significand = magnitude >> shift;
    let increment = match (fpcr >> FPCR_ROUNDING_SHIFT) & 3 {
        0 => {
            remainder > (1 << (shift - 1))
                || remainder == (1 << (shift - 1)) && significand & 1 != 0
        }
        1 => exact > 0 && remainder != 0,
        2 => exact < 0 && remainder != 0,
        _ => false,
    };
    significand += u128::from(increment);
    if significand == 2048 {
        significand >>= 1;
        result_exponent += 1;
    }
    if !(2..=30).contains(&result_exponent) {
        return None;
    }
    Some((
        (u64::from(exact < 0) << 15) | (result_exponent as u64) << 10 | (significand as u64 & 1023),
        if remainder != 0 { INEXACT } else { 0 },
    ))
}

fn reference(state: &GuestState, operand: &Operand) -> Option<GuestState> {
    if state.fpcr & FPCR_EXCEPTION_ENABLE_MASK != 0 {
        return None;
    }
    let mut expected = state.clone();
    let mut result = if operand.shape == Shape::Scalar && state.fpcr & FPCR_NEP != 0 {
        state.v[usize::from(operand.addend)]
    } else {
        [0; 2]
    };
    let mut status = 0;
    for lane in 0..operand.shape.lane_count(Format::Half) {
        let a = read_lane(&state.v[usize::from(operand.addend)], 16, lane);
        let n = read_lane(&state.v[usize::from(operand.left)], 16, lane);
        let m = read_lane(
            &state.v[usize::from(operand.right)],
            16,
            operand.right_lane.map_or(lane, u32::from),
        );
        let (bits, exceptions) = exact_lane(operand.operation, state.fpcr, a, n, m)?;
        // The separate complete architectural model must agree too.
        let model = fused::evaluate(Format::Half, operand.operation, state.fpcr, a, n, m).unwrap();
        assert_eq!((model.bits, model.exceptions), (bits, exceptions));
        write_lane(&mut result, 16, lane, bits);
        status |= exceptions;
    }
    expected.v[usize::from(operand.destination)] = result;
    expected.fpsr |= status;
    Some(expected)
}

fn mxcsr() -> u32 {
    let mut value = 0;
    // SAFETY: valid writable output on this baseline SSE2 host.
    unsafe {
        core::arch::asm!("stmxcsr [{p}]", p = in(reg) &mut value, options(nostack, preserves_flags));
    }
    value
}
fn set_mxcsr(value: u32) {
    // SAFETY: test callers provide only defined baseline SSE control/status bits.
    unsafe {
        core::arch::asm!("ldmxcsr [{p}]", p = in(reg) &value, options(nostack, preserves_flags));
    }
}

fn check(mapping: &Mapping, operand: &Operand, mut state: GuestState, caller: u32) -> bool {
    let input = state.clone();
    let fast = reference(&state, operand);
    let native = fast.is_some();
    let mut expected = fast.unwrap_or_else(|| state.clone());
    expected.x[8] += 1;
    if native {
        expected.x[9] += 1;
    }
    let saved = mxcsr();
    set_mxcsr(caller);
    // SAFETY: this host's owned RX image contains three non-memory instructions
    // under the one-pointer block ABI; source/destination snapshots are private.
    let exit = unsafe { mapping.call_block(&mut state) };
    let actual_csr = mxcsr();
    set_mxcsr(saved);
    assert_eq!(actual_csr, caller, "MXCSR {operand:?}");
    let exit = exit.unwrap();
    assert_eq!(
        exit.next_pc,
        if native { PC + 12 } else { PC + 4 },
        "{operand:?} {input:?}"
    );
    assert_eq!(
        exit.kind,
        if native {
            ExitKind::Fallthrough
        } else {
            ExitKind::FloatingPoint
        } as u64
    );
    assert_eq!(state, expected, "{operand:?} native={native} {input:?}");
    native
}

#[test]
fn half_fma_forms_aliases_rounding_controls_and_host_environment() {
    let triples = [
        [0x3c00, 0x4000, 0x4200],
        [0x0400, 0x5200, 0x5003],
        [0xbc00, 0x3c01, 0x3bfe],
        [0x3c00, 0xbc00, 0x3c00],
        [0x3c00, 0x3c00, 0x3c00],
        [0x3c01, 0x3801, 0x3801],
        [0x0400, 0x0400, 0x0400],
        [0x7bff, 0x7bff, 0x7bff],
        [0x0800, 0x0800, 0x0800],
        [0, 0x3c00, 0x3c00],
        [0x8000, 0x3c00, 0x3c00],
        [1, 0x3c00, 0x3c00],
        [0x7c00, 0x3c00, 0x3c00],
        [0x7c01, 0x3c00, 0x3c00],
        [0x7e01, 0x3c00, 0x3c00],
        [0x7800, 0x0400, 0x0400],
    ];
    let mut native = 0;
    let mut helper = 0;
    for target in targets() {
        for base in forms() {
            let initial = decode(base).unwrap().unwrap();
            for (d, n, m, a) in [
                (0, 1, 2, 3),
                (1, 1, 2, 3),
                (2, 1, 2, 3),
                (3, 1, 2, 3),
                (31, 31, 15, 31),
                (15, 15, 15, 15),
            ] {
                let word = base
                    | d
                    | n << 5
                    | m << 16
                    | if initial.shape == Shape::Scalar && initial.right_lane.is_none() {
                        a << 10
                    } else {
                        0
                    };
                let (operand, mapping) = compile(word, target);
                for (case, values) in triples.into_iter().enumerate() {
                    for rc in 0..4 {
                        for controls in [
                            0,
                            FPCR_AH
                                | FPCR_NEP
                                | FPCR_FZ
                                | FPCR_FIZ
                                | FPCR_DN
                                | FPCR_AHP
                                | FPCR_FZ16,
                        ] {
                            let mut state =
                                input(&operand, values, controls | rc << FPCR_ROUNDING_SHIFT);
                            if case % 2 != 0 {
                                state.fpsr = FPSR_QC | EXCEPTIONS | (1 << 31);
                            }
                            let fast = check(
                                &mapping,
                                &operand,
                                state,
                                [0x1f80, 0, 0xffff, 0x8040][case % 4],
                            );
                            if fast {
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
    assert!(native > 0 && helper > 0);
}

#[test]
fn half_fma_all_normal_exponents_and_exact_span_edges() {
    for target in [TargetCpu::Baseline, TargetCpu::detect()] {
        let (operand, mapping) = compile(0x1fc2_0c20, target); // FMADD H0,H1,H2,H3
        for ea in 1..31 {
            for en in 1..31 {
                for em in 1..31 {
                    let bits = |e: u64, m| e << 10 | m;
                    let fpcr = ((ea + en + em) as u32 & 3) << FPCR_ROUNDING_SHIFT;
                    let values = [
                        bits(ea, ea % 2 * 1023),
                        bits(en, en % 2 * 1023),
                        bits(em, em % 2 * 1023),
                    ];
                    check(&mapping, &operand, input(&operand, values, fpcr), 0x1f80);
                    let d = en as i32 + em as i32 - ea as i32 - 15;
                    if (-31..=40).contains(&d) {
                        let q = d - 10;
                        assert!(22.max(22 + q.max(0)).max(11 + (-q).max(0)) < 53);
                    }
                }
            }
        }
    }
}

#[test]
fn half_fma_last_lane_rollback_and_enabled_exceptions_preserve_state() {
    for target in targets() {
        for base in forms() {
            let scalar = decode(base).unwrap().unwrap();
            let word = base
                | 1 << 5
                | 2 << 16
                | if scalar.shape == Shape::Scalar && scalar.right_lane.is_none() {
                    3 << 10
                } else {
                    0
                };
            let (operand, mapping) = compile(word, target);
            for ah in [0, FPCR_AH] {
                for enable in 0..32 {
                    let enabled = 1u32 << enable;
                    if enabled & FPCR_EXCEPTION_ENABLE_MASK == 0 {
                        continue;
                    }
                    let state = input(&operand, [0x3c00, 0x4000, 0x4200], ah | enabled);
                    assert!(!check(&mapping, &operand, state, 0xffff));
                }
            }
            for source in [operand.addend, operand.left, operand.right] {
                for bad in [0, 0x8000, 1, 0x7c00, 0x7c01, 0x7e01] {
                    let mut state = input(&operand, [0x3c01, 0x4001, 0x4201], FPCR_NEP | FPCR_AH);
                    let lane = if source == operand.right {
                        operand.right_lane.map(u32::from)
                    } else {
                        None
                    }
                    .unwrap_or_else(|| operand.shape.lane_count(Format::Half) - 1);
                    write_lane(&mut state.v[usize::from(source)], 16, lane, bad);
                    assert!(!check(&mapping, &operand, state, 0xffff));
                }
            }
            if operand.shape != Shape::Scalar {
                let mut state = input(&operand, [0x1001, 0x4001, 0x4201], 0);
                // Last output cancels after prior inexact lanes staged pending IXC.
                let lane = operand.shape.lane_count(Format::Half) - 1;
                write_lane(&mut state.v[usize::from(operand.addend)], 16, lane, 0xbc00);
                write_lane(&mut state.v[usize::from(operand.left)], 16, lane, 0x3c00);
                if let Some(index) = operand.right_lane {
                    write_lane(
                        &mut state.v[usize::from(operand.right)],
                        16,
                        u32::from(index),
                        0x3c00,
                    );
                } else {
                    write_lane(&mut state.v[usize::from(operand.right)], 16, lane, 0x3c00);
                }
                if operand.operation == FusedOperation::Subtract {
                    write_lane(&mut state.v[usize::from(operand.addend)], 16, lane, 0x3c00);
                }
                let a = read_lane(&state.v[usize::from(operand.addend)], 16, 0);
                let n = read_lane(&state.v[usize::from(operand.left)], 16, 0);
                let m = read_lane(
                    &state.v[usize::from(operand.right)],
                    16,
                    operand.right_lane.map_or(0, u32::from),
                );
                assert_eq!(
                    exact_lane(operand.operation, state.fpcr, a, n, m)
                        .unwrap()
                        .1,
                    INEXACT
                );
                assert!(!check(&mapping, &operand, state, 0));
            }
        }
    }
}

#[test]
fn half_fma_signed_random_lanes_and_controls_match_exact_integer_rounding() {
    let mut random = 0x937a_158c_6d24_be01u64;
    let mut next = || {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        random
    };
    for target in targets() {
        for base in forms() {
            let scalar = decode(base).unwrap().unwrap();
            let word = base
                | 1 << 5
                | 2 << 16
                | if scalar.shape == Shape::Scalar && scalar.right_lane.is_none() {
                    3 << 10
                } else {
                    0
                };
            let (operand, mapping) = compile(word, target);
            for _ in 0..128 {
                let mut state = input(
                    &operand,
                    [0x3c00; 3],
                    next() as u32 & !FPCR_EXCEPTION_ENABLE_MASK,
                );
                state.fpsr = next() as u32;
                for source in [operand.addend, operand.left, operand.right] {
                    // Poison inactive lanes stays intact; every active lane has
                    // independent sign/exponent/mantissa, not a repeated vector.
                    if let Some(index) = operand.right_lane.filter(|_| source == operand.right) {
                        let bits = next();
                        let normal = (bits & 0x83ff) | ((bits >> 16) % 30 + 1) << 10;
                        write_lane(
                            &mut state.v[usize::from(source)],
                            16,
                            u32::from(index),
                            normal,
                        );
                    } else {
                        for lane in 0..operand.shape.lane_count(Format::Half) {
                            let bits = next();
                            let normal = (bits & 0x83ff) | ((bits >> 16) % 30 + 1) << 10;
                            write_lane(&mut state.v[usize::from(source)], 16, lane, normal);
                        }
                    }
                }
                check(
                    &mapping,
                    &operand,
                    state,
                    [0x1f80, 0, 0xffff, 0x8040][next() as usize % 4],
                );
            }
        }
    }
}
