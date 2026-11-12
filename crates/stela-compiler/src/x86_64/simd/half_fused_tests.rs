//! Vector Half FMLA and FMLS (by vector and by element, 4H and 8H) against
//! the Arm reference, compiled as blocks for every tier this host has:
//! every inline completion matches the reference in every V register and
//! FPSR, every exit leaves the state unchanged, and on AVX2 hosts with
//! F16C every input (zeros, subnormals, infinities and NaNs included)
//! completes without an exit in every rounding mode unless AH or a trap
//! enable is set, but for a quiet NaN addend with a NaN product and a
//! result FZ16 may flush.
use crate::{
    GuestAddress, GuestState, Options, TargetCpu,
    aarch64::floating::{
        self, FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FZ16, FPCR_NEP,
        FPCR_ROUNDING_SHIFT, Format, fused::FusedOperation,
    },
    block::{BlockProfile, CompilationPlan},
    x86_64::{asm::vector_extensions, native::run},
};
use alloc::vec::Vec;

const PC: GuestAddress = GuestAddress(0x1000_0000);
const RETURN: u64 = 0x4000;
const D: u32 = 3;
const N: u32 = 4;
const M: u32 = 9;

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

fn controls() -> [u32; 8] {
    [
        0,
        1 << FPCR_ROUNDING_SHIFT,
        2 << FPCR_ROUNDING_SHIFT,
        3 << FPCR_ROUNDING_SHIFT,
        FPCR_DN,
        FPCR_FZ16,
        FPCR_AH,
        FPCR_EXCEPTION_ENABLE_MASK,
    ]
}

/// Zeros, subnormals, normals across the range, the largest finite value,
/// infinities and NaNs (both signs) and random values.
fn halves() -> Vec<u16> {
    let mut values = Vec::new();
    for exponent in [0u16, 1, 2, 7, 14, 15, 16, 22, 29, 30] {
        for fraction in [0u16, 1, 0x155, 0x200, 0x3ff] {
            values.push(exponent << 10 | fraction);
        }
    }
    values.extend([0x7c00, 0x7e00, 0x7c01]);
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    for _ in 0..40 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        // Mostly finite magnitudes.
        values.push((seed as u16) % 0x7800);
    }
    let positive = values.len();
    for index in 0..positive {
        values.push(values[index] | 0x8000);
    }
    values
}

/// Whether a lane must complete inline on the packed recipe: every one but
/// a quiet NaN addend with a NaN product (a NaN factor, or infinity times
/// zero, which Arm makes the default NaN).
fn completes(addend: u64, left: u64, right: u64) -> bool {
    let magnitude = |bits: u64| bits & 0x7fff;
    let nan = |bits: u64| magnitude(bits) > 0x7c00;
    let infinite_zero = |a: u64, b: u64| magnitude(a) == 0x7c00 && magnitude(b) == 0;
    let nan_product =
        nan(left) || nan(right) || infinite_zero(left, right) || infinite_zero(right, left);
    !(nan(addend) && addend & 0x200 != 0 && nan_product)
}

/// Under FZ16, whether Arm may flush the result: with the inputs flushed,
/// the unflushed result is nonzero and at most the minimum normal, or
/// underflows (to zero).
fn flushes(operation: FusedOperation, fpcr: u32, addend: u64, left: u64, right: u64) -> bool {
    let flush = |bits: u64| {
        if bits & 0x7c00 == 0 {
            bits & 0x8000
        } else {
            bits
        }
    };
    fpcr & FPCR_FZ16 != 0
        && floating::fused::evaluate(
            Format::Half,
            operation,
            fpcr & !FPCR_FZ16,
            flush(addend),
            flush(left),
            flush(right),
        )
        .is_ok_and(|outcome| {
            let magnitude = outcome.bits & 0x7fff;
            magnitude != 0 && magnitude <= 0x0400 || outcome.exceptions & floating::UNDERFLOW != 0
        })
}

#[derive(Clone, Copy, Debug)]
struct Form {
    subtract: bool,
    /// The element index of a by-element form.
    element: Option<u32>,
    lanes: u32,
}

fn word(form: Form) -> u32 {
    let q = u32::from(form.lanes == 8);
    match form.element {
        None => 0x0e40_0c00 | q << 30 | u32::from(form.subtract) << 23 | M << 16 | N << 5 | D,
        Some(index) => {
            0x0f00_1000
                | q << 30
                | u32::from(form.subtract) << 14
                | (index >> 1 & 1) << 21
                | (index & 1) << 20
                | M << 16
                | (index >> 2) << 11
                | N << 5
                | D
        }
    }
}

fn lane(vector: [u64; 2], index: usize) -> u64 {
    vector[index / 4] >> (16 * (index % 4)) & 0xffff
}

fn set_lane(vector: &mut [u64; 2], index: usize, bits: u64) {
    let shift = 16 * (index % 4);
    vector[index / 4] = vector[index / 4] & !(0xffff << shift) | bits << shift;
}

fn reference(form: Form, initial: &GuestState) -> Option<GuestState> {
    let operation = if form.subtract {
        FusedOperation::Subtract
    } else {
        FusedOperation::Add
    };
    let mut expected = initial.clone();
    let mut result = [0u64; 2];
    for index in 0..form.lanes as usize {
        let right = match form.element {
            Some(element) => lane(initial.v[M as usize], element as usize),
            None => lane(initial.v[M as usize], index),
        };
        let outcome = floating::fused::evaluate(
            Format::Half,
            operation,
            initial.fpcr,
            lane(initial.v[D as usize], index),
            lane(initial.v[N as usize], index),
            right,
        )
        .ok()?;
        expected.fpsr |= outcome.exceptions;
        set_lane(&mut result, index, outcome.bits);
    }
    expected.v[D as usize] = result;
    Some(expected)
}

#[test]
fn half_fused_lanes_complete_inline() {
    let all = halves();
    let mut inline = 0usize;
    let mut runs = 0usize;
    for target in targets() {
        let wide = target.supports(TargetCpu::Avx2)
            && target.supports(TargetCpu::F16c)
            && !target.data_independent_timing()
            && !vector_extensions::half_supported(target);
        for subtract in [false, true] {
            for element in [None, Some(5)] {
                for lanes in [4, 8] {
                    let form = Form {
                        subtract,
                        element,
                        lanes,
                    };
                    let code = compile(word(form), target);
                    for start in 0..all.len() {
                        let mut vectors = [[0x5a5a_a5a5_3c3c_c3c3u64, 0x0123_4567_89ab_cdef]; 3];
                        for index in 0..8 {
                            for (which, vector) in vectors.iter_mut().enumerate() {
                                let pick =
                                    (start * (which + 1) + index * (5 + 2 * which)) % all.len();
                                set_lane(vector, index, u64::from(all[pick]));
                            }
                        }
                        let finite = (0..lanes as usize).all(|index| {
                            let right = element.map_or(index, |element| element as usize);
                            completes(
                                lane(vectors[0], index),
                                lane(vectors[1], index),
                                lane(vectors[2], right),
                            )
                        });
                        for fpcr in controls() {
                            let mut initial = GuestState {
                                fpcr,
                                fpsr: 0x0800_0000,
                                ..GuestState::default()
                            };
                            initial.x[30] = RETURN;
                            initial.v[D as usize] = vectors[0];
                            initial.v[N as usize] = vectors[1];
                            initial.v[M as usize] = vectors[2];
                            // The element source is Vm itself.
                            let mut actual = initial.clone();
                            let exit = run(&code, &mut actual);
                            runs += 1;
                            let label =
                                || alloc::format!("{form:?} {vectors:x?} {fpcr:#x} {target:?}");
                            if exit == PC.0 {
                                assert_eq!(actual, initial, "{}", label());
                                let operation = if subtract {
                                    FusedOperation::Subtract
                                } else {
                                    FusedOperation::Add
                                };
                                let flushed = (0..lanes as usize).any(|index| {
                                    let right = element.map_or(index, |element| element as usize);
                                    flushes(
                                        operation,
                                        fpcr,
                                        lane(vectors[0], index),
                                        lane(vectors[1], index),
                                        lane(vectors[2], right),
                                    )
                                });
                                let must_inline = wide
                                    && finite
                                    && !flushed
                                    && fpcr & (FPCR_EXCEPTION_ENABLE_MASK | FPCR_AH) == 0;
                                assert!(!must_inline, "exited: {}", label());
                                continue;
                            }
                            assert_eq!(exit, RETURN, "{}", label());
                            let expected =
                                reference(form, &initial).expect("completed with enabled traps");
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
    }
    assert!(inline > runs / 6, "{inline} of {runs}");
}

/// Scalar FMADD, FMSUB, FNMADD and FNMSUB of H, and FMLA and FMLS of H by
/// element, against the reference: on AVX2 hosts with F16C every lane
/// [`completes`] inline unless AH or a trap enable is set or FZ16
/// [`flushes`] it, the result alone in Vd or, under FPCR.NEP, in the
/// addend's other bits; every exit leaves the state unchanged.
#[test]
fn scalar_half_fused_forms_complete_inline() {
    const A: u32 = 12;
    let registers = M << 16 | N << 5 | D;
    // (word, operation, addend register, right element).
    let forms: [(u32, FusedOperation, u32, usize); 6] = [
        (0x1fc0_0000 | A << 10 | registers, FusedOperation::Add, A, 0),
        (
            0x1fc0_8000 | A << 10 | registers,
            FusedOperation::Subtract,
            A,
            0,
        ),
        (
            0x1fe0_0000 | A << 10 | registers,
            FusedOperation::NegatedAdd,
            A,
            0,
        ),
        (
            0x1fe0_8000 | A << 10 | registers,
            FusedOperation::NegatedSubtract,
            A,
            0,
        ),
        // FMLA H3, H4, V9.H[5] and FMLS H3, H4, V9.H[2].
        (
            0x5f00_1000 | 1 << 11 | 1 << 20 | registers,
            FusedOperation::Add,
            D,
            5,
        ),
        (
            0x5f00_5000 | 1 << 21 | registers,
            FusedOperation::Subtract,
            D,
            2,
        ),
    ];
    let all = halves();
    let mut inline = 0usize;
    let mut runs = 0usize;
    for target in targets() {
        let wide = target.supports(TargetCpu::Avx2)
            && target.supports(TargetCpu::F16c)
            && !target.data_independent_timing()
            && !vector_extensions::half_supported(target);
        for &(word, operation, addend, element) in &forms {
            let code = compile(word, target);
            for start in 0..all.len() {
                let pick =
                    |which: usize| u64::from(all[(start * (which + 1) + which * 7) % all.len()]);
                let (a, n, m) = (pick(0), pick(1), pick(2));
                let finite = completes(a, n, m);
                for fpcr in controls().into_iter().chain([FPCR_NEP]) {
                    let mut initial = GuestState {
                        fpcr,
                        fpsr: 0x0800_0000,
                        ..GuestState::default()
                    };
                    initial.x[30] = RETURN;
                    // Other lanes hold infinities, NaNs and subnormals.
                    initial.v[D as usize] = [0x5a5a_a5a5_3c3c_c3c3, 0x0123_4567_89ab_cdef];
                    initial.v[A as usize] = [0x7c01_2222_0001_4444, 0x5555_6666_7777_8888];
                    initial.v[N as usize] = [0x7e00_7c00_0001_0000, 0x7c01_3c00_8000_7bff];
                    initial.v[M as usize] = [0x7e00_7c00_0001_0000, 0x7c01_3c00_8000_7bff];
                    set_lane(&mut initial.v[addend as usize], 0, a);
                    set_lane(&mut initial.v[N as usize], 0, n);
                    set_lane(&mut initial.v[M as usize], element, m);
                    let mut actual = initial.clone();
                    let exit = run(&code, &mut actual);
                    runs += 1;
                    let label = alloc::format!("{word:08x} {a:x} {n:x} {m:x} {fpcr:#x} {target:?}");
                    if exit == PC.0 {
                        assert_eq!(actual, initial, "{label}");
                        let must_inline = wide
                            && finite
                            && !flushes(operation, fpcr, a, n, m)
                            && fpcr & (FPCR_EXCEPTION_ENABLE_MASK | FPCR_AH) == 0;
                        assert!(!must_inline, "exited: {label}");
                        continue;
                    }
                    assert_eq!(exit, RETURN, "{label}");
                    let outcome = floating::fused::evaluate(Format::Half, operation, fpcr, a, n, m)
                        .expect("completed with enabled traps");
                    let mut expected = initial.clone();
                    expected.fpsr |= outcome.exceptions;
                    let mut result = if fpcr & FPCR_NEP != 0 {
                        initial.v[addend as usize]
                    } else {
                        [0; 2]
                    };
                    set_lane(&mut result, 0, outcome.bits);
                    expected.v[D as usize] = result;
                    assert_eq!(actual, expected, "{label}");
                    inline += 1;
                }
            }
        }
    }
    assert!(inline > runs / 6, "{inline} of {runs}");
}

/// FMLA and FMLS of 8H and 4H and FNMADD of H over every triple of
/// infinities, quiet and signaling NaNs of both signs, zeros and ordinary
/// values, eight distinct triples per vector: on the packed recipe every
/// vector without a quiet NaN addend beside a NaN product completes inline
/// with Arm's propagated NaN (negated for FMLS's Vn and FNMADD's Vn and
/// Va, quieted, or the default NaN under DN), infinity or invalid default
/// NaN and IOC; every exit leaves the state unchanged.
#[test]
fn special_half_fused_lanes_complete_inline() {
    const VALUES: [u64; 10] = [
        0x7c00, 0xfc00, 0x7e01, 0xfe02, 0x7c03, 0xfc05, 0x0000, 0x8000, 0x3c00, 0x0001,
    ];
    const A: u32 = 12;
    let triples: Vec<[u64; 3]> = (0..VALUES.len().pow(3))
        .map(|index| {
            [
                VALUES[index / 100],
                VALUES[index / 10 % 10],
                VALUES[index % 10],
            ]
        })
        .collect();
    let mut inline = 0usize;
    for target in targets() {
        let packed = target.supports(TargetCpu::Avx2)
            && target.supports(TargetCpu::F16c)
            && !target.data_independent_timing()
            && !vector_extensions::half_supported(target);
        // (word, operation, lanes, addend register; lanes 1 is scalar).
        let forms: [(u32, FusedOperation, usize, u32); 4] = [
            (
                0x4e40_0c00 | M << 16 | N << 5 | D,
                FusedOperation::Add,
                8,
                D,
            ),
            (
                0x4ec0_0c00 | M << 16 | N << 5 | D,
                FusedOperation::Subtract,
                8,
                D,
            ),
            (
                0x0ec0_0c00 | M << 16 | N << 5 | D,
                FusedOperation::Subtract,
                4,
                D,
            ),
            (
                0x1fe0_0000 | M << 16 | A << 10 | N << 5 | D,
                FusedOperation::NegatedAdd,
                1,
                A,
            ),
        ];
        for (word, operation, lanes, addend) in forms {
            let code = compile(word, target);
            for chunk in triples.chunks(lanes) {
                for fpcr in [0, FPCR_DN, 2 << FPCR_ROUNDING_SHIFT] {
                    let mut initial = GuestState {
                        fpcr,
                        ..GuestState::default()
                    };
                    initial.x[30] = RETURN;
                    for (index, &[a, n, m]) in chunk.iter().enumerate() {
                        set_lane(&mut initial.v[addend as usize], index, a);
                        set_lane(&mut initial.v[N as usize], index, n);
                        set_lane(&mut initial.v[M as usize], index, m);
                    }
                    let mut actual = initial.clone();
                    let exit = run(&code, &mut actual);
                    let label = alloc::format!("{word:08x} {chunk:x?} {fpcr:#x} {target:?}");
                    let completing = chunk.iter().all(|&[a, n, m]| completes(a, n, m));
                    if exit == PC.0 {
                        assert_eq!(actual, initial, "{label}");
                        assert!(!(packed && completing), "exited: {label}");
                        continue;
                    }
                    assert_eq!(exit, RETURN, "{label}");
                    let mut expected = initial.clone();
                    let mut result = [0u64; 2];
                    for (index, &[a, n, m]) in chunk.iter().enumerate() {
                        let outcome =
                            floating::fused::evaluate(Format::Half, operation, fpcr, a, n, m)
                                .unwrap();
                        expected.fpsr |= outcome.exceptions;
                        set_lane(&mut result, index, outcome.bits);
                    }
                    expected.v[D as usize] = result;
                    assert_eq!(actual, expected, "{label}");
                    inline += 1;
                }
            }
        }
    }
    let host = TargetCpu::detect();
    if host.supports(TargetCpu::Avx2) && host.supports(TargetCpu::F16c) {
        assert!(inline > 500, "{inline}");
    }
}

/// Under FZ16 the packed Half recipes flush subnormal inputs inline without
/// IDC: FADD 8H keeps the normal operand, FDIV 8H by a subnormal divides by
/// zero (DZC), FMLA 8H drops a subnormal addend and factor; a product FZ16
/// flushes takes the helper, leaving the state unchanged.
#[test]
fn fz16_flushes_half_inputs_inline() {
    const SUBNORMAL: u64 = 0x0123;
    const ONE: u64 = 0x3c00;
    const SMALL: u64 = 0x0555;
    let registers = M << 16 | N << 5 | D;
    // (word, binary operation or None for FMLA, [Vn, Vm, Vd], inline).
    let rows: [(u32, Option<floating::BinaryOperation>, [u64; 3], bool); 5] = [
        (
            0x4e40_1400 | registers,
            Some(floating::BinaryOperation::Add),
            [ONE, SUBNORMAL | 0x8000, 0],
            true,
        ),
        (
            0x6e40_3c00 | registers,
            Some(floating::BinaryOperation::Divide),
            [ONE, SUBNORMAL, 0],
            true,
        ),
        (0x4e40_0c00 | registers, None, [ONE, ONE, SUBNORMAL], true),
        (0x4e40_0c00 | registers, None, [SUBNORMAL, ONE, ONE], true),
        // 0x0555 squared is far below 2^-14: Arm flushes it.
        (0x4e40_0c00 | registers, None, [SMALL, SMALL, 0], false),
    ];
    for target in targets() {
        let packed = target.supports(TargetCpu::Avx2)
            && target.supports(TargetCpu::F16c)
            && !target.data_independent_timing()
            && !vector_extensions::half_supported(target);
        if !packed {
            continue;
        }
        for (row, &(word, operation, [n, m, d], inline)) in rows.iter().enumerate() {
            let code = compile(word, target);
            let mut initial = GuestState {
                fpcr: FPCR_FZ16,
                ..GuestState::default()
            };
            initial.x[30] = RETURN;
            for index in 0..8 {
                set_lane(&mut initial.v[N as usize], index, n);
                set_lane(&mut initial.v[M as usize], index, m);
                set_lane(&mut initial.v[D as usize], index, d);
            }
            let mut actual = initial.clone();
            let exit = run(&code, &mut actual);
            let label = alloc::format!("row {row} {target:?}");
            if !inline {
                assert_eq!(exit, PC.0, "{label}");
                assert_eq!(actual, initial, "{label}");
                continue;
            }
            assert_eq!(exit, RETURN, "{label}");
            let outcome = match operation {
                Some(operation) => floating::evaluate(Format::Half, operation, FPCR_FZ16, n, m),
                None => {
                    floating::fused::evaluate(Format::Half, FusedOperation::Add, FPCR_FZ16, d, n, m)
                }
            }
            .unwrap();
            assert_eq!(outcome.exceptions & floating::INPUT_DENORMAL, 0);
            let mut expected = initial.clone();
            expected.fpsr = outcome.exceptions;
            let mut result = [0u64; 2];
            for index in 0..8 {
                set_lane(&mut result, index, outcome.bits);
            }
            expected.v[D as usize] = result;
            assert_eq!(actual, expected, "{label}");
        }
    }
}
