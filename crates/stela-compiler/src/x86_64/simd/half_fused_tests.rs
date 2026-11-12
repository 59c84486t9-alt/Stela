//! Vector Half FMLA and FMLS (by vector and by element, 4H and 8H) against
//! the Arm reference, compiled as blocks for every tier this host has:
//! every inline completion matches the reference in every V register and
//! FPSR, every exit leaves the state unchanged, and on AVX2 hosts with
//! F16C every finite input (zeros and subnormals included) completes
//! without an exit in every rounding mode unless FZ16, AH or a trap
//! enable is set.
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
fn finite_half_fused_lanes_complete_inline() {
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
                            [
                                lane(vectors[0], index),
                                lane(vectors[1], index),
                                lane(vectors[2], right),
                            ]
                            .iter()
                            .all(|bits| bits & 0x7c00 != 0x7c00)
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
                                let must_inline = wide
                                    && finite
                                    && fpcr & (FPCR_EXCEPTION_ENABLE_MASK | FPCR_AH | FPCR_FZ16)
                                        == 0;
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
/// element, against the reference: on AVX2 hosts with F16C every finite
/// lane (zeros and subnormals included) completes inline unless FZ16, AH or
/// a trap enable is set, the result alone in Vd or, under FPCR.NEP, in the
/// addend's other bits; every exit leaves the state unchanged.
#[test]
fn finite_scalar_half_fused_forms_complete_inline() {
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
                let finite = [a, n, m].iter().all(|bits| bits & 0x7c00 != 0x7c00);
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
                            && fpcr & (FPCR_EXCEPTION_ENABLE_MASK | FPCR_AH | FPCR_FZ16) == 0;
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
