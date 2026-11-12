//! Scalar FCVT between S and D over every input class against the Arm
//! reference, compiled as blocks for every tier this host has: every
//! inline completion matches the reference in every V register and FPSR,
//! every exit leaves the state unchanged, D to S completes every
//! non-NaN input inline with FZ, FIZ, AH and the trap enables clear (tiny,
//! subnormal and overflowing results included), and both directions flush
//! a subnormal input inline under FZ or FIZ with AH clear.
use crate::{
    GuestAddress, GuestState, Options, TargetCpu,
    aarch64::floating::{
        FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ, FPCR_NEP,
        FPCR_ROUNDING_SHIFT, Format,
        precision::{self, PrecisionRounding},
    },
    block::{BlockProfile, CompilationPlan},
    x86_64::native::run,
};
use alloc::{vec, vec::Vec};

const PC: GuestAddress = GuestAddress(0x1000_0000);
const RETURN: u64 = 0x4000;
const D: u32 = 3;
const N: u32 = 4;

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

fn controls() -> [u32; 11] {
    [
        0,
        1 << FPCR_ROUNDING_SHIFT,
        2 << FPCR_ROUNDING_SHIFT,
        3 << FPCR_ROUNDING_SHIFT,
        FPCR_DN,
        FPCR_NEP,
        FPCR_FZ,
        FPCR_FIZ,
        FPCR_FZ | FPCR_NEP,
        FPCR_AH,
        FPCR_EXCEPTION_ENABLE_MASK,
    ]
}

/// Zeros, subnormals, values around both formats' minimum normals and
/// maximums, normals, infinities and NaNs, both signs.
fn floats(format: Format) -> Vec<u64> {
    let fraction_bits = format.fraction_bits();
    let infinity = format.exponent_mask();
    let quiet = 1u64 << (fraction_bits - 1);
    let bias = u64::from(format.exponent_bias());
    let minimum = 1u64 << fraction_bits;
    let mut values = vec![
        0,
        1,
        minimum - 3,
        minimum,
        bias << fraction_bits,
        (bias << fraction_bits) + 1,
        infinity - 1,
        infinity,
        infinity | quiet,
        infinity | 1,
    ];
    if format == Format::Double {
        let single_bias = u64::from(Format::Single.exponent_bias());
        // Single's minimum normal, just below and above it, a value that
        // rounds up to it, Single's subnormal range and its overflow edge.
        let single_minimum = (bias - single_bias + 1) << fraction_bits;
        values.extend([
            single_minimum,
            single_minimum - 1,
            single_minimum + (1 << 28),
            single_minimum - (1 << 28),
            (bias - single_bias - 10) << fraction_bits | 0x1234_5678,
            (bias - single_bias - 30) << fraction_bits,
            (bias + single_bias) << fraction_bits | (minimum - 1),
            (bias + single_bias + 1) << fraction_bits,
            (bias + 3) << fraction_bits | 0x1000_0001,
        ]);
    }
    let positive = values.len();
    for index in 0..positive {
        values.push(values[index] | format.sign_mask());
    }
    values
}

fn word(source: Format) -> u32 {
    let registers = N << 5 | D;
    match source {
        Format::Double => 0x1e62_4000 | registers,
        _ => 0x1e22_c000 | registers,
    }
}

#[test]
fn scalar_conversions_complete_subnormal_tiny_and_flushed_inputs_inline() {
    let mut runs = 0;
    let mut inline = 0;
    for target in targets() {
        for (source, destination) in [
            (Format::Double, Format::Single),
            (Format::Single, Format::Double),
        ] {
            let code = compile(word(source), target);
            for bits in floats(source) {
                for fpcr in controls() {
                    let mut initial = GuestState {
                        fpcr,
                        fpsr: 0x0800_0000,
                        ..GuestState::default()
                    };
                    initial.x[30] = RETURN;
                    initial.v[N as usize] = [bits, 0x0123_4567_89ab_cdef];
                    initial.v[D as usize] = [0xdead_beef_0bad_f00d, 0xfeed_face_cafe_d00d];
                    let label = alloc::format!("{source:?} {bits:#x} {fpcr:#x} {target:?}");
                    let magnitude = bits & !source.sign_mask();
                    let nan = magnitude > source.exponent_mask();
                    let subnormal = magnitude != 0 && magnitude < 1 << source.fraction_bits();
                    let flushing = fpcr & (FPCR_FZ | FPCR_FIZ) != 0 && fpcr & FPCR_AH == 0;
                    let reference = precision::evaluate(
                        source,
                        destination,
                        PrecisionRounding::Fpcr,
                        fpcr,
                        bits,
                    );
                    let usable = fpcr & FPCR_EXCEPTION_ENABLE_MASK == 0
                        && !target.data_independent_timing()
                        && !nan;
                    let must_inline = usable
                        && if source == Format::Double {
                            let result = reference.as_ref().unwrap().bits;
                            let single_minimum = 1 << Format::Single.fraction_bits();
                            let rounded = fpcr & (FPCR_FZ | FPCR_FIZ | FPCR_AH) == 0;
                            rounded && result & !Format::Single.sign_mask() != single_minimum
                                || flushing && (subnormal || magnitude == 0)
                        } else {
                            !subnormal || flushing
                        };
                    let mut actual = initial.clone();
                    let exit = run(&code, &mut actual);
                    runs += 1;
                    if exit == PC.0 {
                        assert_eq!(actual, initial, "{label}");
                        assert!(!must_inline, "exited: {label}");
                        continue;
                    }
                    assert_eq!(exit, RETURN, "{label}");
                    inline += 1;
                    let outcome = reference.expect("completed with traps");
                    let mut expected = initial.clone();
                    expected.fpsr |= outcome.exceptions;
                    let mask = if destination == Format::Single {
                        u64::from(u32::MAX)
                    } else {
                        u64::MAX
                    };
                    expected.v[D as usize] = if fpcr & FPCR_NEP != 0 {
                        let old = initial.v[D as usize];
                        [old[0] & !mask | outcome.bits, old[1]]
                    } else {
                        [outcome.bits, 0]
                    };
                    assert_eq!(actual, expected, "{label}");
                }
            }
        }
    }
    assert!(inline > runs / 2, "{inline} of {runs} inline");
}
