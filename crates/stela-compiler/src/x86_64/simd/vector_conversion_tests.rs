//! Vector FCVT{N,M,P,Z}{S,U} of S and D lanes, with and without
//! fixed-point bits, over every input class against the Arm reference,
//! compiled as blocks for every tier this host has: every inline
//! completion matches the reference in every V register and FPSR, every
//! exit leaves the state unchanged, and with AH and the trap enables clear
//! every lane set of a saturating recipe completes inline, zeros,
//! subnormals (flushed under FZ or FIZ), NaNs (zero with IOC) and
//! saturating out-of-range lanes (IOC) included.
use crate::{
    GuestAddress, GuestState, Options, TargetCpu,
    aarch64::floating::{
        FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ, FPCR_ROUNDING_SHIFT,
        Format,
        integer::{self, IntegerFormat, IntegerRounding, IntegerWidth},
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

/// Zeros, subnormals, fractions, values at and beyond the 32-bit range,
/// infinities and NaNs, both signs.
fn floats() -> Vec<u64> {
    let mut values = vec![
        0,
        1,
        0x007f_fffd,
        0x0080_0000,
        0x3e80_0000, // 0.25
        0x3f00_0000, // 0.5
        0x3f80_0000, // 1
        0x3fc0_0000, // 1.5
        0x4020_0000, // 2.5
        0x4b80_0001,
        0x4eff_ffff, // the largest Single below 2^31
        0x4f00_0000, // 2^31
        0x4f00_0001,
        0x7f7f_ffff,
        0x7f80_0000,
        0x7fc0_0000,
        0x7f80_0001,
    ];
    let positive = values.len();
    for index in 0..positive {
        values.push(values[index] | 0x8000_0000);
    }
    values
}

#[test]
fn single_lanes_convert_every_input_inline() {
    let forms = [
        (0x0e21_a800u32, IntegerRounding::NearestEven),
        (0x0e21_b800, IntegerRounding::TowardNegative),
        (0x0ea1_a800, IntegerRounding::TowardPositive),
        (0x0ea1_b800, IntegerRounding::TowardZero),
    ];
    let controls = [
        0,
        1 << FPCR_ROUNDING_SHIFT,
        FPCR_DN,
        FPCR_FZ,
        FPCR_FIZ,
        FPCR_AH,
        FPCR_EXCEPTION_ENABLE_MASK,
    ];
    let format = IntegerFormat {
        width: IntegerWidth::Bits32,
        signed: true,
    };
    let all = floats();
    let mut runs = 0;
    let mut inline = 0;
    for target in targets() {
        for (base, rounding) in forms {
            for lanes in [2usize, 4] {
                let word = base | u32::from(lanes == 4) << 30 | N << 5 | D;
                let code = compile(word, target);
                for start in 0..all.len() {
                    let mut n = [0u64; 2];
                    for lane in 0..lanes {
                        let bits = all[(start + lane * 5) % all.len()];
                        n[lane / 2] |= bits << (32 * (lane % 2));
                    }
                    for fpcr in controls {
                        let mut initial = GuestState {
                            fpcr,
                            fpsr: 0x0800_0000,
                            ..GuestState::default()
                        };
                        initial.x[30] = RETURN;
                        initial.v[N as usize] = n;
                        initial.v[D as usize] = [0xdead_beef_0bad_f00d, 0xfeed_face_cafe_d00d];
                        let label = alloc::format!("{word:08x} {n:x?} {fpcr:#x} {target:?}");
                        let must_inline = fpcr & (FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK) == 0
                            && !target.data_independent_timing();
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
                        let mut expected = initial.clone();
                        let mut result = [0u64; 2];
                        for lane in 0..lanes {
                            let bits = n[lane / 2] >> (32 * (lane % 2)) & 0xffff_ffff;
                            let outcome = integer::to_integer(
                                Format::Single,
                                format,
                                0,
                                rounding,
                                fpcr,
                                bits,
                            )
                            .expect("completed with traps");
                            expected.fpsr |= outcome.exceptions;
                            result[lane / 2] |= (outcome.bits & 0xffff_ffff) << (32 * (lane % 2));
                        }
                        expected.v[D as usize] = result;
                        assert_eq!(actual, expected, "{label}");
                    }
                }
            }
        }
    }
    assert!(inline > runs / 2, "{inline} of {runs} inline");
}

/// Zeros, subnormals, fractions, values at and beyond the 32- and 64-bit
/// ranges, infinities and NaNs of `format`, both signs.
fn wide_floats(format: Format) -> Vec<u64> {
    if format == Format::Single {
        let mut values = floats();
        values.extend([0x4f80_0000, 0x4f7f_ffff, 0x3f19_999a, 0xbf19_999a]);
        return values;
    }
    let mut values = vec![
        0,
        1,
        0x000f_ffff_ffff_fffd,
        0x0010_0000_0000_0000,
        0x3fd0_0000_0000_0000, // 0.25
        0x3fe0_0000_0000_0000, // 0.5
        0x3fe3_3333_3333_3333, // 0.6
        0x3ff0_0000_0000_0000, // 1
        0x3ff8_0000_0000_0000, // 1.5
        0x4004_0000_0000_0000, // 2.5
        0x41ef_ffff_ffe0_0000, // 2^32 - 1
        0x43df_ffff_ffff_ffff, // the largest Double below 2^63
        0x43e0_0000_0000_0000, // 2^63
        0x43ef_ffff_ffff_ffff, // the largest Double below 2^64
        0x43f0_0000_0000_0000, // 2^64
        0x7fef_ffff_ffff_ffff,
        0x7ff0_0000_0000_0000,
        0x7ff8_0000_0000_0000,
        0x7ff0_0000_0000_0001,
    ];
    let positive = values.len();
    for index in 0..positive {
        values.push(values[index] | 1 << 63);
    }
    values
}

/// Vector FCVT{N,M,P,Z}U of S lanes and FCVT{N,M,P,Z}{S,U} of D lanes on
/// every tier this host has, against the reference: with AH and the trap
/// enables clear, every lane set completes inline (AVX-512's packed
/// conversions, or one lane at a time outside the DIT profile), zeros, subnormals (flushed under FZ or FIZ), NaNs (zero with
/// IOC), negative inputs of unsigned forms (zero, with IOC from -1 down)
/// and saturating out-of-range lanes (IOC) included; every exit leaves the
/// state unchanged.
#[test]
fn unsigned_and_double_lanes_saturate_inline() {
    // (word without Q, format, signed, rounding, 64-bit lanes only).
    let forms = [
        (
            0x2ea1_b800u32,
            Format::Single,
            false,
            IntegerRounding::TowardZero,
        ),
        (
            0x2e21_a800,
            Format::Single,
            false,
            IntegerRounding::NearestEven,
        ),
        (
            0x2e21_b800,
            Format::Single,
            false,
            IntegerRounding::TowardNegative,
        ),
        (
            0x2ea1_a800,
            Format::Single,
            false,
            IntegerRounding::TowardPositive,
        ),
        (
            0x4ee1_b800,
            Format::Double,
            true,
            IntegerRounding::TowardZero,
        ),
        (
            0x4e61_a800,
            Format::Double,
            true,
            IntegerRounding::NearestEven,
        ),
        (
            0x6ee1_b800,
            Format::Double,
            false,
            IntegerRounding::TowardZero,
        ),
        (
            0x6ee1_a800,
            Format::Double,
            false,
            IntegerRounding::TowardPositive,
        ),
    ];
    let controls = [
        0,
        2 << FPCR_ROUNDING_SHIFT,
        FPCR_DN,
        FPCR_FZ,
        FPCR_FIZ,
        FPCR_AH,
        FPCR_EXCEPTION_ENABLE_MASK,
    ];
    let mut runs = 0;
    let mut inline = 0;
    for target in targets() {
        for (base, format, signed, rounding) in forms {
            let integer = IntegerFormat {
                width: if format == Format::Double {
                    IntegerWidth::Bits64
                } else {
                    IntegerWidth::Bits32
                },
                signed,
            };
            let packed = crate::x86_64::asm::vector_extensions::packed_conversion_supported(
                format, integer, target,
            );
            let all = wide_floats(format);
            let shapes: &[usize] = if format == Format::Double {
                &[2]
            } else {
                &[2, 4]
            };
            for &lanes in shapes {
                let q = u32::from(lanes * format.bits() as usize == 128);
                let word = base | q << 30 | N << 5 | D;
                let code = compile(word, target);
                let width = format.bits() as usize;
                let mask = if width == 64 { u64::MAX } else { 0xffff_ffff };
                for start in 0..all.len() {
                    let mut n = [0u64; 2];
                    let per = 64 / width;
                    for lane in 0..lanes {
                        let bits = all[(start + lane * 5) % all.len()];
                        n[lane / per] |= bits << (width * (lane % per));
                    }
                    for fpcr in controls {
                        let mut initial = GuestState {
                            fpcr,
                            fpsr: 0x0800_0000,
                            ..GuestState::default()
                        };
                        initial.x[30] = RETURN;
                        initial.v[N as usize] = n;
                        initial.v[D as usize] = [0xdead_beef_0bad_f00d, 0xfeed_face_cafe_d00d];
                        let label = alloc::format!("{word:08x} {n:x?} {fpcr:#x} {target:?}");
                        let must_inline = (packed || !target.data_independent_timing())
                            && fpcr & (FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK) == 0;
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
                        let mut expected = initial.clone();
                        let mut result = [0u64; 2];
                        for lane in 0..lanes {
                            let bits = n[lane / per] >> (width * (lane % per)) & mask;
                            let outcome =
                                integer::to_integer(format, integer, 0, rounding, fpcr, bits)
                                    .expect("completed with traps");
                            expected.fpsr |= outcome.exceptions;
                            result[lane / per] |= (outcome.bits & mask) << (width * (lane % per));
                        }
                        expected.v[D as usize] = result;
                        assert_eq!(actual, expected, "{label}");
                    }
                }
            }
        }
    }
    assert!(inline > 0, "{inline} of {runs} inline");
}

/// Vector FCVTZS and FCVTZU with fixed-point bits complete every lane set
/// inline like their integer forms (the scale by 2^fbits is exact, or
/// overflows to a saturated lane) on every tier outside the DIT profile; every inline completion
/// matches the reference, every exit leaves the state unchanged.
#[test]
fn fixed_point_lanes_saturate_inline() {
    // (word with registers, format, signed, fraction bits, lanes).
    let forms = [
        (0x4f38_fc83u32, Format::Single, true, 8u32, 4usize),
        (0x0f21_fc83, Format::Single, true, 31, 2),
        (0x6f30_fc83, Format::Single, false, 16, 4),
        (0x4f60_fc83, Format::Double, true, 32, 2),
        (0x6f7f_fc83, Format::Double, false, 1, 2),
    ];
    let controls = [0, FPCR_FZ, FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK];
    let mut inline = 0;
    for target in targets() {
        for (word, format, signed, frac_bits, lanes) in forms {
            let integer = IntegerFormat {
                width: if format == Format::Double {
                    IntegerWidth::Bits64
                } else {
                    IntegerWidth::Bits32
                },
                signed,
            };
            let code = compile(word, target);
            let all = wide_floats(format);
            let width = format.bits() as usize;
            let per = 64 / width;
            let mask = if width == 64 { u64::MAX } else { 0xffff_ffff };
            for start in 0..all.len() {
                let mut n = [0u64; 2];
                for lane in 0..lanes {
                    let bits = all[(start + lane * 5) % all.len()];
                    n[lane / per] |= bits << (width * (lane % per));
                }
                for fpcr in controls {
                    let mut initial = GuestState {
                        fpcr,
                        ..GuestState::default()
                    };
                    initial.x[30] = RETURN;
                    initial.v[N as usize] = n;
                    initial.v[D as usize] = [0xdead_beef_0bad_f00d, 0xfeed_face_cafe_d00d];
                    let label = alloc::format!("{word:08x} {n:x?} {fpcr:#x} {target:?}");
                    let must_inline = !target.data_independent_timing()
                        && fpcr & (FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK) == 0;
                    let mut actual = initial.clone();
                    let exit = run(&code, &mut actual);
                    if exit == PC.0 {
                        assert_eq!(actual, initial, "{label}");
                        assert!(!must_inline, "exited: {label}");
                        continue;
                    }
                    assert_eq!(exit, RETURN, "{label}");
                    inline += 1;
                    let mut expected = initial.clone();
                    let mut result = [0u64; 2];
                    for lane in 0..lanes {
                        let bits = n[lane / per] >> (width * (lane % per)) & mask;
                        let outcome = integer::to_integer(
                            format,
                            integer,
                            frac_bits as u8,
                            IntegerRounding::TowardZero,
                            fpcr,
                            bits,
                        )
                        .expect("completed with traps");
                        expected.fpsr |= outcome.exceptions;
                        result[lane / per] |= (outcome.bits & mask) << (width * (lane % per));
                    }
                    expected.v[D as usize] = result;
                    assert_eq!(actual, expected, "{label}");
                }
            }
        }
    }
    assert!(inline > 0);
}
