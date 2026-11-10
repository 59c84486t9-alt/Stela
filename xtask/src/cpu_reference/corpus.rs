//! The cases, by priority: FP edge cases, saturating SIMD, flags and
//! integer edge cases, single-PE LSE atomics, key-independent PAC, and the
//! FPCR trap and register-overlap probes. Every name is unique and stable:
//! the recorded results are keyed by it.
use super::record::Case;

const MEMORY_PATTERN: [u8; 64] = {
    let mut bytes = [0; 64];
    let mut index = 0;
    while index < 64 {
        bytes[index] = (index as u8).wrapping_mul(37).wrapping_add(11);
        index += 1;
    }
    bytes
};

/// FP formats: name, ftype, bit width.
const FORMATS: [(&str, u32, u32); 3] = [("h", 0b11, 16), ("s", 0b00, 32), ("d", 0b01, 64)];

/// FPCR RMode values.
const ROUNDINGS: [(&str, u64); 4] = [("rn", 0), ("rp", 1 << 22), ("rm", 2 << 22), ("rz", 3 << 22)];
const FPCR_FZ: u64 = 1 << 24;
const FPCR_DN: u64 = 1 << 25;
const FPCR_FZ16: u64 = 1 << 19;

/// Edge values of a format: zeros, halves, integers around 2^31, 2^32,
/// 2^63 and 2^64, infinities, NaNs and subnormals.
fn edge_values(bits: u32) -> Vec<(String, u64)> {
    let mut values: Vec<f64> = vec![
        0.0, -0.0, 0.5, -0.5, 1.5, -1.5, 2.5, -2.5, 1.0, -1.0, 255.5, 65504.0, -65504.0,
    ];
    if bits > 16 {
        for power in [31, 32, 63, 64] {
            let base = 2f64.powi(power);
            values.extend([
                base,
                -base,
                base - 1.0,
                base + 1.0,
                -base - 1.0,
                -base + 1.0,
            ]);
        }
        values.extend([2f64.powi(52) + 0.5, 2f64.powi(52) - 0.5, 1e30, -1e30]);
    }
    let mut out: Vec<u64> = values
        .into_iter()
        .map(|value| match bits {
            16 => u64::from(half(value)),
            32 => u64::from((value as f32).to_bits()),
            _ => value.to_bits(),
        })
        .collect();
    let (exponent, fraction) = match bits {
        16 => (0x7c00u64, 0x3ffu64),
        32 => (0x7f80_0000, 0x7f_ffff),
        _ => (0x7ff0_0000_0000_0000, 0xf_ffff_ffff_ffff),
    };
    let sign = 1u64 << (bits - 1);
    let quiet = (fraction + 1) >> 1;
    out.extend([
        exponent,                // +Inf
        exponent | sign,         // -Inf
        exponent | quiet,        // qNaN
        exponent | quiet | sign, // -qNaN
        exponent | 1,            // sNaN
        1,                       // smallest subnormal
        sign | fraction,         // largest negative subnormal
        exponent - 1 - fraction, // largest normal
    ]);
    out.sort_unstable();
    out.dedup();
    out.into_iter()
        .map(|value| (format!("{value:#x}"), value))
        .collect()
}

/// `value` rounded to Half, ties to even (for exact test inputs).
fn half(value: f64) -> u16 {
    if value == 0.0 {
        return if value.is_sign_negative() { 0x8000 } else { 0 };
    }
    let sign = if value < 0.0 { 0x8000u16 } else { 0 };
    let magnitude = value.abs();
    if magnitude >= 65520.0 {
        return sign | 0x7c00;
    }
    let exponent = magnitude.log2().floor() as i32;
    if exponent < -14 {
        let units = (magnitude / 2f64.powi(-24)).round_ties_even() as u16;
        return sign | units;
    }
    let mantissa = (magnitude / 2f64.powi(exponent) - 1.0) * 1024.0;
    let mut bits = (((exponent + 15) as u16) << 10) + mantissa.round_ties_even() as u16;
    if bits >= 0x7c00 {
        bits = 0x7c00;
    }
    sign | bits
}

fn fp_conversions(cases: &mut Vec<Case>) {
    // FCVT{N,P,M,Z,A}{S,U} to W and X: (name, rmode, opcode).
    const OPERATIONS: [(&str, u32, u32); 10] = [
        ("fcvtns", 0, 0),
        ("fcvtnu", 0, 1),
        ("fcvtas", 0, 4),
        ("fcvtau", 0, 5),
        ("fcvtps", 1, 0),
        ("fcvtpu", 1, 1),
        ("fcvtms", 2, 0),
        ("fcvtmu", 2, 1),
        ("fcvtzs", 3, 0),
        ("fcvtzu", 3, 1),
    ];
    for (format, ftype, bits) in FORMATS {
        for (name, rmode, opcode) in OPERATIONS {
            for (width, sf) in [("w", 0u32), ("x", 1)] {
                let word = 0x1e20_0000 | sf << 31 | ftype << 22 | rmode << 19 | opcode << 16 | 1;
                for (label, value) in edge_values(bits) {
                    cases.push(
                        Case::new(format!("{name}.{format}.{width}.{label}"), &[word])
                            .x(1, 0x5555_5555_5555_5555)
                            .v(0, value, 0),
                    );
                }
            }
        }
        // Fixed point: FCVTZS and FCVTZU with fbits 1, 31, 32 and 63.
        for (name, opcode) in [("fcvtzs", 0u32), ("fcvtzu", 1)] {
            for (width, sf, scales) in [
                ("w", 0u32, &[1u32, 31, 32][..]),
                ("x", 1, &[1, 31, 32, 63, 64]),
            ] {
                for &fbits in scales {
                    let word = 0x1e18_0000
                        | sf << 31
                        | ftype << 22
                        | opcode << 16
                        | (64 - fbits) << 10
                        | 1;
                    for (label, value) in edge_values(bits).into_iter().step_by(3) {
                        cases.push(
                            Case::new(format!("{name}.{format}.{width}.f{fbits}.{label}"), &[word])
                                .v(0, value, 0),
                        );
                    }
                }
            }
        }
        // Precision conversions to the other formats.
        for (target, opc) in [("h", 0b11u32), ("s", 0b00), ("d", 0b01)] {
            if target == format {
                continue;
            }
            let word = 0x1e22_4000 | ftype << 22 | opc << 15 | 1;
            for (label, value) in edge_values(bits) {
                for (mode, fpcr) in [("rn", 0), ("rz", 3 << 22), ("dn", FPCR_DN)] {
                    cases.push(
                        Case::new(format!("fcvt.{format}{target}.{mode}.{label}"), &[word])
                            .v(0, value, 0)
                            .v(1, 0x1111, 0x2222)
                            .fpcr(fpcr),
                    );
                }
            }
        }
    }
}

fn fp_rounding(cases: &mut Vec<Case>) {
    const ROUNDS: [(&str, u32); 7] = [
        ("frintn", 0x1e24_4000),
        ("frintp", 0x1e24_c000),
        ("frintm", 0x1e25_4000),
        ("frintz", 0x1e25_c000),
        ("frinta", 0x1e26_4000),
        ("frintx", 0x1e27_4000),
        ("frinti", 0x1e27_c000),
    ];
    const BOUNDED: [(&str, u32); 4] = [
        ("frint32z", 0x1e28_4000),
        ("frint32x", 0x1e28_c000),
        ("frint64z", 0x1e29_4000),
        ("frint64x", 0x1e29_c000),
    ];
    for (format, ftype, bits) in FORMATS {
        let bounded: &[(&str, u32)] = if bits == 16 { &[] } else { &BOUNDED };
        for &(name, base) in ROUNDS.iter().chain(bounded) {
            let word = base | ftype << 22 | 1;
            for (label, value) in edge_values(bits) {
                for (mode, fpcr) in [("rn", 0), ("rm", 2 << 22)] {
                    cases.push(
                        Case::new(format!("{name}.{format}.{mode}.{label}"), &[word])
                            .v(0, value, 0)
                            .fpcr(fpcr),
                    );
                }
            }
        }
    }
}

fn fp_extrema(cases: &mut Vec<Case>) {
    const OPERATIONS: [(&str, u32); 4] = [
        ("fmax", 0b0100),
        ("fmin", 0b0101),
        ("fmaxnm", 0b0110),
        ("fminnm", 0b0111),
    ];
    for (format, ftype, bits) in FORMATS {
        let (exponent, quiet) = match bits {
            16 => (0x7c00u64, 0x200u64),
            32 => (0x7f80_0000, 0x40_0000),
            _ => (0x7ff0_0000_0000_0000, 0x8_0000_0000_0000),
        };
        let sign = 1u64 << (bits - 1);
        let one = match bits {
            16 => 0x3c00,
            32 => 0x3f80_0000,
            _ => 0x3ff0_0000_0000_0000,
        };
        let values = [
            ("+0", 0),
            ("-0", sign),
            ("+1", one),
            ("-1", one | sign),
            ("+inf", exponent),
            ("-inf", exponent | sign),
            ("qnan", exponent | quiet | 5),
            ("snan", exponent | 3),
        ];
        for (name, opcode) in OPERATIONS {
            let word = 0x1e20_0800 | ftype << 22 | 2 << 16 | opcode << 12 | 1 << 5;
            for (left, a) in values {
                for (right, b) in values {
                    for (mode, fpcr) in [("", 0), (".dn", FPCR_DN)] {
                        cases.push(
                            Case::new(format!("{name}.{format}.{left}.{right}{mode}"), &[word])
                                .v(1, a, 0)
                                .v(2, b, 0)
                                .fpcr(fpcr),
                        );
                    }
                }
            }
        }
    }
}

fn fp_arithmetic(cases: &mut Vec<Case>) {
    // FADD, FSUB, FMUL and FDIV at the overflow and underflow boundaries,
    // under every rounding mode and FZ.
    const OPERATIONS: [(&str, u32); 4] = [
        ("fmul", 0b0000),
        ("fdiv", 0b0001),
        ("fadd", 0b0010),
        ("fsub", 0b0011),
    ];
    for (format, ftype, bits) in [FORMATS[1], FORMATS[2]] {
        let (max, min_normal, min_sub, one, three) = match bits {
            32 => (
                0x7f7f_ffffu64,
                0x0080_0000u64,
                1u64,
                0x3f80_0000u64,
                0x4040_0000u64,
            ),
            _ => (
                0x7fef_ffff_ffff_ffff,
                0x0010_0000_0000_0000,
                1,
                0x3ff0_0000_0000_0000,
                0x4008_0000_0000_0000,
            ),
        };
        let sign = 1u64 << (bits - 1);
        let pairs = [
            ("max.max", max, max),
            ("max.-max", max, max | sign),
            ("minn.half", min_normal, min_normal - 1),
            ("minn.minn", min_normal, min_normal),
            ("sub.sub", min_sub, min_sub),
            ("one.three", one, three),
            ("sub.one", min_sub, one),
            ("minn.three", min_normal, three),
        ];
        for (name, opcode) in OPERATIONS {
            let word = 0x1e20_0800 | ftype << 22 | 2 << 16 | opcode << 12 | 1 << 5;
            for (label, a, b) in pairs {
                for (mode, rounding) in ROUNDINGS {
                    for (flush, fz) in [("", 0), (".fz", FPCR_FZ)] {
                        cases.push(
                            Case::new(format!("{name}.{format}.{label}.{mode}{flush}"), &[word])
                                .v(1, a, 0)
                                .v(2, b, 0)
                                .fpcr(rounding | fz),
                        );
                    }
                }
            }
        }
        // Fused against unfused: a*b - c with an exact cancellation.
        let (a, c) = match bits {
            32 => (0x3f80_0001u64, 0x3f80_0002u64),
            _ => (0x3ff0_0000_0000_0001, 0x3ff0_0000_0000_0002),
        };
        for (name, o1, o0) in [
            ("fmadd", 0u32, 0u32),
            ("fmsub", 0, 1),
            ("fnmadd", 1, 0),
            ("fnmsub", 1, 1),
        ] {
            let word = 0x1f00_0000 | ftype << 22 | o1 << 21 | 2 << 16 | o0 << 15 | 3 << 10 | 1 << 5;
            for (mode, rounding) in ROUNDINGS {
                cases.push(
                    Case::new(format!("{name}.{format}.cancel.{mode}"), &[word])
                        .v(1, a, 0)
                        .v(2, a, 0)
                        .v(3, c | sign, 0)
                        .fpcr(rounding),
                );
            }
        }
        // FSQRT of edge values.
        for (label, value) in edge_values(bits) {
            cases.push(
                Case::new(
                    format!("fsqrt.{format}.{label}"),
                    &[0x1e21_c000 | ftype << 22 | 1],
                )
                .v(0, value, 0),
            );
        }
    }
}

fn fp_estimates(cases: &mut Vec<Case>) {
    // FRECPE and FRSQRTE, scalar, on edge values and a sweep; FRECPS and
    // FRSQRTS with 0 x Inf.
    for (format, sz, bits) in [("s", 0u32, 32u32), ("d", 1, 64)] {
        let mut values = edge_values(bits);
        for step in 0..48u64 {
            let value = match bits {
                32 => 0x3f80_0000 + step * 0x0002_a3c5,
                _ => 0x3ff0_0000_0000_0000 + step * 0x0000_5478_a3c5_1234,
            };
            // 1.0 is an edge value too.
            if values.iter().all(|(_, edge)| *edge != value) {
                values.push((format!("{value:#x}"), value));
            }
        }
        for (name, base) in [("frecpe", 0x5ea1_d800u32), ("frsqrte", 0x7ea1_d800)] {
            for (label, value) in &values {
                for (mode, fpcr) in [("", 0), (".fz", FPCR_FZ)] {
                    cases.push(
                        Case::new(
                            format!("{name}.{format}.{label}{mode}"),
                            &[base | sz << 22 | 1],
                        )
                        .v(0, *value, 0)
                        .fpcr(fpcr),
                    );
                }
            }
        }
        let infinity = match bits {
            32 => 0x7f80_0000u64,
            _ => 0x7ff0_0000_0000_0000,
        };
        for (name, base) in [("frecps", 0x5e20_fc00u32), ("frsqrts", 0x5ea0_fc00)] {
            let word = base | sz << 22 | 2 << 16 | 1 << 5;
            for (label, a, b) in [
                ("0.inf", 0, infinity),
                ("inf.0", infinity, 0),
                ("-0.inf", 1 << (bits - 1), infinity),
            ] {
                cases.push(
                    Case::new(format!("{name}.{format}.{label}"), &[word])
                        .v(1, a, 0)
                        .v(2, b, 0),
                );
            }
        }
    }
    // Half FRECPE over a sweep of every exponent, with FZ16 0 and 1.
    for step in 0..128u64 {
        let value = (step * 0x0203) & 0xffff;
        for (mode, fpcr) in [("", 0), (".fz16", FPCR_FZ16)] {
            cases.push(
                Case::new(format!("frecpe.h.{value:#x}{mode}"), &[0x5ef9_d801])
                    .v(0, value, 0)
                    .fpcr(fpcr),
            );
            cases.push(
                Case::new(format!("frsqrte.h.{value:#x}{mode}"), &[0x7ef9_d801])
                    .v(0, value, 0)
                    .fpcr(fpcr),
            );
        }
    }
}

fn fp_compares(cases: &mut Vec<Case>) {
    for (format, ftype, bits) in FORMATS {
        let values = edge_values(bits);
        for (name, opc) in [("fcmp", 0u32), ("fcmpe", 0x10)] {
            let word = 0x1e20_2000 | ftype << 22 | 2 << 16 | 1 << 5 | opc;
            for (left, a) in values.iter().step_by(4) {
                for (right, b) in values.iter().step_by(5) {
                    cases.push(
                        Case::new(format!("{name}.{format}.{left}.{right}"), &[word])
                            .v(1, *a, 0)
                            .v(2, *b, 0),
                    );
                }
            }
        }
    }
}

/// Lanes for saturating cases: every lane width's extremes.
fn lanes(size: u32) -> [(&'static str, u64, u64); 6] {
    match size {
        0 => [
            ("max", 0x7f7f_7f7f_7f7f_7f7f, 0x8080_8080_8080_8080),
            ("min", 0x8080_8080_8080_8080, 0x7f7f_7f7f_7f7f_7f7f),
            ("mix", 0x01ff_807f_0080_ff7f, 0xfe01_7f80_00ff_0180),
            ("ones", 0xffff_ffff_ffff_ffff, 0x0101_0101_0101_0101),
            ("zero", 0, 0),
            ("walk", 0x0102_0408_1020_4080, 0x8040_2010_0804_0201),
        ],
        1 => [
            ("max", 0x7fff_7fff_7fff_7fff, 0x8000_8000_8000_8000),
            ("min", 0x8000_8000_8000_8000, 0x7fff_7fff_7fff_7fff),
            ("mix", 0x0001_ffff_8000_7fff, 0xfffe_0001_7fff_8000),
            ("ones", 0xffff_ffff_ffff_ffff, 0x0001_0001_0001_0001),
            ("zero", 0, 0),
            ("walk", 0x0102_0408_1020_4080, 0x8040_2010_0804_0201),
        ],
        2 => [
            ("max", 0x7fff_ffff_7fff_ffff, 0x8000_0000_8000_0000),
            ("min", 0x8000_0000_8000_0000, 0x7fff_ffff_7fff_ffff),
            ("mix", 0x0000_0001_ffff_ffff, 0x8000_0000_7fff_ffff),
            ("ones", 0xffff_ffff_ffff_ffff, 0x0000_0001_0000_0001),
            ("zero", 0, 0),
            ("walk", 0x0102_0408_1020_4080, 0x8040_2010_0804_0201),
        ],
        _ => [
            ("max", 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000),
            ("min", 0x8000_0000_0000_0000, 0x7fff_ffff_ffff_ffff),
            ("mix", 0x0000_0000_0000_0001, 0xffff_ffff_ffff_ffff),
            ("ones", 0xffff_ffff_ffff_ffff, 0x0000_0000_0000_0001),
            ("zero", 0, 0),
            ("walk", 0x0102_0408_1020_4080, 0x8040_2010_0804_0201),
        ],
    }
}

fn saturating_simd(cases: &mut Vec<Case>) {
    // Three-register forms, 128-bit: V0 = op(V1, V2). FPSR.QC shows.
    const THREE: [(&str, u32, &[u32]); 12] = [
        ("sqadd", 0x4e20_0c00, &[0, 1, 2, 3]),
        ("uqadd", 0x6e20_0c00, &[0, 1, 2, 3]),
        ("sqsub", 0x4e20_2c00, &[0, 1, 2, 3]),
        ("uqsub", 0x6e20_2c00, &[0, 1, 2, 3]),
        ("sqdmulh", 0x4e20_b400, &[1, 2]),
        ("sqrdmulh", 0x6e20_b400, &[1, 2]),
        ("sqshl", 0x4e20_4c00, &[0, 1, 2, 3]),
        ("uqshl", 0x6e20_4c00, &[0, 1, 2, 3]),
        ("sqrshl", 0x4e20_5c00, &[0, 1, 2, 3]),
        ("srshl", 0x4e20_5400, &[0, 1, 2, 3]),
        ("urshl", 0x6e20_5400, &[0, 1, 2, 3]),
        ("sshl", 0x4e20_4400, &[0, 1, 2, 3]),
    ];
    for (name, base, sizes) in THREE {
        for &size in sizes {
            let word = base | size << 22 | 2 << 16 | 1 << 5;
            let values = lanes(size);
            for (left, a, b) in values {
                for (right, c, d) in values {
                    cases.push(
                        Case::new(format!("{name}.{size}.{left}.{right}"), &[word])
                            .v(1, a, b)
                            .v(2, c, d),
                    );
                }
            }
        }
    }
    // Shift counts -128..127 in every byte lane of SSHL/USHL/SRSHL/SQSHL.
    for (name, base) in [
        ("sshl", 0x4e20_4400u32),
        ("ushl", 0x6e20_4400),
        ("srshl", 0x4e20_5400),
        ("sqshl", 0x4e20_4c00),
        ("uqrshl", 0x6e20_5c00),
    ] {
        for size in 0..4u32 {
            for chunk in 0..16u64 {
                let counts: u64 = (0..8).fold(0, |acc, lane| {
                    acc | ((chunk * 16 + lane * 2) & 0xff) << (lane * 8)
                });
                cases.push(
                    Case::new(
                        format!("{name}.{size}.counts{chunk}"),
                        &[base | size << 22 | 2 << 16 | 1 << 5],
                    )
                    .v(1, 0x8123_4567_89ab_cdef, 0x7fed_cba9_8765_4321)
                    .v(2, counts, counts.rotate_left(8)),
                );
            }
        }
    }
    // Two-register narrowing and unary forms.
    const TWO: [(&str, u32, &[u32]); 6] = [
        ("sqxtn", 0x0e21_4800, &[0, 1, 2]),
        ("sqxtun", 0x2e21_2800, &[0, 1, 2]),
        ("uqxtn", 0x2e21_4800, &[0, 1, 2]),
        ("sqabs", 0x4e20_7800, &[0, 1, 2, 3]),
        ("sqneg", 0x6e20_7800, &[0, 1, 2, 3]),
        ("suqadd", 0x4e20_3800, &[0, 1, 2, 3]),
    ];
    for (name, base, sizes) in TWO {
        for &size in sizes {
            let source = if name.ends_with("xtn") || name.ends_with("xtun") {
                size + 1
            } else {
                size
            };
            for (label, a, b) in lanes(source) {
                cases.push(
                    Case::new(
                        format!("{name}.{size}.{label}"),
                        &[base | size << 22 | 1 << 5],
                    )
                    .v(0, 0x0f0f_0f0f_0f0f_0f0f, 0xf0f0_f0f0_f0f0_f0f0)
                    .v(1, a, b),
                );
            }
        }
    }
    // TBL and TBX with indices 0..63 over one to four tables.
    for (name, op) in [("tbl", 0u32), ("tbx", 1)] {
        for tables in 1..=4u32 {
            for chunk in 0..4u64 {
                let indices: u64 =
                    (0..8).fold(0, |acc, lane| acc | (chunk * 17 + lane * 9) << (lane * 8));
                let word = 0x4e00_0000 | 5 << 16 | (tables - 1) << 13 | op << 12 | 1 << 5;
                let mut case = Case::new(format!("{name}.{tables}.{chunk}"), &[word])
                    .v(0, 0xeeee_eeee_eeee_eeee, 0xdddd_dddd_dddd_dddd)
                    .v(5, indices, indices | 0x8040_2010_0000_0000);
                for table in 0..4 {
                    case = case.v(
                        1 + table,
                        0x0706_0504_0302_0100 + table as u64 * 0x1010_1010_1010_1010,
                        0x0f0e_0d0c_0b0a_0908 + table as u64 * 0x1010_1010_1010_1010,
                    );
                }
                cases.push(case);
            }
        }
    }
}

/// 64-bit operands around every sign and carry boundary.
const INTEGERS: [u64; 10] = [
    0,
    1,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    0xffff_ffff_ffff_ffff,
    0x0123_4567_89ab_cdef,
    0xfedc_ba98_7654_3210,
];

fn integers(cases: &mut Vec<Case>) {
    // Flag setters, X and W: Xd = op(Xn, Xm) with NZCV in and out.
    const FLAGS: [(&str, u32); 4] = [
        ("adds", 0xab02_0020),
        ("subs", 0xeb02_0020),
        ("adcs", 0xba02_0020),
        ("sbcs", 0xfa02_0020),
    ];
    for (name, word) in FLAGS {
        for (width, mask) in [("x", u32::MAX), ("w", 0x7fff_ffff)] {
            for (i, a) in INTEGERS.iter().enumerate() {
                for (j, b) in INTEGERS.iter().enumerate().step_by(2) {
                    for carry in [0u64, 0x2000_0000] {
                        if carry != 0 && !name.ends_with("cs") {
                            continue;
                        }
                        cases.push(
                            Case::new(
                                format!("{name}.{width}.{i}.{j}.c{}", carry >> 29),
                                &[word & mask],
                            )
                            .x(1, *a)
                            .x(2, *b)
                            .nzcv(carry),
                        );
                    }
                }
            }
        }
    }
    // CCMP and CCMN (register and immediate) under every condition.
    for (name, word) in [
        ("ccmp", 0xfa42_0025u32),
        ("ccmn", 0xba42_0025),
        ("ccmp.imm", 0xfa5f_0825),
    ] {
        for condition in 0..16u32 {
            for nzcv in [0u64, 0x4000_0000, 0x6000_0000, 0x9000_0000, 0xf000_0000] {
                cases.push(
                    Case::new(
                        format!("{name}.{condition}.{:x}", nzcv >> 28),
                        &[word | condition << 12],
                    )
                    .x(1, 5)
                    .x(2, 0xffff_ffff_ffff_fffb)
                    .nzcv(nzcv),
                );
            }
        }
    }
    // Shifts by register with counts 0, 31, 32, 63, 64 and 255.
    for (name, word) in [
        ("lslv", 0x9ac2_2020u32),
        ("lsrv", 0x9ac2_2420),
        ("asrv", 0x9ac2_2820),
        ("rorv", 0x9ac2_2c20),
    ] {
        for (width, mask) in [("x", u32::MAX), ("w", 0x7fff_ffff)] {
            for count in [0u64, 1, 31, 32, 33, 63, 64, 255, 0xffff_ffff_ffff_ffc1] {
                cases.push(
                    Case::new(format!("{name}.{width}.{count:#x}"), &[word & mask])
                        .x(1, 0x8123_4567_89ab_cdef)
                        .x(2, count),
                );
            }
        }
    }
    // Division, multiply-high, CLS/CLZ, RBIT and EXTR.
    for (name, word) in [
        ("sdiv", 0x9ac2_0c20u32),
        ("udiv", 0x9ac2_0820),
        ("smulh", 0x9b42_7c20),
        ("umulh", 0x9bc2_7c20),
        ("sdiv.w", 0x1ac2_0c20),
        ("udiv.w", 0x1ac2_0820),
    ] {
        for (i, a) in INTEGERS.iter().enumerate() {
            for (j, b) in INTEGERS.iter().enumerate() {
                cases.push(
                    Case::new(format!("{name}.{i}.{j}"), &[word])
                        .x(1, *a)
                        .x(2, *b),
                );
            }
        }
    }
    for (name, word) in [
        ("cls", 0xdac0_1420u32),
        ("clz", 0xdac0_1020),
        ("rbit", 0xdac0_0020),
        ("cls.w", 0x5ac0_1420),
        ("clz.w", 0x5ac0_1020),
    ] {
        for (i, a) in INTEGERS.iter().enumerate() {
            cases.push(Case::new(format!("{name}.{i}"), &[word]).x(1, *a));
        }
    }
    for lsb in [0u32, 1, 31, 32, 63] {
        cases.push(
            Case::new(format!("extr.{lsb}"), &[0x93c2_0020 | lsb << 10])
                .x(1, 0x0123_4567_89ab_cdef)
                .x(2, 0xfedc_ba98_7654_3210),
        );
    }
    // A spread of BFM, SBFM and UBFM immediates on two sources.
    for (name, base) in [
        ("sbfm", 0x9340_0020u32),
        ("bfm", 0xb340_0020),
        ("ubfm", 0xd340_0020),
    ] {
        for immr in (0..64u32).step_by(7) {
            for imms in (0..64u32).step_by(9) {
                cases.push(
                    Case::new(
                        format!("{name}.{immr}.{imms}"),
                        &[base | immr << 16 | imms << 10],
                    )
                    .x(0, 0x5a5a_5a5a_a5a5_a5a5)
                    .x(1, 0x8123_4567_89ab_cdef),
                );
            }
        }
    }
}

fn atomics(cases: &mut Vec<Case>) {
    // Single-PE LSE: Xt = old [X1], [X1] = op(old, Xs), all orderings.
    const OPERATIONS: [(&str, u32); 9] = [
        ("ldadd", 0x0000),
        ("ldclr", 0x1000),
        ("ldeor", 0x2000),
        ("ldset", 0x3000),
        ("ldsmax", 0x4000),
        ("ldsmin", 0x5000),
        ("ldumax", 0x6000),
        ("ldumin", 0x7000),
        ("swp", 0x8000),
    ];
    let operands = [0x8000_0000_0000_0001u64, 0x7f, 0xffff_ffff_ffff_ff80];
    for (name, opcode) in OPERATIONS {
        for (size, label) in [(0u32, "b"), (1, "h"), (2, "w"), (3, "x")] {
            for (order, bits) in [("", 0u32), ("a", 1 << 23), ("l", 1 << 22), ("al", 3 << 22)] {
                let word = 0x3820_0000 | size << 30 | bits | 2 << 16 | opcode | 1 << 5 | 3;
                for (index, operand) in operands.iter().enumerate() {
                    cases.push(
                        Case::new(format!("{name}{order}.{label}.{index}"), &[word])
                            .memory(1, 16, &MEMORY_PATTERN)
                            .x(2, *operand)
                            .x(3, 0x3333),
                    );
                }
            }
        }
    }
    // CAS: equal and unequal compare values, and an in-granule unaligned
    // address (FEAT_LSE2).
    for (size, label) in [(0u32, "b"), (1, "h"), (2, "w"), (3, "x")] {
        let word = 0x08a0_7c00 | size << 30 | 2 << 16 | 1 << 5 | 3;
        let expected = u64::from_le_bytes(MEMORY_PATTERN[16..24].try_into().unwrap());
        for (case, compare) in [("equal", expected), ("unequal", expected ^ 1)] {
            cases.push(
                Case::new(format!("cas.{label}.{case}"), &[word])
                    .memory(1, 16, &MEMORY_PATTERN)
                    .x(2, compare)
                    .x(3, 0x0123_4567_89ab_cdef),
            );
        }
    }
    // LDAR and LDADD inside a 16-byte granule but not naturally aligned.
    cases.push(Case::new("ldar.x.unaligned", &[0xc8df_fc23]).memory(1, 20, &MEMORY_PATTERN));
    cases.push(
        Case::new("ldadd.x.unaligned", &[0xf822_0023])
            .memory(1, 20, &MEMORY_PATTERN)
            .x(2, 1),
    );
    // LDP and STP of X at aligned and unaligned addresses.
    cases.push(Case::new("ldp.x.aligned", &[0xa940_0c22]).memory(1, 16, &MEMORY_PATTERN));
    cases.push(Case::new("ldp.x.unaligned", &[0xa940_0c22]).memory(1, 20, &MEMORY_PATTERN));
    cases.push(
        Case::new("stp.x.aligned", &[0xa900_0c22])
            .memory(1, 16, &MEMORY_PATTERN)
            .x(2, 0x1111_2222_3333_4444)
            .x(3, 0x5555_6666_7777_8888),
    );
}

fn pointer_authentication(cases: &mut Vec<Case>) {
    // Key-independent PAC: XPACI and XPACD strip any PAC field; an arm64
    // (not arm64e) process has its keys disabled, so PACIA and AUTIA leave
    // the pointer.
    let pointers = [
        0x0000_7fff_1234_5678u64,
        0x00ff_7fff_1234_5678,
        0x5a3c_7fff_1234_5678,
        0xff80_0000_1234_5678,
        0x8000_0000_0000_0000,
        0xffff_ffff_ffff_ffff,
    ];
    for (index, pointer) in pointers.iter().enumerate() {
        cases.push(Case::new(format!("xpaci.{index}"), &[0xdac1_43e0]).x(0, *pointer));
        cases.push(Case::new(format!("xpacd.{index}"), &[0xdac1_47e0]).x(0, *pointer));
        cases.push(
            Case::new(format!("pacia.autia.{index}"), &[0xdac1_0020, 0xdac1_1020])
                .x(0, *pointer)
                .x(1, 7),
        );
    }
}

fn fpcr_traps(cases: &mut Vec<Case>) {
    const MSR_FPCR_X1: u32 = 0xd51b_4401;
    const MRS_X2_FPCR: u32 = 0xd53b_4402;
    const FDIV_D0_D1_D2: u32 = 0x1e62_1820;
    const FADD_D0_D1_D2: u32 = 0x1e62_2820;
    const ONE: u64 = 0x3ff0_0000_0000_0000;
    for bit in [8u64, 9, 10, 11, 12, 15] {
        cases.push(
            Case::new(format!("fpcr.enable{bit}"), &[MSR_FPCR_X1, MRS_X2_FPCR]).x(1, 1 << bit),
        );
    }
    cases.push(Case::new("fpcr.all", &[MSR_FPCR_X1, MRS_X2_FPCR]).x(1, u64::from(u32::MAX)));
    for (label, divisor) in [("exact", ONE), ("zero", 0)] {
        for (enables, bits) in [("all", 0x9f00u64), ("dze", 0x200), ("ioe", 0x100)] {
            cases.push(
                Case::new(
                    format!("fdiv.trap.{enables}.{label}"),
                    &[MSR_FPCR_X1, FDIV_D0_D1_D2],
                )
                .x(1, bits)
                .v(0, 7, 7)
                .v(1, ONE, 0)
                .v(2, divisor, 0),
            );
        }
    }
    cases.push(
        Case::new("fadd.trap.ixe.exact", &[MSR_FPCR_X1, FADD_D0_D1_D2])
            .x(1, 0x1000)
            .v(1, ONE, 0)
            .v(2, ONE, 0),
    );
    cases.push(
        Case::new("fadd.trap.ixe.inexact", &[MSR_FPCR_X1, FADD_D0_D1_D2])
            .x(1, 0x1000)
            .v(1, ONE, 0)
            .v(2, 1, 0),
    );
}

fn register_overlaps(cases: &mut Vec<Case>) {
    // CONSTRAINED UNPREDICTABLE overlaps (CPU-09): X1 is base and data.
    for (name, word) in [
        ("ldr.post", 0xf840_8421u32),
        ("ldr.pre", 0xf840_8c21),
        ("str.post", 0xf800_8421),
        ("str.pre", 0xf800_8c21),
        ("ldrb.post", 0x3840_1421),
        ("ldrsh.post", 0x78c0_2421),
        ("ldp.same", 0xa940_0441),
        ("ldp.zr", 0xa940_7c5f),
        ("ldnp.same", 0xa840_0441),
        ("ldpsw.same", 0x6940_0441),
        ("ldp.w.same", 0x2940_0441),
        ("ldp.post", 0xa8c1_0821),
        ("ldp.w.post", 0x28c1_0821),
        ("stp.pre", 0xa981_0821),
        ("stp.w.post", 0x2881_0821),
        ("ldp.d.same", 0x6d40_0441),
        ("ldp.q.same", 0xad40_0441),
        ("ldp.s.same", 0x2d40_0441),
        ("ldnp.d.same", 0x6c40_0441),
        ("ldp.d.pre.same", 0x6dc1_0441),
    ] {
        cases.push(
            Case::new(format!("overlap.{name}"), &[word])
                .memory(1, 16, &MEMORY_PATTERN)
                .memory(2, 16, &MEMORY_PATTERN),
        );
    }
    // The same forms without the overlap.
    cases
        .push(Case::new("overlap.control.ldr.post", &[0xf840_8441]).memory(2, 16, &MEMORY_PATTERN));
    cases
        .push(Case::new("overlap.control.ldp.post", &[0xa8c1_1043]).memory(2, 16, &MEMORY_PATTERN));
}

/// Every case, in a fixed order.
pub fn all() -> Vec<Case> {
    let mut cases = Vec::new();
    fp_conversions(&mut cases);
    fp_rounding(&mut cases);
    fp_extrema(&mut cases);
    fp_arithmetic(&mut cases);
    fp_estimates(&mut cases);
    fp_compares(&mut cases);
    saturating_simd(&mut cases);
    integers(&mut cases);
    atomics(&mut cases);
    pointer_authentication(&mut cases);
    fpcr_traps(&mut cases);
    register_overlaps(&mut cases);
    cases
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_names_are_unique() {
        let cases = all();
        let mut names: Vec<&str> = cases.iter().map(|case| case.name.as_str()).collect();
        names.sort_unstable();
        let total = names.len();
        names.dedup();
        assert_eq!(names.len(), total);
    }

    #[test]
    fn half_conversion_rounds_exact_values() {
        assert_eq!(half(1.0), 0x3c00);
        assert_eq!(half(-2.5), 0xc100);
        assert_eq!(half(65504.0), 0x7bff);
        assert_eq!(half(2f64.powi(-24)), 1);
    }
}
