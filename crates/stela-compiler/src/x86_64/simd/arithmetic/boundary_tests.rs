//! Results at the minimum normal: exact values just below, at and above it,
//! in every rounding mode, with and without flushing, in ordinary and
//! system-mode blocks on every target the host runs. Arm with FPCR.AH zero
//! detects tininess before rounding, x86 after, so a product whose exact
//! value is below the minimum normal but rounds to it is tiny on Arm only:
//! UFC with IXC, or under FZ a signed zero with UFC alone. Products are
//! checked against an exact integer model of FPMul (which the reference
//! must match too); the operations that share the rounded-status path
//! (FMADD/FMSUB/FNMADD/FNMSUB, FMLA/FMLS, FDIV, FCVT and FCVTN narrowing)
//! against the reference. A completion must match in every lane and FPSR;
//! an exit to the helper must leave the state unchanged.
use crate::{
    GuestAddress, GuestState, Options, TargetCpu,
    aarch64::floating::{
        self, BinaryOperation, FPCR_AH, FPCR_FZ, FPCR_FZ16, FPCR_ROUNDING_SHIFT, Format, INEXACT,
        UNDERFLOW,
        fused::{self, FusedOperation},
        precision::{self, PrecisionRounding},
    },
    block::{BlockProfile, CompilationPlan, Features},
    x86_64::native::run,
};
use alloc::{format, string::String, vec::Vec};

const PC: GuestAddress = GuestAddress(0x1000_0000);
const RETURN: u64 = 0x4000;
const D: u32 = 3;
const N: u32 = 4;
const M: u32 = 5;
const A: u32 = 6;

fn targets() -> Vec<TargetCpu> {
    let host = TargetCpu::detect();
    let mut targets: Vec<TargetCpu> = [
        TargetCpu::Baseline,
        TargetCpu::X86_64_V2,
        TargetCpu::X86_64_V3,
    ]
    .into_iter()
    .filter(|target| host.supports(*target))
    .collect();
    targets.push(host);
    targets
}

/// The word compiled before a RET, as an ordinary block and as a
/// system-mode block (pinned registers).
fn compiled(word: u32, target: TargetCpu) -> [(Vec<u8>, bool); 2] {
    let source = [word, 0xd65f_03c0].map(u32::to_le_bytes).concat();
    let compile = |profile| {
        CompilationPlan::new(&source, PC, &Options::new(profile, target))
            .unwrap()
            .compile()
            .unwrap()
            .native
            .x86_64_code
    };
    [
        (compile(BlockProfile::ORDINARY), false),
        (
            crate::x86_64::pinned::entered(&compile(BlockProfile::new(Features::SYSTEM_MODE))),
            true,
        ),
    ]
}

/// The flush control of `format`: FZ16 for Half, FZ otherwise.
fn flush_control(format: Format) -> u32 {
    if format == Format::Half {
        FPCR_FZ16
    } else {
        FPCR_FZ
    }
}

/// The FPCR values every case runs: each rounding mode with and without
/// flushing, then AH (checked against the reference alone).
fn controls(format: Format) -> Vec<u32> {
    let mut controls = Vec::new();
    for flush in [0, flush_control(format)] {
        for mode in 0..4 {
            controls.push(mode << FPCR_ROUNDING_SHIFT | flush);
        }
    }
    controls.extend([
        FPCR_AH,
        FPCR_AH | 2 << FPCR_ROUNDING_SHIFT,
        FPCR_AH | FPCR_FZ,
    ]);
    controls
}

struct Unpacked {
    sign: bool,
    significand: u128,
    exponent: i32,
    subnormal: bool,
}

/// A finite nonzero operand as significand times a power of two.
fn unpack(format: Format, bits: u64) -> Option<Unpacked> {
    let fraction_bits = format.fraction_bits();
    let field = (bits & format.exponent_mask()) >> fraction_bits;
    let fraction = bits & ((1 << fraction_bits) - 1);
    let bias = format.exponent_bias() as i32;
    if field == format.exponent_mask() >> fraction_bits || field == 0 && fraction == 0 {
        return None;
    }
    let (significand, biased) = if field == 0 {
        (fraction, 1)
    } else {
        (fraction | 1 << fraction_bits, field as i32)
    };
    Some(Unpacked {
        sign: bits & format.sign_mask() != 0,
        significand: u128::from(significand),
        exponent: biased - bias - fraction_bits as i32,
        subnormal: field == 0,
    })
}

/// Arm's FPMul (FNMUL: the rounded product negated) of finite nonzero
/// operands with FPCR.AH zero, from the exact product: tiny before
/// rounding when below the minimum normal, flushed to a signed zero with
/// UFC alone under `flush`, otherwise rounded in FPCR's mode with IXC when
/// inexact and UFC when tiny and inexact. `None` for other operands, a
/// flushed subnormal input or an overflow.
fn exact_product(
    format: Format,
    fpcr: u32,
    left: u64,
    right: u64,
    negate: bool,
) -> Option<(u64, u32)> {
    let (left, right) = (unpack(format, left)?, unpack(format, right)?);
    let flush = fpcr & flush_control(format) != 0;
    if fpcr & FPCR_AH != 0 || flush && (left.subnormal || right.subnormal) {
        return None;
    }
    let fraction_bits = format.fraction_bits() as i32;
    let bias = format.exponent_bias() as i32;
    let minimum = 1 - bias;
    let sign = left.sign ^ right.sign;
    let product = left.significand * right.significand;
    let exponent = left.exponent + right.exponent;
    let top = (u128::BITS - product.leading_zeros()) as i32 - 1 + exponent;
    let tiny = top < minimum;
    let sign_bit = if sign ^ negate { format.sign_mask() } else { 0 };
    if tiny && flush {
        return Some((sign_bit, UNDERFLOW));
    }
    let mut grid = (top - fraction_bits).max(minimum - fraction_bits);
    let shift = grid - exponent;
    let (mut rounded, inexact) = if shift <= 0 {
        (product << -shift, false)
    } else {
        let kept = product >> shift;
        let rest = product & ((1 << shift) - 1);
        let half = 1u128 << (shift - 1);
        let up = match (fpcr >> FPCR_ROUNDING_SHIFT) & 3 {
            0 => rest > half || rest == half && kept & 1 == 1,
            1 => rest != 0 && !sign,
            2 => rest != 0 && sign,
            _ => false,
        };
        (kept + u128::from(up), rest != 0)
    };
    if rounded == 1 << (fraction_bits + 1) {
        rounded >>= 1;
        grid += 1;
    }
    let bits = if rounded < 1 << fraction_bits {
        rounded as u64
    } else {
        let biased = grid + fraction_bits + bias;
        if biased >= (format.exponent_mask() >> fraction_bits) as i32 {
            return None;
        }
        (biased as u64) << fraction_bits | (rounded as u64 & ((1 << fraction_bits) - 1))
    };
    let mut exceptions = 0;
    if inexact {
        exceptions |= INEXACT;
        if tiny {
            exceptions |= UNDERFLOW;
        }
    }
    Some((sign_bit | bits, exceptions))
}

/// Operand pairs whose exact products lie just below, at and just above
/// the minimum normal: (1 + a ulp) times a subnormal b ulps below it; the
/// minimum normal times values just below and above one; and normal pairs
/// 2^k (1 + a ulp) times 2^(emin - k) (1 - b ulp), each with both sign
/// patterns and both orders.
fn boundary_pairs(format: Format) -> Vec<(u64, u64)> {
    let fraction_bits = format.fraction_bits();
    let bias = u64::from(format.exponent_bias());
    let one = bias << fraction_bits;
    let minimum = 1u64 << fraction_bits;
    let mut pairs = Vec::new();
    for a in 0..5u64 {
        for b in 1..5u64 {
            pairs.push((one | a, minimum - b));
        }
        // 1 - a ulp/2, just below one.
        pairs.push((one - 1 - a, minimum));
        pairs.push((one | a, minimum));
        pairs.push((one | a, minimum | 1));
        for b in 1..4u64 {
            for k in [1u64, 3, u64::from(fraction_bits / 2)] {
                // 2^-k (1 + a ulp) and 2^(emin + k - 1) (2 - 2b ulp).
                let left = (bias - k) << fraction_bits | a;
                let right = k << fraction_bits | ((1 << fraction_bits) - 2 * b);
                pairs.push((left, right));
            }
        }
    }
    let sign = format.sign_mask();
    let mut all = Vec::new();
    for (left, right) in pairs {
        for (l, r) in [(left, right), (right, left)] {
            for flips in [(0, 0), (sign, 0), (0, sign), (sign, sign)] {
                all.push((l ^ flips.0, r ^ flips.1));
            }
        }
    }
    all
}

/// Pack `values` as `format` lanes from lane zero.
fn pack(format: Format, values: &[u64]) -> [u64; 2] {
    let width = format.bits() as usize;
    let mut limbs = [0u64; 2];
    for (lane, value) in values.iter().enumerate() {
        let bit = lane * width;
        limbs[bit / 64] |= value << (bit % 64);
    }
    limbs
}

struct Tally {
    completed: usize,
    tiny_completed: usize,
    exited: usize,
}

/// Run `word` from `initial` on every profile and check a completion
/// against `expected` (destination vector and the FPSR flags added).
fn check(
    code: &[u8],
    initial: &GuestState,
    expected: ([u64; 2], u32),
    label: &dyn Fn() -> String,
    tally: &mut Tally,
) {
    let mut actual = initial.clone();
    let exit = run(code, &mut actual);
    if exit == PC.0 {
        assert_eq!(&actual, initial, "exit changed state: {}", label());
        tally.exited += 1;
        return;
    }
    assert_eq!(exit, RETURN, "{}", label());
    let mut want = initial.clone();
    want.v[D as usize] = expected.0;
    want.fpsr |= expected.1;
    assert_eq!(actual, want, "{}", label());
    tally.completed += 1;
    if expected.1 & UNDERFLOW != 0 && initial.fpsr & UNDERFLOW == 0 {
        tally.tiny_completed += 1;
    }
}

/// How a product form takes its operands.
#[derive(Clone, Copy, Debug)]
enum Product {
    /// Lanes elementwise; 1 is scalar.
    Elementwise(usize),
    /// Every lane times Vm's element 1.
    ByElement(usize),
}

/// FMUL, FNMUL and FMULX in every precision and shape against the exact
/// model, on every target and profile, FPSR with IXC clear and set, UFC
/// clear and set. Before Arm's before-rounding tininess was applied to the
/// full path, a product rounding up to the minimum normal completed with
/// IXC alone, or under FZ as the minimum normal rather than zero.
#[test]
fn boundary_products_match_the_exact_model() {
    use BinaryOperation::{Multiply, MultiplyExtended, NegatedMultiply};
    use Format::{Double, Half, Single};
    use Product::{ByElement, Elementwise};
    let forms: &[(u32, BinaryOperation, Format, Product)] = &[
        (0x6e20_dc00, Multiply, Single, Elementwise(4)),
        (0x2e20_dc00, Multiply, Single, Elementwise(2)),
        (0x6e60_dc00, Multiply, Double, Elementwise(2)),
        (0x1e20_0800, Multiply, Single, Elementwise(1)),
        (0x1e60_0800, Multiply, Double, Elementwise(1)),
        (0x1e20_8800, NegatedMultiply, Single, Elementwise(1)),
        (0x1e60_8800, NegatedMultiply, Double, Elementwise(1)),
        (0x4e20_dc00, MultiplyExtended, Single, Elementwise(4)),
        (0x4e60_dc00, MultiplyExtended, Double, Elementwise(2)),
        (0x5e20_dc00, MultiplyExtended, Single, Elementwise(1)),
        (0x5e60_dc00, MultiplyExtended, Double, Elementwise(1)),
        // FMUL by element: S index 1 (L), D index 1 (H).
        (0x4f80_9000 | 1 << 21, Multiply, Single, ByElement(4)),
        (0x4fc0_9000 | 1 << 11, Multiply, Double, ByElement(2)),
        (
            0x6f80_9000 | 1 << 21,
            MultiplyExtended,
            Single,
            ByElement(4),
        ),
        (0x6e40_1c00, Multiply, Half, Elementwise(8)),
        (0x4e40_1c00, MultiplyExtended, Half, Elementwise(8)),
        (0x1ee0_0800, Multiply, Half, Elementwise(1)),
        (0x1ee0_8800, NegatedMultiply, Half, Elementwise(1)),
    ];
    let mut tally = Tally {
        completed: 0,
        tiny_completed: 0,
        exited: 0,
    };
    let mut modelled = 0usize;
    for target in targets() {
        for &(base, operation, format, product) in forms {
            let word = base | M << 16 | N << 5 | D;
            let pairs = boundary_pairs(format);
            let lanes = match product {
                Elementwise(lanes) | ByElement(lanes) => lanes,
            };
            for (code, system) in compiled(word, target) {
                for chunk in pairs.chunks(lanes) {
                    for fpcr in controls(format) {
                        for fpsr in [0, INEXACT, INEXACT | UNDERFLOW] {
                            let (lefts, rights): (Vec<u64>, Vec<u64>) = match product {
                                Elementwise(_) => chunk.iter().copied().unzip(),
                                // Element 1 is the chunk's first right operand.
                                ByElement(_) => {
                                    chunk.iter().map(|&(left, _)| (left, chunk[0].1)).unzip()
                                }
                            };
                            let m = match product {
                                Elementwise(_) => pack(format, &rights),
                                ByElement(_) => pack(format, &[0, rights[0]]),
                            };
                            let mut initial = GuestState {
                                fpcr,
                                fpsr,
                                ..GuestState::default()
                            };
                            initial.x[30] = RETURN;
                            initial.v[N as usize] = pack(format, &lefts);
                            initial.v[M as usize] = m;
                            initial.v[D as usize] = [u64::MAX, u64::MAX];
                            let mut results = Vec::new();
                            let mut exceptions = 0;
                            for (&left, &right) in lefts.iter().zip(&rights) {
                                let reference =
                                    floating::evaluate(format, operation, fpcr, left, right)
                                        .unwrap();
                                if let Some(model) = exact_product(
                                    format,
                                    fpcr,
                                    left,
                                    right,
                                    operation == NegatedMultiply,
                                ) {
                                    assert_eq!(
                                        (reference.bits, reference.exceptions),
                                        model,
                                        "reference vs model: {format:?} {operation:?} \
                                         fpcr={fpcr:#x} {left:#x} {right:#x}"
                                    );
                                    modelled += 1;
                                }
                                results.push(reference.bits);
                                exceptions |= reference.exceptions;
                            }
                            let mut expected = pack(format, &results);
                            if lanes == 1 {
                                // Scalars clear the rest of Vd (NEP zero).
                                expected[1] = 0;
                            } else if lanes * format.bits() as usize == 64 {
                                expected[1] = 0;
                            }
                            check(
                                &code,
                                &initial,
                                (expected, exceptions),
                                &|| {
                                    format!(
                                        "{word:08x} {operation:?} {format:?} system={system} \
                                         {target:?} fpcr={fpcr:#x} fpsr={fpsr:#x} \
                                         n={lefts:x?} m={rights:x?}"
                                    )
                                },
                                &mut tally,
                            );
                        }
                    }
                }
            }
        }
    }
    assert!(modelled > 10_000, "{modelled}");
    assert!(tally.completed > 10_000, "{} completed", tally.completed);
    assert!(
        tally.tiny_completed > 1_000,
        "{} tiny completed",
        tally.tiny_completed
    );
}

/// The operations that share the products' rounded-status path, from
/// operands at the same boundary: FMADD, FMSUB, FNMADD and FNMSUB (S, D,
/// H), FMLA and FMLS (4S, 2D), FDIV (S, D, 4S, 2D), FCVT narrowing (S from
/// D, H from S and D) and FCVTN (2S, 4H) against the reference.
#[test]
fn boundary_siblings_match_the_reference() {
    use Format::{Double, Half, Single};
    let mut tally = Tally {
        completed: 0,
        tiny_completed: 0,
        exited: 0,
    };
    let state = |fpcr, fpsr| {
        let mut state = GuestState {
            fpcr,
            fpsr,
            ..GuestState::default()
        };
        state.x[30] = RETURN;
        state.v[D as usize] = [u64::MAX, u64::MAX];
        state
    };
    for target in targets() {
        // Fused forms: (word, operation, format, lanes).
        let fused_forms: &[(u32, FusedOperation, Format, usize)] = &[
            (0x1f00_0000, FusedOperation::Add, Single, 1),
            (0x1f00_8000, FusedOperation::Subtract, Single, 1),
            (0x1f20_0000, FusedOperation::NegatedAdd, Single, 1),
            (0x1f20_8000, FusedOperation::NegatedSubtract, Single, 1),
            (0x1f40_0000, FusedOperation::Add, Double, 1),
            (0x1f60_8000, FusedOperation::NegatedSubtract, Double, 1),
            (0x1fc0_0000, FusedOperation::Add, Half, 1),
            (0x4e20_cc00, FusedOperation::Add, Single, 4),
            (0x4ea0_cc00, FusedOperation::Subtract, Single, 4),
            (0x4e60_cc00, FusedOperation::Add, Double, 2),
        ];
        for &(base, operation, format, lanes) in fused_forms {
            let word = if lanes == 1 {
                base | M << 16 | A << 10 | N << 5 | D
            } else {
                base | M << 16 | N << 5 | D
            };
            let pairs = boundary_pairs(format);
            let sign = format.sign_mask();
            let tiny_addend = 1u64;
            let addends = [
                0,
                sign,
                tiny_addend,
                sign | tiny_addend,
                1 << format.fraction_bits(),
            ];
            for (code, system) in compiled(word, target) {
                for (index, chunk) in pairs.chunks(lanes).enumerate() {
                    for fpcr in controls(format) {
                        for fpsr in [0, INEXACT] {
                            let (lefts, rights): (Vec<u64>, Vec<u64>) =
                                chunk.iter().copied().unzip();
                            let addend_lanes: Vec<u64> = (0..lefts.len())
                                .map(|lane| addends[(index + lane) % addends.len()])
                                .collect();
                            let mut initial = state(fpcr, fpsr);
                            initial.v[N as usize] = pack(format, &lefts);
                            initial.v[M as usize] = pack(format, &rights);
                            let addend_register = if lanes == 1 { A } else { D };
                            initial.v[addend_register as usize] = pack(format, &addend_lanes);
                            let mut results = Vec::new();
                            let mut exceptions = 0;
                            for lane in 0..lefts.len() {
                                let outcome = fused::evaluate(
                                    format,
                                    operation,
                                    fpcr,
                                    addend_lanes[lane],
                                    lefts[lane],
                                    rights[lane],
                                )
                                .unwrap();
                                results.push(outcome.bits);
                                exceptions |= outcome.exceptions;
                            }
                            let mut expected = pack(format, &results);
                            if lanes == 1 {
                                expected[1] = 0;
                            }
                            check(
                                &code,
                                &initial,
                                (expected, exceptions),
                                &|| {
                                    format!(
                                        "{word:08x} {operation:?} {format:?} system={system} \
                                         {target:?} fpcr={fpcr:#x} fpsr={fpsr:#x} \
                                         a={addend_lanes:x?} n={lefts:x?} m={rights:x?}"
                                    )
                                },
                                &mut tally,
                            );
                        }
                    }
                }
            }
        }
        // Quotients: the products' pairs with the right operand inverted
        // around one, so quotients land at the same boundary.
        let divides: &[(u32, Format, usize)] = &[
            (0x1e20_1800, Single, 1),
            (0x1e60_1800, Double, 1),
            (0x6e20_fc00, Single, 4),
            (0x6e60_fc00, Double, 2),
        ];
        for &(base, format, lanes) in divides {
            let word = base | M << 16 | N << 5 | D;
            let fraction_bits = format.fraction_bits();
            let one = u64::from(format.exponent_bias()) << fraction_bits;
            let minimum = 1u64 << fraction_bits;
            let mut pairs = Vec::new();
            for a in 0..5u64 {
                for b in 1..5u64 {
                    pairs.push((minimum - b, one - a));
                    pairs.push((minimum + b, one | a));
                    pairs.push((minimum | a, one | b));
                    pairs.push((minimum - b, one | a));
                }
            }
            let sign = format.sign_mask();
            let pairs: Vec<(u64, u64)> = pairs
                .into_iter()
                .flat_map(|(n, m)| [(n, m), (n ^ sign, m), (n, m ^ sign)])
                .collect();
            for (code, system) in compiled(word, target) {
                for chunk in pairs.chunks(lanes) {
                    for fpcr in controls(format) {
                        for fpsr in [0, INEXACT] {
                            let (lefts, rights): (Vec<u64>, Vec<u64>) =
                                chunk.iter().copied().unzip();
                            let mut initial = state(fpcr, fpsr);
                            initial.v[N as usize] = pack(format, &lefts);
                            initial.v[M as usize] = pack(format, &rights);
                            let mut results = Vec::new();
                            let mut exceptions = 0;
                            for (&left, &right) in lefts.iter().zip(&rights) {
                                let outcome = floating::evaluate(
                                    format,
                                    BinaryOperation::Divide,
                                    fpcr,
                                    left,
                                    right,
                                )
                                .unwrap();
                                results.push(outcome.bits);
                                exceptions |= outcome.exceptions;
                            }
                            let mut expected = pack(format, &results);
                            if lanes == 1 {
                                expected[1] = 0;
                            }
                            check(
                                &code,
                                &initial,
                                (expected, exceptions),
                                &|| {
                                    format!(
                                        "{word:08x} FDIV {format:?} system={system} {target:?} \
                                         fpcr={fpcr:#x} fpsr={fpsr:#x} n={lefts:x?} m={rights:x?}"
                                    )
                                },
                                &mut tally,
                            );
                        }
                    }
                }
            }
        }
        // Narrowing: sources just below, at and above the destination's
        // minimum normal, in source ulps.
        let narrowing: &[(u32, Format, Format, usize)] = &[
            (0x1e62_4000, Double, Single, 1),
            (0x1e23_c000, Single, Half, 1),
            (0x1e63_c000, Double, Half, 1),
            (0x0e61_6800, Double, Single, 2),
            (0x0e21_6800, Single, Half, 4),
        ];
        for &(base, source, destination, lanes) in narrowing {
            let word = base | N << 5 | D;
            let source_bits = source.fraction_bits() as i64;
            let destination_minimum = 1 - i64::from(destination.exponent_bias());
            let biased = (destination_minimum + i64::from(source.exponent_bias())) as u64;
            let at = biased << source_bits;
            // Half a destination ulp below the minimum normal, in source ulps.
            let half_ulp = 1u64 << (source_bits - destination.fraction_bits() as i64 - 1);
            let mut values = Vec::new();
            for delta in [
                1u64,
                2,
                3,
                half_ulp - 1,
                half_ulp,
                half_ulp + 1,
                2 * half_ulp - 1,
            ] {
                values.extend([at - delta, at + delta]);
            }
            values.push(at);
            let sign = source.sign_mask();
            let values: Vec<u64> = values.into_iter().flat_map(|v| [v, v ^ sign]).collect();
            for (code, system) in compiled(word, target) {
                for chunk in values.chunks(lanes) {
                    for fpcr in controls(destination) {
                        for fpsr in [0, INEXACT] {
                            let mut initial = state(fpcr, fpsr);
                            initial.v[N as usize] = pack(source, chunk);
                            let mut results = Vec::new();
                            let mut exceptions = 0;
                            for &value in chunk {
                                let outcome = precision::evaluate(
                                    source,
                                    destination,
                                    PrecisionRounding::Fpcr,
                                    fpcr,
                                    value,
                                )
                                .unwrap();
                                results.push(outcome.bits);
                                exceptions |= outcome.exceptions;
                            }
                            let mut expected = pack(destination, &results);
                            if lanes == 1 || lanes * destination.bits() as usize == 64 {
                                expected[1] = 0;
                            }
                            check(
                                &code,
                                &initial,
                                (expected, exceptions),
                                &|| {
                                    format!(
                                        "{word:08x} narrow {source:?}->{destination:?} \
                                         system={system} {target:?} fpcr={fpcr:#x} \
                                         fpsr={fpsr:#x} n={chunk:x?}"
                                    )
                                },
                                &mut tally,
                            );
                        }
                    }
                }
            }
        }
    }
    assert!(tally.completed > 5_000, "{} completed", tally.completed);
}
