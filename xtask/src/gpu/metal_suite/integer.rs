//! MSL's integer arithmetic, bitwise, comparison and integer functions over
//! char to ulong, scalar and vector, at every MSL version that compiles
//! them. Results are exact: each is asserted against arithmetic in the
//! type's width, with C's promotion, truncating division and wrapping.
use super::plan::{Buffer, Case, Output, Plan, Tolerance, VERSIONS, suffix};
use super::values::{Dtype, Random, ints};

const COUNT: usize = 512;

#[derive(Clone, Copy)]
struct Type {
    name: &'static str,
    dtype: Dtype,
    bits: u32,
    signed: bool,
}

const TYPES: [Type; 8] = [
    Type {
        name: "char",
        dtype: Dtype::I8,
        bits: 8,
        signed: true,
    },
    Type {
        name: "uchar",
        dtype: Dtype::U8,
        bits: 8,
        signed: false,
    },
    Type {
        name: "short",
        dtype: Dtype::I16,
        bits: 16,
        signed: true,
    },
    Type {
        name: "ushort",
        dtype: Dtype::U16,
        bits: 16,
        signed: false,
    },
    Type {
        name: "int",
        dtype: Dtype::I32,
        bits: 32,
        signed: true,
    },
    Type {
        name: "uint",
        dtype: Dtype::U32,
        bits: 32,
        signed: false,
    },
    Type {
        name: "long",
        dtype: Dtype::I64,
        bits: 64,
        signed: true,
    },
    Type {
        name: "ulong",
        dtype: Dtype::U64,
        bits: 64,
        signed: false,
    },
];

fn mask(bits: u32) -> u128 {
    (1u128 << bits) - 1
}

fn wrap(v: i128, t: Type) -> i128 {
    let u = (v as u128) & mask(t.bits);
    if t.signed && u >> (t.bits - 1) & 1 == 1 {
        u as i128 - (1i128 << t.bits)
    } else {
        u as i128
    }
}

fn unsigned(v: i128, bits: u32) -> u128 {
    (v as u128) & mask(bits)
}

fn range(t: Type) -> (i128, i128) {
    if t.signed {
        (-(1i128 << (t.bits - 1)), (1i128 << (t.bits - 1)) - 1)
    } else {
        (0, (1i128 << t.bits) - 1)
    }
}

fn saturate(v: i128, t: Type) -> i128 {
    let (lo, hi) = range(t);
    v.clamp(lo, hi)
}

fn trunc_div(a: i128, b: i128) -> i128 {
    let q = a.abs() / b.abs();
    if (a < 0) == (b < 0) { q } else { -q }
}

/// x * y and its high half, exactly: 64-bit unsigned products reach 2^128.
fn product_high(x: i128, y: i128, t: Type) -> i128 {
    if t.bits == 64 && !t.signed {
        ((x as u128 * y as u128) >> 64) as i128
    } else {
        (x * y) >> t.bits
    }
}

fn mad_sat(x: i128, y: i128, z: i128, t: Type) -> i128 {
    if t.bits == 64 && !t.signed {
        (x as u128 * y as u128 + z as u128).min(mask(64)) as i128
    } else {
        saturate(x * y + z, t)
    }
}

fn extract(v: i128, offset: u32, count: u32, t: Type) -> i128 {
    if count == 0 {
        return 0;
    }
    let field = (unsigned(v, t.bits) >> offset) & mask(count);
    if t.signed && field >> (count - 1) & 1 == 1 {
        field as i128 - (1i128 << count)
    } else {
        field as i128
    }
}

fn insert(base: i128, value: i128, offset: u32, count: u32, t: Type) -> i128 {
    let m = mask(count) << offset;
    ((unsigned(base, t.bits) & !m) | ((unsigned(value, t.bits) << offset) & m)) as i128
}

/// The bit-field operands of extract_bits and insert_bits.
fn field(y: i128, z: i128, bits: u32) -> (u32, u32) {
    let offset = (unsigned(y, 32) % u128::from(bits)) as u32;
    let count = (unsigned(z, 32) % u128::from(bits - offset + 1)) as u32;
    (offset, count)
}

fn median(a: i128, b: i128, c: i128) -> i128 {
    let mut v = [a, b, c];
    v.sort();
    v[1]
}

type Op = fn(i128, i128, i128, Type) -> i128;

/// An operation's name, MSL expression over x, y and z, operand
/// constraint, and expected value before wrapping to the type.
const OPS: &[(&str, &str, &str, Op)] = &[
    ("add", "x + y", "", |x, y, _, _| x + y),
    ("sub", "x - y", "", |x, y, _, _| x - y),
    ("mul", "x * y", "", |x, y, _, _| x.wrapping_mul(y)),
    ("div", "x / y", "divisor", |x, y, _, _| trunc_div(x, y)),
    ("rem", "x % y", "divisor", |x, y, _, _| {
        x - y * trunc_div(x, y)
    }),
    ("and", "x & y", "", |x, y, _, _| x & y),
    ("or", "x | y", "", |x, y, _, _| x | y),
    ("xor", "x ^ y", "", |x, y, _, _| x ^ y),
    ("not", "~x", "", |x, _, _, _| !x),
    ("neg", "-x", "", |x, _, _, _| -x),
    ("shl", "x << (y & SHIFT)", "", |x, y, _, t| {
        x.wrapping_shl((unsigned(y, t.bits) & u128::from(t.bits - 1)) as u32)
    }),
    ("shr", "x >> (y & SHIFT)", "", |x, y, _, t| {
        x >> (unsigned(y, t.bits) & u128::from(t.bits - 1))
    }),
    ("eq", "T(x == y)", "", |x, y, _, _| i128::from(x == y)),
    ("lt", "T(x < y)", "", |x, y, _, _| i128::from(x < y)),
    ("le", "T(x <= y)", "", |x, y, _, _| i128::from(x <= y)),
    (
        "select",
        "x > y ? z : y",
        "",
        |x, y, z, _| if x > y { z } else { y },
    ),
    ("min", "min(x, y)", "", |x, y, _, _| x.min(y)),
    ("max", "max(x, y)", "", |x, y, _, _| x.max(y)),
    (
        "clamp",
        "clamp(x, min(y, z), max(y, z))",
        "",
        |x, y, z, _| x.max(y.min(z)).min(y.max(z)),
    ),
    ("abs", "T(abs(x))", "", |x, _, _, _| x.abs()),
    ("absdiff", "T(absdiff(x, y))", "", |x, y, _, _| {
        (x - y).abs()
    }),
    ("add_sat", "addsat(x, y)", "", |x, y, _, t| {
        saturate(x + y, t)
    }),
    ("sub_sat", "subsat(x, y)", "", |x, y, _, t| {
        saturate(x - y, t)
    }),
    ("hadd", "hadd(x, y)", "", |x, y, _, _| (x + y) >> 1),
    ("rhadd", "rhadd(x, y)", "", |x, y, _, _| (x + y + 1) >> 1),
    ("mul_hi", "mulhi(x, y)", "", |x, y, _, t| {
        product_high(x, y, t)
    }),
    ("mad_hi", "madhi(x, y, z)", "", |x, y, z, t| {
        product_high(x, y, t) + z
    }),
    ("mad_sat", "madsat(x, y, z)", "", mad_sat),
    ("clz", "clz(x)", "", |x, _, _, t| {
        i128::from(t.bits) - (128 - unsigned(x, t.bits).leading_zeros()) as i128
    }),
    ("ctz", "ctz(x)", "", |x, _, _, t| {
        let v = unsigned(x, t.bits);
        if v == 0 {
            i128::from(t.bits)
        } else {
            i128::from(v.trailing_zeros())
        }
    }),
    ("popcount", "popcount(x)", "", |x, _, _, t| {
        i128::from(unsigned(x, t.bits).count_ones())
    }),
    ("reverse_bits", "reverse_bits(x)", "", |x, _, _, t| {
        (unsigned(x, t.bits).reverse_bits() >> (128 - t.bits)) as i128
    }),
    ("rotate", "rotate(x, y)", "", |x, y, _, t| {
        let (v, n) = (
            unsigned(x, t.bits),
            (unsigned(y, t.bits) % u128::from(t.bits)) as u32,
        );
        if n == 0 {
            v as i128
        } else {
            (((v << n) | (v >> (t.bits - n))) & mask(t.bits)) as i128
        }
    }),
    (
        "extract_bits",
        "extract_bits(x, uint(y) % BITS, uint(z) % (BITS - uint(y) % BITS + 1))",
        "",
        |x, y, z, t| {
            let (offset, count) = field(y, z, t.bits);
            extract(x, offset, count, t)
        },
    ),
    (
        "insert_bits",
        "insert_bits(x, z, uint(y) % BITS, uint(z) % (BITS - uint(y) % BITS + 1))",
        "",
        |x, y, z, t| {
            let (offset, count) = field(y, z, t.bits);
            insert(x, z, offset, count, t)
        },
    ),
    ("max3", "max3(x, y, z)", "", |x, y, z, _| x.max(y).max(z)),
    ("min3", "min3(x, y, z)", "", |x, y, z, _| x.min(y).min(z)),
    ("median3", "median3(x, y, z)", "", |x, y, z, _| {
        median(x, y, z)
    }),
    ("mul24", "mul24(x, y)", "int24", |x, y, _, _| x * y),
    ("mad24", "mad24(x, y, z)", "int24", |x, y, z, _| x * y + z),
];

/// Functions MSL defines only for 32-bit operands.
fn only_32(op: &str) -> bool {
    matches!(op, "mul24" | "mad24")
}

/// Operations tested on scalars only: the bit-field offsets are scalars.
fn scalar(op: &str) -> bool {
    matches!(op, "select" | "extract_bits" | "insert_bits")
}

fn operands(t: Type, constraint: &str, rng: &mut Random, count: usize) -> Vec<i128> {
    let (lo, hi) = range(t);
    let mut edges = vec![0, 1, lo, hi, lo + 1, hi - 1, 2, 3, 7, 1i128 << (t.bits - 2)];
    if t.signed {
        edges.extend([-1, -2, -7]);
    }
    (0..count)
        .map(|i| {
            let mut v = if i < edges.len() {
                edges[i]
            } else if i % 3 == 0 {
                i128::from(rng.u64() % 256) - if t.signed { 128 } else { 0 }
            } else {
                wrap(i128::from(rng.u64()), t)
            };
            if constraint == "divisor" {
                // Division by zero and the overflowing INT_MIN / -1 are undefined.
                if v == 0 || (t.signed && v == -1) {
                    v = 3;
                }
            } else if constraint == "int24" {
                v = if t.signed {
                    v.rem_euclid(1 << 23) * if i % 2 == 1 { 1 } else { -1 }
                } else {
                    v.rem_euclid(1 << 24)
                };
            }
            wrap(v, t)
        })
        .collect()
}

fn msl_name(type_name: &str, op: &str, lanes: u32) -> String {
    if lanes > 1 {
        format!("{type_name}{lanes}_{op}")
    } else {
        format!("{type_name}_{op}")
    }
}

fn msl() -> String {
    let mut lines = vec![
        "#include <metal_stdlib>".to_string(),
        "using namespace metal;".to_string(),
    ];
    for t in TYPES {
        for lanes in [1, 4] {
            let ty = if lanes > 1 {
                format!("{}{lanes}", t.name)
            } else {
                t.name.to_string()
            };
            for &(op, expr, ..) in OPS {
                if (only_32(op) && t.bits != 32) || (lanes > 1 && scalar(op)) {
                    continue;
                }
                let e = expr
                    .replace("SHIFT", &(t.bits - 1).to_string())
                    .replace("BITS", &t.bits.to_string())
                    .replace("T(", &format!("{ty}("));
                let name = msl_name(t.name, op, lanes);
                lines.push(format!("#ifndef SKIP_{name}"));
                lines.push(format!(
                    "kernel void {name}(device const {ty} *a [[buffer(0)]], device const {ty} *b [[buffer(1)]], \
                     device const {ty} *c [[buffer(2)]], device {ty} *r [[buffer(3)]], uint i [[thread_position_in_grid]]) \
                     {{ {ty} x = a[i], y = b[i], z = c[i]; (void)y; (void)z; r[i] = {ty}({e}); }}"
                ));
                lines.push("#endif".into());
            }
        }
    }
    lines.join("\n") + "\n"
}

pub fn build(plan: &mut Plan) {
    let source = plan.generated("integer.metal", msl());
    for (version, ..) in VERSIONS {
        let library = plan.library(&format!("integer_{version}"), &source, &[], version);
        let skipped = plan.unavailable(&source, version);
        for (row, t) in TYPES.into_iter().enumerate() {
            let mut rng = Random::new(5000 + row as u64);
            for &(op, _, constraint, f) in OPS {
                if only_32(op) && t.bits != 32 {
                    continue;
                }
                let int24 = if constraint == "int24" {
                    constraint
                } else {
                    ""
                };
                let xs = operands(t, int24, &mut rng, COUNT);
                let ys = operands(t, constraint, &mut rng, COUNT);
                let zs = operands(t, int24, &mut rng, COUNT);
                let expected: Vec<i128> = (0..COUNT)
                    .map(|i| wrap(f(xs[i], ys[i], zs[i], t), t))
                    .collect();
                let buffers = [
                    Buffer::data("in0", 0, ints(t.dtype, &xs)),
                    Buffer::data("in1", 1, ints(t.dtype, &ys)),
                    Buffer::data("in2", 2, ints(t.dtype, &zs)),
                    Buffer::zeroed("result", 3, COUNT * t.bits as usize / 8),
                ];
                let output = Output::new("result", t.dtype, Tolerance::default())
                    .expect_same(ints(t.dtype, &expected));
                for lanes in [1u32, 4] {
                    if lanes > 1 && scalar(op) {
                        continue;
                    }
                    let name = msl_name(t.name, op, lanes);
                    if skipped.contains(&name) {
                        continue;
                    }
                    let vector = if lanes > 1 {
                        lanes.to_string()
                    } else {
                        String::new()
                    };
                    plan.add(
                        Case::compute1(
                            &format!("integer.{}{vector}.{op}{}", t.name, suffix(version)),
                            &library,
                            &name,
                            COUNT as u32 / lanes,
                        )
                        .buffers(buffers.clone())
                        .output(output.clone()),
                    );
                }
            }
        }
    }
}
