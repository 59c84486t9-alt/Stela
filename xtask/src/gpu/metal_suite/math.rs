//! MSL's floating-point math library over float, half and float4, compiled
//! with fast math (Metal's default, the air.fast_* functions) and without
//! it (the precise air.* functions), at every MSL version. Every result is
//! asserted against its double-precision value within the accuracy the
//! Metal Shading Language specification gives the function: the bound a
//! shader may rely on, not the last bit Apple's GPU produces.
use super::plan::{Buffer, Case, LATEST, Output, Plan, Tolerance, VERSIONS, metal_version};
use super::reference;
use super::values::{
    Dtype, F16_MIN, F32_MIN, Random, domain_values, f16_bits, f16_from_bits, f32r, floats, ints,
    libm, sum, u32s,
};
use serde_json::json;

const COUNT: usize = 512;

fn u(n: f64) -> Tolerance {
    Tolerance::ulp(n)
}

fn exact() -> Tolerance {
    Tolerance::ulp(0.0)
}

fn p4() -> Tolerance {
    u(4.0)
}

/// With fast math the specification bounds sin and cos absolutely on
/// [-pi, pi], the exponentials relative to 3 + floor(|2x|) ulps and the
/// logarithms absolutely on [0.5, 2].
fn fast_trig() -> Tolerance {
    Tolerance::abs(2f64.powi(-13))
}

fn fast_exp() -> Tolerance {
    Tolerance::ulp(4.0).with_rel(2e-5)
}

fn fast_log() -> Tolerance {
    Tolerance::ulp(3.0).with_abs(2f64.powi(-21))
}

fn fast_derived() -> Tolerance {
    Tolerance::abs(2f64.powi(-12)).with_rel(2f64.powi(-12))
}

fn fast_pow() -> Tolerance {
    Tolerance::abs(1e-30).with_rel(1e-4)
}

/// Half-precision functions: correctly rounded basics, and transcendentals
/// within a few ulps or a half's resolution at 1.
fn half() -> Tolerance {
    Tolerance::ulp(2.0).with_abs(2f64.powi(-10))
}

/// Half sine and cosine, accurate to about 2^-9 on [-pi, pi] on Apple's
/// GPUs.
fn half_trig() -> Tolerance {
    Tolerance::ulp(2.0).with_abs(2f64.powi(-8))
}

/// Interpolation of operands up to 16 loses their low bits to cancellation.
fn mix() -> Tolerance {
    Tolerance::ulp(4.0).with_abs(4e-6)
}

fn half_mix() -> Tolerance {
    Tolerance::ulp(2.0).with_abs(2f64.powi(-6))
}

fn half_pow() -> Tolerance {
    Tolerance::ulp(4.0).with_rel(2f64.powi(-9))
}

/// A function's MSL expression over x, y, z, the domain of each operand
/// (precise, fast), and its tolerances (precise f32, fast f32, half). A
/// fast tolerance of None checks the result is one of the operation's
/// admissible values instead.
struct Row {
    name: &'static str,
    expr: &'static str,
    domains: Vec<(&'static str, &'static str)>,
    precise: Tolerance,
    fast: Option<Tolerance>,
    half: Tolerance,
}

fn row(
    name: &'static str,
    expr: &'static str,
    domains: Vec<(&'static str, &'static str)>,
    precise: Tolerance,
    fast: Tolerance,
    half: Tolerance,
) -> Row {
    Row {
        name,
        expr,
        domains,
        precise,
        fast: Some(fast),
        half,
    }
}

fn table() -> Vec<Row> {
    let any = ("any", "finite");
    let finite = ("finite", "finite");
    let small = ("small", "small");
    vec![
        row(
            "sin",
            "sin(x)",
            vec![("wide_angle", "angle")],
            p4(),
            fast_trig(),
            half_trig(),
        ),
        row(
            "cos",
            "cos(x)",
            vec![("wide_angle", "angle")],
            p4(),
            fast_trig(),
            half_trig(),
        ),
        row(
            "tan",
            "tan(x)",
            vec![("wide_angle", "tan_angle")],
            u(6.0),
            fast_derived(),
            half_trig(),
        ),
        row(
            "asin",
            "asin(x)",
            vec![("unit", "unit")],
            p4(),
            u(5.0),
            half(),
        ),
        row(
            "acos",
            "acos(x)",
            vec![("unit", "unit")],
            p4(),
            u(5.0),
            half(),
        ),
        row("atan", "atan(x)", vec![any], u(5.0), u(5.0), half()),
        row(
            "sinh",
            "sinh(x)",
            vec![("exp", "small")],
            p4(),
            fast_derived(),
            half(),
        ),
        row(
            "cosh",
            "cosh(x)",
            vec![("exp", "small")],
            p4(),
            fast_derived(),
            half(),
        ),
        row(
            "tanh",
            "tanh(x)",
            vec![("any", "small")],
            u(5.0),
            fast_derived(),
            half(),
        ),
        row(
            "asinh",
            "asinh(x)",
            vec![("finite", "small")],
            p4(),
            fast_derived(),
            half(),
        ),
        row(
            "acosh",
            "acosh(x)",
            vec![("ge1", "ge1")],
            p4(),
            fast_derived(),
            half(),
        ),
        row(
            "atanh",
            "atanh(x)",
            vec![("unit", "open_unit")],
            u(5.0),
            fast_derived(),
            half(),
        ),
        row(
            "exp",
            "exp(x)",
            vec![("exp", "exp")],
            p4(),
            fast_exp(),
            half(),
        ),
        row(
            "exp2",
            "exp2(x)",
            vec![("exp2", "exp2")],
            p4(),
            fast_exp(),
            half(),
        ),
        row(
            "exp10",
            "exp10(x)",
            vec![("exp10", "exp10")],
            p4(),
            fast_exp(),
            half(),
        ),
        row(
            "log",
            "log(x)",
            vec![("any", "normal_positive")],
            p4(),
            fast_log(),
            half(),
        ),
        row(
            "log2",
            "log2(x)",
            vec![("any", "normal_positive")],
            p4(),
            fast_log(),
            half(),
        ),
        row(
            "log10",
            "log10(x)",
            vec![("any", "normal_positive")],
            p4(),
            fast_log(),
            half(),
        ),
        row(
            "sqrt",
            "sqrt(x)",
            vec![("any", "normal_positive")],
            u(1.0),
            u(3.0),
            u(1.0),
        ),
        row(
            "rsqrt",
            "rsqrt(x)",
            vec![("any", "normal_positive")],
            u(2.0),
            u(3.0),
            u(2.0),
        ),
        row(
            "sinpi",
            "sinpi(x)",
            vec![("wide_angle", "unit")],
            p4(),
            fast_derived(),
            half(),
        ),
        row(
            "cospi",
            "cospi(x)",
            vec![("wide_angle", "unit")],
            p4(),
            fast_derived(),
            half(),
        ),
        row(
            "tanpi",
            "tanpi(x)",
            vec![("small", "open_unit")],
            u(6.0),
            fast_derived(),
            half(),
        ),
        row("ceil", "ceil(x)", vec![any], exact(), exact(), exact()),
        row("floor", "floor(x)", vec![any], exact(), exact(), exact()),
        row("round", "round(x)", vec![any], exact(), exact(), exact()),
        row("rint", "rint(x)", vec![any], exact(), exact(), exact()),
        row("trunc", "trunc(x)", vec![any], exact(), exact(), exact()),
        // Apple's fast fract omits the clamp below 1, so tiny negatives give 1.
        row("fract", "fract(x)", vec![finite], exact(), u(1.0), exact()),
        row("fabs", "fabs(x)", vec![any], exact(), exact(), exact()),
        row("sign", "sign(x)", vec![any], exact(), exact(), exact()),
        row(
            "saturate",
            "saturate(x)",
            vec![finite],
            exact(),
            exact(),
            exact(),
        ),
        row("add", "x + y", vec![any; 2], exact(), exact(), exact()),
        row("sub", "x - y", vec![any; 2], exact(), exact(), exact()),
        row("mul", "x * y", vec![any; 2], exact(), exact(), exact()),
        row(
            "divide",
            "x / y",
            vec![any, ("divisor", "divisor")],
            u(1.0),
            u(3.0),
            u(1.0),
        ),
        row(
            "pow",
            "pow(x, y)",
            vec![("pow_base", "pow_base"), ("pow_exponent", "pow_exponent")],
            u(16.0),
            fast_pow(),
            half_pow(),
        ),
        row(
            "powr",
            "powr(x, y)",
            vec![("pow_base", "pow_base"), ("pow_exponent", "pow_exponent")],
            u(16.0),
            fast_pow(),
            half_pow(),
        ),
        row(
            "atan2",
            "atan2(x, y)",
            vec![finite, ("finite", "divisor")],
            u(6.0),
            u(6.0),
            half(),
        ),
        Row {
            name: "fmod",
            expr: "fmod(x, y)",
            domains: vec![("finite", "small"), ("divisor", "divisor")],
            precise: exact(),
            fast: None,
            half: Tolerance::ulp(1.0).with_abs(2f64.powi(-8)),
        },
        row(
            "fmin",
            "fmin(x, y)",
            vec![any; 2],
            exact(),
            exact(),
            exact(),
        ),
        row(
            "fmax",
            "fmax(x, y)",
            vec![any; 2],
            exact(),
            exact(),
            exact(),
        ),
        row(
            "copysign",
            "copysign(x, y)",
            vec![any; 2],
            exact(),
            exact(),
            exact(),
        ),
        row(
            "fdim",
            "fdim(x, y)",
            vec![finite; 2],
            exact(),
            exact(),
            exact(),
        ),
        row(
            "step",
            "step(x, y)",
            vec![finite; 2],
            exact(),
            exact(),
            exact(),
        ),
        row(
            "fma",
            "fma(x, y, z)",
            vec![("finite", "small"); 3],
            u(1.0),
            u(1.0),
            u(1.0),
        ),
        row(
            "mix",
            "mix(x, y, z)",
            vec![small, small, ("unorm", "unorm")],
            mix(),
            mix(),
            half_mix(),
        ),
        row(
            "clamp",
            "clamp(x, min(y, z), max(y, z))",
            vec![finite; 3],
            exact(),
            exact(),
            exact(),
        ),
        row(
            "smoothstep",
            "smoothstep(min(y, z) - 1, max(y, z) + 1, x)",
            vec![small; 3],
            mix(),
            mix(),
            half_mix(),
        ),
        row(
            "fmax3",
            "fmax3(x, y, z)",
            vec![finite; 3],
            exact(),
            exact(),
            exact(),
        ),
        row(
            "fmin3",
            "fmin3(x, y, z)",
            vec![finite; 3],
            exact(),
            exact(),
            exact(),
        ),
        row(
            "fmedian3",
            "fmedian3(x, y, z)",
            vec![finite; 3],
            exact(),
            exact(),
            exact(),
        ),
        row(
            "ldexp",
            "ldexp(x, to_int(y))",
            vec![finite, small],
            exact(),
            exact(),
            exact(),
        ),
    ]
}

/// The first __METAL_VERSION__ with a function.
fn min_version(name: &str) -> u32 {
    match name {
        "fmax3" | "fmin3" | "fmedian3" | "explicit" => 210,
        "nextafter" => 310,
        _ => 0,
    }
}

fn available(name: &str, version: &str) -> bool {
    metal_version(version) >= min_version(name)
}

const HELPERS: &str = r#"
#include <metal_stdlib>
using namespace metal;
static int to_int(float v) { return int(v); }
static int to_int(half v) { return int(v); }
static int4 to_int(float4 v) { return int4(v); }
#define KERNEL(NAME, T, EXPR) \
kernel void NAME(device const T *a [[buffer(0)]], device const T *b [[buffer(1)]], \
                 device const T *c [[buffer(2)]], device T *r [[buffer(3)]], \
                 uint i [[thread_position_in_grid]]) \
{ T x = a[i], y = b[i], z = c[i]; (void)y; (void)z; r[i] = (EXPR); }
"#;

/// Functions with a second result, predicates and explicit namespaces.
const EXTRA: &str = r#"
#define PAIR(NAME, T, I) \
kernel void NAME##_frexp(device const T *a [[buffer(0)]], device T *r [[buffer(3)]], \
                         device I *e [[buffer(4)]], uint i [[thread_position_in_grid]]) \
{ I k; r[i] = frexp(a[i], k); e[i] = k; } \
kernel void NAME##_modf(device const T *a [[buffer(0)]], device T *r [[buffer(3)]], \
                        device T *w [[buffer(4)]], uint i [[thread_position_in_grid]]) \
{ T k; r[i] = modf(a[i], k); w[i] = k; } \
kernel void NAME##_sincos(device const T *a [[buffer(0)]], device T *r [[buffer(3)]], \
                          device T *w [[buffer(4)]], uint i [[thread_position_in_grid]]) \
{ T k; r[i] = sincos(a[i], k); w[i] = k; } \
kernel void NAME##_predicates(device const T *a [[buffer(0)]], device uint *r [[buffer(3)]], \
                              uint i [[thread_position_in_grid]]) \
{ T x = a[i]; r[i] = uint(isnan(x)) | uint(isinf(x)) << 1 | uint(isfinite(x)) << 2 | \
                     uint(isnormal(x)) << 3 | uint(signbit(x)) << 4; } \
kernel void NAME##_ordering(device const T *a [[buffer(0)]], device const T *b [[buffer(1)]], \
                            device uint *r [[buffer(3)]], uint i [[thread_position_in_grid]]) \
{ r[i] = uint(isordered(a[i], b[i])) | uint(isunordered(a[i], b[i])) << 1; } \
kernel void NAME##_ilogb(device const T *a [[buffer(0)]], device int *r [[buffer(3)]], \
                         uint i [[thread_position_in_grid]]) \
{ r[i] = ilogb(a[i]); } \

PAIR(f32, float, int)
PAIR(f16, half, int)

#if __METAL_VERSION__ >= 310
kernel void f32_nextafter(device const float *a [[buffer(0)]], device const float *b [[buffer(1)]],
                          device float *r [[buffer(3)]], uint i [[thread_position_in_grid]])
{ r[i] = nextafter(a[i], b[i]); }
kernel void f16_nextafter(device const half *a [[buffer(0)]], device const half *b [[buffer(1)]],
                          device half *r [[buffer(3)]], uint i [[thread_position_in_grid]])
{ r[i] = nextafter(a[i], b[i]); }
#endif

#if __METAL_VERSION__ >= 210
kernel void f32_explicit_precise(device const float *a [[buffer(0)]], device float *r [[buffer(3)]],
                                 uint i [[thread_position_in_grid]])
{
    float x = a[i];
    r[i * 4 + 0] = precise::sin(x);
    r[i * 4 + 1] = precise::exp(x * 0.01f);
    r[i * 4 + 2] = precise::sqrt(fabs(x));
    r[i * 4 + 3] = precise::divide(x, 3.0f);
}

kernel void f32_explicit_fast(device const float *a [[buffer(0)]], device float *r [[buffer(3)]],
                              uint i [[thread_position_in_grid]])
{
    float x = a[i];
    r[i * 4 + 0] = fast::sin(x);
    r[i * 4 + 1] = fast::exp(x * 0.01f);
    r[i * 4 + 2] = fast::sqrt(fabs(x));
    r[i * 4 + 3] = fast::divide(x, 3.0f);
}
#endif

// Geometric functions over float2, float3 and float4.
kernel void f32_geometric(device const float4 *a [[buffer(0)]], device const float4 *b [[buffer(1)]],
                          device float4 *r [[buffer(3)]], uint i [[thread_position_in_grid]])
{
    float4 x = a[i], y = b[i];
    r[i * 4 + 0] = float4(dot(x.xy, y.xy), dot(x.xyz, y.xyz), dot(x, y), length(x));
    r[i * 4 + 1] = float4(length(x.xy), length(x.xyz), distance(x, y), distance(x.xy, y.xy));
    r[i * 4 + 2] = normalize(x);
    r[i * 4 + 3] = float4(cross(x.xyz, y.xyz), length_squared(x));
}

kernel void f16_geometric(device const half4 *a [[buffer(0)]], device const half4 *b [[buffer(1)]],
                          device half4 *r [[buffer(3)]], uint i [[thread_position_in_grid]])
{
    half4 x = a[i], y = b[i];
    r[i * 4 + 0] = half4(dot(x.xy, y.xy), dot(x.xyz, y.xyz), dot(x, y), length(x));
    r[i * 4 + 1] = half4(length(x.xy), length(x.xyz), distance(x, y), distance(x.xy, y.xy));
    r[i * 4 + 2] = normalize(x);
    r[i * 4 + 3] = half4(cross(x.xyz, y.xyz), length_squared(x));
}

// Reflection, refraction, facing and squared distance, from unit
// directions where the definitions take them.
#define REFLECTIONS(NAME, T, T4) \
kernel void NAME##_reflections(device const T4 *a [[buffer(0)]], device const T4 *b [[buffer(1)]], \
                               device T4 *r [[buffer(3)]], uint i [[thread_position_in_grid]]) \
{ \
    T4 x = a[i], y = b[i], u = normalize(x), n = normalize(y); \
    r[i * 4 + 0] = reflect(x, n); \
    r[i * 4 + 1] = refract(u, n, T(0.66)); \
    r[i * 4 + 2] = faceforward(x, y, y.wzyx); \
    r[i * 4 + 3] = T4(distance_squared(x, y), distance_squared(x.xy, y.xy), distance_squared(x.xyz, y.xyz), T(0)); \
}
REFLECTIONS(f32, float, float4)
REFLECTIONS(f16, half, half4)

// Matrix arithmetic: products, transpose and determinant.
kernel void f32_matrix(device const float4x4 *a [[buffer(0)]], device const float4x4 *b [[buffer(1)]],
                       device float4x4 *r [[buffer(3)]], uint i [[thread_position_in_grid]])
{
    float4x4 x = a[i], y = b[i];
    float3x3 x3 = float3x3(x[0].xyz, x[1].xyz, x[2].xyz);
    float2x2 x2 = float2x2(x[0].xy, x[1].xy);
    r[i * 4 + 0] = x * y;
    r[i * 4 + 1] = transpose(x);
    r[i * 4 + 2] = float4x4(x * y[0], float4(x3 * y[1].xyz, determinant(x)),
                            float4(determinant(x3), determinant(x2), x2 * y[2].xy), y[3] * x);
    r[i * 4 + 3] = x + y * 2.0f;
}
"#;

fn msl() -> String {
    let mut lines = vec![HELPERS.to_string()];
    for r in table() {
        let guard = min_version(r.name);
        if guard > 0 {
            lines.push(format!("#if __METAL_VERSION__ >= {guard}"));
        }
        lines.push(format!("KERNEL(f32_{}, float, {})", r.name, r.expr));
        lines.push(format!("KERNEL(f16_{}, half, {})", r.name, r.expr));
        lines.push(format!("KERNEL(f32x4_{}, float4, {})", r.name, r.expr));
        if guard > 0 {
            lines.push("#endif".into());
        }
    }
    lines.push(EXTRA.to_string());
    lines.join("\n") + "\n"
}

/// Half trigonometry is accurate only on [-pi, pi].
fn half_domain(domain: &'static str, dtype: Dtype) -> &'static str {
    if dtype == Dtype::F16 && domain == "wide_angle" {
        "angle"
    } else {
        domain
    }
}

fn case_name(mode: &str, dtype: &str, name: &str, version: &str) -> String {
    let suffix = if version == LATEST {
        String::new()
    } else {
        format!("@{version}")
    };
    format!("math.{mode}.{dtype}.{name}{suffix}")
}

fn size(dtype: Dtype) -> usize {
    dtype.size()
}

fn add_table(plan: &mut Plan, library: &str, mode: &str, precise: bool, version: &str) {
    for (index, r) in table().into_iter().enumerate() {
        if !available(r.name, version) {
            continue;
        }
        let fast = r.fast.clone();
        for (dtype, tol) in [
            (
                Dtype::F32,
                if precise {
                    Some(r.precise.clone())
                } else {
                    fast
                },
            ),
            (Dtype::F16, Some(r.half.clone())),
        ] {
            let arity = r.domains.len();
            let seed = (index * 16
                + usize::from(dtype == Dtype::F16) * 4
                + usize::from(precise) * 2) as u64;
            let mut operands: Vec<Vec<f64>> = r
                .domains
                .iter()
                .enumerate()
                .map(|(k, d)| {
                    let domain = half_domain(if precise { d.0 } else { d.1 }, dtype);
                    domain_values(domain, dtype, COUNT, seed + k as u64, precise)
                })
                .collect();
            while operands.len() < 3 {
                operands.push(vec![0.0; COUNT]);
            }
            let largest = if dtype == Dtype::F32 {
                1.0 - 2f64.powi(-24)
            } else {
                1.0 - 2f64.powi(-11)
            };
            let expected: Vec<f64> = (0..COUNT)
                .map(|i| {
                    let args: Vec<f64> = operands[..arity].iter().map(|o| o[i]).collect();
                    let v = if r.name == "fract" {
                        reference::fract(largest, args[0])
                    } else {
                        reference::function(r.name, &args).unwrap()
                    };
                    dtype.round(v)
                })
                .collect();
            let buffers: Vec<Buffer> = (0..3)
                .map(|k| Buffer::data(&format!("in{k}"), k as u32, floats(dtype, &operands[k])))
                .collect();
            let output = match tol {
                Some(tol) => {
                    // The sign of a zero result is asserted only in precise
                    // mode, for the functions IEEE 754 defines it of.
                    let mut t = tol;
                    if matches!(
                        r.name,
                        "copysign" | "fabs" | "mul" | "trunc" | "floor" | "ceil" | "rint"
                    ) {
                        t.signed_zero = Some(precise);
                    }
                    Output::new("result", dtype, t.doubled()).expect(floats(dtype, &expected), t)
                }
                None => {
                    // Fast fmod computes x - y * trunc(x / y) from an
                    // approximate quotient, so near a multiple of y the
                    // result may be either end of its range: r, or r moved
                    // by y towards it.
                    let t = Tolerance::abs(2f64.powi(-10)).with_ulp(4.0);
                    let shifted = |sign: f64| -> Vec<f64> {
                        (0..COUNT)
                            .map(|i| {
                                dtype.round(
                                    expected[i]
                                        + sign * operands[1][i].abs().copysign(operands[0][i]),
                                )
                            })
                            .collect()
                    };
                    Output::new("result", dtype, t.doubled())
                        .expect(floats(dtype, &expected), t)
                        .expect_alternative(floats(dtype, &shifted(-1.0)))
                        .expect_alternative(floats(dtype, &shifted(1.0)))
                }
            };
            let result = Buffer::zeroed("result", 3, COUNT * size(dtype));
            plan.add(
                Case::compute1(
                    &case_name(mode, dtype.name(), r.name, version),
                    library,
                    &format!("{}_{}", dtype.name(), r.name),
                    COUNT as u32,
                )
                .buffers(buffers.clone())
                .buffer(result.clone())
                .output(output.clone()),
            );
            if dtype == Dtype::F32 {
                plan.add(
                    Case::compute1(
                        &case_name(mode, "f32x4", r.name, version),
                        library,
                        &format!("f32x4_{}", r.name),
                        (COUNT / 4) as u32,
                    )
                    .buffers(buffers)
                    .buffer(Buffer::zeroed("result", 3, COUNT * 4))
                    .output(output),
                );
            }
        }
    }
}

fn frexp(v: f64) -> (f64, i32) {
    if v == 0.0 || !v.is_finite() {
        return (v, 0);
    }
    let mut e = 0;
    let m = libm::frexp(v, &mut e);
    (m, e)
}

/// The next value after x towards y, by stepping its encoding.
fn step(x: f64, y: f64, dtype: Dtype) -> f64 {
    let up = (y > x) == (x > 0.0);
    if dtype == Dtype::F32 {
        let i = (x as f32).to_bits();
        f64::from(f32::from_bits(if up {
            i.wrapping_add(1)
        } else {
            i.wrapping_sub(1)
        }))
    } else {
        let i = f16_bits(x);
        f16_from_bits(if up {
            i.wrapping_add(1)
        } else {
            i.wrapping_sub(1)
        })
    }
}

fn add_pairs(plan: &mut Plan, library: &str, mode: &str, precise: bool, version: &str) {
    for dtype in [Dtype::F32, Dtype::F16] {
        let size = size(dtype);
        let name = dtype.name();
        let values = domain_values(
            if precise { "any" } else { "finite" },
            dtype,
            COUNT,
            900 + size as u64,
            true,
        );
        let mut finite: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
        finite.resize(COUNT, 1.0);
        let smallest = if dtype == Dtype::F32 {
            F32_MIN
        } else {
            F16_MIN
        };
        // frexp and ilogb of subnormals depend on whether the device flushes
        // them, which fast math allows; precise keeps them.
        let inputs: Vec<f64> = if precise {
            finite
                .iter()
                .map(|&v| {
                    if v.abs() >= smallest || v == 0.0 {
                        v
                    } else {
                        1.0
                    }
                })
                .collect()
        } else {
            finite.clone()
        };
        let mantissas: Vec<f64> = inputs.iter().map(|&v| frexp(v).0).collect();
        let exponents: Vec<i128> = inputs.iter().map(|&v| i128::from(frexp(v).1)).collect();
        plan.add(
            Case::compute1(
                &case_name(mode, name, "frexp", version),
                library,
                &format!("{name}_frexp"),
                COUNT as u32,
            )
            .buffer(Buffer::data("in0", 0, floats(dtype, &inputs)))
            .buffer(Buffer::zeroed("result", 3, COUNT * size))
            .buffer(Buffer::zeroed("exponent", 4, COUNT * 4))
            .output(
                Output::new("result", dtype, exact()).expect(floats(dtype, &mantissas), exact()),
            )
            .output(
                Output::new("exponent", Dtype::I32, Tolerance::default())
                    .expect_same(ints(Dtype::I32, &exponents)),
            ),
        );
        let mut fractions = vec![];
        let mut wholes = vec![];
        for &v in &finite {
            let mut whole = 0.0;
            fractions.push(dtype.round(libm::modf(v, &mut whole)));
            wholes.push(whole);
        }
        plan.add(
            Case::compute1(
                &case_name(mode, name, "modf", version),
                library,
                &format!("{name}_modf"),
                COUNT as u32,
            )
            .buffer(Buffer::data("in0", 0, floats(dtype, &finite)))
            .buffer(Buffer::zeroed("result", 3, COUNT * size))
            .buffer(Buffer::zeroed("whole", 4, COUNT * size))
            .output(
                Output::new("result", dtype, exact()).expect(floats(dtype, &fractions), exact()),
            )
            .output(Output::new("whole", dtype, exact()).expect(floats(dtype, &wholes), exact())),
        );
        let angles = domain_values(
            half_domain(if precise { "wide_angle" } else { "angle" }, dtype),
            dtype,
            COUNT,
            950 + size as u64,
            true,
        );
        let trig = if dtype == Dtype::F32 {
            if precise { p4() } else { fast_trig() }
        } else {
            half_trig()
        };
        let sines: Vec<f64> = angles.iter().map(|&a| dtype.round(libm::sin(a))).collect();
        let cosines: Vec<f64> = angles.iter().map(|&a| dtype.round(libm::cos(a))).collect();
        plan.add(
            Case::compute1(
                &case_name(mode, name, "sincos", version),
                library,
                &format!("{name}_sincos"),
                COUNT as u32,
            )
            .buffer(Buffer::data("in0", 0, floats(dtype, &angles)))
            .buffer(Buffer::zeroed("result", 3, COUNT * size))
            .buffer(Buffer::zeroed("cosine", 4, COUNT * size))
            .output(
                Output::new("result", dtype, trig.doubled())
                    .expect(floats(dtype, &sines), trig.clone()),
            )
            .output(
                Output::new("cosine", dtype, trig.doubled()).expect(floats(dtype, &cosines), trig),
            ),
        );
        let flags: Vec<u32> = values
            .iter()
            .map(|&v| {
                let normal = v.is_finite() && v.abs() >= smallest;
                u32::from(v.is_nan())
                    | u32::from(v.is_infinite()) << 1
                    | u32::from(v.is_finite()) << 2
                    | u32::from(normal) << 3
                    | u32::from(v.is_sign_negative()) << 4
            })
            .collect();
        let mut predicates = Case::compute1(
            &case_name(mode, name, "predicates", version),
            library,
            &format!("{name}_predicates"),
            COUNT as u32,
        )
        .buffer(Buffer::data("in0", 0, floats(dtype, &values)))
        .buffer(Buffer::zeroed("result", 3, COUNT * 4))
        .output(Output::new("result", Dtype::U32, Tolerance::default()).expect_same(u32s(&flags)));
        if !precise {
            // Fast math lets the compiler assume no NaN or infinity.
            predicates = predicates.informational();
        }
        plan.add(predicates);
        // Ordered when neither operand is NaN, against the values reversed.
        let others: Vec<f64> = values.iter().rev().copied().collect();
        let ordering: Vec<u32> = values
            .iter()
            .zip(&others)
            .map(|(a, b)| {
                let unordered = a.is_nan() || b.is_nan();
                u32::from(!unordered) | u32::from(unordered) << 1
            })
            .collect();
        let mut ordered = Case::compute1(
            &case_name(mode, name, "ordering", version),
            library,
            &format!("{name}_ordering"),
            COUNT as u32,
        )
        .buffer(Buffer::data("in0", 0, floats(dtype, &values)))
        .buffer(Buffer::data("in1", 1, floats(dtype, &others)))
        .buffer(Buffer::zeroed("result", 3, COUNT * 4))
        .output(
            Output::new("result", Dtype::U32, Tolerance::default()).expect_same(u32s(&ordering)),
        );
        if !precise {
            ordered = ordered.informational();
        }
        plan.add(ordered);
        let logb: Vec<i128> = inputs
            .iter()
            .map(|&v| {
                if v != 0.0 {
                    i128::from(frexp(v).1 - 1)
                } else {
                    -(1i128 << 31)
                }
            })
            .collect();
        plan.add(
            Case::compute1(
                &case_name(mode, name, "ilogb", version),
                library,
                &format!("{name}_ilogb"),
                COUNT as u32,
            )
            .buffer(Buffer::data("in0", 0, floats(dtype, &inputs)))
            .buffer(Buffer::zeroed("result", 3, COUNT * 4))
            .output(
                Output::new("result", Dtype::I32, Tolerance::default())
                    .expect_same(ints(Dtype::I32, &logb)),
            ),
        );
        let toward = domain_values("finite", dtype, COUNT, 970 + size as u64, true);
        if !available("nextafter", version) {
            continue;
        }
        let tiny = if dtype == Dtype::F32 {
            2f64.powi(-149)
        } else {
            2f64.powi(-24)
        };
        let nexts: Vec<f64> = inputs
            .iter()
            .zip(&toward)
            .map(|(&x, &y)| {
                if x == y {
                    y
                } else if x == 0.0 {
                    tiny.copysign(y - x)
                } else {
                    step(x, y, dtype)
                }
            })
            .collect();
        plan.add(
            Case::compute1(
                &case_name(mode, name, "nextafter", version),
                library,
                &format!("{name}_nextafter"),
                COUNT as u32,
            )
            .buffer(Buffer::data("in0", 0, floats(dtype, &inputs)))
            .buffer(Buffer::data("in1", 1, floats(dtype, &toward)))
            .buffer(Buffer::zeroed("result", 3, COUNT * size))
            .output(
                Output::new("result", dtype, exact())
                    .expect(floats(dtype, &nexts), exact().with_ftz(false)),
            ),
        );
    }
}

fn dot(p: &[f64], q: &[f64]) -> f64 {
    sum(p.iter().zip(q).map(|(s, t)| s * t))
}

fn length(p: &[f64]) -> f64 {
    libm::sqrt(dot(p, p))
}

type Matrix = [[f64; 4]; 4];

/// Column-major: column c is v[k*16 + c*4 .. +4].
fn matrix(v: &[f64], k: usize) -> Matrix {
    let mut m = [[0.0; 4]; 4];
    for (c, column) in m.iter_mut().enumerate() {
        for (r, value) in column.iter_mut().enumerate() {
            *value = v[k * 16 + c * 4 + r];
        }
    }
    m
}

/// A determinant by cofactor expansion along the first row, with columns
/// as the outer index.
fn det(a: &[Vec<f64>]) -> f64 {
    let n = a.len();
    if n == 1 {
        return a[0][0];
    }
    let mut total = 0.0;
    for c in 0..n {
        let minor: Vec<Vec<f64>> = (0..n)
            .filter(|&cc| cc != c)
            .map(|cc| (1..n).map(|r| a[cc][r]).collect())
            .collect();
        let sign = if c % 2 == 0 { 1.0 } else { -1.0 };
        total += sign * a[c][0] * det(&minor);
    }
    total
}

fn add_vectors(plan: &mut Plan, library: &str, mode: &str, precise: bool, version: &str) {
    let mut rng = Random::new(if precise { 78 } else { 77 });
    let n = 128;
    let a: Vec<f64> = (0..n * 4).map(|_| rng.uniform(-4.0, 4.0)).collect();
    let b: Vec<f64> = (0..n * 4).map(|_| rng.uniform(-4.0, 4.0)).collect();
    for (dtype, tol) in [
        (Dtype::F32, Tolerance::ulp(8.0).with_abs(1e-5)),
        (Dtype::F16, Tolerance::ulp(4.0).with_abs(2f64.powi(-6))),
    ] {
        let x: Vec<f64> = a.iter().map(|&v| dtype.round(v)).collect();
        let y: Vec<f64> = b.iter().map(|&v| dtype.round(v)).collect();
        let mut expected = vec![];
        for i in 0..n {
            let (u, v) = (&x[i * 4..i * 4 + 4], &y[i * 4..i * 4 + 4]);
            let dist = |p: &[f64], q: &[f64]| {
                length(&p.iter().zip(q).map(|(s, t)| s - t).collect::<Vec<_>>())
            };
            expected.extend([
                dot(&u[..2], &v[..2]),
                dot(&u[..3], &v[..3]),
                dot(u, v),
                length(u),
            ]);
            expected.extend([
                length(&u[..2]),
                length(&u[..3]),
                dist(u, v),
                dist(&u[..2], &v[..2]),
            ]);
            expected.extend(u.iter().map(|s| s / length(u)));
            expected.extend([
                u[1] * v[2] - u[2] * v[1],
                u[2] * v[0] - u[0] * v[2],
                u[0] * v[1] - u[1] * v[0],
            ]);
            expected.push(dot(u, u));
        }
        let expected: Vec<f64> = expected.into_iter().map(|e| dtype.round(e)).collect();
        let name = dtype.name();
        plan.add(
            Case::compute(
                &case_name(mode, name, "geometric", version),
                library,
                &format!("{name}_geometric"),
                [n as u32, 1, 1],
                [32, 1, 1],
            )
            .buffer(Buffer::data("in0", 0, floats(dtype, &x)))
            .buffer(Buffer::data("in1", 1, floats(dtype, &y)))
            .buffer(Buffer::zeroed("result", 3, n * 16 * size(dtype)))
            .output(
                Output::new("result", dtype, tol.doubled()).expect(floats(dtype, &expected), tol),
            ),
        );
    }
    for (dtype, tol) in [
        (Dtype::F32, Tolerance::ulp(16.0).with_abs(1e-5)),
        (Dtype::F16, Tolerance::ulp(8.0).with_abs(2f64.powi(-6))),
    ] {
        let x: Vec<f64> = a.iter().map(|&v| dtype.round(v)).collect();
        let y: Vec<f64> = b.iter().map(|&v| dtype.round(v)).collect();
        let mut expected = vec![];
        let mut mask = vec![];
        for i in 0..n {
            let (p, q) = (&x[i * 4..i * 4 + 4], &y[i * 4..i * 4 + 4]);
            let unit = |v: &[f64]| v.iter().map(|s| s / length(v)).collect::<Vec<_>>();
            let (u, m) = (unit(p), unit(q));
            let d = dot(&m, p);
            expected.extend(p.iter().zip(&m).map(|(s, t)| s - 2.0 * d * t));
            let (eta, c) = (dtype.round(0.66), dot(&m, &u));
            let k = 1.0 - eta * eta * (1.0 - c * c);
            if k < 0.0 {
                expected.extend([0.0; 4]);
            } else {
                expected.extend(
                    u.iter()
                        .zip(&m)
                        .map(|(s, t)| eta * s - (eta * c + libm::sqrt(k)) * t),
                );
            }
            let reference = [q[3], q[2], q[1], q[0]];
            let facing = dot(&reference, q);
            expected.extend(p.iter().map(|s| if facing < 0.0 { *s } else { -s }));
            let squared = |len: usize| (0..len).map(|j| (p[j] - q[j]) * (p[j] - q[j])).sum::<f64>();
            expected.extend([squared(4), squared(2), squared(3), 0.0]);
            // Refraction near total internal reflection, and a facing
            // test near zero, may round either way.
            let edge = k.abs() < 1e-2;
            let tie = facing.abs() < 1e-2 * length(&reference) * length(q);
            for uncertain in [false, edge, tie, false] {
                mask.extend([u8::from(!uncertain); 4]);
            }
        }
        let expected: Vec<f64> = expected.into_iter().map(|e| dtype.round(e)).collect();
        let name = dtype.name();
        plan.add(
            Case::compute(
                &case_name(mode, name, "reflections", version),
                library,
                &format!("{name}_reflections"),
                [n as u32, 1, 1],
                [32, 1, 1],
            )
            .buffer(Buffer::data("in0", 0, floats(dtype, &x)))
            .buffer(Buffer::data("in1", 1, floats(dtype, &y)))
            .buffer(Buffer::zeroed("result", 3, n * 16 * size(dtype)))
            .output(
                Output::new("result", dtype, tol.doubled())
                    .expect(floats(dtype, &expected), tol)
                    .mask(mask),
            ),
        );
    }
    let m = 64;
    let xs: Vec<f64> = (0..m * 16).map(|_| f32r(rng.uniform(-2.0, 2.0))).collect();
    let ys: Vec<f64> = (0..m * 16).map(|_| f32r(rng.uniform(-2.0, 2.0))).collect();
    let mut expected = vec![];
    for k in 0..m {
        let (x, y) = (matrix(&xs, k), matrix(&ys, k));
        let mul = |a: &Matrix, b: &Matrix| -> Vec<Vec<f64>> {
            (0..4)
                .map(|c| {
                    (0..4)
                        .map(|r| sum((0..4).map(|i| a[i][r] * b[c][i])))
                        .collect()
                })
                .collect()
        };
        let mv = |a: &[Vec<f64>], v: &[f64], n: usize| -> Vec<f64> {
            (0..n)
                .map(|r| sum((0..n).map(|i| a[i][r] * v[i])))
                .collect()
        };
        let full: Vec<Vec<f64>> = x.iter().map(|c| c.to_vec()).collect();
        let x3: Vec<Vec<f64>> = x[..3].iter().map(|c| c[..3].to_vec()).collect();
        let x2: Vec<Vec<f64>> = x[..2].iter().map(|c| c[..2].to_vec()).collect();
        let product = mul(&x, &y);
        let transpose: Vec<Vec<f64>> = (0..4).map(|c| (0..4).map(|r| x[r][c]).collect()).collect();
        let mut m2 = vec![mv(&full, &y[0], 4)];
        let mut column = mv(&x3, &y[1][..3], 3);
        column.push(det(&full));
        m2.push(column);
        let mut column = vec![det(&x3), det(&x2)];
        column.extend(mv(&x2, &y[2][..2], 2));
        m2.push(column);
        m2.push(
            (0..4)
                .map(|c| sum((0..4).map(|i| y[3][i] * x[c][i])))
                .collect(),
        );
        let scaled: Vec<Vec<f64>> = (0..4)
            .map(|c| (0..4).map(|r| x[c][r] + y[c][r] * 2.0).collect())
            .collect();
        for matrix in [product, transpose, m2, scaled] {
            for column in matrix {
                expected.extend(column);
            }
        }
    }
    let expected: Vec<f64> = expected.into_iter().map(f32r).collect();
    let tol = Tolerance::ulp(16.0).with_abs(1e-5);
    plan.add(
        Case::compute(
            &case_name(mode, "f32", "matrix", version),
            library,
            "f32_matrix",
            [m as u32, 1, 1],
            [32, 1, 1],
        )
        .buffer(Buffer::data("in0", 0, floats(Dtype::F32, &xs)))
        .buffer(Buffer::data("in1", 1, floats(Dtype::F32, &ys)))
        .buffer(Buffer::zeroed("result", 3, m * 4 * 64))
        .output(
            Output::new("result", Dtype::F32, tol.doubled())
                .expect(floats(Dtype::F32, &expected), tol),
        ),
    );
    let values = domain_values("small", Dtype::F32, COUNT, 991, true);
    if !available("explicit", version) {
        return;
    }
    for space in ["precise", "fast"] {
        let tol = if space == "fast" {
            Tolerance::ulp(4.0).with_abs(2f64.powi(-13))
        } else {
            Tolerance::ulp(4.0)
        };
        let mut expected = vec![];
        for &v in &values {
            expected.extend([
                libm::sin(v),
                libm::exp(f32r(v * f32r(0.01))),
                libm::sqrt(v.abs()),
                v / 3.0,
            ]);
        }
        let expected: Vec<f64> = expected.into_iter().map(f32r).collect();
        plan.add(
            Case::compute1(
                &case_name(mode, "f32", &format!("explicit_{space}"), version),
                library,
                &format!("f32_explicit_{space}"),
                COUNT as u32,
            )
            .buffer(Buffer::data("in0", 0, floats(Dtype::F32, &values)))
            .buffer(Buffer::zeroed("result", 3, COUNT * 16))
            .output(
                Output::new("result", Dtype::F32, tol.doubled())
                    .expect(floats(Dtype::F32, &expected), tol),
            ),
        );
    }
}

fn add_all(plan: &mut Plan, library: &str, mode: &str, precise: bool, version: &str) {
    add_table(plan, library, mode, precise, version);
    add_pairs(plan, library, mode, precise, version);
    add_vectors(plan, library, mode, precise, version);
}

/// fp32 subnormals through arithmetic, compared without the suite's usual
/// flush: a product that underflows to one, a quotient of values near
/// FLT_MIN, a fused multiply-add of a subnormal product and addend, and a
/// subnormal product scaled back to the normal range. An M1 Pro flushes
/// each subnormal input and result to zero in both modes, whose libraries
/// both set air.compile.denorms_disable; fast math folds the two scales
/// into one and divides within 2.5 ulps.
fn add_denormals(plan: &mut Plan) {
    let source = plan.generated(
        "denormals.metal",
        "#include <metal_stdlib>\nusing namespace metal;\n\
         kernel void denormals(device const float *in0 [[buffer(0)]], device float4 *result \
         [[buffer(3)]], uint i [[thread_position_in_grid]])\n{\n    float x = in0[i];\n    \
         float tiny = x * 0x1p-140f;\n    result[i] = float4(tiny, x / 3.0f, \
         fma(x, 0x1p-140f, 0x1p-149f), tiny * 0x1p20f);\n}\n"
            .into(),
    );
    let mut rng = Random::new(1407);
    let inputs: Vec<f64> = (0..COUNT)
        .map(|i| {
            let m = rng.uniform(1.0, 2.0);
            f32r(if i % 2 == 0 {
                m * 2f64.powi(rng.below(20) as i32 - 10)
            } else {
                m * F32_MIN
            })
        })
        .collect();
    let flush = |v: f64| if v.abs() < F32_MIN { 0.0 } else { v };
    for (mode, flags, fast) in [
        ("fast", &[][..], true),
        ("precise", &["-fno-fast-math"][..], false),
    ] {
        let expected: Vec<f64> = inputs
            .iter()
            .flat_map(|&x| {
                let tiny = flush(f32r(x * 2f64.powi(-140)));
                let scaled = if fast {
                    flush(f32r(x * 2f64.powi(-120)))
                } else {
                    tiny
                };
                [tiny, flush(f32r(x / 3.0)), tiny, scaled]
            })
            .collect();
        let library = plan.library(&format!("denormals_{mode}"), &source, flags, LATEST);
        let tol = if fast { u(2.5) } else { exact() }.with_ftz(false);
        plan.add(
            Case::compute1(
                &format!("math.denormals.{mode}"),
                &library,
                "denormals",
                COUNT as u32,
            )
            .buffer(Buffer::data("in0", 0, floats(Dtype::F32, &inputs)))
            .buffer(Buffer::zeroed("result", 3, COUNT * 16))
            .output(
                Output::new("result", Dtype::F32, tol.clone())
                    .expect(floats(Dtype::F32, &expected), tol),
            ),
        );
    }
}

/// Every case at every MSL version, fast and precise, each from its own
/// library. A mode is held to the specification's precise bounds only when
/// both its arithmetic and its functions are precise; any other is held to
/// the fast bounds, which precise results also meet.
pub fn build(plan: &mut Plan) {
    add_denormals(plan);
    let source = plan.generated("math.metal", msl());
    for (version, ..) in VERSIONS {
        for (mode, precise, flags) in [
            ("fast", false, &[][..]),
            ("precise", true, &["-fno-fast-math"][..]),
        ] {
            let library = plan.library(&format!("math_{mode}_{version}"), &source, flags, version);
            add_all(plan, &library, mode, precise, version);
        }
    }
    // MSL 3.2's finer modes, at the latest version: relaxed arithmetic,
    // which keeps infinities and NaNs; safe arithmetic with the default
    // fast functions; fast arithmetic with precise functions.
    for (mode, flag) in [
        ("relaxed", "-fmetal-math-mode=relaxed"),
        ("safe", "-fmetal-math-mode=safe"),
        ("precise_functions", "-fmetal-math-fp32-functions=precise"),
    ] {
        let library = plan.library(&format!("math_{mode}"), &source, &[flag], LATEST);
        add_all(plan, &library, mode, false, LATEST);
    }
    // The modes an application asks for at run time, through
    // MTLCompileOptions' math mode and floating-point functions.
    for (mode, precise, options) in [
        (
            "runtime_safe",
            true,
            json!({"math_mode": "safe", "math_functions": "precise"}),
        ),
        ("runtime_relaxed", false, json!({"math_mode": "relaxed"})),
        ("runtime_fast", false, json!({"math_mode": "fast"})),
        (
            "runtime_precise_functions",
            false,
            json!({"math_mode": "fast", "math_functions": "precise"}),
        ),
    ] {
        let library = plan.runtime_library(&format!("math_{mode}"), &source, options);
        add_all(plan, &library, mode, precise, LATEST);
    }
}
