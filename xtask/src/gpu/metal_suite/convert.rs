//! Conversions between MSL's scalar types, bit reinterpretation with
//! as_type, and the pack and unpack functions, at every MSL version that
//! compiles them, asserted exactly. A float to integer conversion of a
//! value out of the integer's range, or of NaN, is undefined, so no case
//! converts one.
use super::plan::{Buffer, Case, Output, Plan, Tolerance, VERSIONS, suffix};
use super::values::{
    Dtype, Random, bits32, domain_values, f16_from_bits, f16r, f32r, floats, from_bits32, ints,
    libm, u32s,
};
use std::collections::BTreeSet;

const COUNT: usize = 512;

const INTS: [(&str, Dtype, u32, bool); 8] = [
    ("char", Dtype::I8, 8, true),
    ("uchar", Dtype::U8, 8, false),
    ("short", Dtype::I16, 16, true),
    ("ushort", Dtype::U16, 16, false),
    ("int", Dtype::I32, 32, true),
    ("uint", Dtype::U32, 32, false),
    ("long", Dtype::I64, 64, true),
    ("ulong", Dtype::U64, 64, false),
];
const FLOATS: [(&str, Dtype); 2] = [("float", Dtype::F32), ("half", Dtype::F16)];

fn kernel(name: &str, src: &str, dst: &str, expr: &str) -> String {
    format!(
        "#ifndef SKIP_{name}\nkernel void {name}(device const {src} *a [[buffer(0)]], device {dst} *r [[buffer(3)]], \
         uint i [[thread_position_in_grid]]) {{ {src} x = a[i]; r[i] = {expr}; }}\n#endif"
    )
}

/// x rounded to bfloat, ties to even, as a float.
pub(super) fn bfloat(x: f64) -> f64 {
    let v = f32r(x);
    if v.is_nan() {
        return x;
    }
    let bits = bits32(v);
    from_bits32(bits.wrapping_add(0x7FFF + ((bits >> 16) & 1)) & 0xFFFF_0000)
}

pub(super) fn srgb_encode(c: f64) -> f64 {
    let c = c.clamp(0.0, 1.0);
    if c <= 0.0031308 {
        c * 12.92
    } else {
        1.055 * libm::pow(c, 1.0 / 2.4) - 0.055
    }
}

fn srgb_decode(c: f64) -> f64 {
    if c <= 0.04045 {
        c / 12.92
    } else {
        libm::pow((c + 0.055) / 1.055, 2.4)
    }
}

type Encode = Option<fn(f64) -> f64>;

/// name, MSL, lanes, bits per lane, lane encoding (sRGB when None).
const PACKERS: [(&str, &str, usize, u32, Encode); 5] = [
    (
        "unorm4x8",
        "pack_float_to_unorm4x8",
        4,
        8,
        Some(|v| (v.clamp(0.0, 1.0) * 255.0).round_ties_even()),
    ),
    (
        "snorm4x8",
        "pack_float_to_snorm4x8",
        4,
        8,
        Some(|v| (v.clamp(-1.0, 1.0) * 127.0).round_ties_even()),
    ),
    (
        "unorm2x16",
        "pack_float_to_unorm2x16",
        2,
        16,
        Some(|v| (v.clamp(0.0, 1.0) * 65535.0).round_ties_even()),
    ),
    (
        "snorm2x16",
        "pack_float_to_snorm2x16",
        2,
        16,
        Some(|v| (v.clamp(-1.0, 1.0) * 32767.0).round_ties_even()),
    ),
    ("srgb_unorm4x8", "pack_float_to_srgb_unorm4x8", 4, 8, None),
];

type Decode = Option<fn(f64, u32) -> f64>;

/// name, MSL, lane widths, lane decoding (sRGB when None), signed lanes.
const UNPACKERS: [(&str, &str, &[u32], Decode, bool); 7] = [
    (
        "unorm4x8",
        "unpack_unorm4x8_to_float",
        &[8, 8, 8, 8],
        Some(|q, _| q / 255.0),
        false,
    ),
    (
        "snorm4x8",
        "unpack_snorm4x8_to_float",
        &[8, 8, 8, 8],
        Some(|q, _| (q / 127.0).max(-1.0)),
        true,
    ),
    (
        "unorm2x16",
        "unpack_unorm2x16_to_float",
        &[16, 16],
        Some(|q, _| q / 65535.0),
        false,
    ),
    (
        "snorm2x16",
        "unpack_snorm2x16_to_float",
        &[16, 16],
        Some(|q, _| (q / 32767.0).max(-1.0)),
        true,
    ),
    (
        "srgb_unorm4x8",
        "unpack_unorm4x8_srgb_to_float",
        &[8, 8, 8, 8],
        None,
        false,
    ),
    (
        "unorm10a2",
        "unpack_unorm10a2_to_float",
        &[10, 10, 10, 2],
        Some(|q, b| q / f64::from((1u32 << b) - 1)),
        false,
    ),
    (
        "unorm565",
        "unpack_unorm565_to_float",
        &[5, 6, 5],
        Some(|q, b| q / f64::from((1u32 << b) - 1)),
        false,
    ),
];

fn msl() -> String {
    let mut lines = vec![
        "#include <metal_stdlib>".to_string(),
        "using namespace metal;".to_string(),
    ];
    for (fname, _) in FLOATS {
        for (iname, ..) in INTS {
            lines.push(kernel(
                &format!("{fname}_to_{iname}"),
                fname,
                iname,
                &format!("{iname}(x)"),
            ));
            lines.push(kernel(
                &format!("{iname}_to_{fname}"),
                iname,
                fname,
                &format!("{fname}(x)"),
            ));
        }
        lines.push(kernel(
            &format!("{fname}_to_bool"),
            fname,
            "uint",
            "uint(bool(x))",
        ));
    }
    for (name, src, dst, expr) in [
        ("float_to_half", "float", "half", "half(x)"),
        ("half_to_float", "half", "float", "float(x)"),
        (
            "float_to_bfloat",
            "float",
            "ushort",
            "as_type<ushort>(bfloat(x))",
        ),
        (
            "bfloat_to_float",
            "ushort",
            "float",
            "float(as_type<bfloat>(x))",
        ),
        ("float4_to_int4", "float4", "int4", "int4(x)"),
        ("int4_to_float4", "int4", "float4", "float4(x)"),
        ("float4_to_half4", "float4", "half4", "half4(x)"),
        ("half4_to_float4", "half4", "float4", "float4(x)"),
        ("as_float_uint", "float", "uint", "as_type<uint>(x)"),
        ("as_uint_float", "uint", "float", "as_type<float>(x)"),
        ("as_uint_half2", "uint", "half2", "as_type<half2>(x)"),
        ("as_uint_uchar4", "uint", "uchar4", "as_type<uchar4>(x)"),
        ("as_ushort2_uint", "ushort2", "uint", "as_type<uint>(x)"),
        ("as_float2_ulong", "float2", "ulong", "as_type<ulong>(x)"),
    ] {
        lines.push(kernel(name, src, dst, expr));
    }
    for (name, function, lanes, ..) in PACKERS {
        let t = if lanes == 4 { "float4" } else { "float2" };
        lines.push(kernel(
            &format!("pack_{name}"),
            t,
            "uint",
            &format!("{function}({t}(x))"),
        ));
    }
    for (name, function, widths, ..) in UNPACKERS {
        let src = if widths.iter().sum::<u32>() == 16 {
            "ushort"
        } else {
            "uint"
        };
        let expr = format!("float4({function}(x){})", ", 0.0f".repeat(4 - widths.len()));
        lines.push(kernel(&format!("unpack_{name}"), src, "float4", &expr));
    }
    lines.join("\n") + "\n"
}

fn float_inputs(
    dtype: Dtype,
    rng: &mut Random,
    limit: f64,
    count: usize,
    edges: &[f64],
) -> Vec<f64> {
    (0..count)
        .map(|i| {
            dtype.round(if i < edges.len() {
                edges[i]
            } else {
                rng.uniform(-limit, limit)
            })
        })
        .collect()
}

fn int_range(bits: u32, signed: bool) -> (i128, i128) {
    if signed {
        (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
    } else {
        (0, (1i128 << bits) - 1)
    }
}

/// A conversion's input and expectation bytes.
enum Values<'a> {
    Floats(Dtype, &'a [f64]),
    Ints(Dtype, &'a [i128]),
}

impl Values<'_> {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Values::Floats(d, v) => floats(*d, v),
            Values::Ints(d, v) => ints(*d, v),
        }
    }

    fn len(&self) -> usize {
        match self {
            Values::Floats(_, v) => v.len(),
            Values::Ints(_, v) => v.len(),
        }
    }
}

struct Family<'a> {
    library: &'a str,
    skipped: &'a BTreeSet<String>,
    suffix: String,
}

impl Family<'_> {
    /// A conversion of the inputs (`lanes` to a thread) with its expected
    /// values, or none when only the reference comparison applies.
    #[allow(clippy::too_many_arguments)]
    fn add(
        &self,
        plan: &mut Plan,
        name: &str,
        function: &str,
        input: Values,
        dst: Dtype,
        expected: Option<Vec<u8>>,
        tolerance: Tolerance,
        lanes: usize,
    ) -> Option<Case> {
        if self.skipped.contains(function) {
            return None;
        }
        let mut output = Output::new("result", dst, tolerance.clone());
        if let Some(expected) = expected {
            output = output.expect(expected, tolerance);
        }
        let _ = plan;
        Some(
            Case::compute1(
                &format!("convert.{name}{}", self.suffix),
                self.library,
                function,
                (input.len() / lanes) as u32,
            )
            .buffer(Buffer::data("in0", 0, input.bytes()))
            .buffer(Buffer::zeroed("result", 3, input.len() * dst.size()))
            .output(output),
        )
    }
}

fn exact() -> Tolerance {
    Tolerance::default()
}

fn no_ftz() -> Tolerance {
    Tolerance::default().with_ftz(false)
}

pub fn build(plan: &mut Plan) {
    let source = plan.generated("convert.metal", msl());
    for (version, ..) in VERSIONS {
        let library = plan.library(&format!("convert_{version}"), &source, &[], version);
        let skipped = plan.unavailable(&source, version);
        let family = Family {
            library: &library,
            skipped: &skipped,
            suffix: suffix(version),
        };
        let mut cases = vec![];
        let mut rng = Random::new(7000);
        for (fname, fdtype) in FLOATS {
            for (iname, idtype, bits, signed) in INTS {
                let (lo, hi) = int_range(bits, signed);
                let half = fdtype == Dtype::F16;
                let top = hi.min(if half { 60000 } else { 1 << 62 });
                let bottom = lo.max(if half { -60000 } else { -(1i128 << 62) });
                let (topf, bottomf) = (top as f64, bottom as f64);
                let edges = [
                    0.0,
                    -0.0,
                    0.5,
                    -0.5,
                    0.99,
                    -0.99,
                    1.0,
                    1.5,
                    2.5,
                    -2.5,
                    topf,
                    bottomf,
                    if top < 1 << 20 {
                        topf - 0.5
                    } else {
                        topf / 2.0
                    },
                ];
                let xs = float_inputs(fdtype, &mut rng, topf.min(1e6), COUNT, &edges);
                let xs: Vec<f64> = xs
                    .into_iter()
                    .map(|v| {
                        let t = v.trunc() as i128;
                        if bottom <= t && t <= top { v } else { 0.0 }
                    })
                    .collect();
                let truncated: Vec<i128> = xs.iter().map(|v| v.trunc() as i128).collect();
                cases.push(family.add(
                    plan,
                    &format!("{fname}_to_{iname}"),
                    &format!("{fname}_to_{iname}"),
                    Values::Floats(fdtype, &xs),
                    idtype,
                    Some(ints(idtype, &truncated)),
                    exact(),
                    1,
                ));
                let mut values = vec![lo, hi, 0, 1, if signed { -1 } else { 2 }, lo + 1, hi - 1];
                while values.len() < COUNT {
                    values.push((u128::from(rng.u64()) % (hi - lo + 1) as u128) as i128 + lo);
                }
                let converted: Vec<f64> = values.iter().map(|&v| fdtype.round(v as f64)).collect();
                cases.push(family.add(
                    plan,
                    &format!("{iname}_to_{fname}"),
                    &format!("{iname}_to_{fname}"),
                    Values::Ints(idtype, &values),
                    fdtype,
                    Some(floats(fdtype, &converted)),
                    no_ftz(),
                    1,
                ));
            }
            let specials = domain_values("any", fdtype, COUNT, 7100, true);
            let truth: Vec<u32> = specials.iter().map(|&v| u32::from(v != 0.0)).collect();
            cases.push(family.add(
                plan,
                &format!("{fname}_to_bool"),
                &format!("{fname}_to_bool"),
                Values::Floats(fdtype, &specials),
                Dtype::U32,
                Some(u32s(&truth)),
                exact(),
                1,
            ));
        }
        let mut wide = domain_values("any", Dtype::F32, COUNT, 7200, true);
        for k in 0..20 {
            wide[40 + k] = f32r(65504.0 + k as f64 * 4.0);
            wide[60 + k] = f32r(2f64.powi(-24) * (k as f64 + 0.5));
        }
        let halved: Vec<f64> = wide.iter().map(|&v| f16r(v)).collect();
        cases.push(family.add(
            plan,
            "float_to_half",
            "float_to_half",
            Values::Floats(Dtype::F32, &wide),
            Dtype::F16,
            Some(floats(Dtype::F16, &halved)),
            no_ftz(),
            1,
        ));
        // Every 64th encoding and the subnormals, NaN payloads included.
        let mut half_bits: Vec<i128> = (0..65536i128).step_by(64).collect();
        half_bits.extend(0..1024);
        half_bits.truncate(2048);
        let halves: Vec<f64> = half_bits.iter().map(|&b| f16_from_bits(b as u16)).collect();
        cases.push(family.add(
            plan,
            "half_to_float",
            "half_to_float",
            Values::Ints(Dtype::U16, &half_bits),
            Dtype::F32,
            Some(floats(Dtype::F32, &halves)),
            no_ftz(),
            1,
        ));
        let bf_in: Vec<f64> = wide.iter().copied().filter(|v| !v.is_nan()).collect();
        let bf_out: Vec<i128> = bf_in
            .iter()
            .map(|&v| i128::from(bits32(bfloat(v)) >> 16))
            .collect();
        cases.push(family.add(
            plan,
            "float_to_bfloat",
            "float_to_bfloat",
            Values::Floats(Dtype::F32, &bf_in),
            Dtype::U16,
            Some(ints(Dtype::U16, &bf_out)),
            exact(),
            1,
        ));
        let bf_bits: Vec<i128> = (0..65536i128).step_by(97).take(COUNT).collect();
        // A bfloat widens exactly: its bits are the float's upper half.
        let bf_values: Vec<u32> = bf_bits.iter().map(|&b| (b as u32) << 16).collect();
        cases.push(family.add(
            plan,
            "bfloat_to_float",
            "bfloat_to_float",
            Values::Ints(Dtype::U16, &bf_bits),
            Dtype::F32,
            Some(super::values::u32s(&bf_values)),
            no_ftz(),
            1,
        ));
        let vec = float_inputs(Dtype::F32, &mut rng, 1000.0, COUNT, &[0.5, -0.5, 1.5, -1.5]);
        let vec_trunc: Vec<i128> = vec.iter().map(|v| v.trunc() as i128).collect();
        cases.push(family.add(
            plan,
            "float4_to_int4",
            "float4_to_int4",
            Values::Floats(Dtype::F32, &vec),
            Dtype::I32,
            Some(ints(Dtype::I32, &vec_trunc)),
            exact(),
            4,
        ));
        let ivec: Vec<i128> = (0..COUNT)
            .map(|_| i128::from(rng.u64() % 2_000_001) - 1_000_000)
            .collect();
        let ivec_f: Vec<f64> = ivec.iter().map(|&v| f32r(v as f64)).collect();
        cases.push(family.add(
            plan,
            "int4_to_float4",
            "int4_to_float4",
            Values::Ints(Dtype::I32, &ivec),
            Dtype::F32,
            Some(floats(Dtype::F32, &ivec_f)),
            exact(),
            4,
        ));
        cases.push(family.add(
            plan,
            "float4_to_half4",
            "float4_to_half4",
            Values::Floats(Dtype::F32, &wide),
            Dtype::F16,
            Some(floats(Dtype::F16, &halved)),
            no_ftz(),
            4,
        ));
        cases.push(family.add(
            plan,
            "half4_to_float4",
            "half4_to_float4",
            Values::Ints(Dtype::U16, &half_bits),
            Dtype::F32,
            Some(floats(Dtype::F32, &halves)),
            no_ftz(),
            4,
        ));
        let words: Vec<i128> = (0..COUNT).map(|_| i128::from(rng.u32())).collect();
        for (name, function) in [
            ("as_type.float_uint", "as_float_uint"),
            ("as_type.uint_float", "as_uint_float"),
            ("as_type.uint_half2", "as_uint_half2"),
            ("as_type.uint_uchar4", "as_uint_uchar4"),
            ("as_type.ushort2_uint", "as_ushort2_uint"),
        ] {
            cases.push(family.add(
                plan,
                name,
                function,
                Values::Ints(Dtype::U32, &words),
                Dtype::U32,
                Some(ints(Dtype::U32, &words)),
                exact(),
                1,
            ));
        }
        let longs: Vec<i128> = (0..COUNT).map(|_| i128::from(rng.u64())).collect();
        // Reinterpretation keeps every bit: the expectation is the input.
        cases.push(family.add(
            plan,
            "as_type.float2_ulong",
            "as_float2_ulong",
            Values::Ints(Dtype::U64, &longs),
            Dtype::U64,
            Some(ints(Dtype::U64, &longs)),
            exact(),
            1,
        ));
        for (name, _, lanes, width, encode) in PACKERS {
            let mut values: Vec<f64> = vec![
                0.0,
                1.0,
                -1.0,
                0.5,
                2.0,
                -2.0,
                1.0 / 255.0,
                0.5 / 255.0,
                1.5 / 255.0,
                2.5 / 255.0,
            ];
            values.extend((0..COUNT - 10).map(|_| rng.uniform(-1.2, 1.2)));
            let values: Vec<f64> = values.into_iter().map(f32r).collect();
            let expected: Vec<u32> = values
                .chunks(lanes)
                .map(|lane_values| {
                    let mut word = 0u32;
                    for (lane, &v) in lane_values.iter().enumerate() {
                        let q = match encode {
                            Some(f) => f(v),
                            None if lane < 3 => (srgb_encode(v) * 255.0).round_ties_even(),
                            None => (v.clamp(0.0, 1.0) * 255.0).round_ties_even(),
                        } as i64;
                        word |= ((q & ((1 << width) - 1)) as u32) << (lane as u32 * width);
                    }
                    word
                })
                .collect();
            if skipped.contains(&format!("pack_{name}")) {
                continue;
            }
            // Each lane compares within one step of its quantization.
            let lane_type = if width == 8 { Dtype::U8 } else { Dtype::U16 };
            let t = Tolerance::units(1.0);
            cases.push(Some(
                Case::compute1(
                    &format!("convert.pack.{name}{}", suffix(version)),
                    &library,
                    &format!("pack_{name}"),
                    (values.len() / lanes) as u32,
                )
                .buffer(Buffer::data("in0", 0, floats(Dtype::F32, &values)))
                .buffer(Buffer::zeroed(
                    "result",
                    3,
                    values.len() * width as usize / 8,
                ))
                .output(Output::new("result", lane_type, t.clone()).expect(u32s(&expected), t)),
            ));
        }
        for (name, _, widths, decode, signed) in UNPACKERS {
            let total: u32 = widths.iter().sum();
            let mut words: Vec<u32> = vec![0, ((1u64 << total) - 1) as u32];
            words.extend((0..COUNT - 2).map(|_| rng.u32() & ((1u64 << total) - 1) as u32));
            let mut expected = vec![];
            for &w in &words {
                let mut at = 0;
                for (lane, &b) in widths.iter().enumerate() {
                    let mut q = i64::from((w >> at) & ((1u32 << b) - 1));
                    at += b;
                    if signed && q >> (b - 1) != 0 {
                        q -= 1 << b;
                    }
                    let q = q as f64;
                    expected.push(f32r(match decode {
                        Some(f) => f(q, b),
                        None if lane < 3 => srgb_decode(q / 255.0),
                        None => q / 255.0,
                    }));
                }
                expected.extend(std::iter::repeat_n(0.0, 4 - widths.len()));
            }
            if skipped.contains(&format!("unpack_{name}")) {
                continue;
            }
            let src = if total == 16 { Dtype::U16 } else { Dtype::U32 };
            let input: Vec<i128> = words.iter().map(|&w| i128::from(w)).collect();
            // Apple's sRGB decode is within 1.2e-4 of the exact curve.
            let t = if decode.is_some() {
                Tolerance::ulp(2.0)
            } else {
                Tolerance::ulp(8.0).with_abs(2.5e-4)
            };
            cases.push(Some(
                Case::compute1(
                    &format!("convert.unpack.{name}{}", suffix(version)),
                    &library,
                    &format!("unpack_{name}"),
                    COUNT as u32,
                )
                .buffer(Buffer::data("in0", 0, ints(src, &input)))
                .buffer(Buffer::zeroed("result", 3, COUNT * 16))
                .output(
                    Output::new("result", Dtype::F32, t.clone())
                        .expect(floats(Dtype::F32, &expected), t),
                ),
            ));
        }
        for case in cases.into_iter().flatten() {
            plan.add(case);
        }
    }
}
