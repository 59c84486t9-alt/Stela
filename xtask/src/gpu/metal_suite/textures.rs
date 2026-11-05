//! corpus/textures.metal: texel reads of every pixel format the runner
//! uploads, over every texture type, and sampling, gathering, compare
//! sampling, writes, read-write access, texture atomics and queries.
//! Reads and writes are asserted against a decoder of each format, and
//! every sampling form against a reference sampler of Metal's address
//! modes, filters and mip selection. Filtering is asserted to the
//! precision GPUs filter at (eight fractional weight bits), and levels of
//! detail lie half a step above a 1/64 lattice, the coarsest resolution a
//! device uses, so the reference holds whether it truncates or rounds.
use super::plan::{Buffer, Case, Output, Plan, Texture, Tolerance};
use super::values::{Dtype, Random, f16_from_bits, f16r, f32r, f32s, floats, ints, libm, u32s};
use serde_json::{Value, json};

const SOURCE: &str = "textures.metal";

/// 8-bit filter weights resolve to a 256th of the texel difference.
fn filter() -> Tolerance {
    Tolerance::ulp(2.0).with_abs(1.0 / 128.0)
}

pub(super) type Texel = [f64; 4];

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Float,
    Uint,
    Int,
}

pub(super) struct Format {
    name: &'static str,
    size: usize,
    kind: Kind,
    decode: fn(&[u8]) -> Texel,
}

fn unorm(q: u64, bits: u32) -> f64 {
    q as f64 / ((1u64 << bits) - 1) as f64
}

fn signed(q: u64, bits: u32) -> i64 {
    if q >> (bits - 1) & 1 == 1 {
        q as i64 - (1i64 << bits)
    } else {
        q as i64
    }
}

fn snorm(q: u64, bits: u32) -> f64 {
    (signed(q, bits) as f64 / ((1u64 << (bits - 1)) - 1) as f64).max(-1.0)
}

pub fn srgb(c: f64) -> f64 {
    if c <= 0.04045 {
        c / 12.92
    } else {
        libm::pow((c + 0.055) / 1.055, 2.4)
    }
}

/// The unsigned float of rg11b10 and its 10-bit lane: 5 exponent bits.
fn small_float(q: u64, mantissa: u32) -> f64 {
    let (e, m) = (q >> mantissa, q & ((1 << mantissa) - 1));
    let fraction = m as f64 / f64::from(1u32 << mantissa);
    match e {
        0 => fraction * 2f64.powi(-14),
        31 if m == 0 => f64::INFINITY,
        31 => f64::NAN,
        _ => (1.0 + fraction) * 2f64.powi(e as i32 - 15),
    }
}

fn fields(word: u64, widths: &[u32]) -> Vec<u64> {
    let mut at = 0;
    widths
        .iter()
        .map(|&w| {
            let v = (word >> at) & ((1 << w) - 1);
            at += w;
            v
        })
        .collect()
}

fn word(b: &[u8]) -> u64 {
    u64::from(u32::from_le_bytes(b[..4].try_into().unwrap()))
}

fn short(b: &[u8], i: usize) -> u64 {
    u64::from(u16::from_le_bytes([b[2 * i], b[2 * i + 1]]))
}

/// A texel's lanes, the missing ones read as (0, 0, 0, 1).
fn lanes(values: &[f64]) -> Texel {
    let mut t = [0.0, 0.0, 0.0, 1.0];
    t[..values.len()].copy_from_slice(values);
    t
}

/// A 16-bit packed format, its lanes listed from the least significant
/// bits, mapped to RGBA by `order`.
fn packed16(b: &[u8], widths: &[u32], order: &str) -> Texel {
    let q = fields(short(b, 0), widths);
    let mut t = [0.0, 0.0, 0.0, 1.0];
    for (i, c) in order.chars().enumerate() {
        t["rgba".find(c).unwrap()] = unorm(q[i], widths[i]);
    }
    t
}

macro_rules! entry {
    ($name:literal, $size:expr, $kind:ident, $decode:expr) => {
        Format {
            name: $name,
            size: $size,
            kind: Kind::$kind,
            decode: $decode,
        }
    };
}

fn formats() -> Vec<Format> {
    vec![
        entry!("r8unorm", 1, Float, |b| lanes(&[unorm(b[0].into(), 8)])),
        entry!("rg8unorm", 2, Float, |b| lanes(&[
            unorm(b[0].into(), 8),
            unorm(b[1].into(), 8)
        ])),
        entry!("rgba8unorm", 4, Float, |b| [0, 1, 2, 3]
            .map(|i| unorm(b[i].into(), 8))),
        entry!("rgba8unorm_srgb", 4, Float, |b| {
            [
                srgb(b[0] as f64 / 255.0),
                srgb(b[1] as f64 / 255.0),
                srgb(b[2] as f64 / 255.0),
                b[3] as f64 / 255.0,
            ]
        }),
        entry!("bgra8unorm", 4, Float, |b| [b[2], b[1], b[0], b[3]]
            .map(|v| v as f64 / 255.0)),
        entry!("bgra8unorm_srgb", 4, Float, |b| {
            [
                srgb(b[2] as f64 / 255.0),
                srgb(b[1] as f64 / 255.0),
                srgb(b[0] as f64 / 255.0),
                b[3] as f64 / 255.0,
            ]
        }),
        entry!("r8snorm", 1, Float, |b| lanes(&[snorm(b[0].into(), 8)])),
        entry!("rgba8snorm", 4, Float, |b| [0, 1, 2, 3]
            .map(|i| snorm(b[i].into(), 8))),
        entry!("r16unorm", 2, Float, |b| lanes(&[unorm(short(b, 0), 16)])),
        entry!("rg16unorm", 4, Float, |b| lanes(&[
            unorm(short(b, 0), 16),
            unorm(short(b, 1), 16)
        ])),
        entry!("rgba16unorm", 8, Float, |b| [0, 1, 2, 3]
            .map(|i| unorm(short(b, i), 16))),
        entry!("r16snorm", 2, Float, |b| lanes(&[snorm(short(b, 0), 16)])),
        entry!("rgba16snorm", 8, Float, |b| [0, 1, 2, 3]
            .map(|i| snorm(short(b, i), 16))),
        entry!("r16float", 2, Float, |b| lanes(&[f16_from_bits(
            short(b, 0) as u16
        )])),
        entry!("rg16float", 4, Float, |b| {
            lanes(&[
                f16_from_bits(short(b, 0) as u16),
                f16_from_bits(short(b, 1) as u16),
            ])
        }),
        entry!("rgba16float", 8, Float, |b| [0, 1, 2, 3]
            .map(|i| f16_from_bits(short(b, i) as u16))),
        entry!("r32float", 4, Float, |b| lanes(&[f32_at(b, 0)])),
        entry!("rg32float", 8, Float, |b| lanes(&[
            f32_at(b, 0),
            f32_at(b, 1)
        ])),
        entry!("rgba32float", 16, Float, |b| [0, 1, 2, 3]
            .map(|i| f32_at(b, i))),
        entry!("rgb10a2unorm", 4, Float, |b| {
            let q = fields(word(b), &[10, 10, 10, 2]);
            [
                unorm(q[0], 10),
                unorm(q[1], 10),
                unorm(q[2], 10),
                unorm(q[3], 2),
            ]
        }),
        entry!("bgr10a2unorm", 4, Float, |b| {
            let q = fields(word(b), &[10, 10, 10, 2]);
            [
                unorm(q[2], 10),
                unorm(q[1], 10),
                unorm(q[0], 10),
                unorm(q[3], 2),
            ]
        }),
        entry!("rg11b10float", 4, Float, |b| {
            let q = fields(word(b), &[11, 11, 10]);
            [
                small_float(q[0], 6),
                small_float(q[1], 6),
                small_float(q[2], 5),
                1.0,
            ]
        }),
        entry!("rgb9e5float", 4, Float, |b| {
            let q = fields(word(b), &[9, 9, 9, 5]);
            let scale = 2f64.powi(q[3] as i32 - 15 - 9);
            [
                q[0] as f64 * scale,
                q[1] as f64 * scale,
                q[2] as f64 * scale,
                1.0,
            ]
        }),
        entry!("b5g6r5unorm", 2, Float, |b| packed16(b, &[5, 6, 5], "bgr")),
        entry!("a1bgr5unorm", 2, Float, |b| packed16(
            b,
            &[1, 5, 5, 5],
            "abgr"
        )),
        entry!("abgr4unorm", 2, Float, |b| packed16(
            b,
            &[4, 4, 4, 4],
            "abgr"
        )),
        entry!("bgr5a1unorm", 2, Float, |b| packed16(
            b,
            &[5, 5, 5, 1],
            "bgra"
        )),
        entry!("r8uint", 1, Uint, |b| lanes(&[b[0] as f64])),
        entry!("rg8uint", 2, Uint, |b| lanes(&[b[0] as f64, b[1] as f64])),
        entry!("rgba8uint", 4, Uint, |b| [0, 1, 2, 3].map(|i| b[i] as f64)),
        entry!("rgba8sint", 4, Int, |b| [0, 1, 2, 3]
            .map(|i| b[i] as i8 as f64)),
        entry!("r16uint", 2, Uint, |b| lanes(&[short(b, 0) as f64])),
        entry!("rgba16uint", 8, Uint, |b| [0, 1, 2, 3]
            .map(|i| short(b, i) as f64)),
        entry!("rgba16sint", 8, Int, |b| [0, 1, 2, 3]
            .map(|i| signed(short(b, i), 16) as f64)),
        entry!("r32uint", 4, Uint, |b| lanes(&[word(b) as f64])),
        entry!("rg32uint", 8, Uint, |b| lanes(&[
            word(b) as f64,
            word(&b[4..]) as f64
        ])),
        entry!("rgba32uint", 16, Uint, |b| [0, 1, 2, 3]
            .map(|i| word(&b[4 * i..]) as f64)),
        entry!("r32sint", 4, Int, |b| lanes(
            &[word(b) as u32 as i32 as f64]
        )),
        entry!("rgba32sint", 16, Int, |b| [0, 1, 2, 3]
            .map(|i| word(&b[4 * i..]) as u32 as i32 as f64)),
        entry!("rgb10a2uint", 4, Uint, |b| {
            let q = fields(word(b), &[10, 10, 10, 2]);
            [q[0] as f64, q[1] as f64, q[2] as f64, q[3] as f64]
        }),
    ]
}

fn f32_at(b: &[u8], i: usize) -> f64 {
    f64::from(f32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap()))
}

pub(super) fn format_named(name: &str) -> Format {
    formats().into_iter().find(|f| f.name == name).unwrap()
}

/// One texel's bytes: random, except that float formats hold finite
/// values in [-4, 4] so filtering stays exact.
pub(super) fn texel_bytes(f: &Format, rng: &mut Random) -> Vec<u8> {
    match f.name {
        "r16float" | "rg16float" | "rgba16float" => {
            let n = f.size / 2;
            let v: Vec<f64> = (0..n).map(|_| f16r(rng.uniform(-4.0, 4.0))).collect();
            floats(Dtype::F16, &v)
        }
        "r32float" | "rg32float" | "rgba32float" => {
            let n = f.size / 4;
            let v: Vec<f64> = (0..n).map(|_| f32r(rng.uniform(-4.0, 4.0))).collect();
            f32s(&v)
        }
        "rg11b10float" => {
            let (r, g) = (rng.u32() % (30 << 6), rng.u32() % (30 << 6));
            u32s(&[r | g << 11 | (rng.u32() % (30 << 5)) << 22])
        }
        "rgb9e5float" => u32s(&[(rng.u32() & 0x7FF_FFFF) | (rng.u32() % 20 + 5) << 27]),
        _ => (0..f.size).map(|_| (rng.u32() % 256) as u8).collect(),
    }
}

fn make_texels(f: &Format, count: usize, rng: &mut Random) -> Vec<Vec<u8>> {
    (0..count).map(|_| texel_bytes(f, rng)).collect()
}

pub(super) fn decode(f: &Format, texel: &[u8]) -> Texel {
    let t = (f.decode)(texel);
    if f.kind == Kind::Float {
        t.map(f32r)
    } else {
        t
    }
}

pub(super) fn read_tolerance(f: &Format) -> Tolerance {
    match f.kind {
        Kind::Float if f.name.contains("srgb") => Tolerance::abs(2.5e-4),
        Kind::Float => Tolerance::ulp(1.0),
        _ => Tolerance::default(),
    }
}

/// Integer coordinates, four to a point.
fn coords(points: &[[u32; 4]]) -> Vec<u8> {
    points
        .iter()
        .flat_map(|p| p.iter().flat_map(|v| v.to_le_bytes()))
        .collect()
}

fn texels_as(dtype: Dtype, values: &[f64]) -> Vec<u8> {
    match dtype {
        Dtype::F32 | Dtype::F16 => floats(dtype, values),
        _ => ints(
            dtype,
            &values.iter().map(|&v| v as i128).collect::<Vec<_>>(),
        ),
    }
}

fn t2d(name: &str, format: &str, w: u32, h: u32) -> Texture {
    Texture::d2(name, format, w, h).index(0)
}

fn reads(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(61);
    let (w, h) = (16u32, 8u32);
    for f in formats() {
        let texels = make_texels(&f, (w * h) as usize, &mut rng);
        let points: Vec<[u32; 4]> = (0..h)
            .flat_map(|y| (0..w).map(move |x| [x, y, 0, 0]))
            .collect();
        let expect: Vec<f64> = points
            .iter()
            .flat_map(|p| decode(&f, &texels[(p[1] * w + p[0]) as usize]))
            .collect();
        let mut shaders = vec![match f.kind {
            Kind::Float => "float",
            Kind::Uint => "uint",
            Kind::Int => "int",
        }];
        if matches!(f.name, "rgba8unorm" | "rgba16float" | "r16float") {
            shaders.push("half");
        }
        if matches!(f.name, "rgba16uint" | "r16uint") {
            shaders.push("ushort");
        }
        if f.name == "rgba16sint" {
            shaders.push("short");
        }
        for shader in shaders {
            let dtype = match shader {
                "float" => Dtype::F32,
                "half" => Dtype::F16,
                "uint" => Dtype::U32,
                "int" => Dtype::I32,
                "ushort" => Dtype::U16,
                _ => Dtype::I16,
            };
            let values: Vec<f64> = if shader == "half" {
                expect.iter().map(|&v| f16r(v)).collect()
            } else {
                expect.clone()
            };
            let tol = if shader == "half" {
                Tolerance::ulp(1.0).with_abs(2f64.powi(-11))
            } else {
                read_tolerance(&f)
            };
            let tol = tol.with_ftz(false);
            plan.add(
                Case::compute1(
                    &format!("texture.read.{}.{shader}", f.name),
                    library,
                    &format!("read2d_{shader}"),
                    points.len() as u32,
                )
                .buffer(Buffer::data("coords", 0, coords(&points)))
                .buffer(Buffer::zeroed("out", 1, points.len() * 4 * dtype.size()))
                .output(
                    Output::new("out", dtype, tol.clone()).expect(texels_as(dtype, &values), tol),
                )
                .texture(t2d("t", f.name, w, h).data(texels.concat())),
            );
        }
    }
    let f = format_named("rgba8unorm");
    // A mipmapped 2D texture read at each level.
    let levels: Vec<(u32, u32)> = (0..5)
        .map(|l| (16 >> l, if 8 >> l > 0 { 8 >> l } else { 1 }))
        .collect();
    let texels: Vec<Vec<Vec<u8>>> = levels
        .iter()
        .map(|&(lw, lh)| make_texels(&f, (lw * lh) as usize, &mut rng))
        .collect();
    let mut points = vec![];
    let mut expect = vec![];
    for (l, &(lw, lh)) in levels.iter().enumerate() {
        for y in 0..lh {
            for x in 0..lw {
                points.push([x, y, l as u32, 0]);
                expect.extend(decode(&f, &texels[l][(y * lw + x) as usize]));
            }
        }
    }
    let one = Tolerance::ulp(1.0);
    plan.add(
        Case::compute1(
            "texture.read.mipmapped",
            library,
            "read2d_float",
            points.len() as u32,
        )
        .buffer(Buffer::data("coords", 0, coords(&points)))
        .buffer(Buffer::zeroed("out", 1, points.len() * 16))
        .output(Output::new("out", Dtype::F32, one.clone()).expect(f32s(&expect), one.clone()))
        .texture(
            t2d("t", "rgba8unorm", 16, 8)
                .mipmaps(5)
                .data(texels.concat().concat()),
        ),
    );
    // Texture types: 1D, 1D array, 2D array, 3D and cube, each texel once.
    for (name, kind, (width, height, depth, array), function) in [
        ("1d", "1d", (32, 1, 1, 1), "read1d"),
        ("1d_array", "1d_array", (16, 1, 1, 4), "read1d_array"),
        ("2d_array", "2d_array", (8, 4, 1, 3), "read2d_array"),
        ("3d", "3d", (8, 4, 4, 1), "read3d"),
        ("cube", "cube", (4, 4, 1, 1), "readcube"),
    ] {
        let slices = array * if kind == "cube" { 6 } else { 1 };
        let count = width * height * depth * slices;
        let texels = make_texels(&f, count as usize, &mut rng);
        let mut points = vec![];
        let mut expect = vec![];
        for s in 0..slices {
            for z in 0..depth {
                for y in 0..height {
                    for x in 0..width {
                        let index = ((s * depth + z) * height + y) * width + x;
                        points.push(match kind {
                            "1d" => [x, 0, 0, 0],
                            "1d_array" => [x, s, 0, 0],
                            "3d" => [x, y, z, 0],
                            _ => [x, y, 0, s],
                        });
                        expect.extend(decode(&f, &texels[index as usize]));
                    }
                }
            }
        }
        plan.add(
            Case::compute1(
                &format!("texture.read.type_{name}"),
                library,
                function,
                points.len() as u32,
            )
            .buffer(Buffer::data("coords", 0, coords(&points)))
            .buffer(Buffer::zeroed("out", 1, points.len() * 16))
            .output(Output::new("out", Dtype::F32, one.clone()).expect(f32s(&expect), one.clone()))
            .texture(
                Texture::new("t", "rgba8unorm", kind, [width, height, depth])
                    .index(0)
                    .array(array)
                    .data(texels.concat()),
            ),
        );
    }
    let depths: Vec<f64> = (0..64).map(|_| f32r(rng.uniform(0.0, 1.0))).collect();
    plan.add(
        Case::compute1("texture.read.depth32float", library, "read_depth", 64)
            .buffer(Buffer::data(
                "coords",
                0,
                coords(&(0..64).map(|i| [i % 8, i / 8, 0, 0]).collect::<Vec<_>>()),
            ))
            .buffer(Buffer::zeroed("out", 1, 256))
            .output(Output::new("out", Dtype::F32, Tolerance::default()).expect_same(f32s(&depths)))
            .texture(t2d("t", "depth32float", 8, 8).data(f32s(&depths))),
    );
    if plan.has(SOURCE, "read_buffer") {
        let texels = make_texels(&f, 256, &mut rng);
        let expect: Vec<f64> = texels.iter().flat_map(|t| decode(&f, t)).collect();
        plan.add(
            Case::compute1("texture.read.texture_buffer", library, "read_buffer", 256)
                .buffer(Buffer::data(
                    "coords",
                    0,
                    coords(&(0..256).map(|i| [i, 0, 0, 0]).collect::<Vec<_>>()),
                ))
                .buffer(Buffer::zeroed("out", 1, 256 * 16))
                .buffer(Buffer::data("storage", 0, texels.concat()).unbound())
                .output(Output::new("out", Dtype::F32, one.clone()).expect(f32s(&expect), one))
                .texture(
                    Texture::new("t", "rgba8unorm", "buffer", [256, 1, 1])
                        .index(0)
                        .set("buffer", "storage"),
                ),
        );
    }
}

/// Texel index i under an address mode, or None for the border.
fn address(i: i64, size: i64, mode: &str) -> Option<i64> {
    if (0..size).contains(&i) {
        return Some(i);
    }
    match mode {
        "clamp_to_edge" => Some(i.clamp(0, size - 1)),
        "repeat" => Some(i.rem_euclid(size)),
        "mirror_repeat" => {
            let m = i.rem_euclid(2 * size);
            Some(if m < size { m } else { 2 * size - 1 - m })
        }
        "mirror_clamp_to_edge" => Some((if i < 0 { -1 - i } else { i }).min(size - 1)),
        _ => None,
    }
}

/// A sampler state, as the runner creates it.
#[derive(Clone)]
struct Sampler {
    label: String,
    min: &'static str,
    mag: &'static str,
    mip: &'static str,
    address: [&'static str; 3],
    border: &'static str,
    lod: Option<(f64, f64)>,
    compare: Option<&'static str>,
}

impl Sampler {
    fn new(label: &str, filter: &'static str, address: &'static str) -> Self {
        Self {
            label: label.to_string(),
            min: filter,
            mag: filter,
            mip: "none",
            address: [address; 3],
            border: "transparent_black",
            lod: None,
            compare: None,
        }
    }

    fn json(&self) -> Value {
        let mut s = json!({
            "name": "s", "index": 0, "min": self.min, "mag": self.mag, "mip": self.mip,
            "address": self.address, "border": self.border,
        });
        if let Some((lo, hi)) = self.lod {
            s["lod_min"] = json!(lo);
            s["lod_max"] = json!(hi);
        }
        if let Some(c) = self.compare {
            s["compare"] = json!(c);
        }
        s
    }

    fn border_color(&self) -> Texel {
        if self.address[0] == "clamp_to_zero" {
            return [0.0; 4];
        }
        match self.border {
            "opaque_black" => [0.0, 0.0, 0.0, 1.0],
            "opaque_white" => [1.0; 4],
            _ => [0.0; 4],
        }
    }

    fn nearest(&self) -> bool {
        self.min == "nearest" || self.mag == "nearest"
    }
}

/// One mip level of a texture: width, height, depth and texels.
#[derive(Clone)]
struct Level {
    w: i64,
    h: i64,
    d: i64,
    texels: Vec<Texel>,
}

impl Level {
    fn fetch(&self, s: &Sampler, x: i64, y: i64, z: i64) -> Texel {
        match (
            address(x, self.w, s.address[0]),
            address(y, self.h, s.address[1]),
            address(z, self.d, s.address[2]),
        ) {
            (Some(x), Some(y), Some(z)) => self.texels[((z * self.h + y) * self.w + x) as usize],
            _ => s.border_color(),
        }
    }

    /// The level's filtered value at normalized coordinates.
    fn filter(&self, s: &Sampler, linear: bool, u: f64, v: f64, r: f64, dims: u32) -> Texel {
        let (x, y, z) = (u * self.w as f64, v * self.h as f64, r * self.d as f64);
        if !linear {
            return self.fetch(
                s,
                x.floor() as i64,
                y.floor() as i64,
                if dims > 2 { z.floor() as i64 } else { 0 },
            );
        }
        let axis = |c: f64, used: bool| {
            if used {
                let c = c - 0.5;
                (c.floor() as i64, c - c.floor())
            } else {
                (0, 0.0)
            }
        };
        let (x0, fx) = axis(x, true);
        let (y0, fy) = axis(y, dims > 1);
        let (z0, fz) = axis(z, dims > 2);
        let mut out = [0.0; 4];
        for dz in 0..if dims > 2 { 2 } else { 1 } {
            for dy in 0..if dims > 1 { 2 } else { 1 } {
                for dx in 0..2 {
                    let weight = (if dx == 1 { fx } else { 1.0 - fx })
                        * (if dims > 1 {
                            if dy == 1 { fy } else { 1.0 - fy }
                        } else {
                            1.0
                        })
                        * (if dims > 2 {
                            if dz == 1 { fz } else { 1.0 - fz }
                        } else {
                            1.0
                        });
                    let t = self.fetch(s, x0 + dx, y0 + dy, z0 + dz);
                    for k in 0..4 {
                        out[k] += t[k] * weight;
                    }
                }
            }
        }
        out
    }
}

/// Metal's filtered sample of a 1D, 2D or 3D texture at normalized
/// coordinates and a level of detail.
fn sample(levels: &[Level], s: &Sampler, uvw: [f64; 3], lod: f64, dims: u32) -> Texel {
    let (lo, hi) = s.lod.unwrap_or((0.0, 1000.0));
    let lod = lod.max(lo).min(hi).min((levels.len() - 1) as f64);
    let linear = if lod <= 0.0 { s.mag } else { s.min } == "linear";
    let at = |l: usize| levels[l].filter(s, linear, uvw[0], uvw[1], uvw[2], dims);
    match s.mip {
        "none" => at(0),
        "nearest" => at((lod + 0.5).floor() as usize),
        _ => {
            let base = lod.floor() as usize;
            let frac = lod - lod.floor();
            let first = at(base);
            if frac == 0.0 || base + 1 >= levels.len() {
                return first;
            }
            let second = at(base + 1);
            [0, 1, 2, 3].map(|k| first[k] * (1.0 - frac) + second[k] * frac)
        }
    }
}

fn level(w: i64, h: i64, texels: Vec<Texel>) -> Level {
    Level { w, h, d: 1, texels }
}

fn samplers() -> Vec<Sampler> {
    let mut out = vec![];
    for filt in ["nearest", "linear"] {
        for mode in [
            "clamp_to_edge",
            "repeat",
            "mirror_repeat",
            "mirror_clamp_to_edge",
            "clamp_to_zero",
            "clamp_to_border",
        ] {
            out.push(Sampler::new(&format!("{filt}.{mode}"), filt, mode));
        }
    }
    let mut black = Sampler::new("border.opaque_black", "nearest", "clamp_to_border");
    black.border = "opaque_black";
    let mut white = Sampler::new("border.opaque_white", "linear", "clamp_to_border");
    white.border = "opaque_white";
    let mut mixed = Sampler::new("mixed_address", "linear", "repeat");
    mixed.address = ["repeat", "mirror_repeat", "mirror_repeat"];
    let mip = |label: &str, filt, mip| {
        let mut s = Sampler::new(label, filt, "repeat");
        s.mip = mip;
        s
    };
    let mut clamp = mip("lod_clamp", "linear", "linear");
    clamp.lod = Some((1.0, 2.5));
    let mut min_mag = mip("min_mag", "nearest", "nearest");
    min_mag.mag = "linear";
    out.extend([
        black,
        white,
        mixed,
        mip("mip.nearest", "linear", "nearest"),
        mip("mip.linear", "linear", "linear"),
        mip("mip.nearest_filter", "nearest", "linear"),
        clamp,
        min_mag,
    ]);
    out
}

/// Coordinates away from texel edges for nearest filtering, which
/// resolves edges to the device's sub-texel precision.
fn sample_points(rng: &mut Random, count: usize, nearest: bool, w: i64, h: i64) -> Vec<(f64, f64)> {
    (0..count)
        .map(|_| {
            if nearest {
                let x = (rng.below((w * 4) as u32) - w) as f64 + 0.5 + rng.uniform(-0.3, 0.3);
                let x = x / w as f64;
                let y = (rng.below((h * 4) as u32) - h) as f64 + 0.5 + rng.uniform(-0.3, 0.3);
                (f32r(x), f32r(y / h as f64))
            } else {
                let x = rng.uniform(-1.0, 2.0);
                (f32r(x), f32r(rng.uniform(-1.0, 2.0)))
            }
        })
        .collect()
}

/// Whether a coordinate is within `margin` texels of a texel edge, where
/// nearest filtering is the device's call.
fn near_edge(c: f64, size: i64, margin: f64) -> bool {
    let t = c * size as f64;
    (t - t.round()).abs() < margin
}

fn sampling(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(71);
    let (w, h, mips) = (16i64, 16i64, 5usize);
    for name in [
        "rgba8unorm",
        "rgba16float",
        "rgba32float",
        "rgba8unorm_srgb",
    ] {
        let f = format_named(name);
        let sizes: Vec<(i64, i64)> = (0..mips)
            .map(|l| ((w >> l).max(1), (h >> l).max(1)))
            .collect();
        let mut raw: Vec<Vec<Vec<u8>>> = sizes
            .iter()
            .map(|&(lw, lh)| make_texels(&f, (lw * lh) as usize, &mut rng))
            .collect();
        if name == "rgba16float" || name == "rgba32float" {
            // Values in [0, 1], so filtering error is bounded as for unorm.
            let half = name == "rgba16float";
            raw = raw
                .iter()
                .map(|t| {
                    t.iter()
                        .map(|_| {
                            let v: Vec<f64> = (0..4)
                                .map(|_| {
                                    let x = rng.uniform(0.0, 1.0);
                                    if half { f16r(x) } else { f32r(x) }
                                })
                                .collect();
                            floats(if half { Dtype::F16 } else { Dtype::F32 }, &v)
                        })
                        .collect()
                })
                .collect();
        }
        let levels: Vec<Level> = sizes
            .iter()
            .zip(&raw)
            .map(|(&(lw, lh), texels)| {
                level(lw, lh, texels.iter().map(|t| decode(&f, t)).collect())
            })
            .collect();
        let data = raw.concat().concat();
        for s in samplers() {
            let filtered = s.min == "linear" || s.mag == "linear";
            let nearest = s.min == "nearest" && s.mag == "nearest";
            let points = sample_points(&mut rng, 256, s.nearest(), w, h);
            let mipped = s.mip != "none";
            let mut lods = vec![0.0; points.len()];
            if mipped {
                // Off the halfway point where nearest mip selection is the
                // device's choice.
                lods = (0..points.len())
                    .map(|_| f64::from(rng.u32() % (64 * (mips as u32 - 1) + 1)) / 64.0)
                    .collect();
                lods = lods
                    .into_iter()
                    .map(|l| {
                        if (l * 64.0) % 64.0 == 32.0 {
                            l + 1.0 / 64.0
                        } else {
                            l
                        }
                    })
                    .collect();
            }
            let expected: Vec<f64> = points
                .iter()
                .zip(&lods)
                .flat_map(|(&(u, v), &lod)| sample(&levels, &s, [u, v, 0.0], lod, 2))
                .map(f32r)
                .collect();
            let mut tol = if nearest && !mipped {
                Tolerance::ulp(1.0)
            } else {
                filter()
            };
            if name.contains("srgb") {
                tol.abs = Some(tol.abs.unwrap_or(0.0).max(2.5e-4));
            }
            let coords: Vec<f64> = points
                .iter()
                .zip(&lods)
                .flat_map(|(&(u, v), &l)| [u, v, l, 0.0])
                .collect();
            let mut case = Case::compute1(
                &format!("texture.sample.{name}.{}", s.label),
                library,
                "sample2d_level",
                256,
            )
            .buffer(Buffer::data("coords", 0, f32s(&coords)))
            .buffer(Buffer::zeroed("out", 1, 256 * 16))
            .output(Output::new("out", Dtype::F32, tol.clone()).expect(f32s(&expected), tol))
            .texture(
                t2d("t", name, w as u32, h as u32)
                    .mipmaps(if mipped { mips as u32 } else { 1 })
                    .data(if mipped {
                        data.clone()
                    } else {
                        raw[0].concat()
                    }),
            )
            .sampler(s.json());
            if name == "rgba32float" && filtered {
                case = case.requires(&[], &["float32_filtering"]);
            }
            plan.add(case);
        }
    }
    forms(plan, library, &mut rng);
    gathers(plan, library, &mut rng);
}

/// The other sample forms: integer offsets, explicit gradients and a
/// minimum level of detail, the 1D, 2D array, 3D and cube types, and
/// samplers the shader declares.
fn forms(plan: &mut Plan, library: &str, rng: &mut Random) {
    let f = format_named("rgba8unorm");
    let raw = make_texels(&f, 16 * 16 * 5 / 3 + 64, rng);
    let sizes = [(16, 16), (8, 8), (4, 4), (2, 2), (1, 1)];
    let mut at = 0;
    let levels: Vec<Level> = sizes
        .iter()
        .map(|&(lw, lh)| {
            let texels = raw[at..at + (lw * lh) as usize]
                .iter()
                .map(|t| decode(&f, t))
                .collect();
            at += (lw * lh) as usize;
            level(lw, lh, texels)
        })
        .collect();
    let tex = || {
        t2d("t", "rgba8unorm", 16, 16)
            .mipmaps(5)
            .data(raw[..341].concat())
    };
    let mut lin = Sampler::new("lin", "linear", "repeat");
    lin.mip = "linear";
    let pts: Vec<[f64; 4]> = (0..256)
        .map(|_| {
            let (a, b) = (rng.uniform(-1.0, 2.0), rng.uniform(-1.0, 2.0));
            let (c, d) = (rng.uniform(0.001, 0.5), rng.uniform(0.0, 3.0));
            [a, b, c, d].map(f32r)
        })
        .collect();
    // A level of detail on the 1/64 lattice, offset by half a step so that
    // truncating or rounding devices both land within the filter bound.
    let lattice = |l: f64| (l * 64.0).floor() / 64.0 + 1.0 / 128.0;
    let mip = Tolerance::ulp(2.0).with_abs(3.0 / 256.0);
    // Offsets shift the footprint by whole texels of level 0.
    let offset: Vec<f64> = pts
        .iter()
        .flat_map(|p| {
            sample(
                &levels,
                &lin,
                [p[0] - 2.0 / 16.0, p[1] + 3.0 / 16.0, 0.0],
                0.0,
                2,
            )
        })
        .map(f32r)
        .collect();
    let tol = filter();
    plan.add(
        Case::compute1("texture.sample.offset", library, "sample2d_offset", 256)
            .buffer(Buffer::data("coords", 0, f32s(&pts.concat())))
            .buffer(Buffer::zeroed("out", 1, 256 * 16))
            .output(Output::new("out", Dtype::F32, tol.clone()).expect(f32s(&offset), tol))
            .texture(tex())
            .sampler(lin.json()),
    );
    // gradient2d(dPdx = (c.z, 0), dPdy = (0, c.w)): the level of detail is
    // log2 of the longer gradient in texels.
    let mut coords = vec![];
    let mut expected = vec![];
    for p in &pts {
        let lod = lattice(p[3]);
        let dx = f32r(2f64.powf(lod) / 16.0);
        let dy = f32r(dx * 2f64.powf(-2.0 * p[2]));
        coords.extend([p[0], p[1], dx, dy]);
        expected.extend(sample(&levels, &lin, [p[0], p[1], 0.0], lod, 2).map(f32r));
    }
    if plan.has(SOURCE, "sample2d_grad") {
        plan.add(
            Case::compute1("texture.sample.gradient", library, "sample2d_grad", 256)
                .buffer(Buffer::data("coords", 0, f32s(&coords)))
                .buffer(Buffer::zeroed("out", 1, 256 * 16))
                .output(
                    Output::new("out", Dtype::F32, mip.clone())
                        .expect(f32s(&expected), mip.clone()),
                )
                .texture(tex())
                .sampler(lin.json()),
        );
    }
    // gradient2d((c.z, 0), (0, c.z)) with min_lod_clamp(c.w).
    let mut coords = vec![];
    let mut expected = vec![];
    for p in &pts {
        let lod = lattice(libm::log2(f64::from(p[2] as f32) * 16.0));
        let floor = lattice(p[3]);
        let dz = f32r(2f64.powf(lod) / 16.0);
        coords.extend([p[0], p[1], dz, floor]);
        expected.extend(sample(&levels, &lin, [p[0], p[1], 0.0], lod.max(floor), 2).map(f32r));
    }
    if plan.has(SOURCE, "sample2d_min_lod") {
        plan.add(
            Case::compute1(
                "texture.sample.min_lod_clamp",
                library,
                "sample2d_min_lod",
                256,
            )
            .buffer(Buffer::data("coords", 0, f32s(&coords)))
            .buffer(Buffer::zeroed("out", 1, 256 * 16))
            .output(Output::new("out", Dtype::F32, mip.clone()).expect(f32s(&expected), mip))
            .texture(tex())
            .sampler(lin.json()),
        );
    }
    let mut flat = lin.clone();
    flat.mip = "none";
    for (kind, function, (width, height, depth, array), count) in [
        (
            "2d_array",
            "sample2d_array",
            (8i64, 8i64, 1i64, 4u32),
            4 * 64,
        ),
        ("3d", "sample3d", (8, 8, 8, 1), 512),
        ("cube", "samplecube", (8, 8, 1, 1), 6 * 64),
        ("1d", "sample1d", (64, 1, 1, 1), 64),
    ] {
        let texels = make_texels(&f, count, rng);
        let decoded: Vec<Texel> = texels.iter().map(|t| decode(&f, t)).collect();
        let mut pts: Vec<[f64; 4]> = (0..256)
            .map(|_| {
                let (a, b, c) = (
                    rng.uniform(-1.5, 1.5),
                    rng.uniform(-1.5, 1.5),
                    rng.uniform(-1.5, 1.5),
                );
                [a, b, c, f64::from(rng.u32() % 4)].map(f32r)
            })
            .collect();
        if kind == "3d" {
            pts.iter_mut().for_each(|p| p[3] = 0.0);
        }
        let mut expected = vec![];
        let mut mask = vec![];
        for p in &pts {
            let (texel, defined) = match kind {
                "2d_array" => {
                    let slice = p[3] as usize * 64;
                    (
                        sample(
                            &[level(8, 8, decoded[slice..slice + 64].to_vec())],
                            &flat,
                            [p[0], p[1], 0.0],
                            0.0,
                            2,
                        ),
                        true,
                    )
                }
                "3d" => {
                    let volume = Level {
                        w: 8,
                        h: 8,
                        d: 8,
                        texels: decoded.clone(),
                    };
                    (sample(&[volume], &flat, [p[0], p[1], p[2]], 0.0, 3), true)
                }
                "cube" => cube(&decoded, width, [p[0], p[1], p[2]]),
                _ => (
                    sample(
                        &[level(64, 1, decoded.clone())],
                        &flat,
                        [p[0], 0.0, 0.0],
                        0.0,
                        1,
                    ),
                    true,
                ),
            };
            expected.extend(texel.map(f32r));
            mask.push(u8::from(defined));
        }
        let tol = filter();
        plan.add(
            Case::compute1(
                &format!("texture.sample.type_{kind}"),
                library,
                function,
                256,
            )
            .buffer(Buffer::data("coords", 0, f32s(&pts.concat())))
            .buffer(Buffer::zeroed("out", 1, 256 * 16))
            .output(
                Output::new("out", Dtype::F32, tol.clone())
                    .expect(f32s(&expected), tol)
                    .expect_mask(mask)
                    .set("stride", 4),
            )
            .texture(
                Texture::new(
                    "t",
                    "rgba8unorm",
                    kind,
                    [width as u32, height as u32, depth as u32],
                )
                .index(0)
                .array(array)
                .data(texels.concat()),
            )
            .sampler(flat.json()),
        );
    }
    // Samplers the shader declares: nearest repeat, linear mirrored repeat,
    // linear clamp at pixel coordinates, and nearest clamp to an opaque
    // white border.
    let texels = make_texels(&f, 64, rng);
    let image = [level(8, 8, texels.iter().map(|t| decode(&f, t)).collect())];
    let pts: Vec<[f64; 4]> = (0..256)
        .map(|_| {
            [
                f32r(rng.uniform(-1.0, 2.0)),
                f32r(rng.uniform(-1.0, 2.0)),
                0.0,
                0.0,
            ]
        })
        .collect();
    let nearest = Sampler::new("n", "nearest", "repeat");
    let mirror = Sampler::new("m", "linear", "mirror_repeat");
    let pixel = Sampler::new("p", "linear", "clamp_to_edge");
    let mut border = Sampler::new("b", "nearest", "clamp_to_border");
    border.border = "opaque_white";
    let mut expected = vec![];
    let mut mask = vec![];
    for p in &pts {
        let ambiguous = near_edge(p[0], 8, 0.01) || near_edge(p[1], 8, 0.01);
        for (s, exact) in [
            (&nearest, !ambiguous),
            (&mirror, true),
            (&pixel, true),
            (&border, !ambiguous),
        ] {
            expected.extend(sample(&image, s, [p[0], p[1], 0.0], 0.0, 2).map(f32r));
            mask.push(u8::from(exact));
        }
    }
    let tol = filter();
    plan.add(
        Case::compute1(
            "texture.sample.constexpr_samplers",
            library,
            "sample_constexpr",
            256,
        )
        .buffer(Buffer::data("coords", 0, f32s(&pts.concat())))
        .buffer(Buffer::zeroed("out", 1, 256 * 64))
        .output(
            Output::new("out", Dtype::F32, tol.clone())
                .expect(f32s(&expected), tol)
                .expect_mask(mask)
                .set("stride", 4),
        )
        .texture(t2d("t", "rgba8unorm", 8, 8).data(texels.concat())),
    );
}

/// A cube sample's face and face coordinates: the major axis picks the
/// face (+X, -X, +Y, -Y, +Z, -Z), the other two give (s, t) as Metal and
/// every other API define them. Defined where the bilinear footprint lies
/// within the face and the major axis is clear; elsewhere seamless
/// filtering across faces is the device's.
fn cube(texels: &[Texel], size: i64, d: [f64; 3]) -> (Texel, bool) {
    let a = d.map(f64::abs);
    let (face, ma, sc, tc) = if a[0] >= a[1] && a[0] >= a[2] {
        if d[0] >= 0.0 {
            (0, a[0], -d[2], -d[1])
        } else {
            (1, a[0], d[2], -d[1])
        }
    } else if a[1] >= a[2] {
        if d[1] >= 0.0 {
            (2, a[1], d[0], d[2])
        } else {
            (3, a[1], d[0], -d[2])
        }
    } else if d[2] >= 0.0 {
        (4, a[2], d[0], -d[1])
    } else {
        (5, a[2], -d[0], -d[1])
    };
    let mut sorted = a;
    sorted.sort_by(|x, y| y.partial_cmp(x).unwrap());
    let (u, v) = ((sc / ma + 1.0) / 2.0, (tc / ma + 1.0) / 2.0);
    let n = size as f64;
    let inside = |c: f64| c * n > 0.5 + 1e-3 && c * n < n - 0.5 - 1e-3;
    let defined = sorted[0] > sorted[1] * 1.001 && inside(u) && inside(v);
    let per_face = (size * size) as usize;
    let image = level(
        size,
        size,
        texels[face * per_face..(face + 1) * per_face].to_vec(),
    );
    let s = Sampler::new("c", "linear", "clamp_to_edge");
    (image.filter(&s, true, u, v, 0.0, 2), defined)
}

fn gathers(plan: &mut Plan, library: &str, rng: &mut Random) {
    let f = format_named("rgba8unorm");
    let (w, h) = (8i64, 8i64);
    let texels = make_texels(&f, (w * h) as usize, rng);
    let decoded: Vec<Texel> = texels.iter().map(|t| decode(&f, t)).collect();
    let pts: Vec<(f64, f64)> = (0..256)
        .map(|_| {
            let x = (rng.below((w * 3) as u32) - w) as f64 + rng.uniform(0.6, 1.4);
            let x = f32r(x / w as f64);
            let y = (rng.below((h * 3) as u32) - h) as f64 + rng.uniform(0.6, 1.4);
            (x, f32r(y / h as f64))
        })
        .collect();
    let edge = |x: i64, y: i64| decoded[(y.clamp(0, h - 1) * w + x.clamp(0, w - 1)) as usize];
    for (lane, comp) in ["x", "y", "z", "w"].into_iter().enumerate() {
        let mut expected = vec![];
        for &(u, v) in &pts {
            for (ox, oy) in [(0, 0), (1, -1)] {
                let x0 = (u * w as f64 - 0.5).floor() as i64 + ox;
                let y0 = (v * h as f64 - 0.5).floor() as i64 + oy;
                expected.extend([
                    edge(x0, y0 + 1)[lane],
                    edge(x0 + 1, y0 + 1)[lane],
                    edge(x0 + 1, y0)[lane],
                    edge(x0, y0)[lane],
                ]);
            }
        }
        let one = Tolerance::ulp(1.0);
        let coords: Vec<f64> = pts.iter().flat_map(|&(u, v)| [u, v, 0.0, 0.0]).collect();
        plan.add(
            Case::compute1(
                &format!("texture.gather.{comp}"),
                library,
                &format!("gather_{comp}"),
                256,
            )
            .buffer(Buffer::data("coords", 0, f32s(&coords)))
            .buffer(Buffer::zeroed("out", 1, 256 * 32))
            .output(Output::new("out", Dtype::F32, one.clone()).expect(
                f32s(&expected.into_iter().map(f32r).collect::<Vec<_>>()),
                one,
            ))
            .texture(t2d("t", "rgba8unorm", w as u32, h as u32).data(texels.concat()))
            .sampler(json!({"name": "s", "index": 0, "min": "linear", "mag": "linear"})),
        );
    }
    let depths: Vec<f64> = (0..w * h).map(|_| f32r(rng.uniform(0.0, 1.0))).collect();
    let refs: Vec<(f64, f64, f64)> = (0..h)
        .flat_map(|y| (0..w).map(move |x| (x, y)))
        .map(|(x, y)| {
            (
                f32r((x as f64 + 0.5) / w as f64),
                f32r((y as f64 + 0.5) / h as f64),
                f32r(rng.uniform(0.0, 1.0)),
            )
        })
        .collect();
    let depth_texture = || t2d("t", "depth32float", w as u32, h as u32).data(f32s(&depths));
    let test = |compare: &str, r: f64, d: f64| match compare {
        "less" => r < d,
        "less_equal" => r <= d,
        "greater_equal" => r >= d,
        "never" => false,
        "always" => true,
        _ => r == d,
    };
    for compare in ["less", "greater_equal", "never", "always", "equal"] {
        let expected: Vec<f64> = refs
            .iter()
            .zip(&depths)
            .map(|(&(_, _, r), &d)| f64::from(u8::from(test(compare, r, d))))
            .collect();
        let coords: Vec<f64> = refs.iter().flat_map(|&(u, v, r)| [u, v, r, 0.0]).collect();
        plan.add(
            Case::compute1(&format!("texture.sample_compare.{compare}"), library, "sample_compare", refs.len() as u32)
                .buffer(Buffer::data("coords", 0, f32s(&coords)))
                .buffer(Buffer::zeroed("out", 1, refs.len() * 4))
                .output(Output::new("out", Dtype::F32, Tolerance::default()).expect_same(f32s(&expected)))
                .texture(depth_texture())
                .sampler(json!({"name": "s", "index": 0, "min": "nearest", "mag": "nearest", "compare": compare})),
        );
    }
    // Linear compare filtering (percentage closer): the bilinear blend of
    // each tap's comparison.
    let depth = |x: i64, y: i64| depths[(y.clamp(0, h - 1) * w + x.clamp(0, w - 1)) as usize];
    let mut coords = vec![];
    let mut expected = vec![];
    for &(u, v, r) in &refs {
        let (u, v) = (f32r(u + 0.3 / w as f64), f32r(v - 0.2 / h as f64));
        let (x, y) = (u * w as f64 - 0.5, v * h as f64 - 0.5);
        let (x0, y0) = (x.floor() as i64, y.floor() as i64);
        let (fx, fy) = (x - x.floor(), y - y.floor());
        let tap = |dx: i64, dy: i64| f64::from(u8::from(r < depth(x0 + dx, y0 + dy)));
        expected.push(
            (tap(0, 0) * (1.0 - fx) + tap(1, 0) * fx) * (1.0 - fy)
                + (tap(0, 1) * (1.0 - fx) + tap(1, 1) * fx) * fy,
        );
        coords.extend([u, v, r, 0.0]);
    }
    let tol = filter();
    plan.add(
        Case::compute1(
            "texture.sample_compare.linear",
            library,
            "sample_compare",
            refs.len() as u32,
        )
        .buffer(Buffer::data("coords", 0, f32s(&coords)))
        .buffer(Buffer::zeroed("out", 1, refs.len() * 4))
        .output(Output::new("out", Dtype::F32, tol.clone()).expect(f32s(&expected), tol))
        .texture(depth_texture())
        .sampler(
            json!({"name": "s", "index": 0, "min": "linear", "mag": "linear", "compare": "less"}),
        ),
    );
    // gather_compare at texel corners: the four comparisons in gather order.
    let mut coords = vec![];
    let mut expected = vec![];
    for &(u, v, r) in &refs {
        let (u, v) = (f32r(u + 0.5 / w as f64), f32r(v + 0.5 / h as f64));
        let x0 = (u * w as f64 - 0.5).floor() as i64;
        let y0 = (v * h as f64 - 0.5).floor() as i64;
        let tap = |x: i64, y: i64| f64::from(u8::from(r <= depth(x, y)));
        expected.extend([
            tap(x0, y0 + 1),
            tap(x0 + 1, y0 + 1),
            tap(x0 + 1, y0),
            tap(x0, y0),
        ]);
        coords.extend([u, v, r, 0.0]);
    }
    plan.add(
        Case::compute1("texture.gather_compare", library, "gather_compare", refs.len() as u32)
            .buffer(Buffer::data("coords", 0, f32s(&coords)))
            .buffer(Buffer::zeroed("out", 1, refs.len() * 16))
            .output(Output::new("out", Dtype::F32, Tolerance::default()).expect_same(f32s(&expected)))
            .texture(depth_texture())
            .sampler(json!({"name": "s", "index": 0, "min": "nearest", "mag": "nearest", "compare": "less_equal"})),
    );
    let coords: Vec<f64> = refs.iter().flat_map(|&(u, v, r)| [u, v, r, 0.0]).collect();
    plan.add(
        Case::compute1(
            "texture.sample.depth",
            library,
            "sample_depth",
            refs.len() as u32,
        )
        .buffer(Buffer::data("coords", 0, f32s(&coords)))
        .buffer(Buffer::zeroed("out", 1, refs.len() * 4))
        .output(Output::new("out", Dtype::F32, Tolerance::default()).expect_same(f32s(&depths)))
        .texture(depth_texture())
        .sampler(json!({"name": "s", "index": 0, "min": "nearest", "mag": "nearest"})),
    );
}

/// The bytes a write of these lanes stores in a unorm, float or integer
/// format.
fn encode(name: &str, values: &[f64]) -> Vec<u8> {
    let n = if name.starts_with("rgba") {
        4
    } else if name.starts_with("rg") {
        2
    } else {
        1
    };
    let v = &values[..n];
    if name.ends_with("8unorm") {
        v.iter()
            .map(|&x| (x.clamp(0.0, 1.0) * 255.0).round() as u8)
            .collect()
    } else if name.ends_with("16float") {
        floats(Dtype::F16, v)
    } else if name.ends_with("32float") {
        f32s(v)
    } else if name.ends_with("32uint") || name.ends_with("32sint") {
        v.iter()
            .flat_map(|&x| (x as i64 as u32).to_le_bytes())
            .collect()
    } else if name.ends_with("16uint") {
        v.iter().flat_map(|&x| (x as u16).to_le_bytes()).collect()
    } else if name.ends_with("8uint") {
        v.iter().map(|&x| x as u8).collect()
    } else {
        panic!("no encoder for {name}")
    }
}

fn writes(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(81);
    let (w, h) = (16u32, 8u32);
    type Gen = fn(&mut Random) -> f64;
    let unit: Gen = |r| f32r(f64::from(r.u32() % 256) / 255.0);
    let half: Gen = |r| f16r(r.uniform(-100.0, 100.0));
    let float: Gen = |r| f32r(r.uniform(-100.0, 100.0));
    let word: Gen = |r| f64::from(r.u32());
    let short: Gen = |r| f64::from(r.u32() % 65536);
    let byte: Gen = |r| f64::from(r.u32() % 256);
    let int: Gen = |r| f64::from(r.u32()) - 2f64.powi(31);
    for (name, shader, generate) in [
        ("rgba8unorm", "float", unit),
        ("r8unorm", "float", unit),
        ("rg8unorm", "float", unit),
        ("rgba16float", "float", half),
        ("r32float", "float", float),
        ("rg32float", "float", float),
        ("rgba32float", "float", float),
        ("rgba32uint", "uint", word),
        ("r32uint", "uint", word),
        ("rgba16uint", "uint", short),
        ("rgba8uint", "uint", byte),
        ("rgba32sint", "int", int),
        ("r32sint", "int", int),
    ] {
        let texels: Vec<Vec<f64>> = (0..w * h)
            .map(|_| (0..4).map(|_| generate(&mut rng)).collect())
            .collect();
        let dtype = match shader {
            "float" => Dtype::F32,
            "uint" => Dtype::U32,
            _ => Dtype::I32,
        };
        let expected: Vec<u8> = texels.iter().flat_map(|t| encode(name, t)).collect();
        plan.add(
            Case::compute(
                &format!("texture.write.{name}"),
                library,
                &format!("write2d_{shader}"),
                [w, h, 1],
                [8, 8, 1],
            )
            .dispatch_threads()
            .buffer(Buffer::data(
                "values",
                0,
                texels_as(dtype, &texels.concat()),
            ))
            .output(Output::new("t", Dtype::U8, Tolerance::default()).expect_same(expected))
            .texture(t2d("t", name, w, h).usage(&["read", "write"])),
        );
    }
    let values: Vec<f64> = (0..8 * 4 * 4)
        .map(|_| f32r(rng.uniform(-1.0, 1.0)))
        .collect();
    let mut expected = vec![0.0; 16 * 8 * 4];
    expected.extend(&values);
    expected.extend(vec![0.0; 4 * 2 * 4 + 2 * 4]);
    plan.add(
        Case::compute(
            "texture.write.level1",
            library,
            "write2d_level",
            [16, 8, 1],
            [8, 8, 1],
        )
        .dispatch_threads()
        .buffer(Buffer::data("values", 0, f32s(&values)))
        .output(Output::new("t", Dtype::F32, Tolerance::default()).expect_same(f32s(&expected)))
        .texture(
            t2d("t", "rgba32float", 16, 8)
                .mipmaps(4)
                .usage(&["read", "write"])
                .data(vec![0; 16 * (128 + 32 + 8 + 2)]),
        ),
    );
    for (kind, (width, height, depth, array), function) in [
        ("3d", (8, 4, 4, 1), "write3d"),
        ("2d_array", (8, 4, 1, 4), "write2d_array"),
    ] {
        let count = width * height * depth * array;
        let values: Vec<f64> = (0..count * 4)
            .map(|_| f32r(rng.uniform(-1.0, 1.0)))
            .collect();
        plan.add(
            Case::compute(
                &format!("texture.write.type_{kind}"),
                library,
                function,
                [width, height, depth * array],
                [4, 4, 1],
            )
            .dispatch_threads()
            .buffer(Buffer::data("values", 0, f32s(&values)))
            .output(Output::new("t", Dtype::F32, Tolerance::default()).expect_same(f32s(&values)))
            .texture(
                Texture::new("t", "rgba32float", kind, [width, height, depth])
                    .index(0)
                    .array(array)
                    .usage(&["read", "write"]),
            ),
        );
    }
    if plan.has(SOURCE, "read_write") {
        let values: Vec<f64> = (0..w * h * 4)
            .map(|_| f32r(rng.uniform(-1.0, 1.0)))
            .collect();
        let expected: Vec<f64> = values
            .chunks(4)
            .flat_map(|t| [t[3], t[2], t[1], t[0]].map(|v| f32r(v * 0.5 + 0.25)))
            .collect();
        plan.add(
            Case::compute(
                "texture.read_write.rgba32float",
                library,
                "read_write",
                [w, h, 1],
                [8, 8, 1],
            )
            .dispatch_threads()
            .output(Output::new("t", Dtype::F32, Tolerance::default()).expect_same(f32s(&expected)))
            .texture(
                t2d("t", "rgba32float", w, h)
                    .usage(&["read", "write"])
                    .data(f32s(&values)),
            )
            .requires(&[], &["read_write_textures_tier2"]),
        );
    }
    if plan.has(SOURCE, "texture_atomics") {
        let n = 1024;
        let values: Vec<u32> = (0..n).map(|_| rng.u32() % 100_000).collect();
        let mut cells = [0u32; 32];
        for (i, &v) in values.iter().enumerate() {
            cells[(i / 4) % 4 * 4 + i % 4] += v;
            let k = (4 + (i / 4) % 4) * 4 + i % 4;
            cells[k] = cells[k].max(v);
        }
        plan.add(
            Case::compute1("texture.atomics.r32uint", library, "texture_atomics", n)
                .buffer(Buffer::data("values", 0, u32s(&values)))
                .output(
                    Output::new("t", Dtype::U32, Tolerance::default()).expect_same(u32s(&cells)),
                )
                .texture(
                    t2d("t", "r32uint", 4, 8)
                        .usage(&["read", "write", "atomic"])
                        .data(vec![0; 128]),
                ),
        );
    }
}

fn queries(plan: &mut Plan, library: &str) {
    plan.add(
        Case::compute("texture.queries", library, "queries", [1, 1, 1], [1, 1, 1])
            .buffer(Buffer::zeroed("out", 0, 48))
            .output(
                Output::new("out", Dtype::U32, Tolerance::default())
                    .expect_same(u32s(&[64, 32, 6, 16, 8, 16, 8, 4, 5, 16, 16, 5])),
            )
            .texture(Texture::d2("a", "rgba8unorm", 64, 32).index(0).mipmaps(6))
            .texture(Texture::new("b", "rgba8unorm", "3d", [16, 8, 4]).index(1))
            .texture(
                Texture::new("c", "rgba8unorm", "2d_array", [32, 16, 1])
                    .index(2)
                    .array(5)
                    .mipmaps(2),
            )
            .texture(
                Texture::new("d", "rgba8unorm", "cube", [16, 16, 1])
                    .index(3)
                    .mipmaps(5),
            ),
    );
}

/// A direction to the centre of texel (i, j) of a cube face of n texels,
/// scaled by `length`: the inverse of `cube`'s face selection.
fn cube_direction(face: usize, i: i64, j: i64, n: i64, length: f64) -> [f64; 3] {
    let s = 2.0 * (i as f64 + 0.5) / n as f64 - 1.0;
    let t = 2.0 * (j as f64 + 0.5) / n as f64 - 1.0;
    let d = match face {
        0 => [1.0, -t, -s],
        1 => [-1.0, -t, s],
        2 => [s, 1.0, t],
        3 => [s, -1.0, -t],
        4 => [s, -t, 1.0],
        _ => [-s, -t, -1.0],
    };
    d.map(|c| f32r(c * length))
}

/// The cases above on the other texture types: gathers of arrays and
/// depth, depth arrays and cubes, cube arrays, 1D arrays, writes of cubes
/// and 1D textures, and queries of every type.
fn variants(plan: &mut Plan, library: &str, rng: &mut Random) {
    let f = format_named("rgba8unorm");
    let nearest = json!({"name": "s", "index": 0, "min": "nearest", "mag": "nearest"});
    let (w, h, slices) = (8i64, 8i64, 3usize);
    // Texel corners, where gathers' four taps are unambiguous.
    let corners: Vec<(f64, f64, usize)> = (0..256)
        .map(|_| {
            let x = (rng.below((w - 1) as u32) + 1) as f64 / w as f64;
            let y = (rng.below((h - 1) as u32) + 1) as f64 / h as f64;
            (f32r(x), f32r(y), rng.below(slices as u32) as usize)
        })
        .collect();
    let taps = |at: &dyn Fn(i64, i64, usize) -> f64, (u, v, slice): (f64, f64, usize)| {
        let (x0, y0) = (
            (u * w as f64 - 0.5).floor() as i64,
            (v * h as f64 - 0.5).floor() as i64,
        );
        [
            at(x0, y0 + 1, slice),
            at(x0 + 1, y0 + 1, slice),
            at(x0 + 1, y0, slice),
            at(x0, y0, slice),
        ]
    };
    let coords: Vec<f64> = corners
        .iter()
        .flat_map(|&(u, v, s)| [u, v, 0.0, s as f64])
        .collect();
    let texels = make_texels(&f, (w * h) as usize * slices, rng);
    let decoded: Vec<Texel> = texels.iter().map(|t| decode(&f, t)).collect();
    let lane_y = |x: i64, y: i64, s: usize| decoded[s * (w * h) as usize + (y * w + x) as usize][1];
    let expected: Vec<f64> = corners
        .iter()
        .flat_map(|&c| taps(&lane_y, c))
        .map(f32r)
        .collect();
    let one = Tolerance::ulp(1.0);
    plan.add(
        Case::compute1(
            "texture.gather.type_2d_array",
            library,
            "gather2d_array",
            256,
        )
        .buffer(Buffer::data("coords", 0, f32s(&coords)))
        .buffer(Buffer::zeroed("out", 1, 256 * 16))
        .output(Output::new("out", Dtype::F32, one.clone()).expect(f32s(&expected), one))
        .texture(
            Texture::new("t", "rgba8unorm", "2d_array", [w as u32, h as u32, 1])
                .index(0)
                .array(slices as u32)
                .data(texels.concat()),
        )
        .sampler(json!({"name": "s", "index": 0, "min": "linear", "mag": "linear"})),
    );
    let depths: Vec<f64> = (0..(w * h) as usize * slices)
        .map(|_| f32r(rng.uniform(0.0, 1.0)))
        .collect();
    let depth = |x: i64, y: i64, s: usize| depths[s * (w * h) as usize + (y * w + x) as usize];
    let depth_array = || {
        Texture::new("t", "depth32float", "2d_array", [w as u32, h as u32, 1])
            .index(0)
            .array(slices as u32)
            .data(f32s(&depths))
    };
    let first: Vec<f64> = corners
        .iter()
        .flat_map(|&(u, v, _)| taps(&depth, (u, v, 0)))
        .collect();
    let flat: Vec<f64> = corners
        .iter()
        .flat_map(|&(u, v, _)| [u, v, 0.0, 0.0])
        .collect();
    plan.add(
        Case::compute1("texture.gather.depth", library, "gather_depth", 256)
            .buffer(Buffer::data("coords", 0, f32s(&flat)))
            .buffer(Buffer::zeroed("out", 1, 256 * 16))
            .output(Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&first)))
            .texture(
                t2d("t", "depth32float", w as u32, h as u32)
                    .data(f32s(&depths[..(w * h) as usize])),
            )
            .sampler(nearest.clone()),
    );
    let expected: Vec<f64> = corners.iter().flat_map(|&c| taps(&depth, c)).collect();
    plan.add(
        Case::compute1(
            "texture.gather.depth_2d_array",
            library,
            "gather_depth_array",
            256,
        )
        .buffer(Buffer::data("coords", 0, f32s(&coords)))
        .buffer(Buffer::zeroed("out", 1, 256 * 16))
        .output(Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected)))
        .texture(depth_array())
        .sampler(nearest.clone()),
    );
    // Texel centres of a depth array, sampled, compared and read.
    let centres: Vec<(i64, i64, usize, f64)> = (0..256)
        .map(|_| {
            (
                rng.below(w as u32),
                rng.below(h as u32),
                rng.below(slices as u32) as usize,
                f32r(rng.uniform(0.0, 1.0)),
            )
        })
        .collect();
    let coords: Vec<f64> = centres
        .iter()
        .flat_map(|&(x, y, s, r)| {
            [
                (x as f64 + 0.5) / w as f64,
                (y as f64 + 0.5) / h as f64,
                r,
                s as f64,
            ]
            .map(f32r)
        })
        .collect();
    let values: Vec<f64> = centres.iter().map(|&(x, y, s, _)| depth(x, y, s)).collect();
    plan.add(
        Case::compute1(
            "texture.sample.depth_2d_array",
            library,
            "sample_depth_array",
            256,
        )
        .buffer(Buffer::data("coords", 0, f32s(&coords)))
        .buffer(Buffer::zeroed("out", 1, 256 * 4))
        .output(Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&values)))
        .texture(depth_array())
        .sampler(nearest.clone()),
    );
    let compared: Vec<f64> = centres
        .iter()
        .map(|&(x, y, s, r)| f64::from(u8::from(r < depth(x, y, s))))
        .collect();
    plan.add(
        Case::compute1(
            "texture.sample_compare.depth_2d_array",
            library,
            "sample_compare_array",
            256,
        )
        .buffer(Buffer::data("coords", 0, f32s(&coords)))
        .buffer(Buffer::zeroed("out", 1, 256 * 4))
        .output(Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&compared)))
        .texture(depth_array())
        .sampler(
            json!({"name": "s", "index": 0, "min": "nearest", "mag": "nearest", "compare": "less"}),
        ),
    );
    let points: Vec<u32> = centres
        .iter()
        .flat_map(|&(x, y, s, _)| [x as u32, y as u32, s as u32, 0])
        .collect();
    plan.add(
        Case::compute1(
            "texture.read.depth_2d_array",
            library,
            "read_depth_array",
            256,
        )
        .buffer(Buffer::data("coords", 0, u32s(&points)))
        .buffer(Buffer::zeroed("out", 1, 256 * 4))
        .output(Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&values)))
        .texture(depth_array()),
    );
    // Cube texel centres along unnormalized directions, sampled nearest.
    let n = 4i64;
    let per_face = (n * n) as usize;
    let cube_points: Vec<(usize, usize, i64, i64, f64)> = (0..256)
        .map(|_| {
            let face = rng.below(6) as usize;
            (
                rng.below(2) as usize,
                face,
                rng.below(n as u32),
                rng.below(n as u32),
                rng.uniform(0.5, 3.0),
            )
        })
        .collect();
    let coords: Vec<f64> = cube_points
        .iter()
        .flat_map(|&(cube, face, i, j, length)| {
            let d = cube_direction(face, i, j, n, length);
            [d[0], d[1], d[2], cube as f64]
        })
        .collect();
    let cube_depths: Vec<f64> = (0..per_face * 6)
        .map(|_| f32r(rng.uniform(0.0, 1.0)))
        .collect();
    let expected: Vec<f64> = cube_points
        .iter()
        .map(|&(_, face, i, j, _)| cube_depths[face * per_face + (j * n + i) as usize])
        .collect();
    plan.add(
        Case::compute1(
            "texture.sample.depth_cube",
            library,
            "sample_depth_cube",
            256,
        )
        .buffer(Buffer::data("coords", 0, f32s(&coords)))
        .buffer(Buffer::zeroed("out", 1, 256 * 4))
        .output(Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected)))
        .texture(
            Texture::new("t", "depth32float", "cube", [n as u32, n as u32, 1])
                .index(0)
                .data(f32s(&cube_depths)),
        )
        .sampler(nearest.clone()),
    );
    let cube_texels = make_texels(&f, per_face * 12, rng);
    let expected: Vec<f64> = cube_points
        .iter()
        .flat_map(|&(cube, face, i, j, _)| {
            decode(
                &f,
                &cube_texels[(cube * 6 + face) * per_face + (j * n + i) as usize],
            )
        })
        .map(f32r)
        .collect();
    let one = Tolerance::ulp(1.0);
    plan.add(
        Case::compute1(
            "texture.sample.type_cube_array",
            library,
            "samplecube_array",
            256,
        )
        .buffer(Buffer::data("coords", 0, f32s(&coords)))
        .buffer(Buffer::zeroed("out", 1, 256 * 16))
        .output(Output::new("out", Dtype::F32, one.clone()).expect(f32s(&expected), one))
        .texture(
            Texture::new("t", "rgba8unorm", "cube_array", [n as u32, n as u32, 1])
                .index(0)
                .array(2)
                .data(cube_texels.concat()),
        )
        .sampler(nearest.clone()),
    );
    // A 1D array sampled linearly with repeat.
    let lin = Sampler::new("lin", "linear", "repeat");
    let row = 32i64;
    let texels = make_texels(&f, row as usize * slices, rng);
    let decoded: Vec<Texel> = texels.iter().map(|t| decode(&f, t)).collect();
    let pts: Vec<(f64, usize)> = (0..256)
        .map(|_| {
            (
                f32r(rng.uniform(-1.5, 1.5)),
                rng.below(slices as u32) as usize,
            )
        })
        .collect();
    let expected: Vec<f64> = pts
        .iter()
        .flat_map(|&(x, s)| {
            let image = [level(
                row,
                1,
                decoded[s * row as usize..(s + 1) * row as usize].to_vec(),
            )];
            sample(&image, &lin, [x, 0.0, 0.0], 0.0, 1)
        })
        .map(f32r)
        .collect();
    let coords: Vec<f64> = pts
        .iter()
        .flat_map(|&(x, s)| [x, 0.0, 0.0, s as f64])
        .collect();
    let tol = filter();
    plan.add(
        Case::compute1(
            "texture.sample.type_1d_array",
            library,
            "sample1d_array",
            256,
        )
        .buffer(Buffer::data("coords", 0, f32s(&coords)))
        .buffer(Buffer::zeroed("out", 1, 256 * 16))
        .output(Output::new("out", Dtype::F32, tol.clone()).expect(f32s(&expected), tol))
        .texture(
            Texture::new("t", "rgba8unorm", "1d_array", [row as u32, 1, 1])
                .index(0)
                .array(slices as u32)
                .data(texels.concat()),
        )
        .sampler(lin.json()),
    );
    // Writes: a cube's faces, a 1D texture and a 1D array.
    for (kind, size, array, grid, group, function) in [
        (
            "cube",
            [8u32, 8, 1],
            1u32,
            [8u32, 8, 6],
            [8u32, 8, 1],
            "writecube",
        ),
        ("1d", [64, 1, 1], 1, [64, 1, 1], [16, 1, 1], "write1d"),
        (
            "1d_array",
            [16, 1, 1],
            4,
            [16, 4, 1],
            [16, 1, 1],
            "write1d_array",
        ),
    ] {
        let count = grid.iter().product::<u32>() as usize;
        let values: Vec<f64> = (0..count * 4)
            .map(|_| f32r(rng.uniform(-1.0, 1.0)))
            .collect();
        plan.add(
            Case::compute(
                &format!("texture.write.type_{kind}"),
                library,
                function,
                grid,
                group,
            )
            .dispatch_threads()
            .buffer(Buffer::data("values", 0, f32s(&values)))
            .output(Output::new("t", Dtype::F32, Tolerance::exact()).expect_same(f32s(&values)))
            .texture(
                Texture::new("t", "rgba32float", kind, size)
                    .index(0)
                    .array(array)
                    .usage(&["read", "write"]),
            ),
        );
    }
    plan.add(
        Case::compute(
            "texture.queries.types",
            library,
            "queries_types",
            [1, 1, 1],
            [1, 1, 1],
        )
        .buffer(Buffer::zeroed("out", 0, 80))
        .output(
            Output::new("out", Dtype::U32, Tolerance::exact()).expect_same(u32s(&[
                24, 12, 3, 12, 8, 3, 4, 16, 8, 4, 5, 16, 2, 40, 3, 20, 10, 3, 4, 2,
            ])),
        )
        .texture(Texture::d2("d", "depth32float", 24, 12).index(0).mipmaps(3))
        .texture(
            Texture::new("ca", "rgba8unorm", "cube_array", [8, 8, 1])
                .index(1)
                .array(3)
                .mipmaps(4),
        )
        .texture(
            Texture::new("ms", "rgba8unorm", "2d_ms", [16, 8, 1])
                .index(2)
                .samples(4)
                .usage(&["read", "render"]),
        )
        .texture(
            Texture::new("ta", "rgba8unorm", "2d_array", [32, 16, 1])
                .index(3)
                .array(2)
                .mipmaps(5),
        )
        .texture(
            Texture::new("dc", "depth32float", "cube", [16, 16, 1])
                .index(4)
                .mipmaps(2),
        )
        .texture(Texture::new("t1", "rgba8unorm", "1d", [40, 1, 1]).index(5))
        .texture(
            Texture::new("t3", "rgba8unorm", "3d", [16, 8, 4])
                .index(6)
                .mipmaps(3),
        )
        .texture(
            Texture::new("da", "depth32float", "2d_array", [20, 10, 1])
                .index(7)
                .array(3)
                .mipmaps(2),
        )
        .texture(Texture::new("tc", "rgba8unorm", "cube", [4, 4, 1]).index(8)),
    );
}

pub fn build(plan: &mut Plan) {
    let library = plan.library("textures", SOURCE, &[], super::plan::LATEST);
    reads(plan, &library);
    sampling(plan, &library);
    writes(plan, &library);
    queries(plan, &library);
    variants(plan, &library, &mut Random::new(907));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::metal_suite::values::f16_bits;

    #[test]
    fn address_modes_fold_coordinates() {
        assert_eq!(address(-1, 4, "repeat"), Some(3));
        assert_eq!(address(-1, 4, "mirror_repeat"), Some(0));
        assert_eq!(address(5, 4, "mirror_repeat"), Some(2));
        assert_eq!(address(-3, 4, "mirror_clamp_to_edge"), Some(2));
        assert_eq!(address(9, 4, "mirror_clamp_to_edge"), Some(3));
        assert_eq!(address(4, 4, "clamp_to_border"), None);
    }

    #[test]
    fn half_round_trips() {
        assert_eq!(f16_bits(f16_from_bits(0x3555)), 0x3555);
    }
}
