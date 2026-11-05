//! Block-compressed formats: random blocks of each BC format a texture is
//! read from texel by texel, decoded as the BC specification (Direct3D's
//! functional specification of BC1 to BC7, which Metal's formats follow)
//! fixes them. Endpoint interpolation rounds as each decoder chooses, so
//! normalized results are held to two steps of their endpoints' precision.
use super::plan::{Buffer, Case, Output, Plan, Texture, Tolerance};
use super::textures::srgb;
use super::values::{Dtype, Random, f16_from_bits, f32s};

type Texel = [f64; 4];

fn bits(block: &[u8], at: usize, count: usize) -> u64 {
    (0..count).fold(0, |v, k| {
        let bit = at + k;
        v | (u64::from(block[bit / 8] >> (bit % 8) & 1) << k)
    })
}

fn rgb565(c: u64) -> [f64; 3] {
    let (r, g, b) = ((c >> 11) & 31, (c >> 5) & 63, c & 31);
    [r as f64 / 31.0, g as f64 / 63.0, b as f64 / 31.0]
}

fn mix(a: f64, b: f64, wb: f64) -> f64 {
    a * (1.0 - wb) + b * wb
}

/// A BC1 colour block's 16 texels; `four` forces the four-colour palette
/// that BC2 and BC3 always use.
fn bc1(block: &[u8], four: bool) -> Vec<Texel> {
    let (c0, c1) = (bits(block, 0, 16), bits(block, 16, 16));
    let (a, b) = (rgb565(c0), rgb565(c1));
    let palette: Vec<Texel> = if four || c0 > c1 {
        [0.0, 1.0, 1.0 / 3.0, 2.0 / 3.0]
            .iter()
            .map(|&w| {
                [
                    mix(a[0], b[0], w),
                    mix(a[1], b[1], w),
                    mix(a[2], b[2], w),
                    1.0,
                ]
            })
            .collect()
    } else {
        let half = [0.0, 1.0, 0.5].map(|w| {
            [
                mix(a[0], b[0], w),
                mix(a[1], b[1], w),
                mix(a[2], b[2], w),
                1.0,
            ]
        });
        vec![half[0], half[1], half[2], [0.0; 4]]
    };
    (0..16)
        .map(|i| palette[bits(block, 32 + 2 * i, 2) as usize])
        .collect()
}

/// A BC4 channel block's 16 values, unsigned or signed.
fn bc4(block: &[u8], signed: bool) -> Vec<f64> {
    let end = |v: u64| {
        if signed {
            (f64::from(v as u8 as i8)).max(-127.0) / 127.0
        } else {
            v as f64 / 255.0
        }
    };
    let (r0, r1) = (bits(block, 0, 8), bits(block, 8, 8));
    let (a, b) = (end(r0), end(r1));
    let greater = if signed {
        (r0 as u8 as i8) > (r1 as u8 as i8)
    } else {
        r0 > r1
    };
    let mut palette = vec![a, b];
    if greater {
        palette.extend((1..7).map(|k| mix(a, b, f64::from(k) / 7.0)));
    } else {
        palette.extend((1..5).map(|k| mix(a, b, f64::from(k) / 5.0)));
        palette.extend([if signed { -1.0 } else { 0.0 }, 1.0]);
    }
    (0..16)
        .map(|i| palette[bits(block, 16 + 3 * i, 3) as usize])
        .collect()
}

/// A BC7 mode 6 block: one subset, 7-bit RGBA endpoints with a p-bit
/// each, and 4-bit indices.
fn bc7_mode6(block: &[u8]) -> Vec<Texel> {
    const WEIGHTS: [u64; 16] = [0, 4, 9, 13, 17, 21, 26, 30, 34, 38, 43, 47, 51, 55, 60, 64];
    let mut at = 7;
    let mut take = |n: usize| {
        let v = bits(block, at, n);
        at += n;
        v
    };
    let mut e = [[0u64; 4]; 2];
    for c in 0..4 {
        for end in &mut e {
            end[c] = take(7);
        }
    }
    let p = [take(1), take(1)];
    for (end, p) in e.iter_mut().zip(p) {
        for c in end.iter_mut() {
            *c = *c << 1 | p;
        }
    }
    (0..16)
        .map(|i| {
            let w = WEIGHTS[take(if i == 0 { 3 } else { 4 }) as usize];
            [0, 1, 2, 3].map(|c| (((64 - w) * e[0][c] + w * e[1][c] + 32) >> 6) as f64 / 255.0)
        })
        .collect()
}

/// A BC6H mode 11 block: one region of untransformed 10-bit endpoints and
/// 4-bit indices, unsigned or signed, as half floats.
fn bc6h_mode11(block: &[u8], signed: bool) -> Vec<Texel> {
    const WEIGHTS: [i64; 16] = [0, 4, 9, 13, 17, 21, 26, 30, 34, 38, 43, 47, 51, 55, 60, 64];
    let field = |at: usize| {
        let v = bits(block, at, 10) as i64;
        if signed && v & 512 != 0 { v - 1024 } else { v }
    };
    let ends: [[i64; 3]; 2] = [
        [field(5), field(15), field(25)],
        [field(35), field(45), field(55)],
    ];
    let unquantize = |e: i64| -> i64 {
        if signed {
            let (s, a) = (e < 0, e.abs());
            let u = if a == 0 {
                0
            } else if a >= 511 {
                0x7FFF
            } else {
                ((a << 15) + 0x4000) >> 9
            };
            if s { -u } else { u }
        } else if e == 0 {
            0
        } else if e == 1023 {
            0xFFFF
        } else {
            ((e << 16) + 0x8000) >> 10
        }
    };
    let finish = |x: i64| -> u16 {
        if signed {
            if x < 0 {
                0x8000 | ((-x * 31) >> 5) as u16
            } else {
                ((x * 31) >> 5) as u16
            }
        } else {
            ((x * 31) >> 6) as u16
        }
    };
    let mut at = 65;
    (0..16)
        .map(|i| {
            let n = if i == 0 { 3 } else { 4 };
            let w = WEIGHTS[bits(block, at, n) as usize];
            at += n;
            let mut t = [1.0; 4];
            for c in 0..3 {
                let (a, b) = (unquantize(ends[0][c]), unquantize(ends[1][c]));
                let x = ((64 - w) * a + w * b + 32) >> 6;
                t[c] = f16_from_bits(finish(x));
            }
            t
        })
        .collect()
}

struct Format {
    name: &'static str,
    bytes: usize,
    half: bool,
    decode: fn(&[u8]) -> Vec<Texel>,
}

fn with_srgb(t: Vec<Texel>) -> Vec<Texel> {
    t.into_iter()
        .map(|[r, g, b, a]| [srgb(r), srgb(g), srgb(b), a])
        .collect()
}

fn bc2(block: &[u8]) -> Vec<Texel> {
    let mut t = bc1(&block[8..], true);
    for (i, texel) in t.iter_mut().enumerate() {
        texel[3] = bits(block, 4 * i, 4) as f64 / 15.0;
    }
    t
}

fn bc3(block: &[u8]) -> Vec<Texel> {
    let alpha = bc4(&block[..8], false);
    let mut t = bc1(&block[8..], true);
    for (texel, a) in t.iter_mut().zip(alpha) {
        texel[3] = a;
    }
    t
}

fn bc5(block: &[u8], signed: bool) -> Vec<Texel> {
    let (r, g) = (bc4(&block[..8], signed), bc4(&block[8..], signed));
    r.into_iter()
        .zip(g)
        .map(|(r, g)| [r, g, 0.0, 1.0])
        .collect()
}

fn formats() -> Vec<Format> {
    let f = |name, bytes, half, decode| Format {
        name,
        bytes,
        half,
        decode,
    };
    vec![
        f("bc1_rgba", 8, false, |b| bc1(b, false)),
        f("bc1_rgba_srgb", 8, false, |b| with_srgb(bc1(b, false))),
        f("bc2_rgba", 16, false, bc2),
        f("bc2_rgba_srgb", 16, false, |b| with_srgb(bc2(b))),
        f("bc3_rgba", 16, false, bc3),
        f("bc3_rgba_srgb", 16, false, |b| with_srgb(bc3(b))),
        f("bc4_runorm", 8, false, |b| {
            bc4(b, false)
                .into_iter()
                .map(|r| [r, 0.0, 0.0, 1.0])
                .collect()
        }),
        f("bc4_rsnorm", 8, false, |b| {
            bc4(b, true)
                .into_iter()
                .map(|r| [r, 0.0, 0.0, 1.0])
                .collect()
        }),
        f("bc5_rgunorm", 16, false, |b| bc5(b, false)),
        f("bc5_rgsnorm", 16, false, |b| bc5(b, true)),
        f("bc6h_rgbufloat", 16, true, |b| bc6h_mode11(b, false)),
        f("bc6h_rgbfloat", 16, true, |b| bc6h_mode11(b, true)),
        f("bc7_rgbaunorm", 16, false, bc7_mode6),
        f("bc7_rgbaunorm_srgb", 16, false, |b| with_srgb(bc7_mode6(b))),
    ]
}

/// A random block of a format, in the mode the decoder above reads.
fn block(f: &Format, rng: &mut Random) -> Vec<u8> {
    let mut b: Vec<u8> = (0..f.bytes).map(|_| (rng.u32() % 256) as u8).collect();
    if f.name.starts_with("bc7") {
        b[0] = (b[0] & 0x80) | 0x40;
    }
    if f.name.starts_with("bc6h") {
        b[0] = (b[0] & 0xE0) | 0x03;
    }
    b
}

pub fn build(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(4093);
    let (w, h) = (8u32, 8u32);
    for f in formats() {
        let blocks: Vec<Vec<u8>> = (0..(w / 4) * (h / 4))
            .map(|_| block(&f, &mut rng))
            .collect();
        let decoded: Vec<Vec<Texel>> = blocks.iter().map(|b| (f.decode)(b)).collect();
        let mut points = vec![];
        let mut expect = vec![];
        for y in 0..h {
            for x in 0..w {
                points.extend([x, y, 0, 0]);
                let block = (y / 4 * (w / 4) + x / 4) as usize;
                expect.extend(decoded[block][((y % 4) * 4 + x % 4) as usize]);
            }
        }
        // Two steps of the endpoints' precision, through the sRGB curve's
        // steepest slope for sRGB formats.
        let tol = if f.half {
            Tolerance::ulp(1.0)
        } else if f.name.ends_with("srgb") {
            Tolerance::abs(0.02)
        } else if f.name.contains("snorm") {
            Tolerance::abs(2.0 / 127.0)
        } else {
            Tolerance::abs(2.0 / 255.0)
        }
        .with_ftz(false);
        plan.add(
            Case::compute1(
                &format!("texture.compressed.{}", f.name),
                library,
                "read2d_float",
                w * h,
            )
            .requires(&[], &["bc_compression"])
            .buffer(Buffer::data(
                "coords",
                0,
                points.iter().flat_map(|v: &u32| v.to_le_bytes()).collect(),
            ))
            .buffer(Buffer::zeroed("out", 1, (w * h * 16) as usize))
            .output(Output::new("out", Dtype::F32, tol.clone()).expect(f32s(&expect), tol))
            .texture(
                Texture::d2("t", f.name, w, h)
                    .index(0)
                    .data(blocks.concat()),
            ),
        );
    }
}
