//! Block-compressed formats: random blocks of each BC format a texture is
//! read from texel by texel, decoded as the BC specification (Direct3D's
//! functional specification of BC1 to BC7, which Metal's formats follow)
//! fixes them. Endpoint interpolation rounds as each decoder chooses, so
//! normalized results are held to two steps of their endpoints' precision.
//! ETC2 and EAC blocks, which the Khronos Data Format Specification decodes
//! exactly, and PVRTC ones, which Apple's GPUs decode as Imagination's
//! decompressor does, are held to a fraction of a step.
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

/// An ETC2 or EAC block as the big-endian 64-bit word the Khronos Data
/// Format Specification numbers its bits in.
fn big_endian(block: &[u8]) -> u64 {
    block[..8].iter().fold(0, |v, &b| v << 8 | u64::from(b))
}

fn field(v: u64, high: u32, low: u32) -> i32 {
    ((v >> low) & ((1 << (high - low + 1)) - 1)) as i32
}

fn extend(v: i32, bits: u32) -> i32 {
    v << (8 - bits) | v >> (2 * bits - 8)
}

const ETC_DISTANCES: [i32; 8] = [3, 6, 11, 16, 23, 32, 41, 64];

/// An ETC2 RGB block's texels in rows, 8-bit codes; a punch-through
/// block's transparent texels are all zero.
fn etc2_codes(block: &[u8], punch_through: bool) -> Vec<[i32; 4]> {
    const MODIFIERS: [[i32; 2]; 8] = [
        [2, 8],
        [5, 17],
        [9, 29],
        [13, 42],
        [18, 60],
        [24, 80],
        [33, 106],
        [47, 183],
    ];
    let v = big_endian(block);
    let (diff, flip) = (field(v, 33, 33) == 1, field(v, 32, 32) == 1);
    let opaque = !punch_through || diff;
    let (r, g, b) = (field(v, 63, 59), field(v, 55, 51), field(v, 47, 43));
    let (dr, dg, db) = [field(v, 58, 56), field(v, 50, 48), field(v, 42, 40)]
        .map(|d| if d & 4 != 0 { d - 8 } else { d })
        .into();
    let outside = |c: i32| !(0..=31).contains(&c);
    let mut texels = Vec::new();
    for y in 0..4u32 {
        for x in 0..4u32 {
            let p = x * 4 + y;
            let index = (field(v, p + 16, p + 16) << 1 | field(v, p, p)) as usize;
            let sub = if flip { y >= 2 } else { x >= 2 };
            let planar =
                (punch_through || diff) && !outside(r + dr) && !outside(g + dg) && outside(b + db);
            let color: [i32; 3] = if !punch_through && !diff {
                let shift = |c: u32| 63 - 8 * c - 4 * u32::from(sub);
                let base = [0, 1, 2].map(|c| extend(field(v, shift(c), shift(c) - 3), 4));
                let table = if sub {
                    field(v, 36, 34)
                } else {
                    field(v, 39, 37)
                } as usize;
                let m = MODIFIERS[table][index & 1] * if index & 2 != 0 { -1 } else { 1 };
                base.map(|c| c + m)
            } else if outside(r + dr) {
                let c0 = [
                    field(v, 60, 59) << 2 | field(v, 57, 56),
                    field(v, 55, 52),
                    field(v, 51, 48),
                ]
                .map(|c| extend(c, 4));
                let c1 =
                    [field(v, 47, 44), field(v, 43, 40), field(v, 39, 36)].map(|c| extend(c, 4));
                let d = ETC_DISTANCES[(field(v, 35, 34) << 1 | field(v, 32, 32)) as usize];
                [0, 1, 2].map(|c| [c0[c], c1[c] + d, c1[c], c1[c] - d][index])
            } else if outside(g + dg) {
                let c0 = [
                    field(v, 62, 59),
                    field(v, 58, 56) << 1 | field(v, 52, 52),
                    field(v, 51, 51) << 3 | field(v, 49, 47),
                ];
                let c1 = [field(v, 46, 43), field(v, 42, 39), field(v, 38, 35)];
                let key = |c: [i32; 3]| c[0] << 8 | c[1] << 4 | c[2];
                let order = i32::from(key(c0) >= key(c1));
                let d =
                    ETC_DISTANCES[(field(v, 34, 34) << 2 | field(v, 32, 32) << 1 | order) as usize];
                let (c0, c1) = (c0.map(|c| extend(c, 4)), c1.map(|c| extend(c, 4)));
                [0, 1, 2].map(|c| [c0[c] + d, c0[c] - d, c1[c] + d, c1[c] - d][index])
            } else if planar {
                let o = [
                    extend(field(v, 62, 57), 6),
                    extend(field(v, 56, 56) << 6 | field(v, 54, 49), 7),
                    extend(
                        field(v, 48, 48) << 5 | field(v, 44, 43) << 3 | field(v, 41, 39),
                        6,
                    ),
                ];
                let h = [
                    extend(field(v, 38, 34) << 1 | field(v, 32, 32), 6),
                    extend(field(v, 31, 25), 7),
                    extend(field(v, 24, 19), 6),
                ];
                let w = [
                    extend(field(v, 18, 13), 6),
                    extend(field(v, 12, 6), 7),
                    extend(field(v, 5, 0), 6),
                ];
                let (x, y) = (x as i32, y as i32);
                [0, 1, 2].map(|c| (x * (h[c] - o[c]) + y * (w[c] - o[c]) + 4 * o[c] + 2) >> 2)
            } else {
                let base = if sub {
                    [r + dr, g + dg, b + db]
                } else {
                    [r, g, b]
                }
                .map(|c| extend(c, 5));
                let table = if sub {
                    field(v, 36, 34)
                } else {
                    field(v, 39, 37)
                } as usize;
                let mut m = MODIFIERS[table][index & 1] * if index & 2 != 0 { -1 } else { 1 };
                if !opaque && index & 1 == 0 {
                    m = 0;
                }
                base.map(|c| c + m)
            };
            let color = color.map(|c| c.clamp(0, 255));
            texels.push(if !opaque && !planar && index == 2 {
                [0; 4]
            } else {
                [color[0], color[1], color[2], 255]
            });
        }
    }
    texels
}

const ALPHA_MODIFIERS: [[i32; 8]; 16] = [
    [-3, -6, -9, -15, 2, 5, 8, 14],
    [-3, -7, -10, -13, 2, 6, 9, 12],
    [-2, -5, -8, -13, 1, 4, 7, 12],
    [-2, -4, -6, -13, 1, 3, 5, 12],
    [-3, -6, -8, -12, 2, 5, 7, 11],
    [-3, -7, -9, -11, 2, 6, 8, 10],
    [-4, -7, -8, -11, 3, 6, 7, 10],
    [-3, -5, -8, -11, 2, 4, 7, 10],
    [-2, -6, -8, -10, 1, 5, 7, 9],
    [-2, -5, -8, -10, 1, 4, 7, 9],
    [-2, -4, -8, -10, 1, 3, 7, 9],
    [-2, -5, -7, -10, 1, 4, 6, 9],
    [-3, -4, -7, -10, 2, 3, 6, 9],
    [-1, -2, -3, -10, 0, 1, 2, 9],
    [-4, -6, -8, -9, 3, 5, 7, 8],
    [-3, -5, -7, -9, 2, 4, 6, 8],
];

/// An ETC2 alpha or EAC block's base, multiplier and modifier per texel,
/// in rows.
fn eac_parts(block: &[u8]) -> Vec<(i32, i32, i32)> {
    let v = big_endian(block);
    let table = &ALPHA_MODIFIERS[field(v, 51, 48) as usize];
    (0..16u32)
        .map(|i| {
            let p = i % 4 * 4 + i / 4;
            let index = field(v, 47 - 3 * p, 45 - 3 * p) as usize;
            (field(v, 63, 56), field(v, 55, 52), table[index])
        })
        .collect()
}

/// An EAC R11 block's values in rows.
fn eac(block: &[u8], signed: bool) -> Vec<f64> {
    eac_parts(block)
        .into_iter()
        .map(|(base, multiplier, modifier)| {
            let multiplier = if multiplier == 0 { 1 } else { multiplier * 8 };
            if signed {
                let base = (base as u8 as i8).max(-127) as i32;
                f64::from((base * 8 + modifier * multiplier).clamp(-1023, 1023)) / 1023.0
            } else {
                f64::from((base * 8 + 4 + modifier * multiplier).clamp(0, 2047)) / 2047.0
            }
        })
        .collect()
}

fn etc2(block: &[u8], punch_through: bool) -> Vec<Texel> {
    etc2_codes(block, punch_through)
        .into_iter()
        .map(|c| c.map(|c| f64::from(c) / 255.0))
        .collect()
}

fn etc2_eac(block: &[u8]) -> Vec<Texel> {
    let alpha = eac_parts(&block[..8]);
    etc2(&block[8..], false)
        .into_iter()
        .zip(alpha)
        .map(|([r, g, b, _], (base, multiplier, modifier))| {
            [
                r,
                g,
                b,
                f64::from((base + modifier * multiplier).clamp(0, 255)) / 255.0,
            ]
        })
        .collect()
}

fn eac_rg(block: &[u8], signed: bool) -> Vec<Texel> {
    eac(&block[..8], signed)
        .into_iter()
        .zip(eac(&block[8..], signed))
        .map(|(r, g)| [r, g, 0.0, 1.0])
        .collect()
}

fn eac_r(block: &[u8], signed: bool) -> Vec<Texel> {
    eac(block, signed)
        .into_iter()
        .map(|r| [r, 0.0, 0.0, 1.0])
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
        f("etc2_rgb8", 8, false, |b| etc2(b, false)),
        f("etc2_rgb8_srgb", 8, false, |b| with_srgb(etc2(b, false))),
        f("etc2_rgb8a1", 8, false, |b| etc2(b, true)),
        f("etc2_rgb8a1_srgb", 8, false, |b| with_srgb(etc2(b, true))),
        f("eac_rgba8", 16, false, etc2_eac),
        f("eac_rgba8_srgb", 16, false, |b| with_srgb(etc2_eac(b))),
        f("eac_r11unorm", 8, false, |b| eac_r(b, false)),
        f("eac_r11snorm", 8, false, |b| eac_r(b, true)),
        f("eac_rg11unorm", 16, false, |b| eac_rg(b, false)),
        f("eac_rg11snorm", 16, false, |b| eac_rg(b, true)),
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

/// A PVRTC level's block at column x, row y: Morton order, y's bits in
/// the even places, the longer side's rest above the interleaved bits.
pub(super) fn twiddle(columns: u32, rows: u32, x: u32, y: u32) -> usize {
    let smaller = columns.min(rows);
    let (mut out, mut shift) = (0, 0);
    while 1 << shift < smaller {
        out |= (y >> shift & 1) << (2 * shift) | (x >> shift & 1) << (2 * shift + 1);
        shift += 1;
    }
    (out | (if columns > rows { x } else { y } >> shift) << (2 * shift)) as usize
}

/// A PVRTC block's two colors, 5 bits a color channel and 4 of alpha.
fn pvrtc_colors(block: u64) -> [[i32; 4]; 2] {
    let w4 = |v: u32| (v << 1 | v >> 3) as i32;
    let color = (block >> 32) as u32;
    let (a, b) = (color & 0xffff, color >> 16);
    let first = if a & 0x8000 != 0 {
        [
            (a >> 10 & 31) as i32,
            (a >> 5 & 31) as i32,
            w4(a >> 1 & 15),
            15,
        ]
    } else {
        let blue = a >> 1 & 7;
        [
            w4(a >> 8 & 15),
            w4(a >> 4 & 15),
            (blue << 2 | blue >> 1) as i32,
            ((a >> 12 & 7) << 1) as i32,
        ]
    };
    let second = if b & 0x8000 != 0 {
        [
            (b >> 10 & 31) as i32,
            (b >> 5 & 31) as i32,
            (b & 31) as i32,
            15,
        ]
    } else {
        [
            w4(b >> 8 & 15),
            w4(b >> 4 & 15),
            w4(b & 15),
            ((b >> 12 & 7) << 1) as i32,
        ]
    };
    [first, second]
}

const PVRTC_WEIGHTS: [i32; 4] = [0, 3, 5, 8];

/// A 2-bpp block's weight at x, y and how it weighs the texels it stores
/// none for: 0 not at all, 1 from four neighbors, 2 across, 3 along.
fn pvrtc2_value(block: u64, x: u32, y: u32) -> (i32, u32) {
    let mut bits = block as u32;
    if block >> 32 & 1 == 0 {
        return (if bits >> (y * 8 + x) & 1 != 0 { 8 } else { 0 }, 0);
    }
    let mut mode = 1;
    if bits & 1 != 0 {
        mode = if bits & 1 << 20 != 0 { 3 } else { 2 };
        bits = if bits & 1 << 21 != 0 {
            bits | 1 << 20
        } else {
            bits & !(1 << 20)
        };
    }
    bits = if bits & 2 != 0 { bits | 1 } else { bits & !1 };
    (
        PVRTC_WEIGHTS[(bits >> (2 * (y * 4 + x / 2)) & 3) as usize],
        mode,
    )
}

/// A PVRTC level's texels in rows, as Imagination's decompressor and
/// Apple's GPUs decode them: each texel blends the colors of the four
/// blocks whose centers surround it, wrapping, and its block's modulation
/// weighs the two.
fn pvrtc(blocks: &[u8], size: u32, two_bpp: bool) -> Vec<[i32; 4]> {
    let width = if two_bpp { 8 } else { 4 };
    let (columns, rows) = (size.div_ceil(width).max(1), size.div_ceil(4).max(1));
    let block = |x: u32, y: u32| {
        let at = 8 * twiddle(columns, rows, x % columns, y % rows);
        u64::from_le_bytes(blocks[at..at + 8].try_into().unwrap())
    };
    let mut texels = Vec::new();
    for y in 0..size {
        for x in 0..size {
            let (sx, sy) = (x + columns * width - width / 2, y + rows * 4 - 2);
            let (px, py, lx, ly) = (sx / width, sy / 4, sx % width, sy % 4);
            let quad = [
                block(px, py),
                block(px + 1, py),
                block(px, py + 1),
                block(px + 1, py + 1),
            ];
            let weights = [
                (width - lx) * (4 - ly),
                lx * (4 - ly),
                (width - lx) * ly,
                lx * ly,
            ];
            let mut sums = [[0i32; 4]; 2];
            for (block, weight) in quad.iter().zip(weights) {
                for (sum, color) in sums.iter_mut().zip(pvrtc_colors(*block)) {
                    for c in 0..4 {
                        sum[c] += weight as i32 * color[c];
                    }
                }
            }
            let (qx, qy) = (lx + width / 2, ly + 2);
            let (weight, punch) = if two_bpp {
                let at = |x: u32, y: u32| {
                    pvrtc2_value(
                        quad[(usize::from(y >= 4) * 2) + usize::from(x >= 8)],
                        x % 8,
                        y % 4,
                    )
                };
                let (stored, mode) = at(qx, qy);
                let (l, r, u, d) = (
                    at(qx - 1, qy).0,
                    at(qx + 1, qy).0,
                    at(qx, qy - 1).0,
                    at(qx, qy + 1).0,
                );
                let weight = match mode {
                    _ if mode == 0 || (qx ^ qy) & 1 == 0 => stored,
                    1 => (l + r + u + d + 2) / 4,
                    2 => (l + r + 1) / 2,
                    _ => (u + d + 1) / 2,
                };
                (weight, false)
            } else {
                let own = quad[usize::from(qy >= 4) * 2 + usize::from(qx >= 4)];
                let value = (own as u32 >> (2 * ((qy % 4) * 4 + qx % 4)) & 3) as usize;
                if own >> 32 & 1 != 0 {
                    ([0, 4, 4, 8][value], value == 2)
                } else {
                    (PVRTC_WEIGHTS[value], false)
                }
            };
            let mut texel = [0; 4];
            for c in 0..4 {
                let widen = |s: i32| match (c < 3, two_bpp) {
                    (true, false) => (s >> 1) + (s >> 6),
                    (true, true) => (s >> 2) + (s >> 7),
                    (false, false) => s + (s >> 4),
                    (false, true) => (s >> 1) + (s >> 5),
                };
                texel[c] = (widen(sums[0][c]) * (8 - weight) + widen(sums[1][c]) * weight) / 8;
            }
            if punch {
                texel[3] = 0;
            }
            texels.push(texel);
        }
    }
    texels
}

/// PVRTC textures of each format, square and a power of two. Shared ones
/// receive their level's blocks in its Morton order from the CPU; private
/// ones receive rows of blocks from a blit, which reorders them.
fn pvrtc_cases(plan: &mut Plan, library: &str, rng: &mut Random) {
    for (name, two_bpp, alpha, srgb) in [
        ("pvrtc_rgba_4bpp", false, true, false),
        ("pvrtc_rgba_4bpp_srgb", false, true, true),
        ("pvrtc_rgb_4bpp", false, false, false),
        ("pvrtc_rgb_4bpp_srgb", false, false, true),
        ("pvrtc_rgba_2bpp", true, true, false),
        ("pvrtc_rgba_2bpp_srgb", true, true, true),
        ("pvrtc_rgb_2bpp", true, false, false),
        ("pvrtc_rgb_2bpp_srgb", true, false, true),
    ] {
        let size = 16u32;
        let blocks: Vec<u8> = (0..size * size / if two_bpp { 4 } else { 2 })
            .map(|_| (rng.u32() % 256) as u8)
            .collect();
        let mut points = vec![];
        let mut expect = vec![];
        let (columns, rows) = (size / if two_bpp { 8 } else { 4 }, size / 4);
        let mut morton = blocks.clone();
        if !srgb {
            for y in 0..rows {
                for x in 0..columns {
                    let (to, from) = (
                        twiddle(columns, rows, x, y) * 8,
                        (y * columns + x) as usize * 8,
                    );
                    morton[to..to + 8].copy_from_slice(&blocks[from..from + 8]);
                }
            }
        }
        for (i, texel) in pvrtc(&morton, size, two_bpp).into_iter().enumerate() {
            let i = i as u32;
            points.extend([i % size, i / size, 0, 0]);
            let unorm = |c: i32| f64::from(c) / 255.0;
            let color = |c: i32| {
                if srgb {
                    super::textures::srgb(unorm(c))
                } else {
                    unorm(c)
                }
            };
            expect.extend([
                color(texel[0]),
                color(texel[1]),
                color(texel[2]),
                if alpha { unorm(texel[3]) } else { 1.0 },
            ]);
        }
        // Apple's decode is bit for bit Imagination's; its sRGB curve is
        // a table within 0.0002 of the exact one.
        let tol = Tolerance::abs(0.5 / 255.0).with_ftz(false);
        plan.add(
            Case::compute1(
                &format!("texture.compressed.{name}"),
                library,
                "read2d_float",
                size * size,
            )
            .requires(&["apple1"], &[])
            .buffer(Buffer::data(
                "coords",
                0,
                points.iter().flat_map(|v: &u32| v.to_le_bytes()).collect(),
            ))
            .buffer(Buffer::zeroed("out", 1, (size * size * 16) as usize))
            .output(Output::new("out", Dtype::F32, tol.clone()).expect(f32s(&expect), tol))
            .texture(storage(
                Texture::d2("t", name, size, size).index(0).data(blocks),
                srgb,
            )),
        );
    }
}

/// ASTC LDR textures of every block size, a block short of whole blocks on
/// each side, compared with Apple's decode: a legal block of a common mode
/// with one partition, one with up to four, a void extent and a random
/// block, mostly illegal. Apple returns a linear texel's top 12 bits of
/// the Khronos UNORM16 result and an sRGB texel's 8.
fn astc_cases(plan: &mut Plan, library: &str, rng: &mut Random) {
    const MODES: [u32; 12] = [
        0x0042, 0x0053, 0x0063, 0x0102, 0x0142, 0x0182, 0x0242, 0x0442, 0x0542, 0x0843, 0x0101,
        0x0151,
    ];
    let sizes = [
        (4, 4),
        (5, 4),
        (5, 5),
        (6, 5),
        (6, 6),
        (8, 5),
        (8, 6),
        (8, 8),
        (10, 5),
        (10, 6),
        (10, 8),
        (10, 10),
        (12, 10),
        (12, 12),
    ];
    for (i, (bw, bh)) in sizes.into_iter().enumerate() {
        for srgb in [false, true] {
            let name = format!("astc_{bw}x{bh}_{}", if srgb { "srgb" } else { "ldr" });
            let mut blocks = Vec::new();
            for kind in 0..4 {
                let mut words: [u32; 4] = std::array::from_fn(|_| rng.u32());
                match kind {
                    0 => words[0] = (words[0] & !0x1fff) | MODES[rng.u32() as usize % MODES.len()],
                    1 => words[0] = (words[0] & !0x7ff) | MODES[rng.u32() as usize % MODES.len()],
                    2 => {
                        words[0] = 0xffff_fdfc;
                        words[1] = u32::MAX;
                    }
                    _ => {}
                }
                blocks.extend(words.iter().flat_map(|w| w.to_le_bytes()));
            }
            let (width, height) = (2 * bw - 1, 2 * bh - 1);
            let points: Vec<u32> = (0..width * height)
                .flat_map(|i| [i % width, i / width, 0, 0])
                .collect();
            let tol = if srgb {
                Tolerance::abs(0.5 / 255.0)
            } else {
                // Apple's 12 bits, held widened to 16.
                Tolerance::abs(2e-5)
            }
            .with_ftz(false);
            plan.add(
                Case::compute1(
                    &format!("texture.compressed.{name}"),
                    library,
                    "read2d_float",
                    width * height,
                )
                .requires(&["apple2"], &[])
                .buffer(Buffer::data(
                    "coords",
                    0,
                    points.iter().flat_map(|v| v.to_le_bytes()).collect(),
                ))
                .buffer(Buffer::zeroed("out", 1, (width * height * 16) as usize))
                .output(Output::new("out", Dtype::F32, tol))
                .texture(storage(
                    Texture::d2("t", &name, width, height).index(0).data(blocks),
                    i % 2 == 0,
                )),
            );
        }
    }
}

/// Shared textures receive their blocks from the CPU, private ones from a
/// blit: half the ETC2 and EAC formats take each way.
fn storage(texture: Texture, shared: bool) -> Texture {
    if shared {
        texture.set("storage", "shared")
    } else {
        texture
    }
}

pub fn build(plan: &mut Plan, library: &str) {
    pvrtc_cases(plan, library, &mut Random::new(4094));
    astc_cases(plan, library, &mut Random::new(4095));
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
        // BC1 to BC5 interpolate palettes between endpoints at a precision
        // neither Metal nor Vulkan fixes: Apple's weights are sixty-fourths,
        // and NVIDIA's texture unit widens endpoints to 8 bits and weighs
        // them up to 2.7% of their span from k/7, k/5 and k/3, sRGB ones in
        // linear space, so those take 3% of the channel's range. The others
        // take two steps of the endpoints' precision, through the sRGB
        // curve's steepest slope for sRGB formats.
        let palette = ["bc1", "bc2", "bc3", "bc4", "bc5"]
            .iter()
            .any(|p| f.name.starts_with(p));
        let range = if f.name.contains("snorm") { 2.0 } else { 1.0 };
        let etc = f.name.starts_with("etc2") || f.name.starts_with("eac");
        let tol = if etc {
            // Exact codes: ETC2's 8-bit ones within half a step, EAC's
            // 11-bit ones at a 16-bit image's precision.
            Tolerance::abs(if f.name.contains("11") {
                1e-4
            } else {
                0.5 / 255.0
            })
        } else if f.half {
            Tolerance::ulp(1.0)
        } else if palette {
            Tolerance::abs(0.03 * range)
        } else if f.name.ends_with("srgb") {
            Tolerance::abs(0.02)
        } else {
            Tolerance::abs(2.0 / 255.0)
        }
        .with_ftz(false);
        // Every Apple family samples ETC2 and EAC.
        let (families, features): (&[&str], &[&str]) = if etc {
            (&["apple1"], &[])
        } else {
            (&[], &["bc_compression"])
        };
        // Two decoders, each within the bound of the exact palette.
        let cross = if palette { tol.doubled() } else { tol.clone() };
        plan.add(
            Case::compute1(
                &format!("texture.compressed.{}", f.name),
                library,
                "read2d_float",
                w * h,
            )
            .requires(families, features)
            .buffer(Buffer::data(
                "coords",
                0,
                points.iter().flat_map(|v: &u32| v.to_le_bytes()).collect(),
            ))
            .buffer(Buffer::zeroed("out", 1, (w * h * 16) as usize))
            .output(Output::new("out", Dtype::F32, cross).expect(f32s(&expect), tol))
            .texture(storage(
                Texture::d2("t", f.name, w, h)
                    .index(0)
                    .data(blocks.concat()),
                etc && (f.name.ends_with("srgb") || f.name.contains("snorm")),
            )),
        );
    }
}
