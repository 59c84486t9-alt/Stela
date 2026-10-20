//! ASTC 2D block decoding, LDR, sRGB and HDR. Public: the Khronos Data Format
//! Specification's ASTC chapter (block modes, integer sequence encoding,
//! partition hash, colour endpoint modes, unquantization, weight infill,
//! void-extent blocks and the LNS-to-FP16 conversion), with the hardware
//! codes 0x60..0x6d (4x4 to 12x12) and the unorm/float type split from Mesa
//! `cmdbuf.xml` and `layout/formats.c`.
//!
//! A texel's 16-bit interpolated value becomes: in LDR, `C / 65535`; in
//! sRGB, `C >> 8` as an 8-bit sRGB value (decoded by the caller); in HDR, the
//! LNS value through the specification's FP16 conversion for HDR
//! components, and the unorm16 value as FP16 for LDR components. A block the
//! specification calls illegal, and an HDR endpoint or void extent in the
//! LDR profiles, decode to the error colour: magenta in LDR and sRGB, NaN in
//! HDR (Inferred: the specification allows either, and Apple's choice is
//! unrecorded).

use super::block::Position;
use crate::platform::apple::agx::isa::float::half_to_f32;
use alloc::vec::Vec;

/// Which colour profile the descriptor selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Ldr,
    Srgb,
    Hdr,
}

/// The quantization levels, ISE-encodable, in order.
const LEVELS: [u32; 21] = [
    2, 3, 4, 5, 6, 8, 10, 12, 16, 20, 24, 32, 40, 48, 64, 80, 96, 128, 160, 192, 256,
];

/// A level's encoding: trits or quints (3 or 5 as the multiplier, or 1),
/// and the bits per value.
fn encoding(level: u32) -> (u32, u32) {
    let (multiplier, rest) = if level.is_multiple_of(3) {
        (3, level / 3)
    } else if level.is_multiple_of(5) {
        (5, level / 5)
    } else {
        (1, level)
    };
    (multiplier, rest.trailing_zeros())
}

/// Bits an ISE sequence of `count` values at `level` takes.
fn ise_bits(count: u32, level: u32) -> u32 {
    let (m, n) = encoding(level);
    match m {
        3 => count * n + (8 * count).div_ceil(5),
        5 => count * n + (7 * count).div_ceil(3),
        _ => count * n,
    }
}

/// A bit stream over a block; bits past `end` read as zero.
struct Stream {
    bits: u128,
    end: u32,
}

impl Stream {
    fn read(&self, at: u32, count: u32) -> u32 {
        let mut v = 0;
        for i in 0..count {
            let bit = at + i;
            if bit < self.end && bit < 128 && (self.bits >> bit) & 1 == 1 {
                v |= 1 << i;
            }
        }
        v
    }
}

fn bit(v: u32, i: u32) -> u32 {
    (v >> i) & 1
}

fn trits(t: u32) -> [u32; 5] {
    let (c, t4, t3);
    if t >> 2 & 7 == 7 {
        c = (t >> 5 & 7) << 2 | (t & 3);
        t4 = 2;
        t3 = 2;
    } else {
        c = t & 0x1f;
        if t >> 5 & 3 == 3 {
            t4 = 2;
            t3 = bit(t, 7);
        } else {
            t4 = bit(t, 7);
            t3 = t >> 5 & 3;
        }
    }
    let (t2, t1, t0);
    if c & 3 == 3 {
        t2 = 2;
        t1 = bit(c, 4);
        t0 = bit(c, 3) << 1 | (bit(c, 2) & !bit(c, 3) & 1);
    } else if c >> 2 & 3 == 3 {
        t2 = 2;
        t1 = 2;
        t0 = c & 3;
    } else {
        t2 = bit(c, 4);
        t1 = c >> 2 & 3;
        t0 = bit(c, 1) << 1 | (bit(c, 0) & !bit(c, 1) & 1);
    }
    [t0, t1, t2, t3, t4]
}

fn quints(q: u32) -> [u32; 3] {
    if q >> 1 & 3 == 3 && q >> 5 & 3 == 0 {
        let q2 = bit(q, 0) << 2 | (bit(q, 4) & !bit(q, 0) & 1) << 1 | (bit(q, 3) & !bit(q, 0) & 1);
        return [4, 4, q2];
    }
    let (q2, c);
    if q >> 1 & 3 == 3 {
        q2 = 4;
        c = (q >> 3 & 3) << 3 | (!(q >> 5) & 3) << 1 | bit(q, 0);
    } else {
        q2 = q >> 5 & 3;
        c = q & 0x1f;
    }
    let (q1, q0) = if c & 7 == 5 {
        (4, c >> 3 & 3)
    } else {
        (c >> 3 & 3, c & 7)
    };
    [q0, q1, q2]
}

/// Decode `count` ISE values at `level` from `stream` starting at `at`:
/// each value's (trit or quint, low bits).
fn ise(stream: &Stream, mut at: u32, count: usize, level: u32) -> Vec<(u32, u32)> {
    let (m, n) = encoding(level);
    let mut out = Vec::with_capacity(count);
    match m {
        3 => {
            while out.len() < count {
                let mut low = [0u32; 5];
                let mut t = 0;
                for (i, (shift, width)) in
                    [(0, 2), (2, 2), (4, 1), (5, 2), (7, 1)].iter().enumerate()
                {
                    low[i] = stream.read(at, n);
                    at += n;
                    t |= stream.read(at, *width) << shift;
                    at += width;
                }
                let digits = trits(t);
                for i in 0..5 {
                    if out.len() < count {
                        out.push((digits[i], low[i]));
                    }
                }
            }
        }
        5 => {
            while out.len() < count {
                let mut low = [0u32; 3];
                let mut q = 0;
                for (i, (shift, width)) in [(0, 3), (3, 2), (5, 2)].iter().enumerate() {
                    low[i] = stream.read(at, n);
                    at += n;
                    q |= stream.read(at, *width) << shift;
                    at += width;
                }
                let digits = quints(q);
                for i in 0..3 {
                    if out.len() < count {
                        out.push((digits[i], low[i]));
                    }
                }
            }
        }
        _ => {
            for _ in 0..count {
                out.push((0, stream.read(at, n)));
                at += n;
            }
        }
    }
    out
}

/// Replicate the `bits`-wide `value` into `width` bits.
fn replicate(value: u32, bits: u32, width: u32) -> u32 {
    if bits == 0 {
        return 0;
    }
    let mut out = 0;
    let mut have = 0;
    while have < width {
        out = out << bits | value;
        have += bits;
    }
    out >> (have - width)
}

/// An unquantized colour endpoint value (0..255).
fn unquantize_colour((digit, low): (u32, u32), level: u32) -> u32 {
    let (m, n) = encoding(level);
    if m == 1 {
        return replicate(low, n, 8);
    }
    let a = if low & 1 == 1 { 0x1ff } else { 0 };
    let (b, c) = match (m, n) {
        (3, 1) => (0, 204),
        (3, 2) => {
            let b = bit(low, 1);
            (b << 8 | b << 4 | b << 2 | b << 1, 93)
        }
        (3, 3) => {
            let cb = low >> 1 & 3;
            (cb << 7 | cb << 2 | cb, 44)
        }
        (3, 4) => {
            let dcb = low >> 1 & 7;
            (dcb << 6 | dcb, 22)
        }
        (3, 5) => {
            let e = low >> 1 & 0xf;
            (e << 5 | e >> 2, 11)
        }
        (3, _) => {
            let f = low >> 1 & 0x1f;
            (f << 4 | f >> 4, 5)
        }
        (5, 1) => (0, 113),
        (5, 2) => {
            let b = bit(low, 1);
            (b << 8 | b << 3 | b << 2, 54)
        }
        (5, 3) => {
            let cb = low >> 1 & 3;
            (cb << 7 | cb << 1 | cb >> 1, 26)
        }
        (5, 4) => {
            let dcb = low >> 1 & 7;
            (dcb << 6 | dcb >> 1, 13)
        }
        _ => {
            let e = low >> 1 & 0xf;
            (e << 5 | e >> 3, 6)
        }
    };
    let t = (digit * c + b) ^ a;
    (a & 0x80) | (t >> 2)
}

/// An unquantized weight (0..64).
fn unquantize_weight((digit, low): (u32, u32), level: u32) -> u32 {
    let (m, n) = encoding(level);
    let t = if m == 1 {
        replicate(low, n, 6)
    } else if n == 0 {
        if m == 3 {
            [0, 32, 63][digit as usize]
        } else {
            [0, 16, 32, 47, 63][digit as usize]
        }
    } else {
        let a = if low & 1 == 1 { 0x7f } else { 0 };
        let (b, c) = match (m, n) {
            (3, 1) => (0, 50),
            (3, 2) => {
                let b = bit(low, 1);
                (b << 6 | b << 2 | b, 23)
            }
            (3, _) => {
                let cb = low >> 1 & 3;
                (cb << 5 | cb, 11)
            }
            (5, 1) => (0, 28),
            _ => {
                let b = bit(low, 1);
                (b << 6 | b << 1, 13)
            }
        };
        let t = (digit * c + b) ^ a;
        (a & 0x20) | (t >> 2)
    };
    if t > 32 { t + 1 } else { t }
}

fn hash52(mut p: u32) -> u32 {
    p ^= p >> 15;
    p = p.wrapping_sub(p << 17);
    p = p.wrapping_add(p << 7);
    p = p.wrapping_add(p << 4);
    p ^= p >> 5;
    p = p.wrapping_add(p << 16);
    p ^= p >> 7;
    p ^= p >> 3;
    p ^= p << 6;
    p ^= p >> 17;
    p
}

/// The specification's partition function for a 2D texel.
fn partition(seed: u32, x: u32, y: u32, count: u32, small: bool) -> usize {
    let (x, y, z) = if small {
        (x << 1, y << 1, 0)
    } else {
        (x, y, 0)
    };
    let seed = seed + (count - 1) * 1024;
    let r = hash52(seed);
    let mut s = [
        r & 0xf,
        r >> 4 & 0xf,
        r >> 8 & 0xf,
        r >> 12 & 0xf,
        r >> 16 & 0xf,
        r >> 20 & 0xf,
        r >> 24 & 0xf,
        r >> 28 & 0xf,
        r >> 18 & 0xf,
        r >> 22 & 0xf,
        r >> 26 & 0xf,
        r.rotate_left(2) & 0xf,
    ];
    for v in &mut s {
        *v *= *v;
    }
    let (sh1, sh2) = if seed & 1 == 1 {
        (
            if seed & 2 != 0 { 4 } else { 5 },
            if count == 3 { 6 } else { 5 },
        )
    } else {
        (
            if count == 3 { 6 } else { 5 },
            if seed & 2 != 0 { 4 } else { 5 },
        )
    };
    let sh3 = if seed & 0x10 != 0 { sh1 } else { sh2 };
    for (i, v) in s.iter_mut().enumerate() {
        *v >>= match i {
            0 | 2 | 4 | 6 => sh1,
            1 | 3 | 5 | 7 => sh2,
            _ => sh3,
        };
    }
    let a = (s[0] * x + s[1] * y + s[10] * z + (r >> 14)) & 0x3f;
    let b = (s[2] * x + s[3] * y + s[11] * z + (r >> 10)) & 0x3f;
    let mut c = (s[4] * x + s[5] * y + s[8] * z + (r >> 6)) & 0x3f;
    let mut d = (s[6] * x + s[7] * y + s[9] * z + (r >> 2)) & 0x3f;
    if count < 4 {
        d = 0;
    }
    if count < 3 {
        c = 0;
    }
    if a >= b && a >= c && a >= d {
        0
    } else if b >= c && b >= d {
        1
    } else if c >= d {
        2
    } else {
        3
    }
}

/// The weight grid's width, height, dual-plane flag and weight level.
struct BlockMode {
    width: u32,
    height: u32,
    dual: bool,
    level: u32,
}

fn block_mode(mode: u32) -> Option<BlockMode> {
    let mut r = bit(mode, 4);
    let a = mode >> 5 & 3;
    let mut h = bit(mode, 9);
    let mut d = bit(mode, 10);
    let (width, height);
    if mode & 3 != 0 {
        r |= (mode & 3) << 1;
        let b = mode >> 7 & 3;
        (width, height) = match mode >> 2 & 3 {
            0 => (b + 4, a + 2),
            1 => (b + 8, a + 2),
            2 => (a + 2, b + 8),
            _ if mode & 0x100 != 0 => ((b & 1) + 2, a + 2),
            _ => (a + 2, (b & 1) + 6),
        };
    } else {
        r |= (mode >> 2 & 3) << 1;
        if mode >> 2 & 3 == 0 {
            return None;
        }
        let b = mode >> 9 & 3;
        (width, height) = match mode >> 7 & 3 {
            0 => (12, a + 2),
            1 => (a + 2, 12),
            2 => {
                d = 0;
                h = 0;
                (a + 6, b + 6)
            }
            _ => match a {
                0 => (6, 10),
                1 => (10, 6),
                _ => return None,
            },
        };
    }
    let level = LEVELS[(r - 2 + 6 * h) as usize];
    Some(BlockMode {
        width,
        height,
        dual: d == 1,
        level,
    })
}

/// An endpoint pair, each component 16 bits, with whether its colour and
/// alpha are HDR (LNS) values.
struct Endpoints {
    e: [[i32; 4]; 2],
    hdr_rgb: bool,
    hdr_alpha: bool,
}

fn bit_transfer_signed(a: &mut i32, b: &mut i32) {
    *b = (*b >> 1) | (*a & 0x80);
    *a = (*a >> 1) & 0x3f;
    if *a & 0x20 != 0 {
        *a -= 0x40;
    }
}

fn blue_contract(c: [i32; 4]) -> [i32; 4] {
    [(c[0] + c[2]) >> 1, (c[1] + c[2]) >> 1, c[2], c[3]]
}

fn clamp8(c: [i32; 4]) -> [i32; 4] {
    c.map(|v| v.clamp(0, 255))
}

fn hdr_rgb_direct(v: &[i32]) -> [[i32; 3]; 2] {
    let majcomp = ((v[4] & 0x80) >> 7) | ((v[5] & 0x80) >> 6);
    if majcomp == 3 {
        return [
            [v[0] << 4, v[2] << 4, (v[4] & 0x7f) << 5],
            [v[1] << 4, v[3] << 4, (v[5] & 0x7f) << 5],
        ];
    }
    let mut a = v[0] | ((v[1] & 0x40) << 2);
    let mut b0 = v[2] & 0x3f;
    let mut b1 = v[3] & 0x3f;
    let mut c = v[1] & 0x3f;
    let mut d0 = v[4] & 0x7f;
    let mut d1 = v[5] & 0x7f;
    let modeval = ((v[1] & 0x80) >> 7) | ((v[2] & 0x80) >> 6) | ((v[3] & 0x80) >> 5);
    let dbits = [7, 6, 7, 6, 5, 6, 5, 6][modeval as usize];
    let b = |x: i32, i: i32| (x >> i) & 1;
    let (bit0, bit1, bit2, bit3, bit4, bit5) = (
        b(v[2], 6),
        b(v[3], 6),
        b(v[4], 6),
        b(v[5], 6),
        b(v[4], 5),
        b(v[5], 5),
    );
    let oh = 1 << modeval;
    if oh & 0xa4 != 0 {
        a |= bit0 << 9;
    }
    if oh & 0x8 != 0 {
        a |= bit2 << 9;
    }
    if oh & 0x50 != 0 {
        a |= bit4 << 9;
    }
    if oh & 0x50 != 0 {
        a |= bit5 << 10;
    }
    if oh & 0xa0 != 0 {
        a |= bit1 << 10;
    }
    if oh & 0xc0 != 0 {
        a |= bit2 << 11;
    }
    if oh & 0x4 != 0 {
        c |= bit1 << 6;
    }
    if oh & 0xe8 != 0 {
        c |= bit3 << 6;
    }
    if oh & 0x20 != 0 {
        c |= bit2 << 7;
    }
    if oh & 0x5b != 0 {
        b0 |= bit0 << 6;
        b1 |= bit1 << 6;
    }
    if oh & 0x12 != 0 {
        b0 |= bit2 << 7;
        b1 |= bit3 << 7;
    }
    if oh & 0xaf != 0 {
        d0 |= bit4 << 5;
        d1 |= bit5 << 5;
    }
    if oh & 0x5 != 0 {
        d0 |= bit2 << 6;
        d1 |= bit3 << 6;
    }
    let sx = 32 - dbits;
    d0 = (d0 << sx) >> sx;
    d1 = (d1 << sx) >> sx;
    let shift = (modeval >> 1) ^ 3;
    a <<= shift;
    b0 <<= shift;
    b1 <<= shift;
    c <<= shift;
    d0 <<= shift;
    d1 <<= shift;
    let mut e1 = [a, a - b0, a - b1];
    let mut e0 = [a - c, a - b0 - c - d0, a - b1 - c - d1];
    for v in e0.iter_mut().chain(e1.iter_mut()) {
        *v = (*v).clamp(0, 0xfff);
    }
    if majcomp == 1 {
        e0.swap(0, 1);
        e1.swap(0, 1);
    } else if majcomp == 2 {
        e0.swap(0, 2);
        e1.swap(0, 2);
    }
    [e0, e1]
}

fn hdr_rgb_scale(v: &[i32]) -> [[i32; 3]; 2] {
    let modeval = ((v[0] & 0xc0) >> 6) | (((v[1] & 0x80) >> 7) << 2) | (((v[2] & 0x80) >> 7) << 3);
    let (majcomp, mode) = if modeval & 0xc != 0xc {
        (modeval >> 2, modeval & 3)
    } else if modeval != 0xf {
        (modeval & 3, 4)
    } else {
        (0, 5)
    };
    let mut red = v[0] & 0x3f;
    let mut green = v[1] & 0x1f;
    let mut blue = v[2] & 0x1f;
    let mut scale = v[3] & 0x1f;
    let b = |x: i32, i: i32| (x >> i) & 1;
    let (bit0, bit1, bit2, bit3, bit4, bit5, bit6) = (
        b(v[1], 6),
        b(v[1], 5),
        b(v[2], 6),
        b(v[2], 5),
        b(v[3], 7),
        b(v[3], 6),
        b(v[3], 5),
    );
    let oh = 1 << mode;
    if oh & 0x30 != 0 {
        green |= bit0 << 6;
    }
    if oh & 0x3a != 0 {
        green |= bit1 << 5;
    }
    if oh & 0x30 != 0 {
        blue |= bit2 << 6;
    }
    if oh & 0x3a != 0 {
        blue |= bit3 << 5;
    }
    if oh & 0x3d != 0 {
        scale |= bit6 << 5;
    }
    if oh & 0x2d != 0 {
        scale |= bit5 << 6;
    }
    if oh & 0x04 != 0 {
        scale |= bit4 << 7;
    }
    if oh & 0x3b != 0 {
        red |= bit4 << 6;
    }
    if oh & 0x04 != 0 {
        red |= bit3 << 6;
    }
    if oh & 0x10 != 0 {
        red |= bit5 << 7;
    }
    if oh & 0x0f != 0 {
        red |= bit2 << 7;
    }
    if oh & 0x05 != 0 {
        red |= bit1 << 8;
    }
    if oh & 0x0a != 0 {
        red |= bit0 << 8;
    }
    if oh & 0x05 != 0 {
        red |= bit0 << 9;
    }
    if oh & 0x02 != 0 {
        red |= bit6 << 9;
    }
    if oh & 0x01 != 0 {
        red |= bit3 << 10;
    }
    if oh & 0x02 != 0 {
        red |= bit5 << 10;
    }
    let shift = [1, 1, 2, 3, 4, 5][mode as usize];
    red <<= shift;
    green <<= shift;
    blue <<= shift;
    scale <<= shift;
    if mode != 5 {
        green = red - green;
        blue = red - blue;
    }
    if majcomp == 1 {
        core::mem::swap(&mut red, &mut green);
    } else if majcomp == 2 {
        core::mem::swap(&mut red, &mut blue);
    }
    let e1 = [red.max(0), green.max(0), blue.max(0)];
    let e0 = [
        (red - scale).max(0),
        (green - scale).max(0),
        (blue - scale).max(0),
    ];
    [e0, e1]
}

fn hdr_alpha(v6: i32, v7: i32) -> [i32; 2] {
    let selector = ((v6 >> 7) & 1) | ((v7 >> 6) & 2);
    let (mut v6, mut v7) = (v6 & 0x7f, v7 & 0x7f);
    if selector == 3 {
        return [v6 << 5, v7 << 5];
    }
    v6 |= (v7 << (selector + 1)) & 0x780;
    v7 &= 0x3f >> selector;
    v7 ^= 32 >> selector;
    v7 -= 32 >> selector;
    v6 <<= 4 - selector;
    v7 <<= 4 - selector;
    v7 += v6;
    [v6, v7.clamp(0, 0xfff)]
}

/// Decode endpoint mode `cem` from its unquantized values.
fn endpoints(cem: u32, v: &[i32]) -> Endpoints {
    let ldr = |e0: [i32; 4], e1: [i32; 4]| Endpoints {
        e: [e0, e1],
        hdr_rgb: false,
        hdr_alpha: false,
    };
    let hdr = |rgb: [[i32; 3]; 2], alpha: Option<[i32; 2]>, alpha_hdr: bool| {
        let a = alpha.unwrap_or([0x780, 0x780]);
        Endpoints {
            e: [
                [rgb[0][0], rgb[0][1], rgb[0][2], a[0]],
                [rgb[1][0], rgb[1][1], rgb[1][2], a[1]],
            ],
            hdr_rgb: true,
            hdr_alpha: alpha_hdr,
        }
    };
    let mut v: Vec<i32> = v.to_vec();
    match cem {
        0 => ldr([v[0], v[0], v[0], 255], [v[1], v[1], v[1], 255]),
        1 => {
            let l0 = (v[0] >> 2) | (v[1] & 0xc0);
            let l1 = (l0 + (v[1] & 0x3f)).min(255);
            ldr([l0, l0, l0, 255], [l1, l1, l1, 255])
        }
        2 => {
            let (y0, y1) = if v[1] >= v[0] {
                (v[0] << 4, v[1] << 4)
            } else {
                ((v[1] << 4) + 8, (v[0] << 4) - 8)
            };
            hdr([[y0; 3], [y1; 3]], None, true)
        }
        3 => {
            let (y0, d) = if v[0] & 0x80 != 0 {
                (
                    ((v[1] & 0xe0) << 4) | ((v[0] & 0x7f) << 2),
                    (v[1] & 0x1f) << 2,
                )
            } else {
                (
                    ((v[1] & 0xf0) << 4) | ((v[0] & 0x7f) << 1),
                    (v[1] & 0xf) << 1,
                )
            };
            let y1 = (y0 + d).min(0xfff);
            hdr([[y0; 3], [y1; 3]], None, true)
        }
        4 => ldr([v[0], v[0], v[0], v[2]], [v[1], v[1], v[1], v[3]]),
        5 => {
            let (mut a, mut b) = (v[1], v[0]);
            bit_transfer_signed(&mut a, &mut b);
            let (mut c, mut d) = (v[3], v[2]);
            bit_transfer_signed(&mut c, &mut d);
            ldr([b, b, b, d], clamp8([b + a, b + a, b + a, d + c]))
        }
        6 => ldr(
            [
                (v[0] * v[3]) >> 8,
                (v[1] * v[3]) >> 8,
                (v[2] * v[3]) >> 8,
                255,
            ],
            [v[0], v[1], v[2], 255],
        ),
        7 => hdr(hdr_rgb_scale(&v), None, true),
        8 | 12 => {
            let (a0, a1) = if cem == 12 { (v[6], v[7]) } else { (255, 255) };
            if v[1] + v[3] + v[5] >= v[0] + v[2] + v[4] {
                ldr([v[0], v[2], v[4], a0], [v[1], v[3], v[5], a1])
            } else {
                ldr(
                    blue_contract([v[1], v[3], v[5], a1]),
                    blue_contract([v[0], v[2], v[4], a0]),
                )
            }
        }
        9 | 13 => {
            let pairs = if cem == 13 { 4 } else { 3 };
            for p in 0..pairs {
                let (mut a, mut b) = (v[2 * p + 1], v[2 * p]);
                bit_transfer_signed(&mut a, &mut b);
                v[2 * p + 1] = a;
                v[2 * p] = b;
            }
            let (a0, a1) = if cem == 13 {
                (v[6], v[6] + v[7])
            } else {
                (255, 255)
            };
            if v[1] + v[3] + v[5] >= 0 {
                ldr(
                    [v[0], v[2], v[4], a0],
                    clamp8([v[0] + v[1], v[2] + v[3], v[4] + v[5], a1]),
                )
            } else {
                ldr(
                    clamp8(blue_contract([v[0] + v[1], v[2] + v[3], v[4] + v[5], a1])),
                    clamp8(blue_contract([v[0], v[2], v[4], a0])),
                )
            }
        }
        10 => ldr(
            [
                (v[0] * v[3]) >> 8,
                (v[1] * v[3]) >> 8,
                (v[2] * v[3]) >> 8,
                v[4],
            ],
            [v[0], v[1], v[2], v[5]],
        ),
        11 => hdr(hdr_rgb_direct(&v), None, true),
        14 => hdr(hdr_rgb_direct(&v), Some([v[6], v[7]]), false),
        _ => hdr(hdr_rgb_direct(&v), Some(hdr_alpha(v[6], v[7])), true),
    }
}

fn lns_to_half(p: u32) -> u16 {
    let (e, m) = (p >> 11, p & 0x7ff);
    let mt = if m < 512 {
        3 * m
    } else if m < 1536 {
        4 * m - 512
    } else {
        5 * m - 2048
    };
    let r = (e << 10) | (mt >> 3);
    r.min(0x7bff) as u16
}

fn unorm16_to_half(p: u32) -> u16 {
    if p == 0xffff {
        return 0x3c00;
    }
    if p < 4 {
        return (p << 8) as u16;
    }
    let lz = p.leading_zeros() - 16;
    let mut v = p << (lz + 1);
    v >>= 6;
    (v as u16 & 0x3ff) | (((14 - lz) as u16) << 10)
}

fn error(profile: Profile) -> [f64; 4] {
    match profile {
        Profile::Hdr => [f64::NAN; 4],
        _ => [1.0, 0.0, 1.0, 1.0],
    }
}

/// The texel at (`x`, `y`) of a `dims` block.
pub fn astc(block: &[u8], (bw, bh): (u32, u32), (x, y): Position, profile: Profile) -> [f64; 4] {
    let bits = u128::from_le_bytes(block[..16].try_into().expect("an ASTC block is 16 bytes"));
    let read = |at: u32, n: u32| ((bits >> at) as u64 & ((1u64 << n) - 1)) as u32;
    let mode = read(0, 11);
    if mode & 0x1ff == 0x1fc {
        return void_extent(bits, profile);
    }
    let Some(grid) = block_mode(mode) else {
        return error(profile);
    };
    let partitions = read(11, 2) + 1;
    let planes = if grid.dual { 2 } else { 1 };
    let weight_count = grid.width * grid.height * planes;
    let weight_bits = ise_bits(weight_count, grid.level);
    if grid.width > bw
        || grid.height > bh
        || weight_count > 64
        || !(24..=96).contains(&weight_bits)
        || (grid.dual && partitions == 4)
    {
        return error(profile);
    }
    let mut below = 128 - weight_bits;
    let (cems, colour_start, seed) = if partitions == 1 {
        (alloc::vec![read(13, 4)], 17, 0)
    } else {
        let seed = read(13, 10);
        let field = read(23, 6);
        let cems = if field & 3 == 0 {
            alloc::vec![field >> 2; partitions as usize]
        } else {
            let extra = 3 * partitions - 4;
            below -= extra;
            let encoded = field | read(below, extra) << 6;
            let base = encoded & 3;
            let encoded = encoded >> 2;
            (0..partitions)
                .map(|i| {
                    let class = bit(encoded, i);
                    let low = encoded >> (partitions + 2 * i) & 3;
                    ((base - 1 + class) << 2) | low
                })
                .collect()
        };
        (cems, 29, seed)
    };
    let ccs = if grid.dual {
        below -= 2;
        Some(read(below, 2))
    } else {
        None
    };
    let values: u32 = cems.iter().map(|cem| 2 * ((cem >> 2) + 1)).sum();
    if values > 18 || below < colour_start {
        return error(profile);
    }
    let available = below - colour_start;
    let Some(level) = LEVELS
        .iter()
        .rev()
        .copied()
        .find(|&level| ise_bits(values, level) <= available)
    else {
        return error(profile);
    };
    if level < 6 {
        return error(profile);
    }
    // The sequence ends at its own length: a partial block's missing bits
    // read as zero, not as the unused bits above it.
    let colour = Stream {
        bits,
        end: colour_start + ise_bits(values, level),
    };
    let unquantized: Vec<i32> = ise(&colour, colour_start, values as usize, level)
        .into_iter()
        .map(|v| unquantize_colour(v, level) as i32)
        .collect();
    let weight_stream = Stream {
        bits: bits.reverse_bits(),
        end: weight_bits,
    };
    let weights: Vec<u32> = ise(&weight_stream, 0, weight_count as usize, grid.level)
        .into_iter()
        .map(|v| unquantize_weight(v, grid.level))
        .collect();
    let small = bw * bh < 31;
    let p = if partitions == 1 {
        0
    } else {
        partition(seed, x, y, partitions, small)
    };
    let offset: u32 = cems[..p].iter().map(|cem| 2 * ((cem >> 2) + 1)).sum();
    let cem = cems[p];
    let count = 2 * ((cem >> 2) + 1) as usize;
    let ends = endpoints(cem, &unquantized[offset as usize..offset as usize + count]);
    if profile != Profile::Hdr && (ends.hdr_rgb || ends.hdr_alpha) {
        return error(profile);
    }
    // Weight infill.
    let ds = (1024 + bw / 2) / (bw - 1);
    let dt = (1024 + bh / 2) / (bh - 1);
    let gs = (ds * x * (grid.width - 1) + 32) >> 6;
    let gt = (dt * y * (grid.height - 1) + 32) >> 6;
    let (js, fs, jt, ft) = (gs >> 4, gs & 0xf, gt >> 4, gt & 0xf);
    let w11 = (fs * ft + 8) >> 4;
    let w10 = ft - w11;
    let w01 = fs - w11;
    let w00 = 16 + w11 - fs - ft;
    let weight = |plane: u32| -> u32 {
        let at = |gx: u32, gy: u32| -> u32 {
            if gx < grid.width && gy < grid.height {
                weights[((gy * grid.width + gx) * planes + plane) as usize]
            } else {
                0
            }
        };
        (at(js, jt) * w00
            + at(js + 1, jt) * w01
            + at(js, jt + 1) * w10
            + at(js + 1, jt + 1) * w11
            + 8)
            >> 4
    };
    let mut out = [0.0; 4];
    for (c, channel) in out.iter_mut().enumerate() {
        let plane = u32::from(ccs == Some(c as u32));
        let w = weight(plane);
        let hdr = if c == 3 { ends.hdr_alpha } else { ends.hdr_rgb };
        let expand = |v: i32| -> u32 {
            if hdr {
                (v as u32) << 4
            } else if profile == Profile::Srgb {
                (v as u32) << 8 | 0x80
            } else {
                v as u32 * 257
            }
        };
        let (c0, c1) = (expand(ends.e[0][c]), expand(ends.e[1][c]));
        let value = (c0 * (64 - w) + c1 * w + 32) >> 6;
        *channel = match profile {
            Profile::Ldr => f64::from(value) / 65535.0,
            Profile::Srgb => f64::from(value >> 8) / 255.0,
            Profile::Hdr if hdr => f64::from(half_to_f32(lns_to_half(value))),
            Profile::Hdr => f64::from(half_to_f32(unorm16_to_half(value))),
        };
    }
    out
}

fn void_extent(bits: u128, profile: Profile) -> [f64; 4] {
    let read = |at: u32, n: u32| ((bits >> at) as u64 & ((1u64 << n) - 1)) as u32;
    let hdr = read(9, 1) == 1;
    if read(10, 2) != 3 || (hdr && profile != Profile::Hdr) {
        return error(profile);
    }
    let extents = [read(12, 13), read(25, 13), read(38, 13), read(51, 13)];
    if extents != [0x1fff; 4] && (extents[0] >= extents[1] || extents[2] >= extents[3]) {
        return error(profile);
    }
    let colour = [read(64, 16), read(80, 16), read(96, 16), read(112, 16)];
    colour.map(|c| match profile {
        _ if hdr => f64::from(half_to_f32(c as u16)),
        Profile::Ldr => f64::from(c) / 65535.0,
        Profile::Srgb => f64::from(c >> 8) / 255.0,
        Profile::Hdr => f64::from(half_to_f32(unorm16_to_half(c))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_sequences_decode_trits_and_quints() {
        // Every trit and quint pattern decodes to digits in range.
        for t in 0..256 {
            assert!(trits(t).iter().all(|&d| d < 3));
        }
        for q in 0..128 {
            assert!(quints(q).iter().all(|&d| d < 5));
        }
        assert_eq!(trits(0), [0; 5]);
        assert_eq!(quints(0), [0; 3]);
        assert_eq!(ise_bits(5, 3), 8);
        assert_eq!(ise_bits(3, 5), 7);
        assert_eq!(ise_bits(4, 16), 16);
    }

    #[test]
    fn unquantization_spans_the_full_range() {
        for &level in &LEVELS {
            let (m, n) = encoding(level);
            let all = || (0..m).flat_map(move |d| (0..1u32 << n).map(move |low| (d, low)));
            // Colour endpoints use QUANT_6 and above; each level spans the
            // whole range with distinct values.
            if level >= 6 {
                let mut values: Vec<u32> = all().map(|v| unquantize_colour(v, level)).collect();
                values.sort_unstable();
                values.dedup();
                assert_eq!(values.len() as u32, level, "{level}");
                assert_eq!((values[0], values[values.len() - 1]), (0, 255), "{level}");
            }
            if level <= 32 {
                let mut values: Vec<u32> = all().map(|v| unquantize_weight(v, level)).collect();
                values.sort_unstable();
                values.dedup();
                assert_eq!(values.len() as u32, level, "{level}");
                assert_eq!((values[0], values[values.len() - 1]), (0, 64), "{level}");
                if level == 24 {
                    assert_eq!(
                        values,
                        [
                            0, 2, 5, 8, 11, 13, 16, 19, 22, 24, 27, 30, 34, 37, 40, 42, 45, 48, 51,
                            53, 56, 59, 62, 64
                        ]
                    );
                }
            }
        }
    }

    #[test]
    fn a_void_extent_block_is_its_constant_colour() {
        let mut block = [
            0xfc, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        block[8..10].copy_from_slice(&0xffffu16.to_le_bytes());
        block[14..16].copy_from_slice(&0xffffu16.to_le_bytes());
        assert_eq!(
            astc(&block, (4, 4), (1, 2), Profile::Ldr),
            [1.0, 0.0, 0.0, 1.0]
        );
        // An HDR void extent is an error in LDR.
        block[1] |= 0x02;
        assert_eq!(
            astc(&block, (4, 4), (0, 0), Profile::Ldr),
            [1.0, 0.0, 1.0, 1.0]
        );
        // A reserved block mode is an error too.
        assert_eq!(
            astc(&[0; 16], (4, 4), (0, 0), Profile::Ldr),
            [1.0, 0.0, 1.0, 1.0]
        );
    }

    /// Blocks whose texels were decoded by Apple's ImageIO decoder (8-bit).
    #[test]
    fn partial_sequences_and_dual_planes_decode_as_apples_decoder() {
        let close = |got: [f64; 4], want: [u8; 4]| {
            (0..4).all(|c| (got[c] * 255.0 - f64::from(want[c])).abs() <= 1.0)
        };
        // Three partitions of CEM 8, 18 colour values at QUANT_6: the last
        // trit block's missing bits read as zero (blue 0, not 51).
        let partial = [
            0x3d, 0xf7, 0x42, 0xf0, 0x83, 0x6e, 0xc0, 0x2b, 0x51, 0xab, 0x5c, 0xee, 0x32, 0x54,
            0xee, 0xbd,
        ];
        assert!(close(
            astc(&partial, (4, 4), (1, 0), Profile::Ldr),
            [77, 115, 0, 255]
        ));
        // A dual-plane 2x4 grid at QUANT_24 weights (red on plane 1).
        let dual = [
            0x4f, 0xc7, 0xe2, 0x52, 0x58, 0x63, 0x44, 0xd9, 0xe5, 0xf5, 0x93, 0x6f, 0x46, 0xe5,
            0xbd, 0x8b,
        ];
        assert!(close(
            astc(&dual, (4, 4), (3, 3), Profile::Ldr),
            [53, 29, 124, 255]
        ));
    }

    #[test]
    fn lns_and_unorm16_convert_to_half() {
        assert_eq!(lns_to_half(0x7800), 0x3c00);
        assert_eq!(lns_to_half(0xffff), 0x7bff);
        assert_eq!(unorm16_to_half(0xffff), 0x3c00);
        assert_eq!(unorm16_to_half(0x8000), 0x3800);
        assert_eq!(unorm16_to_half(0), 0);
    }

    /// A hex string's bytes.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    type Vector = ((u32, u32), u32, &'static [u32], &'static str, &'static str);

    /// Checks a vector's labels against its block (partition count, the
    /// single or shared CEM, a grid within the footprint) and returns the
    /// block with its weight level and dual-plane flag.
    fn labelled(&((bw, bh), _, cems, block, _): &Vector) -> (Vec<u8>, u32, bool) {
        let block = hex(block);
        let v = u128::from_le_bytes(block[..].try_into().unwrap());
        let parts = (v >> 11 & 3) as usize + 1;
        assert_eq!(cems.len(), parts, "{block:02x?}");
        if parts == 1 {
            assert_eq!(cems[0], (v >> 13 & 0xf) as u32);
        } else if v >> 23 & 3 == 0 {
            assert!(cems.iter().all(|&c| c == (v >> 25 & 0xf) as u32));
        }
        let mode = block_mode((v & 0x7ff) as u32).unwrap();
        assert!(mode.width <= bw && mode.height <= bh);
        (block, mode.level, mode.dual)
    }

    /// The vectors' footprints, block-mode rows, partition counts, CEMs,
    /// dual-plane flags and weight encodings (0 bits, 1 trits, 2 quints).
    fn coverage(vectors: &[Vector]) -> [Vec<u32>; 6] {
        let mut sets: [Vec<u32>; 6] = Default::default();
        for vector in vectors {
            let ((bw, bh), row, cems, ..) = *vector;
            let (_, level, dual) = labelled(vector);
            let encoding = match level {
                _ if level % 3 == 0 => 1,
                _ if level % 5 == 0 => 2,
                _ => 0,
            };
            let found = [
                bw << 8 | bh,
                row,
                cems.len() as u32,
                u32::from(dual),
                encoding,
            ];
            for (set, value) in [0, 1, 2, 4, 5].into_iter().zip(found) {
                sets[set].push(value);
            }
            sets[3].extend(cems);
        }
        for set in &mut sets {
            set.sort_unstable();
            set.dedup();
        }
        sets
    }

    #[test]
    fn ldr_blocks_match_a_host_decoder_in_every_block_mode_family() {
        for vector in &ASTC_LDR_VECTORS {
            let ((bw, bh), _, _, _, texels) = *vector;
            let (block, ..) = labelled(vector);
            for (t, want) in hex(texels).chunks(4).enumerate() {
                let at = (t as u32 % bw, t as u32 / bw);
                let got = astc(&block, (bw, bh), at, Profile::Ldr);
                let close = (0..4).all(|c| (got[c] * 255.0 - f64::from(want[c])).abs() <= 1.0);
                assert!(
                    close,
                    "{bw}x{bh} {block:02x?} texel {at:?}: {got:?} against {want:?}"
                );
            }
        }
        let [footprints, rows, parts, cems, dual, encodings] = coverage(&ASTC_LDR_VECTORS);
        assert_eq!(footprints.len(), 14);
        assert_eq!(rows, (0..10).collect::<Vec<_>>());
        assert_eq!(parts, [1, 2, 3, 4]);
        assert_eq!(cems, [0, 1, 4, 5, 6, 8, 9, 10, 12, 13]);
        assert_eq!((dual, encodings), (vec![0, 1], vec![0, 1, 2]));
    }

    #[test]
    fn hdr_blocks_match_a_host_decoder_in_every_hdr_endpoint_mode() {
        for vector in &ASTC_HDR_VECTORS {
            let ((bw, bh), _, _, _, texels) = *vector;
            let (block, ..) = labelled(vector);
            for (t, want) in hex(texels).chunks(8).enumerate() {
                let at = (t as u32 % bw, t as u32 / bw);
                let got = astc(&block, (bw, bh), at, Profile::Hdr);
                let want: [f64; 4] = core::array::from_fn(|c| {
                    f64::from(half_to_f32(u16::from_le_bytes([
                        want[2 * c],
                        want[2 * c + 1],
                    ])))
                });
                assert_eq!(got, want, "{bw}x{bh} {block:02x?} texel {at:?}");
            }
        }
        let [_, _, parts, cems, dual, encodings] = coverage(&ASTC_HDR_VECTORS);
        assert_eq!(parts, [1, 2, 3, 4]);
        assert!([2, 3, 7, 11, 14, 15].iter().all(|c| cems.contains(c)));
        assert_eq!((dual, encodings), (vec![0, 1], vec![0, 1, 2]));
    }

    #[test]
    fn void_extents_match_a_host_decoder() {
        // Constant colours 0x1234, 0x8000, 0xffff, 0x4000 (LDR, unorm16) and
        // 2.5, 0.25, 1.0, 1.0 (HDR, half): ImageIO returned 0x12, 0x80, 0xff,
        // 0x40 and the same halves at every texel.
        let ldr = hex("fcfdffffffffffff34120080ffff0040");
        let got = astc(&ldr, (4, 4), (3, 1), Profile::Ldr).map(|c| (c * 255.0).round() as u8);
        assert_eq!(got, [0x12, 0x80, 0xff, 0x40]);
        let hdr = hex("fcffffffffffffff00410034003c003c");
        assert_eq!(
            astc(&hdr, (4, 4), (2, 3), Profile::Hdr),
            [2.5, 0.25, 1.0, 1.0]
        );
    }

    // Host-decoder vectors, chosen by the procedure in the AGX research
    // notes (`docs/research/agx.md`, "Codec vectors"): random legal blocks
    // decoded by macOS ImageIO. Each entry is the footprint, the
    // specification's block-mode table row, the partitions' CEMs, the block
    // and its texels in row order (RGBA8 for LDR, RGBA half bits for HDR).
    const ASTC_LDR_VECTORS: [Vector; 28] = [
        (
            (4, 4),
            3,
            &[5, 1, 4, 0],
            "bf9b86eab5490f05b22d5861365a6645",
            "d1d1d1ffd1d1d1ff494949ffd1d1d1ffd1d1d1ffcfcfcfa7c2c2c28fd1d1d1ffd1d1d1ffd1d1d1ff3d3d3dde373737d68e8e8e30a8a8a860a8a8a8608a8a8a28",
        ),
        (
            (4, 4),
            3,
            &[4, 6, 1, 5],
            "8edbdfb65c82a70b5125e635581e8cc9",
            "1e1e1eff67167dff292929ff191919ff480f57ff1a1a1a501a1a1a501e1e1e4b1e1e1eff2a2a2aff2b2b2bff242424ffb3b3b33aa5a5a52fa1a1a12b641579ff",
        ),
        (
            (5, 4),
            0,
            &[9, 10, 8],
            "12548eb1acdc102ff849826ca5695389",
            "e054f2ffe059eeffdd4df6ffdd41feffe246fbffe152f3ff2391009c23910066239200222492002e249100692391008b2391006f239200392492002e2492005b2391007d23910072239200502492002e",
        ),
        (
            (6, 5),
            0,
            &[9, 6, 8],
            "1234607be743d25b2aa9873c3bc1476d",
            "4e551cff7454e3fff2bf7ffff4bf7ffff6bf7fff8e54e3ff4c551cff7a50d9fff3ba7ffff5bb7ffff6bc7fff8e52ddff4a551cff7f4ed3fff4b57ffff6b77ffff7b87fff8e4fd6ff48551cff844bcafff5b080fff7b380ff8b4bcaff8e4dd0ff46551cfff7b280fff7ab80fff8ae80ff8e48c2ff8e4bcaff",
        ),
        (
            (6, 6),
            4,
            &[0, 0],
            "5d28752056db090ac06b06a9a7058680",
            "4f4f4fffb9b9b9ff4e4e4eff4e4e4eff4e4e4eff4e4e4effb1b1b1ff4f4f4fff4f4f4fff4e4e4eff4e4e4eff4e4e4eff4e4e4eff4f4f4fff505050ff4e4e4eff4e4e4eff4e4e4eff4e4e4eff4f4f4fff4f4f4fff4f4f4fff4f4f4fff4f4f4fff4f4f4fff4e4e4eff4e4e4eff4f4f4fff4f4f4fff505050ff4f4f4fff4f4f4fff4f4f4fff4f4f4fff4f4f4fffb1b1b1ff",
        ),
        (
            (6, 6),
            4,
            &[12, 10],
            "7d68ec437bbad40b66a309d1951d27de",
            "e3ff388ee3ff38bc6c939059677b755f5a42376ce3ff388ee2fe37ffe2fe37d15a42376c5a42376c66777160e3ff388ee2fe37ffe3ff38a368837e5d636b6463636b6463e3ff38c7e3ff38c7e3ff3899605a52665a42376c636b6463e3ff38c7e3ff388ee2fe37ea677b755f677b755f5836296ee3ff38c7e2fe37ffe2fe37ffe2fe37dc5e5249685836296ee3ff38c7",
        ),
        (
            (8, 5),
            1,
            &[12],
            "25823b4233d2ecdc74d5c22f075a266d",
            "bc677b36d7b6b01cdcc5ba17c788912bdcc5ba17d2a6a521d2a6a521ad395c45ba607638d7b6b01cd7b6b01cca919728dabeb619c57f8b2ec788912bb0426242b758713bd7b6b01cd2a6a521cd979b26d7b6b01cb758713bbc677b36b2486640bc677b36d2a6a521c2788730d2a6a521d2a6a521bc677b36c2788730c2788730c2768531cd979b26b2486640d7b6b01ccd979b26c2768531c788912bd2a6a521",
        ),
        (
            (8, 5),
            1,
            &[13],
            "17a02b26c0fbdec54b966dd21dbdfbdf",
            "bc9d985cc59f9f68c59f9f68c59f9f68c19e9c62bc9d985cc59f9f68c19e9c62ba9d975ac59f9f68c59f9f67c49f9e67c09e9b62bd9d995dc49f9e67c19e9c62b99d9658c59f9f68c49f9e67c39f9d65c09e9b61bd9e995ec39f9d65c19e9c62b79c9456c59f9f68c39f9e66c29e9d64bf9e9a60be9e9a5fc29e9d64c19e9c62b59c9354c59f9f68c39f9d65c19e9c62be9e9a60be9e9a60c19e9c62c19e9c62",
        ),
        (
            (8, 6),
            9,
            &[13],
            "54a1fdbce33b22639e13ffbfd3b41bf1",
            "7fbf886e7cb687767fbf886e7cb687767ebb88727cb687767fbf886e7ebb88727fbf886e7ebb88727ebb88727fbf886e7fbf886e7ebb88727cb687767fbf886e7cb687767fbf886e7fbf886e7ebb88727ebb88727fbf886e7fbf886e7fbf886e7fbf886e7fbf886e7ebb88727fbf886e7fbf886e7fbf886e7cb687767fbf886e7cb687767fbf886e7ebb88727ebb88727fbf886e7ebb88727cb687767fbf886e7fbf886e7ebb88727cb687767fbf886e7ebb88727cb687767ebb88727cb68776",
        ),
        (
            (8, 6),
            9,
            &[0, 0],
            "14c9486040af2b0bf012ab18a6aeba3f",
            "030303ff555555ff7a7a7aff7a7a7aff7a7a7aff7a7a7aff6b6b6bff3f3f3fff7a7a7aff282828ff373737ff7a7a7aff7a7a7aff595959ff3f3f3fff3f3f3fff3f3f3fff161616ff373737ff737373ff464646ff3f3f3fff303030ff030303ff030303ff555555ff464646ff121212ff6b6b6bff595959ff303030ff030303ff030303ff2c2c2cff3f3f3fff3f3f3fff3f3f3fff606060ff6b6b6bff3f3f3fff030303ff555555ff464646ff121212ff6b6b6bff373737ff030303ff030303ff",
        ),
        (
            (8, 8),
            2,
            &[13, 13],
            "0bc820da89f2af7f188341fdb1c6cdb1",
            "73afb2cac35ab87bc45bb87cc45bb87dc55bb87dc55bb87ec65cb87f71b1aad5c058b774c058b775c159b777c259b778c25ab879c35ab87ac45bb87c72b0aed076aebbbd76aebabfc159b776c159b777c159b777c259b778c35ab87973afb2ca72b0aed073b0b0cd74afb3c874afb5c575aeb7c2c058b77576adbdbb77adbfb872b0aed072b0add072b1add172b1acd2c55cb87fc65cb87f71b1aad571b1aad5c55bb87dc45bb87cc45ab87bc35ab87ac35ab87ac25ab87974afb6c575afb7c3c55bb87dc55bb87ec55bb87ec55bb87ec55cb87fc65cb87f71b1aad571b1aad573afb2ca73afb2cac35ab87ac35ab87ac35ab87ac35ab87a73afb2ca73afb2ca",
        ),
        (
            (8, 8),
            2,
            &[9],
            "1922573241df7cf766e0f95ecf6d371a",
            "974e5eff984e5eff9a4c5eff9b4c5eff9c4b5dff9d4a5dff9f495dffa0485cff964f5fff974e5eff994d5eff9a4c5eff9c4b5dff9d4a5dff9f495dffa0485cff9f495dff9f485cff9f485cffa0485cffa0485cffa0485cffa0485cffa0485cff994d5eff994d5eff994d5eff984d5eff984e5eff984e5eff974e5eff974e5eff9c4b5dff9c4b5dff9d4a5dff9d4a5dff9e4a5dff9e495dff9f495dff9f495dff9d4a5dff9d4a5dff9c4b5dff9c4b5dff9c4b5dff9c4b5dff9c4b5dff9c4b5dff9f495dff9f495dff9f495dff9e495dff9e495dff9e495dff9e495dff9e495dff974e5eff974e5eff974e5eff974e5eff974e5eff974e5eff974e5eff974e5eff",
        ),
        (
            (10, 6),
            8,
            &[13],
            "a4a12fe538084e79635df5430b53fb4b",
            "dae7e397f2f9ff8edae7e397dae7e397f2f9ff8edae7e397f2f9ff8ef2f9ff8ef2f9ff8ef2f9ff8ef2f9ff8ef2f9ff8ef2f9ff8edae7e397f2f9ff8ef2f9ff8edae7e397f2f9ff8edae7e397f2f9ff8edae7e397dae7e397f2f9ff8ef2f9ff8edae7e397dae7e397dae7e397dae7e397f2f9ff8edae7e397f2f9ff8ef2f9ff8edae7e397f2f9ff8edae7e397dae7e397dae7e397dae7e397f2f9ff8ef2f9ff8ef2f9ff8ef2f9ff8ef2f9ff8ef2f9ff8edae7e397f2f9ff8edae7e397f2f9ff8edae7e397f2f9ff8edae7e397f2f9ff8ef2f9ff8ef2f9ff8edae7e397f2f9ff8edae7e397f2f9ff8ef2f9ff8edae7e397",
        ),
        (
            (10, 6),
            8,
            &[9, 9],
            "a4292752e18dcbd8a26d2b65998af017",
            "24c96dff24c96dff24c96dff36c86dff24c96dff36c86dff36c86dff36c86dff5a5136ff5a5136ff36c86dff36c86dff24c96dff24c96dff24c96dff24c96dff36c86dff24c96dff474c2cff474c2cff36c86dff24c96dff36c86dff24c96dff36c86dff24c96dff24c96dff5a5136ff5a5136ff474c2cff24c96dff36c86dff24c96dff36c86dff36c86dff24c96dff474c2cff5a5136ff474c2cff5a5136ff24c96dff24c96dff36c86dff24c96dff36c86dff24c96dff5a5136ff5a5136ff474c2cff5a5136ff36c86dff24c96dff36c86dff36c86dff24c96dff5a5136ff5a5136ff474c2cff5a5136ff474c2cff",
        ),
        (
            (10, 10),
            7,
            &[1, 1, 1],
            "84d13a4248baa21121aa8fdae48acbd2",
            "7a7a7aff7a7a7aff7a7a7aff7a7a7aff222222ff7a7a7aff7a7a7aff7a7a7aff7a7a7aff7a7a7aff333333ff272727ff0c0c0cff212121ff2d2d2dff2d2d2dff212121ff0c0c0cff1d1d1dff1d1d1dff2d2d2dff181818ff0c0c0cff212121ff2d2d2dff2d2d2dff2d2d2dff2d2d2dff292929ff1d1d1dff070707ff070707ff0c0c0cff212121ff232323ff0e0e0eff131313ff282828ff292929ff1d1d1dff2d2d2dff2d2d2dff2d2d2dff2d2d2dff232323ff0e0e0eff070707ff070707ff181818ff333333ff070707ff070707ff0c0c0cff212121ff2d2d2dff2d2d2dff212121ff0c0c0cff181818ff333333ff333333ff272727ff202020ff2c2c2cff2d2d2dff212121ff242424ff303030ff7a7a7aff7a7a7aff1d1d1dff1d1d1dff202020ff2c2c2cff333333ff2d2d2dff2d2d2dff2d2d2dff2d2d2dff2d2d2dff333333ff272727ff0c0c0cff212121ff232323ff0e0e0eff131313ff282828ff1c1c1cff070707ff2d2d2dff181818ff070707ff070707ff070707ff070707ff131313ff282828ff1c1c1cff070707ff",
        ),
        (
            (10, 10),
            7,
            &[0],
            "84016eecf9c9d0bc13e6c4d595f35425",
            "373737ff373737ff4f4f4fffbababaffc6c6c6ff5b5b5bff373737ff373737ff8a8a8afff6f6f6ff373737ffa2a2a2ffdededeff737373ff676767ffd2d2d2ffbababaff4f4f4fff8a8a8afff6f6f6ff373737ffa2a2a2ffdededeff737373ff373737ff373737ff737373ffdededefff6f6f6fff6f6f6fff6f6f6fff6f6f6ffdededeff737373ff373737ff373737ff737373ffdededefff6f6f6fff6f6f6fff6f6f6ff8a8a8aff373737ff373737ff676767ffd2d2d2ffbababaff4f4f4fff8a8a8afff6f6f6ff373737ffa2a2a2fff6f6f6fff6f6f6fff6f6f6fff6f6f6ffbababaff4f4f4fff8a8a8afff6f6f6ff373737ffa2a2a2ffdededeff737373ff676767ffd2d2d2fff6f6f6fff6f6f6fff6f6f6fff6f6f6ff373737ff373737ff373737ff373737ff676767ffd2d2d2ffbababaff4f4f4fff373737ff373737fff6f6f6fff6f6f6fff6f6f6fff6f6f6ffc6c6c6ff5b5b5bff373737ff373737ff8a8a8afff6f6f6fff6f6f6ff8a8a8aff373737ff373737ff373737ff373737ff373737ff373737ff8a8a8afff6f6f6ff",
        ),
        (
            (12, 10),
            5,
            &[9, 9, 4],
            "049438d7603f22b7851543830f238fc7",
            "8c99b3ff8598b2ff8598b3ff8c99b3ff8c99b2ff8598b2ff8c99b3ff8c99b3ff8598b2ff8c99b2ff8598b2ff8c99b3ff8b99b3ff8598b2ff8698b3ff8c99b3ff8c99b2ff8598b2ff8b99b3ff8c99b3ff8598b2ff8b99b2ff8598b2ff8c99b3ff8a99b3ff8598b2ff8798b3ff8c99b3ff8c99b2ff8598b2ff8a99b3ff8c99b3ff8598b2ff8a99b2ff8598b2ff8c99b3ff8a99b3ff8598b2ff8798b3ff8c99b3ff8c99b2ff8598b2ff8a99b3ff8c99b3ff8598b2ff8a99b2ff8598b2ff8c99b3ff8999b3ff8598b2ff8898b3ff8c99b3ff8c99b2ff8598b2ff8999b3ff8c99b3ff8598b2ff8999b2ff8598b2ff8c99b3ff8898b2ff8598b2ff8999b3ff8c99b3ff8c99b2ff8598b2ff8898b2ff8c99b3ff8598b3ff8898b2ff8598b2ff8c99b3ff8798b2ff8598b2ff8a99b3ff8c99b3ff8c99b2ff8598b2ff8798b2ff8c99b3ff8598b3ff8798b2ff8598b2ff8c99b3ff8798b2ff8598b2ff8a99b3ff8c99b3ff8c99b2ff8598b2ff8798b2ff8c99b3ff8598b3ff8798b2ff8598b2ff8c99b3ff8698b2ff8598b2ff8b99b3ff8c99b3ff8c99b2ff8598b2ff8698b2ff8c99b3ff8598b3ff8698b2ff8598b2ff8c99b3ff8598b2ff8598b2ff8c99b3ff8c99b3ff8c99b2ff8598b2ff8598b2ff8c99b3ff8598b3ff8598b2ff8598b2ff8c99b3ff",
        ),
        (
            (12, 10),
            5,
            &[10],
            "0440775e81fa66e9bff66ce93db9e99a",
            "3baf40f41c551fb31c551fb33baf40f43baf40f41c551fb33baf40f41c551fb33baf40f43baf40f43baf40f41c551fb33baf40f41c551fb31c551fb33baf40f43baf40f41c551fb33baf40f4206023bb3baf40f437a43cec37a43cec206023bb3baf40f41c551fb31c551fb33baf40f43baf40f41c551fb33baf40f4246c27c33baf40f4339938e4339938e4246c27c33baf40f41c551fb31c551fb33baf40f43baf40f41c551fb33baf40f4267129c73baf40f4319336e0319336e0267129c73baf40f41c551fb31c551fb33baf40f43baf40f41c551fb33baf40f42a7c2dcf3baf40f42d8832d82d8832d82a7c2dcf3baf40f41c551fb31c551fb33baf40f43baf40f41c551fb33baf40f42d8832d83baf40f42a7c2dcf2a7c2dcf2d8832d83baf40f41c551fb31c551fb33baf40f43baf40f41c551fb33baf40f4319336e03baf40f4267129c7267129c7319336e03baf40f41c551fb31c551fb33baf40f43baf40f41c551fb33baf40f4339938e43baf40f4246c27c3246c27c3339938e43baf40f41c551fb31c551fb33baf40f43baf40f41c551fb33baf40f437a43cec3baf40f4206023bb206023bb37a43cec3baf40f41c551fb31c551fb33baf40f43baf40f41c551fb33baf40f43baf40f43baf40f41c551fb31c551fb33baf40f4",
        ),
        (
            (12, 12),
            6,
            &[9, 4],
            "8ce8648bc0125153984c8a12fa26db29",
            "5050508a1e5420ff52525291545454955656569c585858a0595959a35a5a5aa75d5d5dae5e5e5eb1606060b5616161b8616161b8205423ff5656569c545454954d4d4d834949497943434367404040603939394e353535432f2f2f32185513ff2c2c2c2b2f2f2f323333333c353535433939394e3c3c3c55404040601b551bff1c551cff494949791d541eff1e541fff717171e36e6e6edc6a6a6ad1225427ff215426ff215425ff205424ff205423ff1f5422ff5656569c1e5420ff1e541fff185513ff185513ff2c2c2c2b185513ff185513ff185513ff185513ff185513ff185513ff2c2c2c2b2c2c2c2b185513ff185513ff185515ff3939394e1a5519ff1c551cff1d541dff1e5420ff1f5421ff205424ff646464c06d6d6dd823542aff1e541fff1e5420ff52525291545454951f5421ff1f5422ff1f5422ff1f5423ff205423ff5e5e5eb1606060b5616161b8205425ff205425ff616161b8616161b8205425ff205425ff205425ff205425ff205425ff616161b8616161b8616161b81e541fff1e5420ff52525291545454955656569c1f5422ff1f5422ff1f5423ff205423ff5e5e5eb1606060b5616161b81e541fff1e5420ff5656569c585858a05c5c5caa205424ff215425ff215426ff225427ff6a6a6ad16e6e6edc717171e3185513ff185514ff353535433939394e40404060434343671c541dff1d541eff1e5420ff5656569c5d5d5dae616161b8205425ff205423ff545454955050508a47474772434343671a5518ff195516ff185514ff292929232020200b1c1c1c00",
        ),
        (
            (12, 12),
            6,
            &[4, 1, 5],
            "b4b09d0acdff55cc9426c9cee3b42d1c",
            "a2a2a2ff3a3a3ae23a3a3ae83a3a3aed3a3a3af33a3a3af83a3a3af93a3a3af63a3a3af4aaaaaaff3a3a3aee3a3a3aec3a3a3aec3a3a3ae93a3a3ae63a3a3ae33a3a3ae13a3a3ade3a3a3add3a3a3add3a3a3add3a3a3add3a3a3add3a3a3add3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aec3a3a3aef3a3a3af23a3a3af53a3a3af73a3a3afa3a3a3afa3a3a3af73a3a3af53a3a3af23a3a3aef3a3a3aec3a3a3aeb3a3a3ae83a3a3ae53a3a3ae23a3a3ae03a3a3add3a3a3aec3a3a3ae93a3a3ae63a3a3ae33a3a3ae13a3a3ade3a3a3adfa5a5a5ff3a3a3aea3a3a3aef3a3a3af53a3a3afa3a3a3afa3a3a3af73a3a3af53a3a3af23a3a3aef3a3a3aec3a3a3aeb3a3a3ae83a3a3ae53a3a3ae23a3a3ae03a3a3add3a3a3aec3a3a3aee3a3a3af13a3a3af43a3a3af63a3a3af9acacacff3a3a3af33a3a3aed3a3a3ae83a3a3ae23a3a3add3a3a3afa3a3a3af53a3a3aef3a3a3aea3a3a3ae43a3a3adf3a3a3ade3a3a3ae13a3a3ae33a3a3ae63a3a3ae93a3a3aec3a3a3afa3a3a3af53a3a3aef3a3a3aea3a3a3ae43a3a3adf3a3a3ade3a3a3ae13a3a3ae33a3a3ae63a3a3ae93a3a3aec3a3a3add3a3a3ae03a3a3ae23a3a3ae53a3a3ae83a3a3aeb3a3a3aeb3a3a3ae83a3a3ae53a3a3ae23a3a3ae03a3a3add3a3a3add3a3a3ae23a3a3ae83a3a3aed3a3a3af33a3a3af83a3a3af93a3a3af63a3a3af43a3a3af13a3a3aee3a3a3aec",
        ),
        (
            (5, 4),
            3,
            &[0, 0, 6],
            "8ef3be8821fb35585c30c9a685d88523",
            "b4b4b4ff91532fffc06f3eff666666ff191919ff5c5c5cff965731ffbb6b3cff626262ff191919ff7c7c7cffa25d34ffb86a3bff5f5f5fffb0b0b0ff969696ffad6338ffb2673aff5f5f5fffb0b0b0ff",
        ),
        (
            (5, 5),
            3,
            &[0],
            "fe01d0f7b3aa3d8d26ffc7eedb53e574",
            "fbfbfbfff4f4f4ffedededfff4f4f4fffbfbfbfff2f2f2ffefefefffedededfff4f4f4fffbfbfbfff2f2f2ffefefefffedededffedededffedededfff2f2f2fff4f4f4fff6f6f6fff9f9f9fffbfbfbfff6f6f6fff9f9f9fffbfbfbfff9f9f9fff6f6f6ff",
        ),
        (
            (5, 5),
            3,
            &[0, 0, 0, 0],
            "2e9b1aa07868ff0ef1ad272eac7d7b8a",
            "bdbdbdffb5b5b5ff484848ff4b4b4bff4e4e4eff848484ff808080ff595959ff5b5b5bff5d5d5dff4b4b4bff4d4d4dff6c6c6cff6b6b6bff6b6b6bff4b4b4bff4f4f4fff6b6b6bff696969ff676767ff4b4b4bff515151ff696969ff666666ff636363ff",
        ),
        (
            (6, 5),
            3,
            &[9, 9],
            "cdab2212471fa90de997d59691699871",
            "879a8aff869a87ff859a84ff2897a4ff2798a5ff2698a6ff869a86ff869a87ff869a88ff869a86ff2598a6ff2198aaff859a83ff859a83ff849b82ff2698a6ff839b7eff829b7bff859b82ff849b81ff839b7eff2098abff829b7bff829b7bff859a85ff869a86ff2e969eff2c97a0ff849b81ff839b7cff",
        ),
        (
            (10, 5),
            0,
            &[5, 9, 8],
            "b1f01c7d48de55187c15d74317076e3b",
            "6b9fa4ff6b9c9dff6b9896ff6b9897ff6b9a9bff6b9a9aff6b9897ff6b9794ff6b9794ff6b9794ff6b9b9cff6b9b9bff6b9999ff6b9a99ff6b9b9bff6b9b9cff6b9b9dff6b9b9bff6b9997ff6b9794ff1b94c9ff30979dff449a71ff4a9b65ff4a9b65ff569c4bff6a9f1fff6d9f19ff449a71ff1b94c9ff4a9b65ff539c52ff5f9d39ff629e32ff629e32ff629e32ff5f9d39ff599d45ff3b9884ff1b94c9ff79a100ff79a100ff79a100ff79a100ff79a100ff6d9f19ff599d45ff449a71ff30979dff1b94c9ff",
        ),
        (
            (10, 5),
            3,
            &[6],
            "2ec730faf9fc335b1f3650f2361726d8",
            "17fc7cff17fc7cff17fc7cff17fc7cff17fc7cff17fc7bff17fc7bff17fc7bff17fc7bff17fc7bff18fc7cff17fc7cff17fc7cff17fc7cff17fc7cff17fc7cff17fc7cff17fc7cff17fc7cff17fc7cff18fc7cff18fc7cff18fc7cff18fc7cff18fc7cff18fc7cff18fc7cff18fd7cff17fd7cff17fd7cff18fd7cff18fd7cff18fd7cff17fd7cff17fc7cff17fc7cff17fc7cff17fd7cff17fd7cff17fd7cff17fd7cff17fd7cff17fd7cff17fd7cff17fd7cff17fd7cff17fd7cff17fd7cff17fc7cff17fc7cff",
        ),
        (
            (10, 8),
            0,
            &[4],
            "d180b614529c4bb5fba647c40626dbec",
            "3333337c3333337c3333337c26262695121212bf141414b926262695383838714949494d5b5b5b29212121a0282828903030308126262695121212bf0f0f0fc4191919af26262695383838714949494d0f0f0fc41e1e1ea52d2d2d8626262695121212bf0a0a0ace0d0d0dc9141414b926262695383838712323239a2b2b2b8b3333337c30303081262626952323239a2323239a212121a02323239a262626954242425d3a3a3a6c3333337c353535763f3f3f624242425d4242425d3f3f3f622b2b2b8b171717b45b5b5b294c4c4c483d3d3d674242425d535353385b5b5b295b5b5b295151513e2d2d2d860a0a0ace5b5b5b29535353384c4c4c484e4e4e435858582e5b5b5b295b5b5b295151513e2d2d2d860a0a0ace5b5b5b295b5b5b295b5b5b295b5b5b295b5b5b295b5b5b295b5b5b295151513e2d2d2d860a0a0ace",
        ),
        (
            (10, 8),
            3,
            &[5, 5],
            "fd49c82e56cca0c85674523959ce505f",
            "ecececaeecececaeecececaeecececaeecececaeebebebb0e9e9e9b2e7e7e7b64f4f4f0151515102e7e7e7b6e8e8e8b4e9e9e9b2eaeaeab1ebebebafebebebafebebebb0eaeaeab1e9e9e9b34c4c4c01505050014f4f4f014e4e4e014c4c4c014c4c4c014b4b4b004b4b4b004b4b4b004b4b4b004b4b4b004b4b4b004e4e4e014f4f4f0151515102535353025353530253535302535353025353530253535302e7e7e7b65151510252525202555555025757570358585803575757035757570356565603dededec5ddddddc6ddddddc657575703575757035858580357575703565656035454540253535302e2e2e2bde2e2e2bde0e0e0c1dfdfdfc256565603575757035757570355555502525252024f4f4f01e7e7e7b6ecececaee8e8e8b5e5e5e5bae0e0e0c1ddddddc6565656035353530250505001e9e9e9b3ecececae",
        ),
    ];

    const ASTC_HDR_VECTORS: [Vector; 16] = [
        (
            (6, 6),
            0,
            &[3, 3, 2, 7],
            "5218f7f01951cee194ffbf272a04f195",
            "601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c601c601c601c003c000000000000003c42238a0c4223003c363018113630003c801900098019003c2420740b2420003c783692137836003c000000000000003c4840e8164840003c185d4821185d003ce83cb815e83c003c904630199046003cc066c024c066003c",
        ),
        (
            (6, 6),
            3,
            &[3, 2, 7, 2],
            "bdbbb4e80d81c30ae746d85d27d5d5d9",
            "585558555855003cbc5dbc5dbc5d003cec68ec68ec68003ca82da82da82d003cfe5bae5d9e5a003cf85baa5d9a5a003ca827a827a827003c3e293e293e29003c206620662066003cf85baa5d9a5a003ced5ba15d915a003ce45b9a5d8a5a003c1f701f701f70003cec68ec68ec68003c966096609660003ce75b9c5d8c5a003cd95b915d815a003c607160716071003c526a526a526a003c206620662066003cee61ee61ee61003cea5b9e5d8e5a003c887188718871003c4c714c714c71003c265126512651003cbc5dbc5dbc5d003c526a526a526a003c287228722872003cd871d871d871003c887188718871003cc73ac73ac73a003c255425542554003c1f701f701f70003c787278727872003c147214721472003cba71ba71ba71003c",
        ),
        (
            (4, 4),
            3,
            &[11],
            "cf65dfa4d706ce496cd401e5ed251a9c",
            "6512c00e3014003c8e12660b1a12003c9a12c10ad211003c8e12340d4213003ca012b9094211003c6a12130bf611003c5812b80b3e12003c6512b80b3e12003c4012340d4213003c40123c0ef613003c5e12510c9812003ca0128006b00f003c7a12340d4213003c7a12b9094211003c6e121c0a7811003c5212c00e3014003c",
        ),
        (
            (4, 4),
            0,
            &[11],
            "1364bfe08dd55cf8a2b750ac432160e0",
            "d82be822e010003ca01d38179216003ca01d3817e010003cce1fc718b218003c9c286a20e010003c0022cf1af015003c881fa2189213003c602054192616003ca824001de010003c6027511f4e15003cc8219d1a2616003ce820e1199213003c90216e1ae010003cd82be822b114003cba233f1cb218003c90216e1ae010003c",
        ),
        (
            (8, 8),
            4,
            &[15, 14],
            "0e2ad2ffa79b60dc9cbd8dcc6d199209",
            "802dc02dc82dc011a12de72dde2dc011cf2d1e2efc2dc0110000ee179601a238000039186401fe3800007c1832015a390000e418ec00da3900003e19bb00353a332e942e3e2ec011392e9c2e422ec011392e9c2e422ec011000061184601353900006f183c014739000046185a011039000046185a0110390000541850012339752eec2e6a2ec0116e2ee22e652ec011612ecf2e5d2ec0110000d218f600c8390000b2180a01a3390000a5181401913900008a1828016c3900007c1832015a39612ecf2e5d2ec011612ecf2e5d2ec0116e2ee22e652ec01100001a19ce00113a00001a19ce00113a00002c19c400233a00005019b400483a00005019b400483a2c2e8d2e3a2ec011402ea42e472ec011542ebc2e542ec0110000f618e200ec3900002c19c400233a00005019b400483a000086199d007f3a0000bc198700b63af72d4e2e172ec011fe2d552e1b2ec011042e5d2e1f2ec011000039186401fe38000046185a011039000061184601353900006f183c01473900007c1832015a39c22d0f2ef42dc011d62d262e012ec011d62d262e012ec0110000c117aa017e380000c117aa017e38000003188c01b53800002b186e01ec3800002b186e01ec389a2ddf2dd92dc011bb2d072eef2dc011f02d462e122ec011000046185a01103900008a1828016c390000e418ec00da3900007419a5006c3a0000ce197f00c83a",
        ),
        (
            (8, 8),
            4,
            &[15],
            "1ee2cdecf47a59c3f92f541c4bcf0d8c",
            "7806f5032511cf078a0609043311d1079d0619044111d207af0628044f11d307b80630045611d407cd0640046411d507e40650047211d607fc0660048011d807590572026910bc077e059c027e10bf07bf05ee02a210c307f6053d03c310c7071b067203df10c9075306c0030911cd07930611043a11d107b80630045611d407e104e9012410b4070f051e023f10b707590572026910bc077e059c027e10bf07ac05d4029810c207da051603b210c50724067f03e610ca074906b3030211cc07ea04f4012a10b507060513023910b60746055d025e10bb0762057c026e10bd077e059c027e10bf079a05bb028d10c007da051603b210c507f6053d03c310c707af04aa010510b007ea04f4012a10b507340548025410ba076b0587027310bd07a305c7029310c107e4052303b710c5072e068c03ed10ca076506db031711ce078705a6028310bf079005b1028810c007750591027810be077e059c027e10bf077e059c027e10bf077e059c027e10bf076b0587027310bd076b0587027310bd071b067203df10c907f6053d03c310c707a305c7029310c1077e059c027e10bf0746055d025e10bb07210533024910b807d704df011f10b307af04aa010510b007ac05d4029810c2079005b1028810c00762057c026e10bd0746055d025e10bb07210533024910b807060513023910b607d704df011f10b307bd04bf010f10b107",
        ),
        (
            (12, 12),
            1,
            &[14, 14],
            "07a829dc50d26b4d3f673a9a0a15bee6",
            "e25161448c4133349d5c2534ac21db34cf5e99301a1bff34c752ef42ed3e4134e25161448c413334fe509e4557442534fc4cfb4b4e50cb33424c184dd452af336e4d214bd94ed933765d9632151fe9349c58103aa02d9c34c0464055c062073326413148404ac73a3b3fb246404a723ab73e6c46404a613ae6401248404abc3afb401c48404ac03a3c413c48404aca3a1342a548404aed3a5342c648404af83abd417b48404adf3a3b3fb246404a723a3b406f47404a993af4422849404a113b26413148404ac73a3b3fb246404a723aa13e5e46404a5d3abc40fb47404ab53ad0400748404ab93a26413148404ac73afd419a48404aea3a2842af48404af13a51414648404ace3a203fa446404a6f3a0a403a47404a8f3a3e42ba48404af43a26413148404ac73a3b3fb246404a723aa13e5e46404a5d3aac40e947404ab23abc40fb47404ab53afb401c48404ac03a1342a548404aed3afd419a48404aea3a26413148404ac73a3b3fb246404a723aa63ff446404a803ae8419048404ae63a26413148404ac73a3b3fb246404a723a8c3e5046404a5a3a8b40c647404aab3a8b40c647404aab3abc40fb47404ab53a3e42ba48404af43ad2418548404ae33abc40fb47404ab53a8b3fe346404a7d3af73f2947404a8b3a3c413c48404aca3a26413148404ac73a3b3fb246404a723a8c3e5046404a5a3a7b40b547404aa73a7b40b547404aa73a9c40d847404aae3a3e42ba48404af43ae8419048404ae63a8b40c647404aab3a563fc046404a763a8b3fe346404a7d3ae6401248404abc3a26413148404ac73a3b3fb246404a723a8c3e5046404a5a3a7b40b547404aa73a4b408047404a9d3a8b40c647404aab3a2842af48404af13abd417b48404adf3a7b40b547404aa73aa63ff446404a803adc3f1747404a883a5b409247404aa03a26413148404ac73a3b3fb246404a723a763e4246404a563a6b40a347404aa43a2b405d47404a963a6b40a347404aa43a3e42ba48404af43ad2418548404ae33a5b409247404aa03adc3f1747404a883a703fd146404a793a1b404c47404a923a26413148404ac73a3b3fb246404a723a763e4246404a563a4b408047404a9d3a0a403a47404a8f3a3b406f47404a993a6942d448404afb3aa7417048404adc3a0a403a47404a8f3ac13f0647404a843a3b3fb246404a723a563fc046404a763a26413148404ac73a3b3fb246404a723a763e4246404a563a3b406f47404a993af73f2947404a8b3a1b404c47404a923a6942d448404afb3a67415148404ad13ac13f0647404a843adc3f1747404a883a703fd146404a793aea3e8846404a683a26413148404ac73a3b3fb246404a723a613e3446404a533a1b404c47404a923aa63ff446404a803a0a403a47404a8f3a6942d448404afb3a51414648404ace3a3b3fb246404a723ac13f0647404a843a203fa446404a6f3a363e1846404a4c3a26413148404ac73a3b3fb246404a723a613e3446404a533a0a403a47404a8f3a8b3fe346404a7d3af73f2947404a8b3a6942d448404afb3a51414648404ace3a053f9646404a6b3af73f2947404a8b3a563fc046404a763ae03de045404a3e3a",
        ),
        (
            (12, 12),
            6,
            &[2, 7, 2],
            "98d0e96432f2b4cbbbfa8b9e80b0c790",
            "c035c035c035003cc035c035c035003cc035c035c035003c785a6658f858003c784878487848003c784878487848003c784878487848003c784878487848003c784878487848003c784878487848003c784878487848003c784878487848003c802680268026003c7e287e287e28003c5a2c5a2c5a2c003c3c5a3958bd58003c1a471a471a47003cf147f147f147003c0c490c490c49003cb849b849b849003c244b244b244b003cfb4bfb4bfb4b003c144d144d144d003cc04dc04dc04d003c802680268026003c502a502a502a003cf031f031f031003c785a6658f858003cb45a93583459003c7e4c7e4c7e4c003c2e4f2e4f2e4f003c845084508450003c385338533853003c8a548a548a54003c425742574257003c905890589058003c004500450045003cf246f246f246003cb84ab84ab84a003c475bfc58ac59003c6c5b1a59ca59003c7f5b2959d959003c095409540954003c8a548a548a54003cd055d055d055003c7c567c567c56003c0f580f580f58003c905890589058003cb063b063b063003cec5fec5fec5f003c3c583c583c58003c925b3859e859003c475bfc58ac59003c215bde588e59003c7e4c7e4c7e4c003c244b244b244b003c784878487848003c1a471a471a47003c724472447244003c005a0c589058003cc035c035c035003ccc34cc34cc34003ced32ed32ed32003c5a5a4f58da58003c4b5a4458cb58003c435a3e58c358003c345a3358b758003c044504450445003c724472447244003c314431443144003c075a11589558003c005a0c589058003c802680268026003c7e287e287e28003c5a2c5a2c5a2c003c3c5a3958bd58003c5a5a4f58da58003c695a5a58e958003c875a71580759003c965a7c581659003c244b244b244b003cfb4bfb4bfb4b003ce95ab4586159003cfc5ac0587059003c005a0c589058003c075a11589558003c5c295c295c29003c1e5a2258a658003c2d5a2d58b158003c345a3358b758003c435a3e58c358003c4b5a4458cb58003c1a471a471a47003c615a5558e158003c705a6058f058003c785a6658f858003cb063b063b063003cb063b063b063003cb063b063b063003c905890589058003c905890589058003c905890589058003c905890589058003c905890589058003cb063b063b063003cb063b063b063003cb063b063b063003cb063b063b063003cb063b063b063003c986198619861003cc85dc85dc85d003cd055d055d055003c8a548a548a54003c095409540954003c745274527452003cc851c851c851003ca84ca84ca84c003cb84ab84ab84a003cf246f246f246003c004500450045003c605460546054003c585258525852003c884e884e884e003c845084508450003c2e4f2e4f2e4f003c6c4e6c4e6c4e003c144d144d144d003cd65aa9585259003c603d603d603d003ca63ba63ba63b003ce237e237e237003cc035c035c035003cb063b063b063003cb063b063b063003cb063b063b063003c905890589058003c905890589058003c905890589058003c185cb059605a003c185cb059605a003c185cb059605a003c185cb059605a003cb063b063b063003cb063b063b063003c",
        ),
        (
            (6, 6),
            9,
            &[11, 11, 11],
            "04d173d6a3edb8784ff2e2c959947dbb",
            "c0466063c062003c00006038c00d003cc0466063c062003cc0466063c062003cc0466063c062003c00006038c00d003cc0466063c062003cc0466063c062003c00006038c00d003cc0466063c062003cc0466063c062003cc0466063c062003cc0466063c062003cc0466063c062003c00006038c00d003cc0466063c062003cc0466063c062003c00006038c00d003c00006038c00d003cc0466063c062003c00006038c00d003cc0466063c062003c00006038c00d003c00006038c00d003c2e279025a826003c7e286a27a828003c2e279025a826003cc0466063c062003cc0466063c062003c00006038c00d003c2e279025a826003c7e286a27a828003c7e286a27a828003c7e286a27a828003c2e279025a826003c2e279025a826003c",
        ),
        (
            (6, 6),
            9,
            &[7],
            "04e1c0a15a93de046cc7c8f2b7409914",
            "402a80318035003c402a80318035003c402a80318035003c903c00440048003c402a80318035003c903c00440048003c402a80318035003c402a80318035003c903c00440048003c402a80318035003c402a80318035003c903c00440048003c903c00440048003c402a80318035003c402a80318035003c903c00440048003c402a80318035003c903c00440048003c402a80318035003c402a80318035003c402a80318035003c402a80318035003c402a80318035003c402a80318035003c903c00440048003c402a80318035003c903c00440048003c903c00440048003c402a80318035003c903c00440048003c903c00440048003c903c00440048003c903c00440048003c903c00440048003c903c00440048003c903c00440048003c",
        ),
        (
            (8, 8),
            2,
            &[11, 11],
            "492c7d960729ae79bab7f20b97180868",
            "6061f6672a60003c00008416c417003c00000614e018003c000010134019003c000010134019003c00001013e018003c00001013c417003c000010134016003c000010134016003c000010134016003c000010134016003c000010134c17003c000010136c18003c00001013e018003c00001013c417003c000010134016003c000010134016003c0000bc154016003c00008a184016003c00006f174c17003c0000f4146c18003c00001013e018003c00001013c417003c000010134016003c000010134019003c0000bc152418003c00008a18a016003c000040194016003c000040194016003c00004019a016003c000040192418003c000040194019003c606148642a60003c606148642a60003c606148642a60003c9d6248642661003c436448649162003c58659e640064003c586525660064003c5865f6670064003c5865f6670064003c5865f6670064003c5865f6670064003c436498669162003c9d623f652661003cdf6148648460003cd26348641862003c586548640064003c586548640064003c5865b2650064003c586566670064003c4364f6679162003c9d62f6672661003cdf61f6678460003cd263f6671862003c5865f6670064003c586548640064003c5865b2650064003c586566670064003c586598660064003c58653f650064003c586548640064003c000010134019003c000010134019003c",
        ),
        (
            (8, 8),
            1,
            &[3, 3, 2],
            "2670f9302236180b33bf627ae644ab3f",
            "d84bd84bd84b003c604f604f604f003cb02fb02fb02f003c385338533853003cd04cd04cd04c003cd04cd04cd04c003cd04cd04cd04c003c604f604f604f003c754c754c754c003c1e4e1e4e1e4e003ce14ee14ee14e003cfe51fe51fe51003c8d4d8d4d8d4d003cd04cd04cd04c003c364d364d364d003c834e834e834e003cfc4cfc4cfc4c003c364d364d364d003c924e924e924e003c165116511651003c2c4e2c4e2c4e003cd04cd04cd04c003cef2aef2aef2a003c242c242c242c003cc74dc74dc74d003c3f4c3f4c3f4c003c3b4e3b4e3b4e003c3f4c3f4c3f4c003cc22ec22ec22e003c1e291e291e29003c242c242c242c003cdc29dc29dc29003c0f4e0f4e0f4e003c3f4c3f4c3f4c003cc451c451c451003c722672267226003c212f212f212f003c1e291e291e29003cdd2bdd2bdd2b003c1e291e291e29003c792c792c792c003c282a282a282a003c5e515e515e51003c7b277b277b27003c2a2e2a2e2a2e003c1e291e291e29003c902990299029003c1e291e291e29003c792c792c792c003c962c962c962c003c165116511651003c3f283f283f28003c6c2d6c2d6c2d003c1e291e291e29003c222822282228003c1e291e291e29003c792c792c792c003cb02fb02fb02f003cb450b450b450003c1e291e291e29003c792c792c792c003c1e291e291e29003c002600260026003c1e291e291e29003c",
        ),
        (
            (8, 8),
            2,
            &[14],
            "0bc2cf73fc093e01fb368d0f011822ce",
            "5e49710f685d87374849880e385fa6373249c20dd860c5373249c20dd860c5371c49fc0c9062e4371c49fc0c9062e4370649580c66640138f0489c0b006611386048400500748c386048400500748c386048400500748c386048400500748c386048400500748c386048400500748c386048400500748c386048400500748c38f0489c0b006611388a49da10f8594a37664aa018c8481536104b001ec03c3d35d04b9423ba306534574cd428b4241a33264d5631c8117230c04dc036c005852d944d343530097c2e944d343530097c2e944d343530097c2e944d343530097c2e944d343530097c2e944d343530097c2e944d343530097c2e944d343530097c2e924a221a5845d735be4ae91be84199352b4bc71e1a3b1e35624b6d20ce37e034994bde214e34a234d04b9423ba306534254c8226d829d333464c3a2868265733a94cb52c421ce531674c9a290623dc32044cf624482d2734994bde214e34a2342b4bc71e1a3b1e35be4ae91be84199353a4a1c175a4c5336e24925142e53ce36924a221a5845d7357c4a5c192447f635504a0c18804a34363a4a1c175a4c5336244a4416f04d71360e4a7e15e24f9036f849ba146051af36e24925142e53ce36c04dc036c005852d944d343530097c2e524dea32580eef2f264d5631c8117230fa4c07303815ee30ce4c3e2eae186931994c212cd01d2332784c602a40219e32",
        ),
        (
            (12, 12),
            5,
            &[2, 2],
            "046a07c4d5eae9a1fa7f84d144ae6671",
            "434043404340003cc036c036c036003cca46ca46ca46003cca46ca46ca46003c044d044d044d003cde39de39de39003ce649e649e649003cde39de39de39003cfc3cfc3cfc3c003c405e405e405e003c405e405e405e003c564356435643003c704170417041003cc036c036c036003c564656465646003c584758475847003c044d044d044d003cc23ac23ac23a003ce649e649e649003c513b513b513b003c405e405e405e003c405e405e405e003c405e405e405e003c564356435643003c405e405e405e003c4e374e374e37003c004500450045003c9c489c489c48003c9d4c9d4c9d4c003c423c423c423c003c584a584a584a003c6e3d6e3d6e3d003c405e405e405e003c405e405e405e003c6e3d6e3d6e3d003c564356435643003c004500450045003cdd37dd37dd37003c9a449a449a44003c024902490249003c484c484c484c003cfc3cfc3cfc3c003ccc4acc4acc4a003c405e405e405e003c405e405e405e003ce03de03de03d003cc53ec53ec53e003c564356435643003c584758475847003c403840384038003c564356435643003c584a584a584a003ce94be94be94b003cc53ec53ec53e003c405e405e405e003c405e405e405e003cc23ac23ac23a003c523e523e523e003cfe40fe40fe40003c564356435643003c9c489c489c48003c403840384038003c544254425442003ccc4acc4acc4a003ce94be94be94b003ce23fe23fe23f003c405e405e405e003c544254425442003c503a503a503a003c523e523e523e003c544254425442003c564356435643003ccc4acc4acc4a003c963896389638003c704170417041003c484c484c484c003c5b4b5b4b5b4b003c405e405e405e003ce94be94be94b003c9a449a449a44003c6c396c396c39003cc53ec53ec53e003c9a449a449a44003c564356435643003c484c484c484c003c963896389638003c994099409940003c9d4c9d4c9d4c003c405e405e405e003ce241e241e241003ce94be94be94b003ce445e445e445003cfa38fa38fa38003cc53ec53ec53e003ce445e445e445003c405e405e405e003c5a4e5a4e5a4e003cfa38fa38fa38003ce23fe23fe23f003ce84de84de84d003c405e405e405e003ce443e443e443003c484c484c484c003c464846484648003c963896389638003c533f533f533f003c464846484648003c405e405e405e003cec4fec4fec4f003c6c396c396c39003cc53ec53ec53e003c405e405e405e003c584a584a584a003c9a449a449a44003c9d4c9d4c9d4c003c744974497449003c403840384038003ce23fe23fe23f003c405e405e405e003c405e405e405e003cea51ea51ea51003cde39de39de39003c405e405e405e003cec4fec4fec4f003ce649e649e649003ce445e445e445003c044d044d044d003ce94be94be94b003c4e374e374e37003c405e405e405e003c405e405e405e003c405e405e405e003c605360536053003cde39de39de39003cfc3cfc3cfc3c003c495049504950003ce649e649e649003cca46ca46ca46003c044d044d044d003c044d044d044d003cc036c036c036003c405e405e405e003c405e405e405e003c564356435643003c",
        ),
        (
            (12, 12),
            5,
            &[2, 2, 7, 3],
            "04188cc861e0e80194a5fcb6fa6ed97c",
            "604060406040003c384338433843003c384338433843003c384338433843003c384338433843003c384338433843003c300c300c300c003c604060406040003c384338433843003cb037b037b037003c302830283028003cb037b037b037003c824082408240003cfe42fe42fe42003cfe42fe42fe42003c384338433843003cfe42fe42fe42003c384338433843003cf80cf80cf80c003c302830283028003cb037b037b037003cb037b037b037003cf828f828f828003c883688368836003cca40ca40ca40003c964296429642003c964296429642003c384338433843003c964296429642003c384338433843003cf22af22af22a003c302830283028003cb037b037b037003cb037b037b037003cf22af22af22a003ca234a234a234003cf840f840f840003c684268426842003c684268426842003c384338433843003cd817d817d817003cb01bb01bb01b003c182c182c182c003c302830283028003cb037b037b037003cb037b037b037003c182c182c182c003cd833d833d833003c544154415441003c0c420c420c42003c0c420c420c42003cb037b037b037003cb015b015b015003cb037b037b037003cd02dd02dd02d003c302830283028003cb037b037b037003cb037b037b037003cd02dd02dd02d003cb031b031b031003c824182418241003cba30ba30ba30003cba30ba30ba30003cb037b037b037003cba14ba14ba14003cb037b037b037003cca2eca2eca2e003c302830283028003cb037b037b037003cb037b037b037003cca2eca2eca2e003cba30ba30ba30003cba30ba30ba30003cca2eca2eca2e003cca2eca2eca2e003cb037b037b037003cca2eca2eca2e003cb037b037b037003cba30ba30ba30003c302830283028003cb037b037b037003cb037b037b037003cba30ba30ba30003cca2eca2eca2e003cb031b031b031003cd02dd02dd02d003cd02dd02dd02d003cb037b037b037003cd02dd02dd02d003cb037b037b037003cb031b031b031003c302830283028003cb037b037b037003cb037b037b037003cb031b031b031003cd02dd02dd02d003c004c404a103f003cc0464045003a003c181018101810003cb01bb01bb01b003cc0464045003a003c404ec04c8041003c004c404a103f003c6044c042b037003c404ec04c8041003c404ec04c8041003c004c404a103f003c181018101810003c784ce84ad83f003c2046a8446039003c2046a8446039003c404ec04c8041003c2046a8446039003c404ec04c8041003c784ce84ad83f003c6044c042b037003c404ec04c8041003c404ec04c8041003c784ce84ad83f003c2046a8446039003c881a881a881a003cf80cf80cf80c003cf80cf80cf80c003c384338433843003c824082408240003c384338433843003c881a881a881a003c300c300c300c003cb01bb01bb01b003cb01bb01bb01b003c881a881a881a003cf80cf80cf80c003cb01bb01bb01b003c300c300c300c003c604060406040003c384338433843003c604060406040003c384338433843003cb01bb01bb01b003c300c300c300c003cb01bb01bb01b003cb01bb01bb01b003cb01bb01bb01b003c604060406040003c",
        ),
        (
            (12, 12),
            6,
            &[7, 7],
            "982813ce7097252c4330b5f0f6893382",
            "b750654fc451003cb750654fc451003cb650644fc351003cb650634fc351003c5f16b3181f19003c5d16b2181d19003c5a16af181a19003c5916ae181919003c5616ac181619003c5416ab181419003c5116a9181119003cb450604fc051003cba506a4fc851003cb950694fc751003cb850684fc651003cb850674fc651003c6e16be182e19003c6b16bc182b19003c6516b7182519003c6216b5182219003c5c16b1181c19003c5916ae181919003c5316aa181319003cb450604fc051003cbd506f4fcc51003cbc506e4fcb51003cbb506c4fca51003cba506b4fc951003cb950694fc751003c7816c8183819003c6f16bf182f19003c6b16bc182b19003c6216b5182219003c5d16b2181d19003c5416ab181419003cb450604fc051003cbd506f4fcc51003cbc506e4fcb51003cbb506c4fca51003cba506b4fc951003cb950694fc751003c7816c8183819003c6f16bf182f19003c6b16bc182b19003c6216b5182219003c5d16b2181d19003c5416ab181419003cb450604fc051003cc050744fd051003cc050744fd051003cc050744fd051003cc050744fd051003cc050744fd051003cb01600197019003cb01600197019003cb01600197019003cb01600197019003cb01600197019003cb01600197019003cc050744fd051003cbd506f4fcc51003cbd506f4fcc51003cbd506f4fcc51003cbd506f4fcc51003cbd506f4fcc51003cbd506f4fcc51003c9816e8185819003c9816e8185819003c9816e8185819003c9816e8185819003c9816e8185819003cbd506f4fcc51003cb450604fc051003cb450604fc051003cb550614fc151003cb550624fc251003cb650634fc351003cb650644fc351003c6b16bc182b19003c6e16be182e19003c7416c4183419003c7716c7183719003c7d16cd183d19003cba506a4fc851003cc050744fd051003cbf50734fcf51003cbe50714fce51003cbd50704fcd51003cbc506e4fcb51003cbc506d4fcb51003c8716d7184719003c8316d3184319003c7a16ca183a19003c7516c5183519003c6c16bd182c19003cb750654fc451003cb450604fc051003cb450604fc051003cb450614fc151003cb450614fc151003cb550614fc151003cb550624fc251003cb550634fc251003c5f16b3181f19003c6216b5182219003c6316b6182319003c6616b8182619003cb750654fc451003cbd506f4fcc51003cbc506e4fcb51003cbb506d4fca51003cbb506c4fca51003cba506b4fc951003cba506a4fc851003cb950694fc751003c7a16ca183a19003c7416c4183419003c7116c1183119003c6b16bc182b19003cb750654fc451003cb750654fc451003cb750664fc551003cb850684fc651003cb950684fc751003cba506a4fc851003cbb506b4fc951003cbc506d4fcb51003c9516e5185519003c9e16ee185e19003ca216f2186219003cab16fb186b19003cc050744fd051003cc050744fd051003cbf50724fcf51003cbd50704fcd51003cbd506f4fcc51003cbb506c4fca51003cba506b4fc951003cb950684fc751003cb850674fc651003c6816ba182819003c6216b5182219003c5616ac181619003cb450604fc051003c",
        ),
    ];
}
