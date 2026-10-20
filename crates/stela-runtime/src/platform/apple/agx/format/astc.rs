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
}
