//! Block-compressed texel decoding (Public: the S3TC/RGTC rules of the
//! Khronos Data Format Specification §§19–20 and the ETC2/EAC rules of its
//! §§21–22 and OpenGL ES 3.0 Annex C).
//!
//! Each decoder returns one texel of a 4x4 block as `[f64; 4]` before any
//! sRGB conversion. Interpolated BC endpoints are exact fractions of the
//! expanded endpoints (Inferred: hardware rounding of the interpolation is
//! unrecorded and conformance allows that freedom). BC6H and BC7 decode in
//! [`super::bptc`], ASTC in [`super::astc`]; PVRTC refuses by name in
//! [`super::texel`].

/// A texel's position inside its block (`x`, `y`).
pub type Position = (u32, u32);

fn u64_le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().expect("a block half is 8 bytes"))
}

fn u64_be(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes[..8].try_into().expect("a block half is 8 bytes"))
}

fn expand(value: u32, bits: u32) -> u32 {
    (value << (8 - bits)) | (value >> (2 * bits - 8))
}

/// An R5G6B5 endpoint (R in the high bits) as unorm floats.
fn endpoint_565(word: u32) -> [f64; 3] {
    [
        f64::from(word >> 11 & 0x1f) / 31.0,
        f64::from(word >> 5 & 0x3f) / 63.0,
        f64::from(word & 0x1f) / 31.0,
    ]
}

fn mix(a: [f64; 3], b: [f64; 3], wa: f64, wb: f64, total: f64) -> [f64; 3] {
    [0, 1, 2].map(|c| (a[c] * wa + b[c] * wb) / total)
}

/// The colour half of BC1, BC2 and BC3. `four_colour` forces the
/// four-colour palette (BC2 and BC3 always use it).
fn bc1_colour(block: &[u8], (x, y): Position, four_colour: bool) -> [f64; 4] {
    let word = u64_le(block);
    let c0 = (word & 0xffff) as u32;
    let c1 = (word >> 16 & 0xffff) as u32;
    let index = (word >> (32 + 2 * (4 * y + x))) & 3;
    let (e0, e1) = (endpoint_565(c0), endpoint_565(c1));
    let rgb = match index {
        0 => e0,
        1 => e1,
        2 if four_colour || c0 > c1 => mix(e0, e1, 2.0, 1.0, 3.0),
        2 => mix(e0, e1, 1.0, 1.0, 2.0),
        _ if four_colour || c0 > c1 => mix(e0, e1, 1.0, 2.0, 3.0),
        _ => return [0.0; 4],
    };
    [rgb[0], rgb[1], rgb[2], 1.0]
}

/// One BC4 channel (also BC3 alpha and each BC5 channel).
fn bc4_channel(block: &[u8], (x, y): Position, signed: bool) -> f64 {
    let word = u64_le(block);
    let index = (word >> (16 + 3 * (4 * y + x))) & 7;
    let (e0, e1, unsigned_order) = if signed {
        let to = |b: u64| f64::from((b as u8 as i8).max(-127)) / 127.0;
        (
            to(word & 0xff),
            to(word >> 8 & 0xff),
            (word as u8 as i8) > (word >> 8) as u8 as i8,
        )
    } else {
        let to = |b: u64| (b & 0xff) as f64 / 255.0;
        (to(word), to(word >> 8), (word & 0xff) > (word >> 8 & 0xff))
    };
    let (low, high) = if signed { (-1.0, 1.0) } else { (0.0, 1.0) };
    match index {
        0 => e0,
        1 => e1,
        i if unsigned_order => (e0 * (8 - i) as f64 + e1 * (i - 1) as f64) / 7.0,
        6 => low,
        7 => high,
        i => (e0 * (6 - i) as f64 + e1 * (i - 1) as f64) / 5.0,
    }
}

pub fn bc1(block: &[u8], at: Position) -> [f64; 4] {
    bc1_colour(block, at, false)
}

pub fn bc2(block: &[u8], (x, y): Position) -> [f64; 4] {
    let alpha = (u64_le(block) >> (4 * (4 * y + x))) & 0xf;
    let mut texel = bc1_colour(&block[8..], (x, y), true);
    texel[3] = alpha as f64 / 15.0;
    texel
}

pub fn bc3(block: &[u8], at: Position) -> [f64; 4] {
    let mut texel = bc1_colour(&block[8..], at, true);
    texel[3] = bc4_channel(block, at, false);
    texel
}

pub fn bc4(block: &[u8], at: Position, signed: bool) -> [f64; 4] {
    [bc4_channel(block, at, signed), 0.0, 0.0, 1.0]
}

pub fn bc5(block: &[u8], at: Position, signed: bool) -> [f64; 4] {
    [
        bc4_channel(block, at, signed),
        bc4_channel(&block[8..], at, signed),
        0.0,
        1.0,
    ]
}

/// ETC1 modifier tables (codeword, small and large magnitude).
const ETC_MODIFIERS: [[i32; 2]; 8] = [
    [2, 8],
    [5, 17],
    [9, 29],
    [13, 42],
    [18, 60],
    [24, 80],
    [33, 106],
    [47, 183],
];
/// T and H mode distances.
const ETC_DISTANCES: [i32; 8] = [3, 6, 11, 16, 23, 32, 41, 64];
/// EAC modifier tables.
const EAC_MODIFIERS: [[i32; 8]; 16] = [
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

fn bits(word: u64, high: u32, count: u32) -> u32 {
    ((word >> (high + 1 - count)) & ((1 << count) - 1)) as u32
}

fn clamp8(value: i32) -> i32 {
    value.clamp(0, 255)
}

fn rgb8(c: [i32; 3]) -> [f64; 4] {
    [
        f64::from(c[0]) / 255.0,
        f64::from(c[1]) / 255.0,
        f64::from(c[2]) / 255.0,
        1.0,
    ]
}

fn add(c: [i32; 3], d: i32) -> [i32; 3] {
    c.map(|v| clamp8(v + d))
}

/// ETC2 RGB. `punchthrough` is ETC2 RGB8A1: bit 33 is the opaque flag,
/// individual mode is absent and, when not opaque, index 2 is transparent
/// black and the small modifiers are zero.
pub fn etc2(block: &[u8], (x, y): Position, punchthrough: bool) -> [f64; 4] {
    let word = u64_be(block);
    let k = 4 * x + y;
    let msb = (word >> (16 + k)) & 1;
    let lsb = (word >> k) & 1;
    let index = (msb << 1 | lsb) as usize;
    let flag = word >> 33 & 1 == 1;
    let differential = flag || punchthrough;
    let transparent = punchthrough && !flag;
    if !differential {
        let flip = word >> 32 & 1 == 1;
        let second = if flip { y >= 2 } else { x >= 2 };
        let shift = if second { 4 } else { 0 };
        let colour = [63, 55, 47].map(|high| expand(bits(word, high - shift, 4), 4) as i32);
        let table = bits(word, if second { 36 } else { 39 }, 3) as usize;
        return rgb8(add(colour, modifier(table, index, false)));
    }
    let base = [63, 55, 47].map(|high| bits(word, high, 5) as i32);
    let delta = [58, 50, 42].map(|high| {
        let d = bits(word, high, 3) as i32;
        if d >= 4 { d - 8 } else { d }
    });
    let second_base = [0, 1, 2].map(|c| base[c] + delta[c]);
    let overflow = |c: usize| !(0..32).contains(&second_base[c]);
    if overflow(0) {
        // T mode.
        let r1 = bits(word, 60, 2) << 2 | bits(word, 57, 2);
        let c1 = [r1, bits(word, 55, 4), bits(word, 51, 4)].map(|v| expand(v, 4) as i32);
        let c2 = [47, 43, 39].map(|high| expand(bits(word, high, 4), 4) as i32);
        let d = ETC_DISTANCES[(bits(word, 35, 2) << 1 | bits(word, 32, 1)) as usize];
        if transparent && index == 2 {
            return [0.0; 4];
        }
        return rgb8([c1, add(c2, d), c2, add(c2, -d)][index]);
    }
    if overflow(1) {
        // H mode.
        let r1 = bits(word, 62, 4);
        let g1 = bits(word, 58, 3) << 1 | bits(word, 52, 1);
        let b1 = bits(word, 51, 1) << 3 | bits(word, 49, 3);
        let first = [r1, g1, b1];
        let second = [bits(word, 46, 4), bits(word, 42, 4), bits(word, 38, 4)];
        let pack = |c: [u32; 3]| c[0] << 8 | c[1] << 4 | c[2];
        let order = u32::from(pack(first) >= pack(second));
        let d = ETC_DISTANCES[(bits(word, 34, 1) << 2 | bits(word, 32, 1) << 1 | order) as usize];
        let (c1, c2) = (
            first.map(|v| expand(v, 4) as i32),
            second.map(|v| expand(v, 4) as i32),
        );
        if transparent && index == 2 {
            return [0.0; 4];
        }
        return rgb8([add(c1, d), add(c1, -d), add(c2, d), add(c2, -d)][index]);
    }
    if overflow(2) {
        // Planar mode (always opaque).
        let ro = bits(word, 62, 6);
        let go = bits(word, 56, 1) << 6 | bits(word, 54, 6);
        let bo = bits(word, 48, 1) << 5 | bits(word, 44, 2) << 3 | bits(word, 41, 3);
        let rh = bits(word, 38, 5) << 1 | bits(word, 32, 1);
        let gh = bits(word, 31, 7);
        let bh = bits(word, 24, 6);
        let rv = bits(word, 18, 6);
        let gv = bits(word, 12, 7);
        let bv = bits(word, 5, 6);
        let e = |v: u32, n: u32| expand(v, n) as i32;
        let (x, y) = (x as i32, y as i32);
        let plane = |o: i32, h: i32, v: i32| clamp8((x * (h - o) + y * (v - o) + 4 * o + 2) >> 2);
        return rgb8([
            plane(e(ro, 6), e(rh, 6), e(rv, 6)),
            plane(e(go, 7), e(gh, 7), e(gv, 7)),
            plane(e(bo, 6), e(bh, 6), e(bv, 6)),
        ]);
    }
    let flip = word >> 32 & 1 == 1;
    let second = if flip { y >= 2 } else { x >= 2 };
    let colour = if second { second_base } else { base }.map(|v| expand(v as u32, 5) as i32);
    let table = bits(word, if second { 36 } else { 39 }, 3) as usize;
    if transparent && index == 2 {
        return [0.0; 4];
    }
    rgb8(add(colour, modifier(table, index, transparent)))
}

fn modifier(table: usize, index: usize, zero_small: bool) -> i32 {
    let [small, large] = ETC_MODIFIERS[table];
    let small = if zero_small { 0 } else { small };
    [small, large, -small, -large][index]
}

/// One EAC block's indexed value: (base, multiplier, modifier).
fn eac_parts(block: &[u8], (x, y): Position) -> (u64, i32, i32) {
    let word = u64_be(block);
    let k = 4 * x + y;
    let index = (word >> (45 - 3 * k)) & 7;
    let table = (word >> 48 & 0xf) as usize;
    (
        word >> 56,
        (word >> 52 & 0xf) as i32,
        EAC_MODIFIERS[table][index as usize],
    )
}

/// EAC 8-bit alpha (ETC2 RGBA8).
pub fn eac_alpha(block: &[u8], at: Position) -> f64 {
    let (base, multiplier, modifier) = eac_parts(block, at);
    f64::from(clamp8(base as i32 + modifier * multiplier)) / 255.0
}

/// One EAC 11-bit channel.
pub fn eac11(block: &[u8], at: Position, signed: bool) -> f64 {
    let (base, multiplier, modifier) = eac_parts(block, at);
    let scaled = if multiplier == 0 {
        modifier
    } else {
        modifier * multiplier * 8
    };
    if signed {
        let base = i32::from(base as u8 as i8).max(-127);
        f64::from((base * 8 + scaled).clamp(-1023, 1023)) / 1023.0
    } else {
        f64::from((base as i32 * 8 + 4 + scaled).clamp(0, 2047)) / 2047.0
    }
}

pub fn etc2_rgba8(block: &[u8], at: Position) -> [f64; 4] {
    let mut texel = etc2(&block[8..], at, false);
    texel[3] = eac_alpha(block, at);
    texel
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bc1_palettes_and_transparency() {
        // c0 = pure red (0xf800) > c1 = pure blue (0x001f): four colours.
        let mut block = [0x00, 0xf8, 0x1f, 0x00, 0, 0, 0, 0];
        // Texel 1 index 1, texel 2 index 2, texel 3 index 3.
        block[4] = 0b11_10_01_00;
        assert_eq!(bc1(&block, (0, 0)), [1.0, 0.0, 0.0, 1.0]);
        assert_eq!(bc1(&block, (1, 0)), [0.0, 0.0, 1.0, 1.0]);
        assert_eq!(bc1(&block, (2, 0)), [2.0 / 3.0, 0.0, 1.0 / 3.0, 1.0]);
        // Swapped endpoints: three colours and transparent black.
        let swapped = [0x1f, 0x00, 0x00, 0xf8, block[4], 0, 0, 0];
        assert_eq!(bc1(&swapped, (2, 0)), [0.5, 0.0, 0.5, 1.0]);
        assert_eq!(bc1(&swapped, (3, 0)), [0.0; 4]);
    }

    #[test]
    fn bc4_interpolates_eight_or_six_values() {
        // e0 = 255 > e1 = 0; texel 0 index 2 = 6/7.
        let block = [255, 0, 2, 0, 0, 0, 0, 0];
        assert!((bc4(&block, (0, 0), false)[0] - 6.0 / 7.0).abs() < 1e-12);
        // e0 = 0 <= e1 = 255; texel 0 index 6 = 0, index 7 = 1.
        let low = [0, 255, 6, 0, 0, 0, 0, 0];
        let high = [0, 255, 7, 0, 0, 0, 0, 0];
        assert_eq!(bc4(&low, (0, 0), false)[0], 0.0);
        assert_eq!(bc4(&high, (0, 0), false)[0], 1.0);
        let signed = [0x80, 0x7f, 0, 0, 0, 0, 0, 0];
        assert_eq!(bc4(&signed, (0, 0), true)[0], -1.0);
    }

    #[test]
    fn etc1_individual_and_differential_modes() {
        // Individual mode: R1 = 0xf, others 0, table 0, all indices 0 (+2).
        let individual = [0xf0, 0x00, 0x00, 0x00, 0, 0, 0, 0];
        assert_eq!(etc2(&individual, (0, 0), false), rgb8([255, 2, 2]));
        assert_eq!(etc2(&individual, (2, 0), false), rgb8([2, 2, 2]));
        // Differential: base R = 16, dR = +1, indices 3 (-large = -8).
        let mut diff = [0x81, 0x00, 0x00, 0x02, 0xff, 0xff, 0xff, 0xff];
        let base = expand(16, 5) as i32;
        assert_eq!(etc2(&diff, (0, 0), false), rgb8([base - 8, 0, 0]));
        assert_eq!(
            etc2(&diff, (3, 0), false),
            rgb8([expand(17, 5) as i32 - 8, 0, 0])
        );
        // Punch-through, not opaque: index 2 is transparent.
        diff[3] = 0x00;
        diff[6] = 0x00;
        diff[7] = 0x00;
        assert_eq!(etc2(&diff, (0, 0), true), [0.0; 4]);
    }

    #[test]
    fn etc2_planar_mode_interpolates() {
        // B = 31 with dB = +1 overflows: planar. All colours 0 except BO.
        // Planar origin blue 6 bits: bit 48, bits 44..43, bits 41..39.
        let word: u64 = (31 << 43) | (1 << 40) | (1 << 33);
        let block = word.to_be_bytes();
        let texel = etc2(&block, (0, 0), false);
        let bo = bits(word, 48, 1) << 5 | bits(word, 44, 2) << 3 | bits(word, 41, 3);
        assert_eq!(texel[2], f64::from(expand(bo, 6) as i32) / 255.0);
    }

    #[test]
    fn eac_alpha_and_r11() {
        // base 128, multiplier 2, table 0, every index 7 (+14).
        let block = [128, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(eac_alpha(&block, (1, 2)), f64::from(128 + 28) / 255.0);
        assert_eq!(
            eac11(&block, (1, 2), false),
            f64::from(128 * 8 + 4 + 14 * 16) / 2047.0
        );
    }
}
