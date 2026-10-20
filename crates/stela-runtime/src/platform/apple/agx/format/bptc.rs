//! BPTC block decoding: BC7 (unorm) and BC6H (signed and unsigned half
//! float). Public: the Khronos Data Format Specification's BPTC chapter (the
//! mode tables, endpoint packing, P-bits, anchors, interpolation weights and
//! the BC6H unquantization and half-float finish), with the hardware codes
//! 0x79 (BC6H signed), 0x7a (BC6H unsigned) and 0x7b (BC7) from Mesa
//! `cmdbuf.xml` and `layout/formats.c`.
//!
//! The partition tables are the specification's, as 16-bit masks (2 subsets,
//! bit `i` set when texel `i` is in subset 1) and 32-bit pairs (3 subsets, two
//! bits per texel). They were checked against a host GPU's BC7 decoder, and
//! the 2-subset anchors against the specification's anchor table.
//!
//! Reserved encodings decode as the specification directs: a BC7 block with
//! no mode bit set, and the four reserved BC6H modes, decode to zero in every
//! channel (BC7 alpha included).

use super::block::Position;

/// 2-subset partitions (texel `i` in subset 1 when bit `i` is set).
const PARTITIONS_2: [u16; 64] = [
    0xcccc, 0x8888, 0xeeee, 0xecc8, 0xc880, 0xfeec, 0xfec8, 0xec80, 0xc800, 0xffec, 0xfe80, 0xe800,
    0xffe8, 0xff00, 0xfff0, 0xf000, 0xf710, 0x008e, 0x7100, 0x08ce, 0x008c, 0x7310, 0x3100, 0x8cce,
    0x088c, 0x3110, 0x6666, 0x366c, 0x17e8, 0x0ff0, 0x718e, 0x399c, 0xaaaa, 0xf0f0, 0x5a5a, 0x33cc,
    0x3c3c, 0x55aa, 0x9696, 0xa55a, 0x73ce, 0x13c8, 0x324c, 0x3bdc, 0x6996, 0xc33c, 0x9966, 0x0660,
    0x0272, 0x04e4, 0x4e40, 0x2720, 0xc936, 0x936c, 0x39c6, 0x639c, 0x9336, 0x9cc6, 0x817e, 0xe718,
    0xccf0, 0x0fcc, 0x7744, 0xee22,
];

/// The anchor texel of subset 1 in each 2-subset partition.
const ANCHOR_2: [u8; 64] = [
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 2, 8, 2, 2, 8, 8, 15, 2, 8,
    2, 2, 8, 8, 2, 2, 15, 15, 6, 8, 2, 8, 15, 15, 2, 8, 2, 2, 2, 15, 15, 6, 6, 2, 6, 8, 15, 15, 2,
    2, 15, 15, 15, 15, 15, 2, 2, 15,
];

/// 3-subset partitions (texel `i`'s subset in bits `2i + 1..2i`).
const PARTITIONS_3: [u32; 64] = [
    0xaa685050, 0x6a5a5040, 0x5a5a4200, 0x5450a0a8, 0xa5a50000, 0xa0a05050, 0x5555a0a0, 0x5a5a5050,
    0xaa550000, 0xaa555500, 0xaaaa5500, 0x90909090, 0x94949494, 0xa4a4a4a4, 0xa9a59450, 0x2a0a4250,
    0xa5945040, 0x0a425054, 0xa5a5a500, 0x55a0a0a0, 0xa8a85454, 0x6a6a4040, 0xa4a45000, 0x1a1a0500,
    0x0050a4a4, 0xaaa59090, 0x14696914, 0x69691400, 0xa08585a0, 0xaa821414, 0x50a4a450, 0x6a5a0200,
    0xa9a58000, 0x5090a0a8, 0xa8a09050, 0x24242424, 0x00aa5500, 0x24924924, 0x24499224, 0x50a50a50,
    0x500aa550, 0xaaaa4444, 0x66660000, 0xa5a0a5a0, 0x50a050a0, 0x69286928, 0x44aaaa44, 0x66666600,
    0xaa444444, 0x54a854a8, 0x95809580, 0x96969600, 0xa85454a8, 0x80959580, 0xaa141414, 0x96960000,
    0xaaaa1414, 0xa05050a0, 0xa0a5a5a0, 0x96000000, 0x40804080, 0xa9a8a9a8, 0xaaaaaa44, 0x2a4a5254,
];

/// The anchor texels of subsets 1 and 2 in each 3-subset partition.
const ANCHOR_3: [(u8, u8); 64] = [
    (3, 15),
    (3, 8),
    (15, 8),
    (15, 3),
    (8, 15),
    (3, 15),
    (15, 3),
    (15, 8),
    (8, 15),
    (8, 15),
    (6, 15),
    (6, 15),
    (6, 15),
    (5, 15),
    (3, 15),
    (3, 8),
    (3, 15),
    (3, 8),
    (8, 15),
    (15, 3),
    (3, 15),
    (3, 8),
    (6, 15),
    (10, 8),
    (5, 3),
    (8, 15),
    (8, 6),
    (6, 10),
    (8, 15),
    (5, 15),
    (15, 10),
    (15, 8),
    (8, 15),
    (15, 3),
    (3, 15),
    (5, 10),
    (6, 10),
    (10, 8),
    (8, 9),
    (15, 10),
    (15, 6),
    (3, 15),
    (15, 8),
    (5, 15),
    (15, 3),
    (15, 6),
    (15, 6),
    (15, 8),
    (3, 15),
    (15, 3),
    (5, 15),
    (5, 15),
    (5, 15),
    (8, 15),
    (5, 15),
    (10, 15),
    (5, 15),
    (10, 15),
    (8, 15),
    (13, 15),
    (15, 3),
    (12, 15),
    (3, 15),
    (3, 8),
];

const WEIGHTS_2: [u32; 4] = [0, 21, 43, 64];
const WEIGHTS_3: [u32; 8] = [0, 9, 18, 27, 37, 46, 55, 64];
const WEIGHTS_4: [u32; 16] = [0, 4, 9, 13, 17, 21, 26, 30, 34, 38, 43, 47, 51, 55, 60, 64];

fn weights(bits: u32) -> &'static [u32] {
    match bits {
        2 => &WEIGHTS_2,
        3 => &WEIGHTS_3,
        _ => &WEIGHTS_4,
    }
}

/// A little-endian bit reader over one 128-bit block.
struct Bits {
    value: u128,
    at: u32,
}

impl Bits {
    fn new(block: &[u8]) -> Self {
        Bits {
            value: u128::from_le_bytes(block[..16].try_into().expect("a BPTC block is 16 bytes")),
            at: 0,
        }
    }

    fn take(&mut self, count: u32) -> u32 {
        let v = (self.value >> self.at) as u32 & ((1u64 << count) - 1) as u32;
        self.at += count;
        v
    }

    /// The bits at `start..start + count`.
    fn field(&self, start: u32, count: u32) -> u32 {
        (self.value >> start) as u32 & ((1u64 << count) - 1) as u32
    }
}

/// The subset of texel `t` and whether it is its subset's anchor.
fn subset(subsets: u32, partition: usize, t: usize) -> (usize, bool) {
    match subsets {
        1 => (0, t == 0),
        2 => {
            let s = usize::from(PARTITIONS_2[partition] >> t & 1 == 1);
            (s, t == [0, usize::from(ANCHOR_2[partition])][s])
        }
        _ => {
            let s = (PARTITIONS_3[partition] >> (2 * t) & 3) as usize;
            let (a1, a2) = ANCHOR_3[partition];
            (s, t == [0, usize::from(a1), usize::from(a2)][s])
        }
    }
}

/// Texel `t`'s index from an index field starting at `start`: `bits` per
/// texel, one fewer for each anchor.
fn index(block: &Bits, start: u32, bits: u32, subsets: u32, partition: usize, t: usize) -> u32 {
    let mut at = start;
    for u in 0..t {
        at += bits - u32::from(subset(subsets, partition, u).1);
    }
    let width = bits - u32::from(subset(subsets, partition, t).1);
    block.field(at, width)
}

fn interpolate(a: u32, b: u32, weight: u32) -> u32 {
    ((64 - weight) * a + weight * b + 32) >> 6
}

struct Bc7Mode {
    subsets: u32,
    partition_bits: u32,
    rotation_bits: u32,
    selection_bits: u32,
    colour_bits: u32,
    alpha_bits: u32,
    endpoint_pbits: bool,
    shared_pbits: bool,
    index_bits: u32,
    second_index_bits: u32,
}

const fn bc7_mode(row: [u32; 10]) -> Bc7Mode {
    Bc7Mode {
        subsets: row[0],
        partition_bits: row[1],
        rotation_bits: row[2],
        selection_bits: row[3],
        colour_bits: row[4],
        alpha_bits: row[5],
        endpoint_pbits: row[6] == 1,
        shared_pbits: row[7] == 1,
        index_bits: row[8],
        second_index_bits: row[9],
    }
}

/// BC7 modes 0..7: subsets, partition, rotation and index-selection bits,
/// colour and alpha bits, endpoint and shared P-bits, index bits.
const BC7_MODES: [Bc7Mode; 8] = [
    bc7_mode([3, 4, 0, 0, 4, 0, 1, 0, 3, 0]),
    bc7_mode([2, 6, 0, 0, 6, 0, 0, 1, 3, 0]),
    bc7_mode([3, 6, 0, 0, 5, 0, 0, 0, 2, 0]),
    bc7_mode([2, 6, 0, 0, 7, 0, 1, 0, 2, 0]),
    bc7_mode([1, 0, 2, 1, 5, 6, 0, 0, 2, 3]),
    bc7_mode([1, 0, 2, 0, 7, 8, 0, 0, 2, 2]),
    bc7_mode([1, 0, 0, 0, 7, 7, 1, 0, 4, 0]),
    bc7_mode([2, 6, 0, 0, 5, 5, 1, 0, 2, 0]),
];

/// Expand a `bits`-wide value to 8 bits by replicating its high bits.
fn expand8(value: u32, bits: u32) -> u32 {
    let v = value << (8 - bits);
    v | v >> bits
}

/// BC7 texel at (`x`, `y`) as unorm values.
pub fn bc7(block: &[u8], (x, y): Position) -> [f64; 4] {
    let mut bits = Bits::new(block);
    let Some(number) = (0..8).find(|&m| bits.field(m, 1) == 1) else {
        return [0.0; 4];
    };
    bits.take(number + 1);
    let mode = &BC7_MODES[number as usize];
    let partition = bits.take(mode.partition_bits) as usize;
    let rotation = bits.take(mode.rotation_bits);
    let selection = bits.take(mode.selection_bits);
    let endpoints = 2 * mode.subsets as usize;
    // Endpoints: channel-major, then subset, then e0/e1.
    let mut e = [[0u32; 4]; 6];
    for c in 0..3 {
        for endpoint in e.iter_mut().take(endpoints) {
            endpoint[c] = bits.take(mode.colour_bits);
        }
    }
    for endpoint in e.iter_mut().take(endpoints) {
        endpoint[3] = bits.take(mode.alpha_bits);
    }
    let mut p = [0u32; 6];
    if mode.endpoint_pbits {
        for slot in p.iter_mut().take(endpoints) {
            *slot = bits.take(1);
        }
    } else if mode.shared_pbits {
        for s in 0..mode.subsets as usize {
            let bit = bits.take(1);
            p[2 * s] = bit;
            p[2 * s + 1] = bit;
        }
    }
    let has_pbit = mode.endpoint_pbits || mode.shared_pbits;
    for (i, endpoint) in e.iter_mut().enumerate().take(endpoints) {
        for (c, value) in endpoint.iter_mut().enumerate() {
            let width = if c == 3 {
                mode.alpha_bits
            } else {
                mode.colour_bits
            };
            if width == 0 {
                *value = 255;
                continue;
            }
            let (v, w) = if has_pbit {
                (*value << 1 | p[i], width + 1)
            } else {
                (*value, width)
            };
            *value = expand8(v, w);
        }
    }
    let t = (4 * y + x) as usize;
    let (s, _) = subset(mode.subsets, partition, t);
    let first = bits.at;
    let second = first + 16 * mode.index_bits - mode.subsets;
    let primary = index(&bits, first, mode.index_bits, mode.subsets, partition, t);
    let (colour_index, colour_bits, alpha_index, alpha_bits) = if mode.second_index_bits == 0 {
        (primary, mode.index_bits, primary, mode.index_bits)
    } else {
        let secondary = index(&bits, second, mode.second_index_bits, 1, 0, t);
        if selection == 1 {
            (secondary, mode.second_index_bits, primary, mode.index_bits)
        } else {
            (primary, mode.index_bits, secondary, mode.second_index_bits)
        }
    };
    let (e0, e1) = (e[2 * s], e[2 * s + 1]);
    let mut out = [0u32; 4];
    for c in 0..3 {
        out[c] = interpolate(e0[c], e1[c], weights(colour_bits)[colour_index as usize]);
    }
    out[3] = interpolate(e0[3], e1[3], weights(alpha_bits)[alpha_index as usize]);
    match rotation {
        1 => out.swap(0, 3),
        2 => out.swap(1, 3),
        3 => out.swap(2, 3),
        _ => {}
    }
    out.map(|v| f64::from(v) / 255.0)
}

/// A BC6H header field: `count` bits of endpoint value `target` (0..12 for
/// r0, g0, b0, r1, g1, b1, r2, g2, b2, r3, g3, b3) starting at `low`, read
/// from the block from bit `at` upward; `reversed` stores the field's bits
/// high to low.
#[derive(Clone, Copy)]
struct Field {
    target: u8,
    low: u8,
    count: u8,
    reversed: bool,
}

const fn f(target: u8, high: u8, low: u8) -> Field {
    Field {
        target,
        low,
        count: high - low + 1,
        reversed: false,
    }
}

const fn rev(target: u8, low: u8, high: u8) -> Field {
    Field {
        target,
        low,
        count: high - low + 1,
        reversed: true,
    }
}

// Endpoint value numbers.
const R0: u8 = 0;
const G0: u8 = 1;
const B0: u8 = 2;
const R1: u8 = 3;
const G1: u8 = 4;
const B1: u8 = 5;
const R2: u8 = 6;
const G2: u8 = 7;
const B2: u8 = 8;
const R3: u8 = 9;
const G3: u8 = 10;
const B3: u8 = 11;

struct Bc6Mode {
    /// The mode number's bits and value (2 or 5 bits).
    mode_bits: u32,
    value: u32,
    subsets: u32,
    transformed: bool,
    /// Endpoint bits, then the delta bits of R, G and B.
    endpoint_bits: u32,
    delta_bits: [u32; 3],
    /// The header fields after the mode bits, in stream order.
    layout: &'static [Field],
}

const BC6_MODES: [Bc6Mode; 14] = [
    Bc6Mode {
        mode_bits: 2,
        value: 0b00,
        subsets: 2,
        transformed: true,
        endpoint_bits: 10,
        delta_bits: [5, 5, 5],
        layout: &[
            f(G2, 4, 4),
            f(B2, 4, 4),
            f(B3, 4, 4),
            f(R0, 9, 0),
            f(G0, 9, 0),
            f(B0, 9, 0),
            f(R1, 4, 0),
            f(G3, 4, 4),
            f(G2, 3, 0),
            f(G1, 4, 0),
            f(B3, 0, 0),
            f(G3, 3, 0),
            f(B1, 4, 0),
            f(B3, 1, 1),
            f(B2, 3, 0),
            f(R2, 4, 0),
            f(B3, 2, 2),
            f(R3, 4, 0),
            f(B3, 3, 3),
        ],
    },
    Bc6Mode {
        mode_bits: 2,
        value: 0b01,
        subsets: 2,
        transformed: true,
        endpoint_bits: 7,
        delta_bits: [6, 6, 6],
        layout: &[
            f(G2, 5, 5),
            f(G3, 4, 4),
            f(G3, 5, 5),
            f(R0, 6, 0),
            f(B3, 0, 0),
            f(B3, 1, 1),
            f(B2, 4, 4),
            f(G0, 6, 0),
            f(B2, 5, 5),
            f(B3, 2, 2),
            f(G2, 4, 4),
            f(B0, 6, 0),
            f(B3, 3, 3),
            f(B3, 5, 5),
            f(B3, 4, 4),
            f(R1, 5, 0),
            f(G2, 3, 0),
            f(G1, 5, 0),
            f(G3, 3, 0),
            f(B1, 5, 0),
            f(B2, 3, 0),
            f(R2, 5, 0),
            f(R3, 5, 0),
        ],
    },
    Bc6Mode {
        mode_bits: 5,
        value: 0b00010,
        subsets: 2,
        transformed: true,
        endpoint_bits: 11,
        delta_bits: [5, 4, 4],
        layout: &[
            f(R0, 9, 0),
            f(G0, 9, 0),
            f(B0, 9, 0),
            f(R1, 4, 0),
            f(R0, 10, 10),
            f(G2, 3, 0),
            f(G1, 3, 0),
            f(G0, 10, 10),
            f(B3, 0, 0),
            f(G3, 3, 0),
            f(B1, 3, 0),
            f(B0, 10, 10),
            f(B3, 1, 1),
            f(B2, 3, 0),
            f(R2, 4, 0),
            f(B3, 2, 2),
            f(R3, 4, 0),
            f(B3, 3, 3),
        ],
    },
    Bc6Mode {
        mode_bits: 5,
        value: 0b00110,
        subsets: 2,
        transformed: true,
        endpoint_bits: 11,
        delta_bits: [4, 5, 4],
        layout: &[
            f(R0, 9, 0),
            f(G0, 9, 0),
            f(B0, 9, 0),
            f(R1, 3, 0),
            f(R0, 10, 10),
            f(G3, 4, 4),
            f(G2, 3, 0),
            f(G1, 4, 0),
            f(G0, 10, 10),
            f(G3, 3, 0),
            f(B1, 3, 0),
            f(B0, 10, 10),
            f(B3, 1, 1),
            f(B2, 3, 0),
            f(R2, 3, 0),
            f(B3, 0, 0),
            f(B3, 2, 2),
            f(R3, 3, 0),
            f(G2, 4, 4),
            f(B3, 3, 3),
        ],
    },
    Bc6Mode {
        mode_bits: 5,
        value: 0b01010,
        subsets: 2,
        transformed: true,
        endpoint_bits: 11,
        delta_bits: [4, 4, 5],
        layout: &[
            f(R0, 9, 0),
            f(G0, 9, 0),
            f(B0, 9, 0),
            f(R1, 3, 0),
            f(R0, 10, 10),
            f(B2, 4, 4),
            f(G2, 3, 0),
            f(G1, 3, 0),
            f(G0, 10, 10),
            f(B3, 0, 0),
            f(G3, 3, 0),
            f(B1, 4, 0),
            f(B0, 10, 10),
            f(B2, 3, 0),
            f(R2, 3, 0),
            f(B3, 1, 1),
            f(B3, 2, 2),
            f(R3, 3, 0),
            f(B3, 4, 4),
            f(B3, 3, 3),
        ],
    },
    Bc6Mode {
        mode_bits: 5,
        value: 0b01110,
        subsets: 2,
        transformed: true,
        endpoint_bits: 9,
        delta_bits: [5, 5, 5],
        layout: &[
            f(R0, 8, 0),
            f(B2, 4, 4),
            f(G0, 8, 0),
            f(G2, 4, 4),
            f(B0, 8, 0),
            f(B3, 4, 4),
            f(R1, 4, 0),
            f(G3, 4, 4),
            f(G2, 3, 0),
            f(G1, 4, 0),
            f(B3, 0, 0),
            f(G3, 3, 0),
            f(B1, 4, 0),
            f(B3, 1, 1),
            f(B2, 3, 0),
            f(R2, 4, 0),
            f(B3, 2, 2),
            f(R3, 4, 0),
            f(B3, 3, 3),
        ],
    },
    Bc6Mode {
        mode_bits: 5,
        value: 0b10010,
        subsets: 2,
        transformed: true,
        endpoint_bits: 8,
        delta_bits: [6, 5, 5],
        layout: &[
            f(R0, 7, 0),
            f(G3, 4, 4),
            f(B2, 4, 4),
            f(G0, 7, 0),
            f(B3, 2, 2),
            f(G2, 4, 4),
            f(B0, 7, 0),
            f(B3, 3, 3),
            f(B3, 4, 4),
            f(R1, 5, 0),
            f(G2, 3, 0),
            f(G1, 4, 0),
            f(B3, 0, 0),
            f(G3, 3, 0),
            f(B1, 4, 0),
            f(B3, 1, 1),
            f(B2, 3, 0),
            f(R2, 5, 0),
            f(R3, 5, 0),
        ],
    },
    Bc6Mode {
        mode_bits: 5,
        value: 0b10110,
        subsets: 2,
        transformed: true,
        endpoint_bits: 8,
        delta_bits: [5, 6, 5],
        layout: &[
            f(R0, 7, 0),
            f(B3, 0, 0),
            f(B2, 4, 4),
            f(G0, 7, 0),
            f(G2, 5, 5),
            f(G2, 4, 4),
            f(B0, 7, 0),
            f(G3, 5, 5),
            f(B3, 4, 4),
            f(R1, 4, 0),
            f(G3, 4, 4),
            f(G2, 3, 0),
            f(G1, 5, 0),
            f(G3, 3, 0),
            f(B1, 4, 0),
            f(B3, 1, 1),
            f(B2, 3, 0),
            f(R2, 4, 0),
            f(B3, 2, 2),
            f(R3, 4, 0),
            f(B3, 3, 3),
        ],
    },
    Bc6Mode {
        mode_bits: 5,
        value: 0b11010,
        subsets: 2,
        transformed: true,
        endpoint_bits: 8,
        delta_bits: [5, 5, 6],
        layout: &[
            f(R0, 7, 0),
            f(B3, 1, 1),
            f(B2, 4, 4),
            f(G0, 7, 0),
            f(B2, 5, 5),
            f(G2, 4, 4),
            f(B0, 7, 0),
            f(B3, 5, 5),
            f(B3, 4, 4),
            f(R1, 4, 0),
            f(G3, 4, 4),
            f(G2, 3, 0),
            f(G1, 4, 0),
            f(B3, 0, 0),
            f(G3, 3, 0),
            f(B1, 5, 0),
            f(B2, 3, 0),
            f(R2, 4, 0),
            f(B3, 2, 2),
            f(R3, 4, 0),
            f(B3, 3, 3),
        ],
    },
    Bc6Mode {
        mode_bits: 5,
        value: 0b11110,
        subsets: 2,
        transformed: false,
        endpoint_bits: 6,
        delta_bits: [6, 6, 6],
        layout: &[
            f(R0, 5, 0),
            f(G3, 4, 4),
            f(B3, 0, 0),
            f(B3, 1, 1),
            f(B2, 4, 4),
            f(G0, 5, 0),
            f(G2, 5, 5),
            f(B2, 5, 5),
            f(B3, 2, 2),
            f(G2, 4, 4),
            f(B0, 5, 0),
            f(G3, 5, 5),
            f(B3, 3, 3),
            f(B3, 5, 5),
            f(B3, 4, 4),
            f(R1, 5, 0),
            f(G2, 3, 0),
            f(G1, 5, 0),
            f(G3, 3, 0),
            f(B1, 5, 0),
            f(B2, 3, 0),
            f(R2, 5, 0),
            f(R3, 5, 0),
        ],
    },
    Bc6Mode {
        mode_bits: 5,
        value: 0b00011,
        subsets: 1,
        transformed: false,
        endpoint_bits: 10,
        delta_bits: [10, 10, 10],
        layout: &[
            f(R0, 9, 0),
            f(G0, 9, 0),
            f(B0, 9, 0),
            f(R1, 9, 0),
            f(G1, 9, 0),
            f(B1, 9, 0),
        ],
    },
    Bc6Mode {
        mode_bits: 5,
        value: 0b00111,
        subsets: 1,
        transformed: true,
        endpoint_bits: 11,
        delta_bits: [9, 9, 9],
        layout: &[
            f(R0, 9, 0),
            f(G0, 9, 0),
            f(B0, 9, 0),
            f(R1, 8, 0),
            f(R0, 10, 10),
            f(G1, 8, 0),
            f(G0, 10, 10),
            f(B1, 8, 0),
            f(B0, 10, 10),
        ],
    },
    Bc6Mode {
        mode_bits: 5,
        value: 0b01011,
        subsets: 1,
        transformed: true,
        endpoint_bits: 12,
        delta_bits: [8, 8, 8],
        layout: &[
            f(R0, 9, 0),
            f(G0, 9, 0),
            f(B0, 9, 0),
            f(R1, 7, 0),
            rev(R0, 10, 11),
            f(G1, 7, 0),
            rev(G0, 10, 11),
            f(B1, 7, 0),
            rev(B0, 10, 11),
        ],
    },
    Bc6Mode {
        mode_bits: 5,
        value: 0b01111,
        subsets: 1,
        transformed: true,
        endpoint_bits: 16,
        delta_bits: [4, 4, 4],
        layout: &[
            f(R0, 9, 0),
            f(G0, 9, 0),
            f(B0, 9, 0),
            f(R1, 3, 0),
            rev(R0, 10, 15),
            f(G1, 3, 0),
            rev(G0, 10, 15),
            f(B1, 3, 0),
            rev(B0, 10, 15),
        ],
    },
];

fn sign_extend(value: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((value << shift) as i32) >> shift
}

/// The 16-bit unquantized endpoint (Khronos BPTC "unquantize").
fn unquantize(value: i32, bits: u32, signed: bool) -> i32 {
    if !signed {
        if bits >= 15 {
            value
        } else if value == 0 {
            0
        } else if value == (1 << bits) - 1 {
            0xffff
        } else {
            ((value << 16) + 0x8000) >> bits
        }
    } else if bits >= 16 {
        value
    } else {
        let (negative, magnitude) = (value < 0, value.abs());
        let q = if magnitude == 0 {
            0
        } else if magnitude >= (1 << (bits - 1)) - 1 {
            0x7fff
        } else {
            ((magnitude << 15) + 0x4000) >> (bits - 1)
        };
        if negative { -q } else { q }
    }
}

/// The interpolated value as the half-float bit pattern the format names.
fn finish(value: i32, signed: bool) -> u16 {
    if !signed {
        ((value * 31) >> 6) as u16
    } else if value < 0 {
        0x8000 | (((-value) * 31) >> 5) as u16
    } else {
        ((value * 31) >> 5) as u16
    }
}

/// BC6H texel at (`x`, `y`) as floats; `signed` for the signed format.
pub fn bc6h(block: &[u8], (x, y): Position, signed: bool) -> [f64; 4] {
    let bits = Bits::new(block);
    let low2 = bits.field(0, 2);
    let mode = BC6_MODES.iter().find(|mode| {
        if mode.mode_bits == 2 {
            low2 == mode.value
        } else {
            low2 >= 2 && bits.field(0, 5) == mode.value
        }
    });
    let Some(mode) = mode else {
        return [0.0, 0.0, 0.0, 1.0];
    };
    let mut values = [0u32; 12];
    let mut at = mode.mode_bits;
    for field in mode.layout {
        let raw = bits.field(at, u32::from(field.count));
        let ordered = if field.reversed {
            raw.reverse_bits() >> (32 - u32::from(field.count))
        } else {
            raw
        };
        values[usize::from(field.target)] |= ordered << field.low;
        at += u32::from(field.count);
    }
    let partition = if mode.subsets == 2 {
        let p = bits.field(at, 5) as usize;
        at += 5;
        p
    } else {
        0
    };
    let count = 2 * mode.subsets as usize;
    let eb = mode.endpoint_bits;
    // Endpoint e's channel c, as a signed integer of `eb` bits.
    let mut endpoints = [[0i32; 3]; 4];
    for (e, endpoint) in endpoints.iter_mut().enumerate().take(count) {
        for (c, value) in endpoint.iter_mut().enumerate() {
            let raw = values[3 * e + c];
            *value = if e == 0 || !mode.transformed {
                if signed {
                    sign_extend(raw, eb)
                } else {
                    raw as i32
                }
            } else {
                let delta = sign_extend(raw, mode.delta_bits[c]);
                let base = values[c] as i32;
                let sum = ((base + delta) as u32) & ((1 << eb) - 1);
                if signed {
                    sign_extend(sum, eb)
                } else {
                    sum as i32
                }
            };
        }
    }
    let t = (4 * y + x) as usize;
    let (s, _) = subset(mode.subsets, partition, t);
    let index_bits = if mode.subsets == 2 { 3 } else { 4 };
    let i = index(&bits, at, index_bits, mode.subsets, partition, t);
    let weight = weights(index_bits)[i as usize];
    let mut out = [0.0, 0.0, 0.0, 1.0];
    for (c, channel) in out.iter_mut().enumerate().take(3) {
        let a = unquantize(endpoints[2 * s][c], eb, signed);
        let b = unquantize(endpoints[2 * s + 1][c], eb, signed);
        let value = ((64 - weight as i32) * a + weight as i32 * b + 32) >> 6;
        *channel = f64::from(crate::platform::apple::agx::isa::float::half_to_f32(
            finish(value, signed),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    struct Writer(u128, u32);

    impl Writer {
        fn put(&mut self, value: u32, bits: u32) -> &mut Self {
            self.0 |= u128::from(value & ((1u64 << bits) - 1) as u32) << self.1;
            self.1 += bits;
            self
        }
        fn block(&self) -> [u8; 16] {
            self.0.to_le_bytes()
        }
    }

    #[test]
    fn the_partition_tables_agree_with_their_anchors() {
        for p in 0..64 {
            assert_eq!(PARTITIONS_2[p] & 1, 0);
            assert_eq!(PARTITIONS_2[p] >> ANCHOR_2[p] & 1, 1);
            let (a1, a2) = ANCHOR_3[p];
            assert_eq!(PARTITIONS_3[p] & 3, 0);
            assert_eq!(PARTITIONS_3[p] >> (2 * a1) & 3, 1);
            assert_eq!(PARTITIONS_3[p] >> (2 * a2) & 3, 2);
        }
    }

    #[test]
    fn bc7_mode6_interpolates_its_endpoints() {
        // Mode 6: one subset, 7-bit colour and alpha with endpoint P-bits.
        let mut w = Writer(0, 0);
        w.put(1 << 6, 7);
        for _ in 0..3 {
            w.put(0, 7).put(127, 7);
        }
        w.put(0, 7).put(127, 7);
        w.put(0, 1).put(1, 1);
        // Texel 0 (anchor, 3 bits) index 0; texel 1 index 15.
        w.put(0, 3).put(15, 4);
        let block = w.block();
        assert_eq!(bc7(&block, (0, 0)), [0.0; 4]);
        assert_eq!(bc7(&block, (1, 0)), [1.0; 4]);
        // A block with no mode bit is reserved: zero.
        assert_eq!(bc7(&[0; 16], (0, 0)), [0.0; 4]);
    }

    #[test]
    fn bc7_mode5_rotates_alpha_into_red() {
        let mut w = Writer(0, 0);
        w.put(1 << 5, 6).put(1, 2);
        // Colour endpoints 7 bits: red 0..0, green 127..127, blue 0..0.
        w.put(0, 7)
            .put(0, 7)
            .put(127, 7)
            .put(127, 7)
            .put(0, 7)
            .put(0, 7);
        // Alpha 8 bits: 51..51.
        w.put(51, 8).put(51, 8);
        let block = w.block();
        // Rotation 1 swaps alpha and red.
        assert_eq!(bc7(&block, (0, 0)), [0.2, 1.0, 0.0, 0.0]);
    }

    #[test]
    fn bc6h_mode11_unquantizes_and_finishes_as_half() {
        // Mode 11 (0b00011): one subset, 10-bit endpoints, no transform.
        let mut w = Writer(0, 0);
        w.put(0b00011, 5);
        for v in [0, 0, 0, 1023, 1023, 1023] {
            w.put(v, 10);
        }
        let block = w.block();
        assert_eq!(bc6h(&block, (0, 0), false), [0.0, 0.0, 0.0, 1.0]);
        // Index 0 everywhere: texel 15 is e0 too. The maximum unsigned
        // endpoint finishes at 0xffff * 31 >> 6 = 0x7bff, the largest half.
        let ones = Writer(w.0 | (u128::MAX << 65), 0).block();
        let top = f64::from(crate::platform::apple::agx::isa::float::half_to_f32(0x7bff));
        assert_eq!(bc6h(&ones, (3, 3), false), [top, top, top, 1.0]);
        // Reserved modes decode to zero.
        assert_eq!(
            bc6h(
                &[0b10011, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                (0, 0),
                true
            ),
            [0.0, 0.0, 0.0, 1.0]
        );
    }

    /// A hex string's bytes.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn bc7_matches_a_host_decoder_in_every_mode() {
        let mut modes = [0; 9];
        for (mode, block, texels) in BC7_VECTORS {
            let (block, texels) = (hex(block), hex(texels));
            modes[usize::from(mode)] += 1;
            for t in 0..16 {
                let got = bc7(&block, (t % 4, t / 4)).map(|c| (c * 255.0).round() as u8);
                let at = 4 * t as usize;
                assert_eq!(
                    got,
                    texels[at..at + 4],
                    "mode {mode} {block:02x?} texel {t}"
                );
            }
        }
        // Modes 0..7 and the reserved encoding (no mode bit), two blocks each.
        assert_eq!(modes, [2; 9]);
    }

    #[test]
    fn bc6h_matches_a_host_decoder_in_every_mode() {
        for (signed, vectors) in [
            (true, &BC6H_SIGNED_VECTORS),
            (false, &BC6H_UNSIGNED_VECTORS),
        ] {
            let mut modes = [0; 32];
            for &(mode, block, texels) in vectors {
                let (block, texels) = (hex(block), hex(texels));
                modes[usize::from(mode)] += 1;
                for t in 0..16 {
                    let got = bc6h(&block, (t % 4, t / 4), signed);
                    let at = 6 * t as usize;
                    let want: [f64; 3] = core::array::from_fn(|c| {
                        let bits = u16::from_le_bytes([texels[at + 2 * c], texels[at + 2 * c + 1]]);
                        f64::from(crate::platform::apple::agx::isa::float::half_to_f32(bits))
                    });
                    assert_eq!(
                        got,
                        [want[0], want[1], want[2], 1.0],
                        "{signed} mode {mode:#x} {block:02x?} texel {t}"
                    );
                }
            }
            // The two 2-bit modes and the sixteen 5-bit modes (four of them
            // reserved), two blocks each.
            for (mode, &n) in modes.iter().enumerate() {
                let listed = mode < 2 || mode & 3 >= 2;
                assert_eq!(n, if listed { 2 } else { 0 }, "{signed} mode {mode:#x}");
            }
        }
    }

    // Host-decoder vectors, chosen by the procedure in the AGX research
    // notes (`docs/research/agx.md`, "Codec vectors"): random blocks with
    // each mode's header forced, decoded by the host GPU's BC7 and BC6H
    // samplers through Metal. BC7 texels are RGBA8, BC6H texels RGB half
    // bits (alpha is 1).
    const BC7_VECTORS: [(u8, &str, &str); 18] = [
        (
            0x00,
            "49da9d683295ddd16ba47b4f9dc8c3ce",
            "725fc2ff725fc2ffd69484ff4146e0ffa57aa2ffbe8793ff4146e0ff4146e0ffefa1c5ffefa699ff42e721ff4ace39ffefab6fffefab6fff49d236ff47d92fff",
        ),
        (
            0x01,
            "6238e0bb6894a2a399f9656574e69ef3",
            "c39691ff225399ffe7a48effe7a48eff225399ffe3a38fff416098ffdea3a3ff225399ff616d96ff847c94ffb9a1f9ffc39691ff02469bff616d96ff02469bff",
        ),
        (
            0x02,
            "ac39d00e5899cbe2bf42c147249dcca5",
            "e794adff4cbb91ffe794adff3bef3eff735ae7ffb63957ff934aa0ff00e718ffb63957ffb63957ff934aa0ffb5ff8cff4cbb91ffe794adff9ba7a0ff3bef3eff",
        ),
        (
            0x03,
            "e80c5f40a0be9ac7aa0d311c63515acc",
            "86f4d4ff86f4d4ff5eaa0cff6bc24eff81f363ff81c76cff81c76cff81f363ff81dd68ff81b171ff81c76cff81f363ff81c76cff81dd68ff81c76cff81dd68ff",
        ),
        (
            0x04,
            "f0c3ad3cabea641bc50a6f3bd3b2d3d3",
            "3e8b85a359adaaa859ad38a859ad5da83e8b85a366be38ab4d9daaa666be5dab327b5da166beaaab66be5dab256a859e59ad85a873ce85ad4d9daaa666be5dab",
        ),
        (
            0x05,
            "2021fa8135dc72d7d9020c43d293d375",
            "420e87bae958b7dcb240a7ba7926977579269775420e87dc420e87ba420e8797b240a775792697dc420e87bab240a775792697ba420e87bab240a775420e87ba",
        ),
        (
            0x06,
            "c0481a9156cd3f651bc3943ffe50dc58",
            "5c50846c2d1c5d474638725bafabc9ae51447b638b84ab92d3d3e7cb4638725bc8c7dec2d3d3e7cb2210543e5c50846cafabc9aebab8d2b78078a2895c50846c",
        ),
        (
            0x07,
            "80a8215a730f33bde34fef7aaa3432e0",
            "34e7a69ed49b649ad49b649ad6b6b3c634e7a69e2debadbad7cfffefd3821871d6b6b3c6d382187120f3baf334e7a69ed3821871d3821871d6b6b3c620f3baf3",
        ),
        (
            0x08,
            "00b8f5f784f6f364a906a9e6f12992a5",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x00,
            "0d70eed81ba334a8183c5f32cb1a3525",
            "3ce42aff2be824ff927149ff927149ff19eb1eff3ce42aff876628ff9e7d69ff6636abff3b7563ff466675ff6636abff3b7563ff6636abff5c469aff318452ff",
        ),
        (
            0x01,
            "c244575ee8d4cb89deb122062134845e",
            "10a124ff87eb87ff4a7096ff1e9540ff97f776ff8ff17fff97f776ff1e9540ff4a7096ff66d1aaff10a124ff2c895bff10a124ff5864b2ff744ce9ff2c895bff",
        ),
        (
            0x02,
            "cc4a4b189e3f42e4c083e6210352828f",
            "29fff7ff29fff7ff4a086bff524c6eff29fff7ff3fb3a6ff733399ff524c6eff4a086bff4a086bff84e784ff390063ff390063ff6b9b79ff84e784ff6b9b79ff",
        ),
        (
            0x03,
            "b89246f6cd81869056935479cc8967ea",
            "482ca3ff482ca3ffec10a8ff36a4e4ffb041bcff474b9affec10a8ff7273d0ff36a4e4ffb041bcff474b9affb041bcff7273d0ff7273d0ff474b9aff466892ff",
        ),
        (
            0x04,
            "b0a8ecf0a36fedd64538b3c6c986359a",
            "c6c0ef3ec6269c2d59a2df3bc684ce375962bd348e84ce378ea2df3b59269c2d8e269c2dfbdeff428e269c2dfba2df3bfb84ce375962bd34c6269c2d8e62bd34",
        ),
        (
            0x05,
            "a0384029d3c5b1a3ddf859b061d1dcc3",
            "4beca24200ec70322593893a4bc1a24270c1bb4a00ec703200c170320068703270ecbb4a0068703225c1893a7068bb4a7068bb4a25ec893a4beca24200687032",
        ),
        (
            0x06,
            "c0580db6fda08307f891a05009402cd5",
            "647765636ab6d00e6365477b6793953d62603e82679aa03462603e82657c6e5c6793953d62603e8262603e826477656368a5b226636c5372657c6e5c69aabb1e",
        ),
        (
            0x07,
            "80ffd8b21db4cfc0e41c1d3d4f0ba227",
            "583b506b89aa2cb09b3e8ba09b3e8ba0583b506b89aa2cb01838183818381838583b506b96df248e89aa2cb06d3c3cf7db41c3d396df248e89aa2cb096df248e",
        ),
        (
            0x08,
            "00f9d180c9b58c9489918bd831cf41f4",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
    ];

    const BC6H_SIGNED_VECTORS: [(u8, &str, &str); 36] = [
        (
            0x00,
            "24da9d683295ddd16ba47b4f9dc8c3ce",
            "18c93a4deb4a0dc8514f714b41c8e84e564be4c8a24d054bdfca064ba04ddcc8214be34c3aca0f4b634ddfca064ba04d2bccf54a1b4e85cbfd4add4d91c7334b694c85cbfd4add4da9c8174e224b75c87f4e3c4be4c8a24d054b41c8e84e564b",
        ),
        (
            0x01,
            "5938e0bb6894a2a399f9656574e69ef3",
            "8df5aef6dfc272e388db20b902f25ef1f7c08df5aef6dfc277ee0eec0fbf88ea28e6f0bc72e388db20b98df5aef6dfc277ee0eec0fbf72e388db20b9fde6d8e008bbe8df38d638b7a612561b78ccd68c368057d4524bec4c4dbed68c368057d4",
        ),
        (
            0x02,
            "4239d00e5899cbe2bf42c147249dcca5",
            "99c4afc9e800d3c3f7c9420144c32bca830169c4c0c9fe0039c4d2c91401d3c3f7c94201d3c3f7c942014cc460cadb0073c31aca6e019ec438cace009ec438cace006ac452cad70018c47acae40032c46ecadf004cc460cadb0084c445cad200",
        ),
        (
            0x06,
            "260c5f40a0be9ac7aa0d311c63515acc",
            "50f01117ef031cf08216e20350f01117ef03d4efbc15d00350f01117ef031cf08216e20308f04c16de03f7ef1c16d90350f01117ef03f7ef1c16d90308f04c16de03bff05d1724042df0b116e60308f04c16de03e1ef0317940438f026176804",
        ),
        (
            0x0a,
            "4ac3ad3cabea641bc50a6f3bd3b2d3d3",
            "a7ba702a70ca63bacf2af7ca91ba612a9bc968bae6299ccaa7ba702a70ca63bacf2af7ca8fba922aa0ca5bbac029efcabdba512a44ca63bacf2af7ca63bacf2af7ca9dba882a47c97abab02accca4ebaed2a23cb8fba922aa0ca63bacf2af7ca",
        ),
        (
            0x0e,
            "2e21fa8135dc72d7d9020c43d293d375",
            "a8f619881a60e2f70e863e5dfbf40d00085a12f20687066410f76a87265f10f76a87265f06f3b584c16076f53601665879f7bc86325e79f7bc86325e76f53601665807f443824d5d62f5378a1163cbf589891d62fbf40d00085a8cf2dd856362",
        ),
        (
            0x12,
            "32481a9156cd3f651bc3943ffe50dc58",
            "743c96329847743c96329847242aec30ec4f4445a439743f743c96329847232d31318f4e4445a439743f2f491e309240743fdc323c462c470235ff3f0c4c2c2964414445a439743f38465337b93f0c4c2c2964412f491e309240174b7c2b1e41",
        ),
        (
            0x16,
            "56a8215a730f33bde34fef7aaa3432e0",
            "2446334b57d38b3d043a4ac9cc33db451dc52b4a1a5211d5fc4da458b4d6bb39a63ea8c7b4358a43eec52b4a1a5211d54348d54e40d48b3d043a4ac9e4312c484cc45442a944b5d12446334b57d3e4312c484cc4e4312c484cc4fc4da458b4d6",
        ),
        (
            0x1a,
            "bab8f5f784f6f364a906a9e6f12992a5",
            "00be1995123400be19951234c8c486950ab5d2bbf694db5524c9cc959cf8d2bbf694db55f6c6a995d3d624c9cc959cf89ac26395419300be199512349ac26395419343b7078fcb969ac263954193c8c486950ab543b7078fcb9674be7e94e627",
        ),
        (
            0x1e,
            "9e70eed81ba334a8183c5f32cb1a3525",
            "25a6e412f39242cd88ad9d17bbba048f7303bbba048f7303fe24fff8d5af25a6e412f3921781ec4f46bb25a6e412f392fe24fff8d5af25a6e412f392bbba048f73039e9368311da71b0e01f35fb68d1900f61ab31781ec4f46bb1781ec4f46bb",
        ),
        (
            0x03,
            "e344575ee8d4cb89deb122062134845e",
            "47e50f9963251dda28d1f53ae3f04921f40eb0dd35bf0e34a8ee10164413a8ee1016441310e71590ef21adf2432a810be3f04921f40ea8ee1016441315eb1d042b1adeec160db81615eb1d042b1a7ee308a2d628e2d761dc453f4ce9dc849f1d",
        ),
        (
            0x07,
            "c74a4b189e3f42e4c083e6210352828f",
            "a5b3e5e9835ee6b441e81c59f6b379e9225d7bb4cde8e95a49b40fe9c25b1fb5f7e72858beb3c4e9175eddb39ae98f5df6b379e9225da5b3e5e9835eddb39ae98f5d29b438e9495cddb39ae98f5d7bb4cde8e95a38b5d6e7bb577bb4cde8e95a",
        ),
        (
            0x0b,
            "4b9246f6cd81869056935479cc8967ea",
            "910934096dcd000a99092dcd910934096dcdeb0a6f0aa5ccc90967094dcd000a99092dcdeb0a6f0aa5cc7d0a0b0ae5cc9f0b130b3dcc9f0b130b3dcceb0a6f0aa5ccb40a3d0ac5cc7d0a0b0ae5cc460ad80904cd300bae0a7dcc1b0c840bf5cb",
        ),
        (
            0x0f,
            "6fa8ecf0a36fedd64538b3c6c986359a",
            "8686696a085b8686696a075b8586676a065b8686696a075b8686696a075b8486666a065b8586686a075b8486666a065b8586676a065b8486666a065b8586686a075b8586676a065b8686686a075b8686696a075b8486676a065b8586676a065b",
        ),
        (
            0x13,
            "53384029d3c5b1a3ddf859b061d1dcc3",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x17,
            "77580db6fda08307f891a05009402cd5",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x1b,
            "bbffd8b21db4cfc0e41c1d3d4f0ba227",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x1f,
            "fff9d180c9b58c9489918bd831cf41f4",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x00,
            "d49e1f306161cc56265e8774526f6451",
            "1b3c7b0f60258d38810b6b25db38cf0b2d25843c950fd1259b3e1b101528cf39c30c7024cf39c30c7024843c950fd1259b3e1b1015281e3a120d3324db38cf0b2d25843c950fd125323e0010a32729391d0cf024cf39c30c7024843c950fd125",
        ),
        (
            0x01,
            "2d176371dae386d619bb6af53a9beaf6",
            "ae6cf4af1d6314677656d54dae6cf4af1d637168c4350253085c58d26831ae6cf4af1d63b8652877a848ce6912152f5820d6d4500d47d29b6d1bf73fae6cf4af1d637168c4350253e03ea4b7f234b921f19c7d38b921f19c7d38b8652877a848",
        ),
        (
            0x02,
            "6239eb9f9c5562f1486f846eb0db77c1",
            "b2c41c85a9477ac42585a0479cc5f884cd474cc4c5856c4824c50b85ba477ac42585a0479ec4aa855f489ec4aa855f489cc5f884cd479cc5f884cd47b8c4a1855a4884c4b285634824c50b85ba4718c4d6857548fec3df8579484cc4c5856c48",
        ),
        (
            0x06,
            "26cc68b8ccfe3d89ca02c81ced3b0c3c",
            "8db23de2dab2cdb2b3e1c7b2b5b112e16fb2b5b1e7e16fb250b2c0e2ebb2ecb272e1beb2b5b1a1e16fb2b5b1e7e16fb2ecb272e1beb2abb2fbe1d1b2b5b1efe06fb2b5b158e16fb250b2c0e2ebb2cdb2b3e1c7b2b5b1e7e16fb2b5b1efe06fb2",
        ),
        (
            0x0a,
            "aa2724aa4fad204dbb09d56fa167f1ec",
            "5426dd08c076d62536095476992562092076172609098c76172609098c765426dd08c076f52521096e76b8254d093a76172609098c76b8254d093a763526f308a67681265d099175992562092076f52521096e769b2654096e7563266709b775",
        ),
        (
            0x0e,
            "2eb806b452ecb771444c107720394aaf",
            "c29e8a06a6d0789e7209eccef3a1720987cd45a17209cdcdb69c550609d0ca9d720932cf96a0720913ce96a0720913cef59b4206cecfd59f720960ce96a0720913ce269f7209a6ce659d67063dd0a2a2720942cd45a17209cdcd269f7209a6ce",
        ),
        (
            0x12,
            "b2cf8e50d4eec1a0b687c7b1be714e34",
            "1b5a9f1e5e27cb87fa24cb272b1bb522a427f4ebeb23041c43a70527ee2739ef3124be1bdcf054249c1b39ef3124be1b3ce55c23941c39ef3124be1bdee67e23711c34e61c2b3428f4ebeb23041c9479941c3c2743a70527ee271b5a9f1e5e27",
        ),
        (
            0x16,
            "b6fbe6c1c0bc01ad23459936d3494f1a",
            "92a459aed95b7ba31eb0aa5cf6a7d6a84e59f6a7d6a84e597ba31eb0aa5ca9a593ac085b92a459aed95bb498e4b1745edfa69caa1f5aeba2b5b2d15c1b9c29b2e85db4a602b3365c1caa48b3ab5b1caa48b3ab5bb4a602b3365cecb0d4b3945a",
        ),
        (
            0x1a,
            "3a5bc2f6f7e186bab86a9801a44a0af8",
            "cfa60ab5538889a6d3d6d38615a74193d28924aa9cf8fc8f44a69cf8548562a749127d8b0fae5d0e39920cacf2b61391a8a71234fc8c62a749127d8b0fae5d0e39920cacf2b6139144a69cf8548524aa9cf8fc8fecb0dc70dc9300ad1d969e91",
        ),
        (
            0x1e,
            "3e9abba9cb22fe4e2aa74ceed6fcb7cd",
            "e4509fae265ebc5541b29963a143b39c99a7de472da5479ad06210bc5072003c718d93bfaf4bceac4a8ede472da5479a745ecbb8686d3038d08590cb3038d08590cbd13f129596b3d13f129596b3d13f129596b37f4f6fb44d82de472da5479a",
        ),
        (
            0x03,
            "8387707bdf6ce0effac31fae23f5c164",
            "8b2aedc21f1ba96365bd2174eb1ff4c38f0a645211bf3859a96365bd2174f7131dc51188585ee8bdd96bc44718c0a848eb1ff4c38f0a9b1a78c448028b2aedc21f1ba96365bd2174f7131dc51188645211bf38593b2571c3d7122f3148c27825",
        ),
        (
            0x07,
            "c7033c7b42f8051a6f302b5f71b36e74",
            "3292424fb8d2d49fe74e1dd36df8974cacd520ccbf4d65d4bb27c5500cd1c1d9644dc9d4a961485260cfddb0764e9bd3cceaf24c47d53292424fb8d220ccbf4d65d4bb27c5500cd10854ed51c5cfd49fe74e1dd37ebe1b4e00d43292424fb8d2",
        ),
        (
            0x0b,
            "ab23fa2e82fa97990c102b15dd97170f",
            "ceaab41ce1e9c6ac4d1e23ebc6ac4d1e23eb78ac0e1ef1ea37a9691bdee817acc01db3ea2fab031d1fea78ac0e1ef1ea9ca8eb1a7ce89ca8eb1a7ce881aa751cb0e9e6a9f81b4de981aa751cb0e978ac0e1ef1eaeea75e1a0ce8c6ac4d1e23eb",
        ),
        (
            0x0f,
            "8f4751d071dcb7124bc9020051f04ece",
            "491d24a6c242491d24a6c142491d24a6c342481d25a6c4424a1d23a6c1424a1d23a6c0424a1d23a6c0424a1d23a6c0424a1d23a6c042491d24a6c2424a1d23a6c042481d25a6c542481d25a6c542491d24a6c142481d25a6c542481d25a6c442",
        ),
        (
            0x13,
            "133716dd846ad11ba07796795d0da7bc",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x17,
            "374df00d064862e25ad4bea83f59ccc5",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x1b,
            "7b78c65c36c408ba85b7ad4de500709c",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x1f,
            "5f717eec2a4a005fffae164d235d258a",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
    ];

    const BC6H_UNSIGNED_VECTORS: [(u8, &str, &str); 36] = [
        (
            0x00,
            "24da9d683295ddd16ba47b4f9dc8c3ce",
            "92579d2675251858a827b825fe577427ab25ac57d1268225af568325d026b0579025712601578725b126af568325d02609567a250d275c567e25ee265658992534265c567e25ee26ca570b279125e4573f279e25ac57d1268225fe577427ab25",
        ),
        (
            0x01,
            "5938e0bb6894a2a399f9656574e69ef3",
            "31423541885b3e4b224f6760f643ef437c5c31423541885bbc45a846705db347af497f5e3e4b224f676031423541885bbc45a846705d3e4b224f67607949694c735f044ddc515c610b3e6342bb56d4412448cc523b370938d15dd4412448cc52",
        ),
        (
            0x02,
            "4239d00e5899cbe2bf42c147249dcca5",
            "c25937577400255a1357a1006d5af956c100da592f577f00f25926578a00255a1357a100255a1357a100e959df566d00555a0257b700c059f3566700c059f3566700da59e6566b00035ad2567200f659d8566f00e959df566d00cd59ec566900",
        ),
        (
            0x06,
            "260c5f40a0be9ac7aa0d311c63515acc",
            "e743880bf7010144410bf101e743880bf7012544de0ae801e743880bf7010144410bf1010b44260bef0113440e0bec01e743880bf70113440e0bec010b44260bef01af43ae0b1202f843580bf3010b44260bef011e44810b4a02f343930b3402",
        ),
        (
            0x0a,
            "4ac3ad3cabea641bc50a6f3bd3b2d3d3",
            "bb5e3815d756dd5e67159356c65e30154157db5ef314c156bb5e3815d756dd5e67159356c75e4915bf56e15ee0149756b05e2815ed56dd5e67159356dd5e67159356c05e44156b57d25e5815a956e85e76157d56c75e4915bf56dd5e67159356",
        ),
        (
            0x0e,
            "2e21fa8135dc72d7d9020c43d293d375",
            "e94031780d304d4037799f2ec0417f11042d3543bb780332b5408878932fb5408878932fba42f256603083419b00332c8140df78192f8140df78192f83419b00332c3a424833a62e8c4122778831584179770e31c0417f11042df742d6673131",
        ),
        (
            0x12,
            "32481a9156cd3f651bc3943ffe50dc58",
            "3a1e4b19cc233a1e4b19cc2312157618f627a222d21cba1f3a1e4b19cc23911698184727a222d21cba1f97240f184920ba1f6e191e239623811aff1f06269614b220a222d21cba1f1c23a91bdc1f06269614b22097240f1849208b25be158f20",
        ),
        (
            0x16,
            "56a8215a730f33bde34fef7aaa3432e0",
            "12239925d052c51e021dd657e619ed22ed5915250d29f351fe26522c2251dd1c531fa758da1ac521845915250d29f35121246a275b52c51e021dd657f2181624565a2a215422a15312239925d052f2181624565af2181624565afe26522c2251",
        ),
        (
            0x1a,
            "bab8f5f784f6f364a906a9e6f12992a5",
            "7c5def710b3d7c5def710b3d185ab871f43e935e00726e3cea5796712e40935e00726e3c0159a771913fea5796712e402f5bca71573e7c5def710b3d2f5bca71573eda60f874913c2f5bca71573e185ab871f43eda60f874913c415d3c72f636",
        ),
        (
            0x1e,
            "9e70eed81ba334a8183c5f32cb1a3525",
            "0e22933e553fe333c0433a2f712b4c41db36712b4c41db363524444205660e22933e553f2a11ab39974e0e22933e553f3524444205660e22933e553f712b4c41db369c191f3cf6462f3cfe44c0623230a14363642a11ab39974e2a11ab39974e",
        ),
        (
            0x03,
            "e344575ee8d4cb89deb122062134845e",
            "7b49a72db112104f16427a1dad4366187a07464d8c3b071aca447c1ca209ca447c1ca2099648622af710c8422115c005ad4366187a07ca447c1ca20994460623150daf45c11f5c0b94460623150d5f4aec306b142d502c46a21f78474b26cf0e",
        ),
        (
            0x07,
            "c74a4b189e3f42e4c083e6210352828f",
            "3c621c47412f9c61ee478e2c14625247912ed161a847742dea618747e12d7f611348142c30622d470b2f20624247c72e14625247912e3c621c47412f20624247c72efa617347242e20624247c72ed161a847742d73612448dd2bd161a847742d",
        ),
        (
            0x0b,
            "4b9246f6cd81869056935479cc8967ea",
            "c8049a0450550005cc047055c8049a04505575053705b555e404b30460550005cc04705575053705b5553e0505059555cf058905e955cf058905e95575053705b5555a051e05a5553e05050595552305ec04855598055705c9550d06c2050c56",
        ),
        (
            0x0f,
            "6fa8ecf0a36fedd64538b3c6c986359a",
            "bc783435842dbc783435832dbd783335832dbc783435832dbc783435832dbd783335832dbd783435832dbd783335832dbd783335832dbd783335832dbd783435832dbd783335832dbc783435832dbc783435832dbd783335832dbd783335832d",
        ),
        (
            0x13,
            "53384029d3c5b1a3ddf859b061d1dcc3",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x17,
            "77580db6fda08307f891a05009402cd5",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x1b,
            "bbffd8b21db4cfc0e41c1d3d4f0ba227",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x1f,
            "fff9d180c9b58c9489918bd831cf41f4",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x00,
            "d49e1f306161cc56265e8774526f6451",
            "0d1ebd07b012461cc005b5126d1ce7059612421eca07e8124d1f0d080a14e71c61063812e71c61063812421eca07e8124d1f0d080a140f1d890619126d1ce7059612421eca07e812191f0008d113941c0e067812e71c61063812421eca07e812",
        ),
        (
            0x01,
            "2d176371dae386d619bb6af53a9beaf6",
            "5736d8418e318a33cd3cea265736d8418e313834073e8129042ecc53b4185736d8418e31dc32943b5424e734413f172c5440fd398623563a6f42fb1f5736d8418e313834073e81290331924f791a0234594b3e1c0234594b3e1cdc32943b5424",
        ),
        (
            0x02,
            "6239eb9f9c5562f1486f846eb0db77c1",
            "b6598179d423d2597c79d02341599379e623e9592c7936247d598979dd23d2597c79d023c0593a792f24c0593a792f2441599379e62341599379e623b3593e792d24cd59367931247d598979dd23035a24793a24105a1f793c24e9592c793624",
        ),
        (
            0x06,
            "26cc68b8ccfe3d89ca02c81ced3b0c3c",
            "c862f04aa262a862354bab623463864bd76234631b4bd762e762af4a99629962564bb06234633e4bd76234631b4bd7629962564bb062b962114ba6623463974bd7623463634bd762e762af4a9962a862354bab6234631b4bd7623463974bd762",
        ),
        (
            0x0a,
            "aa2724aa4fad204dbb09d56fa167f1ec",
            "2a136e04603beb129b042a3bcc12b104103b0b138404463b0b138404463b2a136e04603bfa129004373bdc12a6041d3b0b138404463bdc12a6041d3b1a137904533b4013ae04c83acc12b104103bfa129004373b4d13aa04b73a3113b304db3a",
        ),
        (
            0x0e,
            "2eb806b452ecb771444c107720394aaf",
            "dd6c4503eb53016db904c754446bb9047a559b6bb9045755e26d2a033954596db904a554f26bb9043455f26bb9043455436e21035654536cb9040d55f26bb9043455aa6cb904ea548b6d33031f54ed6ab9049d559b6bb9045755aa6cb904ea54",
        ),
        (
            0x12,
            "b2cf8e50d4eec1a0b687c7b1be714e34",
            "8f3e4f0faf1311447d12e5131a425a11d2138146f511020ed7458213f713df441812df0d0e442a12ce0ddf441812df0dde49ae114a0edf441812df0d0c49bf11380e62498e151a148146f511020eca3c4a0e9e13d7458213f7138f3e4f0faf13",
        ),
        (
            0x16,
            "b6fbe6c1c0bc01ad23459936d3494f1a",
            "336a4f65ec2dbe6a6c64552e81681068a72c81681068a72cbe6a6c64552ea7693266842d336a4f65ec2d22708a633a2f0c692d670f2d066b2163682e6e6e6763f42e2169fa621b2e6d67d762d52d6d67d762d52d2169fa621b2e066492624a2d",
        ),
        (
            0x1a,
            "3a5bc2f6f7e186bab86a9801a44a0af8",
            "1469f43e52783769913f1279f168573e92776a672e407e745a692e40d279ca68a83dbd767465b33b5f737566003ef273a7680b3dfd75ca68a83dbd767465b33b5f737566003ef2735a692e40d2796a672e407e7406646e388e72fb65e93cac73",
        ),
        (
            0x1e,
            "3e9abba9cb22fe4e2aa74ceed6fcb7cd",
            "7228a066132fde2acf64cc31d02125700235ef23c26bfd276831e85f2839001e0c78704cd725ce67461cef23c26bfd273a2f8a61b436181cff7b2858181cff7b2858e81f1874b940e81f1874b940e81f1874b940bf27db638f10ef23c26bfd27",
        ),
        (
            0x03,
            "8387707bdf6ce0effac31fae23f5c164",
            "4515a85af460d4316c5d103af50f245a30683229965cd245d4316c5d103afb09905954702c2f2a5dae3de223125c0e4df50f245a30684d0de259ce6b4515a85af460d4316c5d103afb09905954703229965cd2459d12665a92649718fa5a6e5c",
        ),
        (
            0x07,
            "c7033c7b42f8051a6f302b5f71b36e74",
            "ce38a127b352bf3973278052d83f4b263951cb3cdf26dc51d13462288953bc3db226aa51d43024295f54eb3a3b274152e83e79266b51ce38a127b352cb3cdf26dc51d13462288953c531f6282c54bf3973278052db3b0d270f52ce38a127b352",
        ),
        (
            0x0b,
            "ab23fa2e82fa97990c102b15dd97170f",
            "a0665a0e1647a465260f7646a465260f7646cb65070f8e466b67b40d9847fb65e00ead467066810ef746cb65070f8e46b967750dc947b967750dc947c7663a0e2f471467fc0d6147c7663a0e2f47cb65070f8e4610682f0d0148a465260f7646",
        ),
        (
            0x0f,
            "8f4751d071dcb7124bc9020051f04ece",
            "a40eed686121a40eed686021a40eed686121a40eed686221a50eee686021a50eee686021a50eee686021a50eee686021a50eee686021a40eed686121a50eee686021a40eed686221a40eed686221a40eed686021a40eed686221a40eed686221",
        ),
        (
            0x13,
            "133716dd846ad11ba07796795d0da7bc",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x17,
            "374df00d064862e25ad4bea83f59ccc5",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x1b,
            "7b78c65c36c408ba85b7ad4de500709c",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            0x1f,
            "5f717eec2a4a005fffae164d235d258a",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
    ];
}
