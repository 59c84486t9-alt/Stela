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
}
