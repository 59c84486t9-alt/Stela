//! AdvSIMD packed-index lookup. Encoding facts: pinned Arm A64 2026-06
//! luti2_advsimd.xml and luti4_advsimd.xml. Requires enabled AdvSIMD and FEAT_LUT.
//! All operands, including the wrapping second table, are read before Vd changes.

const REGISTER_MASK: u32 = 31;
const TABLE_SHIFT: u32 = 5;
const INDEX_SHIFT: u32 = 16;
const SEGMENT_SHIFT: u32 = 13;
const HALFWORD_SEGMENT_SHIFT: u32 = 12;
const TWO_BIT_HALFWORD_SEGMENTS: u32 = 7;
const SEGMENT_MASK: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub canonical_id: &'static str,
    pub destination: u8,
    pub table: u8,
    pub indices: u8,
    pub index_bits: u8,
    pub element_bytes: u8,
    pub segment: u8,
}

impl Operand {
    pub const fn table_registers(self) -> u8 {
        if self.index_bits == 4 && self.element_bytes == 2 {
            2
        } else {
            1
        }
    }

    pub const fn index_byte_offset(self) -> usize {
        // A segment supplies exactly one 128-bit result.
        self.segment as usize * (16 / self.element_bytes as usize) * self.index_bits as usize / 8
    }
}

#[derive(Clone, Copy)]
struct Encoding {
    canonical_id: &'static str,
    mask: u32,
    value: u32,
    index_bits: u8,
    element_bytes: u8,
}

const ENCODINGS: [Encoding; 4] = [
    Encoding {
        canonical_id: "LUTI2_asimdtbl_L5",
        mask: 0xffe0_9c00,
        value: 0x4e80_1000,
        index_bits: 2,
        element_bytes: 1,
    },
    Encoding {
        canonical_id: "LUTI2_asimdtbl_L6",
        mask: 0xffe0_8c00,
        value: 0x4ec0_0000,
        index_bits: 2,
        element_bytes: 2,
    },
    Encoding {
        canonical_id: "LUTI4_asimdtbl_L5",
        mask: 0xffe0_bc00,
        value: 0x4e40_2000,
        index_bits: 4,
        element_bytes: 1,
    },
    Encoding {
        canonical_id: "LUTI4_asimdtbl_L7",
        mask: 0xffe0_9c00,
        value: 0x4e40_1000,
        index_bits: 4,
        element_bytes: 2,
    },
];

pub fn decode(word: u32) -> Option<Operand> {
    let encoding = ENCODINGS
        .iter()
        .find(|encoding| word & encoding.mask == encoding.value)?;
    let segment = match (encoding.index_bits, encoding.element_bytes) {
        (2, 2) => (word >> HALFWORD_SEGMENT_SHIFT) & TWO_BIT_HALFWORD_SEGMENTS,
        (4, 1) => (word >> (SEGMENT_SHIFT + 1)) & 1,
        _ => (word >> SEGMENT_SHIFT) & SEGMENT_MASK,
    };
    Some(Operand {
        canonical_id: encoding.canonical_id,
        destination: (word & REGISTER_MASK) as u8,
        table: ((word >> TABLE_SHIFT) & REGISTER_MASK) as u8,
        indices: ((word >> INDEX_SHIFT) & REGISTER_MASK) as u8,
        index_bits: encoding.index_bits,
        element_bytes: encoding.element_bytes,
        segment: segment as u8,
    })
}

#[cfg(test)]
mod tests;
