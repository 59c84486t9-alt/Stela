//! LUT-extension register tables. The shared boundary owns feature/mode admission.
//! Halfword LUTI4 uses either 256 bits of one table or 128 bits of two tables.
use crate::aarch64::scalable::ElementSize;

const REGISTER_MASK: u32 = 31;
const TABLE_SHIFT: u32 = 5;
const INDEX_SHIFT: u32 = 16;
const PART_SHIFT: u32 = 22;
const PART_LOW_SHIFT: u32 = 12;
const LUTI2_BYTE_MASK: u32 = 0xff20_fc00;
const LUTI2_BYTE: u32 = 0x4520_b000;
const LUTI2_HALF_MASK: u32 = 0xff20_ec00;
const LUTI2_HALF: u32 = 0x4520_a800;
const LUTI4_BYTE_MASK: u32 = 0xff60_fc00;
const LUTI4_BYTE: u32 = 0x4560_a400;
const LUTI4_HALF_MASK: u32 = 0xff20_fc00;
const LUTI4_HALF_PAIR: u32 = 0x4520_b400;
const LUTI4_HALF_SINGLE: u32 = 0x4520_bc00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: u8,
    pub table: u8,
    pub indexes: u8,
    pub element: ElementSize,
    pub index_bits: u8,
    pub part: u8,
    pub table_registers: u8,
}

impl Operand {
    pub const fn minimum_vl_bits(self) -> usize {
        if self.index_bits == 4
            && matches!(self.element, ElementSize::Halfword)
            && self.table_registers == 1
        {
            256
        } else {
            128
        }
    }
    pub const fn canonical_id(self) -> &'static str {
        match (self.index_bits, self.element, self.table_registers) {
            (2, ElementSize::Byte, _) => "luti2_z_zz_8",
            (2, ElementSize::Halfword, _) => "luti2_z_zz_16",
            (4, ElementSize::Byte, _) => "luti4_z_zz_8",
            (4, ElementSize::Halfword, 1) => "luti4_z_zz_1x16",
            (4, ElementSize::Halfword, 2) => "luti4_z_zz_2x16",
            _ => unreachable!(),
        }
    }
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let high_part = ((word >> PART_SHIFT) & 3) as u8;
    let (element, index_bits, part, table_registers) = if word & LUTI2_BYTE_MASK == LUTI2_BYTE {
        (ElementSize::Byte, 2, high_part, 1)
    } else if word & LUTI2_HALF_MASK == LUTI2_HALF {
        (
            ElementSize::Halfword,
            2,
            (high_part << 1) | ((word >> PART_LOW_SHIFT) & 1) as u8,
            1,
        )
    } else if word & LUTI4_BYTE_MASK == LUTI4_BYTE {
        (ElementSize::Byte, 4, high_part >> 1, 1)
    } else if word & LUTI4_HALF_MASK == LUTI4_HALF_PAIR {
        (ElementSize::Halfword, 4, high_part, 2)
    } else if word & LUTI4_HALF_MASK == LUTI4_HALF_SINGLE {
        (ElementSize::Halfword, 4, high_part, 1)
    } else {
        return None;
    };
    Some(Ok(Operand {
        destination: (word & REGISTER_MASK) as u8,
        table: ((word >> TABLE_SHIFT) & REGISTER_MASK) as u8,
        indexes: ((word >> INDEX_SHIFT) & REGISTER_MASK) as u8,
        element,
        index_bits,
        part,
        table_registers,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_forms_and_parts() {
        for (base, count, id) in [
            (LUTI2_BYTE, 4, "luti2_z_zz_8"),
            (LUTI2_HALF, 8, "luti2_z_zz_16"),
            (LUTI4_BYTE, 2, "luti4_z_zz_8"),
            (LUTI4_HALF_PAIR, 4, "luti4_z_zz_2x16"),
            (LUTI4_HALF_SINGLE, 4, "luti4_z_zz_1x16"),
        ] {
            for part in 0..count {
                let encoded = if base == LUTI2_HALF {
                    ((part >> 1) << PART_SHIFT) | ((part & 1) << PART_LOW_SHIFT)
                } else if base == LUTI4_BYTE {
                    part << 23
                } else {
                    part << PART_SHIFT
                };
                let op = decode(base | encoded | 31 | (31 << TABLE_SHIFT) | (31 << INDEX_SHIFT))
                    .unwrap()
                    .unwrap();
                assert_eq!(op.part, part as u8);
                assert_eq!(op.canonical_id(), id);
                assert_eq!(op.table, 31);
            }
        }
        assert!(decode(0).is_none());
    }
}
