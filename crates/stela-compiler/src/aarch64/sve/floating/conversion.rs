//! Predicated SVE Single-to-Double conversions; Arm A64 2026-06.

use crate::aarch64::floating::{Format, precision::PrecisionRounding};

const CONVERSION_MASK: u32 = 0xffff_e000;
const REGISTER_MASK: u32 = 31;
const GOVERNING_MASK: u32 = 7;
const SOURCE_SHIFT: u32 = 5;
const GOVERNING_SHIFT: u32 = 10;
const BITS_PER_BYTE: u32 = 8;
const FCVT_Z_P_Z_S2D: u32 = 0x65cb_a000;
const FCVTLT_Z_P_Z_S2D: u32 = 0x64cb_a000;

/// The source or destination half within a max-width predicate slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    Low,
    UpperSource,
    UpperDestination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Precision {
        source: Format,
        destination: Format,
        rounding: PrecisionRounding,
        placement: Placement,
    },
}

impl Kind {
    pub const fn source_bits(self) -> u32 {
        let Self::Precision { source, .. } = self;
        source.bits()
    }

    pub const fn destination_bits(self) -> u32 {
        let Self::Precision { destination, .. } = self;
        destination.bits()
    }

    /// Predicate slots follow the wider format, including FCVTLT's source half.
    pub const fn slot_bytes(self) -> u8 {
        let source = self.source_bits();
        let destination = self.destination_bits();
        (if source > destination {
            source
        } else {
            destination
        } / BITS_PER_BYTE) as u8
    }

    pub const fn source_offset(self) -> u8 {
        match self {
            Self::Precision {
                source,
                placement: Placement::UpperSource,
                ..
            } => (source.bits() / BITS_PER_BYTE) as u8,
            _ => 0,
        }
    }

    pub const fn destination_offset(self) -> u8 {
        match self {
            Self::Precision {
                destination,
                placement: Placement::UpperDestination,
                ..
            } => (destination.bits() / BITS_PER_BYTE) as u8,
            _ => 0,
        }
    }

    pub const fn written_bytes(self) -> u8 {
        if self.destination_offset() == 0 {
            self.slot_bytes()
        } else {
            (self.destination_bits() / BITS_PER_BYTE) as u8
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub governing: u8,
    pub source: u8,
}

/// Only the two reviewed Single-to-Double forms are recognized. Numerical
/// evaluation belongs to the shared precision core at the completion boundary.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let placement = match word & CONVERSION_MASK {
        FCVT_Z_P_Z_S2D => Placement::Low,
        FCVTLT_Z_P_Z_S2D => Placement::UpperSource,
        _ => return None,
    };
    Some(Ok(Operand {
        kind: Kind::Precision {
            source: Format::Single,
            destination: Format::Double,
            rounding: PrecisionRounding::Fpcr,
            placement,
        },
        destination: (word & REGISTER_MASK) as u8,
        governing: ((word >> GOVERNING_SHIFT) & GOVERNING_MASK) as u8,
        source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widening_selects_one_single_per_double_slot() {
        for (opcode, source_offset) in [(FCVT_Z_P_Z_S2D, 0), (FCVTLT_Z_P_Z_S2D, 4)] {
            let operand = decode(opcode | (7 << GOVERNING_SHIFT) | (31 << SOURCE_SHIFT) | 31)
                .unwrap()
                .unwrap();
            assert_eq!(
                (operand.destination, operand.governing, operand.source),
                (31, 7, 31)
            );
            assert_eq!(operand.kind.source_bits(), 32);
            assert_eq!(operand.kind.destination_bits(), 64);
            assert_eq!(operand.kind.slot_bytes(), 8);
            assert_eq!(operand.kind.source_offset(), source_offset);
            assert_eq!(operand.kind.destination_offset(), 0);
            assert_eq!(operand.kind.written_bytes(), 8);
        }
    }

    #[test]
    fn other_conversion_families_remain_unrecognized() {
        const FCVT_DOUBLE_TO_SINGLE: u32 = 0x65ca_a000;
        const FCVT_TOP_DOUBLE_TO_SINGLE: u32 = 0x64ca_a000;
        const FCVT_TO_ODD_DOUBLE_TO_SINGLE: u32 = 0x650a_a000;
        const FCVT_SINGLE_TO_SIGNED_WORD: u32 = 0x659c_a000;
        const SCVTF_SIGNED_WORD_TO_SINGLE: u32 = 0x6594_a000;
        const BFCVT_SINGLE_TO_BFLOAT: u32 = 0x658a_a000;
        for opcode in [
            FCVT_DOUBLE_TO_SINGLE,
            FCVT_TOP_DOUBLE_TO_SINGLE,
            FCVT_TO_ODD_DOUBLE_TO_SINGLE,
            FCVT_SINGLE_TO_SIGNED_WORD,
            SCVTF_SIGNED_WORD_TO_SINGLE,
            BFCVT_SINGLE_TO_BFLOAT,
        ] {
            assert!(decode(opcode).is_none());
        }
    }
}
