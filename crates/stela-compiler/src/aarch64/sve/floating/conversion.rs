//! SVE predicated conversions (FCVT, FCVTZS/U, SCVTF/UCVTF, ...).

use crate::aarch64::floating::{
    Format,
    integer::{IntegerFormat, IntegerWidth},
    precision::PrecisionRounding,
};

const CONVERSION_MASK: u32 = 0xffff_e000;
const REGISTER_MASK: u32 = 31;
const GOVERNING_MASK: u32 = 7;
const SOURCE_SHIFT: u32 = 5;
const GOVERNING_SHIFT: u32 = 10;
const BITS_PER_BYTE: u32 = 8;
const FCVT_Z_P_Z_S2D: u32 = 0x65cb_a000;
const FCVTLT_Z_P_Z_S2D: u32 = 0x64cb_a000;
const FCVTZS_Z_P_Z_D2W: u32 = 0x65d8_a000;
const FCVTZS_Z_P_Z_D2X: u32 = 0x65de_a000;
const FCVTZS_Z_P_Z_S2W: u32 = 0x659c_a000;
const FCVTZS_Z_P_Z_S2X: u32 = 0x65dc_a000;
const FCVTZU_Z_P_Z_D2W: u32 = 0x65d9_a000;
const FCVTZU_Z_P_Z_S2W: u32 = 0x659d_a000;
const SCVTF_Z_P_Z_W2D: u32 = 0x65d0_a000;
const SCVTF_Z_P_Z_W2S: u32 = 0x6594_a000;
const SCVTF_Z_P_Z_X2D: u32 = 0x65d6_a000;
const SCVTF_Z_P_Z_X2S: u32 = 0x65d4_a000;
const UCVTF_Z_P_Z_W2D: u32 = 0x65d1_a000;
const UCVTF_Z_P_Z_W2S: u32 = 0x6595_a000;

const FCVTZS_Z_P_Z_FP162H: u32 = 0x655a_a000;
const FCVTZS_Z_P_Z_FP162W: u32 = 0x655c_a000;
const FCVTZS_Z_P_Z_FP162X: u32 = 0x655e_a000;
const FCVTZU_Z_P_Z_D2X: u32 = 0x65df_a000;
const FCVTZU_Z_P_Z_FP162H: u32 = 0x655b_a000;
const FCVTZU_Z_P_Z_FP162W: u32 = 0x655d_a000;
const FCVTZU_Z_P_Z_FP162X: u32 = 0x655f_a000;
const FCVTZU_Z_P_Z_S2X: u32 = 0x65dd_a000;
const SCVTF_Z_P_Z_H2FP16: u32 = 0x6552_a000;
const SCVTF_Z_P_Z_W2FP16: u32 = 0x6554_a000;
const SCVTF_Z_P_Z_X2FP16: u32 = 0x6556_a000;
const UCVTF_Z_P_Z_H2FP16: u32 = 0x6553_a000;
const UCVTF_Z_P_Z_W2FP16: u32 = 0x6555_a000;
const UCVTF_Z_P_Z_X2D: u32 = 0x65d7_a000;
const UCVTF_Z_P_Z_X2FP16: u32 = 0x6557_a000;
const UCVTF_Z_P_Z_X2S: u32 = 0x65d5_a000;

const BFCVT_Z_P_Z_S2BF: u32 = 0x658a_a000;
const BFCVTNT_Z_P_Z_S2BF: u32 = 0x648a_a000;
const FCVT_Z_P_Z_D2H: u32 = 0x65c8_a000;
const FCVT_Z_P_Z_D2S: u32 = 0x65ca_a000;
const FCVT_Z_P_Z_H2D: u32 = 0x65c9_a000;
const FCVT_Z_P_Z_H2S: u32 = 0x6589_a000;
const FCVT_Z_P_Z_S2H: u32 = 0x6588_a000;
const FCVTLT_Z_P_Z_H2S: u32 = 0x6489_a000;
const FCVTNT_Z_P_Z_D2S: u32 = 0x64ca_a000;
const FCVTNT_Z_P_Z_S2H: u32 = 0x6488_a000;
const FCVTX_Z_P_Z_D2S: u32 = 0x650a_a000;
const FCVTXNT_Z_P_Z_D2S: u32 = 0x640a_a000;

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
    ToInteger {
        source: Format,
        destination: IntegerFormat,
    },
    FromInteger {
        source: IntegerFormat,
        destination: Format,
    },
    Bfloat16 {
        upper: bool,
    },
}

impl Kind {
    pub const fn source_bits(self) -> u32 {
        match self {
            Self::Precision { source, .. } | Self::ToInteger { source, .. } => source.bits(),
            Self::FromInteger { source, .. } => source.width.bits(),
            Self::Bfloat16 { .. } => u32::BITS,
        }
    }

    pub const fn destination_bits(self) -> u32 {
        match self {
            Self::Precision { destination, .. } | Self::FromInteger { destination, .. } => {
                destination.bits()
            }
            Self::ToInteger { destination, .. } => destination.width.bits(),
            Self::Bfloat16 { .. } => u16::BITS,
        }
    }

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
            Self::Bfloat16 { upper: true } => (u16::BITS / BITS_PER_BYTE) as u8,
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

/// Decodes exactly 28 integer, 12 precision and 2 BF16 forms.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let kind = match word & CONVERSION_MASK {
        BFCVT_Z_P_Z_S2BF => Kind::Bfloat16 { upper: false },
        BFCVTNT_Z_P_Z_S2BF => Kind::Bfloat16 { upper: true },
        FCVT_Z_P_Z_D2H => Kind::Precision {
            source: Format::Double,
            destination: Format::Half,
            rounding: PrecisionRounding::Fpcr,
            placement: Placement::Low,
        },
        FCVT_Z_P_Z_D2S => Kind::Precision {
            source: Format::Double,
            destination: Format::Single,
            rounding: PrecisionRounding::Fpcr,
            placement: Placement::Low,
        },
        FCVT_Z_P_Z_H2D => Kind::Precision {
            source: Format::Half,
            destination: Format::Double,
            rounding: PrecisionRounding::Fpcr,
            placement: Placement::Low,
        },
        FCVT_Z_P_Z_H2S => Kind::Precision {
            source: Format::Half,
            destination: Format::Single,
            rounding: PrecisionRounding::Fpcr,
            placement: Placement::Low,
        },
        FCVT_Z_P_Z_S2H => Kind::Precision {
            source: Format::Single,
            destination: Format::Half,
            rounding: PrecisionRounding::Fpcr,
            placement: Placement::Low,
        },
        FCVTLT_Z_P_Z_H2S => Kind::Precision {
            source: Format::Half,
            destination: Format::Single,
            rounding: PrecisionRounding::Fpcr,
            placement: Placement::UpperSource,
        },
        FCVTNT_Z_P_Z_D2S => Kind::Precision {
            source: Format::Double,
            destination: Format::Single,
            rounding: PrecisionRounding::Fpcr,
            placement: Placement::UpperDestination,
        },
        FCVTNT_Z_P_Z_S2H => Kind::Precision {
            source: Format::Single,
            destination: Format::Half,
            rounding: PrecisionRounding::Fpcr,
            placement: Placement::UpperDestination,
        },
        FCVTX_Z_P_Z_D2S => Kind::Precision {
            source: Format::Double,
            destination: Format::Single,
            rounding: PrecisionRounding::ToOdd,
            placement: Placement::Low,
        },
        FCVTXNT_Z_P_Z_D2S => Kind::Precision {
            source: Format::Double,
            destination: Format::Single,
            rounding: PrecisionRounding::ToOdd,
            placement: Placement::UpperDestination,
        },
        FCVT_Z_P_Z_S2D | FCVTLT_Z_P_Z_S2D => Kind::Precision {
            source: Format::Single,
            destination: Format::Double,
            rounding: PrecisionRounding::Fpcr,
            placement: if word & CONVERSION_MASK == FCVT_Z_P_Z_S2D {
                Placement::Low
            } else {
                Placement::UpperSource
            },
        },
        FCVTZS_Z_P_Z_D2W => Kind::ToInteger {
            source: Format::Double,
            destination: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: true,
            },
        },
        FCVTZS_Z_P_Z_D2X => Kind::ToInteger {
            source: Format::Double,
            destination: IntegerFormat {
                width: IntegerWidth::Bits64,
                signed: true,
            },
        },
        FCVTZS_Z_P_Z_S2W => Kind::ToInteger {
            source: Format::Single,
            destination: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: true,
            },
        },
        FCVTZS_Z_P_Z_S2X => Kind::ToInteger {
            source: Format::Single,
            destination: IntegerFormat {
                width: IntegerWidth::Bits64,
                signed: true,
            },
        },
        FCVTZU_Z_P_Z_D2W => Kind::ToInteger {
            source: Format::Double,
            destination: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: false,
            },
        },
        FCVTZU_Z_P_Z_S2W => Kind::ToInteger {
            source: Format::Single,
            destination: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: false,
            },
        },
        SCVTF_Z_P_Z_W2D => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: true,
            },
            destination: Format::Double,
        },
        SCVTF_Z_P_Z_W2S => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: true,
            },
            destination: Format::Single,
        },
        SCVTF_Z_P_Z_X2D => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits64,
                signed: true,
            },
            destination: Format::Double,
        },
        SCVTF_Z_P_Z_X2S => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits64,
                signed: true,
            },
            destination: Format::Single,
        },
        UCVTF_Z_P_Z_W2D => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: false,
            },
            destination: Format::Double,
        },
        UCVTF_Z_P_Z_W2S => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: false,
            },
            destination: Format::Single,
        },
        FCVTZS_Z_P_Z_FP162H => Kind::ToInteger {
            source: Format::Half,
            destination: IntegerFormat {
                width: IntegerWidth::Bits16,
                signed: true,
            },
        },
        FCVTZS_Z_P_Z_FP162W => Kind::ToInteger {
            source: Format::Half,
            destination: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: true,
            },
        },
        FCVTZS_Z_P_Z_FP162X => Kind::ToInteger {
            source: Format::Half,
            destination: IntegerFormat {
                width: IntegerWidth::Bits64,
                signed: true,
            },
        },
        FCVTZU_Z_P_Z_D2X => Kind::ToInteger {
            source: Format::Double,
            destination: IntegerFormat {
                width: IntegerWidth::Bits64,
                signed: false,
            },
        },
        FCVTZU_Z_P_Z_FP162H => Kind::ToInteger {
            source: Format::Half,
            destination: IntegerFormat {
                width: IntegerWidth::Bits16,
                signed: false,
            },
        },
        FCVTZU_Z_P_Z_FP162W => Kind::ToInteger {
            source: Format::Half,
            destination: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: false,
            },
        },
        FCVTZU_Z_P_Z_FP162X => Kind::ToInteger {
            source: Format::Half,
            destination: IntegerFormat {
                width: IntegerWidth::Bits64,
                signed: false,
            },
        },
        FCVTZU_Z_P_Z_S2X => Kind::ToInteger {
            source: Format::Single,
            destination: IntegerFormat {
                width: IntegerWidth::Bits64,
                signed: false,
            },
        },
        SCVTF_Z_P_Z_H2FP16 => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits16,
                signed: true,
            },
            destination: Format::Half,
        },
        SCVTF_Z_P_Z_W2FP16 => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: true,
            },
            destination: Format::Half,
        },
        SCVTF_Z_P_Z_X2FP16 => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits64,
                signed: true,
            },
            destination: Format::Half,
        },
        UCVTF_Z_P_Z_H2FP16 => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits16,
                signed: false,
            },
            destination: Format::Half,
        },
        UCVTF_Z_P_Z_W2FP16 => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: false,
            },
            destination: Format::Half,
        },
        UCVTF_Z_P_Z_X2D => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits64,
                signed: false,
            },
            destination: Format::Double,
        },
        UCVTF_Z_P_Z_X2FP16 => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits64,
                signed: false,
            },
            destination: Format::Half,
        },
        UCVTF_Z_P_Z_X2S => Kind::FromInteger {
            source: IntegerFormat {
                width: IntegerWidth::Bits64,
                signed: false,
            },
            destination: Format::Single,
        },
        _ => return None,
    };
    Some(Ok(Operand {
        kind,
        destination: (word & REGISTER_MASK) as u8,
        governing: ((word >> GOVERNING_SHIFT) & GOVERNING_MASK) as u8,
        source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_integer_forms_use_complete_max_width_slots() {
        for (opcode, source_bits, destination_bits) in [
            (SCVTF_Z_P_Z_W2S, 32, 32),
            (SCVTF_Z_P_Z_W2D, 32, 64),
            (SCVTF_Z_P_Z_X2S, 64, 32),
            (SCVTF_Z_P_Z_X2D, 64, 64),
            (UCVTF_Z_P_Z_W2S, 32, 32),
            (UCVTF_Z_P_Z_W2D, 32, 64),
            (FCVTZS_Z_P_Z_S2W, 32, 32),
            (FCVTZS_Z_P_Z_S2X, 32, 64),
            (FCVTZS_Z_P_Z_D2W, 64, 32),
            (FCVTZS_Z_P_Z_D2X, 64, 64),
            (FCVTZU_Z_P_Z_S2W, 32, 32),
            (FCVTZU_Z_P_Z_D2W, 64, 32),
        ] {
            let word = opcode
                | REGISTER_MASK
                | (REGISTER_MASK << SOURCE_SHIFT)
                | (GOVERNING_MASK << GOVERNING_SHIFT);
            let operand = decode(word).unwrap().unwrap();
            assert_eq!(
                (operand.destination, operand.source, operand.governing),
                (31, 31, 7)
            );
            assert_eq!(operand.kind.source_bits(), source_bits);
            assert_eq!(operand.kind.destination_bits(), destination_bits);
            let slot_bytes = (source_bits.max(destination_bits) / BITS_PER_BYTE) as u8;
            assert_eq!(operand.kind.slot_bytes(), slot_bytes);
            assert_eq!(operand.kind.written_bytes(), slot_bytes);
            assert_eq!(operand.kind.source_offset(), 0);
            assert_eq!(operand.kind.destination_offset(), 0);
        }
    }
}
