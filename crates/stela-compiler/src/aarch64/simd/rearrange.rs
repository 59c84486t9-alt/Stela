//! Lane movement and permutes: DUP, INS, SMOV, UMOV, EXT, REV16/32/64,
//! ZIP/UZP/TRN, TBL and TBX.
use super::super::{Register, register};
use crate::aarch64::Unsupported;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneSource {
    General(Register),
    Vector { register: u8, byte: u8 },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Duplicate {
        destination: u8,
        source: LaneSource,
        lane_bytes: u8,
        bytes: u8,
    },
    Insert {
        destination: u8,
        source: LaneSource,
        byte: u8,
        lane_bytes: u8,
    },
    Extract {
        destination: Register,
        source: u8,
        byte: u8,
        lane_bytes: u8,
        signed: bool,
        x64: bool,
    },
    /// Each output byte selects left[0..16] or right[16..32]; 255 means zero.
    Permute {
        destination: u8,
        left: u8,
        right: u8,
        selection: [u8; 16],
    },
    Table {
        destination: u8,
        first: u8,
        registers: u8,
        indices: u8,
        bytes: u8,
        preserve: bool,
    },
}

// Names centralize source encoding facts; operands stay separate from opcodes.
macro_rules! encodings {
    ($($name:ident => ($mask:expr, $value:expr)),+ $(,)?) => {
        #[derive(Clone, Copy)]
        enum Encoding { $($name),+ }
        impl Encoding {
            fn matches(self, word: u32) -> bool {
                let (mask, value) = match self { $(Self::$name => ($mask, $value)),+ };
                word & mask == value
            }
        }
    };
}
encodings! {
    DupGeneral => (0xbfe0fc00, 0x0e000c00),
    DupVector => (0xbfe0fc00, 0x0e000400),
    DupScalar => (0xffe0fc00, 0x5e000400),
    InsertGeneral => (0xffe0fc00, 0x4e001c00),
    InsertVector => (0xffe08400, 0x6e000400),
    SignedMove => (0xbfe0fc00, 0x0e002c00),
    UnsignedMove => (0xbfe0fc00, 0x0e003c00),
    ExtractBytes => (0xbfe08400, 0x2e000000),
    Reverse16 => (0xbf3ffc00, 0x0e201800),
    Reverse32 => (0xbf3ffc00, 0x2e200800),
    Reverse64 => (0xbf3ffc00, 0x0e200800),
    Zip => (0xbf20bc00, 0x0e003800),
    Unzip => (0xbf20bc00, 0x0e001800),
    Transpose => (0xbf20bc00, 0x0e002800),
    Table => (0xbfe08c00, 0x0e000000),
}

pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    use Encoding::*;
    let d = (word & 31) as u8;
    let n = ((word >> 5) & 31) as u8;
    let m = ((word >> 16) & 31) as u8;
    let q = (word >> 30) & 1;
    let bytes = (8 << q) as u8;
    if [
        DupGeneral,
        DupVector,
        DupScalar,
        InsertGeneral,
        InsertVector,
        SignedMove,
        UnsignedMove,
    ]
    .into_iter()
    .any(|kind| kind.matches(word))
    {
        let imm5 = ((word >> 16) & 31) as u8;
        if imm5 & 15 == 0 {
            return Some(Err(Unsupported));
        }
        let size = (imm5 & 15).trailing_zeros();
        let lane_bytes = 1 << size;
        let byte = (imm5 >> (size + 1)) * lane_bytes;
        if SignedMove.matches(word) || UnsignedMove.matches(word) {
            let signed = SignedMove.matches(word);
            if (signed && lane_bytes >= (4 << q)) || (!signed && ((q == 1) != (lane_bytes == 8))) {
                return Some(Err(Unsupported));
            }
            return Some(Ok(Operand::Extract {
                destination: register(u32::from(d), false),
                source: n,
                byte,
                lane_bytes,
                signed,
                x64: q != 0,
            }));
        }
        let general = DupGeneral.matches(word) || InsertGeneral.matches(word);
        let source = if general {
            LaneSource::General(register(u32::from(n), false))
        } else {
            LaneSource::Vector {
                register: n,
                byte: if InsertVector.matches(word) {
                    ((word >> 11) as u8 & 15) >> size << size
                } else {
                    byte
                },
            }
        };
        if InsertGeneral.matches(word) || InsertVector.matches(word) {
            return Some(Ok(Operand::Insert {
                destination: d,
                source,
                byte,
                lane_bytes,
            }));
        }
        let scalar = DupScalar.matches(word);
        if !scalar && q == 0 && lane_bytes == 8 {
            return Some(Err(Unsupported));
        }
        return Some(Ok(Operand::Duplicate {
            destination: d,
            source,
            lane_bytes,
            bytes: if scalar { lane_bytes } else { bytes },
        }));
    }
    if Table.matches(word) {
        return Some(Ok(Operand::Table {
            destination: d,
            first: n,
            registers: (((word >> 13) & 3) + 1) as u8,
            indices: m,
            bytes,
            preserve: word & (1 << 12) != 0,
        }));
    }
    let mut selection = [255; 16];
    if ExtractBytes.matches(word) {
        let offset = ((word >> 11) & 15) as u8;
        if offset >= bytes {
            return Some(Err(Unsupported));
        }
        for i in 0..bytes {
            let source = i + offset;
            selection[usize::from(i)] = if source < bytes {
                source
            } else {
                16 + source - bytes
            };
        }
    } else if [Reverse16, Reverse32, Reverse64]
        .into_iter()
        .any(|kind| kind.matches(word))
    {
        let container = if Reverse16.matches(word) {
            2
        } else if Reverse32.matches(word) {
            4
        } else {
            8
        };
        let lane = 1 << ((word >> 22) & 3);
        if lane >= container {
            return Some(Err(Unsupported));
        }
        for i in 0..bytes {
            selection[usize::from(i)] =
                i / container * container + container - lane - (i % container / lane) * lane
                    + i % lane;
        }
    } else if [Zip, Unzip, Transpose]
        .into_iter()
        .any(|kind| kind.matches(word))
    {
        let lane = 1 << ((word >> 22) & 3);
        if lane == 8 && q == 0 {
            return Some(Err(Unsupported));
        }
        let elements = bytes / lane;
        let part = ((word >> 14) & 1) as u8;
        for output in 0..elements {
            let (side, index) = if Zip.matches(word) {
                (output % 2, part * (elements / 2) + output / 2)
            } else if Transpose.matches(word) {
                (output % 2, (output / 2) * 2 + part)
            } else {
                (
                    output / (elements / 2),
                    (output % (elements / 2)) * 2 + part,
                )
            };
            for byte in 0..lane {
                selection[usize::from(output * lane + byte)] = side * 16 + index * lane + byte;
            }
        }
    } else {
        return None;
    }
    Some(Ok(Operand::Permute {
        destination: d,
        left: n,
        right: m,
        selection,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lane_reserved_sizes_and_ignored_bits_follow_the_source_spec() {
        for imm5 in 0..32 {
            for q in 0..2 {
                for base in [0x0e000c00, 0x0e000400, 0x0e002c00, 0x0e003c00] {
                    let word = base | (q << 30) | (imm5 << 16) | (31 << 5) | 31;
                    let size = (imm5 & 15u32).trailing_zeros();
                    let valid = imm5 & 15 != 0
                        && match base {
                            0x0e002c00 => size < 2 + q,
                            0x0e003c00 => {
                                if q == 0 {
                                    size < 3
                                } else {
                                    size == 3
                                }
                            }
                            _ => q == 1 || size != 3,
                        };
                    assert_eq!(decode(word).unwrap().is_ok(), valid, "{word:08x}");
                }
            }
        }
        // INS ignores low imm4 bits below the selected element size.
        assert_eq!(decode(0x6e080400), decode(0x6e083c00));
        assert_eq!(decode(0x2e004000), Some(Err(Unsupported))); // EXT 8B offset 8
        assert_eq!(decode(0x0e601800), Some(Err(Unsupported))); // REV16 halfword
        assert!(decode(0x0e800000).is_none()); // adjacent table fixed bit
    }
}
