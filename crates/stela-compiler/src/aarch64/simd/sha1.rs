//! SHA1C, SHA1H, SHA1M, SHA1P, SHA1SU0 and SHA1SU1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Choose,
    Parity,
    Majority,
    Rotate,
    Schedule0,
    Schedule1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    /// Read/write except SHA1H, whose S result clears destination bits 127:32.
    pub destination: u8,
    pub left: u8,
    /// Ignored for SHA1H/SHA1SU1. V31 is ordinary data in every role.
    pub right: u8,
}

const REGISTER_MASK: u32 = 31;
const LEFT_REGISTER_SHIFT: u8 = 5;
const RIGHT_REGISTER_SHIFT: u8 = 16;

const THREE_REGISTER_MASK: u32 = 0xffe0fc00;
const TWO_REGISTER_MASK: u32 = 0xfffffc00;
const SHA1C: u32 = 0x5e000000;
const SHA1P: u32 = 0x5e001000;
const SHA1M: u32 = 0x5e002000;
const SHA1SU0: u32 = 0x5e003000;
const SHA1H: u32 = 0x5e280800;
const SHA1SU1: u32 = 0x5e281800;

pub fn decode(word: u32) -> Option<Operand> {
    let kind = match word & THREE_REGISTER_MASK {
        SHA1C => Kind::Choose,
        SHA1P => Kind::Parity,
        SHA1M => Kind::Majority,
        SHA1SU0 => Kind::Schedule0,
        _ => match word & TWO_REGISTER_MASK {
            SHA1H => Kind::Rotate,
            SHA1SU1 => Kind::Schedule1,
            _ => return None,
        },
    };
    Some(Operand {
        kind,
        destination: (word & REGISTER_MASK) as u8,
        left: ((word >> LEFT_REGISTER_SHIFT) & REGISTER_MASK) as u8,
        right: ((word >> RIGHT_REGISTER_SHIFT) & REGISTER_MASK) as u8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_forms_accept_all_registers_and_decline_fixed_bit_mutations() {
        for (base, mask, kind) in [
            (SHA1C, THREE_REGISTER_MASK, Kind::Choose),
            (SHA1P, THREE_REGISTER_MASK, Kind::Parity),
            (SHA1M, THREE_REGISTER_MASK, Kind::Majority),
            (SHA1SU0, THREE_REGISTER_MASK, Kind::Schedule0),
            (SHA1H, TWO_REGISTER_MASK, Kind::Rotate),
            (SHA1SU1, TWO_REGISTER_MASK, Kind::Schedule1),
        ] {
            for destination in 0..32 {
                for left in 0..32 {
                    for right in 0..if mask == THREE_REGISTER_MASK { 32 } else { 1 } {
                        let operand = decode(
                            base | destination
                                | (left << LEFT_REGISTER_SHIFT)
                                | (right << RIGHT_REGISTER_SHIFT),
                        )
                        .unwrap();
                        assert_eq!(operand.kind, kind);
                        assert_eq!(operand.destination, destination as u8);
                        assert_eq!(operand.left, left as u8);
                        if mask == THREE_REGISTER_MASK {
                            assert_eq!(operand.right, right as u8);
                        }
                    }
                }
            }
            // The fixed size/Q/top-level bits must not broaden this family.
            for bit in [22, 23, 24, 25, 26, 27, 28, 29, 30, 31] {
                assert!(decode(base ^ (1 << bit)).is_none());
            }
        }
    }
}
