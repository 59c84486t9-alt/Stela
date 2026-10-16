//! SHA256H, SHA256H2, SHA256SU0 and SHA256SU1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Hash,
    Hash2,
    Schedule0,
    Schedule1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub left: u8,
    /// Ignored for SHA256SU0. V31 is ordinary vector data, never ZR/SP.
    pub right: u8,
}

const REGISTER_MASK: u32 = 31;
const LEFT_REGISTER_SHIFT: u8 = 5;
const RIGHT_REGISTER_SHIFT: u8 = 16;

const THREE_REGISTER_MASK: u32 = 0xffe0fc00;
const TWO_REGISTER_MASK: u32 = 0xfffffc00;
const SHA256H: u32 = 0x5e004000;
const SHA256H2: u32 = 0x5e005000;
const SHA256SU1: u32 = 0x5e006000;
const SHA256SU0: u32 = 0x5e282800;

pub fn decode(word: u32) -> Option<Operand> {
    let kind = match word & THREE_REGISTER_MASK {
        SHA256H => Kind::Hash,
        SHA256H2 => Kind::Hash2,
        SHA256SU1 => Kind::Schedule1,
        _ if word & TWO_REGISTER_MASK == SHA256SU0 => Kind::Schedule0,
        _ => return None,
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
    fn exact_forms_accept_all_registers_and_keep_hash_parts_distinct() {
        for (base, mask, kind) in [
            (SHA256H, THREE_REGISTER_MASK, Kind::Hash),
            (SHA256H2, THREE_REGISTER_MASK, Kind::Hash2),
            (SHA256SU0, TWO_REGISTER_MASK, Kind::Schedule0),
            (SHA256SU1, THREE_REGISTER_MASK, Kind::Schedule1),
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
            for bit in [22, 23, 24, 25, 26, 27, 28, 29, 30, 31] {
                assert!(decode(base ^ (1 << bit)).is_none());
            }
        }
    }
}
