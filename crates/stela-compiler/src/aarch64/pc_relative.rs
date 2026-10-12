//! ADR/ADRP form addresses from the instruction's guest PC, never its native PC.
use super::{Register, register};
use crate::GuestAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: Register,
    pub address: u64,
}

pub fn decode(pc: GuestAddress, word: u32) -> Option<Operand> {
    // Arm ADR_only_pcreladdr / ADRP_only_pcreladdr: op is bit 31;
    // immlo is bits 30:29, immhi is bits 23:5, bits 28:24 are 10000.
    if word & 0x1f000000 != 0x10000000 {
        return None;
    }
    let immediate = ((word >> 5) & 0x7ffff) << 2 | ((word >> 29) & 3);
    let signed = (i64::from(immediate) << 43) >> 43;
    let address = if word >> 31 == 0 {
        pc.0.wrapping_add_signed(signed)
    } else {
        // ADRP's architectural granule is always 4 KiB, including on Apple
        // platforms whose virtual memory mappings use 16 KiB pages.
        (pc.0 & !0xfff).wrapping_add_signed(signed * 4096)
    };
    Some(Operand {
        destination: register(word & 31, false),
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Lifter, aarch64::Operation};

    fn word(page: bool, immediate: i32, destination: u32) -> u32 {
        let encoded = immediate as u32 & 0x1fffff;
        0x10000000
            | (u32::from(page) << 31)
            | ((encoded & 3) << 29)
            | ((encoded >> 2) << 5)
            | destination
    }

    #[test]
    fn signed_extrema_low_immediate_bits_and_every_destination() {
        for page in [false, true] {
            for immediate in [-1048576, -1048575, -4, -3, -2, -1, 0, 1, 2, 3, 1048575] {
                for destination in 0..32 {
                    for pc in [0u64, 0xffc, 0x1000, 0x3ffc, u64::MAX - 3] {
                        let expected = if page {
                            (i128::from(pc & !4095) + i128::from(immediate) * 4096) as u64
                        } else {
                            (i128::from(pc) + i128::from(immediate)) as u64
                        };
                        let operand =
                            decode(GuestAddress(pc), word(page, immediate, destination)).unwrap();
                        assert_eq!(operand.address, expected);
                        assert_eq!(operand.destination, register(destination, false));
                    }
                }
            }
        }
    }

    #[test]
    fn fixed_bits_reject_neighbors_and_lifter_keeps_per_instruction_pc() {
        for bit in 24..29 {
            assert!(decode(GuestAddress(0), 0x10000000 ^ (1 << bit)).is_none());
        }
        for page in [false, true] {
            let instruction = super::super::Decoder
                .lift(GuestAddress(0x4004), word(page, 1, 31))
                .unwrap();
            assert_eq!(instruction.pc, GuestAddress(0x4004));
            assert_eq!(
                instruction.operation,
                Operation::PcRelative(Operand {
                    destination: Register::Zero,
                    address: if page { 0x5000 } else { 0x4005 },
                })
            );
        }
    }
}
