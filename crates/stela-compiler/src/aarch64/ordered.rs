//! Base-only acquire/release transfers and data-memory ordering barriers.
use super::{Register, register};

const TRANSFER_MASK: u32 = 0x3fe0_8000;
const ACQUIRE_CLASS: u32 = 0x08c0_8000;
const RELEASE_CLASS: u32 = 0x0880_8000;
const ACQUIRE_PC_MASK: u32 = 0x3fe0_fc00;
const ACQUIRE_PC_CLASS: u32 = 0x38a0_c000;
const BARRIER_MASK: u32 = 0xffff_f0ff;
const DMB_CLASS: u32 = 0xd503_30bf;
const SIZE_SHIFT: u32 = 30;
const BASE_SHIFT: u32 = 5;
const REGISTER_MASK: u32 = 31;
const OPTION_SHIFT: u32 = 8;
const OPTION_MASK: u32 = 15;
const REQUIREMENT_MASK: u8 = 3;
const READS_OPTION: u8 = 1;
const WRITES_OPTION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Acquire,
    Release,
    AcquirePc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Barrier {
    All,
    Reads,
    Writes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Transfer {
        kind: Kind,
        bytes: u8,
        data: Register,
        base: Register,
    },
    Barrier {
        option: u8,
        requirement: Barrier,
    },
}

/// SBO fields select the documented execute-as-one constrained behavior.
/// They do not become register inputs; data31 is ZR and base31 is SP.
/// Reserved DMB options with low bits00 have the specified SY behavior.
pub fn decode(word: u32) -> Option<Operand> {
    if word & BARRIER_MASK == DMB_CLASS {
        let option = ((word >> OPTION_SHIFT) & OPTION_MASK) as u8;
        let requirement = match option & REQUIREMENT_MASK {
            READS_OPTION => Barrier::Reads,
            WRITES_OPTION => Barrier::Writes,
            _ => Barrier::All,
        };
        return Some(Operand::Barrier {
            option,
            requirement,
        });
    }
    let kind = match word & TRANSFER_MASK {
        ACQUIRE_CLASS => Kind::Acquire,
        RELEASE_CLASS => Kind::Release,
        _ if word & ACQUIRE_PC_MASK == ACQUIRE_PC_CLASS => Kind::AcquirePc,
        _ => return None,
    };
    Some(Operand::Transfer {
        kind,
        bytes: 1 << (word >> SIZE_SHIFT),
        data: register(word & REGISTER_MASK, false),
        base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SBO_SOURCE: u32 = REGISTER_MASK << 16;
    const SBO_SECOND: u32 = REGISTER_MASK << 10;

    #[test]
    fn all_twelve_forms_preserve_register_roles_and_aliases() {
        for (class, kind) in [
            (ACQUIRE_CLASS, Kind::Acquire),
            (RELEASE_CLASS, Kind::Release),
            (ACQUIRE_PC_CLASS, Kind::AcquirePc),
        ] {
            for size in 0..4 {
                for data in 0..=REGISTER_MASK {
                    for base in 0..=REGISTER_MASK {
                        let word = class | (size << SIZE_SHIFT) | (base << BASE_SHIFT) | data;
                        let expected = Operand::Transfer {
                            kind,
                            bytes: 1 << size,
                            data: register(data, false),
                            base: register(base, true),
                        };
                        assert_eq!(decode(word), Some(expected));
                    }
                }
            }
        }
    }

    #[test]
    fn should_be_one_fields_choose_execute_as_one() {
        for class in [ACQUIRE_CLASS, RELEASE_CLASS] {
            let canonical = class | SBO_SOURCE | SBO_SECOND;
            for source in 0..=REGISTER_MASK {
                for second in 0..=REGISTER_MASK {
                    assert_eq!(
                        decode(class | (source << 16) | (second << 10)),
                        decode(canonical)
                    );
                }
            }
        }
        for source in 0..=REGISTER_MASK {
            assert_eq!(
                decode(ACQUIRE_PC_CLASS | (source << 16)),
                decode(ACQUIRE_PC_CLASS | SBO_SOURCE)
            );
        }
    }

    #[test]
    fn all_barrier_options_include_reserved_sy_fallback() {
        for option in 0..=OPTION_MASK {
            let expected = match option & u32::from(REQUIREMENT_MASK) {
                1 => Barrier::Reads,
                2 => Barrier::Writes,
                _ => Barrier::All,
            };
            assert_eq!(
                decode(DMB_CLASS | (option << OPTION_SHIFT)),
                Some(Operand::Barrier {
                    option: option as u8,
                    requirement: expected,
                })
            );
        }
    }

    #[test]
    fn neighboring_instruction_classes_are_not_claimed() {
        // Exclusives, limited-order, LRCPC3 writeback, LDAPUR, CAS, SWP,
        // DSB (including SSBB/PSSBB), nXS and ISB remain separate.
        for word in [
            0xc85f_7c20,
            0xc89f_7c20,
            0xc8df_7c20,
            0xd940_0820,
            0xd900_0820,
            0xd95f_f020,
            0xc8a0_7c20,
            0xf820_8021,
            0xd503_309f,
            0xd503_349f,
            0xd503_3f9f,
            0xd503_323f,
            0xd503_3fdf,
        ] {
            assert!(decode(word).is_none(), "neighbor {word:08x}");
        }
    }
}
