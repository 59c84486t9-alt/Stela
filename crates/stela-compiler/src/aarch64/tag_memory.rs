//! Allocation-tag generation and memory operations for the declared MTE profile.
use super::{AddressMode, Register, register};

const RANDOM_OPCODE_MASK: u32 = 0xffe0_fc00;
const IRG: u32 = 0x9ac0_1000;
const BULK_OPCODE_MASK: u32 = 0xffff_fc00;
const LDGM: u32 = 0xd9e0_0000;
const STGM: u32 = 0xd9a0_0000;
const STZGM: u32 = 0xd920_0000;
const LOAD_OPCODE_MASK: u32 = 0xffe0_0c00;
const LDG: u32 = 0xd960_0000;
const STORE_OPCODE_MASK: u32 = 0xffe0_0000;
const STG: u32 = 0xd920_0000;
const ST2G: u32 = 0xd9a0_0000;
const STZG: u32 = 0xd960_0000;
const STZ2G: u32 = 0xd9e0_0000;
const PAIR_OPCODE_MASK: u32 = 0xffc0_0000;
const STGP_OFFSET: u32 = 0x6900_0000;
const STGP_PRE: u32 = 0x6980_0000;
const STGP_POST: u32 = 0x6880_0000;
const REGISTER_MASK: u32 = 31;
const BASE_SHIFT: u32 = 5;
const SECOND_SHIFT: u32 = 10;
const RANDOM_MASK_SHIFT: u32 = 16;
const STORE_MODE_SHIFT: u32 = 10;
const MODE_MASK: u32 = 3;
const POST_INDEX: u32 = 1;
const OFFSET: u32 = 2;
const PRE_INDEX: u32 = 3;
const IMMEDIATE_SHIFT: u32 = 12;
const IMMEDIATE_BITS: u32 = 9;
const PAIR_IMMEDIATE_SHIFT: u32 = 15;
const PAIR_IMMEDIATE_BITS: u32 = 7;
const TAG_GRANULE_SHIFT: u32 = 4;
const TAG_GRANULE_BYTES: i32 = 1 << TAG_GRANULE_SHIFT;
const MIN_TAG_DISPLACEMENT: i32 = -(1 << (IMMEDIATE_BITS - 1)) << TAG_GRANULE_SHIFT;
const MAX_TAG_DISPLACEMENT: i32 = ((1 << (IMMEDIATE_BITS - 1)) - 1) << TAG_GRANULE_SHIFT;
const MIN_PAIR_DISPLACEMENT: i32 = -(1 << (PAIR_IMMEDIATE_BITS - 1)) << TAG_GRANULE_SHIFT;
const MAX_PAIR_DISPLACEMENT: i32 = ((1 << (PAIR_IMMEDIATE_BITS - 1)) - 1) << TAG_GRANULE_SHIFT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    Tag,
    TagPair,
    ZeroTag,
    ZeroTagPair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkKind {
    Load,
    Store,
    StoreZero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    RandomTag {
        destination: Register,
        address: Register,
        mask: Register,
    },
    LoadTag {
        destination: Register,
        base: Register,
        displacement: i32,
    },
    StoreTags {
        kind: StoreKind,
        source: Register,
        base: Register,
        displacement: i32,
        mode: AddressMode,
    },
    BulkTags {
        kind: BulkKind,
        data: Register,
        base: Register,
    },
    StorePair {
        data: [Register; 2],
        base: Register,
        displacement: i32,
        mode: AddressMode,
    },
}

impl Operand {
    /// Public descriptors must retain the register roles and scaled immediate
    /// ranges of an allocated encoding before any runtime callback can execute.
    pub const fn is_valid(self) -> bool {
        match self {
            Self::RandomTag {
                destination,
                address,
                mask,
            } => {
                valid_register(destination, true)
                    && valid_register(address, true)
                    && valid_register(mask, false)
            }
            Self::LoadTag {
                destination,
                base,
                displacement,
            } => {
                valid_register(destination, false)
                    && valid_register(base, true)
                    && valid_displacement(displacement, MIN_TAG_DISPLACEMENT, MAX_TAG_DISPLACEMENT)
            }
            Self::StoreTags {
                source,
                base,
                displacement,
                ..
            } => {
                valid_register(source, true)
                    && valid_register(base, true)
                    && valid_displacement(displacement, MIN_TAG_DISPLACEMENT, MAX_TAG_DISPLACEMENT)
            }
            Self::BulkTags { data, base, .. } => {
                valid_register(data, false) && valid_register(base, true)
            }
            Self::StorePair {
                data,
                base,
                displacement,
                ..
            } => {
                valid_register(data[0], false)
                    && valid_register(data[1], false)
                    && valid_register(base, true)
                    && valid_displacement(
                        displacement,
                        MIN_PAIR_DISPLACEMENT,
                        MAX_PAIR_DISPLACEMENT,
                    )
            }
        }
    }

    /// LDGM/STGM/STZGM decode normally but architecturally fault at EL0.
    pub const fn requires_privilege(self) -> bool {
        matches!(self, Self::BulkTags { .. })
    }
}

const fn valid_register(register: Register, stack_pointer: bool) -> bool {
    match register {
        Register::X(index) => index < REGISTER_MASK as u8,
        Register::Sp => stack_pointer,
        Register::Zero => !stack_pointer,
    }
}

const fn valid_displacement(displacement: i32, minimum: i32, maximum: i32) -> bool {
    displacement >= minimum && displacement <= maximum && displacement % TAG_GRANULE_BYTES == 0
}

/// Decode all twenty canonical forms without choosing execution privilege.
/// Tag-store Rt31 denotes SP; LDG, bulk and STGP data31 denote ZR. Store
/// writeback aliases are allocated: all sources precede final base writeback.
pub fn decode(word: u32) -> Option<Operand> {
    let data = word & REGISTER_MASK;
    let base = register((word >> BASE_SHIFT) & REGISTER_MASK, true);
    if word & RANDOM_OPCODE_MASK == IRG {
        return Some(Operand::RandomTag {
            destination: register(data, true),
            address: base,
            mask: register((word >> RANDOM_MASK_SHIFT) & REGISTER_MASK, false),
        });
    }
    let bulk = match word & BULK_OPCODE_MASK {
        LDGM => Some(BulkKind::Load),
        STGM => Some(BulkKind::Store),
        STZGM => Some(BulkKind::StoreZero),
        _ => None,
    };
    if let Some(kind) = bulk {
        return Some(Operand::BulkTags {
            kind,
            data: register(data, false),
            base,
        });
    }
    if word & LOAD_OPCODE_MASK == LDG {
        return Some(Operand::LoadTag {
            destination: register(data, false),
            base,
            displacement: displacement(word, IMMEDIATE_SHIFT, IMMEDIATE_BITS),
        });
    }
    let pair_mode = match word & PAIR_OPCODE_MASK {
        STGP_OFFSET => Some(AddressMode::Offset),
        STGP_PRE => Some(AddressMode::PreIndex),
        STGP_POST => Some(AddressMode::PostIndex),
        _ => None,
    };
    if let Some(mode) = pair_mode {
        return Some(Operand::StorePair {
            data: [
                register(data, false),
                register((word >> SECOND_SHIFT) & REGISTER_MASK, false),
            ],
            base,
            displacement: displacement(word, PAIR_IMMEDIATE_SHIFT, PAIR_IMMEDIATE_BITS),
            mode,
        });
    }
    let kind = match word & STORE_OPCODE_MASK {
        STG => StoreKind::Tag,
        ST2G => StoreKind::TagPair,
        STZG => StoreKind::ZeroTag,
        STZ2G => StoreKind::ZeroTagPair,
        _ => return None,
    };
    let mode = match (word >> STORE_MODE_SHIFT) & MODE_MASK {
        POST_INDEX => AddressMode::PostIndex,
        OFFSET => AddressMode::Offset,
        PRE_INDEX => AddressMode::PreIndex,
        _ => return None,
    };
    Some(Operand::StoreTags {
        kind,
        source: register(data, true),
        base,
        displacement: displacement(word, IMMEDIATE_SHIFT, IMMEDIATE_BITS),
        mode,
    })
}

fn displacement(word: u32, shift: u32, bits: u32) -> i32 {
    let immediate = ((word >> shift) & ((1 << bits) - 1)) as i32;
    let sign_shift = i32::BITS - bits;
    ((immediate << sign_shift) >> sign_shift) << TAG_GRANULE_SHIFT
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE_CLASSES: [(u32, StoreKind); 4] = [
        (STG, StoreKind::Tag),
        (ST2G, StoreKind::TagPair),
        (STZG, StoreKind::ZeroTag),
        (STZ2G, StoreKind::ZeroTagPair),
    ];
    const STORE_MODES: [(u32, AddressMode); 3] = [
        (POST_INDEX, AddressMode::PostIndex),
        (OFFSET, AddressMode::Offset),
        (PRE_INDEX, AddressMode::PreIndex),
    ];
    const PAIR_CLASSES: [(u32, AddressMode); 3] = [
        (STGP_OFFSET, AddressMode::Offset),
        (STGP_PRE, AddressMode::PreIndex),
        (STGP_POST, AddressMode::PostIndex),
    ];

    #[test]
    fn random_tag_all_registers_preserve_sp_and_zero_roles() {
        for destination in 0..=REGISTER_MASK {
            for address in 0..=REGISTER_MASK {
                for mask in 0..=REGISTER_MASK {
                    let word =
                        IRG | (mask << RANDOM_MASK_SHIFT) | (address << BASE_SHIFT) | destination;
                    assert_eq!(
                        decode(word),
                        Some(Operand::RandomTag {
                            destination: register(destination, true),
                            address: register(address, true),
                            mask: register(mask, false),
                        })
                    );
                }
            }
        }
    }

    #[test]
    fn load_and_tag_store_immediates_include_signed_extremes() {
        for immediate in 0..(1 << IMMEDIATE_BITS) {
            let offset = if immediate & (1 << (IMMEDIATE_BITS - 1)) == 0 {
                immediate as i32
            } else {
                immediate as i32 - (1 << IMMEDIATE_BITS)
            } << TAG_GRANULE_SHIFT;
            let fields =
                (immediate << IMMEDIATE_SHIFT) | (REGISTER_MASK << BASE_SHIFT) | REGISTER_MASK;
            assert_eq!(
                decode(LDG | fields),
                Some(Operand::LoadTag {
                    destination: Register::Zero,
                    base: Register::Sp,
                    displacement: offset,
                })
            );
            for (opcode, kind) in STORE_CLASSES {
                for (mode_bits, mode) in STORE_MODES {
                    assert_eq!(
                        decode(opcode | (mode_bits << STORE_MODE_SHIFT) | fields),
                        Some(Operand::StoreTags {
                            kind,
                            source: Register::Sp,
                            base: Register::Sp,
                            displacement: offset,
                            mode,
                        })
                    );
                }
            }
        }
    }

    #[test]
    fn tag_store_aliases_and_load_data_registers_are_allocated() {
        for data in 0..=REGISTER_MASK {
            for base in 0..=REGISTER_MASK {
                let fields = (base << BASE_SHIFT) | data;
                assert_eq!(
                    decode(LDG | fields),
                    Some(Operand::LoadTag {
                        destination: register(data, false),
                        base: register(base, true),
                        displacement: 0,
                    })
                );
                for (opcode, kind) in STORE_CLASSES {
                    for (mode_bits, mode) in STORE_MODES {
                        assert_eq!(
                            decode(opcode | (mode_bits << STORE_MODE_SHIFT) | fields),
                            Some(Operand::StoreTags {
                                kind,
                                source: register(data, true),
                                base: register(base, true),
                                displacement: 0,
                                mode,
                            })
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn pair_all_registers_and_writeback_aliases_are_allocated() {
        for first in 0..=REGISTER_MASK {
            for second in 0..=REGISTER_MASK {
                for base in 0..=REGISTER_MASK {
                    for (opcode, mode) in PAIR_CLASSES {
                        assert_eq!(
                            decode(
                                opcode | (second << SECOND_SHIFT) | (base << BASE_SHIFT) | first
                            ),
                            Some(Operand::StorePair {
                                data: [register(first, false), register(second, false)],
                                base: register(base, true),
                                displacement: 0,
                                mode,
                            })
                        );
                    }
                }
            }
        }
        for immediate in 0..(1 << PAIR_IMMEDIATE_BITS) {
            let offset = if immediate & (1 << (PAIR_IMMEDIATE_BITS - 1)) == 0 {
                immediate as i32
            } else {
                immediate as i32 - (1 << PAIR_IMMEDIATE_BITS)
            } << TAG_GRANULE_SHIFT;
            for (opcode, mode) in PAIR_CLASSES {
                assert_eq!(
                    decode(opcode | (immediate << PAIR_IMMEDIATE_SHIFT)),
                    Some(Operand::StorePair {
                        data: [Register::X(0), Register::X(0)],
                        base: Register::X(0),
                        displacement: offset,
                        mode,
                    })
                );
            }
        }
    }

    #[test]
    fn bulk_privilege_is_an_execution_requirement_and_data31_is_zero() {
        for (opcode, kind) in [
            (LDGM, BulkKind::Load),
            (STGM, BulkKind::Store),
            (STZGM, BulkKind::StoreZero),
        ] {
            for data in 0..=REGISTER_MASK {
                for base in 0..=REGISTER_MASK {
                    let expected = Operand::BulkTags {
                        kind,
                        data: register(data, false),
                        base: register(base, true),
                    };
                    assert!(expected.requires_privilege());
                    assert_eq!(decode(opcode | (base << BASE_SHIFT) | data), Some(expected));
                }
            }
        }
        assert!(!decode(IRG).unwrap().requires_privilege());
        assert!(!decode(LDG).unwrap().requires_privilege());
        assert!(
            !decode(STG | (OFFSET << STORE_MODE_SHIFT))
                .unwrap()
                .requires_privilege()
        );
        assert!(!decode(STGP_OFFSET).unwrap().requires_privilege());
    }

    #[test]
    fn reserved_zero_mode_tag_stores_do_not_become_bulk_immediates() {
        for opcode in [STG, ST2G, STZ2G] {
            for immediate in 1..(1 << IMMEDIATE_BITS) {
                assert!(decode(opcode | (immediate << IMMEDIATE_SHIFT)).is_none());
            }
        }
        for word in [0, u32::MAX, 0xd503_201f, 0xd960_0400 ^ (1 << 21)] {
            assert!(decode(word).is_none());
        }
    }

    #[test]
    fn allocated_decodes_validate_but_malformed_public_roles_and_offsets_do_not() {
        for immediate in 0..(1 << IMMEDIATE_BITS) {
            let fields =
                (immediate << IMMEDIATE_SHIFT) | (REGISTER_MASK << BASE_SHIFT) | REGISTER_MASK;
            assert!(decode(LDG | fields).unwrap().is_valid());
            for (opcode, _) in STORE_CLASSES {
                for (mode, _) in STORE_MODES {
                    assert!(
                        decode(opcode | (mode << STORE_MODE_SHIFT) | fields)
                            .unwrap()
                            .is_valid()
                    );
                }
            }
        }
        for immediate in 0..(1 << PAIR_IMMEDIATE_BITS) {
            for (opcode, _) in PAIR_CLASSES {
                assert!(
                    decode(opcode | (immediate << PAIR_IMMEDIATE_SHIFT) | REGISTER_MASK)
                        .unwrap()
                        .is_valid()
                );
            }
        }
        for register in REGISTER_MASK as u8..=u8::MAX {
            assert!(
                !Operand::LoadTag {
                    destination: Register::X(register),
                    base: Register::Sp,
                    displacement: 0
                }
                .is_valid()
            );
            assert!(
                !Operand::BulkTags {
                    kind: BulkKind::Store,
                    data: Register::Zero,
                    base: Register::X(register)
                }
                .is_valid()
            );
        }
        for displacement in [
            MIN_TAG_DISPLACEMENT - TAG_GRANULE_BYTES,
            MAX_TAG_DISPLACEMENT + TAG_GRANULE_BYTES,
            -1,
            1,
            i32::MIN,
            i32::MAX,
        ] {
            assert!(
                !Operand::LoadTag {
                    destination: Register::Zero,
                    base: Register::Sp,
                    displacement
                }
                .is_valid()
            );
        }
        for displacement in [
            MIN_PAIR_DISPLACEMENT - TAG_GRANULE_BYTES,
            MAX_PAIR_DISPLACEMENT + TAG_GRANULE_BYTES,
            -1,
            1,
            i32::MIN,
            i32::MAX,
        ] {
            assert!(
                !Operand::StorePair {
                    data: [Register::Zero; 2],
                    base: Register::Sp,
                    displacement,
                    mode: AddressMode::Offset
                }
                .is_valid()
            );
        }
        for operand in [
            Operand::RandomTag {
                destination: Register::Zero,
                address: Register::Sp,
                mask: Register::Zero,
            },
            Operand::LoadTag {
                destination: Register::Sp,
                base: Register::Sp,
                displacement: 0,
            },
            Operand::StoreTags {
                kind: StoreKind::Tag,
                source: Register::Zero,
                base: Register::Sp,
                displacement: 0,
                mode: AddressMode::Offset,
            },
            Operand::BulkTags {
                kind: BulkKind::Load,
                data: Register::Sp,
                base: Register::Sp,
            },
            Operand::StorePair {
                data: [Register::Sp, Register::Zero],
                base: Register::Sp,
                displacement: 0,
                mode: AddressMode::Offset,
            },
            Operand::StorePair {
                data: [Register::Zero; 2],
                base: Register::Zero,
                displacement: 0,
                mode: AddressMode::Offset,
            },
        ] {
            assert!(!operand.is_valid());
        }
    }
}
