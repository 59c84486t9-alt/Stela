//! MTE tag generation, loads and stores: IRG, LDG, STG, STZG, ST2G, STZ2G, STGP,
//! LDGM, STGM and STZGM.
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
mod tests;
