//! Acquire/release loads and stores (LDAR, STLR, LDAPR, ...) and DMB.
use super::{Register, Width, register};

const TRANSFER_MASK: u32 = 0x3fe0_8000;
const ACQUIRE_CLASS: u32 = 0x08c0_8000;
const RELEASE_CLASS: u32 = 0x0880_8000;
const LIMITED_ACQUIRE_CLASS: u32 = 0x08c0_0000;
const LIMITED_RELEASE_CLASS: u32 = 0x0880_0000;
const ACQUIRE_PC_MASK: u32 = 0x3fe0_fc00;
const ACQUIRE_PC_CLASS: u32 = 0x38a0_c000;
const UNSCALED_MASK: u32 = 0x3f20_0c00;
const UNSCALED_CLASS: u32 = 0x1900_0000;
const OPCODE_SHIFT: u32 = 22;
const OPCODE_MASK: u32 = 3;
const STORE_OPCODE: u32 = 0;
const UNSIGNED_LOAD_OPCODE: u32 = 1;
const SIGNED_LOAD_X_OPCODE: u32 = 2;
const SIGNED_LOAD_W_OPCODE: u32 = 3;
const DOUBLEWORD_SIZE: u32 = 3;
const WORD_SIZE: u32 = 2;
const IMMEDIATE_SHIFT: u32 = 12;
const IMMEDIATE_BITS: u32 = 9;
const IMMEDIATE_MASK: u32 = (1 << IMMEDIATE_BITS) - 1;
const SIGN_EXTENSION_SHIFT: u32 = i32::BITS - IMMEDIATE_BITS;
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
pub enum LoadExtension {
    Zero,
    Sign(Width),
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
        displacement: i32,
        extension: LoadExtension,
    },
    Barrier {
        option: u8,
        requirement: Barrier,
    },
}

/// SBO fields take the documented constrained behavior and are not register
/// inputs; data register 31 is ZR and base 31 is SP. With FEAT_LOR but no
/// enabled LORegions, limited accesses have full acquire/release order.
/// Reserved DMB options with low bits 00 behave as SY.
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
    if word & UNSCALED_MASK == UNSCALED_CLASS {
        return decode_unscaled(word);
    }
    let kind = match word & TRANSFER_MASK {
        ACQUIRE_CLASS | LIMITED_ACQUIRE_CLASS => Kind::Acquire,
        RELEASE_CLASS | LIMITED_RELEASE_CLASS => Kind::Release,
        _ if word & ACQUIRE_PC_MASK == ACQUIRE_PC_CLASS => Kind::AcquirePc,
        _ => return None,
    };
    Some(Operand::Transfer {
        kind,
        bytes: 1 << (word >> SIZE_SHIFT),
        data: register(word & REGISTER_MASK, false),
        base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
        displacement: 0,
        extension: LoadExtension::Zero,
    })
}

fn decode_unscaled(word: u32) -> Option<Operand> {
    let size = word >> SIZE_SHIFT;
    let (kind, extension) = match (word >> OPCODE_SHIFT) & OPCODE_MASK {
        STORE_OPCODE => (Kind::Release, LoadExtension::Zero),
        UNSIGNED_LOAD_OPCODE => (Kind::AcquirePc, LoadExtension::Zero),
        SIGNED_LOAD_X_OPCODE if size < DOUBLEWORD_SIZE => {
            (Kind::AcquirePc, LoadExtension::Sign(Width::X64))
        }
        SIGNED_LOAD_W_OPCODE if size < WORD_SIZE => {
            (Kind::AcquirePc, LoadExtension::Sign(Width::W32))
        }
        _ => return None,
    };
    let immediate = ((word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK) as i32;
    Some(Operand::Transfer {
        kind,
        bytes: 1 << size,
        data: register(word & REGISTER_MASK, false),
        base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
        displacement: (immediate << SIGN_EXTENSION_SHIFT) >> SIGN_EXTENSION_SHIFT,
        extension,
    })
}

#[cfg(test)]
mod tests;
