//! LDNP and STNP, integer and SIMD.
use super::{Register, register};

const CLASS_MASK: u32 = 0x3b800000;
const NON_TEMPORAL_PAIR_CLASS: u32 = 0x28000000;
const FORM_MASK: u32 = 0xffc00000;
const STNP_W: u32 = 0x28000000;
const LDNP_W: u32 = 0x28400000;
const STNP_X: u32 = 0xa8000000;
const LDNP_X: u32 = 0xa8400000;
const STNP_S: u32 = 0x2c000000;
const LDNP_S: u32 = 0x2c400000;
const STNP_D: u32 = 0x6c000000;
const LDNP_D: u32 = 0x6c400000;
const STNP_Q: u32 = 0xac000000;
const LDNP_Q: u32 = 0xac400000;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const VECTOR_BYTES: u8 = 16;
const REGISTER_MASK: u32 = 31;
const BASE_SHIFT: u32 = 5;
const SECOND_DATA_SHIFT: u32 = 10;
const IMMEDIATE_SHIFT: u32 = 15;
const IMMEDIATE_BITS: u32 = 7;
const IMMEDIATE_MASK: u32 = (1 << IMMEDIATE_BITS) - 1;
const IMMEDIATE_SIGN_SHIFT: u32 = i32::BITS - IMMEDIATE_BITS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Data {
    Integer([Register; 2]),
    Vector([u8; 2]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub load: bool,
    pub bytes: u8,
    pub data: Data,
    pub base: Register,
    pub displacement: i32,
}

/// Only signed-offset forms match (there is no writeback). Reserved sizes and
/// duplicate LDNP destinations are errors; STNP may repeat a source.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if word & CLASS_MASK != NON_TEMPORAL_PAIR_CLASS {
        return None;
    }
    let (load, bytes, vector) = match word & FORM_MASK {
        STNP_W => (false, DWORD_BYTES, false),
        LDNP_W => (true, DWORD_BYTES, false),
        STNP_X => (false, QWORD_BYTES, false),
        LDNP_X => (true, QWORD_BYTES, false),
        STNP_S => (false, DWORD_BYTES, true),
        LDNP_S => (true, DWORD_BYTES, true),
        STNP_D => (false, QWORD_BYTES, true),
        LDNP_D => (true, QWORD_BYTES, true),
        STNP_Q => (false, VECTOR_BYTES, true),
        LDNP_Q => (true, VECTOR_BYTES, true),
        _ => return Some(Err(())),
    };
    let first = word & REGISTER_MASK;
    let second = (word >> SECOND_DATA_SHIFT) & REGISTER_MASK;
    // LDPOVERLAP allows UNKNOWN/UNDEF/NOP, rather than two ordinary writes.
    // Decline even two ZRs or two V31s, matching the shared LDP boundary.
    if load && first == second {
        return Some(Err(()));
    }
    let immediate = ((word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK) as i32;
    let signed = (immediate << IMMEDIATE_SIGN_SHIFT) >> IMMEDIATE_SIGN_SHIFT;
    Some(Ok(Operand {
        load,
        bytes,
        data: if vector {
            Data::Vector([first as u8, second as u8])
        } else {
            Data::Integer([register(first, false), register(second, false)])
        },
        base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
        displacement: signed * i32::from(bytes),
    }))
}

#[cfg(test)]
mod tests;
