//! Scalar integer load/store register-offset addressing.
//!
//! Arm instruction reference: https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85
//! The ordinary-RAM profile disables tags/PAC; base SP alignment is checked.
use super::{MemoryTransfer, Register, Width, register};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexExtend {
    Uxtw,
    Lsl,
    Sxtw,
    Sxtx,
}

impl IndexExtend {
    pub(crate) const fn decode(option: u32) -> Option<Self> {
        const UXTW: u32 = 0b010;
        const LSL: u32 = 0b011;
        const SXTW: u32 = 0b110;
        const SXTX: u32 = 0b111;
        match option {
            UXTW => Some(Self::Uxtw),
            LSL => Some(Self::Lsl),
            SXTW => Some(Self::Sxtw),
            SXTX => Some(Self::Sxtx),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub transfer: MemoryTransfer,
    pub bytes: u8,
    pub data: Register,
    pub base: Register,
    pub index: Register,
    pub extend: IndexExtend,
    pub shift: u8,
}

/// None means another encoding class; Err means a reserved/unsupported form
/// within the scalar register-offset class. SIMD and atomics never match.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if word & 0x3f200c00 != 0x38200800 {
        return None;
    }
    let size = word >> 30;
    let transfer = match (word >> 22) & 3 {
        0 => MemoryTransfer::Store,
        1 => MemoryTransfer::Load {
            signed: false,
            width: if size == 3 { Width::X64 } else { Width::W32 },
        },
        2 if size < 3 => MemoryTransfer::Load {
            signed: true,
            width: Width::X64,
        },
        3 if size < 2 => MemoryTransfer::Load {
            signed: true,
            width: Width::W32,
        },
        _ => return Some(Err(())), // PRFM and reserved signed sizes
    };
    let Some(extend) = IndexExtend::decode((word >> 13) & 7) else {
        return Some(Err(())); // sub-word index extensions are undefined
    };
    Some(Ok(Operand {
        transfer,
        bytes: 1 << size,
        data: register(word & 31, false),
        base: register((word >> 5) & 31, true),
        index: register((word >> 16) & 31, false),
        extend,
        shift: if word & (1 << 12) == 0 { 0 } else { size as u8 },
    }))
}

#[cfg(test)]
mod tests;
