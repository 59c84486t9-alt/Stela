//! Private wire proposal for generic reserved loads, conditional writes and local clear.
//!
//! The operation never encodes a guest instruction. Request bytes describe the
//! guest quantity; request data points to this complete initialized private payload.

use crate::context::memory::MemoryOrder;

pub const EXCLUSIVE_DATA_BYTES: usize = 32;
pub const EXCLUSIVE_DATA_ALIGNMENT: usize = 8;
pub const EXCLUSIVE_OPERATION_OFFSET: u32 = 0;
pub const EXCLUSIVE_ORDER_OFFSET: u32 = 4;
pub const EXCLUSIVE_SHAPE_OFFSET: u32 = 8;
pub const EXCLUSIVE_STATUS_OFFSET: u32 = 12;
pub const EXCLUSIVE_VALUE_OFFSET: u32 = 16;
pub const EXCLUSIVE_STORED: u32 = 0;
pub const EXCLUSIVE_FAILED: u32 = 1;

const BYTE_BYTES: u32 = 1;
const HALFWORD_BYTES: u32 = 2;
const WORD_BYTES: u32 = 4;
const DOUBLEWORD_BYTES: u32 = 8;
const QUADWORD_BYTES: u32 = 16;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExclusiveOperation {
    Load = 0,
    Store = 1,
    Clear = 2,
}

impl ExclusiveOperation {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            value if value == Self::Load as u32 => Some(Self::Load),
            value if value == Self::Store as u32 => Some(Self::Store),
            value if value == Self::Clear as u32 => Some(Self::Clear),
            _ => None,
        }
    }
}

/// Register-count identity belongs to the saved reservation, independently of
/// ordinary Mem's PAIR descriptor. Both kinds operate on one whole quantity.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExclusiveShape {
    Scalar = 0,
    Pair = 1,
}

impl ExclusiveShape {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            value if value == Self::Scalar as u32 => Some(Self::Scalar),
            value if value == Self::Pair as u32 => Some(Self::Pair),
            _ => None,
        }
    }

    pub const fn supports_width(self, bytes: u32) -> bool {
        match self {
            Self::Scalar => matches!(
                bytes,
                BYTE_BYTES | HALFWORD_BYTES | WORD_BYTES | DOUBLEWORD_BYTES
            ),
            Self::Pair => matches!(bytes, DOUBLEWORD_BYTES | QUADWORD_BYTES),
        }
    }
}

/// All 32 bytes are initialized. Raw codes are validated before constructing
/// Rust enums. Loads start with zero value; stores start with zero status.
/// A callback publishes outputs only after complete success. Payload store
/// Pair8 is two dense little-endian 32-bit lanes in value[0], with value[1]
/// zero; Pair16 is two little-endian 64-bit lanes. Payload store
/// status 0/1 is distinct from the callback's MemoryStatus success/fault result.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExclusiveData {
    pub operation: u32,
    pub order: u32,
    pub shape: u32,
    pub status: u32,
    pub value: [u64; 2],
}

impl ExclusiveData {
    pub fn validate(
        &self,
        bytes: u32,
    ) -> Option<(ExclusiveOperation, MemoryOrder, ExclusiveShape)> {
        let operation = ExclusiveOperation::from_code(self.operation)?;
        let order = MemoryOrder::from_code(self.order)?;
        let shape = ExclusiveShape::from_code(self.shape)?;
        if self.status != EXCLUSIVE_STORED {
            return None;
        }
        if operation == ExclusiveOperation::Clear {
            return (bytes == 0
                && order == MemoryOrder::Relaxed
                && shape == ExclusiveShape::Scalar
                && self.value == [0; 2])
                .then_some((operation, order, shape));
        }
        if !shape.supports_width(bytes) {
            return None;
        }
        match operation {
            ExclusiveOperation::Load => {
                if !matches!(order, MemoryOrder::Relaxed | MemoryOrder::AcquireRcsc)
                    || self.value != [0; 2]
                {
                    return None;
                }
            }
            ExclusiveOperation::Store => {
                if !matches!(order, MemoryOrder::Relaxed | MemoryOrder::Release) {
                    return None;
                }
                if bytes < QUADWORD_BYTES {
                    let mask = u64::MAX >> ((DOUBLEWORD_BYTES - bytes) * u8::BITS);
                    if self.value[1] != 0 || self.value[0] & !mask != 0 {
                        return None;
                    }
                }
            }
            ExclusiveOperation::Clear => unreachable!("clear validated separately"),
        }
        Some((operation, order, shape))
    }
}
