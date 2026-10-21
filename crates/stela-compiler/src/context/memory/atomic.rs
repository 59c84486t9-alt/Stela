//! Validated LSE request staging. Register aliasing is resolved before entry.
use super::MemoryOrder;

pub const DATA_BYTES: usize = 64;
pub const DATA_ALIGNMENT: usize = 8;
pub const OPERATION_OFFSET: u32 = 0;
pub const ORDER_OFFSET: u32 = 4;
pub const COMPARE_OFFSET: u32 = 16;
pub const OPERAND_OFFSET: u32 = 32;
pub const RESULT_OFFSET: u32 = 48;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicOperation {
    CompareExchange = 0,
    Add = 1,
    Clear = 2,
    Xor = 3,
    Set = 4,
    SignedMax = 5,
    SignedMin = 6,
    UnsignedMax = 7,
    UnsignedMin = 8,
    Swap = 9,
    CompareExchangePair = 10,
}
impl AtomicOperation {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::CompareExchange),
            1 => Some(Self::Add),
            2 => Some(Self::Clear),
            3 => Some(Self::Xor),
            4 => Some(Self::Set),
            5 => Some(Self::SignedMax),
            6 => Some(Self::SignedMin),
            7 => Some(Self::UnsignedMax),
            8 => Some(Self::UnsignedMin),
            9 => Some(Self::Swap),
            10 => Some(Self::CompareExchangePair),
            _ => None,
        }
    }
}

/// Pair8 packs two dense 32-bit lanes into the low word, Pair16 two 64-bit
/// lanes. The result is zero on input and is published only after success.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AtomicData {
    pub operation: u32,
    pub order: u32,
    pub reserved: [u32; 2],
    pub compare: [u64; 2],
    pub operand: [u64; 2],
    pub result: [u64; 2],
}
impl AtomicData {
    pub fn validate(&self, bytes: u32) -> Option<(AtomicOperation, MemoryOrder)> {
        let operation = AtomicOperation::from_code(self.operation)?;
        let order = MemoryOrder::from_code(self.order)?;
        if self.reserved != [0; 2]
            || self.result != [0; 2]
            || !matches!(
                order,
                MemoryOrder::Relaxed
                    | MemoryOrder::AcquireRcsc
                    | MemoryOrder::Release
                    | MemoryOrder::AcquireRelease
            )
            || if operation == AtomicOperation::CompareExchangePair {
                !matches!(bytes, 8 | 16)
            } else {
                !matches!(bytes, 1 | 2 | 4 | 8)
            }
        {
            return None;
        }
        if bytes < 16 {
            let mask = u64::MAX >> ((8 - bytes) * 8);
            if self.compare[1] != 0
                || self.operand[1] != 0
                || self.compare[0] & !mask != 0
                || self.operand[0] & !mask != 0
            {
                return None;
            }
        }
        if !matches!(
            operation,
            AtomicOperation::CompareExchange | AtomicOperation::CompareExchangePair
        ) && self.compare != [0; 2]
        {
            return None;
        }
        Some((operation, order))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staging_layout_and_unknown_codes_are_explicit() {
        assert_eq!(size_of::<AtomicData>(), DATA_BYTES);
        assert_eq!(align_of::<AtomicData>(), DATA_ALIGNMENT);
        assert_eq!(
            core::mem::offset_of!(AtomicData, result),
            RESULT_OFFSET as usize
        );
        for bytes in [0, 3, 5, 17] {
            assert!(AtomicData::default().validate(bytes).is_none());
        }
        for code in 11..=255 {
            assert!(AtomicOperation::from_code(code).is_none());
        }
        let mut data = AtomicData {
            operation: AtomicOperation::Add as u32,
            ..Default::default()
        };
        assert!(data.validate(8).is_some());
        data.operand[1] = 1;
        assert!(data.validate(8).is_none());
    }
}
