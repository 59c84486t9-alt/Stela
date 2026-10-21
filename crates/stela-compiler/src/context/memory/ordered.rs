//! Ordered GPR access and DMB staging, with source feature identity.
use super::{InstructionRequirements, MemoryOrder};

pub const DATA_BYTES: usize = 32;
pub const DATA_ALIGNMENT: usize = 8;
pub const OPERATION_OFFSET: u32 = 0;
pub const ORDER_OFFSET: u32 = 4;
pub const FEATURE_OFFSET: u32 = 8;
pub const BARRIER_OFFSET: u32 = 12;
pub const VALUE_OFFSET: u32 = 16;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderedOperation {
    Load = 0,
    Store = 1,
    Barrier = 2,
}
impl OrderedOperation {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Load),
            1 => Some(Self::Store),
            2 => Some(Self::Barrier),
            _ => None,
        }
    }
}

#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum OrderedFeature {
    #[default]
    Base = 0,
    Rcpc = 1,
    Rcpc2 = 2,
    Lor = 3,
}
impl OrderedFeature {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Base),
            1 => Some(Self::Rcpc),
            2 => Some(Self::Rcpc2),
            3 => Some(Self::Lor),
            _ => None,
        }
    }
    pub const fn requirements(self) -> InstructionRequirements {
        match self {
            Self::Base => InstructionRequirements::NONE,
            Self::Rcpc => InstructionRequirements::RCPC,
            Self::Rcpc2 => InstructionRequirements::RCPC2,
            Self::Lor => InstructionRequirements::LOR,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OrderedData {
    pub operation: u32,
    pub order: u32,
    pub feature: u32,
    pub barrier: u32,
    pub value: [u64; 2],
}
impl OrderedData {
    pub fn validate(&self, bytes: u32) -> Option<(OrderedOperation, MemoryOrder, OrderedFeature)> {
        let operation = OrderedOperation::from_code(self.operation)?;
        let order = MemoryOrder::from_code(self.order)?;
        let feature = OrderedFeature::from_code(self.feature)?;
        if operation == OrderedOperation::Barrier {
            return (bytes == 0
                && order == MemoryOrder::Relaxed
                && feature == OrderedFeature::Base
                && self.barrier < 16
                && self.value == [0; 2])
                .then_some((operation, order, feature));
        }
        if !matches!(bytes, 1 | 2 | 4 | 8) || self.barrier != 0 || self.value[1] != 0 {
            return None;
        }
        match operation {
            OrderedOperation::Load
                if !matches!(order, MemoryOrder::AcquireRcpc | MemoryOrder::AcquireRcsc)
                    || self.value != [0; 2] =>
            {
                return None;
            }
            OrderedOperation::Store
                if order != MemoryOrder::Release
                    || self.value[0] & !(u64::MAX >> ((8 - bytes) * 8)) != 0 =>
            {
                return None;
            }
            _ => {}
        }
        if (order == MemoryOrder::AcquireRcpc)
            != matches!(feature, OrderedFeature::Rcpc | OrderedFeature::Rcpc2)
            && operation == OrderedOperation::Load
        {
            return None;
        }
        if operation == OrderedOperation::Store && feature == OrderedFeature::Rcpc {
            return None;
        }
        Some((operation, order, feature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn staging_layout_requires_exact_class_order_and_features() {
        assert_eq!(size_of::<OrderedData>(), DATA_BYTES);
        assert_eq!(align_of::<OrderedData>(), DATA_ALIGNMENT);
        assert_eq!(
            core::mem::offset_of!(OrderedData, value),
            VALUE_OFFSET as usize
        );
        let mut data = OrderedData {
            order: MemoryOrder::AcquireRcsc as u32,
            ..Default::default()
        };
        assert!(data.validate(8).is_some());
        data.feature = OrderedFeature::Rcpc as u32;
        assert!(data.validate(8).is_none());
        data.order = MemoryOrder::AcquireRcpc as u32;
        assert!(data.validate(8).is_some());
        data.feature = 4;
        assert!(data.validate(8).is_none());
    }
}
