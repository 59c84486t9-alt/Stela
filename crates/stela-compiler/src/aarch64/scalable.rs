//! Shared scalable operands. Instruction families own allocation and mode checks.

pub mod execution;
pub mod features;
pub mod profile;

pub const VECTOR_REGISTER_COUNT: u8 = 32;
pub const PREDICATE_REGISTER_COUNT: u8 = 16;
pub const VECTOR_CHUNK_BYTES: usize = 16;
pub const MIN_VECTOR_BYTES: usize = VECTOR_CHUNK_BYTES;
pub const MAX_VECTOR_BYTES: usize = 256;
pub const BITS_PER_BYTE: usize = 8;
pub const LOOKUP_TABLE_BYTES: usize = 64;
pub const STREAMING_RESET_FPSR: u32 = 0x0800_009f;
pub const SVCR_SM: u64 = 1;
pub const SVCR_ZA: u64 = 1 << 1;
pub const SVCR_MASK: u64 = SVCR_SM | SVCR_ZA;

/// Family decoders validate these indices before constructing operands.
pub const fn is_z_register(index: u8) -> bool {
    index < VECTOR_REGISTER_COUNT
}

pub const fn is_predicate_register(index: u8) -> bool {
    index < PREDICATE_REGISTER_COUNT
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ElementSize {
    Byte = 1,
    Halfword = 2,
    Word = 4,
    Doubleword = 8,
    Quadword = 16,
}

impl ElementSize {
    pub const fn from_bytes(bytes: usize) -> Option<Self> {
        match bytes {
            1 => Some(Self::Byte),
            2 => Some(Self::Halfword),
            4 => Some(Self::Word),
            8 => Some(Self::Doubleword),
            16 => Some(Self::Quadword),
            _ => None,
        }
    }

    pub const fn bytes(self) -> usize {
        self as usize
    }

    pub const fn bits(self) -> usize {
        self.bytes() * BITS_PER_BYTE
    }
}

/// SME streaming lengths are supported powers of two, unlike general SVE VLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VectorLength(u16);

impl VectorLength {
    pub const fn from_bytes(bytes: usize) -> Option<Self> {
        if bytes >= MIN_VECTOR_BYTES && bytes <= MAX_VECTOR_BYTES && bytes.is_power_of_two() {
            Some(Self(bytes as u16))
        } else {
            None
        }
    }

    pub const fn bytes(self) -> usize {
        self.0 as usize
    }

    pub const fn bits(self) -> usize {
        self.bytes() * BITS_PER_BYTE
    }

    pub const fn predicate_bytes(self) -> usize {
        self.bytes() / BITS_PER_BYTE
    }

    pub const fn chunks(self) -> usize {
        self.bytes() / VECTOR_CHUNK_BYTES
    }

    pub const fn lanes(self, element: ElementSize) -> usize {
        self.bytes() / element.bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Predication {
    Unpredicated,
    Merging(u8),
    Zeroing(u8),
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScalableMode {
    streaming: bool,
    za_enabled: bool,
}

impl ScalableMode {
    pub const fn new(streaming: bool, za_enabled: bool) -> Self {
        Self {
            streaming,
            za_enabled,
        }
    }

    pub const fn from_svcr(value: u64) -> Option<Self> {
        if value & !SVCR_MASK != 0 {
            None
        } else {
            Some(Self::new(value & SVCR_SM != 0, value & SVCR_ZA != 0))
        }
    }

    pub const fn streaming(self) -> bool {
        self.streaming
    }

    pub const fn za_enabled(self) -> bool {
        self.za_enabled
    }

    pub const fn svcr(self) -> u64 {
        (if self.streaming { SVCR_SM } else { 0 }) | (if self.za_enabled { SVCR_ZA } else { 0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_banks_are_bounded() {
        for index in 0..=u8::MAX {
            assert_eq!(is_z_register(index), index < VECTOR_REGISTER_COUNT);
            assert_eq!(
                is_predicate_register(index),
                index < PREDICATE_REGISTER_COUNT
            );
        }
    }

    #[test]
    fn streaming_lengths_reject_non_power_two_sve_lengths() {
        for bytes in 0..=MAX_VECTOR_BYTES + VECTOR_CHUNK_BYTES {
            let expected =
                (MIN_VECTOR_BYTES..=MAX_VECTOR_BYTES).contains(&bytes) && bytes.is_power_of_two();
            assert_eq!(VectorLength::from_bytes(bytes).is_some(), expected);
            if let Some(length) = VectorLength::from_bytes(bytes) {
                assert_eq!(length.predicate_bytes() * BITS_PER_BYTE, bytes);
                assert_eq!(length.chunks() * VECTOR_CHUNK_BYTES, bytes);
                for size in [
                    ElementSize::Byte,
                    ElementSize::Halfword,
                    ElementSize::Word,
                    ElementSize::Doubleword,
                    ElementSize::Quadword,
                ] {
                    assert_eq!(length.lanes(size) * size.bytes(), bytes);
                }
            }
        }
    }

    #[test]
    fn mode_bits_are_independent_and_reserved_bits_decline() {
        for bits in 0..=SVCR_MASK {
            assert_eq!(ScalableMode::from_svcr(bits).unwrap().svcr(), bits);
        }
        for bit in 2..u64::BITS {
            assert!(ScalableMode::from_svcr(1 << bit).is_none());
        }
    }
}
