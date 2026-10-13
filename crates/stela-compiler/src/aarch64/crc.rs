//! Scalar CRC32/CRC32C encodings from the pinned Arm 2026-06 reference.
use super::{Register, register};

const CLASS_MASK: u32 = 0x7fe0e000;
const CLASS_VALUE: u32 = 0x1ac04000;
const SIZE_SHIFT: u32 = 10;
const SIZE_MASK: u32 = 3;
const CASTAGNOLI_BIT: u32 = 1 << 12;
const DOUBLEWORD_BIT: u32 = 1 << 31;
const REGISTER_MASK: u32 = 31;
const ACCUMULATOR_SHIFT: u32 = 5;
const DATA_SHIFT: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polynomial {
    Ieee,
    Castagnoli,
}
impl Polynomial {
    pub(crate) fn reflected(self) -> u32 {
        match self {
            Self::Ieee => 0xedb88320,
            Self::Castagnoli => 0x82f63b78,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSize {
    Byte,
    Halfword,
    Word,
    Doubleword,
}
impl DataSize {
    pub(crate) fn bytes(self) -> u8 {
        match self {
            Self::Byte => 1,
            Self::Halfword => 2,
            Self::Word => 4,
            Self::Doubleword => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub polynomial: Polynomial,
    pub size: DataSize,
    pub destination: Register,
    pub accumulator: Register,
    pub data: Register,
}

/// Register 31 is ZR in every role; sf is set exactly for doubleword data.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if word & CLASS_MASK != CLASS_VALUE {
        return None;
    }
    let size = match (word >> SIZE_SHIFT) & SIZE_MASK {
        0 => DataSize::Byte,
        1 => DataSize::Halfword,
        2 => DataSize::Word,
        _ => DataSize::Doubleword,
    };
    if (word & DOUBLEWORD_BIT != 0) != (size == DataSize::Doubleword) {
        return Some(Err(()));
    }
    Some(Ok(Operand {
        size,
        polynomial: if word & CASTAGNOLI_BIT == 0 {
            Polynomial::Ieee
        } else {
            Polynomial::Castagnoli
        },
        destination: register(word & REGISTER_MASK, false),
        accumulator: register((word >> ACCUMULATOR_SHIFT) & REGISTER_MASK, false),
        data: register((word >> DATA_SHIFT) & REGISTER_MASK, false),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_sizes_polynomials_and_register_triples_preserve_zero_roles() {
        for polynomial in [Polynomial::Ieee, Polynomial::Castagnoli] {
            for (size_field, size) in [
                DataSize::Byte,
                DataSize::Halfword,
                DataSize::Word,
                DataSize::Doubleword,
            ]
            .into_iter()
            .enumerate()
            {
                let base = CLASS_VALUE
                    | ((size_field as u32) << SIZE_SHIFT)
                    | if polynomial == Polynomial::Castagnoli {
                        CASTAGNOLI_BIT
                    } else {
                        0
                    }
                    | if size == DataSize::Doubleword {
                        DOUBLEWORD_BIT
                    } else {
                        0
                    };
                for destination in 0..=REGISTER_MASK {
                    for accumulator in 0..=REGISTER_MASK {
                        for data in 0..=REGISTER_MASK {
                            assert_eq!(
                                decode(
                                    base | (data << DATA_SHIFT)
                                        | (accumulator << ACCUMULATOR_SHIFT)
                                        | destination
                                ),
                                Some(Ok(Operand {
                                    size,
                                    polynomial,
                                    destination: register(destination, false),
                                    accumulator: register(accumulator, false),
                                    data: register(data, false)
                                }))
                            );
                        }
                    }
                }
                assert_eq!(decode(base ^ DOUBLEWORD_BIT), Some(Err(())));
                for bit in 0..32 {
                    if CLASS_MASK & (1 << bit) != 0 {
                        assert!(decode(base ^ (1 << bit)).is_none());
                    }
                }
            }
        }
    }
}
