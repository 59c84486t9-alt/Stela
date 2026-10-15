//! Predicated SVE integer reductions to scalar or 128-bit V results.
//! Streaming permission and scalable register storage belong to the shared core.
use crate::aarch64::scalable::ElementSize;

const REDUCTION_MASK: u32 = 0xff3f_e000;
const AND_CLASS: u32 = 0x041a_2000;
const OR_CLASS: u32 = 0x0418_2000;
const XOR_CLASS: u32 = 0x0419_2000;
const SIGNED_ADD_CLASS: u32 = 0x0400_2000;
const UNSIGNED_ADD_CLASS: u32 = 0x0401_2000;
const SIGNED_MAXIMUM_CLASS: u32 = 0x0408_2000;
const UNSIGNED_MAXIMUM_CLASS: u32 = 0x0409_2000;
const SIGNED_MINIMUM_CLASS: u32 = 0x040a_2000;
const UNSIGNED_MINIMUM_CLASS: u32 = 0x040b_2000;
const QUADWORD_ADD_CLASS: u32 = 0x0405_2000;
const QUADWORD_AND_CLASS: u32 = 0x041e_2000;
const QUADWORD_XOR_CLASS: u32 = 0x041d_2000;
const QUADWORD_OR_CLASS: u32 = 0x041c_2000;
const QUADWORD_SIGNED_MAXIMUM_CLASS: u32 = 0x040c_2000;
const QUADWORD_SIGNED_MINIMUM_CLASS: u32 = 0x040e_2000;
const QUADWORD_UNSIGNED_MAXIMUM_CLASS: u32 = 0x040d_2000;
const QUADWORD_UNSIGNED_MINIMUM_CLASS: u32 = 0x040f_2000;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 0b11;
const GOVERNING_SHIFT: u32 = 10;
const GOVERNING_REGISTER_MASK: u32 = 0b111;
const SOURCE_SHIFT: u32 = 5;
const VECTOR_REGISTER_MASK: u32 = 0b1_1111;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    And,
    Or,
    Xor,
    SignedAdd,
    UnsignedAdd,
    SignedMaximum,
    UnsignedMaximum,
    SignedMinimum,
    UnsignedMinimum,
}

/// Quadword reductions combine matching lane positions across 128-bit chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    Scalar,
    Quadword,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub output: Output,
    pub element_size: ElementSize,
    pub destination: u8,
    pub governing: u8,
    pub source: u8,
}

impl Operand {
    /// Every V result also clears the rest of the current Z register.
    pub const fn result_size(self) -> ElementSize {
        if let Output::Quadword = self.output {
            return ElementSize::Quadword;
        }
        match self.kind {
            Kind::SignedAdd | Kind::UnsignedAdd => ElementSize::Doubleword,
            _ => self.element_size,
        }
    }
}

pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let (kind, output) = match word & REDUCTION_MASK {
        AND_CLASS => (Kind::And, Output::Scalar),
        OR_CLASS => (Kind::Or, Output::Scalar),
        XOR_CLASS => (Kind::Xor, Output::Scalar),
        SIGNED_ADD_CLASS => (Kind::SignedAdd, Output::Scalar),
        UNSIGNED_ADD_CLASS => (Kind::UnsignedAdd, Output::Scalar),
        SIGNED_MAXIMUM_CLASS => (Kind::SignedMaximum, Output::Scalar),
        UNSIGNED_MAXIMUM_CLASS => (Kind::UnsignedMaximum, Output::Scalar),
        SIGNED_MINIMUM_CLASS => (Kind::SignedMinimum, Output::Scalar),
        UNSIGNED_MINIMUM_CLASS => (Kind::UnsignedMinimum, Output::Scalar),
        QUADWORD_ADD_CLASS => (Kind::UnsignedAdd, Output::Quadword),
        QUADWORD_AND_CLASS => (Kind::And, Output::Quadword),
        QUADWORD_XOR_CLASS => (Kind::Xor, Output::Quadword),
        QUADWORD_OR_CLASS => (Kind::Or, Output::Quadword),
        QUADWORD_SIGNED_MAXIMUM_CLASS => (Kind::SignedMaximum, Output::Quadword),
        QUADWORD_SIGNED_MINIMUM_CLASS => (Kind::SignedMinimum, Output::Quadword),
        QUADWORD_UNSIGNED_MAXIMUM_CLASS => (Kind::UnsignedMaximum, Output::Quadword),
        QUADWORD_UNSIGNED_MINIMUM_CLASS => (Kind::UnsignedMinimum, Output::Quadword),
        _ => return None,
    };
    let element_bytes = 1 << ((word >> SIZE_SHIFT) & SIZE_MASK);
    let element_size =
        ElementSize::from_bytes(element_bytes).expect("two-bit SVE reduction element size");
    if kind == Kind::SignedAdd && element_size == ElementSize::Doubleword {
        return Some(Err(()));
    }
    Some(Ok(Operand {
        kind,
        output,
        element_size,
        destination: (word & VECTOR_REGISTER_MASK) as u8,
        governing: ((word >> GOVERNING_SHIFT) & GOVERNING_REGISTER_MASK) as u8,
        source: ((word >> SOURCE_SHIFT) & VECTOR_REGISTER_MASK) as u8,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCODINGS: [(u32, Kind, Output); 17] = [
        (AND_CLASS, Kind::And, Output::Scalar),
        (OR_CLASS, Kind::Or, Output::Scalar),
        (XOR_CLASS, Kind::Xor, Output::Scalar),
        (SIGNED_ADD_CLASS, Kind::SignedAdd, Output::Scalar),
        (UNSIGNED_ADD_CLASS, Kind::UnsignedAdd, Output::Scalar),
        (SIGNED_MAXIMUM_CLASS, Kind::SignedMaximum, Output::Scalar),
        (
            UNSIGNED_MAXIMUM_CLASS,
            Kind::UnsignedMaximum,
            Output::Scalar,
        ),
        (SIGNED_MINIMUM_CLASS, Kind::SignedMinimum, Output::Scalar),
        (
            UNSIGNED_MINIMUM_CLASS,
            Kind::UnsignedMinimum,
            Output::Scalar,
        ),
        (QUADWORD_ADD_CLASS, Kind::UnsignedAdd, Output::Quadword),
        (QUADWORD_AND_CLASS, Kind::And, Output::Quadword),
        (QUADWORD_XOR_CLASS, Kind::Xor, Output::Quadword),
        (QUADWORD_OR_CLASS, Kind::Or, Output::Quadword),
        (
            QUADWORD_SIGNED_MAXIMUM_CLASS,
            Kind::SignedMaximum,
            Output::Quadword,
        ),
        (
            QUADWORD_SIGNED_MINIMUM_CLASS,
            Kind::SignedMinimum,
            Output::Quadword,
        ),
        (
            QUADWORD_UNSIGNED_MAXIMUM_CLASS,
            Kind::UnsignedMaximum,
            Output::Quadword,
        ),
        (
            QUADWORD_UNSIGNED_MINIMUM_CLASS,
            Kind::UnsignedMinimum,
            Output::Quadword,
        ),
    ];

    #[test]
    fn all_allocated_fields_and_reserved_signed_doubleword() {
        for (class, kind, output) in ENCODINGS {
            for size in 0..=SIZE_MASK {
                for governing in 0..=GOVERNING_REGISTER_MASK {
                    for source in 0..=VECTOR_REGISTER_MASK {
                        for destination in 0..=VECTOR_REGISTER_MASK {
                            let word = class
                                | size << SIZE_SHIFT
                                | governing << GOVERNING_SHIFT
                                | source << SOURCE_SHIFT
                                | destination;
                            if kind == Kind::SignedAdd && size == SIZE_MASK {
                                assert_eq!(decode(word), Some(Err(())));
                            } else {
                                let operand = decode(word).unwrap().unwrap();
                                assert_eq!(operand.kind, kind);
                                assert_eq!(operand.output, output);
                                assert_eq!(operand.element_size.bytes(), 1 << size);
                                assert_eq!(operand.governing, governing as u8);
                                assert_eq!(operand.source, source as u8);
                                assert_eq!(operand.destination, destination as u8);
                                let result_size = if output == Output::Quadword {
                                    ElementSize::Quadword
                                } else {
                                    match kind {
                                        Kind::SignedAdd | Kind::UnsignedAdd => {
                                            ElementSize::Doubleword
                                        }
                                        _ => operand.element_size,
                                    }
                                };
                                assert_eq!(operand.result_size(), result_size);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn other_classes_decline() {
        for word in [0, u32::MAX, AND_CLASS ^ (1 << 29), AND_CLASS ^ (1 << 13)] {
            assert_eq!(decode(word), None);
        }
    }
}
