//! SVE contiguous, replicating and whole-register loads. The destination is
//! staged in full, so a fault leaves it unchanged.
use super::super::register;
use super::memory::{Address, Extension, Offset, Scale};
use crate::aarch64::Unsupported;
use crate::aarch64::scalable::ElementSize;

const REGISTER_MASK: u32 = 31;
const BASE_SHIFT: u32 = 5;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const INDEX_SHIFT: u32 = 16;
const DTYPE_SHIFT: u32 = 21;
const DTYPE_MASK: u32 = 15;
const CONTIGUOUS_IMMEDIATE_MASK: u32 = 0xfe10_e000;
const CONTIGUOUS_IMMEDIATE: u32 = 0xa400_a000;
const CONTIGUOUS_REGISTER_MASK: u32 = 0xfe00_e000;
const CONTIGUOUS_REGISTER: u32 = 0xa400_4000;
const NON_TEMPORAL_IMMEDIATE_MASK: u32 = 0xfe70_e000;
const NON_TEMPORAL_IMMEDIATE: u32 = 0xa400_e000;
const NON_TEMPORAL_REGISTER_MASK: u32 = 0xfe60_e000;
const NON_TEMPORAL_REGISTER: u32 = 0xa400_c000;
const NON_TEMPORAL_SIZE_SHIFT: u32 = 23;
const SIZE_MASK: u32 = 3;
const WHOLE_VECTOR_MASK: u32 = 0xffc0_e000;
const WHOLE_VECTOR: u32 = 0x8580_4000;
const WHOLE_PREDICATE_MASK: u32 = 0xffc0_e010;
const WHOLE_PREDICATE: u32 = 0x8580_0000;
const WHOLE_IMMEDIATE_HIGH_SHIFT: u32 = 16;
const WHOLE_IMMEDIATE_HIGH_MASK: u32 = 63;
const WHOLE_IMMEDIATE_LOW_SHIFT: u32 = 10;
const WHOLE_IMMEDIATE_LOW_MASK: u32 = 7;
const WHOLE_IMMEDIATE_LOW_BITS: u32 = 3;
const WHOLE_IMMEDIATE_BITS: u32 = 9;
const CONTIGUOUS_IMMEDIATE_BITS: u32 = 4;
const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const WORD_BYTES: u8 = 4;
const DOUBLEWORD_BYTES: u8 = 8;
const PREDICATE_REGISTER_MASK: u32 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Contiguous,
    ReplicateScalar,
    ReplicateQuad,
    WholeVector,
    WholePredicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub data: u8,
    pub address: Address,
    pub predicate: Option<u8>,
    pub memory_element: ElementSize,
    pub element: ElementSize,
    pub extension: Extension,
    pub non_temporal: bool,
    pub tag_checked: bool,
}

pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    if word & WHOLE_VECTOR_MASK == WHOLE_VECTOR {
        return Some(Ok(whole(word, Kind::WholeVector)));
    }
    if word & WHOLE_PREDICATE_MASK == WHOLE_PREDICATE {
        return Some(Ok(whole(word, Kind::WholePredicate)));
    }
    let immediate = word & CONTIGUOUS_IMMEDIATE_MASK == CONTIGUOUS_IMMEDIATE;
    let indexed = word & CONTIGUOUS_REGISTER_MASK == CONTIGUOUS_REGISTER;
    let non_temporal_immediate = word & NON_TEMPORAL_IMMEDIATE_MASK == NON_TEMPORAL_IMMEDIATE;
    let non_temporal_indexed = word & NON_TEMPORAL_REGISTER_MASK == NON_TEMPORAL_REGISTER;
    if immediate || indexed || non_temporal_immediate || non_temporal_indexed {
        let (memory_bytes, element_bytes, extension) =
            if non_temporal_immediate || non_temporal_indexed {
                let bytes = BYTE_BYTES << ((word >> NON_TEMPORAL_SIZE_SHIFT) & SIZE_MASK);
                (bytes, bytes, Extension::Zero)
            } else {
                contiguous_sizes((word >> DTYPE_SHIFT) & DTYPE_MASK)
            };
        let base = register((word >> BASE_SHIFT) & REGISTER_MASK, true);
        let offset = if immediate || non_temporal_immediate {
            Offset::Immediate {
                value: signed(
                    (word >> INDEX_SHIFT) & DTYPE_MASK,
                    CONTIGUOUS_IMMEDIATE_BITS,
                ),
                scale: Scale::VectorBytes {
                    multiply: memory_bytes,
                    divide: element_bytes,
                },
            }
        } else {
            let index = (word >> INDEX_SHIFT) & REGISTER_MASK;
            if index == REGISTER_MASK {
                return Some(Err(Unsupported));
            }
            Offset::Register {
                index: register(index, false),
                shift: memory_bytes.trailing_zeros() as u8,
            }
        };
        return Some(Ok(Operand {
            kind: Kind::Contiguous,
            data: (word & REGISTER_MASK) as u8,
            address: Address { base, offset },
            predicate: Some(((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8),
            memory_element: element_size(memory_bytes),
            element: element_size(element_bytes),
            extension,
            non_temporal: non_temporal_immediate || non_temporal_indexed,
            tag_checked: indexed
                || non_temporal_indexed
                || (word >> BASE_SHIFT) & REGISTER_MASK != REGISTER_MASK,
        }));
    }
    decode_replicate(word)
}

fn whole(word: u32, kind: Kind) -> Operand {
    let immediate = (((word >> WHOLE_IMMEDIATE_HIGH_SHIFT) & WHOLE_IMMEDIATE_HIGH_MASK)
        << WHOLE_IMMEDIATE_LOW_BITS)
        | ((word >> WHOLE_IMMEDIATE_LOW_SHIFT) & WHOLE_IMMEDIATE_LOW_MASK);
    let data_mask = if kind == Kind::WholePredicate {
        PREDICATE_REGISTER_MASK
    } else {
        REGISTER_MASK
    };
    Operand {
        kind,
        data: (word & data_mask) as u8,
        address: Address {
            base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
            offset: Offset::Immediate {
                value: signed(immediate, WHOLE_IMMEDIATE_BITS),
                scale: if kind == Kind::WholePredicate {
                    Scale::PredicateBytes
                } else {
                    Scale::VectorBytes {
                        multiply: BYTE_BYTES,
                        divide: BYTE_BYTES,
                    }
                },
            },
        },
        predicate: None,
        memory_element: ElementSize::Byte,
        element: ElementSize::Byte,
        extension: Extension::Zero,
        non_temporal: false,
        tag_checked: (word >> BASE_SHIFT) & REGISTER_MASK != REGISTER_MASK,
    }
}

fn signed(value: u32, bits: u32) -> i16 {
    ((value as i32) << (i32::BITS - bits) >> (i32::BITS - bits)) as i16
}

fn contiguous_sizes(dtype: u32) -> (u8, u8, Extension) {
    use Extension::{Sign, Zero};
    // Dtype values encode the complete sign/zero-extending allocation, including
    // the reversed element-size order of signed loads.
    const BYTE_TO_BYTE: u32 = 0;
    const BYTE_TO_HALFWORD: u32 = 1;
    const BYTE_TO_WORD: u32 = 2;
    const BYTE_TO_DOUBLEWORD: u32 = 3;
    const SIGNED_WORD_TO_DOUBLEWORD: u32 = 4;
    const HALFWORD_TO_HALFWORD: u32 = 5;
    const HALFWORD_TO_WORD: u32 = 6;
    const HALFWORD_TO_DOUBLEWORD: u32 = 7;
    const SIGNED_HALFWORD_TO_DOUBLEWORD: u32 = 8;
    const SIGNED_HALFWORD_TO_WORD: u32 = 9;
    const WORD_TO_WORD: u32 = 10;
    const WORD_TO_DOUBLEWORD: u32 = 11;
    const SIGNED_BYTE_TO_DOUBLEWORD: u32 = 12;
    const SIGNED_BYTE_TO_WORD: u32 = 13;
    const SIGNED_BYTE_TO_HALFWORD: u32 = 14;
    const DOUBLEWORD_TO_DOUBLEWORD: u32 = 15;
    match dtype {
        BYTE_TO_BYTE => (BYTE_BYTES, BYTE_BYTES, Zero),
        BYTE_TO_HALFWORD => (BYTE_BYTES, HALFWORD_BYTES, Zero),
        BYTE_TO_WORD => (BYTE_BYTES, WORD_BYTES, Zero),
        BYTE_TO_DOUBLEWORD => (BYTE_BYTES, DOUBLEWORD_BYTES, Zero),
        SIGNED_WORD_TO_DOUBLEWORD => (WORD_BYTES, DOUBLEWORD_BYTES, Sign),
        HALFWORD_TO_HALFWORD => (HALFWORD_BYTES, HALFWORD_BYTES, Zero),
        HALFWORD_TO_WORD => (HALFWORD_BYTES, WORD_BYTES, Zero),
        HALFWORD_TO_DOUBLEWORD => (HALFWORD_BYTES, DOUBLEWORD_BYTES, Zero),
        SIGNED_HALFWORD_TO_DOUBLEWORD => (HALFWORD_BYTES, DOUBLEWORD_BYTES, Sign),
        SIGNED_HALFWORD_TO_WORD => (HALFWORD_BYTES, WORD_BYTES, Sign),
        WORD_TO_WORD => (WORD_BYTES, WORD_BYTES, Zero),
        WORD_TO_DOUBLEWORD => (WORD_BYTES, DOUBLEWORD_BYTES, Zero),
        SIGNED_BYTE_TO_DOUBLEWORD => (BYTE_BYTES, DOUBLEWORD_BYTES, Sign),
        SIGNED_BYTE_TO_WORD => (BYTE_BYTES, WORD_BYTES, Sign),
        SIGNED_BYTE_TO_HALFWORD => (BYTE_BYTES, HALFWORD_BYTES, Sign),
        DOUBLEWORD_TO_DOUBLEWORD => (DOUBLEWORD_BYTES, DOUBLEWORD_BYTES, Zero),
        _ => unreachable!("four-bit dtype"),
    }
}

const SCALAR_REPLICATE_MASK: u32 = 0xffc0_e000;
const SCALAR_IMMEDIATE_MASK: u32 = 63;
const QUAD_IMMEDIATE_MASK: u32 = 0xfe70_e000;
const QUAD_IMMEDIATE: u32 = 0xa400_2000;
const QUAD_REGISTER_MASK: u32 = 0xfe60_e000;
const QUAD_REGISTER: u32 = 0xa400_0000;
const QUAD_BYTES: i16 = 16;
const LD1RB_U16: u32 = 0x8440a000;
const LD1RB_U32: u32 = 0x8440c000;
const LD1RB_U64: u32 = 0x8440e000;
const LD1RB_U8: u32 = 0x84408000;
const LD1RD_U64: u32 = 0x85c0e000;
const LD1RH_U16: u32 = 0x84c0a000;
const LD1RH_U32: u32 = 0x84c0c000;
const LD1RH_U64: u32 = 0x84c0e000;
const LD1RSB_S16: u32 = 0x85c0c000;
const LD1RSB_S32: u32 = 0x85c0a000;
const LD1RSB_S64: u32 = 0x85c08000;
const LD1RSH_S32: u32 = 0x8540a000;
const LD1RSH_S64: u32 = 0x85408000;
const LD1RSW_S64: u32 = 0x84c08000;
const LD1RW_U32: u32 = 0x8540c000;
const LD1RW_U64: u32 = 0x8540e000;

fn decode_replicate(word: u32) -> Option<Result<Operand, Unsupported>> {
    let quad_immediate = word & QUAD_IMMEDIATE_MASK == QUAD_IMMEDIATE;
    let quad_register = word & QUAD_REGISTER_MASK == QUAD_REGISTER;
    let (kind, memory_bytes, element_bytes, extension) = if quad_immediate || quad_register {
        let bytes = BYTE_BYTES << ((word >> NON_TEMPORAL_SIZE_SHIFT) & SIZE_MASK);
        (Kind::ReplicateQuad, bytes, bytes, Extension::Zero)
    } else {
        let (memory_bytes, element_bytes, extension) = match word & SCALAR_REPLICATE_MASK {
            LD1RB_U16 => (BYTE_BYTES, HALFWORD_BYTES, Extension::Zero),
            LD1RB_U32 => (BYTE_BYTES, WORD_BYTES, Extension::Zero),
            LD1RB_U64 => (BYTE_BYTES, DOUBLEWORD_BYTES, Extension::Zero),
            LD1RB_U8 => (BYTE_BYTES, BYTE_BYTES, Extension::Zero),
            LD1RD_U64 => (DOUBLEWORD_BYTES, DOUBLEWORD_BYTES, Extension::Zero),
            LD1RH_U16 => (HALFWORD_BYTES, HALFWORD_BYTES, Extension::Zero),
            LD1RH_U32 => (HALFWORD_BYTES, WORD_BYTES, Extension::Zero),
            LD1RH_U64 => (HALFWORD_BYTES, DOUBLEWORD_BYTES, Extension::Zero),
            LD1RSB_S16 => (BYTE_BYTES, HALFWORD_BYTES, Extension::Sign),
            LD1RSB_S32 => (BYTE_BYTES, WORD_BYTES, Extension::Sign),
            LD1RSB_S64 => (BYTE_BYTES, DOUBLEWORD_BYTES, Extension::Sign),
            LD1RSH_S32 => (HALFWORD_BYTES, WORD_BYTES, Extension::Sign),
            LD1RSH_S64 => (HALFWORD_BYTES, DOUBLEWORD_BYTES, Extension::Sign),
            LD1RSW_S64 => (WORD_BYTES, DOUBLEWORD_BYTES, Extension::Sign),
            LD1RW_U32 => (WORD_BYTES, WORD_BYTES, Extension::Zero),
            LD1RW_U64 => (WORD_BYTES, DOUBLEWORD_BYTES, Extension::Zero),
            _ => return None,
        };
        (
            Kind::ReplicateScalar,
            memory_bytes,
            element_bytes,
            extension,
        )
    };
    let offset = if quad_register {
        let index = (word >> INDEX_SHIFT) & REGISTER_MASK;
        if index == REGISTER_MASK {
            return Some(Err(Unsupported));
        }
        Offset::Register {
            index: register(index, false),
            shift: memory_bytes.trailing_zeros() as u8,
        }
    } else {
        let value = if quad_immediate {
            signed(
                (word >> INDEX_SHIFT) & DTYPE_MASK,
                CONTIGUOUS_IMMEDIATE_BITS,
            ) * QUAD_BYTES
        } else {
            ((word >> INDEX_SHIFT) & SCALAR_IMMEDIATE_MASK) as i16 * i16::from(memory_bytes)
        };
        Offset::Immediate {
            value,
            scale: Scale::Bytes,
        }
    };
    Some(Ok(Operand {
        kind,
        data: (word & REGISTER_MASK) as u8,
        address: Address {
            base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
            offset,
        },
        predicate: Some(((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8),
        memory_element: element_size(memory_bytes),
        element: element_size(element_bytes),
        extension,
        non_temporal: false,
        tag_checked: quad_register || (word >> BASE_SHIFT) & REGISTER_MASK != REGISTER_MASK,
    }))
}

fn element_size(bytes: u8) -> ElementSize {
    match bytes {
        BYTE_BYTES => ElementSize::Byte,
        HALFWORD_BYTES => ElementSize::Halfword,
        WORD_BYTES => ElementSize::Word,
        DOUBLEWORD_BYTES => ElementSize::Doubleword,
        _ => unreachable!("allocated SVE load element size"),
    }
}

#[cfg(test)]
mod tests;
