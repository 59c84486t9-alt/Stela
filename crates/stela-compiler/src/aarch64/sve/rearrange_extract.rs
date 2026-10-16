//! SVE element extraction, broadcast and insertion (LAST*, CLAST*, INSR, ...).
use crate::aarch64::scalable::ElementSize;
use crate::aarch64::{Register, register};

const LAST_MASK: u32 = 0xff3f_e000;
const LASTA_GENERAL: u32 = 0x0520_a000;
const LASTB_GENERAL: u32 = 0x0521_a000;
const LASTA_SCALAR: u32 = 0x0522_8000;
const LASTB_SCALAR: u32 = 0x0523_8000;
const CLASTA_GENERAL: u32 = 0x0530_a000;
const CLASTB_GENERAL: u32 = 0x0531_a000;
const CLASTA_SCALAR: u32 = 0x052a_8000;
const CLASTB_SCALAR: u32 = 0x052b_8000;
const CLASTA_VECTOR: u32 = 0x0528_8000;
const CLASTB_VECTOR: u32 = 0x0529_8000;
const DUP_IMMEDIATE_MASK: u32 = 0xff3f_c000;
const DUP_IMMEDIATE: u32 = 0x2538_c000;
const REGISTER_OPCODE_MASK: u32 = 0xff3f_fc00;
const DUP_GENERAL: u32 = 0x0520_3800;
const INSR_GENERAL: u32 = 0x0524_3800;
const INSR_SCALAR: u32 = 0x0534_3800;
const DUP_INDEX_MASK: u32 = 0xff20_fc00;
const DUP_INDEX: u32 = 0x0520_2000;
const REGISTER_MASK: u32 = 31;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const SOURCE_SHIFT: u32 = 5;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const IMMEDIATE_SHIFT: u32 = 5;
const IMMEDIATE_MASK: u32 = 255;
const IMMEDIATE_SCALE_SHIFT: u32 = 8;
const SHIFT_FLAG: u32 = 1 << 13;
const INDEX_SIZE_SHIFT: u32 = 16;
const INDEX_SIZE_MASK: u32 = 31;
const INDEX_HIGH_SHIFT: u32 = 22;
const INDEX_HIGH_MASK: u32 = 3;
const INDEX_HIGH_SCALE: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    General(Register),
    Scalar(u8),
    Vector(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastPosition {
    LastActive,
    AfterLastActive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Last {
        source: u8,
        predicate: u8,
        position: LastPosition,
        conditional: bool,
    },
    DuplicateImmediate(i16),
    DuplicateGeneral(Register),
    DuplicateElement {
        source: u8,
        index: u8,
    },
    InsertGeneral(Register),
    InsertScalar(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub element_size: ElementSize,
    pub destination: Destination,
    pub kind: Kind,
}

fn element_size(word: u32) -> ElementSize {
    match (word >> SIZE_SHIFT) & SIZE_MASK {
        0 => ElementSize::Byte,
        1 => ElementSize::Halfword,
        2 => ElementSize::Word,
        _ => ElementSize::Doubleword,
    }
}

/// None is outside this family; Some(Err(())) is a reserved family encoding.
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let mut element_size = element_size(word);
    let destination_index = (word & REGISTER_MASK) as u8;
    let source_index = ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8;
    let last = match word & LAST_MASK {
        LASTA_GENERAL => Some((
            Destination::General(register(word & REGISTER_MASK, false)),
            false,
            false,
        )),
        LASTB_GENERAL => Some((
            Destination::General(register(word & REGISTER_MASK, false)),
            true,
            false,
        )),
        LASTA_SCALAR => Some((Destination::Scalar(destination_index), false, false)),
        LASTB_SCALAR => Some((Destination::Scalar(destination_index), true, false)),
        CLASTA_GENERAL => Some((
            Destination::General(register(word & REGISTER_MASK, false)),
            false,
            true,
        )),
        CLASTB_GENERAL => Some((
            Destination::General(register(word & REGISTER_MASK, false)),
            true,
            true,
        )),
        CLASTA_SCALAR => Some((Destination::Scalar(destination_index), false, true)),
        CLASTB_SCALAR => Some((Destination::Scalar(destination_index), true, true)),
        CLASTA_VECTOR => Some((Destination::Vector(destination_index), false, true)),
        CLASTB_VECTOR => Some((Destination::Vector(destination_index), true, true)),
        _ => None,
    };
    let (destination, kind) = if let Some((destination, before, conditional)) = last {
        (
            destination,
            Kind::Last {
                source: source_index,
                predicate: ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8,
                position: if before {
                    LastPosition::LastActive
                } else {
                    LastPosition::AfterLastActive
                },
                conditional,
            },
        )
    } else if word & DUP_IMMEDIATE_MASK == DUP_IMMEDIATE {
        let shifted = word & SHIFT_FLAG != 0;
        if element_size == ElementSize::Byte && shifted {
            return Some(Err(()));
        }
        let immediate = ((word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK) as u8 as i8 as i16;
        (
            Destination::Vector(destination_index),
            Kind::DuplicateImmediate(if shifted {
                immediate << IMMEDIATE_SCALE_SHIFT
            } else {
                immediate
            }),
        )
    } else if word & REGISTER_OPCODE_MASK == DUP_GENERAL {
        (
            Destination::Vector(destination_index),
            Kind::DuplicateGeneral(register(source_index.into(), true)),
        )
    } else if word & DUP_INDEX_MASK == DUP_INDEX {
        let size = (word >> INDEX_SIZE_SHIFT) & INDEX_SIZE_MASK;
        if size == 0 {
            return Some(Err(()));
        }
        let lowest = size.trailing_zeros();
        element_size = ElementSize::from_bytes(1 << lowest)?;
        let combined = (((word >> INDEX_HIGH_SHIFT) & INDEX_HIGH_MASK) << INDEX_HIGH_SCALE) | size;
        (
            Destination::Vector(destination_index),
            Kind::DuplicateElement {
                source: source_index,
                index: (combined >> (lowest + 1)) as u8,
            },
        )
    } else if word & REGISTER_OPCODE_MASK == INSR_GENERAL {
        (
            Destination::Vector(destination_index),
            Kind::InsertGeneral(register(source_index.into(), false)),
        )
    } else if word & REGISTER_OPCODE_MASK == INSR_SCALAR {
        (
            Destination::Vector(destination_index),
            Kind::InsertScalar(source_index),
        )
    } else {
        return None;
    };
    Some(Ok(Operand {
        element_size,
        destination,
        kind,
    }))
}

impl Operand {
    /// Canonical-word MOVPRFX requirements for the four documented followers.
    /// Scalar V sources share Z storage; general-register sources do not.
    #[allow(clippy::result_unit_err)]
    pub fn prefix_requirement(
        self,
        original_word: u32,
    ) -> Result<Option<crate::aarch64::sve::prefix::PrefixRequirement>, ()> {
        use crate::aarch64::sve::prefix::PrefixRequirement;

        if decode(original_word) != Some(Ok(self)) {
            return Err(());
        }
        let Destination::Vector(destination) = self.destination else {
            return Ok(None);
        };
        let sources = match self.kind {
            Kind::Last { source, .. }
                if matches!(original_word & LAST_MASK, CLASTA_VECTOR | CLASTB_VECTOR) =>
            {
                Some(1_u32 << source)
            }
            Kind::InsertGeneral(_) if original_word & REGISTER_OPCODE_MASK == INSR_GENERAL => {
                Some(0)
            }
            Kind::InsertScalar(source) if original_word & REGISTER_OPCODE_MASK == INSR_SCALAR => {
                Some(1_u32 << source)
            }
            _ => None,
        };
        Ok(
            sources.map(|other_vector_sources| PrefixRequirement::Vector {
                destination,
                predicated: None,
                other_vector_sources,
            }),
        )
    }
}

#[cfg(test)]
mod tests;
