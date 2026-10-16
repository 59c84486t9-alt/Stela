//! SVE contiguous and whole-register stores, and PRF* hints. Structured source
//! tuples wrap modulo 32.
use super::memory::{Address, Offset, Scale};
use crate::aarch64::{
    register,
    scalable::{
        ElementSize,
        execution::{GuestMemoryQuantity, ScalableAccessCheck, ScalableAccessRequirements},
    },
};
use alloc::boxed::Box;

const GROUPED_IMMEDIATE_MASK: u32 = 0xfe10_e000;
const GROUPED_IMMEDIATE_CLASS: u32 = 0xe410_e000;
const GROUPED_REGISTER_MASK: u32 = 0xfe00_e000;
const GROUPED_REGISTER_CLASS: u32 = 0xe400_6000;
const MEMORY_SIZE_SHIFT: u32 = 23;
const TUPLE_COUNT_SHIFT: u32 = 21;
const TUPLE_COUNT_MASK: u32 = 3;

const REGISTER_MASK: u32 = 31;
const BASE_SHIFT: u32 = 5;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const OFFSET_SHIFT: u32 = 16;
const IMMEDIATE_BITS: u32 = 4;
const IMMEDIATE_MASK: u32 = (1 << IMMEDIATE_BITS) - 1;
const SIZE_SHIFT: u32 = 21;
const SIZE_MASK: u32 = 3;
const WORD_SIZE_MASK: u32 = 1;
const BYTE_BYTES: u8 = 1;
const WORD_BYTES: u8 = 4;
const WHOLE_VECTOR_MASK: u32 = 0xffc0_e000;
const WHOLE_VECTOR_CLASS: u32 = 0xe580_4000;
const WHOLE_PREDICATE_MASK: u32 = 0xffc0_e010;
const WHOLE_PREDICATE_CLASS: u32 = 0xe580_0000;
const PREFETCH_IMMEDIATE_MASK: u32 = 0xffc0_8010;
const PREFETCH_IMMEDIATE_CLASS: u32 = 0x85c0_0000;
const PREFETCH_REGISTER_MASK: u32 = 0xfe60_e010;
const PREFETCH_REGISTER_CLASS: u32 = 0x8400_c000;
const HINT_MASK: u32 = 15;
const WHOLE_LOW_BITS: u32 = 3;
const WHOLE_OFFSET_BITS: u32 = 9;
const PREFETCH_OFFSET_BITS: u32 = 6;
const IMMEDIATE_SIZE_SHIFT: u32 = 13;
const REGISTER_SIZE_SHIFT: u32 = 23;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Store {
    pub source: u8,
    pub predicate: u8,
    pub address: Address,
    pub element: ElementSize,
    pub memory_element: ElementSize,
    pub register_count: u8,
    pub non_temporal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WholeTarget {
    Vector(u8),
    Predicate(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WholeStore {
    pub target: WholeTarget,
    pub address: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefetch {
    pub hint: u8,
    pub predicate: u8,
    pub address: Address,
    pub element: ElementSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Store(Store),
    Whole(WholeStore),
    Prefetch(Prefetch),
}

#[derive(Clone, Copy)]
enum Element {
    Encoded,
    Word,
    Fixed(u8),
}

#[derive(Clone, Copy)]
struct Form {
    mask: u32,
    value: u32,
    memory_bytes: u8,
    element: Element,
    register_count: u8,
    register_offset: bool,
    non_temporal: bool,
}

const FORMS: &[Form] = &[
    Form {
        mask: 0xff90e000,
        value: 0xe400e000,
        memory_bytes: 1,
        element: Element::Encoded,
        register_count: 1,
        register_offset: false,
        non_temporal: false,
    },
    Form {
        mask: 0xff80e000,
        value: 0xe4004000,
        memory_bytes: 1,
        element: Element::Encoded,
        register_count: 1,
        register_offset: true,
        non_temporal: false,
    },
    Form {
        mask: 0xfff0e000,
        value: 0xe5e0e000,
        memory_bytes: 8,
        element: Element::Fixed(8),
        register_count: 1,
        register_offset: false,
        non_temporal: false,
    },
    Form {
        mask: 0xffe0e000,
        value: 0xe5e04000,
        memory_bytes: 8,
        element: Element::Fixed(8),
        register_count: 1,
        register_offset: true,
        non_temporal: false,
    },
    Form {
        mask: 0xff90e000,
        value: 0xe480e000,
        memory_bytes: 2,
        element: Element::Encoded,
        register_count: 1,
        register_offset: false,
        non_temporal: false,
    },
    Form {
        mask: 0xff80e000,
        value: 0xe4804000,
        memory_bytes: 2,
        element: Element::Encoded,
        register_count: 1,
        register_offset: true,
        non_temporal: false,
    },
    Form {
        mask: 0xffd0e000,
        value: 0xe540e000,
        memory_bytes: 4,
        element: Element::Word,
        register_count: 1,
        register_offset: false,
        non_temporal: false,
    },
    Form {
        mask: 0xffc0e000,
        value: 0xe5404000,
        memory_bytes: 4,
        element: Element::Word,
        register_count: 1,
        register_offset: true,
        non_temporal: false,
    },
    Form {
        mask: 0xfff0e000,
        value: 0xe4400000,
        memory_bytes: 16,
        element: Element::Fixed(16),
        register_count: 2,
        register_offset: false,
        non_temporal: false,
    },
    Form {
        mask: 0xffe0e000,
        value: 0xe4600000,
        memory_bytes: 16,
        element: Element::Fixed(16),
        register_count: 2,
        register_offset: true,
        non_temporal: false,
    },
    Form {
        mask: 0xfff0e000,
        value: 0xe4800000,
        memory_bytes: 16,
        element: Element::Fixed(16),
        register_count: 3,
        register_offset: false,
        non_temporal: false,
    },
    Form {
        mask: 0xffe0e000,
        value: 0xe4a00000,
        memory_bytes: 16,
        element: Element::Fixed(16),
        register_count: 3,
        register_offset: true,
        non_temporal: false,
    },
    Form {
        mask: 0xfff0e000,
        value: 0xe4c00000,
        memory_bytes: 16,
        element: Element::Fixed(16),
        register_count: 4,
        register_offset: false,
        non_temporal: false,
    },
    Form {
        mask: 0xffe0e000,
        value: 0xe4e00000,
        memory_bytes: 16,
        element: Element::Fixed(16),
        register_count: 4,
        register_offset: true,
        non_temporal: false,
    },
];

/// None means another allocation; Err marks a recognized unallocated operand.
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if let Some(form) = grouped_form(word) {
        return Some(decode_store(word, form).map(Operand::Store));
    }
    if let Some(form) = FORMS.iter().find(|form| word & form.mask == form.value) {
        return Some(decode_store(word, *form).map(Operand::Store));
    }
    if let Some(whole) = decode_whole(word) {
        return Some(Ok(Operand::Whole(whole)));
    }
    decode_prefetch(word).map(|result| result.map(Operand::Prefetch))
}

/// B/H/W/D structured and non-temporal classes share size and tuple fields.
fn grouped_form(word: u32) -> Option<Form> {
    let (mask, register_offset) = if word & GROUPED_IMMEDIATE_MASK == GROUPED_IMMEDIATE_CLASS {
        (GROUPED_IMMEDIATE_MASK, false)
    } else if word & GROUPED_REGISTER_MASK == GROUPED_REGISTER_CLASS {
        (GROUPED_REGISTER_MASK, true)
    } else {
        return None;
    };
    let memory_bytes = BYTE_BYTES << ((word >> MEMORY_SIZE_SHIFT) & SIZE_MASK);
    let tuple_index = ((word >> TUPLE_COUNT_SHIFT) & TUPLE_COUNT_MASK) as u8;
    let allocation_mask =
        mask | (SIZE_MASK << MEMORY_SIZE_SHIFT) | (TUPLE_COUNT_MASK << TUPLE_COUNT_SHIFT);
    Some(Form {
        mask: allocation_mask,
        value: word & allocation_mask,
        memory_bytes,
        element: Element::Fixed(memory_bytes),
        register_count: tuple_index + 1,
        register_offset,
        non_temporal: tuple_index == 0,
    })
}

fn signed(value: u32, bits: u32) -> i16 {
    let shift = u32::BITS - bits;
    ((value << shift) as i32 >> shift) as i16
}

fn base(word: u32) -> crate::aarch64::Register {
    register((word >> BASE_SHIFT) & REGISTER_MASK, true)
}

fn decode_store(word: u32, form: Form) -> Result<Store, ()> {
    let element_bytes = match form.element {
        Element::Encoded => BYTE_BYTES << ((word >> SIZE_SHIFT) & SIZE_MASK),
        Element::Word => WORD_BYTES << ((word >> SIZE_SHIFT) & WORD_SIZE_MASK),
        Element::Fixed(bytes) => bytes,
    };
    if element_bytes < form.memory_bytes {
        return Err(());
    }
    let offset = if form.register_offset {
        let index = (word >> OFFSET_SHIFT) & REGISTER_MASK;
        if index == REGISTER_MASK {
            return Err(());
        }
        Offset::Register {
            index: register(index, false),
            shift: form.memory_bytes.trailing_zeros() as u8,
        }
    } else {
        Offset::Immediate {
            value: signed((word >> OFFSET_SHIFT) & IMMEDIATE_MASK, IMMEDIATE_BITS),
            scale: Scale::VectorBytes {
                multiply: form.memory_bytes * form.register_count,
                divide: element_bytes,
            },
        }
    };
    Ok(Store {
        source: (word & REGISTER_MASK) as u8,
        predicate: ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8,
        address: Address {
            base: base(word),
            offset,
        },
        element: ElementSize::from_bytes(usize::from(element_bytes))
            .expect("allocated element width"),
        memory_element: ElementSize::from_bytes(usize::from(form.memory_bytes))
            .expect("allocated memory width"),
        register_count: form.register_count,
        non_temporal: form.non_temporal,
    })
}

fn decode_whole(word: u32) -> Option<WholeStore> {
    let (target, scale) = if word & WHOLE_VECTOR_MASK == WHOLE_VECTOR_CLASS {
        (
            WholeTarget::Vector((word & REGISTER_MASK) as u8),
            Scale::VectorBytes {
                multiply: 1,
                divide: 1,
            },
        )
    } else if word & WHOLE_PREDICATE_MASK == WHOLE_PREDICATE_CLASS {
        (
            WholeTarget::Predicate((word & HINT_MASK) as u8),
            Scale::PredicateBytes,
        )
    } else {
        return None;
    };
    let high_mask = (1 << PREFETCH_OFFSET_BITS) - 1;
    let high = (word >> OFFSET_SHIFT) & high_mask;
    let low = (word >> PREDICATE_SHIFT) & PREDICATE_MASK;
    Some(WholeStore {
        target,
        address: Address {
            base: base(word),
            offset: Offset::Immediate {
                value: signed((high << WHOLE_LOW_BITS) | low, WHOLE_OFFSET_BITS),
                scale,
            },
        },
    })
}

fn decode_prefetch(word: u32) -> Option<Result<Prefetch, ()>> {
    let (offset, size_shift) = if word & PREFETCH_IMMEDIATE_MASK == PREFETCH_IMMEDIATE_CLASS {
        let offset_mask = (1 << PREFETCH_OFFSET_BITS) - 1;
        (
            Offset::Immediate {
                value: signed((word >> OFFSET_SHIFT) & offset_mask, PREFETCH_OFFSET_BITS),
                scale: Scale::VectorBytes {
                    multiply: 1,
                    divide: 1,
                },
            },
            IMMEDIATE_SIZE_SHIFT,
        )
    } else if word & PREFETCH_REGISTER_MASK == PREFETCH_REGISTER_CLASS {
        let index = (word >> OFFSET_SHIFT) & REGISTER_MASK;
        if index == REGISTER_MASK {
            return Some(Err(()));
        }
        let shift = ((word >> REGISTER_SIZE_SHIFT) & SIZE_MASK) as u8;
        (
            Offset::Register {
                index: register(index, false),
                shift,
            },
            REGISTER_SIZE_SHIFT,
        )
    } else {
        return None;
    };
    Some(Ok(Prefetch {
        hint: (word & HINT_MASK) as u8,
        predicate: ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8,
        address: Address {
            base: base(word),
            offset,
        },
        element: ElementSize::from_bytes(usize::from(
            BYTE_BYTES << ((word >> size_shift) & SIZE_MASK),
        ))
        .expect("allocated prefetch element width"),
    }))
}

/// All owned decode classes select CheckSVEEnabled. ST1W/D's other source
/// branch requires esize128 and belongs to separate, unowned XML classes.
pub(crate) fn execution_access_requirements(operand: &Operand) -> ScalableAccessRequirements {
    match operand {
        Operand::Store(_) | Operand::Whole(_) | Operand::Prefetch(_) => {
            ScalableAccessRequirements::Known(Box::new([ScalableAccessCheck::SveEnabled]))
        }
    }
}

/// Maximum individual guest Mem quantity; source lanes and host envelopes
/// remain separate. Whole-register source Operations explicitly access bytes.
pub(crate) const fn guest_memory_quantity(operand: &Operand) -> GuestMemoryQuantity {
    match operand {
        Operand::Store(store) => GuestMemoryQuantity::Maximum(store.memory_element),
        Operand::Whole(_) => GuestMemoryQuantity::Maximum(ElementSize::Byte),
        Operand::Prefetch(_) => GuestMemoryQuantity::None,
    }
}

#[cfg(test)]
mod tests;
