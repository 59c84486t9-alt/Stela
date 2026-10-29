//! SVE contiguous and whole-register stores, and PRF* hints. Structured source
//! tuples wrap modulo 32.
use super::memory::{Address, Offset, Scale};
use crate::aarch64::Unsupported;
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
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
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

fn decode_store(word: u32, form: Form) -> Result<Store, Unsupported> {
    let element_bytes = match form.element {
        Element::Encoded => BYTE_BYTES << ((word >> SIZE_SHIFT) & SIZE_MASK),
        Element::Word => WORD_BYTES << ((word >> SIZE_SHIFT) & WORD_SIZE_MASK),
        Element::Fixed(bytes) => bytes,
    };
    if element_bytes < form.memory_bytes {
        return Err(Unsupported);
    }
    let offset = if form.register_offset {
        let index = (word >> OFFSET_SHIFT) & REGISTER_MASK;
        if index == REGISTER_MASK {
            return Err(Unsupported);
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

fn decode_prefetch(word: u32) -> Option<Result<Prefetch, Unsupported>> {
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
            return Some(Err(Unsupported));
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

/// Every decoded class uses CheckSVEEnabled. The other ST1W/ST1D branch
/// requires 128-bit elements, which these classes never have.
pub(crate) fn execution_access_requirements(operand: &Operand) -> ScalableAccessRequirements {
    match operand {
        Operand::Store(_) | Operand::Whole(_) | Operand::Prefetch(_) => {
            ScalableAccessRequirements::Known(Box::new([ScalableAccessCheck::SveEnabled]))
        }
    }
}

/// Largest single guest memory access of the instruction. Whole-register forms
/// access bytes.
pub(crate) const fn guest_memory_quantity(operand: &Operand) -> GuestMemoryQuantity {
    match operand {
        Operand::Store(store) => GuestMemoryQuantity::Maximum(store.memory_element),
        Operand::Whole(_) => GuestMemoryQuantity::Maximum(ElementSize::Byte),
        Operand::Prefetch(_) => GuestMemoryQuantity::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::Register;
    use alloc::boxed::Box;

    #[test]
    fn every_store_class_preserves_registers_and_address_scale() {
        let mut forms = FORMS.to_vec();
        for size in 0..=SIZE_MASK {
            for tuple_index in 0..=TUPLE_COUNT_MASK {
                for class in [GROUPED_IMMEDIATE_CLASS, GROUPED_REGISTER_CLASS] {
                    let word =
                        class | (size << MEMORY_SIZE_SHIFT) | (tuple_index << TUPLE_COUNT_SHIFT);
                    forms.push(grouped_form(word).unwrap());
                }
            }
        }
        for form in &forms {
            for source in 0..=REGISTER_MASK {
                for base_register in 0..=REGISTER_MASK {
                    for offset in [0, IMMEDIATE_MASK, REGISTER_MASK] {
                        if !form.register_offset && offset > IMMEDIATE_MASK {
                            continue;
                        }
                        let size = match form.element {
                            Element::Encoded => form.memory_bytes.trailing_zeros(),
                            _ => 0,
                        };
                        let word = form.value
                            | (size << SIZE_SHIFT)
                            | source
                            | (base_register << BASE_SHIFT)
                            | (PREDICATE_MASK << PREDICATE_SHIFT)
                            | (offset << OFFSET_SHIFT);
                        let result = decode(word).expect("owned store class");
                        if form.register_offset && offset == REGISTER_MASK {
                            assert_eq!(result, Err(Unsupported));
                            continue;
                        }
                        let Operand::Store(store) = result.expect("allocated operands") else {
                            panic!("store decoded as another operand");
                        };
                        assert_eq!(store.source, source as u8);
                        assert_eq!(store.predicate, PREDICATE_MASK as u8);
                        assert_eq!(store.address.base, register(base_register, true));
                        assert_eq!(store.memory_element.bytes(), usize::from(form.memory_bytes));
                        assert_eq!(store.register_count, form.register_count);
                        assert_eq!(store.non_temporal, form.non_temporal);
                        match store.address.offset {
                            Offset::Register { index, shift } => {
                                assert_eq!(index, Register::X(offset as u8));
                                assert_eq!(shift, form.memory_bytes.trailing_zeros() as u8);
                            }
                            Offset::Immediate { value, scale } => {
                                assert_eq!(value, signed(offset, IMMEDIATE_BITS));
                                assert_eq!(
                                    scale,
                                    Scale::VectorBytes {
                                        multiply: form.memory_bytes * form.register_count,
                                        divide: store.element.bytes() as u8,
                                    }
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn narrowing_halfword_rejects_byte_source_elements() {
        for class in [0xe480_e000, 0xe480_4000] {
            assert_eq!(decode(class), Some(Err(Unsupported)));
            assert!(matches!(
                decode(class | (1 << SIZE_SHIFT)),
                Some(Ok(Operand::Store(_)))
            ));
        }
    }

    #[test]
    fn whole_offsets_preserve_all_signed_nine_bit_values() {
        let count = 1 << WHOLE_OFFSET_BITS;
        for immediate in 0..count {
            let high = immediate >> WHOLE_LOW_BITS;
            let low = immediate & PREDICATE_MASK;
            for (class, target, scale) in [
                (
                    WHOLE_VECTOR_CLASS,
                    WholeTarget::Vector(REGISTER_MASK as u8),
                    Scale::VectorBytes {
                        multiply: 1,
                        divide: 1,
                    },
                ),
                (
                    WHOLE_PREDICATE_CLASS,
                    WholeTarget::Predicate(HINT_MASK as u8),
                    Scale::PredicateBytes,
                ),
            ] {
                let source = match target {
                    WholeTarget::Vector(index) | WholeTarget::Predicate(index) => u32::from(index),
                };
                let word = class
                    | source
                    | (REGISTER_MASK << BASE_SHIFT)
                    | (high << OFFSET_SHIFT)
                    | (low << PREDICATE_SHIFT);
                let Operand::Whole(store) = decode(word).unwrap().unwrap() else {
                    panic!("whole store decoded as another operand");
                };
                assert_eq!(store.target, target);
                assert_eq!(store.address.base, Register::Sp);
                assert_eq!(
                    store.address.offset,
                    Offset::Immediate {
                        value: signed(immediate, WHOLE_OFFSET_BITS),
                        scale,
                    }
                );
            }
        }
    }

    #[test]
    fn prefetch_preserves_all_hints_and_scales_and_declines_reserved_index() {
        for size in 0..=SIZE_MASK {
            for hint in 0..=HINT_MASK {
                for immediate in 0..(1 << PREFETCH_OFFSET_BITS) {
                    let word = PREFETCH_IMMEDIATE_CLASS
                        | hint
                        | (size << IMMEDIATE_SIZE_SHIFT)
                        | (immediate << OFFSET_SHIFT);
                    let Operand::Prefetch(prefetch) = decode(word).unwrap().unwrap() else {
                        panic!("prefetch decoded as another operand");
                    };
                    assert_eq!(prefetch.hint, hint as u8);
                    assert_eq!(prefetch.element.bytes(), usize::from(BYTE_BYTES << size));
                    assert_eq!(
                        prefetch.address.offset,
                        Offset::Immediate {
                            value: signed(immediate, PREFETCH_OFFSET_BITS),
                            scale: Scale::VectorBytes {
                                multiply: 1,
                                divide: 1
                            },
                        }
                    );
                }
                let reserved = PREFETCH_REGISTER_CLASS
                    | hint
                    | (size << REGISTER_SIZE_SHIFT)
                    | (REGISTER_MASK << OFFSET_SHIFT);
                assert_eq!(decode(reserved), Some(Err(Unsupported)));
            }
        }
    }

    #[test]
    fn unrelated_and_nonstreaming_quadword_single_forms_are_unowned() {
        for word in [
            0,
            u32::MAX,
            0xd503_201f,
            0xe500_e000,
            0xe500_4000,
            0xe5c0_e000,
            0xe5c0_4000,
        ] {
            assert_eq!(decode(word), None);
        }
    }

    #[test]
    fn guest_quantity_tracks_narrowed_memory_not_source_lanes() {
        const ST1B_IMMEDIATE: u32 = 0xe400_e000;
        const ST1H_IMMEDIATE: u32 = 0xe480_e000;
        const ST1W_IMMEDIATE: u32 = 0xe540_e000;
        const DOUBLEWORD_SIZE: u32 = 3;
        const WORD_DOUBLEWORD_SELECTOR: u32 = 1;
        for (word, expected) in [
            (
                ST1B_IMMEDIATE | (DOUBLEWORD_SIZE << SIZE_SHIFT),
                ElementSize::Byte,
            ),
            (
                ST1H_IMMEDIATE | (DOUBLEWORD_SIZE << SIZE_SHIFT),
                ElementSize::Halfword,
            ),
            (
                ST1W_IMMEDIATE | (WORD_DOUBLEWORD_SELECTOR << SIZE_SHIFT),
                ElementSize::Word,
            ),
        ] {
            let operand = decode(word).unwrap().unwrap();
            let Operand::Store(store) = operand else {
                panic!("narrow store class");
            };
            assert_eq!(store.element, ElementSize::Doubleword);
            assert_eq!(
                guest_memory_quantity(&operand),
                GuestMemoryQuantity::Maximum(expected)
            );
        }
    }

    #[test]
    fn whole_bytes_and_ignored_hints_keep_source_access_checks() {
        for (word, quantity) in [
            (
                WHOLE_VECTOR_CLASS,
                GuestMemoryQuantity::Maximum(ElementSize::Byte),
            ),
            (
                WHOLE_PREDICATE_CLASS,
                GuestMemoryQuantity::Maximum(ElementSize::Byte),
            ),
            (PREFETCH_IMMEDIATE_CLASS, GuestMemoryQuantity::None),
            (PREFETCH_REGISTER_CLASS, GuestMemoryQuantity::None),
        ] {
            let operand = decode(word).unwrap().unwrap();
            assert_eq!(guest_memory_quantity(&operand), quantity);
            assert_eq!(
                execution_access_requirements(&operand),
                ScalableAccessRequirements::Known(Box::new([ScalableAccessCheck::SveEnabled]))
            );
        }
        for form in FORMS
            .iter()
            .filter(|form| form.memory_bytes == ElementSize::Quadword.bytes() as u8)
        {
            let operand = decode(form.value).unwrap().unwrap();
            assert_eq!(
                guest_memory_quantity(&operand),
                GuestMemoryQuantity::Maximum(ElementSize::Quadword)
            );
        }
    }
}
