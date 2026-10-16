use super::*;
use crate::aarch64::Register;
use alloc::boxed::Box;

#[test]
fn every_store_class_preserves_registers_and_address_scale() {
    let mut forms = FORMS.to_vec();
    for size in 0..=SIZE_MASK {
        for tuple_index in 0..=TUPLE_COUNT_MASK {
            for class in [GROUPED_IMMEDIATE_CLASS, GROUPED_REGISTER_CLASS] {
                let word = class | (size << MEMORY_SIZE_SHIFT) | (tuple_index << TUPLE_COUNT_SHIFT);
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
                        assert_eq!(result, Err(()));
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
        assert_eq!(decode(class), Some(Err(())));
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
            assert_eq!(decode(reserved), Some(Err(())));
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
fn whole_bytes_and_ignored_hints_retain_source_access_checks() {
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
