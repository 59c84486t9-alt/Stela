use super::*;
#[test]
fn all_forms_all_operand_fields_and_aliases() {
    for form in &FORMS {
        for size in 0..=ELEMENT_SIZE_MASK {
            for first in 0..=SCALAR_REGISTER_MASK {
                for limit in 0..=SCALAR_REGISTER_MASK {
                    let word = form.class
                        | (size << ELEMENT_SIZE_SHIFT)
                        | (first << SOURCE_N_SHIFT)
                        | (limit << SOURCE_M_SHIFT);
                    let op = decode(word).unwrap().unwrap();
                    assert_eq!(op.comparison, form.comparison);
                    assert_eq!(op.first, scalar_register(first));
                    assert_eq!(op.limit, scalar_register(limit));
                    for bit in 0..u32::BITS {
                        if form.mask & (1 << bit) != 0 {
                            let changed = word ^ (1 << bit);
                            if let Some(Ok(changed_op)) = decode(changed) {
                                // A changed class may select another
                                // WHILE form.
                                assert!(
                                    FORMS.iter().any(
                                        |candidate| changed & candidate.mask == candidate.class
                                    )
                                );
                                assert_ne!(changed_op, op);
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn representation_fields_and_scalar_width_are_distinct() {
    for form in &FORMS {
        let op = decode(
            form.class
                | match form.representation {
                    Representation::Predicate => PREDICATE_MASK,
                    Representation::Pair => PAIR_DESTINATION_MASK,
                    Representation::Counter => COUNTER_DESTINATION_MASK,
                },
        )
        .unwrap()
        .unwrap();
        match form.representation {
            Representation::Predicate => {
                assert_eq!(op.destination, Destination::Predicate(15));
                if !matches!(
                    op.comparison,
                    Comparison::ReadWriteDistance | Comparison::WriteReadDistance
                ) {
                    assert_eq!(op.width, Width::W32);
                    assert_eq!(
                        decode(form.class | (1 << SCALAR_WIDTH_SHIFT))
                            .unwrap()
                            .unwrap()
                            .width,
                        Width::X64
                    );
                }
            }
            Representation::Pair => assert_eq!(op.destination, Destination::Pair(14)),
            Representation::Counter => {
                assert_eq!(
                    op.destination,
                    Destination::Counter {
                        register: 15,
                        vectors: 2
                    }
                );
                assert_eq!(
                    decode(form.class | (1 << COUNTER_WIDTH_SHIFT))
                        .unwrap()
                        .unwrap()
                        .destination,
                    Destination::Counter {
                        register: 8,
                        vectors: 4
                    }
                );
            }
        }
    }
}
#[test]
fn unrelated_instruction_is_declined() {
    assert_eq!(decode(0xd503201f), None);
}
