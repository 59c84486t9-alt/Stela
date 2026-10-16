use super::*;

#[test]
fn lookup_groups_and_segments_do_not_wrap() {
    for encoding in LOOKUPS {
        for size in 0..4 {
            let element_bits = BYTE_BITS << size;
            let allocated = element_bits <= if encoding.stride == 1 { 32 } else { 16 }
                && !(encoding.index_bits == 4 && encoding.count == 4 && element_bits < 16);
            for immediate in 0..=encoding.immediate_mask {
                for source in 0..=REGISTER_MASK {
                    for destination in 0..=REGISTER_MASK {
                        let destination_field = if encoding.stride == 1 {
                            destination & !(u32::from(encoding.count) - 1)
                        } else {
                            destination & (u32::from(encoding.stride) - 1) | destination & 16
                        };
                        let word = encoding.value
                            | (size << LOOKUP_SIZE_SHIFT)
                            | (immediate << encoding.immediate_shift)
                            | (source << SOURCE_SHIFT)
                            | destination_field;
                        let operand = decode(word);
                        if !allocated {
                            assert!(operand.is_none(), "{word:08x}");
                            continue;
                        }
                        let operand = operand.unwrap();
                        assert_eq!(operand.canonical_id, encoding.canonical_id);
                        assert_eq!(operand.element.bits(), usize::from(element_bits));
                        assert_eq!(operand.destination.first, destination_field as u8);
                        assert_eq!(operand.destination.count, encoding.count);
                        assert_eq!(operand.destination.stride, encoding.stride);
                        assert!(
                            operand.destination.register(encoding.count - 1)
                                < VECTOR_REGISTER_COUNT
                        );
                        assert_eq!(
                            operand.kind,
                            Kind::Lookup {
                                source: source as u8,
                                index_bits: encoding.index_bits,
                                segment: immediate as u8,
                            }
                        );
                        assert_eq!(
                            operand.feature,
                            if encoding.stride == 1 {
                                Feature::Sme2
                            } else {
                                Feature::Sme2p1
                            }
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn select_preserves_aligned_groups_and_counter_predicate_roles() {
    for (base, count) in [(0xc120_8000, 2), (0xc121_8000, 4)] {
        for size in 0..4 {
            for destination in (0..VECTOR_REGISTER_COUNT).step_by(count as usize) {
                for source in (0..VECTOR_REGISTER_COUNT).step_by(count as usize) {
                    for predicate in 0..8 {
                        let word = base
                            | (size << GROUP_SIZE_SHIFT)
                            | u32::from(destination)
                            | (u32::from(source) << SOURCE_SHIFT)
                            | (u32::from(source) << RIGHT_SHIFT)
                            | (predicate << PREDICATE_SHIFT);
                        let operand = decode(word).unwrap();
                        assert_eq!(operand.destination, VectorGroup::new(destination, count, 1));
                        assert_eq!(
                            operand.kind,
                            Kind::Select {
                                left: VectorGroup::new(source, count, 1),
                                right: VectorGroup::new(source, count, 1),
                                predicate: predicate as u8 + COUNTER_PREDICATE_BASE,
                            }
                        );
                        assert_eq!(operand.element.bits(), usize::from(BYTE_BITS << size));
                    }
                }
            }
        }
    }
}

#[test]
fn unpack_rejects_byte_destinations_and_reads_half_as_many_registers() {
    for (base, count) in [(0xc125_e000, 2), (0xc135_e000, 4)] {
        for signed in [true, false] {
            for size in 0..4 {
                for source in (0..VECTOR_REGISTER_COUNT).step_by((count / 2) as usize) {
                    let word = base
                        | u32::from(!signed)
                        | (size << GROUP_SIZE_SHIFT)
                        | (u32::from(source) << SOURCE_SHIFT)
                        | u32::from(VECTOR_REGISTER_COUNT - count);
                    let decoded = decode(word);
                    if size == 0 {
                        assert!(decoded.is_none());
                    } else {
                        let operand = decoded.unwrap();
                        assert_eq!(
                            operand.kind,
                            Kind::Unpack {
                                source: VectorGroup::new(source, count / 2, 1),
                                signed,
                            }
                        );
                        assert_eq!(
                            operand.destination.register(count - 1),
                            VECTOR_REGISTER_COUNT - 1
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn permutation_widths_define_current_and_maximum_svl_guards() {
    for (base, count, wide, unzip) in [
        (0xc136_e002, 4, false, true),
        (0xc137_e002, 4, true, true),
        (0xc120_d001, 2, false, true),
        (0xc120_d401, 2, true, true),
        (0xc136_e000, 4, false, false),
        (0xc137_e000, 4, true, false),
        (0xc120_d000, 2, false, false),
        (0xc120_d400, 2, true, false),
    ] {
        for size in 0..if wide { 1 } else { 4 } {
            let word = base
                | (size << GROUP_SIZE_SHIFT)
                | (28 << SOURCE_SHIFT)
                | if count == 2 { 31 << RIGHT_SHIFT } else { 0 }
                | u32::from(VECTOR_REGISTER_COUNT - count);
            let operand = decode(word).unwrap();
            assert_eq!(
                operand.element.bits(),
                usize::from(if wide {
                    QUADWORD_BITS
                } else {
                    BYTE_BITS << size
                })
            );
            assert_eq!(
                operand.minimum_svl_bits(),
                (operand.element.bits() * usize::from(count)).max(usize::from(QUADWORD_BITS))
            );
            assert_eq!(
                operand.kind,
                Kind::Permute {
                    sources: if count == 2 {
                        PermuteSources::Pair {
                            left: 28,
                            right: 31,
                        }
                    } else {
                        PermuteSources::Quad { first: 28 }
                    },
                    unzip,
                }
            );
        }
    }
}

#[test]
fn unrelated_and_reserved_encodings_are_not_accepted() {
    for word in [
        0,
        0xffff_ffff,
        0xd65f_03c0,
        0xc08c_7000,
        0xc09a_6000,
        0xc08a_8000,
        0xc09a_8000,
        0xc125_e000,
        0xc135_e001,
    ] {
        assert_eq!(decode(word), None, "{word:08x}");
    }
}
