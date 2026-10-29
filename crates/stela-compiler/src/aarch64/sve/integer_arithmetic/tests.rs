use super::*;

mod prefix_requirement {
    use super::*;
    use crate::aarch64::sve::prefix::{self, DecodedPrefix, PrefixRequirement, PrefixViolation};

    fn requirement(word: u32) -> PrefixRequirement {
        decode(word)
            .unwrap()
            .unwrap()
            .prefix_requirement(word)
            .unwrap()
            .unwrap()
    }

    fn unpredicated(destination: u8) -> DecodedPrefix {
        DecodedPrefix {
            destination,
            source: 31,
            predication: Predication::Unpredicated,
            element: None,
        }
    }

    #[test]
    fn exact_june_48_forms_match_policy_and_explicit_source_roles() {
        let facts = [
            (0x0496a8a3, true, true, 0x00000020),   // abs_z_p_z_m
            (0x4507d0a3, true, false, 0x000000a0),  // adclb_z_zzz_
            (0x4507d4a3, true, false, 0x000000a0),  // adclt_z_zzz_
            (0x048008e3, true, true, 0x00000080),   // add_z_p_zz_
            (0x25a0c063, true, false, 0x00000000),  // add_z_zi_
            (0x04a700a3, false, false, 0x00000000), // add_z_zz_
            (0x4580d8e3, true, false, 0x00000080),  // cadd_z_zz_
            (0x0497a8a3, true, true, 0x00000020),   // neg_z_p_z_m
            (0x458700a3, false, false, 0x00000000), // saddlb_z_zz_
            (0x458780a3, false, false, 0x00000000), // saddlbt_z_zz_
            (0x458704a3, false, false, 0x00000000), // saddlt_z_zz_
            (0x458740a3, false, false, 0x00000000), // saddwb_z_zz_
            (0x458744a3, false, false, 0x00000000), // saddwt_z_zz_
            (0x4587d0a3, true, false, 0x000000a0),  // sbclb_z_zzz_
            (0x4587d4a3, true, false, 0x000000a0),  // sbclt_z_zzz_
            (0x4487c0a3, true, false, 0x000000a0),  // sclamp_z_zz_
            (0x049408e3, true, true, 0x00000080),   // sdiv_z_p_zz_
            (0x049608e3, true, true, 0x00000080),   // sdivr_z_p_zz_
            (0x048808e3, true, true, 0x00000080),   // smax_z_p_zz_
            (0x25a8c063, true, false, 0x00000000),  // smax_z_zi_
            (0x048a08e3, true, true, 0x00000080),   // smin_z_p_zz_
            (0x25aac063, true, false, 0x00000000),  // smin_z_zi_
            (0x458710a3, false, false, 0x00000000), // ssublb_z_zz_
            (0x458788a3, false, false, 0x00000000), // ssublbt_z_zz_
            (0x458714a3, false, false, 0x00000000), // ssublt_z_zz_
            (0x45878ca3, false, false, 0x00000000), // ssubltb_z_zz_
            (0x458750a3, false, false, 0x00000000), // ssubwb_z_zz_
            (0x458754a3, false, false, 0x00000000), // ssubwt_z_zz_
            (0x048108e3, true, true, 0x00000080),   // sub_z_p_zz_
            (0x25a1c063, true, false, 0x00000000),  // sub_z_zi_
            (0x04a704a3, false, false, 0x00000000), // sub_z_zz_
            (0x048308e3, true, true, 0x00000080),   // subr_z_p_zz_
            (0x25a3c063, true, false, 0x00000000),  // subr_z_zi_
            (0x458708a3, false, false, 0x00000000), // uaddlb_z_zz_
            (0x45870ca3, false, false, 0x00000000), // uaddlt_z_zz_
            (0x458748a3, false, false, 0x00000000), // uaddwb_z_zz_
            (0x45874ca3, false, false, 0x00000000), // uaddwt_z_zz_
            (0x4487c4a3, true, false, 0x000000a0),  // uclamp_z_zz_
            (0x049508e3, true, true, 0x00000080),   // udiv_z_p_zz_
            (0x049708e3, true, true, 0x00000080),   // udivr_z_p_zz_
            (0x048908e3, true, true, 0x00000080),   // umax_z_p_zz_
            (0x25a9c063, true, false, 0x00000000),  // umax_z_zi_
            (0x048b08e3, true, true, 0x00000080),   // umin_z_p_zz_
            (0x25abc063, true, false, 0x00000000),  // umin_z_zi_
            (0x458718a3, false, false, 0x00000000), // usublb_z_zz_
            (0x45871ca3, false, false, 0x00000000), // usublt_z_zz_
            (0x458758a3, false, false, 0x00000000), // usubwb_z_zz_
            (0x45875ca3, false, false, 0x00000000), // usubwt_z_zz_
        ];
        for (word, allowed, permits_predicated, source_mask) in facts {
            let policy = requirement(word);
            if !allowed {
                assert_eq!(policy, PrefixRequirement::Forbidden, "{word:08x}");
                assert_eq!(
                    prefix::validate(unpredicated(3), policy),
                    Err(PrefixViolation::FollowerNotAuthorized)
                );
                continue;
            }
            let PrefixRequirement::Vector {
                destination,
                predicated,
                other_vector_sources,
            } = policy
            else {
                panic!("{word:08x}")
            };
            assert_eq!(destination, 3);
            assert_eq!(other_vector_sources, source_mask, "{word:08x}");
            assert_eq!(predicated.is_some(), permits_predicated, "{word:08x}");
            assert_eq!(prefix::validate(unpredicated(3), policy), Ok(()));
            if let Some(required) = predicated {
                assert_eq!(required.predicate, 2);
                assert_eq!(required.element, ElementSize::Word);
                for predication in [Predication::Merging(2), Predication::Zeroing(2)] {
                    let pref = DecodedPrefix {
                        predication,
                        element: Some(ElementSize::Word),
                        ..unpredicated(3)
                    };
                    assert_eq!(prefix::validate(pref, policy), Ok(()));
                    assert_eq!(
                        prefix::validate(
                            DecodedPrefix {
                                predication: Predication::Merging(1),
                                ..pref
                            },
                            policy
                        ),
                        Err(PrefixViolation::PredicateMismatch)
                    );
                    assert_eq!(
                        prefix::validate(
                            DecodedPrefix {
                                element: Some(ElementSize::Doubleword),
                                ..pref
                            },
                            policy
                        ),
                        Err(PrefixViolation::ElementMismatch)
                    );
                }
            } else {
                let pref = DecodedPrefix {
                    predication: Predication::Zeroing(2),
                    element: Some(ElementSize::Word),
                    ..unpredicated(3)
                };
                assert_eq!(
                    prefix::validate(pref, policy),
                    Err(PrefixViolation::PredicatedPrefixForbidden)
                );
            }
        }
    }

    #[test]
    fn all_predicates_sizes_and_aliases_use_actual_shared_validator() {
        for opcode in [
            ABS_Z_P_Z_M,
            NEG_Z_P_Z_M,
            ADD_Z_P_ZZ,
            SUB_Z_P_ZZ,
            SUBR_Z_P_ZZ,
            SDIV_Z_P_ZZ,
            SDIVR_Z_P_ZZ,
            UDIV_Z_P_ZZ,
            UDIVR_Z_P_ZZ,
            SMIN_Z_P_ZZ,
            UMIN_Z_P_ZZ,
            SMAX_Z_P_ZZ,
            UMAX_Z_P_ZZ,
        ] {
            for size in 0..=SIZE_MASK {
                for predicate in 0..=PREDICATE_MASK {
                    for destination in [0, 3, 31] {
                        for source in [0, 3, 31] {
                            let word = opcode
                                | (size << SIZE_SHIFT)
                                | (predicate << PREDICATE_SHIFT)
                                | (source << SOURCE_SHIFT)
                                | destination;
                            let Some(Ok(operand)) = decode(word) else {
                                continue;
                            };
                            let policy = operand.prefix_requirement(word).unwrap().unwrap();
                            let pref = DecodedPrefix {
                                destination: destination as u8,
                                source: 31,
                                predication: Predication::Zeroing(predicate as u8),
                                element: Some(operand.element_size),
                            };
                            assert_eq!(
                                prefix::validate(pref, policy),
                                if destination == source {
                                    Err(PrefixViolation::OtherSourceAlias)
                                } else {
                                    Ok(())
                                }
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn both_explicit_sources_and_single_sources_reject_destination_alias() {
        for opcode in [
            ADCLB_Z_ZZZ,
            ADCLT_Z_ZZZ,
            SBCLB_Z_ZZZ,
            SBCLT_Z_ZZZ,
            SCLAMP_Z_ZZ,
            UCLAMP_Z_ZZ,
        ] {
            for destination in [0, 3, 31] {
                for (left, right) in [(destination, 7), (5, destination), (5, 7)] {
                    let word =
                        opcode | (left << SOURCE_SHIFT) | (right << RIGHT_SHIFT) | destination;
                    let policy = requirement(word);
                    assert_eq!(
                        prefix::validate(unpredicated(destination as u8), policy),
                        if left == destination || right == destination {
                            Err(PrefixViolation::OtherSourceAlias)
                        } else {
                            Ok(())
                        }
                    );
                }
            }
        }
        for rotation in [0, ROTATION_FLAG] {
            for destination in [0, 3, 31] {
                let word = CADD_Z_ZZ | rotation | (destination << SOURCE_SHIFT) | destination;
                assert_eq!(
                    prefix::validate(unpredicated(destination as u8), requirement(word)),
                    Err(PrefixViolation::OtherSourceAlias)
                );
            }
        }
    }

    #[test]
    fn immediate_numbers_do_not_create_vector_sources_or_implicit_destination_aliases() {
        for opcode in [
            ADD_Z_ZI, SUB_Z_ZI, SUBR_Z_ZI, SMIN_Z_ZI, UMIN_Z_ZI, SMAX_Z_ZI, UMAX_Z_ZI,
        ] {
            for destination in [0, 3, 31] {
                let word = opcode | (destination << SOURCE_SHIFT) | destination;
                assert_eq!(
                    prefix::validate(unpredicated(destination as u8), requirement(word)),
                    Ok(())
                );
                let PrefixRequirement::Vector {
                    other_vector_sources,
                    ..
                } = requirement(word)
                else {
                    panic!()
                };
                assert_eq!(other_vector_sources, 0);
            }
        }
        // This family has no GPR operands. The copied shared validator's
        // same_numbered_gpr_is_excluded_by_the_family_source_mask test covers
        // the shared GPR-vs-V/Z contract without inventing a family GPR form.
    }

    #[test]
    fn decoded_self_mismatch_reserved_words_and_constructive_identity_stay_explicit() {
        let word = ADD_Z_P_ZZ | (5 << SOURCE_SHIFT) | 3;
        let operand = decode(word).unwrap().unwrap();
        let mut forged = operand;
        forged.destination = 32;
        assert_eq!(forged.prefix_requirement(word), Err(Unsupported));
        let mut forged = operand;
        forged.element_size = ElementSize::Doubleword;
        assert_eq!(forged.prefix_requirement(word), Err(Unsupported));
        let mut forged = operand;
        forged.predication = Predication::Merging(7);
        assert_eq!(forged.prefix_requirement(word), Err(Unsupported));
        let mut forged = operand;
        forged.kind = Kind::Binary {
            operation: Binary::Add,
            left: 3,
            right: Source::Vector(3),
        };
        assert_eq!(forged.prefix_requirement(word), Err(Unsupported));
        assert_eq!(operand.prefix_requirement(0), Err(Unsupported));
        assert_eq!(operand.prefix_requirement(SADDLB_Z_ZZ), Err(Unsupported));
        assert_eq!(operand.prefix_requirement(SDIV_Z_P_ZZ), Err(Unsupported));
        assert_eq!(
            operand.prefix_requirement(ADD_Z_ZI | IMMEDIATE_SHIFT_FLAG),
            Err(Unsupported)
        );
        // The same binary kind cannot authorize a constructive ADD; its exact
        // word and unpredicated role must remain distinct from the merging form.
        let constructive = ADD_Z_ZZ | (3 << SOURCE_SHIFT) | (5 << RIGHT_SHIFT) | 3;
        let constructive_operand = decode(constructive).unwrap().unwrap();
        assert_eq!(constructive_operand.kind, operand.kind);
        assert_eq!(operand.prefix_requirement(constructive), Err(Unsupported));
        assert_eq!(
            constructive_operand.prefix_requirement(constructive),
            Ok(Some(PrefixRequirement::Forbidden))
        );
        assert_eq!(
            prefix::validate(unpredicated(2), requirement(word)),
            Err(PrefixViolation::DestinationMismatch)
        );
    }
}

#[test]
fn canonical_forms_validate_widths_predicates_and_register_roles() {
    let forms = [
        (ABS_Z_P_Z_M, true, false, false, false),
        (ADCLB_Z_ZZZ, false, true, false, false),
        (ADCLT_Z_ZZZ, false, true, false, false),
        (ADD_Z_P_ZZ, true, false, false, false),
        (ADD_Z_ZI, false, false, false, false),
        (ADD_Z_ZZ, false, false, false, false),
        (CADD_Z_ZZ, false, false, false, false),
        (NEG_Z_P_Z_M, true, false, false, false),
        (SADDLB_Z_ZZ, false, false, true, false),
        (SADDLBT_Z_ZZ, false, false, true, false),
        (SADDLT_Z_ZZ, false, false, true, false),
        (SADDWB_Z_ZZ, false, false, true, false),
        (SADDWT_Z_ZZ, false, false, true, false),
        (SBCLB_Z_ZZZ, false, true, false, false),
        (SBCLT_Z_ZZZ, false, true, false, false),
        (SCLAMP_Z_ZZ, false, false, false, false),
        (SDIV_Z_P_ZZ, true, false, false, true),
        (SDIVR_Z_P_ZZ, true, false, false, true),
        (SMAX_Z_P_ZZ, true, false, false, false),
        (SMAX_Z_ZI, false, false, false, false),
        (SMIN_Z_P_ZZ, true, false, false, false),
        (SMIN_Z_ZI, false, false, false, false),
        (SSUBLB_Z_ZZ, false, false, true, false),
        (SSUBLBT_Z_ZZ, false, false, true, false),
        (SSUBLT_Z_ZZ, false, false, true, false),
        (SSUBLTB_Z_ZZ, false, false, true, false),
        (SSUBWB_Z_ZZ, false, false, true, false),
        (SSUBWT_Z_ZZ, false, false, true, false),
        (SUB_Z_P_ZZ, true, false, false, false),
        (SUB_Z_ZI, false, false, false, false),
        (SUB_Z_ZZ, false, false, false, false),
        (SUBR_Z_P_ZZ, true, false, false, false),
        (SUBR_Z_ZI, false, false, false, false),
        (UADDLB_Z_ZZ, false, false, true, false),
        (UADDLT_Z_ZZ, false, false, true, false),
        (UADDWB_Z_ZZ, false, false, true, false),
        (UADDWT_Z_ZZ, false, false, true, false),
        (UCLAMP_Z_ZZ, false, false, false, false),
        (UDIV_Z_P_ZZ, true, false, false, true),
        (UDIVR_Z_P_ZZ, true, false, false, true),
        (UMAX_Z_P_ZZ, true, false, false, false),
        (UMAX_Z_ZI, false, false, false, false),
        (UMIN_Z_P_ZZ, true, false, false, false),
        (UMIN_Z_ZI, false, false, false, false),
        (USUBLB_Z_ZZ, false, false, true, false),
        (USUBLT_Z_ZZ, false, false, true, false),
        (USUBWB_Z_ZZ, false, false, true, false),
        (USUBWT_Z_ZZ, false, false, true, false),
    ];
    for (opcode, predicated, carry, widening, division) in forms {
        let maximum_size = if carry { 1 } else { SIZE_MASK };
        for size in 0..=maximum_size {
            for destination in 0..=REGISTER_MASK {
                let word = opcode | (size << SIZE_SHIFT) | destination;
                let result = decode(word).unwrap();
                if (widening && size == 0) || (division && size < 2) {
                    assert_eq!(result, Err(Unsupported));
                    continue;
                }
                let operand = result.unwrap();
                assert_eq!(operand.destination, destination as u8);
                assert_eq!(
                    operand.element_size.bytes(),
                    if carry { 4 << size } else { 1 << size }
                );
                assert_eq!(
                    operand.predication,
                    if predicated {
                        Predication::Merging(0)
                    } else {
                        Predication::Unpredicated
                    }
                );
            }
        }
    }
}

#[test]
fn immediate_byte_shift_is_reserved_and_signed_minmax_extend_imm8() {
    for opcode in [ADD_Z_ZI, SUB_Z_ZI, SUBR_Z_ZI] {
        assert_eq!(
            decode(opcode | IMMEDIATE_SHIFT_FLAG),
            Some(Err(Unsupported))
        );
        assert!(
            decode(opcode | (1 << SIZE_SHIFT) | IMMEDIATE_SHIFT_FLAG)
                .unwrap()
                .is_ok()
        );
    }
    for opcode in [SMIN_Z_ZI, SMAX_Z_ZI] {
        let operand = decode(opcode | (IMMEDIATE_MASK << SOURCE_SHIFT))
            .unwrap()
            .unwrap();
        assert!(matches!(
            operand.kind,
            Kind::Binary {
                right: Source::Immediate(-1),
                ..
            }
        ));
    }
}

#[test]
fn aliases_include_z31_and_destructive_sources_keep_roles() {
    for destination in 0..=REGISTER_MASK {
        for source in 0..=REGISTER_MASK {
            let operand = decode(ADD_Z_P_ZZ | (source << SOURCE_SHIFT) | destination)
                .unwrap()
                .unwrap();
            assert_eq!(
                operand.kind,
                Kind::Binary {
                    operation: Binary::Add,
                    left: destination as u8,
                    right: Source::Vector(source as u8)
                }
            );
            let operand = decode(
                ADCLT_Z_ZZZ
                    | (source << SOURCE_SHIFT)
                    | (REGISTER_MASK << RIGHT_SHIFT)
                    | destination,
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                operand.kind,
                Kind::Carry {
                    source: source as u8,
                    carry: REGISTER_MASK as u8,
                    subtract: false,
                    top: true
                }
            );
        }
    }
}
