use super::*;
use crate::aarch64::sve::prefix::PrefixRequirement;

#[test]
fn all_28_exact_june_logic_policies_match_canonical_word_adapters() {
    // Independent exact-June metadata, bound in logic28-facts.json.
    let facts = [
        (0x041a0000, true, true),   // and_z_p_zz_
        (0x05800000, true, false),  // and_z_zi_
        (0x04203000, false, false), // and_z_zz_
        (0x04603800, true, false),  // bcax_z_zzz_
        (0x041b0000, true, true),   // bic_z_p_zz_
        (0x04e03000, false, false), // bic_z_zz_
        (0x04603c00, true, false),  // bsl1n_z_zzz_
        (0x04a03c00, true, false),  // bsl2n_z_zzz_
        (0x04203c00, true, false),  // bsl_z_zzz_
        (0x041ba000, true, true),   // cnot_z_p_z_m
        (0x05100000, false, false), // cpy_z_o_i_
        (0x05104000, true, true),   // cpy_z_p_i_
        (0x0528a000, true, true),   // cpy_z_p_r_
        (0x05208000, true, true),   // cpy_z_p_v_
        (0x04203800, true, false),  // eor3_z_zzz_
        (0x04190000, true, true),   // eor_z_p_zz_
        (0x05400000, true, false),  // eor_z_zi_
        (0x04a03000, false, false), // eor_z_zz_
        (0x45009000, true, false),  // eorbt_z_zz_
        (0x45009400, true, false),  // eortb_z_zz_
        (0x04102000, false, false), // movprfx_z_p_z_
        (0x0420bc00, false, false), // movprfx_z_z_
        (0x04e03c00, true, false),  // nbsl_z_zzz_
        (0x041ea000, true, true),   // not_z_p_z_m
        (0x04180000, true, true),   // orr_z_p_zz_
        (0x05000000, true, false),  // orr_z_zi_
        (0x04603000, false, false), // orr_z_zz_
        (0x0520c000, false, false), // sel_z_p_zz_
    ];
    for (word, permitted, predicated) in facts {
        let operand = decode(word).unwrap().unwrap();
        let requirement = operand
            .prefix_requirement(word)
            .unwrap()
            .expect("all28 canonical forms reviewed");
        match requirement {
            PrefixRequirement::Forbidden => assert!(!permitted),
            PrefixRequirement::Vector {
                predicated: actual, ..
            } => {
                assert!(permitted);
                assert_eq!(actual.is_some(), predicated);
            }
        }
    }
}

#[test]
fn other_source_masks_use_shared_vector_storage_and_exclude_only_implicit_destination() {
    let destination = 3;
    let vector_source = 3 << SOURCE_SHIFT;
    for (opcode, expected) in [
        (COPY_REGISTER, 0),
        (COPY_SCALAR_VECTOR, 1_u32 << destination),
        (AND_PREDICATED, 1_u32 << destination),
        (NOT_PREDICATED, 1_u32 << destination),
    ] {
        let word = opcode | vector_source | destination;
        let operand = decode(word).unwrap().unwrap();
        let PrefixRequirement::Vector {
            other_vector_sources,
            ..
        } = operand
            .prefix_requirement(word)
            .unwrap()
            .expect("reviewed source form")
        else {
            panic!("reviewed source form forbidden")
        };
        assert_eq!(other_vector_sources, expected);
    }
    for opcode in [BCAX, EORBT] {
        let word = opcode | (5 << SOURCE_SHIFT) | (7 << RIGHT_SHIFT) | destination;
        let operand = decode(word).unwrap().unwrap();
        let PrefixRequirement::Vector {
            other_vector_sources,
            ..
        } = operand
            .prefix_requirement(word)
            .unwrap()
            .expect("reviewed source form")
        else {
            panic!("reviewed source form forbidden")
        };
        assert_eq!(other_vector_sources, (1_u32 << 5) | (1_u32 << 7));
    }
}

#[test]
fn source_or_normalized_operand_mismatch_cannot_authorize_a_follower() {
    let word = AND_PREDICATED | (2 << SOURCE_SHIFT);
    let operand = decode(word).unwrap().unwrap();
    let mut forged = operand;
    forged.destination = 1;
    assert!(forged.prefix_requirement(word).is_err());
    assert!(operand.prefix_requirement(AND_REGISTER).is_err());
}
