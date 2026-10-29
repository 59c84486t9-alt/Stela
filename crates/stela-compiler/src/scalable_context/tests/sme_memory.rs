//! SME memory dispatch, guest features and memory-service requirements.
use super::*;
use crate::aarch64::sme::memory::{self as sme_memory, Operand as SmeMemoryOperand};
use alloc::vec;
use alloc::vec::Vec;

const RET_X30: u32 = 0xd65f_03c0;
const NOP: u32 = 0xd503_201f;
const GUEST_BASE: GuestAddress = GuestAddress(0x1000);
const BASE_REGISTER_SHIFT: u32 = 5;
const BASE_REGISTER_MASK: u32 = 31 << BASE_REGISTER_SHIFT;
const WORDS: [u32; 78] = [
    0xa14000a0, // ld1b_mzx_p_bi_2x8
    0xa14080a0, // ld1b_mzx_p_bi_4x4
    0xa10000a0, // ld1b_mzx_p_br_2x8
    0xa10080a0, // ld1b_mzx_p_br_4x4
    0xe00000a0, // ld1b_za_p_rrr_
    0xa14060a0, // ld1d_mzx_p_bi_2x8
    0xa140e0a0, // ld1d_mzx_p_bi_4x4
    0xa10060a0, // ld1d_mzx_p_br_2x8
    0xa100e0a0, // ld1d_mzx_p_br_4x4
    0xe0c000a0, // ld1d_za_p_rrr_
    0xa14020a0, // ld1h_mzx_p_bi_2x8
    0xa140a0a0, // ld1h_mzx_p_bi_4x4
    0xa10020a0, // ld1h_mzx_p_br_2x8
    0xa100a0a0, // ld1h_mzx_p_br_4x4
    0xe04000a0, // ld1h_za_p_rrr_
    0xe1c000a0, // ld1q_za_p_rrr_
    0xa14040a0, // ld1w_mzx_p_bi_2x8
    0xa140c0a0, // ld1w_mzx_p_bi_4x4
    0xa10040a0, // ld1w_mzx_p_br_2x8
    0xa100c0a0, // ld1w_mzx_p_br_4x4
    0xe08000a0, // ld1w_za_p_rrr_
    0xa14000a8, // ldnt1b_mzx_p_bi_2x8
    0xa14080a8, // ldnt1b_mzx_p_bi_4x4
    0xa10000a8, // ldnt1b_mzx_p_br_2x8
    0xa10080a8, // ldnt1b_mzx_p_br_4x4
    0xa14060a8, // ldnt1d_mzx_p_bi_2x8
    0xa140e0a8, // ldnt1d_mzx_p_bi_4x4
    0xa10060a8, // ldnt1d_mzx_p_br_2x8
    0xa100e0a8, // ldnt1d_mzx_p_br_4x4
    0xa14020a8, // ldnt1h_mzx_p_bi_2x8
    0xa140a0a8, // ldnt1h_mzx_p_bi_4x4
    0xa10020a8, // ldnt1h_mzx_p_br_2x8
    0xa100a0a8, // ldnt1h_mzx_p_br_4x4
    0xa14040a8, // ldnt1w_mzx_p_bi_2x8
    0xa140c0a8, // ldnt1w_mzx_p_bi_4x4
    0xa10040a8, // ldnt1w_mzx_p_br_2x8
    0xa100c0a8, // ldnt1w_mzx_p_br_4x4
    0xe10000a0, // ldr_za_ri_
    0xe11f80a0, // ldr_zt_br_
    0xa16000a0, // st1b_mzx_p_bi_2x8
    0xa16080a0, // st1b_mzx_p_bi_4x4
    0xa12000a0, // st1b_mzx_p_br_2x8
    0xa12080a0, // st1b_mzx_p_br_4x4
    0xe02000a0, // st1b_za_p_rrr_
    0xa16060a0, // st1d_mzx_p_bi_2x8
    0xa160e0a0, // st1d_mzx_p_bi_4x4
    0xa12060a0, // st1d_mzx_p_br_2x8
    0xa120e0a0, // st1d_mzx_p_br_4x4
    0xe0e000a0, // st1d_za_p_rrr_
    0xa16020a0, // st1h_mzx_p_bi_2x8
    0xa160a0a0, // st1h_mzx_p_bi_4x4
    0xa12020a0, // st1h_mzx_p_br_2x8
    0xa120a0a0, // st1h_mzx_p_br_4x4
    0xe06000a0, // st1h_za_p_rrr_
    0xe1e000a0, // st1q_za_p_rrr_
    0xa16040a0, // st1w_mzx_p_bi_2x8
    0xa160c0a0, // st1w_mzx_p_bi_4x4
    0xa12040a0, // st1w_mzx_p_br_2x8
    0xa120c0a0, // st1w_mzx_p_br_4x4
    0xe0a000a0, // st1w_za_p_rrr_
    0xa16000a8, // stnt1b_mzx_p_bi_2x8
    0xa16080a8, // stnt1b_mzx_p_bi_4x4
    0xa12000a8, // stnt1b_mzx_p_br_2x8
    0xa12080a8, // stnt1b_mzx_p_br_4x4
    0xa16060a8, // stnt1d_mzx_p_bi_2x8
    0xa160e0a8, // stnt1d_mzx_p_bi_4x4
    0xa12060a8, // stnt1d_mzx_p_br_2x8
    0xa120e0a8, // stnt1d_mzx_p_br_4x4
    0xa16020a8, // stnt1h_mzx_p_bi_2x8
    0xa160a0a8, // stnt1h_mzx_p_bi_4x4
    0xa12020a8, // stnt1h_mzx_p_br_2x8
    0xa120a0a8, // stnt1h_mzx_p_br_4x4
    0xa16040a8, // stnt1w_mzx_p_bi_2x8
    0xa160c0a8, // stnt1w_mzx_p_bi_4x4
    0xa12040a8, // stnt1w_mzx_p_br_2x8
    0xa120c0a8, // stnt1w_mzx_p_br_4x4
    0xe12000a0, // str_za_ri_
    0xe13f80a0, // str_zt_br_
];

fn source(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn declared_profile(streaming: bool, za: bool, sme2: bool, zt0: bool) -> ScalableProfile {
    let length = VectorLength::from_bytes(16).unwrap();
    let features = if sme2 {
        ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2)
    } else {
        ScalableFeatures::of(ScalableFeature::Sme)
    };
    ScalableProfile::new_with_features(
        length,
        ScalableMode::new(streaming, za),
        features,
        ScalableControls::new(length, zt0),
    )
    .unwrap()
}

fn target() -> TargetCpu {
    TargetCpu::AtomicLoad16.with_cx16()
}

fn assert_declined(word: u32, profile: ScalableProfile, target: TargetCpu) {
    let bytes = source(&[word, RET_X30]);
    let scan =
        crate::testing::context_leaf_memory(&bytes, GUEST_BASE, profile, target).unwrap_err();
    let compile = crate::testing::context_leaf(&bytes, GUEST_BASE, profile, target).unwrap_err();
    assert_eq!(scan, compile);
}

#[test]
fn every_form_dispatches_exact_body_and_source_map() {
    for word in WORDS {
        let operand = sme_memory::decode(word).unwrap();
        assert_eq!(
            crate::aarch64::sme::decode(word),
            Some(Ok(crate::aarch64::sme::Operand::Memory(operand)))
        );
        let profile = declared_profile(true, true, true, true);
        let bytes = source(&[word, RET_X30]);
        let native = crate::testing::context_leaf(&bytes, GUEST_BASE, profile, target()).unwrap();
        let mut expected = Code::new();
        x86_64::sme::memory::emit(
            &mut expected,
            &operand,
            profile.vector_length(),
            target(),
            GUEST_BASE.0,
        )
        .unwrap();
        assert_eq!(
            &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
            context_wrapper()
        );
        assert_eq!(
            native.source_map,
            [
                (GUEST_BASE, CONTEXT_WRAPPER_BYTES),
                (
                    GuestAddress(GUEST_BASE.0 + INSTRUCTION_BYTES as u64),
                    CONTEXT_WRAPPER_BYTES + expected.len()
                )
            ]
        );
        assert_eq!(
            &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
            expected
        );
        assert_eq!(&native.x86_64_code[native.source_map[1].1..], [RET]);
        assert_eq!(
            crate::testing::context_leaf_memory(&bytes, GUEST_BASE, profile, target()).unwrap(),
            x86_64::sme::memory::requirements(&operand)
        );
    }
}

#[test]
fn mode_feature_and_ezt0_checks_follow_each_memory_class() {
    for word in WORDS {
        match sme_memory::decode(word).unwrap() {
            SmeMemoryOperand::Vectors(_) => {
                assert_declined(word, declared_profile(false, false, true, false), target());
                assert_declined(word, declared_profile(true, true, false, false), target());
                assert!(
                    crate::testing::context_leaf(
                        &source(&[word, RET_X30]),
                        GUEST_BASE,
                        declared_profile(true, false, true, false),
                        target()
                    )
                    .is_ok()
                );
            }
            SmeMemoryOperand::Tile(_) => {
                assert_declined(word, declared_profile(false, true, true, false), target());
                assert_declined(word, declared_profile(true, false, true, false), target());
                assert!(
                    crate::testing::context_leaf(
                        &source(&[word, RET_X30]),
                        GUEST_BASE,
                        declared_profile(true, true, false, false),
                        target()
                    )
                    .is_ok()
                );
            }
            SmeMemoryOperand::ZaVector(_) => {
                assert_declined(word, declared_profile(true, false, true, false), target());
                assert!(
                    crate::testing::context_leaf(
                        &source(&[word, RET_X30]),
                        GUEST_BASE,
                        declared_profile(false, true, false, false),
                        target()
                    )
                    .is_ok()
                );
            }
            SmeMemoryOperand::Zt(_) => {
                assert_declined(word, declared_profile(true, false, true, true), target());
                assert_declined(word, declared_profile(true, true, false, false), target());
                assert_declined(word, declared_profile(true, true, true, false), target());
                assert!(
                    crate::testing::context_leaf(
                        &source(&[word, RET_X30]),
                        GUEST_BASE,
                        declared_profile(false, true, true, true),
                        target()
                    )
                    .is_ok()
                );
            }
        }
    }
}

#[test]
fn independent_host_capabilities_decline_before_scan_or_emission() {
    let profile = declared_profile(true, true, true, true);
    for word in WORDS {
        let operand = sme_memory::decode(word).unwrap();
        for target in [
            TargetCpu::Baseline,
            TargetCpu::AtomicLoad16,
            TargetCpu::Cx16,
        ] {
            if x86_64::sme::memory::validate_target(&operand, target).is_err() {
                assert_declined(word, profile, target);
            }
        }
    }
}

#[test]
fn existing_v1_contract_admits_its_features_and_declines_disabled_zt0() {
    let profile = ScalableProfile::new(
        VectorLength::from_bytes(16).unwrap(),
        ScalableMode::new(true, true),
    );
    assert_eq!(profile.id(), PROFILE_ID);
    assert_eq!(profile.declared_features(), None);
    assert_eq!(profile.required_dit(), None);
    assert!(!profile.controls().zt0_enabled());
    for word in WORDS {
        if matches!(sme_memory::decode(word), Some(SmeMemoryOperand::Zt(_))) {
            assert_declined(word, profile, target());
        } else {
            assert!(
                crate::testing::context_leaf(
                    &source(&[word, RET_X30]),
                    GUEST_BASE,
                    profile,
                    target()
                )
                .is_ok()
            );
        }
    }
    assert!(
        crate::testing::context_leaf(
            &source(&[NOP, RET_X30]),
            GUEST_BASE,
            profile,
            TargetCpu::Baseline
        )
        .is_ok()
    );
}

#[test]
fn complete_body_requirements_fold_every_memory_instruction() {
    let profile = declared_profile(true, true, true, true);
    let mut words = vec![NOP];
    let mut expected = MemoryRequirements::default();
    for word in WORDS {
        let sp_word = (word & !BASE_REGISTER_MASK) | BASE_REGISTER_MASK;
        words.push(sp_word);
        let operand = sme_memory::decode(sp_word).unwrap();
        expected = expected
            .merge(x86_64::sme::memory::requirements(&operand))
            .unwrap();
    }
    words.push(RET_X30);
    assert_eq!(
        crate::testing::context_leaf_memory(&source(&words), GUEST_BASE, profile, target())
            .unwrap(),
        expected
    );
    assert!(crate::testing::context_leaf(&source(&words), GUEST_BASE, profile, target()).is_ok());
}

// Append to scalable_context/sme_memory_tests.rs; reuse its source/profile/target helpers.

#[test]
fn prepared_memory_metadata_retains_per_pc_features_helpers_and_quantities() {
    use crate::aarch64::scalable::execution::{
        GuestMemoryQuantity, ScalableAccessCheck, ScalableAccessRequirements,
    };

    const MULTI_Z_LOAD_BYTE: u32 = 0xa140_00a0;
    const TILE_LOAD_QUADWORD: u32 = 0xe1c0_00a0;
    const WHOLE_ZA_LOAD: u32 = 0xe100_00a0;
    const ZT_LOAD: u32 = 0xe11f_80a0;
    let words = [
        NOP,
        MULTI_Z_LOAD_BYTE,
        TILE_LOAD_QUADWORD,
        WHOLE_ZA_LOAD,
        ZT_LOAD,
        RET_X30,
    ];
    let prepared = crate::testing::prepared_context_leaf(
        &source(&words),
        GUEST_BASE,
        declared_profile(true, true, true, true),
        target(),
    )
    .unwrap();
    let instructions = prepared.execution_requirements.instructions();
    assert_eq!(instructions.len(), words.len());
    let sme = ScalableFeatures::of(ScalableFeature::Sme);
    let sme2 = sme.with(ScalableFeature::Sme2);
    let expected = [
        (None, vec![], GuestMemoryQuantity::None),
        (
            Some(sme2),
            vec![ScalableAccessCheck::StreamingSveEnabled],
            GuestMemoryQuantity::Maximum(ElementSize::Byte),
        ),
        (
            Some(sme),
            vec![ScalableAccessCheck::StreamingSveAndZaEnabled],
            GuestMemoryQuantity::Maximum(ElementSize::Quadword),
        ),
        (
            Some(sme),
            vec![ScalableAccessCheck::SmeAndZaEnabled],
            GuestMemoryQuantity::Maximum(ElementSize::Byte),
        ),
        (
            Some(sme2),
            vec![
                ScalableAccessCheck::SmeEnabled,
                ScalableAccessCheck::SmeZt0Enabled,
            ],
            GuestMemoryQuantity::Maximum(ElementSize::Byte),
        ),
        (None, vec![], GuestMemoryQuantity::None),
    ];
    for (index, (instruction, (features, helpers, quantity))) in
        instructions.iter().zip(expected).enumerate()
    {
        let pc = GuestAddress(GUEST_BASE.0 + (index * size_of::<u32>()) as u64);
        assert_eq!(instruction.pc(), pc);
        assert_eq!(prepared.native.source_map[index].0, pc);
        let clauses: Vec<_> = features.into_iter().map(FeatureRequirement::all).collect();
        assert_eq!(instruction.feature_clauses(), clauses);
        assert_eq!(
            instruction.access(),
            &ScalableAccessRequirements::Known(helpers.into_boxed_slice())
        );
        assert_eq!(instruction.guest_memory_quantity(), quantity);
    }
}

#[test]
fn prepared_sm0_whole_banks_keep_sme_helpers_and_byte_quantities() {
    use crate::aarch64::scalable::execution::{
        GuestMemoryQuantity, ScalableAccessCheck, ScalableAccessRequirements,
    };

    const MEMORY_INSTRUCTIONS: usize = 2;
    const WHOLE_ZA_LOAD: u32 = 0xe100_00a0;
    const WHOLE_ZA_STORE: u32 = 0xe120_00a0;
    const ZT_LOAD: u32 = 0xe11f_80a0;
    const ZT_STORE: u32 = 0xe13f_80a0;
    for (words, sme2, checks) in [
        (
            [WHOLE_ZA_LOAD, WHOLE_ZA_STORE, RET_X30],
            false,
            vec![ScalableAccessCheck::SmeAndZaEnabled],
        ),
        (
            [ZT_LOAD, ZT_STORE, RET_X30],
            true,
            vec![
                ScalableAccessCheck::SmeEnabled,
                ScalableAccessCheck::SmeZt0Enabled,
            ],
        ),
    ] {
        let prepared = crate::testing::prepared_context_leaf(
            &source(&words),
            GUEST_BASE,
            declared_profile(false, true, sme2, sme2),
            target(),
        )
        .unwrap();
        for instruction in &prepared.execution_requirements.instructions()[..MEMORY_INSTRUCTIONS] {
            assert_eq!(
                instruction.access(),
                &ScalableAccessRequirements::Known(checks.clone().into_boxed_slice())
            );
            assert_eq!(
                instruction.guest_memory_quantity(),
                GuestMemoryQuantity::Maximum(ElementSize::Byte)
            );
        }
    }
}
