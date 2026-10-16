use super::*;
use crate::aarch64::scalable::{ScalableMode, VectorLength};
use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

const BASE: GuestAddress = GuestAddress(0x1000);
const ADD_X5_ONE: u32 = 0x9100_04a5;
const FADD_Z0_SINGLE: u32 = 0x6580_8020;
const SVC: u32 = 0xd400_0001;
const BRK: u32 = 0xd420_0000;
const ERET: u32 = 0xd69f_03e0;
const IRG: u32 = 0x9ac0_1000;
const PACIBSP: u32 = 0xd503_237f;
const CNTVCT: u32 = 0xd53b_e040;
const TPIDRRO: u32 = 0xd53b_d060;
const RET: u32 = 0xd65f_03c0;
const PACGA_X1_X2_X3: u32 = 0x9ac3_3041;
const LDRAA_X1_X2: u32 = 0xf820_0441;
const LDRAB_X1_X2: u32 = 0xf8a0_0441;
const SERVICE_WORDS: &[u32] = &[
    ERET,
    IRG,
    PACIBSP,
    CNTVCT,
    TPIDRRO,
    PACGA_X1_X2_X3,
    LDRAA_X1_X2,
    LDRAB_X1_X2,
];

fn source(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn profile(services: BlockProfile) -> ExtendedBlockProfile {
    ExtendedBlockProfile::new(
        ScalableProfile::new(
            VectorLength::from_bytes(16).unwrap(),
            ScalableMode::new(true, false),
        ),
        services,
        NumericalFeatures::default(),
    )
}

#[test]
fn context_entry_declines_every_nonordinary_service_profile() {
    for services in [
        BlockProfile::SystemV1,
        BlockProfile::AppleArm64eSoftwarePauthV1,
        BlockProfile::AppleArm64eSoftwarePauthClockV1,
        BlockProfile::DarwinArm64ThreadV1,
        BlockProfile::AppleArm64eSoftwarePauthThreadV1,
        BlockProfile::AppleArm64eSoftwarePauthClockThreadV1,
    ] {
        let error = compile_for_profile(
            &source(&[RET]),
            BASE,
            profile(services),
            TargetCpu::Baseline,
        )
        .unwrap_err();
        assert!(error.to_string().contains("services are not integrated"));
    }
}

#[test]
fn ordinary_trap_extent_stays_distinct_from_forbidden_system_completion() {
    for trap in [SVC, BRK] {
        let compiled = compile_for_profile(
            &source(&[ADD_X5_ONE, trap, ERET]),
            BASE,
            profile(BlockProfile::Ordinary),
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(compiled.source_bytes, 2 * INSTRUCTION_BYTES);
        assert_eq!(
            compiled
                .native
                .source_map
                .iter()
                .map(|row| row.0)
                .collect::<Vec<_>>(),
            [BASE, GuestAddress(BASE.0 + INSTRUCTION_BYTES as u64)]
        );
    }
    for &service in SERVICE_WORDS {
        for words in [vec![service, RET], vec![ADD_X5_ONE, service, RET]] {
            let offset = if words[0] == ADD_X5_ONE {
                INSTRUCTION_BYTES
            } else {
                0
            };
            let error = compile_for_profile(
                &source(&words),
                BASE,
                profile(BlockProfile::Ordinary),
                TargetCpu::Baseline,
            )
            .unwrap_err();
            assert!(error.to_string().contains("service is not integrated"));
            assert!(
                error
                    .to_string()
                    .contains(&format!("{:#x}", BASE.0 + offset as u64))
            );
        }
    }
}

#[test]
fn unconsumed_service_after_numerical_boundary_does_not_expand_extent() {
    for &service in SERVICE_WORDS {
        let compiled = compile_for_profile(
            &source(&[ADD_X5_ONE, FADD_Z0_SINGLE, service]),
            BASE,
            profile(BlockProfile::Ordinary),
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(compiled.source_bytes, 2 * INSTRUCTION_BYTES);
        assert_eq!(compiled.native.source_map.len(), 2);
        assert_eq!(
            compiled.native.source_map[1].0,
            GuestAddress(BASE.0 + INSTRUCTION_BYTES as u64)
        );
    }
}

#[test]
fn strict_ordinary_ram_atomic_legacy_fp_and_prefix_declines_stay_explicit() {
    const LDR_X0_X1: u32 = 0xf940_0020;
    const CAS_X0_X1_X2: u32 = 0xc8a0_7c41;
    const FADD_S0_S1_S2: u32 = 0x1e22_2820;
    const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
    for word in [LDR_X0_X1, CAS_X0_X1_X2, FADD_S0_S1_S2, MOVPRFX_Z0_Z1] {
        assert!(
            compile_for_profile(
                &source(&[ADD_X5_ONE, word, RET]),
                BASE,
                profile(BlockProfile::Ordinary),
                TargetCpu::Baseline,
            )
            .is_err()
        );
    }
}
#[test]
fn movprfx_pairs_remain_leaf_only_and_numerical_followers_decline() {
    const UNPREDICATED_PREFIX: u32 = 0x0420_bc20;
    const ZEROING_PREFIX: u32 = 0x0410_2020;
    const MERGING_PREFIX: u32 = 0x0411_2020;
    const AND_DESTRUCTIVE: u32 = 0x041a_0040;
    let block_profile = profile(BlockProfile::Ordinary);
    for prefix in [UNPREDICATED_PREFIX, ZEROING_PREFIX, MERGING_PREFIX] {
        let bytes = source(&[prefix, AND_DESTRUCTIVE, RET]);
        let leaf = crate::extended::compile_for_profile(
            &bytes,
            BASE,
            block_profile.scalable(),
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(
            leaf.source_map.iter().map(|row| row.0).collect::<Vec<_>>(),
            [
                BASE,
                GuestAddress(BASE.0 + INSTRUCTION_BYTES as u64),
                GuestAddress(BASE.0 + 2 * INSTRUCTION_BYTES as u64),
            ]
        );
        let error =
            compile_for_profile(&bytes, BASE, block_profile, TargetCpu::Baseline).unwrap_err();
        assert!(error.to_string().contains(&format!("{:#x}", BASE.0)));
    }
    let error = crate::extended::compile_for_profile(
        &source(&[UNPREDICATED_PREFIX, FADD_Z0_SINGLE, RET]),
        BASE,
        block_profile.scalable(),
        TargetCpu::Baseline,
    )
    .unwrap_err();
    assert!(error.to_string().contains("unsupported follower"));
    assert!(
        error
            .to_string()
            .contains(&format!("{:#x}", BASE.0 + INSTRUCTION_BYTES as u64))
    );
}
