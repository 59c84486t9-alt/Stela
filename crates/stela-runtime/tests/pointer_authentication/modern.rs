//! PAuth2/FPAC helpers in cached native blocks.
#![cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]

use anyhow::Result;
use stela_compiler::{GuestAddress, GuestState, block::BlockProfile};
use stela_runtime::{
    blocks::{BlockRuntime, StopReason, ThreadState},
    pauth::{Context, Key, Keys, Version},
};

const ADDRESS_SPACE: u64 = 73;
const BASE: GuestAddress = GuestAddress(0x1000);
const NEXT: GuestAddress = GuestAddress(BASE.0 + 4);
const STOP: GuestAddress = GuestAddress(0x1400);
const PROFILE: BlockProfile = BlockProfile::AppleArm64eSoftwarePauthV1;
const KEY: [u64; 2] = [0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00];
const PACGA_X1_X2_X3: u32 = 0x9ac3_3041;
const PACGA_XZR_X2_SP: u32 = 0x9adf_305f;
const MOV_X7_42: u32 = 0xd280_0547;
const AUTIA_X1_X2: u32 = 0xdac1_1041;
const RETAA: u32 = 0xd65f_0bff;
const RETAB: u32 = 0xd65f_0fff;
const BLRAA_X30_SP: u32 = 0xd73f_0bdf;
const BLRAB_X30_SP: u32 = 0xd73f_0fdf;
const CORRUPT_PAC_BIT: u64 = 1 << 47;

fn keys() -> Keys {
    Keys::from_words(KEY, KEY, KEY, KEY).with_generic_words(KEY)
}

fn state() -> ThreadState {
    ThreadState {
        pc: BASE,
        registers: GuestState {
            x: std::array::from_fn(|index| 0x0123_4567_89ab_cdefu64.rotate_left(index as u32)),
            sp: 0x2000,
            nzcv: 0xa000_0000,
            reserved: 0xa5c3_9e71,
            v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
            fpcr: 0x03c0_0000,
            fpsr: 0x0800_001f,
        },
    }
}

fn runtime(cache: &std::path::Path, words: &[u32]) -> Result<BlockRuntime> {
    let mut runtime = BlockRuntime::new_with_profile(ADDRESS_SPACE, cache.into(), PROFILE);
    runtime.register_code(
        BASE,
        words.iter().flat_map(|word| word.to_le_bytes()).collect(),
    )?;
    Ok(runtime)
}

#[test]
fn pacga_preserves_original_state_and_provenance_across_aot_hot_and_disk_cache() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let words = [MOV_X7_42, PACGA_X1_X2_X3, 0];
    let mut runtime = runtime(cache.path(), &words)?;
    let discovery = runtime.discover(&[BASE], 1)?;
    assert_eq!(discovery.blocks.len(), 1);
    assert!(!discovery.native_executed && !discovery.native_pages_loaded);
    let context = Context::new(ADDRESS_SPACE, keys());
    for phase in 0..3 {
        if phase == 2 {
            runtime = self::runtime(cache.path(), &words)?;
        }
        let mut state = state();
        state.registers.x[2] = 0x3c81_0c25_5889_4393;
        state.registers.x[3] = 0x33a1_4317_4773_58e7;
        let mut expected = state.registers.clone();
        expected.x[7] = 42;
        // Pinned direct-original PACGA/QARMA5 vector, not the runtime under test.
        expected.x[1] = 0x7cec_813d_0000_0000;
        // SAFETY: one register-only prefix and an explicit key helper; no guest RAM.
        let outcome = unsafe { runtime.run_with_pauth(&mut state, None, 1, &context)? };
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, GuestAddress(BASE.0 + 8));
        assert_eq!(outcome.reason, StopReason::BudgetExhausted);
        assert_eq!(outcome.compiled_blocks, 0);
        assert_eq!(outcome.disk_cache_hits, usize::from(phase != 1));
        assert_eq!(outcome.memory_cache_hits, usize::from(phase == 1));
        assert_eq!(outcome.pointer_authentication_events.len(), 1);
        let manifest = runtime.loaded_manifest(BASE).unwrap();
        assert_eq!(manifest.identity.abi, PROFILE.abi());
        assert_eq!(manifest.source_map.len(), 2);
        assert_eq!(manifest.source_map[0].0, BASE);
        assert_eq!(manifest.source_map[1].0, NEXT);
        let serialized = serde_json::to_string(manifest)?;
        assert!(!serialized.contains("1122334455667788"));
        assert!(!serialized.contains("99aabbccddeeff00"));
    }
    Ok(())
}

#[test]
fn pacga_requires_its_independent_key_even_when_destination_is_discarded() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let context = Context::new(ADDRESS_SPACE, Keys::from_words(KEY, KEY, KEY, KEY));
    for word in [PACGA_X1_X2_X3, PACGA_XZR_X2_SP] {
        let mut runtime = runtime(cache.path(), &[word])?;
        let mut state = state();
        let expected = state.registers.clone();
        // SAFETY: immutable register-only PACGA block.
        let outcome = unsafe { runtime.run_with_pauth(&mut state, None, 1, &context)? };
        assert!(matches!(
            outcome.reason,
            StopReason::PointerAuthenticationGenericKeyUnavailable { .. }
        ));
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, BASE);
        assert!(outcome.pointer_authentication_events.is_empty());
    }
    Ok(())
}

#[test]
fn standalone_fpac_failure_keeps_destination_and_pc_unchanged() -> Result<()> {
    let cache = tempfile::tempdir()?;
    for version in [Version::Faulting, Version::FaultingCombined] {
        let context = Context::new_with_version(ADDRESS_SPACE, keys(), version);
        let mut runtime = runtime(cache.path(), &[AUTIA_X1_X2])?;
        let mut state = state();
        state.registers.x[2] = 0x2000;
        state.registers.x[1] =
            context.sign(Key::Ia, STOP.0, state.registers.x[2])? ^ CORRUPT_PAC_BIT;
        let expected = state.registers.clone();
        // SAFETY: immutable AUT helper; no guest memory access.
        let outcome = unsafe { runtime.run_with_pauth(&mut state, None, 1, &context)? };
        assert!(matches!(
            outcome.reason,
            StopReason::PointerAuthenticationFailure { code: 0, .. }
        ));
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, BASE);
        assert!(outcome.pointer_authentication_events.is_empty());
    }
    Ok(())
}

#[test]
fn combined_fpaccombine_failure_precedes_link_write_and_transfer() -> Result<()> {
    let cache = tempfile::tempdir()?;
    for (word, key, link) in [
        (RETAA, Key::Ia, false),
        (RETAB, Key::Ib, false),
        (BLRAA_X30_SP, Key::Ia, true),
        (BLRAB_X30_SP, Key::Ib, true),
    ] {
        for version in [
            Version::Classic,
            Version::Enhanced,
            Version::Faulting,
            Version::FaultingCombined,
        ] {
            let context = Context::new_with_version(ADDRESS_SPACE, keys(), version);
            let mut runtime = runtime(cache.path(), &[word])?;
            let mut state = state();
            state.registers.x[30] =
                context.sign(key, STOP.0, state.registers.sp)? ^ CORRUPT_PAC_BIT;
            let initial = state.registers.clone();
            // SAFETY: one transfer helper; failed targets stop before fetching.
            let outcome = unsafe { runtime.run_with_pauth(&mut state, None, 1, &context)? };
            if version == Version::FaultingCombined {
                let code = u8::from(key == Key::Ib);
                assert!(
                    matches!(outcome.reason, StopReason::PointerAuthenticationFailure { code: actual, .. } if actual == code)
                );
                assert_eq!(state.registers, initial);
                assert_eq!(state.pc, BASE);
                assert!(outcome.pointer_authentication_events.is_empty());
            } else {
                let mut expected = initial;
                if link {
                    expected.x[30] = NEXT.0;
                    assert!(matches!(
                        outcome.reason,
                        StopReason::PointerAuthenticationPoisonedBranch { .. }
                    ));
                } else {
                    assert!(matches!(
                        outcome.reason,
                        StopReason::PointerAuthenticationPoisonedReturn { .. }
                    ));
                }
                assert_eq!(state.registers, expected);
                assert_eq!(outcome.pointer_authentication_events.len(), 1);
                assert_eq!(
                    outcome.pointer_authentication_events[0].authenticated,
                    Some(false)
                );
            }
        }
    }
    Ok(())
}
