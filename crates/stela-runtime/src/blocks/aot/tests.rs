//! Shared loader checks over actual original compiler artifacts; no raw entry.
use super::*;
use stela_compiler::{
    TargetCpu,
    context::memory::address::{AccessEl, AddressAddChecks, EffectiveAddressChecks},
};

const BASE: GuestAddress = GuestAddress(0x1000);
const ADDRESS_SPACE: u64 = 7;
const MOVZ_X0_42: u32 = 0xd280_0540;
const B_NEXT: u32 = 0x1400_0001;
const LDR_X0_X9_8: u32 = 0xf940_0520;
const LDTR_X1_X9_8: u32 = 0xf840_8921;
const RET_X30: u32 = 0xd65f_03c0;

fn source(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn artifact(source: &[u8], profile: BlockProfile) -> Result<(crate::Manifest, Vec<u8>)> {
    let plan =
        CompilationPlan::new(source, BASE, profile, TargetCpu::Baseline)?.with_resident_loops();
    let identity = crate::block_plan_identity(source, BASE, TargetCpu::Baseline, &plan)?;
    let memory_requirements = plan.memory_requirements();
    let native = plan.compile()?.native;
    let manifest = crate::Manifest {
        identity,
        native_sha256: stela_core::sha256(&native.x86_64_code),
        native_bytes: native.x86_64_code.len(),
        source_map: native.source_map,
        verified: false,
        memory_requirements,
    };
    Ok((manifest, native.x86_64_code))
}

fn serialized(manifest: &crate::Manifest) -> Result<(Vec<u8>, Vec<u8>)> {
    let bytes = serde_json::to_vec(manifest)?;
    let checksum = serde_json::to_vec(&stela_core::sha256(&bytes))?;
    Ok((bytes, checksum))
}

fn runtime(source: &[u8], profile: BlockProfile) -> Result<BlockRuntime> {
    let mut runtime = BlockRuntime::new_aot_for_target(ADDRESS_SPACE, profile, TargetCpu::Baseline);
    runtime.register_code(BASE, source.to_vec())?;
    Ok(runtime)
}

fn outcome() -> RunOutcome {
    RunOutcome {
        reason: StopReason::BudgetExhausted,
        blocks_executed: 0,
        compiled_blocks: 0,
        disk_cache_hits: 0,
        memory_cache_hits: 0,
        last_exit: None,
        floating_point_helpers: 0,
        pointer_authentication_events: Vec::new(),
        clock_events: Vec::new(),
        thread_register_events: Vec::new(),
    }
}

#[test]
fn standard_artifact_enters_original_loaded_hit_path_without_disk_or_execution() -> Result<()> {
    let source = source(&[MOVZ_X0_42, B_NEXT]);
    let (manifest, native) = artifact(&source, BlockProfile::Ordinary)?;
    let (bytes, checksum) = serialized(&manifest)?;
    let mut runtime = runtime(&source, BlockProfile::Ordinary)?;
    runtime.preload_artifact(BASE, &bytes, &checksum, &native)?;
    assert_eq!(
        runtime.loaded_manifest(BASE).unwrap().identity,
        manifest.identity
    );
    let mut observations = outcome();
    runtime.load(BASE, &mut observations)?;
    assert_eq!(observations.memory_cache_hits, 1);
    assert_eq!(observations.disk_cache_hits, 0);
    assert_eq!(observations.compiled_blocks, 0);
    assert_eq!(observations.blocks_executed, 0);
    assert_eq!(runtime.loaded.len(), 1);
    assert!(
        runtime
            .preload_artifact(BASE, &bytes, &checksum, &native)
            .is_err()
    );
    Ok(())
}

#[test]
fn aot_miss_refuses_before_compiler_or_filesystem_preparation() -> Result<()> {
    // Unsupported instruction distinguishes availability refusal from invoking
    // the absent runtime miss compiler. Registered bytes remain unchanged.
    let source = [0; size_of::<u32>()];
    let mut runtime = runtime(&source, BlockProfile::Ordinary)?;
    let error = runtime.prepare(BASE).unwrap_err();
    assert_eq!(
        error.to_string(),
        "AOT block unavailable at 0x1000; runtime compilation is unsupported"
    );
    let mut observations = outcome();
    assert!(runtime.load(BASE, &mut observations).is_err());
    assert!(runtime.loaded.is_empty());
    assert_eq!(observations.memory_cache_hits, 0);
    assert_eq!(observations.disk_cache_hits, 0);
    assert_eq!(observations.compiled_blocks, 0);
    Ok(())
}

#[test]
fn stale_source_native_map_and_verification_claim_cannot_publish_loaded_blocks() -> Result<()> {
    let source = source(&[MOVZ_X0_42, B_NEXT]);
    for change in 0..4 {
        let (mut manifest, native) = artifact(&source, BlockProfile::Ordinary)?;
        match change {
            0 => manifest.identity.source_sha256.push('0'),
            1 => manifest.native_sha256.push('0'),
            2 => manifest.source_map[0].0 = GuestAddress(BASE.0 + 4),
            3 => manifest.verified = true,
            _ => unreachable!(),
        }
        let (bytes, checksum) = serialized(&manifest)?;
        let mut runtime = runtime(&source, BlockProfile::Ordinary)?;
        assert!(
            runtime
                .preload_artifact(BASE, &bytes, &checksum, &native)
                .is_err()
        );
        assert!(runtime.loaded.is_empty());
    }
    Ok(())
}

#[test]
fn complete_cpa_role_profile_is_recomputed_before_metadata_acceptance() -> Result<()> {
    use stela_compiler::block::CheckedMemoryProfile;
    let source = source(&[LDR_X0_X9_8, LDTR_X1_X9_8, RET_X30]);
    let checks = EffectiveAddressChecks::new(AddressAddChecks::Disabled, AddressAddChecks::Enabled);
    let profile = |normal, unprivileged| {
        BlockProfile::CheckedMemory(
            CheckedMemoryProfile::SpAlignmentDisabled.with_address_checks(
                normal,
                unprivileged,
                checks,
            ),
        )
    };
    let first = profile(AccessEl::El1, AccessEl::El0);
    let second = profile(AccessEl::El0, AccessEl::El1);
    let (manifest, native) = artifact(&source, first)?;
    let (second_manifest, _) = artifact(&source, second)?;
    assert_eq!(
        manifest.memory_requirements,
        second_manifest.memory_requirements
    );
    assert_ne!(
        manifest.identity.memory_specialization_sha256,
        second_manifest.identity.memory_specialization_sha256
    );
    let (bytes, checksum) = serialized(&manifest)?;
    let mut runtime = runtime(&source, second)?;
    let error = runtime
        .preload_artifact(BASE, &bytes, &checksum, &native)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "cached memory specialization differs from complete requirements"
    );
    assert!(runtime.loaded.is_empty());
    Ok(())
}

#[test]
fn replacing_registered_source_retires_preloaded_native_generation() -> Result<()> {
    let source = source(&[MOVZ_X0_42, B_NEXT]);
    let (manifest, native) = artifact(&source, BlockProfile::Ordinary)?;
    let (bytes, checksum) = serialized(&manifest)?;
    let mut runtime = runtime(&source, BlockProfile::Ordinary)?;
    runtime.preload_artifact(BASE, &bytes, &checksum, &native)?;
    assert!(runtime.unregister_code(BASE));
    assert!(runtime.loaded.is_empty());
    runtime.register_code(BASE, [0; size_of::<u32>()].to_vec())?;
    assert!(
        runtime
            .preload_artifact(BASE, &bytes, &checksum, &native)
            .is_err()
    );
    assert!(runtime.loaded.is_empty());
    Ok(())
}
