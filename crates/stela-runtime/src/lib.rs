//! Execution of translated ARM64 code: the native code cache, block dispatch,
//! guest memory, system state and Darwin services.
#![cfg_attr(not(feature = "std"), no_std)]
// A std host without POSIX mappings (Windows, for setup) backs no guest
// memory, so the execution paths built on it are present but never reached.
#![cfg_attr(
    all(feature = "std", not(host_memory)),
    allow(dead_code, unused_imports)
)]
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, string::String};
#[macro_use]
extern crate alloc;
#[cfg(all(not(feature = "std"), not(panic = "abort")))]
compile_error!(
    "freestanding runtime requires aborting panic; platform must terminate the machine on panic"
);
pub mod amx;
pub mod apfs;
pub mod blocks;
pub mod boot_bundle;
pub mod builds;
mod checksum;
pub mod clock;
#[cfg(feature = "std")]
pub mod code_signature;
pub mod commpage;
pub mod darwin;
#[cfg(feature = "std")]
pub mod dispatch;
pub mod execution;
mod floating;
mod hash;
#[cfg(all(feature = "std", target_os = "macos", target_arch = "x86_64"))]
pub mod hosted;
#[cfg(feature = "std")]
pub mod hosted_registry;
pub mod img4;
#[cfg(feature = "std")]
mod json;
pub mod lzfse;
pub mod mach;
pub mod machine;
pub mod memory;
pub mod pauth;
pub mod payload;
mod platform;
pub mod preboot;
pub mod restore;
/// Stela's own IPv4 client stack over any raw Ethernet link.
pub use platform::net;
/// Host PC storage for the UEFI mount after ExitBootServices.
#[cfg(target_arch = "x86_64")]
pub use platform::pc;
#[cfg(all(target_arch = "x86_64", target_os = "uefi", not(feature = "std")))]
pub mod freestanding {
    pub use crate::execution::boot_frames::FrameError as BootStorageError;
    pub use crate::platform::boot::{BootArena, CpuObservation, MountError, install, verify};
}
/// Destination-local stable CPU declaration ownership for native system Hosts.
pub use platform::cpu::system::{NativeCpuError, NativeCpuLease, NativeCpuOwner};
pub mod process;
pub mod scalable;
pub mod system;
pub mod thread;
pub mod translations;
#[cfg(feature = "std")]
use anyhow::ensure;
use anyhow::{Context, Result};
pub use hash::sha256;
#[cfg(feature = "std")]
pub use json::{read_json, write_json};
use serde::Serialize;
#[cfg(feature = "std")]
use std::io::Read;
#[cfg(feature = "std")]
use std::path::{Path, PathBuf};
use stela_compiler::GuestAddress;
#[cfg(feature = "std")]
use stela_compiler::{NATIVE_ABI, NativeBlock};

fn compiler_source_sha256() -> &'static str {
    stela_compiler::SOURCE_SHA256
}

#[cfg(feature = "std")]
use artifact::prepare::{MAX_CACHE_MANIFEST_BYTES, MAX_CACHE_NATIVE_BYTES};

#[cfg(feature = "std")]
fn bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    ensure!(
        file.metadata()?.len() <= limit as u64,
        "cache file exceeds size limit"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "cache file grew beyond size limit");
    Ok(bytes)
}

pub(crate) mod artifact;
pub use artifact::{Identity, Manifest};
fn memory_specialization_sha256(
    profile: stela_compiler::block::BlockProfile,
    requirements: Option<stela_compiler::context::memory::MemoryRequirements>,
) -> Result<Option<String>> {
    use stela_compiler::block::CheckedMemoryProfile;
    if !matches!(
        profile.checked_memory(),
        Some(CheckedMemoryProfile::AddressChecks(_))
    ) {
        return Ok(None);
    }
    let required = requirements.context("specialized checked plan requirements absent")?;
    // Aggregation alone loses the source-role -> access-EL association. Bind the
    // full typed compilation profile as well as every consumed requirement.
    Ok(Some(sha256(&serde_json::to_vec(&(profile, required))?)))
}

#[derive(Debug, Serialize)]
pub struct Prepared {
    pub key: String,
    pub cache_hit: bool,
    #[cfg(feature = "std")]
    pub directory: PathBuf,
    pub manifest: Manifest,
}

#[cfg(feature = "std")]
fn validate(
    directory: &Path,
    identity: &Identity,
    memory_requirements: Option<stela_compiler::context::memory::MemoryRequirements>,
    profile: stela_compiler::block::BlockProfile,
) -> Result<Manifest> {
    let manifest_bytes = bounded_file(&directory.join("manifest.json"), MAX_CACHE_MANIFEST_BYTES)?;
    let expected: String = serde_json::from_slice(&bounded_file(
        &directory.join("manifest.sha256.json"),
        1024,
    )?)?;
    artifact::prepare::validate_manifest_bytes(&manifest_bytes, &expected)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    ensure!(
        manifest.identity.memory_specialization_sha256
            == memory_specialization_sha256(profile, manifest.memory_requirements)?,
        "cached memory specialization differs from complete requirements"
    );
    artifact::prepare::validate_preparation_metadata(&manifest, identity, memory_requirements)?;
    let native = bounded_file(&directory.join("native.bin"), MAX_CACHE_NATIVE_BYTES)?;
    artifact::prepare::validate_preparation_native(&manifest, &native)
        .context("cached native code checksum mismatch")?;
    artifact::prepare::validate_preparation_claim(&manifest)?;
    Ok(manifest)
}

#[cfg(feature = "std")]
pub fn prepare_leaf(source: &[u8], base: GuestAddress, root: &Path) -> Result<Prepared> {
    prepare_leaf_for_target(source, base, root, stela_compiler::TargetCpu::detect())
}
#[cfg(feature = "std")]
pub fn prepare_leaf_for_target(
    source: &[u8],
    base: GuestAddress,
    root: &Path,
    target: stela_compiler::TargetCpu,
) -> Result<Prepared> {
    let identity = Identity {
        schema_version: 1,
        source_sha256: sha256(source),
        compiler_source_sha256: compiler_source_sha256().to_owned(),
        guest_base: base.0,
        abi: NATIVE_ABI.into(),
        target_cpu: target.id(),
        memory_specialization_sha256: None,
    };
    prepare(
        identity,
        root,
        None,
        stela_compiler::block::BlockProfile::Ordinary,
        || stela_compiler::compile_for_target(source, base, target),
    )
}

#[derive(Debug, Serialize)]
pub struct PreparedBlock {
    pub source_bytes: usize,
    pub prepared: Prepared,
}

/// Decode the consumed prefix to identify it before looking up persistent AOT.
/// A disk hit avoids code generation; source extent still requires decoding.
#[cfg(feature = "std")]
pub fn prepare_block(source: &[u8], base: GuestAddress, root: &Path) -> Result<PreparedBlock> {
    prepare_block_with_profile(
        source,
        base,
        root,
        stela_compiler::block::BlockProfile::Ordinary,
    )
}

/// Profile-tagged shared AOT/JIT preparation. PAC keys stay outside artifacts;
/// this profile prepares a checked helper boundary rather than authenticating.
#[cfg(feature = "std")]
pub fn prepare_block_with_profile(
    source: &[u8],
    base: GuestAddress,
    root: &Path,
    profile: stela_compiler::block::BlockProfile,
) -> Result<PreparedBlock> {
    prepare_block_for_target(
        source,
        base,
        root,
        profile,
        stela_compiler::TargetCpu::detect(),
    )
}
#[cfg(feature = "std")]
pub fn prepare_block_for_target(
    source: &[u8],
    base: GuestAddress,
    root: &Path,
    profile: stela_compiler::block::BlockProfile,
    target: stela_compiler::TargetCpu,
) -> Result<PreparedBlock> {
    let plan = stela_compiler::block::CompilationPlan::new(source, base, profile, target)?;
    prepare_block_plan(source, base, root, target, plan)
}

/// Ordinary dispatch may choose the resident ABI; service profiles keep their
/// own call contract.
#[cfg(feature = "std")]
pub(crate) fn prepare_runtime_block_for_target(
    source: &[u8],
    base: GuestAddress,
    root: &Path,
    profile: stela_compiler::block::BlockProfile,
    target: stela_compiler::TargetCpu,
) -> Result<(PreparedBlock, stela_compiler::block::BlockProfile)> {
    let plan = stela_compiler::block::CompilationPlan::new(source, base, profile, target)?
        .with_resident_loops();
    let artifact_profile = plan.profile();
    Ok((
        prepare_block_plan(source, base, root, target, plan)?,
        artifact_profile,
    ))
}

#[cfg(feature = "std")]
fn prepare_block_plan(
    source: &[u8],
    base: GuestAddress,
    root: &Path,
    target: stela_compiler::TargetCpu,
    plan: stela_compiler::block::CompilationPlan,
) -> Result<PreparedBlock> {
    let profile = plan.profile();
    let source_bytes = plan.source_bytes();
    let memory_requirements = plan.memory_requirements();
    let identity = block_plan_identity(source, base, target, &plan)?;
    let prepared = prepare(identity, root, memory_requirements, profile, || {
        plan.compile().map(|b| b.native)
    })?;
    Ok(PreparedBlock {
        source_bytes,
        prepared,
    })
}

// Identity derived from the source plan, shared by hosted preparation and AOT
// intake.
fn block_plan_identity(
    source: &[u8],
    base: GuestAddress,
    target: stela_compiler::TargetCpu,
    plan: &stela_compiler::block::CompilationPlan,
) -> Result<Identity> {
    let profile = plan.profile();
    let prefix = &source[..plan.source_bytes()];
    Ok(Identity {
        schema_version: 1,
        source_sha256: sha256(prefix),
        compiler_source_sha256: compiler_source_sha256().to_owned(),
        guest_base: base.0,
        abi: profile.abi().into(),
        target_cpu: target.id(),
        memory_specialization_sha256: memory_specialization_sha256(
            profile,
            plan.memory_requirements(),
        )?,
    })
}

#[cfg(feature = "std")]
fn prepare(
    identity: Identity,
    root: &Path,
    memory_requirements: Option<stela_compiler::context::memory::MemoryRequirements>,
    profile: stela_compiler::block::BlockProfile,
    generate: impl FnOnce() -> Result<NativeBlock, stela_compiler::CompileError>,
) -> Result<Prepared> {
    let key = sha256(&serde_json::to_vec(&identity)?);
    std::fs::create_dir_all(root)?;
    let root = root.canonicalize()?;
    let directory = root.join(&key);
    if directory.exists() {
        let manifest = validate(&directory, &identity, memory_requirements, profile)
            .context("refusing invalid cached translation; remove this cache entry to rebuild")?;
        return Ok(Prepared {
            key,
            cache_hit: true,
            directory,
            manifest,
        });
    }
    // Compile before creating an entry. Unsupported code never produces a hit.
    let (manifest, x86_64_code) =
        artifact::prepare::generate(identity.clone(), memory_requirements, generate)?;
    let pending = tempfile::tempdir_in(&root)?;
    let path = pending.path().join("native.bin");
    std::fs::write(&path, &x86_64_code)?;
    write_json(&pending.path().join("manifest.json"), &manifest)?;
    let manifest_hash = sha256(&std::fs::read(pending.path().join("manifest.json"))?);
    write_json(&pending.path().join("manifest.sha256.json"), &manifest_hash)?;
    match std::fs::rename(pending.path(), &directory) {
        Ok(()) => Ok(Prepared {
            key,
            cache_hit: false,
            directory,
            manifest,
        }),
        Err(error) if directory.exists() => {
            let manifest = validate(&directory, &identity, memory_requirements, profile)
                .with_context(|| format!("concurrent cache publication failed: {error}"))?;
            Ok(Prepared {
                key,
                cache_hit: true,
                directory,
                manifest,
            })
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source(value: u32) -> Vec<u8> {
        [0xd2800000 | (value << 5), 0xd65f03c0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect()
    }
    #[test]
    fn cpu_requirements_separate_leaf_and_block_cache_artifacts() -> Result<()> {
        use stela_compiler::{TargetCpu, block::BlockProfile};
        let root = tempfile::tempdir()?;
        let input = source(42);
        let mut keys = std::collections::BTreeSet::new();
        for target in [
            TargetCpu::Baseline,
            TargetCpu::Ssse3,
            TargetCpu::Sse41,
            TargetCpu::Sse42,
        ]
        .into_iter()
        .flat_map(|tier| {
            [
                tier,
                tier.with_pclmulqdq(),
                tier.with_fma(),
                tier.with_pclmulqdq().with_fma(),
                tier.with_f16c(),
                tier.with_pclmulqdq().with_f16c(),
                tier.with_fma().with_f16c(),
                tier.with_pclmulqdq().with_fma().with_f16c(),
            ]
        }) {
            let leaf = prepare_leaf_for_target(&input, GuestAddress(0x1000), root.path(), target)?;
            let block = prepare_block_for_target(
                &input,
                GuestAddress(0x1000),
                root.path(),
                BlockProfile::Ordinary,
                target,
            )?
            .prepared;
            for artifact in [leaf, block] {
                assert_eq!(artifact.manifest.identity.target_cpu, target.id());
                assert!(keys.insert(artifact.key));
            }
            assert!(
                prepare_leaf_for_target(&input, GuestAddress(0x1000), root.path(), target)?
                    .cache_hit
            );
        }
        Ok(())
    }
    #[test]
    fn independent_cpu_requirements_have_distinct_cache_identities() -> Result<()> {
        use stela_compiler::TargetCpu;
        let root = tempfile::tempdir()?;
        let input = source(42);
        let mut keys = std::collections::BTreeSet::new();
        for target in [
            TargetCpu::Baseline,
            TargetCpu::Popcnt,
            TargetCpu::Bmi1,
            TargetCpu::Aes,
            TargetCpu::Sha,
            TargetCpu::Baseline.with_popcnt().with_bmi1(),
            TargetCpu::Baseline.with_aes().with_sha(),
            TargetCpu::Sse42
                .with_pclmulqdq()
                .with_fma()
                .with_f16c()
                .with_popcnt()
                .with_bmi1()
                .with_aes()
                .with_sha(),
        ] {
            let artifact =
                prepare_leaf_for_target(&input, GuestAddress(0x1000), root.path(), target)?;
            assert_eq!(artifact.manifest.identity.target_cpu, target.id());
            assert_eq!(
                artifact
                    .manifest
                    .identity
                    .target_cpu
                    .parse::<TargetCpu>()
                    .unwrap(),
                target
            );
            assert!(keys.insert(artifact.key));
            assert!(
                prepare_leaf_for_target(&input, GuestAddress(0x1000), root.path(), target)?
                    .cache_hit
            );
        }
        Ok(())
    }
    #[test]
    fn clock_profile_cache_isolated_from_both_previous_profiles_and_exact_operands() -> Result<()> {
        use stela_compiler::block::BlockProfile;
        let root = tempfile::tempdir()?;
        let base = GuestAddress(0x1000);
        let profile = BlockProfile::AppleArm64eSoftwarePauthClockV1;
        let ordinary_source = source(42);
        let mut keys = std::collections::BTreeSet::new();
        for selected in [
            BlockProfile::Ordinary,
            BlockProfile::AppleArm64eSoftwarePauthV1,
            profile,
        ] {
            let block = prepare_block_with_profile(&ordinary_source, base, root.path(), selected)?;
            assert_eq!(block.prepared.manifest.identity.abi, selected.abi());
            assert!(keys.insert(block.prepared.key));
        }
        let input: Vec<u8> = [0xd2800020_u32, 0xd53be040, 0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        for previous in [
            BlockProfile::Ordinary,
            BlockProfile::AppleArm64eSoftwarePauthV1,
        ] {
            assert!(prepare_block_with_profile(&input, base, root.path(), previous).is_err());
        }
        let first = prepare_block_with_profile(&input, base, root.path(), profile)?;
        assert_eq!(first.source_bytes, 8);
        assert!(!first.prepared.cache_hit);
        let mut changed = input.clone();
        changed[8..].copy_from_slice(&0xffffffff_u32.to_le_bytes());
        let reused = prepare_block_with_profile(&changed, base, root.path(), profile)?;
        assert!(reused.prepared.cache_hit);
        assert_eq!(first.prepared.key, reused.prepared.key);
        changed[4..8].copy_from_slice(&0xd53be05f_u32.to_le_bytes());
        assert_ne!(
            first.prepared.key,
            prepare_block_with_profile(&changed, base, root.path(), profile)?
                .prepared
                .key
        );
        changed[4..8].copy_from_slice(&0xd5033fdf_u32.to_le_bytes());
        assert_ne!(
            first.prepared.key,
            prepare_block_with_profile(&changed, base, root.path(), profile)?
                .prepared
                .key
        );
        // Shared preparation has no runtime clock, host time query or RX mapping.
        assert!(first.prepared.directory.join("native.bin").is_file());
        Ok(())
    }
    #[test]
    fn pac_profile_cache_identity_is_explicit_and_reuses_only_consumed_prefix() -> Result<()> {
        use stela_compiler::block::BlockProfile;
        let root = tempfile::tempdir()?;
        let base = GuestAddress(0x1000);
        let profile = BlockProfile::AppleArm64eSoftwarePauthV1;
        let ordinary_source = source(42);
        let ordinary = prepare_block(&ordinary_source, base, root.path())?;
        let opted_in = prepare_block_with_profile(&ordinary_source, base, root.path(), profile)?;
        assert_ne!(ordinary.prepared.key, opted_in.prepared.key);
        assert_eq!(
            ordinary.prepared.manifest.identity.abi,
            BlockProfile::Ordinary.abi()
        );
        assert_eq!(opted_in.prepared.manifest.identity.abi, profile.abi());
        assert_eq!(
            ordinary.prepared.manifest.native_sha256,
            opted_in.prepared.manifest.native_sha256
        );
        let source: Vec<u8> = [0xd2800020_u32, 0xd503237f, 0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert!(prepare_block(&source, base, root.path()).is_err());
        let first = prepare_block_with_profile(&source, base, root.path(), profile)?;
        assert_eq!(first.source_bytes, 8);
        assert!(!first.prepared.cache_hit);
        let mut changed_unconsumed = source.clone();
        changed_unconsumed[8..].copy_from_slice(&0xffffffff_u32.to_le_bytes());
        let reused = prepare_block_with_profile(&changed_unconsumed, base, root.path(), profile)?;
        assert!(reused.prepared.cache_hit);
        assert_eq!(first.prepared.key, reused.prepared.key);
        assert_ne!(
            first.prepared.key,
            prepare_block_with_profile(&source, GuestAddress(0x2000), root.path(), profile)?
                .prepared
                .key
        );
        let mut changed_helper = source.clone();
        changed_helper[4..8].copy_from_slice(&0xd50323ff_u32.to_le_bytes());
        assert_ne!(
            first.prepared.key,
            prepare_block_with_profile(&changed_helper, base, root.path(), profile)?
                .prepared
                .key
        );
        // Preparation never maps or invokes the artifact; an intact checksum
        // cannot make metadata from another profile acceptable under this key.
        let mut manifest = first.prepared.manifest;
        manifest.identity.abi = BlockProfile::Ordinary.abi().into();
        write_json(&first.prepared.directory.join("manifest.json"), &manifest)?;
        let hash = sha256(&std::fs::read(
            first.prepared.directory.join("manifest.json"),
        )?);
        write_json(
            &first.prepared.directory.join("manifest.sha256.json"),
            &hash,
        )?;
        assert!(prepare_block_with_profile(&source, base, root.path(), profile).is_err());
        Ok(())
    }
    #[test]
    fn validly_checksummed_legacy_state_abis_are_rejected_without_loading_code() -> Result<()> {
        for (block, legacy_abi) in [
            (false, "x86_64-sysv-guest-state-v2-direct-ram"),
            (true, "x86_64-sysv-guest-state-v1-block-exit-direct-ram"),
        ] {
            let root = tempfile::tempdir()?;
            let input = source(42);
            let current = if block {
                prepare_block(&input, GuestAddress(0x1000), root.path())?.prepared
            } else {
                prepare_leaf(&input, GuestAddress(0x1000), root.path())?
            };
            let mut manifest = current.manifest;
            assert_ne!(manifest.identity.abi, legacy_abi);
            manifest.identity.abi = legacy_abi.into();
            assert_ne!(
                current.key,
                sha256(&serde_json::to_vec(&manifest.identity)?)
            );
            // Model an intact legacy metadata receipt, not simple checksum damage.
            // Neither this test nor preparation maps or invokes the native payload.
            write_json(&current.directory.join("manifest.json"), &manifest)?;
            let metadata = std::fs::read(current.directory.join("manifest.json"))?;
            write_json(
                &current.directory.join("manifest.sha256.json"),
                &sha256(&metadata),
            )?;
            let observed = if block {
                prepare_block(&input, GuestAddress(0x1000), root.path()).map(|p| p.prepared)
            } else {
                prepare_leaf(&input, GuestAddress(0x1000), root.path())
            };
            assert!(observed.is_err());
        }
        Ok(())
    }
    #[test]
    fn old_identity_serialization_and_legacy_deserialization_keep_the_same_key() -> Result<()> {
        let root = tempfile::tempdir()?;
        let prepared = prepare_leaf(&source(42), GuestAddress(0x1000), root.path())?;
        let identity = prepared.manifest.identity;
        assert!(identity.memory_specialization_sha256.is_none());
        let actual = serde_json::to_value(&identity)?;
        let legacy = serde_json::json!({
            "schema_version": identity.schema_version,
            "source_sha256": identity.source_sha256,
            "compiler_source_sha256": identity.compiler_source_sha256,
            "guest_base": identity.guest_base,
            "abi": identity.abi,
            "target_cpu": identity.target_cpu,
        });
        assert_eq!(actual, legacy);
        let restored: Identity = serde_json::from_value(legacy)?;
        assert_eq!(restored, identity);
        assert_eq!(sha256(&serde_json::to_vec(&restored)?), prepared.key);
        Ok(())
    }

    #[test]
    fn mixed_access_specializations_have_distinct_keys_and_exact_cache_reuse() -> Result<()> {
        use stela_compiler::context::memory::address::{
            AccessEl, AddressAddChecks, EffectiveAddressChecks,
        };
        use stela_compiler::{
            TargetCpu,
            block::{BlockProfile, CheckedMemoryProfile},
        };
        const LDR_X0_X9_8: u32 = 0xf940_0520;
        const LDTR_X1_X9_8: u32 = 0xf840_8921;
        const RET_X30: u32 = 0xd65f_03c0;
        const BASE_REGISTER_SHIFT: u32 = 5;
        const REGISTER_FIELD_MASK: u32 = 31;
        let source: Vec<_> = [LDR_X0_X9_8, LDTR_X1_X9_8, RET_X30]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let root = tempfile::tempdir()?;
        let mut keys = std::collections::HashSet::new();
        for stack in [
            CheckedMemoryProfile::SpAlignmentEnabled,
            CheckedMemoryProfile::SpAlignmentDisabled,
        ] {
            // SP is used by the first access so that SA affects compilation.
            let mut source = source.clone();
            let stack_word = (LDR_X0_X9_8 & !(REGISTER_FIELD_MASK << BASE_REGISTER_SHIFT))
                | (REGISTER_FIELD_MASK << BASE_REGISTER_SHIFT);
            source[..size_of::<u32>()].copy_from_slice(&stack_word.to_le_bytes());
            for el0 in [AddressAddChecks::Disabled, AddressAddChecks::Enabled] {
                for el1 in [AddressAddChecks::Disabled, AddressAddChecks::Enabled] {
                    let profile = BlockProfile::CheckedMemory(stack.with_address_checks(
                        AccessEl::El1,
                        AccessEl::El0,
                        EffectiveAddressChecks::new(el0, el1),
                    ));
                    let first = prepare_block_for_target(
                        &source,
                        GuestAddress(0x1000),
                        root.path(),
                        profile,
                        TargetCpu::Baseline,
                    )?;
                    assert!(
                        first
                            .prepared
                            .manifest
                            .identity
                            .memory_specialization_sha256
                            .is_some()
                    );
                    assert_eq!(first.source_bytes, source.len());
                    assert!(keys.insert(first.prepared.key.clone()));
                    let second = prepare_block_for_target(
                        &source,
                        GuestAddress(0x1000),
                        root.path(),
                        profile,
                        TargetCpu::Baseline,
                    )?;
                    assert_eq!(first.prepared.key, second.prepared.key);
                    assert!(second.prepared.cache_hit);
                }
            }
        }
        assert_eq!(keys.len(), 8);
        Ok(())
    }

    #[test]
    fn swapped_source_role_access_levels_cannot_reuse_identical_aggregate_requirements()
    -> Result<()> {
        use stela_compiler::context::memory::address::{
            AccessEl, AddressAddChecks, EffectiveAddressChecks,
        };
        use stela_compiler::{
            TargetCpu,
            block::{BlockProfile, CheckedMemoryProfile, CompilationPlan},
        };
        const LDR_X0_X9_8: u32 = 0xf940_0520;
        const LDTR_X1_X9_8: u32 = 0xf840_8921;
        const RET_X30: u32 = 0xd65f_03c0;
        let source: Vec<_> = [LDR_X0_X9_8, LDTR_X1_X9_8, RET_X30]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let effects =
            EffectiveAddressChecks::new(AddressAddChecks::Disabled, AddressAddChecks::Enabled);
        let profile = |normal, unprivileged| {
            BlockProfile::CheckedMemory(
                CheckedMemoryProfile::SpAlignmentDisabled.with_address_checks(
                    normal,
                    unprivileged,
                    effects,
                ),
            )
        };
        let first_profile = profile(AccessEl::El1, AccessEl::El0);
        let second_profile = profile(AccessEl::El0, AccessEl::El1);
        let first_plan = CompilationPlan::new(
            &source,
            GuestAddress(0x1000),
            first_profile,
            TargetCpu::Baseline,
        )?;
        let second_plan = CompilationPlan::new(
            &source,
            GuestAddress(0x1000),
            second_profile,
            TargetCpu::Baseline,
        )?;
        assert_eq!(
            first_plan.memory_requirements(),
            second_plan.memory_requirements()
        );
        assert_ne!(
            first_plan.compile()?.native.x86_64_code,
            second_plan.compile()?.native.x86_64_code
        );
        let root = tempfile::tempdir()?;
        let first = prepare_block_for_target(
            &source,
            GuestAddress(0x1000),
            root.path(),
            first_profile,
            TargetCpu::Baseline,
        )?;
        let second = prepare_block_for_target(
            &source,
            GuestAddress(0x1000),
            root.path(),
            second_profile,
            TargetCpu::Baseline,
        )?;
        assert_ne!(first.prepared.key, second.prepared.key);
        assert_ne!(
            first
                .prepared
                .manifest
                .identity
                .memory_specialization_sha256,
            second
                .prepared
                .manifest
                .identity
                .memory_specialization_sha256
        );
        for (profile, expected) in [
            (first_profile, first.prepared.key),
            (second_profile, second.prepared.key),
        ] {
            let reused = prepare_block_for_target(
                &source,
                GuestAddress(0x1000),
                root.path(),
                profile,
                TargetCpu::Baseline,
            )?;
            assert_eq!(reused.prepared.key, expected);
            assert!(reused.prepared.cache_hit);
        }
        Ok(())
    }

    #[test]
    fn checksummed_specialized_cache_cannot_drop_its_specialization_identity() -> Result<()> {
        use stela_compiler::context::memory::address::{
            AccessEl, AddressAddChecks, EffectiveAddressChecks,
        };
        use stela_compiler::{
            TargetCpu,
            block::{BlockProfile, CheckedMemoryProfile},
        };
        const LDR_X0_X9_8: u32 = 0xf940_0520;
        const RET_X30: u32 = 0xd65f_03c0;
        let source: Vec<_> = [LDR_X0_X9_8, RET_X30]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let profile = BlockProfile::CheckedMemory(
            CheckedMemoryProfile::SpAlignmentDisabled.with_address_checks(
                AccessEl::El0,
                AccessEl::El0,
                EffectiveAddressChecks::new(AddressAddChecks::Enabled, AddressAddChecks::Disabled),
            ),
        );
        let root = tempfile::tempdir()?;
        let prepared = prepare_block_for_target(
            &source,
            GuestAddress(0x1000),
            root.path(),
            profile,
            TargetCpu::Baseline,
        )?;
        let directory = prepared.prepared.directory;
        let mut manifest = prepared.prepared.manifest;
        assert!(
            manifest
                .identity
                .memory_specialization_sha256
                .take()
                .is_some()
        );
        write_json(&directory.join("manifest.json"), &manifest)?;
        let metadata = std::fs::read(directory.join("manifest.json"))?;
        write_json(&directory.join("manifest.sha256.json"), &sha256(&metadata))?;
        assert!(
            prepare_block_for_target(
                &source,
                GuestAddress(0x1000),
                root.path(),
                profile,
                TargetCpu::Baseline
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn specialization_hash_binds_complete_requirements_and_increment_choice() -> Result<()> {
        use stela_compiler::context::memory::address::{
            AccessEl, AddressAddChecks, AddressCheckRequirements, IncrementChoice,
        };
        use stela_compiler::context::memory::{MemoryRequirements, flags};
        let profile = stela_compiler::block::BlockProfile::CheckedMemory(
            stela_compiler::block::CheckedMemoryProfile::SpAlignmentDisabled.with_address_checks(
                AccessEl::El0,
                AccessEl::El0,
                stela_compiler::context::memory::address::EffectiveAddressChecks::new(
                    AddressAddChecks::Enabled,
                    AddressAddChecks::Disabled,
                ),
            ),
        );
        let required = MemoryRequirements {
            required_address_checks: AddressCheckRequirements::for_access(
                AccessEl::El0,
                AddressAddChecks::Enabled,
            )
            .with_increment_choice(IncrementChoice::Unchecked),
            ..Default::default()
        };
        let original = memory_specialization_sha256(profile, Some(required))?;
        assert!(original.is_some());
        assert_ne!(
            original,
            memory_specialization_sha256(
                profile,
                Some(MemoryRequirements {
                    required_flags: flags::WRITE,
                    ..required
                })
            )?
        );
        assert_ne!(
            original,
            memory_specialization_sha256(
                profile,
                Some(MemoryRequirements {
                    required_address_checks: required
                        .required_address_checks
                        .with_increment_choice(IncrementChoice::Checked),
                    ..required
                })
            )?
        );
        assert!(
            memory_specialization_sha256(
                stela_compiler::block::BlockProfile::Ordinary,
                Some(MemoryRequirements::default())
            )?
            .is_none()
        );
        let legacy = serde_json::json!({
            "required_flags": 0,
            "required_host_caps": 0,
            "required_profile": 0,
            "required_sp_alignment": "Any",
        });
        let mut current = legacy.clone();
        current["context_version"] = serde_json::json!(2);
        assert_eq!(
            serde_json::to_value(MemoryRequirements::default())?,
            current
        );
        let restored: MemoryRequirements = serde_json::from_value(legacy)?;
        assert_eq!(restored.context_version, 0);
        assert!(restored.merge(MemoryRequirements::default()).is_none());
        assert_ne!(
            original,
            memory_specialization_sha256(
                profile,
                Some(MemoryRequirements {
                    context_version: 1,
                    ..required
                })
            )?
        );
        assert_ne!(
            original,
            memory_specialization_sha256(
                profile,
                Some(MemoryRequirements {
                    required_instructions:
                        stela_compiler::context::memory::InstructionRequirements::LSE,
                    ..required
                })
            )?
        );
        Ok(())
    }

    #[test]
    fn intact_old_memory_context_metadata_is_rejected_before_native_payload_read() -> Result<()> {
        use stela_compiler::{
            TargetCpu,
            block::{BlockProfile, CheckedMemoryProfile},
        };
        let source: Vec<_> = [0xf821_0002u32, 0xd65f_03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let profile = BlockProfile::CheckedMemory(CheckedMemoryProfile::SpAlignmentDisabled);
        for version in [None, Some(0), Some(1), Some(3)] {
            let root = tempfile::tempdir()?;
            let prepared = prepare_block_for_target(
                &source,
                GuestAddress(0x1000),
                root.path(),
                profile,
                TargetCpu::Baseline,
            )?;
            let directory = prepared.prepared.directory;
            let mut metadata = serde_json::to_value(prepared.prepared.manifest)?;
            if let Some(version) = version {
                metadata["memory_requirements"]["context_version"] = serde_json::json!(version);
            } else {
                metadata["memory_requirements"]
                    .as_object_mut()
                    .unwrap()
                    .remove("context_version");
            }
            write_json(&directory.join("manifest.json"), &metadata)?;
            let bytes = std::fs::read(directory.join("manifest.json"))?;
            write_json(&directory.join("manifest.sha256.json"), &sha256(&bytes))?;
            // Distinguish metadata refusal from attempting to read/map old code.
            std::fs::remove_file(directory.join("native.bin"))?;
            let error = prepare_block_for_target(
                &source,
                GuestAddress(0x1000),
                root.path(),
                profile,
                TargetCpu::Baseline,
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("memory requirements"),
                "{error:#}"
            );
        }
        Ok(())
    }

    #[test]
    fn oversized_cache_files_are_rejected_before_reading_payloads() -> Result<()> {
        let root = tempfile::tempdir()?;
        let prepared = prepare_leaf(&source(42), GuestAddress(0), root.path())?;
        let native = std::fs::OpenOptions::new()
            .write(true)
            .open(prepared.directory.join("native.bin"))?;
        native.set_len(MAX_CACHE_NATIVE_BYTES as u64 + 1)?;
        assert!(prepare_leaf(&source(42), GuestAddress(0), root.path()).is_err());
        let root = tempfile::tempdir()?;
        let prepared = prepare_leaf(&source(42), GuestAddress(0), root.path())?;
        std::fs::OpenOptions::new()
            .write(true)
            .open(prepared.directory.join("manifest.json"))?
            .set_len(MAX_CACHE_MANIFEST_BYTES as u64 + 1)?;
        assert!(prepare_leaf(&source(42), GuestAddress(0), root.path()).is_err());
        Ok(())
    }
    #[test]
    fn reuses_only_exact_input_and_context_and_rejects_corruption() -> Result<()> {
        let root = tempfile::tempdir()?;
        let first = prepare_leaf(&source(40), GuestAddress(0x1000), root.path())?;
        assert!(!first.cache_hit);
        assert!(prepare_leaf(&source(40), GuestAddress(0x1000), root.path())?.cache_hit);
        assert_ne!(
            first.key,
            prepare_leaf(&source(41), GuestAddress(0x1000), root.path())?.key
        );
        assert_ne!(
            first.key,
            prepare_leaf(&source(40), GuestAddress(0x2000), root.path())?.key
        );
        std::fs::write(first.directory.join("native.bin"), b"changed")?;
        assert!(prepare_leaf(&source(40), GuestAddress(0x1000), root.path()).is_err());
        assert!(prepare_leaf(&[0, 0, 0, 0], GuestAddress(0), root.path()).is_err());
        Ok(())
    }
    #[test]
    fn concurrent_requests_publish_a_complete_single_entry() -> Result<()> {
        let root = tempfile::tempdir()?;
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let path = root.path().to_path_buf();
                std::thread::spawn(move || prepare_leaf(&source(42), GuestAddress(0), &path))
            })
            .collect();
        let results: Vec<_> = threads
            .into_iter()
            .map(|t| t.join().unwrap().unwrap())
            .collect();
        assert!(results.iter().all(|r| r.key == results[0].key));
        assert_eq!(std::fs::read_dir(root.path())?.count(), 1);
        Ok(())
    }
}
