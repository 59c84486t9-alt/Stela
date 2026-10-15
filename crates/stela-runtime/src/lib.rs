//! Persistent AOT storage and serialized native leaf/basic-block execution.
//! Full application launch, platform ABI and Mach-O linking remain future work.
pub mod blocks;
pub mod clock;
pub mod commpage;
pub mod darwin;
pub mod dispatch;
pub mod execution;
mod floating;
pub mod mach;
pub mod memory;
pub mod pauth;
pub mod process;
pub mod scalable;
pub mod system;
pub mod thread;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use stela_compiler::{GuestAddress, NATIVE_ABI, NativeBlock};
use stela_core::{sha256, write_json};

// The compiler material is immutable for this executable. Reuse its exact
// digest across preparation and loading without weakening artifact validation.
fn compiler_source_sha256() -> &'static str {
    static FINGERPRINT: OnceLock<String> = OnceLock::new();
    FINGERPRINT.get_or_init(|| sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()))
}

const MAX_CACHE_NATIVE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CACHE_MANIFEST_BYTES: usize = 64 * 1024 * 1024;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub schema_version: u32,
    pub source_sha256: String,
    pub compiler_source_sha256: String,
    pub guest_base: u64,
    pub abi: String,
    pub target_cpu: String,
    /// Compiler specialization identity; never runtime authority or secret state.
    /// Absent for old profiles, preserving their exact serialized cache key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_specialization_sha256: Option<String>,
}

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

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub identity: Identity,
    pub native_sha256: String,
    pub native_bytes: usize,
    pub source_map: Vec<(GuestAddress, usize)>,
    pub verified: bool,
    /// None is legacy absent metadata; Some(empty) is a checked pure body.
    #[serde(default)]
    pub memory_requirements: Option<stela_compiler::context::memory::MemoryRequirements>,
}

#[derive(Debug, Serialize)]
pub struct Prepared {
    pub key: String,
    pub cache_hit: bool,
    pub directory: PathBuf,
    pub manifest: Manifest,
}

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
    ensure!(
        sha256(&manifest_bytes) == expected,
        "cached manifest checksum mismatch"
    );
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    ensure!(
        manifest.identity.memory_specialization_sha256
            == memory_specialization_sha256(profile, manifest.memory_requirements)?,
        "cached memory specialization differs from complete requirements"
    );
    ensure!(
        manifest.memory_requirements == memory_requirements,
        "cached memory requirements differ from freshly decoded source"
    );
    ensure!(
        manifest.identity == *identity,
        "cached source/compiler/ABI identity mismatch"
    );
    ensure!(
        manifest.native_bytes > 0 && manifest.native_bytes <= MAX_CACHE_NATIVE_BYTES,
        "invalid cached native code size"
    );
    let native = bounded_file(&directory.join("native.bin"), MAX_CACHE_NATIVE_BYTES)?;
    ensure!(
        native.len() == manifest.native_bytes && sha256(&native) == manifest.native_sha256,
        "cached native code checksum mismatch"
    );
    ensure!(
        !manifest.verified,
        "cache metadata cannot attest to verification"
    );
    Ok(manifest)
}

pub fn prepare_leaf(source: &[u8], base: GuestAddress, root: &Path) -> Result<Prepared> {
    prepare_leaf_for_target(source, base, root, stela_compiler::TargetCpu::detect())
}
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
pub fn prepare_block_for_target(
    source: &[u8],
    base: GuestAddress,
    root: &Path,
    profile: stela_compiler::block::BlockProfile,
    target: stela_compiler::TargetCpu,
) -> Result<PreparedBlock> {
    use stela_compiler::block;
    let plan = block::CompilationPlan::new(source, base, profile, target)?;
    let source_bytes = plan.source_bytes();
    let memory_requirements = plan.memory_requirements();
    let prefix = &source[..source_bytes];
    let identity = Identity {
        schema_version: 1,
        source_sha256: sha256(prefix),
        compiler_source_sha256: compiler_source_sha256().to_owned(),
        guest_base: base.0,
        abi: profile.abi().into(),
        target_cpu: target.id(),
        memory_specialization_sha256: memory_specialization_sha256(profile, memory_requirements)?,
    };
    let prepared = prepare(identity, root, memory_requirements, profile, || {
        plan.compile().map(|b| b.native)
    })?;
    Ok(PreparedBlock {
        source_bytes,
        prepared,
    })
}

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
    let NativeBlock {
        x86_64_code,
        source_map,
    } = generate()?;
    ensure!(
        !x86_64_code.is_empty() && x86_64_code.len() <= MAX_CACHE_NATIVE_BYTES,
        "generated code exceeds cache size limit"
    );
    let pending = tempfile::tempdir_in(&root)?;
    let manifest = Manifest {
        identity: identity.clone(),
        native_sha256: sha256(&x86_64_code),
        native_bytes: x86_64_code.len(),
        source_map,
        verified: false,
        memory_requirements,
    };
    let path = pending.path().join("native.bin");
    std::fs::write(&path, &x86_64_code)?;
    std::fs::File::open(path)?.sync_all()?;
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
            // SP is explicitly used by the first access to make SA compile-affecting.
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
        assert_eq!(serde_json::to_value(MemoryRequirements::default())?, legacy);
        let restored: MemoryRequirements = serde_json::from_value(legacy)?;
        assert_eq!(restored, MemoryRequirements::default());
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
