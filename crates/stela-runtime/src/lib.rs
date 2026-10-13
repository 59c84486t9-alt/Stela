//! Persistent AOT storage and serialized native leaf/basic-block execution.
//! Full application launch, platform ABI and Mach-O linking remain future work.
pub mod blocks;
pub mod clock;
pub mod commpage;
pub mod darwin;
pub mod dispatch;
pub mod execution;
pub mod mach;
pub mod memory;
pub mod pauth;
pub mod process;
pub mod thread;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use stela_compiler::{GuestAddress, NATIVE_ABI, NativeBlock};
use stela_core::{sha256, write_json};

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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub identity: Identity,
    pub native_sha256: String,
    pub native_bytes: usize,
    pub source_map: Vec<(GuestAddress, usize)>,
    pub verified: bool,
}

#[derive(Debug, Serialize)]
pub struct Prepared {
    pub key: String,
    pub cache_hit: bool,
    pub directory: PathBuf,
    pub manifest: Manifest,
}

fn validate(directory: &Path, identity: &Identity) -> Result<Manifest> {
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
        compiler_source_sha256: sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
        guest_base: base.0,
        abi: NATIVE_ABI.into(),
        target_cpu: target.id().into(),
    };
    prepare(identity, root, || {
        stela_compiler::compile_for_target(source, base, target)
    })
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
    let source_bytes = block::source_bytes_with_profile(source, base, profile)?;
    let prefix = &source[..source_bytes];
    let identity = Identity {
        schema_version: 1,
        source_sha256: sha256(prefix),
        compiler_source_sha256: sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
        guest_base: base.0,
        abi: profile.abi().into(),
        target_cpu: target.id().into(),
    };
    let prepared = prepare(identity, root, || {
        block::compile_for_target(prefix, base, profile, target).map(|b| b.native)
    })?;
    Ok(PreparedBlock {
        source_bytes,
        prepared,
    })
}

fn prepare(
    identity: Identity,
    root: &Path,
    generate: impl FnOnce() -> Result<NativeBlock, stela_compiler::CompileError>,
) -> Result<Prepared> {
    let key = sha256(&serde_json::to_vec(&identity)?);
    std::fs::create_dir_all(root)?;
    let root = root.canonicalize()?;
    let directory = root.join(&key);
    if directory.exists() {
        let manifest = validate(&directory, &identity)
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
            let manifest = validate(&directory, &identity)
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
        .flat_map(|tier| [tier, tier.with_pclmulqdq()])
        {
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
