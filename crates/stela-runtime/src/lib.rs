//! Execution of translated ARM64 code: the native code cache, block dispatch,
//! guest memory, system state and Darwin services.
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, string::String};
#[macro_use]
extern crate alloc;
#[cfg(all(not(feature = "std"), not(panic = "abort")))]
compile_error!(
    "freestanding runtime requires aborting panic; platform must terminate the machine on panic"
);
pub mod blocks;
pub mod clock;
pub mod commpage;
pub mod darwin;
#[cfg(feature = "std")]
pub mod dispatch;
pub mod execution;
mod floating;
pub mod mach;
pub mod memory;
pub mod pauth;
mod platform;
#[cfg(all(target_arch = "x86_64", target_os = "none", not(feature = "std")))]
pub mod freestanding {
    pub use crate::execution::boot_frames::FrameError as BootStorageError;
    pub use crate::platform::boot::{BootArena, CpuObservation, MountError, install, verify};
}
pub mod process;
pub mod scalable;
pub mod system;
pub mod thread;
#[cfg(feature = "std")]
use anyhow::ensure;
use anyhow::{Context, Result};
use serde::Serialize;
#[cfg(feature = "std")]
use std::io::Read;
#[cfg(feature = "std")]
use std::path::{Path, PathBuf};
use stela_compiler::GuestAddress;
#[cfg(feature = "std")]
use stela_compiler::{NATIVE_ABI, NativeBlock};
use stela_core::sha256;
#[cfg(feature = "std")]
use stela_core::write_json;

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

/// Ordinary dispatch may select a source-derived resident ABI; explicit service
/// profiles retain their existing call and recovery contracts.
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

// Descriptive identity from the SAME immutable source plan, shared by hosted
// preparation and existing-format AOT intake. This mints no execution authority.
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
mod tests;
