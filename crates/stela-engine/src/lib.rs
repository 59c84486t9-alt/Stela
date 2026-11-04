//! Execution of translated ARM64 code: the native code cache, block dispatch,
//! guest memory and system state.
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, string::String};
#[macro_use]
extern crate alloc;
#[cfg(all(not(feature = "std"), not(panic = "abort")))]
compile_error!(
    "freestanding runtime requires aborting panic; platform must terminate the machine on panic"
);
/// Defines a function translated code calls. That code follows
/// `extern "sysv64"`, which only x86-64 has; other hosts never run it and
/// keep the function for its type alone.
macro_rules! translated_callee {
    ($(#[$meta:meta])* $vis:vis fn $($rest:tt)*) => {
        #[cfg(target_arch = "x86_64")]
        $(#[$meta])* $vis extern "sysv64" fn $($rest)*
        #[cfg(not(target_arch = "x86_64"))]
        $(#[$meta])* $vis extern "C" fn $($rest)*
    };
    ($(#[$meta:meta])* $vis:vis unsafe fn $($rest:tt)*) => {
        #[cfg(target_arch = "x86_64")]
        $(#[$meta])* $vis unsafe extern "sysv64" fn $($rest)*
        #[cfg(not(target_arch = "x86_64"))]
        $(#[$meta])* $vis unsafe extern "C" fn $($rest)*
    };
}

pub mod amx;
mod error;
#[cfg(feature = "std")]
use error::Io;
pub use error::{Error, Result};
use stela_contracts::refuse;
#[cfg(feature = "std")]
use stela_contracts::require;
pub mod blocks;
#[cfg(feature = "std")]
pub mod dispatch;
pub mod execution;
mod floating;
#[cfg(feature = "std")]
mod json;
pub mod machine;
pub mod memory;
pub mod pauth;
pub mod platform;
#[cfg(all(target_arch = "x86_64", target_os = "uefi", not(feature = "std")))]
pub mod freestanding {
    pub use crate::platform::boot::BootArena;
}
/// Destination-local stable CPU declaration ownership for native system Hosts.
pub use platform::cpu::system::{NativeCpuError, NativeCpuLease, NativeCpuOwner};
pub mod scalable;
pub mod system;
pub mod translations;
#[cfg(feature = "std")]
pub use json::{read_json, write_json};
use serde::Serialize;
#[cfg(feature = "std")]
use std::io::Read;
#[cfg(feature = "std")]
use std::path::{Path, PathBuf};
use stela_compiler::GuestAddress;
#[cfg(feature = "std")]
use stela_compiler::NativeBlock;
use stela_formats::sha256;

fn compiler_source_sha256() -> &'static str {
    stela_compiler::SOURCE_SHA256
}

#[cfg(feature = "std")]
use artifact::prepare::{MAX_CACHE_MANIFEST_BYTES, MAX_CACHE_NATIVE_BYTES};

#[cfg(feature = "std")]
fn bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).io("open a cache file")?;
    let size = file.metadata().io("read a cache file's size")?.len();
    require!(size <= limit as u64, "cache file exceeds size limit", limit);
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size as usize)?;
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .io("read a cache file")?;
    require!(bytes.len() <= limit, "cache file grew beyond size limit");
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
    let required = requirements.ok_or(refuse!("specialized checked plan requirements absent"))?;
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
) -> Result<(Manifest, Vec<u8>)> {
    let manifest_bytes = bounded_file(&directory.join("manifest.json"), MAX_CACHE_MANIFEST_BYTES)?;
    let expected: String = serde_json::from_slice(&bounded_file(
        &directory.join("manifest.sha256.json"),
        1024,
    )?)?;
    artifact::prepare::validate_manifest_bytes(&manifest_bytes, &expected)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    require!(
        manifest.identity.memory_specialization_sha256
            == memory_specialization_sha256(profile, manifest.memory_requirements)?,
        "cached memory specialization differs from complete requirements"
    );
    artifact::prepare::validate_preparation_metadata(&manifest, identity, memory_requirements)?;
    let native = bounded_file(&directory.join("native.bin"), MAX_CACHE_NATIVE_BYTES)?;
    artifact::prepare::validate_preparation_native(&manifest, &native)?;
    artifact::prepare::validate_preparation_claim(&manifest)?;
    Ok((manifest, native))
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
    use stela_compiler::block::{BlockProfile, Features};
    let profile = BlockProfile::new(Features::LEAF);
    let identity = Identity {
        schema_version: 1,
        source_sha256: sha256(source),
        compiler_source_sha256: compiler_source_sha256().to_owned(),
        guest_base: base.0,
        abi: profile.abi(),
        target_cpu: target.id(),
        memory_specialization_sha256: None,
    };
    prepare(identity, root, None, profile, || {
        stela_compiler::compile(source, base, &stela_compiler::Options::new(profile, target))
            .map(|block| block.native)
    })
    .map(|(prepared, _)| prepared)
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
        stela_compiler::block::BlockProfile::ORDINARY,
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
    let plan = stela_compiler::block::CompilationPlan::new(
        source,
        base,
        &stela_compiler::Options::new(profile, target),
    )?;
    let source_bytes = plan.source_bytes();
    let (prepared, _) = prepare_block_plan(source, base, root, target, plan)?;
    Ok(PreparedBlock {
        source_bytes,
        prepared,
    })
}

#[cfg(feature = "std")]
fn prepare_block_plan(
    source: &[u8],
    base: GuestAddress,
    root: &Path,
    target: stela_compiler::TargetCpu,
    plan: stela_compiler::block::CompilationPlan,
) -> Result<(Prepared, Vec<u8>)> {
    let profile = plan.profile();
    let memory_requirements = plan.memory_requirements();
    let identity = block_plan_identity(source, base, target, &plan)?;
    prepare(identity, root, memory_requirements, profile, || {
        plan.compile().map(|b| b.native)
    })
}

// Identity derived from the source plan, shared by native preparation and AOT
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
        abi: profile.abi(),
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
) -> Result<(Prepared, Vec<u8>)> {
    let key = sha256(&serde_json::to_vec(&identity)?);
    if !root.is_dir() {
        std::fs::create_dir_all(root).io("create the translation cache")?;
    }
    let root = root.canonicalize().io("resolve the translation cache")?;
    let directory = root.join(&key);
    let invalid = |cause| Error::InvalidCacheEntry {
        directory: directory.clone(),
        cause: alloc::boxed::Box::new(cause),
    };
    if directory.exists() {
        let (manifest, native) =
            validate(&directory, &identity, memory_requirements, profile).map_err(invalid)?;
        return Ok((
            Prepared {
                key,
                cache_hit: true,
                directory,
                manifest,
            },
            native,
        ));
    }
    // Compile before creating an entry. Unsupported code never produces a hit.
    let (manifest, x86_64_code) =
        artifact::prepare::generate(identity.clone(), memory_requirements, generate)?;
    let pending = tempfile::tempdir_in(&root).io("create a pending cache entry")?;
    let path = pending.path().join("native.bin");
    std::fs::write(&path, &x86_64_code).io("write generated code")?;
    // The pending directory is private until the publication rename, so its
    // files can be written directly. Hash the same bytes that go to disk.
    let manifest_bytes = json::pretty_bytes(&manifest)?;
    let manifest_hash = sha256(&manifest_bytes);
    std::fs::write(pending.path().join("manifest.json"), manifest_bytes)
        .io("write a generated manifest")?;
    std::fs::write(
        pending.path().join("manifest.sha256.json"),
        json::pretty_bytes(&manifest_hash)?,
    )
    .io("write a generated manifest checksum")?;
    match std::fs::rename(pending.path(), &directory) {
        Ok(()) => {
            // The complete directory moved to its published name.
            drop(pending.keep());
            Ok((
                Prepared {
                    key,
                    cache_hit: false,
                    directory,
                    manifest,
                },
                x86_64_code,
            ))
        }
        // Another process published the same entry first; it must validate.
        Err(_) if directory.exists() => {
            let (manifest, native) =
                validate(&directory, &identity, memory_requirements, profile).map_err(invalid)?;
            Ok((
                Prepared {
                    key,
                    cache_hit: true,
                    directory,
                    manifest,
                },
                native,
            ))
        }
        Err(error) => Err(Error::Io {
            operation: "publish a cache entry".into(),
            error,
        }),
    }
}

#[cfg(test)]
mod tests;
