//! Byte and metadata validation shared by hosted cache and boot artifact intake.
//! Inputs are descriptive data. These checks mint no source, PE or RX authority.
//! Expected identity/requirements still come from the SAME CompilationPlan and
//! actual source owner. JSON decoding and source-map geometry remain original.
use super::{ArtifactError, Identity, Manifest, validate_native_snapshot};
use stela_compiler::context::memory::MemoryRequirements;

pub(crate) const MAX_CACHE_NATIVE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_CACHE_MANIFEST_BYTES: usize = 64 * 1024 * 1024;

/// The one native-generation and standard-manifest path for both hosted cache
/// misses and freestanding in-memory preparation. It has no filesystem, source
/// admission, RX mapping or execution authority. Unsupported source is returned
/// before any persistent cache entry or native mapping can be published.
pub(crate) fn generate(
    identity: Identity,
    memory_requirements: Option<MemoryRequirements>,
    compile: impl FnOnce() -> Result<stela_compiler::NativeBlock, stela_compiler::CompileError>,
) -> anyhow::Result<(Manifest, alloc::vec::Vec<u8>)> {
    let stela_compiler::NativeBlock {
        x86_64_code,
        source_map,
    } = compile()?;
    anyhow::ensure!(
        !x86_64_code.is_empty() && x86_64_code.len() <= MAX_CACHE_NATIVE_BYTES,
        "generated code exceeds cache size limit"
    );
    let manifest = Manifest {
        identity,
        native_sha256: stela_core::sha256(&x86_64_code),
        native_bytes: x86_64_code.len(),
        source_map,
        verified: false,
        memory_requirements,
    };
    Ok((manifest, x86_64_code))
}

/// Validate exact serialized manifest bytes before the existing codec decodes
/// them. This checksum does not associate a separately supplied typed Manifest
/// with those bytes; the actual byte provider must retain that codec association.
pub(crate) fn validate_manifest_bytes(
    manifest_bytes: &[u8],
    expected_sha256: &str,
) -> Result<(), ArtifactError> {
    if manifest_bytes.len() > MAX_CACHE_MANIFEST_BYTES {
        return Err(ArtifactError("cache file exceeds size limit"));
    }
    if stela_core::sha256(manifest_bytes) != expected_sha256 {
        return Err(ArtifactError("cached manifest checksum mismatch"));
    }
    Ok(())
}

/// Validate the actual decoded metadata BEFORE opening/reading native bytes.
/// This preserves the original hosted refusal and I/O order. It neither decodes
/// source nor chooses an ABI/profile; the original compiler/source owner does.
pub(crate) fn validate_preparation_metadata(
    manifest: &Manifest,
    identity: &Identity,
    memory_requirements: Option<MemoryRequirements>,
) -> Result<(), ArtifactError> {
    if manifest.memory_requirements != memory_requirements {
        return Err(ArtifactError(
            "cached memory requirements differ from freshly decoded source",
        ));
    }
    if manifest.identity != *identity {
        return Err(ArtifactError(
            "cached source/compiler/ABI identity mismatch",
        ));
    }
    if manifest.native_bytes == 0 || manifest.native_bytes > MAX_CACHE_NATIVE_BYTES {
        return Err(ArtifactError("invalid cached native code size"));
    }
    Ok(())
}

/// Bind exact bounded native bytes through the ORIGINAL snapshot validator.
/// The caller retains the original "cached native code checksum mismatch"
/// context for this function's native-snapshot error. Verified metadata is
/// checked separately afterwards, preserving the original error ordering.
pub(crate) fn validate_preparation_native(
    manifest: &Manifest,
    native: &[u8],
) -> Result<(), ArtifactError> {
    if native.len() > MAX_CACHE_NATIVE_BYTES {
        return Err(ArtifactError("cache file exceeds size limit"));
    }
    validate_native_snapshot(manifest, native)
}

pub(crate) fn validate_preparation_claim(manifest: &Manifest) -> Result<(), ArtifactError> {
    if manifest.verified {
        return Err(ArtifactError(
            "cache metadata cannot attest to verification",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
