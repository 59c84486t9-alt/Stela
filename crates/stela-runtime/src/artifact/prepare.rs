//! Byte and metadata validation shared by the hosted cache and boot artifacts.
use super::{ArtifactError, Identity, Manifest, validate_native_snapshot};
use stela_compiler::context::memory::MemoryRequirements;

pub(crate) const MAX_CACHE_NATIVE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_CACHE_MANIFEST_BYTES: usize = 64 * 1024 * 1024;

/// The one path that generates native code and its manifest, for hosted cache
/// misses and freestanding preparation alike. Unsupported source is reported
/// before anything is cached or mapped.
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
        native_sha256: crate::sha256(&x86_64_code),
        native_bytes: x86_64_code.len(),
        source_map,
        verified: false,
        memory_requirements,
    };
    Ok((manifest, x86_64_code))
}

/// Validate the serialized manifest bytes before they are decoded.
pub(crate) fn validate_manifest_bytes(
    manifest_bytes: &[u8],
    expected_sha256: &str,
) -> Result<(), ArtifactError> {
    if manifest_bytes.len() > MAX_CACHE_MANIFEST_BYTES {
        return Err(ArtifactError("cache file exceeds size limit"));
    }
    if crate::sha256(manifest_bytes) != expected_sha256 {
        return Err(ArtifactError("cached manifest checksum mismatch"));
    }
    Ok(())
}

/// Validate decoded metadata before reading the native bytes, keeping the
/// hosted path's error and I/O order.
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

/// Validate the native bytes against their snapshot. The caller adds the
/// "cached native code checksum mismatch" context; metadata is checked
/// afterwards, keeping the error order.
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
