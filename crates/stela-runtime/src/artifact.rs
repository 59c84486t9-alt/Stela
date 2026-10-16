//! Compiled artifact data and its byte and source-map integrity checks.
pub(crate) mod prepare;

extern crate alloc;
use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};
use stela_compiler::GuestAddress;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub schema_version: u32,
    pub source_sha256: String,
    pub compiler_source_sha256: String,
    pub guest_base: u64,
    pub abi: String,
    pub target_cpu: String,
    /// Compiler specialization identity. Absent for older profiles, which keeps
    /// their serialized cache key unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_specialization_sha256: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

/// Actual loaded artifact data. Host cache paths and cache-hit bookkeeping are
/// preparation details, not retained native/source ownership or entry grants.
/// Actual loaders bind native bytes before retaining this descriptive container.
/// This data is not a nonforgeable capability; source/PE owners remain mandatory.
#[derive(Debug)]
pub(crate) struct LoadedArtifact {
    pub(crate) manifest: Manifest,
}
impl LoadedArtifact {
    pub(crate) fn bind(manifest: Manifest, native: &[u8]) -> Result<Self, ArtifactError> {
        validate_native_snapshot(&manifest, native)?;
        Ok(Self { manifest })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArtifactError(&'static str);
impl core::fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.0)
    }
}
impl core::error::Error for ArtifactError {}

pub(crate) fn validate_native_snapshot(
    manifest: &Manifest,
    native: &[u8],
) -> Result<(), ArtifactError> {
    if native.len() != manifest.native_bytes || stela_core::sha256(native) != manifest.native_sha256
    {
        return Err(ArtifactError("native snapshot checksum mismatch"));
    }
    Ok(())
}

/// The first offset is the size of the ABI wrapper. This checks the map's
/// geometry only; the caller binds it to the source, compiler and profile.
pub(crate) fn validate_source_map(
    manifest: &Manifest,
    base: GuestAddress,
    source_bytes: usize,
    first_native_offset: usize,
) -> Result<(), ArtifactError> {
    if manifest.verified || manifest.source_map.len() != source_bytes / 4 {
        return Err(ArtifactError(
            "invalid block source map length or verification claim",
        ));
    }
    let mut prior = None;
    for (index, &(guest, native)) in manifest.source_map.iter().enumerate() {
        let expected = base
            .0
            .checked_add(index as u64 * 4)
            .ok_or(ArtifactError("source map address overflow"))?;
        if guest.0 != expected {
            return Err(ArtifactError("block source map guest mismatch"));
        }
        if native >= manifest.native_bytes
            || !prior.is_none_or(|old| native > old)
            || (index == 0 && native != first_native_offset)
        {
            return Err(ArtifactError("invalid block native source map offset"));
        }
        prior = Some(native);
    }
    Ok(())
}
