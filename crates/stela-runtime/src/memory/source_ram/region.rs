//! Initialization of a declared physical RAM region; the file extent may be
//! shorter than the region.
use super::{PhysicalRamRange, SourceRamBuildError, SourceRamPermissions};
use alloc::{string::String, vec::Vec};

/// A cold allocation zeroes the region, then loads this file prefix; a warm
/// reset reloads only the prefix.
pub struct InitializedRamRegion {
    pub range: PhysicalRamRange,
    pub file_prefix: Vec<u8>,
    pub file_sha256: String,
    pub permissions: SourceRamPermissions,
}
impl InitializedRamRegion {
    pub(super) fn validate(&self) -> Result<(), SourceRamBuildError> {
        super::end(self.range)?;
        if self.file_prefix.is_empty() || self.file_prefix.len() as u64 > self.range.bytes {
            return Err(SourceRamBuildError::Declaration(
                "file prefix exceeds declared RAM region",
            ));
        }
        if stela_core::sha256(&self.file_prefix) != self.file_sha256 {
            return Err(SourceRamBuildError::Declaration(
                "RAM file prefix hash differs",
            ));
        }
        if !self.permissions.readable || !self.permissions.writable {
            return Err(SourceRamBuildError::Declaration(
                "reloadable RAM region requires read/write rights",
            ));
        }
        Ok(())
    }
}
