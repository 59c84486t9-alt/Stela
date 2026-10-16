//! The identification and security choice of a new software PE. Advertising
//! a feature in it does not implement that feature.
use crate::system::identification_snapshot::{Origin, Snapshot};
use alloc::sync::Arc;
use anyhow::{Result, ensure};

/// An implementation choice; ID and control checks still apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareEl1Security {
    NonSecureOnly,
}

/// Identification registers consumed when a machine is created. ID bits do
/// not create key, interrupt, debug, RAS, trace or device resources.
#[derive(Debug)]
pub struct SoftwareEl1Declaration {
    identification: Arc<Snapshot>,
    security: SoftwareEl1Security,
}
impl SoftwareEl1Declaration {
    pub fn new(identification: Arc<Snapshot>, security: SoftwareEl1Security) -> Result<Self> {
        ensure!(
            identification.provenance().origin() == Origin::DeclaredGuest,
            "fresh software EL1 requires declared guest identification"
        );
        Ok(Self {
            identification,
            security,
        })
    }

    /// The declared identification registers.
    pub fn identification(&self) -> &Snapshot {
        &self.identification
    }

    pub(in crate::blocks::retirement::checked) fn into_parts(
        self,
    ) -> (Arc<Snapshot>, SoftwareEl1Security) {
        (self.identification, self.security)
    }
}

#[cfg(test)]
mod tests;
