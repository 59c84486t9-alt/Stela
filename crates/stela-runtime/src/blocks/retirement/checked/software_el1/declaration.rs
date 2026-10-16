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
mod tests {
    use super::*;
    use crate::system::identification::Register;

    #[test]
    fn declaration_retains_one_allocation_and_missing_fields() {
        let original = Arc::new(
            Snapshot::declared("owned-declaration-test", &[(Register::IdAa64Isar1El1, 0)]).unwrap(),
        );
        let declared =
            SoftwareEl1Declaration::new(Arc::clone(&original), SoftwareEl1Security::NonSecureOnly)
                .unwrap();
        assert!(declared.identification().same_snapshot(&original));
        assert!(
            declared
                .identification()
                .read(Register::IdAa64Pfr0El1)
                .is_err()
        );
        let (retained, security) = declared.into_parts();
        assert!(Arc::ptr_eq(&original, &retained));
        assert_eq!(security, SoftwareEl1Security::NonSecureOnly);
    }

    #[test]
    fn fresh_declaration_refuses_a_captured_origin_instead_of_adopting_it() {
        let bytes: Arc<[u8]> = 0_u64.to_le_bytes().to_vec().into();
        let captured = Arc::new(
            Snapshot::captured("origin-test-only", bytes, &[(Register::IdAa64Isar1El1, 0)])
                .unwrap(),
        );
        assert!(SoftwareEl1Declaration::new(captured, SoftwareEl1Security::NonSecureOnly).is_err());
    }
}
