//! Context-bound admission for actual source-enabled station radio work.
//!
//! This permission does not authenticate a peer, open the controlled port,
//! install keys or bypass per-MPDU/replay checks. Native packet owners must
//! independently retain and validate those exact existing capabilities.

use super::{Error, HardwareLease, HardwarePolicy, OsLease, OsPolicy, Owner};
use crate::net::wifi::station::{AssociationContext, Phase, Station};
use alloc::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssociationUse {
    /// Enable/configure the complete context, including autonomous responses.
    Configure,
    Management,
    Data,
}

/// Exact borrowed profile for providers to qualify; this is not a permit.
/// Providers must inspect the complete enabled source envelope, including basic
/// rates and autonomous responses, not just the selected width/MCS or one MPDU.
#[derive(Debug)]
pub struct AssociationOperation<'a> {
    context: &'a AssociationContext,
    purpose: AssociationUse,
}
impl AssociationOperation<'_> {
    pub fn context(&self) -> &AssociationContext {
        self.context
    }
    pub const fn purpose(&self) -> AssociationUse {
        self.purpose
    }
}

/// A private, single-use preflight result retaining the exact current context.
/// Publication must reacquire both real providers and revalidate station state.
///
/// ```compile_fail
/// use stela_drivers::net::wifi::regulatory::AssociationAdmission;
/// let admission = AssociationAdmission { owner: 1 };
/// ```
#[derive(Debug)]
pub struct AssociationAdmission {
    owner: u64,
    native: super::NativeContext,
    os_revision: u64,
    context: Arc<AssociationContext>,
    purpose: AssociationUse,
}
impl AssociationAdmission {
    pub fn operation(&self) -> AssociationOperation<'_> {
        AssociationOperation {
            context: &self.context,
            purpose: self.purpose,
        }
    }
}

fn current(station: &Station, operation: &AssociationOperation<'_>) -> Result<(), Error> {
    station
        .validate_association_context(operation.context)
        .map_err(|_| Error::Stale)?;
    let required = match operation.purpose {
        AssociationUse::Configure => Phase::Configuring,
        AssociationUse::Management | AssociationUse::Data => Phase::Associated,
    };
    if station.phase() != required {
        return Err(Error::Mismatch);
    }
    Ok(())
}

fn check(
    hardware: &mut impl HardwareLease,
    os: &mut impl OsLease,
    operation: &AssociationOperation<'_>,
) -> Result<(), Error> {
    let channel = operation.context.channel();
    if hardware.lookup_channel(channel.band, channel.number) != Some(channel)
        || !hardware.allows_association(operation)
    {
        return Err(Error::HardwareDenied);
    }
    if !os.allows_association(operation) {
        return Err(Error::OsDenied);
    }
    Ok(())
}

impl<H: HardwarePolicy, O: OsPolicy> Owner<H, O> {
    /// Check actual current context identity, phase and the entire enabled
    /// profile with both genuine providers. No native effects occur here.
    pub fn admit_association(
        &mut self,
        station: &Station,
        context: Arc<AssociationContext>,
        purpose: AssociationUse,
    ) -> Result<AssociationAdmission, Error> {
        let operation = AssociationOperation {
            context: &context,
            purpose,
        };
        current(station, &operation)?;
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = hardware.context();
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        check(&mut hardware, &mut os, &operation)?;
        Ok(AssociationAdmission {
            owner: self.identity,
            native,
            os_revision: os.revision(),
            context,
            purpose,
        })
    }

    /// Recheck the exact context and purpose at native publication, holding the
    /// immutable station plus hardware then OS guards through `submit`.
    /// Closure return is not command ACK, association success, air completion or
    /// retirement. Keep the context/policy/key/queue alive through actual native
    /// completions and uncertainty; revocation must disable/drain or enforce
    /// restrictions on previously armed/queued autonomous and packet work.
    ///
    /// # Safety
    /// Submit must use this concrete guard's same retained physical controller
    /// and encode only this exact context/purpose through its actual qualified
    /// source path. It must not defer publication beyond the held guards, target
    /// another device, substitute legacy commands, or widen enabled effects.
    /// The backend must preserve the providers' revocation/stop/drain contract
    /// after return. Failed/uncertain publication does not authorize success.
    pub unsafe fn publish_association<'a, T>(
        &'a mut self,
        admission: AssociationAdmission,
        station: &Station,
        purpose: AssociationUse,
        submit: impl FnOnce(&mut H::Lease<'a>, &AssociationOperation<'_>) -> T,
    ) -> Result<T, Error> {
        if admission.owner != self.identity {
            return Err(Error::Stale);
        }
        if admission.purpose != purpose {
            return Err(Error::Mismatch);
        }
        let operation = admission.operation();
        current(station, &operation)?;
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = hardware.context();
        if admission.native != native {
            return Err(Error::Stale);
        }
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        if admission.os_revision != os.revision() {
            return Err(Error::Stale);
        }
        check(&mut hardware, &mut os, &operation)?;
        let result = submit(&mut hardware, &operation);
        drop(os);
        drop(hardware);
        Ok(result)
    }
}
