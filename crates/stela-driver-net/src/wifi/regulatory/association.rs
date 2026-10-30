//! Context-bound admission for source-enabled station radio work.
//!
//! This permission does not authenticate a peer, open the controlled port,
//! install keys or bypass per-MPDU/replay checks. Native packet owners must
//! independently keep and validate those exact existing capabilities.

use super::{Error, HardwareLease, HardwarePolicy, OsLease, OsPolicy, Owner};
use crate::wifi::Channel;
use crate::wifi::station::{
    AssociationContext, Phase, Station, operations::ChannelDefinition, phy::AccessCategory,
};
use alloc::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssociationUse {
    /// Enable/configure the complete context, including autonomous responses.
    Configure,
    /// Current receive/authentication service, including pre-key EAPOL. This
    /// does not authorize protected management TX or authenticated MLME effects.
    Receive,
    /// Canonical EAPOL control-port submission before authentication.
    Authentication,
    Management,
    Data,
    /// Move the association to a channel its AP announced: the operation's
    /// definition is the target, which the whole profile must check on.
    ChannelSwitch,
}

/// Exact borrowed profile for providers to check; this is not a permit.
/// Providers must inspect the complete enabled source envelope, including basic
/// rates and autonomous responses, not just the selected width/MCS or one MPDU.
/// An MLD association's use is one operation per link, each on its own
/// channel.
#[derive(Debug)]
pub struct AssociationOperation<'a> {
    context: &'a AssociationContext,
    definition: ChannelDefinition,
    purpose: AssociationUse,
}
impl AssociationOperation<'_> {
    pub fn context(&self) -> &AssociationContext {
        self.context
    }
    /// The channel definition the operation runs on: where the association
    /// operates, which a channel switch may have moved from its own.
    pub const fn definition(&self) -> ChannelDefinition {
        self.definition
    }
    pub const fn channel(&self) -> Channel {
        self.definition.control
    }
    pub const fn purpose(&self) -> AssociationUse {
        self.purpose
    }
}

/// Current AP queue observation and derived local queues, borrowed only
/// inside both held providers. Values are inspection inputs, never RX provenance
/// or completion evidence; the native owner must independently keep those.
#[derive(Debug)]
pub struct EdcaOperation<'a> {
    association: AssociationOperation<'a>,
    parameter_set_count: u8,
    observed: [AccessCategory; 4],
    effective: [AccessCategory; 4],
}
impl EdcaOperation<'_> {
    pub fn association(&self) -> &AssociationOperation<'_> {
        &self.association
    }
    pub const fn parameter_set_count(&self) -> u8 {
        self.parameter_set_count
    }
    pub fn observed(&self) -> &[AccessCategory; 4] {
        &self.observed
    }
    pub fn effective(&self) -> &[AccessCategory; 4] {
        &self.effective
    }
}

/// A private, single-use preflight result keeping the current context.
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
    definition: ChannelDefinition,
    purpose: AssociationUse,
}
impl AssociationAdmission {
    pub fn operation(&self) -> AssociationOperation<'_> {
        AssociationOperation {
            context: &self.context,
            definition: self.definition,
            purpose: self.purpose,
        }
    }
}

/// Sealed by crate visibility: implementations expose their Station,
/// never a copied context. Exclusive borrowing spans the complete native effect.
pub(crate) trait AssociationOwner {
    fn association_station(&self) -> &Station;
}
#[derive(Clone, Copy)]
pub(crate) enum NativeManagementUse {
    Receive,
    AuthorizePort,
}

fn current(station: &Station, operation: &AssociationOperation<'_>) -> Result<(), Error> {
    station
        .validate_association_context(operation.context)
        .map_err(|_| Error::Stale)?;
    let required = match operation.purpose {
        AssociationUse::Configure => Phase::Configuring,
        AssociationUse::Receive
        | AssociationUse::Authentication
        | AssociationUse::Management
        | AssociationUse::Data
        | AssociationUse::ChannelSwitch => Phase::Associated,
    };
    if station.phase() != required {
        return Err(Error::Mismatch);
    }
    // Every other use runs where the association operates now.
    if operation.purpose != AssociationUse::ChannelSwitch
        && station.operating_definition() != Some(operation.definition)
    {
        return Err(Error::Stale);
    }
    Ok(())
}

/// Check `operation` on every link of `station`'s association: the setup
/// link's own, then each other link where it operates, as its own operation.
fn check(
    hardware: &mut impl HardwareLease,
    os: &mut impl OsLease,
    station: &Station,
    operation: &AssociationOperation<'_>,
) -> Result<(), Error> {
    check_link(hardware, os, operation)?;
    for link in station.link_contexts() {
        let operation = AssociationOperation {
            context: link,
            definition: link.definition(),
            purpose: operation.purpose,
        };
        check_link(hardware, os, &operation)?;
    }
    Ok(())
}

fn check_link(
    hardware: &mut impl HardwareLease,
    os: &mut impl OsLease,
    operation: &AssociationOperation<'_>,
) -> Result<(), Error> {
    let channel = operation.channel();
    if hardware.lookup_channel(channel.band, channel.number) != Some(channel)
        || !hardware.allows_association(operation)
    {
        return Err(Error::HardwareDenied);
    }
    if !os.allows_association(operation)
        || (operation.context.pmf().is_some() && !os.allows_protected_management(operation))
    {
        return Err(Error::OsDenied);
    }
    Ok(())
}

impl<H: HardwarePolicy, O: OsPolicy> Owner<H, O> {
    /// Check current context identity, phase and the entire enabled
    /// profile with both providers. No native effects occur here.
    pub fn admit_association(
        &mut self,
        station: &Station,
        context: Arc<AssociationContext>,
        purpose: AssociationUse,
    ) -> Result<AssociationAdmission, Error> {
        if purpose == AssociationUse::ChannelSwitch {
            return Err(Error::Mismatch);
        }
        let definition = station.operating_definition().ok_or(Error::Stale)?;
        self.admit_operation(station, context, definition, purpose)
    }

    /// Check the current association's whole profile on the `definition`
    /// its AP announced a switch to, before any native effect there.
    pub fn admit_channel_switch(
        &mut self,
        station: &Station,
        context: Arc<AssociationContext>,
        definition: ChannelDefinition,
    ) -> Result<AssociationAdmission, Error> {
        definition.validate().map_err(|_| Error::Mismatch)?;
        self.admit_operation(station, context, definition, AssociationUse::ChannelSwitch)
    }

    fn admit_operation(
        &mut self,
        station: &Station,
        context: Arc<AssociationContext>,
        definition: ChannelDefinition,
        purpose: AssociationUse,
    ) -> Result<AssociationAdmission, Error> {
        let operation = AssociationOperation {
            context: &context,
            definition,
            purpose,
        };
        current(station, &operation)?;
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = hardware.context();
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        check(&mut hardware, &mut os, station, &operation)?;
        Ok(AssociationAdmission {
            owner: self.identity,
            native,
            os_revision: os.revision(),
            context,
            definition,
            purpose,
        })
    }

    /// Reacquire the original current association and independently check the
    /// exact new AP/local queues with both providers before publication.
    /// The country clamp is derived while both policy guards are held.
    ///
    /// # Safety
    /// Submit must program only this exact operation on the same native
    /// controller and keep its private current completed-RX provenance, peer,
    /// keys and DMA owner through ACK/retirement and uncertain outcomes.
    /// Neither public queue arrays nor the returned closure value prove native
    /// observation or completion. `limit` is the current control-channel rule;
    /// both providers must inspect the complete dynamic queue operation.
    pub unsafe fn publish_edca<T>(
        &mut self,
        admission: AssociationAdmission,
        station: &Station,
        parameter_set_count: u8,
        observed: &[AccessCategory; 4],
        limit: Option<&super::database::Wmm>,
        submit: impl FnOnce(&EdcaOperation<'_>) -> T,
    ) -> Result<T, Error> {
        if admission.owner != self.identity {
            return Err(Error::Stale);
        }
        if admission.purpose != AssociationUse::Management || parameter_set_count > 15 {
            return Err(Error::Mismatch);
        }
        let association = admission.operation();
        current(station, &association)?;
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = hardware.context();
        if admission.native != native {
            return Err(Error::Stale);
        }
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        if admission.os_revision != os.revision() {
            return Err(Error::Stale);
        }
        check(&mut hardware, &mut os, station, &association)?;
        let effective = super::wmm::station(observed, limit).map_err(|_| Error::Mismatch)?;
        let operation = EdcaOperation {
            association,
            parameter_set_count,
            observed: *observed,
            effective,
        };
        if !hardware.allows_edca(&operation) {
            return Err(Error::HardwareDenied);
        }
        if !os.allows_edca(&operation) {
            return Err(Error::OsDenied);
        }
        let result = submit(&operation);
        drop(os);
        drop(hardware);
        Ok(result)
    }

    /// Apply a native management consumer while both current providers remain
    /// held. The mutable Station is the same object validated before the effect;
    /// no copied permit outlives the guards. Subsequent native publication must
    /// separately revalidate its original context, keys and deferred owner.
    ///
    /// # Safety
    /// The consumer must belong to this requester and original
    /// authenticated association. The OS supplies negotiated management policy;
    /// these regulatory guards do not authenticate input or grant PMF/MLME.
    pub(crate) unsafe fn consume_association<T>(
        &mut self,
        admission: AssociationAdmission,
        station: &mut Station,
        consume: impl FnOnce(&mut Station, &AssociationOperation<'_>) -> T,
    ) -> Result<T, Error> {
        if admission.owner != self.identity {
            return Err(Error::Stale);
        }
        if admission.purpose != AssociationUse::Management {
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
        check(&mut hardware, &mut os, station, &operation)?;
        let result = consume(station, &operation);
        drop(os);
        drop(hardware);
        Ok(result)
    }

    /// Mutate the native owner while both current providers are
    /// held. The Station borrow ends before the exclusive native callback; no
    /// reference, copied permit or pointer circumvents Rust aliasing.
    ///
    /// # Safety
    /// Native owner, providers and callback belong to the same real requester.
    /// Enforce configure_modern's retention/revocation/drain contract. This
    /// boundary supplies no key/RX authentication or retirement evidence.
    pub(crate) unsafe fn consume_native_association<N: AssociationOwner, T>(
        &mut self,
        admission: AssociationAdmission,
        native_owner: &mut N,
        purpose: NativeManagementUse,
        consume: impl FnOnce(&mut N, &AssociationOperation<'_>) -> T,
    ) -> Result<T, Error> {
        if admission.owner != self.identity {
            return Err(Error::Stale);
        }
        let expected = match purpose {
            NativeManagementUse::Receive => AssociationUse::Receive,
            NativeManagementUse::AuthorizePort => AssociationUse::Management,
        };
        if admission.purpose != expected {
            return Err(Error::Mismatch);
        }
        let operation = admission.operation();
        current(native_owner.association_station(), &operation)?;
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = hardware.context();
        if admission.native != native {
            return Err(Error::Stale);
        }
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        if admission.os_revision != os.revision() {
            return Err(Error::Stale);
        }
        check(
            &mut hardware,
            &mut os,
            native_owner.association_station(),
            &operation,
        )?;
        if matches!(purpose, NativeManagementUse::AuthorizePort)
            && (operation.context().pmf().is_none() || !os.allows_protected_port(&operation))
        {
            return Err(Error::OsDenied);
        }
        if matches!(purpose, NativeManagementUse::Receive)
            && native_owner
                .association_station()
                .protected_port_authorized()
        {
            // One receive batch may release deferred/reordered data. Check
            // Data independently while these same current guards remain held.
            let data = AssociationOperation {
                context: operation.context,
                definition: operation.definition,
                purpose: AssociationUse::Data,
            };
            check(
                &mut hardware,
                &mut os,
                native_owner.association_station(),
                &data,
            )?;
        }
        let result = consume(native_owner, &operation);
        drop(os);
        drop(hardware);
        Ok(result)
    }

    /// Recheck the exact context and purpose at native publication, holding the
    /// immutable station plus hardware then OS guards through `submit`.
    /// Closure return is not command ACK, association success, air completion or
    /// retirement. Keep the context/policy/key/queue alive through native
    /// completions and uncertainty; revocation must disable/drain or enforce
    /// restrictions on previously armed/queued autonomous and packet work.
    ///
    /// # Safety
    /// Submit must use this concrete guard's same physical controller
    /// and encode only this exact context/purpose through its checked
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
        check(&mut hardware, &mut os, station, &operation)?;
        let result = submit(&mut hardware, &operation);
        drop(os);
        drop(hardware);
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
