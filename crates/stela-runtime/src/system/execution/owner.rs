//! Exclusive execution ownership of one PE.
use super::authority::PeExecutionAuthority;
use crate::{
    blocks::{
        ThreadState,
        retirement::{ConsumerKey, RetainedResources},
    },
    system::state::SystemState,
};
#[cfg(not(feature = "std"))]
use alloc::string::String;

/// Private constructor key; only this module supplies resources to the
/// consumer's container.
pub(crate) struct OwnerKey(());

pub struct SystemExecutionOwner<'pe, B> {
    authority: PeExecutionAuthority,
    thread: &'pe mut ThreadState,
    system: &'pe mut SystemState,
    backend: &'pe mut B,
}

impl<'pe, B> SystemExecutionOwner<'pe, B> {
    /// # Safety
    /// These are the exclusively held resources of a new PE. Every event,
    /// monitor, scalable and mutable control or publication owner belongs to
    /// this PE, is held by `B` or the machine, and is borrowed by every entry
    /// and completion. Keep this owner for the PE's whole run; dropping it does
    /// not allow execution to resume or another owner to be created for the PE.
    pub(crate) unsafe fn new_pe(
        thread: &'pe mut ThreadState,
        system: &'pe mut SystemState,
        backend: &'pe mut B,
    ) -> Self {
        Self {
            // SAFETY: the new-PE obligations above.
            authority: unsafe { PeExecutionAuthority::new_pe() },
            thread,
            system,
            backend,
        }
    }

    /// Identity for diagnostics.
    #[cfg(feature = "std")]
    pub(crate) fn identity(&self) -> super::authority::PeIdentity {
        self.authority.identity()
    }

    /// Read-only diagnostics.
    pub(crate) fn pc(&self) -> stela_compiler::GuestAddress {
        self.thread.pc
    }
    #[cfg(feature = "std")]
    pub(crate) fn registers(&self) -> &stela_compiler::GuestState {
        &self.thread.registers
    }

    pub(crate) fn loan(&mut self) -> SystemExecutionLoan<'_, B> {
        SystemExecutionLoan {
            authority: &mut self.authority,
            thread: &mut *self.thread,
            system: &mut *self.system,
            backend: &mut *self.backend,
        }
    }
}

pub(crate) struct SystemExecutionLoan<'run, B> {
    authority: &'run mut PeExecutionAuthority,
    thread: &'run mut ThreadState,
    system: &'run mut SystemState,
    backend: &'run mut B,
}

impl<'run, B> SystemExecutionLoan<'run, B> {
    /// Only the retirement module can construct the key, so nothing else can
    /// extract these resources.
    pub(crate) fn into_retirement(self, _key: ConsumerKey) -> RetainedResources<'run, B> {
        RetainedResources::from_owner(
            OwnerKey(()),
            self.authority,
            self.thread,
            self.system,
            self.backend,
        )
    }
}

// Hosted observation of the owner's private fields.
#[cfg(feature = "std")]
impl<'pe, 'backend>
    SystemExecutionOwner<'pe, crate::blocks::retirement::checked::CheckedProcessOwner<'backend>>
{
    /// Inspect the PE without exposing mutable state, context pointers,
    /// callbacks or producers.
    pub(crate) fn observe(
        &mut self,
    ) -> anyhow::Result<crate::blocks::retirement::checked::OwnedProcessObservation> {
        crate::blocks::retirement::checked::qualify_observation(&self.authority)?;
        self.backend.observe_retained(OwnerKey(()), self.thread)
    }
}
