//! Unique retained execution ownership for one actual PE.
use super::authority::PeExecutionAuthority;
use crate::{
    blocks::{
        ThreadState,
        retirement::{ConsumerKey, RetainedResources},
    },
    system::state::SystemState,
};

/// Constructor key is private to this actual retained-owner module. Only it can
/// supply actual resources to the canonical consumer's private-field container.
pub(crate) struct OwnerKey(());

pub struct SystemExecutionOwner<'pe, B> {
    authority: PeExecutionAuthority,
    thread: &'pe mut ThreadState,
    system: &'pe mut SystemState,
    backend: &'pe mut B,
}

impl<'pe, B> SystemExecutionOwner<'pe, B> {
    /// # Safety
    /// These are the uniquely held actual resources of a genuinely NEW PE, not
    /// copied diagnostics or replacements. All event/monitor/scalable and real
    /// mutable control/publication owners are same-PE, retained by B or this
    /// machine, and every integrated entry/completion borrows this owner.
    /// Retain it for the PE's complete executable lifetime. Its Drop does not
    /// allow execution to resume or permit another constructor for that PE.
    /// Raw component APIs forbid this adopted PE except under its unique active
    /// permit for the exact call/resources. No identity/reset/Clone adoption.
    pub(crate) unsafe fn new_pe(
        thread: &'pe mut ThreadState,
        system: &'pe mut SystemState,
        backend: &'pe mut B,
    ) -> Self {
        Self {
            // SAFETY: actual fresh-PE lifetime/all-entry obligations above.
            authority: unsafe { PeExecutionAuthority::new_pe() },
            thread,
            system,
            backend,
        }
    }

    /// Descriptive identity only; cloning it cannot produce a loan or authority.
    pub(crate) fn identity(&self) -> super::authority::PeIdentity {
        self.authority.identity()
    }

    /// Read-only diagnostics confer no execution or constructor authority.
    pub(crate) fn pc(&self) -> stela_compiler::GuestAddress {
        self.thread.pc
    }
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
    /// ConsumerKey can only be constructed inside canonical blocks::retirement.
    /// No public resource tuple, caller closure, mutable-field accessor or
    /// replace-thread/dispatcher API can extract these actual borrowed owners.
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

// Append to system::execution::owner, the owner of these actual private fields.
impl<'pe, 'backend>
    SystemExecutionOwner<'pe, crate::blocks::retirement::checked::CheckedProcessOwner<'backend>>
{
    /// Inspect this actual retained PE without exposing mutable state, context
    /// pointers, callbacks, producer owners or an execution/completion grant.
    pub(crate) fn observe(
        &mut self,
    ) -> anyhow::Result<crate::blocks::retirement::checked::OwnedProcessObservation> {
        crate::blocks::retirement::checked::qualify_observation(&self.authority)?;
        self.backend.observe_retained(OwnerKey(()), self.thread)
    }
}
