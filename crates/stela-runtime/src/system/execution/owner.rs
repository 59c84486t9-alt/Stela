//! Exclusive execution ownership of one PE.
use super::authority::PeExecutionAuthority;
use crate::{
    blocks::{
        ThreadState,
        retirement::{ConsumerKey, RetainedResources},
    },
    system::{debug::halted::DebugMachine, state::SystemState},
};
#[cfg(not(feature = "std"))]
use alloc::string::String;

/// Constructor key is private to this actual retained-owner module. Only it can
/// supply actual resources to the canonical consumer's private-field container.
pub(crate) struct OwnerKey(());

pub struct SystemExecutionOwner<'pe, B> {
    authority: PeExecutionAuthority,
    thread: &'pe mut ThreadState,
    system: &'pe mut SystemState,
    backend: &'pe mut B,
    debug: Option<DebugMachine>,
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
            debug: None,
        }
    }

    /// Descriptive identity only; cloning it cannot produce a loan or authority.
    #[cfg(feature = "std")]
    pub(crate) fn identity(&self) -> super::authority::PeIdentity {
        self.authority.identity()
    }

    /// Read-only diagnostics confer no execution or constructor authority.
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
            debug: &mut self.debug,
        }
    }
}

pub(crate) struct SystemExecutionLoan<'run, B> {
    authority: &'run mut PeExecutionAuthority,
    thread: &'run mut ThreadState,
    system: &'run mut SystemState,
    backend: &'run mut B,
    debug: &'run mut Option<DebugMachine>,
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
            self.debug,
        )
    }
}

// Hosted process observation over this owner's actual private fields.
#[cfg(feature = "std")]
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

// Only the concrete actual privileged producer can own an enabled lifecycle.
impl<'pe, 'backend>
    SystemExecutionOwner<'pe, crate::blocks::retirement::checked::PrivilegedOwner<'backend>>
{
    /// Fresh actual resources only, as new_pe above. The lifecycle contains no
    /// CPU, ThreadState, SystemState, scalable backing or second phase authority.
    /// The backend must derive debug views from this same resource under the
    /// retained loan and include every CTI/debug producer in its async registry.
    pub(crate) unsafe fn new_pe_with_debug(
        thread: &'pe mut ThreadState,
        system: &'pe mut SystemState,
        backend: &'pe mut crate::blocks::retirement::checked::PrivilegedOwner<'backend>,
        debug: DebugMachine,
    ) -> anyhow::Result<Self> {
        debug
            .qualify_initial(system)
            .map_err(|e| anyhow::anyhow!("initial debug lifecycle: {e:?}"))?;
        backend.qualify_lifecycle(&debug, system)?;
        let authority = if debug.status().halted() {
            unsafe { PeExecutionAuthority::new_pe_halted() }
        } else {
            unsafe { PeExecutionAuthority::new_pe() }
        };
        Ok(Self {
            authority,
            thread,
            system,
            backend,
            debug: Some(debug),
        })
    }
}

impl<'pe, 'backend>
    SystemExecutionOwner<'pe, crate::blocks::retirement::checked::PrivilegedOwner<'backend>>
{
    /// Actual serialized declared-software debugger input; no physical debug or
    /// stopped hardware adoption. This same original owner must actually Halt.
    pub(crate) fn queue_editr(&mut self, route_slot: usize, word: u32) -> anyhow::Result<()> {
        anyhow::ensure!(self.authority.halted(), "actual PE is not Halted");
        let debug = self
            .debug
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("debug lifecycle unavailable"))?;
        anyhow::ensure!(
            debug.external_access(),
            "actual external debug access unavailable"
        );
        debug
            .qualify_halted_boundary()
            .map_err(|e| anyhow::anyhow!("actual halted gate: {e:?}"))?;
        self.backend.enqueue_editr(route_slot, word)
    }
    pub(crate) fn run_editr(&mut self) -> crate::blocks::retirement::checked::OwnedDebugOutcome {
        crate::blocks::retirement::checked::run_halted_owned(self.loan())
    }
}

impl SystemExecutionOwner<'_, crate::blocks::retirement::checked::PrivilegedOwner<'_>> {
    /// Actual read-only original lifecycle observation; no resource/permit escapes.
    pub(crate) fn privileged_observation(&self) -> String {
        format!(
            "authority={:?};debug={:?};MDSCR={:?};DLR={:?};DSPSR={:?};CTI={:?}",
            self.authority,
            self.debug,
            self.debug.as_ref().map(DebugMachine::mdscr),
            self.debug.as_ref().map(DebugMachine::dlr),
            self.debug.as_ref().map(DebugMachine::dspsr),
            self.backend.last_cti_receipt()
        )
    }
}

impl SystemExecutionOwner<'_, crate::blocks::retirement::checked::PrivilegedOwner<'_>> {
    /// Same actual phase, used only to stop this consuming request sequence.
    pub(crate) fn privileged_terminal(&self) -> bool {
        !self.authority.ready() && !self.authority.halted()
    }
}
