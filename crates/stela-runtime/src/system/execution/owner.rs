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

/// Private constructor key; only this module supplies resources to the
/// consumer's container.
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
            debug: None,
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
    /// Only the retirement module can construct the key, so nothing else can
    /// extract these resources.
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

// Only the privileged backend owns a debug lifecycle.
impl<'pe, 'backend>
    SystemExecutionOwner<'pe, crate::blocks::retirement::checked::PrivilegedOwner<'backend>>
{
    /// As `new_pe`, with a debug lifecycle. The lifecycle holds no CPU or
    /// thread state; the backend derives debug views from it and registers
    /// every CTI and debug producer.
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
    /// Queue software-debugger input (no hardware debugger). The PE must itself
    /// halt.
    pub(crate) fn queue_editr(&mut self, route_slot: usize, word: u32) -> anyhow::Result<()> {
        anyhow::ensure!(self.authority.halted(), "PE is not Halted");
        let debug = self
            .debug
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("debug lifecycle unavailable"))?;
        anyhow::ensure!(debug.external_access(), "external debug access unavailable");
        debug
            .qualify_halted_boundary()
            .map_err(|e| anyhow::anyhow!("halted gate: {e:?}"))?;
        self.backend.enqueue_editr(route_slot, word)
    }
    pub(crate) fn run_editr(&mut self) -> crate::blocks::retirement::checked::OwnedDebugOutcome {
        crate::blocks::retirement::checked::run_halted_owned(self.loan())
    }
}

impl SystemExecutionOwner<'_, crate::blocks::retirement::checked::PrivilegedOwner<'_>> {
    /// Read-only lifecycle observation.
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
    /// Whether the PE is in a terminal phase, which ends the request sequence.
    pub(crate) fn privileged_terminal(&self) -> bool {
        !self.authority.ready() && !self.authority.halted()
    }
}
