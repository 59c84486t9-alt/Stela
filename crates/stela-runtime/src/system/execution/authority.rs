//! The execution authority of one PE.
use alloc::sync::Arc;

#[derive(Debug, Clone)]
pub struct PeIdentity(Arc<()>);

impl PeIdentity {
    pub fn same_pe(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Phase {
    Ready,
    NativeActive(u64),
    SystemActive(u64),
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    Suspended(u64),
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    WakeRequalification(u64),
    Halted,
    DebugActive(u64),
    Retiring(u64),
    NativeCommitting,
    RequalificationRequired,
    Indeterminate,
}

#[derive(Debug)]
pub struct PeExecutionAuthority {
    identity: PeIdentity,
    phase: Phase,
    sequence: u64,
}

impl PeExecutionAuthority {
    /// # Safety
    /// Called once, by the constructor of a new PE. Keep this owner for the
    /// PE's whole run, bound to its thread, system state, backend and controls;
    /// never recreate it for an existing PE, a copy or after failure. Every
    /// native and completion route borrows it.
    pub(crate) unsafe fn new_pe() -> Self {
        Self {
            identity: PeIdentity(Arc::new(())),
            phase: Phase::Ready,
            sequence: 0,
        }
    }

    /// As `new_pe`, but starting halted, after validating STATUS and the ITR.
    /// For new PEs only.
    pub(crate) unsafe fn new_pe_halted() -> Self {
        let mut authority = unsafe { Self::new_pe() };
        authority.phase = Phase::Halted;
        authority
    }

    pub fn identity(&self) -> PeIdentity {
        self.identity.clone()
    }

    pub(crate) fn ready(&self) -> bool {
        self.phase == Phase::Ready
    }

    /// Read-only diagnostics for a quiescent or blocked PE. The consumer must
    /// also hold the domain's service borrow before reading backend snapshots.
    #[cfg(feature = "std")]
    pub(crate) fn check_observation(
        &self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
    ) -> Result<(), ()> {
        match self.phase {
            Phase::Ready
            | Phase::Halted
            | Phase::RequalificationRequired
            | Phase::Indeterminate => Ok(()),
            Phase::NativeActive(_)
            | Phase::SystemActive(_)
            | Phase::Suspended(_)
            | Phase::WakeRequalification(_)
            | Phase::DebugActive(_)
            | Phase::Retiring(_)
            | Phase::NativeCommitting => Err(()),
        }
    }

    pub(crate) fn begin_native(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
    ) -> Result<u64, ()> {
        if !self.ready() {
            return Err(());
        }
        let Some(attempt) = self.sequence.checked_add(1) else {
            self.poison();
            return Err(());
        };
        self.sequence = attempt;
        self.phase = Phase::NativeActive(attempt);
        Ok(attempt)
    }

    pub(crate) fn ready_after_retirement(&self, attempt: u64) -> bool {
        self.ready() && self.sequence == attempt
    }

    /// The consumer has validated the retired source and PE. IRQ arbitration
    /// starts after a retirement; this creates no native attempt and runs no
    /// further guest instruction.
    pub(crate) fn begin_interrupt(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        retired_attempt: u64,
    ) -> Result<u64, ()> {
        if !self.ready() || self.sequence != retired_attempt {
            return Err(());
        }
        let Some(attempt) = self.sequence.checked_add(1) else {
            self.poison();
            return Err(());
        };
        self.sequence = attempt;
        self.phase = Phase::SystemActive(attempt);
        Ok(attempt)
    }

    pub(crate) fn native_attempt(&self, attempt: u64) -> bool {
        self.sequence == attempt && self.phase == Phase::NativeActive(attempt)
    }

    pub(crate) fn enter_system(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        attempt: u64,
    ) -> Result<(), ()> {
        if !self.native_attempt(attempt) {
            self.poison();
            return Err(());
        }
        self.phase = Phase::SystemActive(attempt);
        Ok(())
    }

    pub(crate) fn system_attempt(&self, attempt: u64) -> bool {
        self.sequence == attempt && self.phase == Phase::SystemActive(attempt)
    }

    /// The consumer keeps the PE, the source and the finalizer receipt. It
    /// drops its outer memory loan only after this transition and before the
    /// host thread parks or a device service runs.
    #[cfg(feature = "std")]
    pub(crate) fn suspend_system(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        attempt: u64,
    ) -> Result<(), ()> {
        if !self.system_attempt(attempt) {
            self.poison();
            return Err(());
        }
        self.phase = Phase::Suspended(attempt);
        Ok(())
    }

    /// A host return is not a wake or retirement. Domain exclusion, source,
    /// controls and producers must be re-checked.
    #[cfg(feature = "std")]
    pub(crate) fn resume_suspended(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        attempt: u64,
    ) -> Result<(), ()> {
        if self.sequence != attempt || self.phase != Phase::Suspended(attempt) {
            self.poison();
            return Err(());
        }
        self.phase = Phase::WakeRequalification(attempt);
        Ok(())
    }

    /// Called after the consumer reacquired the domain loan and re-checked the
    /// source, controls and producer resources.
    #[cfg(feature = "std")]
    pub(crate) fn qualify_wake(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        attempt: u64,
    ) -> Result<(), ()> {
        if self.sequence != attempt || self.phase != Phase::WakeRequalification(attempt) {
            self.poison();
            return Err(());
        }
        self.phase = Phase::SystemActive(attempt);
        Ok(())
    }

    pub(crate) fn halted(&self) -> bool {
        self.phase == Phase::Halted
    }

    /// The consumer settles HLT's effects while its borrows are held. No next
    /// PC follows; a wrong phase marks the PE failed.
    pub(crate) fn finish_halt(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        attempt: u64,
    ) -> Result<(), ()> {
        if !self.system_attempt(attempt) {
            self.poison();
            return Err(());
        }
        self.phase = Phase::Halted;
        Ok(())
    }

    /// Actual EDITR source and lifecycle qualification precede this call under
    /// the closed consumer. This cannot be reached from Ready or requalification.
    pub(crate) fn begin_debug(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
    ) -> Result<u64, ()> {
        if !self.halted() {
            return Err(());
        }
        let Some(attempt) = self.sequence.checked_add(1) else {
            self.poison();
            return Err(());
        };
        self.sequence = attempt;
        self.phase = Phase::DebugActive(attempt);
        Ok(attempt)
    }
    pub(crate) fn debug_attempt(&self, attempt: u64) -> bool {
        self.sequence == attempt && self.phase == Phase::DebugActive(attempt)
    }
    /// The consumer has verified the debug completion and the halted state. Any
    /// later error or Drop still marks the PE failed.
    pub(crate) fn finish_debug(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        attempt: u64,
    ) -> Result<(), ()> {
        if !self.debug_attempt(attempt) {
            self.poison();
            return Err(());
        }
        self.phase = Phase::Halted;
        Ok(())
    }

    pub(crate) fn start_retirement(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        attempt: u64,
    ) -> Result<(), ()> {
        if !self.system_attempt(attempt) {
            self.poison();
            return Err(());
        }
        self.phase = Phase::Retiring(attempt);
        Ok(())
    }

    pub(crate) fn retiring_attempt(&self, attempt: u64) -> bool {
        self.sequence == attempt && self.phase == Phase::Retiring(attempt)
    }

    /// Called by the consumer while it holds the settled thread state and its
    /// borrows.
    pub(crate) fn finish_refusal(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        attempt: u64,
    ) -> Result<(), ()> {
        if !self.system_attempt(attempt) {
            self.poison();
            return Err(());
        }
        self.phase = Phase::Ready;
        Ok(())
    }

    pub(crate) fn finish_retirement(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        attempt: u64,
        requalify: bool,
    ) -> Result<(), ()> {
        if !self.retiring_attempt(attempt) {
            self.poison();
            return Err(());
        }
        self.phase = if requalify {
            Phase::RequalificationRequired
        } else {
            Phase::Ready
        };
        Ok(())
    }

    /// Only the checked-native consumer may call this, after validating the
    /// source, map, requirements and finalizer.
    pub(crate) fn start_native_retirement(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        attempt: u64,
    ) -> Result<(), ()> {
        if !self.native_attempt(attempt) {
            self.poison();
            return Err(());
        }
        self.phase = Phase::Retiring(attempt);
        Ok(())
    }

    /// A refusal before the native call; the consumer has shown there were no
    /// effects.
    pub(crate) fn finish_native_refusal(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        attempt: u64,
    ) -> Result<(), ()> {
        if !self.native_attempt(attempt) {
            self.poison();
            return Err(());
        }
        self.phase = Phase::Ready;
        Ok(())
    }

    /// A precise fault keeps its fault PC and the completed prefix. Native
    /// entry stays closed: exception delivery is not implemented.
    pub(crate) fn finish_native_fault(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        attempt: u64,
    ) -> Result<(), ()> {
        if !self.native_attempt(attempt) {
            self.poison();
            return Err(());
        }
        self.phase = Phase::RequalificationRequired;
        Ok(())
    }

    /// Prepare the native commit after every fallible check. The consumer pairs
    /// this borrow with the thread state, system state, backend, source,
    /// candidate and continuation in a private commit, which stores the state
    /// and PC exactly once before `finish`. Device effects and pending
    /// interrupt delivery are not handled.
    pub(crate) fn prepare_native_commit(
        &mut self,
        _consumer: &crate::blocks::retirement::ConsumerKey,
        attempt: u64,
    ) -> Result<NativeRetirementCommit<'_>, ()> {
        if !self.native_attempt(attempt) {
            self.poison();
            return Err(());
        }
        // A separate phase, so a forgotten borrow cannot finish through the
        // generic fallible retirement path.
        self.phase = Phase::NativeCommitting;
        Ok(NativeRetirementCommit {
            authority: self,
            finished: false,
        })
    }

    pub(crate) fn poison(&mut self) {
        self.phase = Phase::Indeterminate;
    }
}

/// Phase borrow for a validated native commit. The exclusive borrow prevents
/// other phase changes until settlement; dropping or unwinding before `finish`
/// marks the PE failed, and forgetting it leaves the phase stuck in
/// NativeCommitting.
pub(crate) struct NativeRetirementCommit<'commit> {
    authority: &'commit mut PeExecutionAuthority,
    finished: bool,
}

impl NativeRetirementCommit<'_> {
    /// The paired commit has already stored the candidate registers and PC
    /// once. Nothing fallible or external may happen between those stores and
    /// this settlement, and the borrows stay held throughout.
    pub(crate) fn finish(mut self, _consumer: &crate::blocks::retirement::ConsumerKey) {
        self.authority.phase = Phase::Ready;
        self.finished = true;
    }
}

impl Drop for NativeRetirementCommit<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.authority.poison();
        }
    }
}
