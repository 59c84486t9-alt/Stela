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
    Retiring(u64),
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
            Phase::Ready | Phase::RequalificationRequired | Phase::Indeterminate => Ok(()),
            Phase::NativeActive(_) | Phase::SystemActive(_) | Phase::Retiring(_) => Err(()),
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

    pub(crate) fn poison(&mut self) {
        self.phase = Phase::Indeterminate;
    }
}
