//! Private source for system::execution::authority. No integration/build claim.
use std::sync::Arc;

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
    /// Only the actual fresh-PE constructor may call this, exactly once for a
    /// genuinely NEW PE. Retain this non-Clone owner for the full executable
    /// lifetime, binding its actual ThreadState/System/backend/control resources.
    /// Recreating it for an adopted PE, cloned diagnostics or after failure/Drop
    /// is forbidden. All integrated native and completion routes must borrow it.
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

    /// Readonly diagnostics may inspect a quiescent or terminally blocked PE.
    /// The closed consumer must additionally hold the actual same-domain service
    /// loan before reading retained backend snapshots. This grants no entry,
    /// reset, mutable resource access or phase transition.
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

    /// Called only by the closed consumer while actual settled ThreadState and
    /// real source/control/backend leases remain exclusively held.
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

    /// Only the closed actual checked-native consumer may present ConsumerKey,
    /// after validating full source/map/requirements/finalizer observations.
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

    /// Exact pre-FFI decline only. The same closed consumer retains actual
    /// thread/source/domain/control owners and proves no native/prefix effects.
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

    /// A validated precise fault preserves actual faultPC and completed prefix.
    /// This never reopens native entry without genuine exception delivery and
    /// a separately reviewed requalification proof, which is not supplied here.
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
