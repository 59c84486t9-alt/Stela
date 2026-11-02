//! Host timing batches using the shared policy, without native/source admission.
use super::*;
use crate::platform::work::service::{
    IdleOutcome,
    deadline::{Capture, DeadlineCore},
};

/// A capture from one actual hosted deadline owner. It cannot become a native
/// batch or authorize original Linux callbacks, an IRQ or physical minimum.
/// ```compile_fail
/// use stela_driver_base::platform::work::{
///     kernel_domain::HostedBatch, service::Batch,
/// };
/// fn no_native_batch(batch: HostedBatch) -> Batch { batch }
/// ```
pub struct HostedBatch {
    capture: Capture,
}
impl HostedBatch {
    pub fn raised(&self) -> bool {
        self.capture.raised
    }
    pub fn tick(&self) -> bool {
        self.capture.tick
    }
    pub fn timer(&self) -> bool {
        self.capture.timer
    }
}

/// Same-thread host timing state. A kernel service still needs its actual
/// runtime/current binding and source lifetime before it may deliver callbacks.
pub struct HostedDeadlines {
    reason: HostedReason,
    core: DeadlineCore,
}
impl HostedDeadlines {
    pub fn new(clock: &Arc<HostedClock>, idle: &Arc<HostedIdle>) -> Result<Self, WorkError> {
        if !Arc::ptr_eq(clock, idle.clock()) {
            return Err(WorkError::InvalidTicket);
        }
        clock.execution().check_current()?;
        let core = DeadlineCore::new(clock.now_ns()?)?;
        Ok(Self {
            reason: HostedReason::new(idle)?,
            core,
        })
    }

    fn process(&self) -> Result<(), WorkError> {
        self.reason.idle().clock().execution().check_current()?;
        if self.core.retired() {
            return Err(WorkError::Closed);
        }
        Ok(())
    }
    fn now(&mut self) -> Result<u64, WorkError> {
        self.process()?;
        let now = self.reason.idle().clock().now_ns()?;
        self.core.observe(now)?;
        Ok(now)
    }
    pub fn raised_work(
        &self,
    ) -> Result<super::super::DomainRaised<super::super::HostedDomain>, WorkError> {
        self.process()?;
        if self.reason.state().is_closed() {
            return Err(WorkError::Closed);
        }
        Ok(self.reason.raised())
    }
    /// Start the shared 1-ms observed-time policy. This installs no native
    /// interrupt and grants no original IRQ-work or timer delivery permission.
    pub fn start_ticks(&mut self) -> Result<(), WorkError> {
        self.process()?;
        if !self.core.can_start_ticks() || self.reason.state().is_closed() {
            return Err(WorkError::Busy);
        }
        let now = self.now()?;
        self.core.start_ticks(now)
    }
    pub fn set_timer(&mut self, deadline: Option<u64>) -> Result<(), WorkError> {
        self.process()?;
        if self.reason.state().is_closed() {
            return Err(WorkError::Closed);
        }
        self.core.set_timer(deadline);
        Ok(())
    }
    pub fn next_deadline(&self) -> Result<Option<u64>, WorkError> {
        self.process()?;
        Ok(self.core.next_deadline())
    }
    pub fn due(&mut self) -> Result<bool, WorkError> {
        let now = self.now()?;
        Ok(self.core.due(now, self.reason.state().observed_epoch()))
    }
    pub fn begin(&mut self) -> Result<Option<HostedBatch>, WorkError> {
        self.process()?;
        if self.core.running() {
            return Err(WorkError::Busy);
        }
        let now = self.now()?;
        let epoch = self.reason.state().observed_epoch();
        Ok(self
            .core
            .begin(now, epoch)?
            .map(|capture| HostedBatch { capture }))
    }
    /// Check only this outstanding host capture; no source/native grant.
    pub fn validate_batch(&self, batch: &HostedBatch) -> Result<(), WorkError> {
        self.process()?;
        self.core.validate(&batch.capture)
    }
    /// # Safety
    /// Real consumers completed this captured batch without recursive pumping.
    /// `next_timer` is their actual remaining minimum, with callback/storage
    /// roots kept independently. Numerical reasons cannot prove completion.
    pub unsafe fn finish(
        &mut self,
        batch: HostedBatch,
        next_timer: Option<u64>,
    ) -> Result<(), WorkError> {
        self.validate_batch(&batch)?;
        let now = self.now()?;
        self.core.finish(batch.capture, now, next_timer)
    }
    /// # Safety
    /// Call on the real taskless hosted dispatcher, with no original C owner,
    /// execution-segment/queue loan or mutable task borrow held across waiting.
    pub unsafe fn idle(&mut self) -> Result<IdleOutcome, WorkError> {
        self.process()?;
        if self.reason.state().is_closed() {
            return Err(WorkError::Closed);
        }
        if self.core.running() {
            return Err(WorkError::Busy);
        }
        if self.due()? {
            return Ok(IdleOutcome::Ready);
        }
        self.reason.idle().wait_until_ns(self.next_deadline()?)?;
        Ok(IdleOutcome::Waited)
    }
    pub fn stop_producers(&mut self) -> Result<(), WorkError> {
        self.process()?;
        self.reason.close()
    }
    /// # Safety
    /// Original producers, callback/storage and waiter users are stopped and
    /// joined. An empty timing inventory proves none of those lifecycle joins.
    pub unsafe fn retire(&mut self) -> Result<(), WorkError> {
        self.process()?;
        self.core.retire(self.reason.state().load())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timing() -> (Arc<HostedClock>, Arc<HostedIdle>, HostedDeadlines) {
        let execution = HostedExecution::new();
        let clock = HostedClock::new(&execution).unwrap();
        let idle = HostedIdle::new(&clock).unwrap();
        let deadlines = HostedDeadlines::new(&clock, &idle).unwrap();
        (clock, idle, deadlines)
    }

    fn retire(deadlines: &mut HostedDeadlines) {
        deadlines.stop_producers().unwrap();
        // SAFETY: these timing-only tests create no source callback, waiter or
        // storage consumer; every captured batch has been finished and drained.
        unsafe { deadlines.retire() }.unwrap();
    }

    #[test]
    fn publication_during_a_capture_survives_its_completion() {
        let (_, _, mut deadlines) = timing();
        let raised = deadlines.raised_work().unwrap();
        raised.raise().unwrap();
        let first = deadlines.begin().unwrap().unwrap();
        assert!(first.raised());
        assert!(!first.tick());
        assert!(!first.timer());
        raised.raise().unwrap();
        assert_eq!(deadlines.begin().err(), Some(WorkError::Busy));
        // SAFETY: no callbacks were installed; the first captured reason was
        // consumed here. The later publication must remain for the next capture.
        unsafe { deadlines.finish(first, None) }.unwrap();
        assert!(deadlines.due().unwrap());
        let second = deadlines.begin().unwrap().unwrap();
        assert!(second.raised());
        // SAFETY: the second captured reason was consumed without callbacks.
        unsafe { deadlines.finish(second, None) }.unwrap();
        assert!(!deadlines.due().unwrap());
        retire(&mut deadlines);
        assert_eq!(raised.raise(), Err(WorkError::Closed));
        assert_eq!(deadlines.due(), Err(WorkError::Closed));
    }

    #[test]
    fn actual_observed_timer_is_drained_before_retirement() {
        let (clock, _, mut deadlines) = timing();
        let deadline = clock.now_ns().unwrap();
        deadlines.set_timer(Some(deadline)).unwrap();
        assert_eq!(deadlines.next_deadline(), Ok(Some(deadline)));
        let batch = deadlines.begin().unwrap().unwrap();
        assert!(batch.timer());
        assert!(!batch.tick());
        assert!(!batch.raised());
        deadlines.stop_producers().unwrap();
        // SAFETY: this test has no external users; the live timing capture must
        // nevertheless block retirement until its actual consumer completes.
        assert_eq!(unsafe { deadlines.retire() }, Err(WorkError::Busy));
        // SAFETY: this timing-only consumer has completed its captured deadline,
        // and no additional timer or callback was installed.
        unsafe { deadlines.finish(batch, None) }.unwrap();
        // SAFETY: admission is closed and the sole capture and timer are drained;
        // this test has no source storage, callbacks or waiter users to join.
        unsafe { deadlines.retire() }.unwrap();
    }

    #[test]
    fn same_clock_does_not_authenticate_another_owners_capture() {
        let (clock, idle, mut first) = timing();
        let mut other = HostedDeadlines::new(&clock, &idle).unwrap();
        first.set_timer(Some(clock.now_ns().unwrap())).unwrap();
        other.set_timer(Some(clock.now_ns().unwrap())).unwrap();
        let batch = first.begin().unwrap().unwrap();
        let other_batch = other.begin().unwrap().unwrap();
        assert_eq!(other.validate_batch(&batch), Err(WorkError::InvalidTicket));
        first.validate_batch(&batch).unwrap();
        // SAFETY: each timing-only consumer finished its own actual capture, with
        // no source users or additional timers installed in either owner.
        unsafe {
            first.finish(batch, None).unwrap();
            other.finish(other_batch, None).unwrap();
        }
        retire(&mut first);
        retire(&mut other);
    }

    #[test]
    fn foreign_thread_cannot_pump_the_actual_owner() {
        let (_, _, deadlines) = timing();
        let mut deadlines = thread::spawn(move || {
            let mut deadlines = deadlines;
            assert_eq!(deadlines.due(), Err(WorkError::WrongCpu));
            assert_eq!(deadlines.begin().err(), Some(WorkError::WrongCpu));
            deadlines
        })
        .join()
        .unwrap();
        assert!(!deadlines.due().unwrap());
        retire(&mut deadlines);
    }

    #[test]
    fn clock_identity_is_checked_even_on_the_same_os_thread() {
        let (clock, idle, mut deadlines) = timing();
        let different_clock = HostedClock::new(clock.execution()).unwrap();
        assert_eq!(
            HostedDeadlines::new(&different_clock, &idle).err(),
            Some(WorkError::InvalidTicket)
        );
        retire(&mut deadlines);
    }
}
