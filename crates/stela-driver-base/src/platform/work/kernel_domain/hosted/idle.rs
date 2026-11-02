//! Same-owner observed host time and real park/unpark event transport.
use super::*;
use core::sync::atomic::AtomicBool;
use std::time::Duration;
pub struct HostedClock {
    execution: Arc<HostedExecution>,
}
impl HostedClock {
    pub fn new(execution: &Arc<HostedExecution>) -> Result<Arc<Self>, WorkError> {
        execution.check_current()?;
        Ok(Arc::new(Self {
            execution: execution.clone(),
        }))
    }
    pub fn execution(&self) -> &Arc<HostedExecution> {
        &self.execution
    }
    pub fn now_ns(&self) -> Result<u64, WorkError> {
        self.execution.now_ns()
    }
}
/// Real OS-thread event owner. No native Idle/Clock/Cpu implementation, C IRQ
/// scope, async-signal-safety, timer/LAPIC precision or callback delivery grant.
pub struct HostedIdle {
    clock: Arc<HostedClock>,
    pending: AtomicBool,
    #[cfg(test)]
    before_park: std::sync::Mutex<Option<ParkObserver>>,
}
impl HostedIdle {
    pub fn new(clock: &Arc<HostedClock>) -> Result<Arc<Self>, WorkError> {
        clock.execution.check_current()?;
        Ok(Arc::new(Self {
            clock: clock.clone(),
            pending: AtomicBool::new(false),
            #[cfg(test)]
            before_park: std::sync::Mutex::new(None),
        }))
    }
    pub fn clock(&self) -> &Arc<HostedClock> {
        &self.clock
    }
    pub fn notify(&self) -> Result<(), WorkError> {
        self.clock.execution.check_process()?;
        self.pending.store(true, Ordering::Release);
        self.clock.execution.handle.unpark();
        Ok(())
    }
    pub fn wait_until_ns(&self, deadline: Option<u64>) -> Result<(), WorkError> {
        self.clock.execution.check_current()?;
        if self.pending.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        // Take the per-instance observer before publication; no mutex guard
        // survives. Keep the Box and captured roots across the actual park, so
        // no observer destructor/allocator activity can consume its wake token.
        #[cfg(test)]
        let mut observer = self.before_park.lock().unwrap().take();
        #[cfg(test)]
        if let Some(observer) = observer.as_mut() {
            observer(self);
        }
        if let Some(deadline) = deadline {
            let now = self.clock.now_ns()?;
            if let Some(delay) = deadline.checked_sub(now) {
                thread::park_timeout(Duration::from_nanos(delay));
            }
        } else {
            thread::park();
        }
        #[cfg(test)]
        drop(observer);
        // park consumes a real unpark token atomically, including notify racing
        // entry. Spurious return is allowed; pending remains for the next check.
        Ok(())
    }
}

#[cfg(test)]
type ParkObserver = alloc::boxed::Box<dyn FnMut(&HostedIdle) + Send>;
#[cfg(test)]
impl HostedIdle {
    pub(super) fn observe_before_park(&self, observer: ParkObserver) {
        self.clock.execution.check_current().unwrap();
        let mut slot = self.before_park.lock().unwrap();
        assert!(slot.is_none(), "one observer per actual park attempt");
        *slot = Some(observer);
    }
}
