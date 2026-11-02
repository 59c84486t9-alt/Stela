//! Actual host reason ownership; no source task/current/callback delivery.
use super::*;
use crate::platform::work::service::reason::ReasonCore;
use core::mem::ManuallyDrop;
struct Signal {
    reason: ReasonCore,
    idle: Arc<HostedIdle>,
}
/// Owner of a real host event reason. Close prevents every older raised handle
/// from publishing again; close/observation are not service/task join receipts.
pub struct HostedReason {
    signal: ManuallyDrop<Arc<Signal>>,
}
impl HostedReason {
    pub(super) fn state(&self) -> &ReasonCore {
        &self.signal.reason
    }
    pub(super) fn idle(&self) -> &Arc<HostedIdle> {
        &self.signal.idle
    }
    pub fn new(idle: &Arc<HostedIdle>) -> Result<Self, WorkError> {
        idle.clock().execution().check_current()?;
        Ok(Self {
            signal: ManuallyDrop::new(Arc::new(Signal {
                reason: ReasonCore::new(),
                idle: idle.clone(),
            })),
        })
    }
    pub fn raised(&self) -> super::super::DomainRaised<super::super::HostedDomain> {
        super::super::DomainRaised::from_hosted(HostedRaisedWork {
            signal: ManuallyDrop::new(Arc::clone(&self.signal)),
        })
    }
    pub fn observed_epoch(&self) -> Result<u64, WorkError> {
        self.signal.idle.clock().execution().check_current()?;
        Ok(self.signal.reason.observed_epoch())
    }
    pub fn close(&self) -> Result<(), WorkError> {
        self.signal.idle.clock().execution().check_current()?;
        self.signal.reason.close();
        Ok(())
    }
}
impl Drop for HostedReason {
    fn drop(&mut self) {
        self.signal.reason.close();
        if self.signal.idle.clock().execution().check_process().is_ok() {
            // SAFETY: this host-only graph owns an immutable OS thread handle,
            // clock and atomic reason. Arc release is valid on any thread in
            // its creating process; it performs no native/source retirement.
            unsafe { ManuallyDrop::drop(&mut self.signal) };
        } else {
            super::super::super::quarantine();
        }
    }
}
/// Sealed associated transport. It cannot produce native RaisedWork or a task.
pub struct HostedRaisedWork {
    signal: ManuallyDrop<Arc<Signal>>,
}
impl Clone for HostedRaisedWork {
    fn clone(&self) -> Self {
        Self {
            signal: ManuallyDrop::new(Arc::clone(&self.signal)),
        }
    }
}
impl HostedRaisedWork {
    pub(in crate::platform::work::kernel_domain) fn raise(&self) -> Result<(), WorkError> {
        self.signal.idle.clock().execution().check_process()?;
        self.signal.reason.publish()?;
        // A notify failure retains the actual published reason, not delivery.
        self.signal.idle.notify()
    }
}
impl Drop for HostedRaisedWork {
    fn drop(&mut self) {
        if self.signal.idle.clock().execution().check_process().is_ok() {
            // SAFETY: immutable host event/clock roots are safe to release on
            // the notifying thread. This graph has no native/C task owners.
            unsafe { ManuallyDrop::drop(&mut self.signal) };
        } else {
            super::super::super::quarantine();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_notification_handle_drop_releases_its_original_root() {
        let execution = HostedExecution::new();
        let clock = HostedClock::new(&execution).unwrap();
        let idle = HostedIdle::new(&clock).unwrap();
        let reason = HostedReason::new(&idle).unwrap();
        let storage = Arc::downgrade(&reason.signal);
        let raised = reason.raised();
        thread::spawn(move || {
            raised.raise().unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(reason.observed_epoch(), Ok(1));
        reason.close().unwrap();
        drop(reason);
        assert!(storage.upgrade().is_none());
    }

    #[test]
    fn abandoned_reason_closes_old_handles_before_releasing_storage() {
        let execution = HostedExecution::new();
        let clock = HostedClock::new(&execution).unwrap();
        let idle = HostedIdle::new(&clock).unwrap();
        let reason = HostedReason::new(&idle).unwrap();
        let storage = Arc::downgrade(&reason.signal);
        let raised = reason.raised();
        thread::spawn(move || drop(reason)).join().unwrap();
        assert_eq!(raised.raise(), Err(WorkError::Closed));
        drop(raised);
        assert!(storage.upgrade().is_none());
    }
}
