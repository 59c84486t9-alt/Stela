//! Shared reason publication/close algorithm, independent of execution authority.
use super::{CLOSED, WorkError};
use core::sync::atomic::{AtomicU64, Ordering};
pub(in crate::platform::work) struct ReasonCore {
    epoch: AtomicU64,
}
impl ReasonCore {
    pub(in crate::platform::work) fn new() -> Self {
        Self {
            epoch: AtomicU64::new(0),
        }
    }
    pub(in crate::platform::work) fn load(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }
    pub(in crate::platform::work) fn observed_epoch(&self) -> u64 {
        self.load() & !CLOSED
    }
    pub(in crate::platform::work) fn is_closed(&self) -> bool {
        self.load() & CLOSED != 0
    }
    pub(in crate::platform::work) fn close(&self) {
        self.epoch.fetch_or(CLOSED, Ordering::AcqRel);
    }
    pub(in crate::platform::work) fn publish(&self) -> Result<(), WorkError> {
        self.epoch
            .try_update(Ordering::Release, Ordering::Acquire, |epoch| {
                if epoch & CLOSED != 0 || epoch == CLOSED - 1 {
                    None
                } else {
                    Some(epoch + 1)
                }
            })
            .map_err(|epoch| {
                if epoch & CLOSED != 0 {
                    WorkError::Closed
                } else {
                    WorkError::Exhausted
                }
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn close_and_exhaustion_never_wrap_or_reopen() {
        let reason = ReasonCore::new();
        reason.publish().unwrap();
        assert_eq!(reason.observed_epoch(), 1);
        reason.close();
        assert!(reason.is_closed());
        assert_eq!(reason.publish(), Err(WorkError::Closed));
        assert_eq!(reason.observed_epoch(), 1);
        let full = ReasonCore::new();
        full.epoch.store(CLOSED - 1, Ordering::Release);
        assert_eq!(full.publish(), Err(WorkError::Exhausted));
        assert_eq!(full.load(), CLOSED - 1);
        full.close();
        assert_eq!(full.publish(), Err(WorkError::Closed));
    }
}
