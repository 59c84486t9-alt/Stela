//! Actual hosted resource owners, never native CPU/root/current authority.
extern crate std;
use super::super::WorkError;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use std::{thread, time::Instant};
mod idle;
mod memory;
mod signal;
pub use idle::{HostedClock, HostedIdle};
pub use memory::{HostFrameId, HostedPages};
pub(super) use signal::HostedRaisedWork;
pub use signal::HostedReason;
/// Same OS process/thread and observed clock. It owns no Queue/Runtime/Kernel,
/// installed root, native IRQ or original source-current object.
pub struct HostedExecution {
    pid: u32,
    thread: thread::ThreadId,
    handle: thread::Thread,
    origin: Instant,
    next_frame: AtomicU64,
}
impl HostedExecution {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pid: std::process::id(),
            thread: thread::current().id(),
            handle: thread::current(),
            origin: Instant::now(),
            next_frame: AtomicU64::new(1),
        })
    }
    pub fn check_process(&self) -> Result<(), WorkError> {
        if self.pid == std::process::id() {
            Ok(())
        } else {
            Err(WorkError::WrongCpu)
        }
    }
    pub fn check_current(&self) -> Result<(), WorkError> {
        self.check_process()?;
        if self.thread == thread::current().id() {
            Ok(())
        } else {
            Err(WorkError::WrongCpu)
        }
    }
    pub fn same_owner(&self, other: &Self) -> bool {
        core::ptr::eq(self, other)
    }
    fn now_ns(&self) -> Result<u64, WorkError> {
        self.check_current()?;
        u64::try_from(self.origin.elapsed().as_nanos()).map_err(|_| WorkError::Exhausted)
    }
    fn reserve_frames(&self, count: usize) -> Result<u64, WorkError> {
        self.check_current()?;
        let count = u64::try_from(count).map_err(|_| WorkError::Exhausted)?;
        self.next_frame
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(count)
            })
            .map_err(|_| WorkError::Exhausted)
    }
}

#[cfg(test)]
mod tests;
