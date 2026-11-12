//! Compilations a call leaves to run outside the service's turn
//! (`service/shared.rs`).
//!
//! A call whose compilation no cache holds fails with
//! [`compiler::DEFERRED`](super::compiler::DEFERRED) and leaves a [`Job`]:
//! the compiler's AIR to NIR lowering, or the backend's pipeline creation,
//! which runs NIR to machine code. The job owns its inputs, so it runs on
//! any processor while other calls take turns. Its [`Done`] goes back to its
//! owner in a later turn, and the call, run again, finds what it made.
use super::compiler::CompileLock;
use alloc::{boxed::Box, sync::Arc};
use core::any::Any;

pub(crate) mod kept;

/// Which of the device's parts made a job, and adopts what it made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Owner {
    Compiler,
    Backend,
}

/// What a deferred job made, for its owner.
pub type Made = Box<dyn Any + Send>;

/// A deferred compilation, keyed by what it makes: equal keys make the same.
pub struct Job {
    pub key: [u8; 32],
    pub owner: Owner,
    run: Box<dyn FnOnce() -> Made + Send>,
}

impl Job {
    pub fn new(key: [u8; 32], owner: Owner, run: impl FnOnce() -> Made + Send + 'static) -> Self {
        Self {
            key,
            owner,
            run: Box::new(run),
        }
    }

    /// Runs the job. Jobs run one at a time, on the one compile stack,
    /// under the compile lock the caller holds.
    pub fn run(self, _held: &super::compiler::CompileGuard<'_>) -> Done {
        Done {
            key: self.key,
            owner: self.owner,
            made: (self.run)(),
        }
    }
}

impl core::fmt::Debug for Job {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Job")
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

/// A job that ran.
pub struct Done {
    pub key: [u8; 32],
    pub owner: Owner,
    pub made: Made,
}

/// The lock jobs run under, and what a waiter for it runs: a backend holds
/// it while it destroys what its jobs use.
#[derive(Clone)]
pub struct JobLock {
    pub lock: Arc<CompileLock>,
    pub relax: fn(),
}

/// Which processor offers to run a deferred job, between two slices of its
/// guest and never inside a guest's call: the platform's policy, whose
/// numbers [`Taker::after_millis`] and [`busy_pause_millis`] give.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Taker {
    /// A processor other than the boot one whose guest waits for an
    /// interrupt: it takes any job at once.
    Waiting,
    /// The boot processor while its guest waits, whose Linux work a job
    /// holds up: it takes a job no other took within 100 ms.
    Boot,
    /// A processor other than the boot one between two slices of guest user
    /// code: it takes a job no other took within 20 ms, about a frame at
    /// 60 Hz. With every guest CPU busy, as in a benchmark, a call waiting
    /// for a job then waits about a frame, and no guest call or kernel code
    /// waits for one. The guest's priority of the thread it interrupts is
    /// not known there, so any user code is as good a place as another.
    Busy,
}

impl Taker {
    /// How long a job waits before this taker takes it, in milliseconds.
    pub const fn after_millis(self) -> u64 {
        match self {
            Self::Waiting => 0,
            Self::Boot => 100,
            Self::Busy => 20,
        }
    }
}

/// How long busy processors leave the queue after one of them looked, in
/// milliseconds: after a job, 10 ms, so that a queue costs busy guests about
/// half of one processor at most (jobs averaged 9.6 ms over 4374 in a
/// 50-minute run); with none due, 1 ms, so that the pause adds at most that
/// to a job's wait, and a busy slice pays a load and the queue a look a
/// millisecond.
pub const fn busy_pause_millis(ran: bool) -> u64 {
    if ran { 10 } else { 1 }
}

/// The longest a job waits for a processor when every guest CPU is busy and
/// none runs another job, in milliseconds.
pub const fn busy_wait_millis() -> u64 {
    Taker::Busy.after_millis() + busy_pause_millis(false)
}

#[cfg(test)]
mod tests {
    use super::{Taker, busy_pause_millis, busy_wait_millis};

    #[test]
    fn a_job_waits_about_a_frame_with_every_processor_busy() {
        assert_eq!(Taker::Waiting.after_millis(), 0);
        assert!(Taker::Busy.after_millis() < Taker::Boot.after_millis());
        // A 125 ms wait (100 ms and a 25 ms look gap) was seen; the bound is
        // now a frame and a look.
        assert_eq!(busy_wait_millis(), 21);
        assert!(busy_pause_millis(false) < busy_pause_millis(true));
    }
}
