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
