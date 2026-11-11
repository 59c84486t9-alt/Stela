//! A read's data on its way to guest RAM outside the devices' lock.
//!
//! On a board shared between PEs ([`super::Ans::defer_copies`]) a read whose
//! host transfer completed does not write its PRPs under the lock: the
//! inline decryption and the copy to guest RAM, the bulk of a read's cost,
//! run on the PE that released the lock ([`ReadCopy::run`]). The command
//! stays owned, its completion queued in order, until the copy is done; the
//! next transfer then publishes it exactly as it would have published a read
//! copied in place, and no later completion overtakes it.
use super::commands::Wait;
use super::namespace::ReadPlan;
use super::prp::Prps;
use crate::Result;
use crate::inline_key::InlineKey;
use alloc::{sync::Arc, vec::Vec};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use stela_contracts::Refusal;
use stela_contracts::bus::Access;
use stela_contracts::dma::{Memory, Physical, Port};
use stela_contracts::interrupt::InterruptLatch;

const RUNNING: u8 = 0;
const DONE: u8 = 1;
const FAILED: u8 = 2;
const TAKEN: u8 = 3;

/// What a [`ReadCopy`] came to, which its command's completion waits for.
pub(super) struct CopyDone {
    state: AtomicU8,
    /// Written once, by the copy, before `state` becomes [`FAILED`]; read
    /// once, under the devices' lock, after it is.
    failure: UnsafeCell<Option<Refusal>>,
}

// SAFETY: `failure` is written only before the Release store of FAILED and
// read only after the Acquire load that sees it, by one reader
// ([`CopyDone::outcome`] moves the state on to TAKEN first).
unsafe impl Sync for CopyDone {}
// SAFETY: as above; the refusal it may hold is plain owned data.
unsafe impl Send for CopyDone {}

/// A copy's state as its command's completion sees it.
pub(super) enum Copied {
    Running,
    Done,
    Failed(Refusal),
}

impl CopyDone {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(RUNNING),
            failure: UnsafeCell::new(None),
        })
    }

    fn finish(&self, result: Result<()>) {
        match result {
            Ok(()) => self.state.store(DONE, Ordering::Release),
            Err(reason) => {
                // SAFETY: the one writer, before the Release store below.
                unsafe { *self.failure.get() = Some(reason) };
                self.state.store(FAILED, Ordering::Release);
            }
        }
    }

    /// Whether the copy ran, and how; a failure is reported once.
    pub(super) fn outcome(&self) -> Copied {
        match self.state.load(Ordering::Acquire) {
            RUNNING => Copied::Running,
            DONE => Copied::Done,
            FAILED => {
                self.state.store(TAKEN, Ordering::Relaxed);
                // SAFETY: FAILED was stored after the write, and TAKEN
                // keeps any later call from reading it again.
                let reason = unsafe { (*self.failure.get()).take() };
                Copied::Failed(
                    reason.unwrap_or_else(|| stela_contracts::refuse!("ANS read copy failed")),
                )
            }
            _ => Copied::Failed(stela_contracts::refuse!(
                "ANS read copy failure already reported"
            )),
        }
    }
}

/// A completed read's bytes, decrypted and written to its PRPs by
/// [`Self::run`].
pub struct ReadCopy {
    plan: ReadPlan,
    bytes: usize,
    host: Option<Vec<u8>>,
    prps: Prps,
    inline: Option<(InlineKey, u64)>,
    done: Arc<CopyDone>,
}

impl ReadCopy {
    /// The copy of a read whose host transfer returned `host`, and what its
    /// completion waits for.
    pub(super) fn new(wait: Wait, host: Option<Vec<u8>>) -> Option<(Self, Arc<CopyDone>)> {
        let Wait::Read {
            plan,
            bytes,
            prps,
            inline,
        } = wait
        else {
            return None;
        };
        let done = CopyDone::new();
        Some((
            Self {
                plan,
                bytes,
                host,
                prps,
                inline,
                done: Arc::clone(&done),
            },
            done,
        ))
    }

    /// The bytes a read returns, as [`super::Ans::finish`] writes them in
    /// place: the host's or zeros, through the inline engine, the erased
    /// ranges zeroed after it.
    pub(super) fn data(
        plan: &ReadPlan,
        bytes: usize,
        host: Option<Vec<u8>>,
        inline: Option<&(InlineKey, u64)>,
    ) -> Result<Vec<u8>> {
        let host = match inline {
            Some((key, unit)) => {
                let mut data = host.unwrap_or_else(|| alloc::vec![0; bytes]);
                key.transform(*unit, &mut data, false)?;
                Some(data)
            }
            None => host,
        };
        Ok(plan.finish(bytes, host))
    }

    /// Decrypt and write the read's bytes to guest RAM `memory`, as its
    /// PRPs name them at physical addresses, stopping at the first fault as
    /// the copy in place does.
    pub fn run(self, memory: &mut dyn Memory) {
        let Self {
            plan,
            bytes,
            host,
            prps,
            inline,
            done,
        } = self;
        let result = Self::data(&plan, bytes, host, inline.as_ref()).and_then(|data| {
            let mut latch = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut latch);
            let mut port = Port {
                iommu: &mut Physical,
                stream: 0,
                memory,
                access: &mut access,
            };
            prps.write(&mut port, &data)
        });
        done.finish(result);
    }
}
