//! Journal writes (`stela_formats::journal`) to files in the store's
//! directory, shared by the translation pack and the pipeline store: the
//! targets that carry a journal plan's writes to a file's device extents,
//! queued through the staged partition while the guest runs or completed at
//! once at a stop, and the slot that admits one writer at a time.
use alloc::{format, string::String, vec, vec::Vec};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_drivers::block::{BlockDevice, Command};
use stela_formats::journal::{Target, device_ranges};
use stela_formats::payload::pieces::Extent;

/// A writer's state, one holder at a time: a step while the guest runs
/// skips while another holds it, the write at a stop waits.
pub(super) struct Held<T> {
    held: AtomicBool,
    value: UnsafeCell<Option<T>>,
}
// SAFETY: `held` admits one holder at a time to `value`; the processors
// share one address space and its allocator, so a writer moves between them
// whole.
unsafe impl<T> Sync for Held<T> {}

impl<T> Held<T> {
    pub(super) const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            value: UnsafeCell::new(None),
        }
    }

    /// Runs `f` on the slot holding it: at once or not at all unless
    /// `wait`.
    pub(super) fn holding<R>(&self, wait: bool, f: impl FnOnce(&mut Option<T>) -> R) -> Option<R> {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            if !wait {
                return None;
            }
            core::hint::spin_loop();
        }
        // SAFETY: `held` is ours until the store below.
        let result = f(unsafe { &mut *self.value.get() });
        self.held.store(false, Ordering::Release);
        Some(result)
    }

    /// Runs `f` on the writer, if there is one and nobody else holds it.
    pub(super) fn try_with<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        self.holding(false, |slot| slot.as_mut().map(f)).flatten()
    }

    /// Runs `f` on the writer, if there is one, waiting for its holder.
    pub(super) fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        self.holding(true, |slot| slot.as_mut().map(f)).flatten()
    }
}

/// The commands the write in flight queued, by the file offset it began at.
#[derive(Default)]
pub(super) struct Queued {
    at: Option<u64>,
    tags: Vec<u32>,
}

/// The staged partition while the guest runs: each write queues its
/// commands and is made again until they finished.
pub(super) struct Staged<'a> {
    pub device: &'a mut dyn BlockDevice,
    pub extents: &'a [Extent],
    pub queued: &'a mut Queued,
}

impl Staged<'_> {
    /// Queue `commands` for the write at `at`, or take their results:
    /// whether all finished.
    fn run(
        &mut self,
        at: u64,
        commands: impl FnOnce() -> Result<Vec<Command>, String>,
    ) -> Result<bool, String> {
        if self.queued.at != Some(at) {
            let mut tags = Vec::new();
            for command in commands()? {
                tags.push(
                    self.device
                        .start(command)
                        .map_err(|error| format!("{error:?}"))?,
                );
            }
            *self.queued = Queued { at: Some(at), tags };
            return Ok(false);
        }
        while let Some(&tag) = self.queued.tags.last() {
            match self.device.finish(tag) {
                None => return Ok(false),
                Some(result) => {
                    result.map_err(|error| format!("{error:?}"))?;
                    self.queued.tags.pop();
                }
            }
        }
        *self.queued = Queued::default();
        Ok(true)
    }
}

/// The device writes of `bytes` at file offset `offset`.
fn ranges(
    extents: &[Extent],
    block: u64,
    offset: u64,
    bytes: &[u8],
) -> Result<Vec<(u64, u64, usize)>, String> {
    device_ranges(extents, block, offset, bytes.len() as u64).ok_or_else(|| {
        format!(
            "bytes {offset}+{} are not on the file's blocks",
            bytes.len()
        )
    })
}

impl Target for Staged<'_> {
    type Error = String;
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<bool, String> {
        let block = u64::from(self.device.identity().block_size);
        let extents = self.extents;
        self.run(offset, || {
            Ok(ranges(extents, block, offset, bytes)?
                .into_iter()
                .map(|(lba, length, from)| Command::Write {
                    lba,
                    data: bytes[from..from + length as usize].to_vec(),
                    fua: false,
                })
                .collect())
        })
    }
    fn flush(&mut self) -> Result<bool, String> {
        self.run(u64::MAX, || Ok(vec![Command::Flush]))
    }
}

/// The partition at a stop: each write completes before it returns.
pub(super) struct Direct<'a> {
    pub device: &'a mut dyn BlockDevice,
    pub extents: &'a [Extent],
}

impl Target for Direct<'_> {
    type Error = String;
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<bool, String> {
        let block = u64::from(self.device.identity().block_size);
        for (lba, length, from) in ranges(self.extents, block, offset, bytes)? {
            self.device
                .write(lba, &bytes[from..from + length as usize])
                .map_err(|error| format!("{error:?}"))?;
        }
        Ok(true)
    }
    fn flush(&mut self) -> Result<bool, String> {
        self.device.flush().map_err(|error| format!("{error:?}"))?;
        Ok(true)
    }
}
