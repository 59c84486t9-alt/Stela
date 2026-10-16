//! Actual byte-write accounting for factory-owned mutable instruction RAM.
//! Mapping, control and compiled-source generations remain separate owners.
use super::{MemoryStatus, MemorySystem};
use crate::memory::backing::MemoryBacking;
use crate::platform::sync::{Mutex, MutexGuard};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub(in crate::memory) struct SourceMutationTracker {
    enabled: AtomicBool,
    generation: AtomicU64,
    failed: AtomicBool,
    state: Mutex<Option<SourceMutationState>>,
}
struct SourceMutationState {
    system: Weak<()>,
    generation: u64,
}
impl SourceMutationTracker {
    pub(in crate::memory) fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            failed: AtomicBool::new(false),
            state: Mutex::new(None),
        }
    }
}

/// Constructed only immediately after an actual tracked byte effect. Private
/// fields bind the original backing/System and contiguous before/after epochs.
/// It is not Clone and copied progress cannot replace it.
pub(crate) struct SourceWriteReceipt {
    backing: Arc<MemoryBacking>,
    system: Arc<()>,
    offset: usize,
    bytes: usize,
    before: u64,
    after: u64,
}
impl SourceWriteReceipt {
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
}
impl core::fmt::Debug for SourceWriteReceipt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SourceWriteReceipt")
            .field("backing", &self.backing.id())
            .field("offset", &self.offset)
            .field("bytes", &self.bytes)
            .field("before", &self.before)
            .field("after", &self.after)
            .finish()
    }
}

pub(in crate::memory) struct SourceWriteGuard<'a> {
    backing: &'a Arc<MemoryBacking>,
    system: &'a MemorySystem,
    state: Option<MutexGuard<'a, Option<SourceMutationState>>>,
    offset: usize,
    bytes: usize,
    before: u64,
    after: u64,
    attempted: bool,
    finished: bool,
}
impl SourceWriteGuard<'_> {
    /// Invoke immediately before the exact native write, inside its existing
    /// reservation gate. No fallible work separates this marker from that write.
    pub(in crate::memory) fn attempting(&mut self) {
        if self.state.is_some() {
            self.backing
                .source_mutation
                .generation
                .store(self.after, Ordering::Release);
        }
        self.attempted = true;
    }
    /// Infallible accounting immediately after known completion. Arc retention
    /// does not allocate. Receipt publication uses pre-reserved caller storage.
    pub(in crate::memory) fn complete(&mut self) -> Option<SourceWriteReceipt> {
        self.finished = true;
        let state = self
            .state
            .as_mut()?
            .as_mut()
            .expect("retained source tracker");
        state.generation = self.after;
        Some(SourceWriteReceipt {
            backing: Arc::clone(self.backing),
            system: Arc::clone(&self.system.identity),
            offset: self.offset,
            bytes: self.bytes,
            before: self.before,
            after: self.after,
        })
    }
}
impl Drop for SourceWriteGuard<'_> {
    fn drop(&mut self) {
        if self.state.is_some() && self.attempted && !self.finished {
            // An unknown host-effect outcome never becomes an unchanged source.
            self.backing
                .source_mutation
                .failed
                .store(true, Ordering::Release);
            self.system.failed.store(true, Ordering::Release);
        }
    }
}

impl MemoryBacking {
    /// Sole fresh source-RAM materializer calls this before any PE/view escapes.
    pub(in crate::memory) fn enable_instruction_mutation(
        &self,
        system: &Arc<MemorySystem>,
    ) -> Result<(), MemoryStatus> {
        if !self.maximum_permissions().writable || !self.maximum_permissions().executable {
            return Err(MemoryStatus::InvalidRequest);
        }
        self.bind_coherence(&system.identity)
            .map_err(|_| MemoryStatus::Domain)?;
        let mut state = self
            .source_mutation
            .state
            .lock()
            .map_err(|_| MemoryStatus::Domain)?;
        if state.is_some() {
            return Err(MemoryStatus::InvalidRequest);
        }
        *state = Some(SourceMutationState {
            system: Arc::downgrade(&system.identity),
            generation: 1,
        });
        self.source_mutation.generation.store(1, Ordering::Release);
        self.source_mutation.enabled.store(true, Ordering::Release);
        Ok(())
    }
    #[cfg(test)]
    pub(in crate::memory) fn exhaust_instruction_generation_for_test(&self) {
        let mut state = self.source_mutation.state.lock().unwrap();
        state.as_mut().unwrap().generation = u64::MAX;
        self.source_mutation
            .generation
            .store(u64::MAX, Ordering::Release);
    }
    pub(crate) fn instruction_generation(&self) -> Option<u64> {
        self.source_mutation
            .enabled
            .load(Ordering::Acquire)
            .then(|| self.source_mutation.generation.load(Ordering::Acquire))
    }
    pub(crate) fn instruction_generation_current(&self, generation: u64) -> bool {
        !self.source_mutation.failed.load(Ordering::Acquire)
            && self.instruction_generation() == Some(generation)
    }
}
impl MemorySystem {
    pub(in crate::memory) fn prepare_source_write<'a>(
        &'a self,
        backing: &'a Arc<MemoryBacking>,
        offset: usize,
        bytes: usize,
    ) -> Result<SourceWriteGuard<'a>, MemoryStatus> {
        if self.failed.load(Ordering::Acquire) {
            return Err(MemoryStatus::Domain);
        }
        let mut guard = SourceWriteGuard {
            backing,
            system: self,
            state: None,
            offset,
            bytes,
            before: 0,
            after: 0,
            attempted: false,
            finished: false,
        };
        if !backing.source_mutation.enabled.load(Ordering::Acquire) {
            return Ok(guard);
        }
        if bytes == 0
            || offset
                .checked_add(bytes)
                .is_none_or(|end| end > backing.bytes())
        {
            return Err(MemoryStatus::InvalidRequest);
        }
        let state = backing
            .source_mutation
            .state
            .try_lock()
            .map_err(|_| MemoryStatus::Domain)?;
        let current = state.as_ref().ok_or(MemoryStatus::Domain)?;
        if backing.source_mutation.failed.load(Ordering::Acquire)
            || !current
                .system
                .upgrade()
                .is_some_and(|owner| Arc::ptr_eq(&owner, &self.identity))
        {
            return Err(MemoryStatus::Domain);
        }
        guard.before = current.generation;
        guard.after = current
            .generation
            .checked_add(1)
            .ok_or(MemoryStatus::Domain)?;
        guard.state = Some(state);
        Ok(guard)
    }

    /// Serialize the exact source read against all admitted byte writers.
    /// The closure is memory-owned raw RAM access, never a caller producer.
    pub(in crate::memory) fn read_instruction_source<T>(
        &self,
        backing: &Arc<MemoryBacking>,
        read: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<(T, Option<u64>), &'static str> {
        if self.failed.load(Ordering::Acquire) {
            return Err("source System failed");
        }
        if !backing.source_mutation.enabled.load(Ordering::Acquire) {
            return read().map(|value| (value, None));
        }
        let state = backing
            .source_mutation
            .state
            .try_lock()
            .map_err(|_| "source mutation owner busy or failed")?;
        let current = state.as_ref().ok_or("source mutation owner absent")?;
        if backing.source_mutation.failed.load(Ordering::Acquire)
            || !current
                .system
                .upgrade()
                .is_some_and(|owner| Arc::ptr_eq(&owner, &self.identity))
        {
            return Err("source mutation owner differs or failed");
        }
        let value = read()?;
        Ok((value, Some(current.generation)))
    }

    pub(crate) fn validate_owned_source_writes(
        &self,
        backing: &Arc<MemoryBacking>,
        generation: Option<u64>,
        writes: &[SourceWriteReceipt],
    ) -> Result<(), &'static str> {
        if self.failed.load(Ordering::Acquire) {
            return Err("source System failed");
        }
        let Some(mut expected) = generation else {
            return if backing.instruction_generation().is_none() {
                Ok(())
            } else {
                Err("immutable source changed its ownership class")
            };
        };
        let state = backing
            .source_mutation
            .state
            .try_lock()
            .map_err(|_| "in-flight source mutation owner busy or failed")?;
        let current = state
            .as_ref()
            .ok_or("in-flight source mutation owner absent")?;
        if !current
            .system
            .upgrade()
            .is_some_and(|owner| Arc::ptr_eq(&owner, &self.identity))
        {
            return Err("in-flight source has a foreign System");
        }
        for receipt in writes {
            if !Arc::ptr_eq(&receipt.system, &self.identity) {
                return Err("write receipt has a foreign System");
            }
            if Arc::ptr_eq(&receipt.backing, backing) {
                if receipt.before != expected
                    || receipt.after
                        != expected
                            .checked_add(1)
                            .ok_or("source generation exhausted")?
                    || receipt.bytes == 0
                {
                    return Err("owned source mutation chain is incomplete");
                }
                expected = receipt.after;
            }
        }
        if !backing.instruction_generation_current(expected) {
            return Err("source has an unaccounted byte writer");
        }
        Ok(())
    }
}
