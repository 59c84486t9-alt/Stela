//! Retained original physical-function and bridge-assignment custody.
//!
//! This module performs no device access. A producer must supply the ACTUAL
//! exclusive allocation/control product; observations, ECAM views and BDF data
//! cannot construct one. Native producer integration is a separate dependency.
use alloc::sync::Arc;
use core::{
    marker::PhantomData,
    mem::ManuallyDrop,
    sync::atomic::{AtomicUsize, Ordering},
};
const CLOSED: usize = 1usize << (usize::BITS - 1);
const COUNT: usize = CLOSED - 1;
static ABANDONED_CONTROLS: AtomicUsize = AtomicUsize::new(0);
static ABANDONED_USES: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Closed,
    Open,
    Busy { uses: usize, retentions: usize },
    Exhausted,
    Context,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UseKind {
    Resource,
    Mapping,
    Configuration,
    Interrupt,
    Dma,
    Alias,
}

/// Actual retention-only reservation from the original exclusive function and
/// fabric/bridge-assignment producer, before/alongside its configuration map.
///
/// # Safety
/// Own the real physical allocation, configuration/reset/removal/assignment
/// exclusion and all original parent routing/window reservations. Retain actual
/// host product/code allocations, not merely copied addresses or root numbers.
/// Transitive fields MUST NOT own a Mapping, MappingView, MMIO Authority, Source,
/// driver control or callback to one: resource inventories retain this product.
/// Parent must be the exact original owning bridge/fabric ancestor, immutable
/// and acyclic; no address or lookup can substitute for its actual reservation.
/// check_control validates the original execution owner/context, granting no
/// hardware retirement proof. Do not release rights in Drop: abandonment must
/// retain/quarantine the real product. Only an explicit source-owned retirement
/// transaction may release/reassign/reset the returned original product.
pub unsafe trait PhysicalAssignment: Send + Sync + 'static {
    fn parent(&self) -> Option<&Parent>;
    fn check_control(&self) -> Result<(), Error>;
}

trait Ancestor: Send + Sync {
    fn acquire(&self) -> Result<(), Error>;
    fn release(&self);
}
/// Retention-only actual ancestor, never a new config/reset/I/O capability.
#[derive(Clone)]
pub struct Parent {
    original: Arc<dyn Ancestor>,
}
struct Gate {
    state: AtomicUsize,
    parent: Option<Parent>,
}
impl Gate {
    fn acquire(&self) -> Result<(), Error> {
        if let Some(parent) = &self.parent {
            parent.original.acquire()?;
        }
        let result = self
            .state
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                if value & CLOSED != 0 || value & COUNT == COUNT {
                    None
                } else {
                    Some(value + 1)
                }
            });
        match result {
            Ok(_) => Ok(()),
            Err(value) => {
                if let Some(parent) = &self.parent {
                    parent.original.release();
                }
                Err(if value & CLOSED != 0 {
                    Error::Closed
                } else {
                    Error::Exhausted
                })
            }
        }
    }
    fn release(&self) {
        let prior = self.state.fetch_sub(1, Ordering::AcqRel);
        assert!(prior & COUNT != 0, "original assignment use released twice");
        if let Some(parent) = &self.parent {
            parent.original.release();
        }
    }
}
struct Storage<P: PhysicalAssignment> {
    original: ManuallyDrop<P>,
    gate: Gate,
}
impl<P: PhysicalAssignment> Ancestor for Storage<P> {
    fn acquire(&self) -> Result<(), Error> {
        self.gate.acquire()
    }
    fn release(&self) {
        self.gate.release();
    }
}
/// Unique affine control. Its storage retains actual physical custody without
/// pointing back to the config/mapping/control owner. Drop never releases it.
#[must_use = "keep the original assignment control until explicit retirement"]
pub struct Assignment<P: PhysicalAssignment> {
    storage: ManuallyDrop<Arc<Storage<P>>>,
    returned: bool,
    _local: PhantomData<*mut ()>,
}
pub struct Refusal<P: PhysicalAssignment> {
    pub error: Error,
    pub owner: Assignment<P>,
}
impl<P: PhysicalAssignment> Assignment<P> {
    /// Consume the actual physical reservation. This performs no hardware
    /// mutation or DMA/IRQ admission and supplies no native producer itself.
    pub fn from_owned(original: P) -> Self {
        let parent = original.parent().cloned();
        Self {
            storage: ManuallyDrop::new(Arc::new(Storage {
                original: ManuallyDrop::new(original),
                gate: Gate {
                    state: AtomicUsize::new(0),
                    parent,
                },
            })),
            returned: false,
            _local: PhantomData,
        }
    }
    pub fn retain(&self) -> Retention<P> {
        Retention {
            storage: Arc::clone(&self.storage),
        }
    }
    pub fn parent(&self) -> Parent {
        Parent {
            original: Arc::clone(&self.storage) as Arc<dyn Ancestor>,
        }
    }
    /// Irreversibly close admission BEFORE any assignment/reset/config effect.
    /// Busy still leaves it closed: accepted users retain actual rights until
    /// explicit retirement; a failed close is never a no-effect reset receipt.
    pub fn close(&mut self) -> Result<(), Error> {
        self.storage.original.check_control()?;
        let previous = self.storage.gate.state.fetch_or(CLOSED, Ordering::AcqRel);
        if previous & COUNT != 0 {
            return Err(Error::Busy {
                uses: previous & COUNT,
                retentions: Arc::strong_count(&self.storage) - 1,
            });
        }
        Ok(())
    }
    pub fn uses(&self) -> usize {
        self.storage.gate.state.load(Ordering::Acquire) & COUNT
    }
    /// Return the SAME original product after closed admission and all concrete
    /// uses/retentions have gone. Returning custody does not acknowledge DMA,
    /// native callbacks, hardware unmap, or authorize reset/reassignment itself.
    pub fn into_original(mut self) -> Result<P, Refusal<P>> {
        let failure = self.storage.original.check_control().err().or_else(|| {
            let state = self.storage.gate.state.load(Ordering::Acquire);
            if state & CLOSED == 0 {
                Some(Error::Open)
            } else {
                let retentions = Arc::strong_count(&self.storage) - 1;
                (state & COUNT != 0 || retentions != 0).then_some(Error::Busy {
                    uses: state & COUNT,
                    retentions,
                })
            }
        });
        if let Some(error) = failure {
            return Err(Refusal { error, owner: self });
        }
        // SAFETY: take once; returned suppresses abandonment after success.
        let storage = unsafe { ManuallyDrop::take(&mut self.storage) };
        match Arc::try_unwrap(storage) {
            Ok(mut storage) => {
                self.returned = true;
                // SAFETY: original ownership transfers once; no hardware or
                // native callback runs here. Remaining gate parent is metadata.
                Ok(unsafe { ManuallyDrop::take(&mut storage.original) })
            }
            Err(storage) => {
                self.storage = ManuallyDrop::new(storage);
                Err(Refusal {
                    error: Error::Busy {
                        uses: self.uses(),
                        retentions: Arc::strong_count(&self.storage) - 1,
                    },
                    owner: self,
                })
            }
        }
    }
}
impl<P: PhysicalAssignment> Drop for Assignment<P> {
    fn drop(&mut self) {
        if !self.returned {
            // Losing the affine controller closes every surviving admission
            // atomically, even on a foreign thread. Keep all actual rights;
            // this is metadata denial, never hardware retirement or release.
            self.storage.gate.state.fetch_or(CLOSED, Ordering::AcqRel);
            ABANDONED_CONTROLS.fetch_add(1, Ordering::Relaxed);
        }
        // ManuallyDrop keeps the ENTIRE original control/storage/ancestor graph.
    }
}
/// Allocation/assignment retention only, not entered/config/I/O permission.
pub struct Retention<P: PhysicalAssignment> {
    storage: Arc<Storage<P>>,
}
impl<P: PhysicalAssignment> Clone for Retention<P> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
        }
    }
}
impl<P: PhysicalAssignment> Retention<P> {
    pub fn same_assignment(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.storage, &other.storage)
    }
    pub fn begin_use(&self, kind: UseKind) -> Result<Use<P>, Error> {
        self.storage.gate.acquire()?;
        Ok(Use {
            storage: ManuallyDrop::new(self.storage.clone()),
            kind,
            released: false,
        })
    }
}
/// Owned pending/live use. Drop retains its count AND complete physical graph;
/// it cannot convert unknown device/IRQ/DMA/map completion into retirement.
#[must_use = "explicitly retire the real use or retain its complete graph"]
pub struct Use<P: PhysicalAssignment> {
    storage: ManuallyDrop<Arc<Storage<P>>>,
    kind: UseKind,
    released: bool,
}
impl<P: PhysicalAssignment> Use<P> {
    pub fn kind(&self) -> UseKind {
        self.kind
    }
    /// # Safety
    /// Every actual user represented by this token has completed, including
    /// CPU/raw-pointer access, physical unmap/TLB/cache acknowledgement, native
    /// callback/return tails and source-specific IRQ/DMA fences as appropriate.
    /// No user may restart. This releases metadata counts, not hardware rights.
    pub unsafe fn release(mut self) -> Result<(), (Error, Self)> {
        if let Err(error) = self.storage.original.check_control() {
            return Err((error, self));
        }
        self.storage.gate.release();
        self.released = true;
        // SAFETY: exactly this consumed use's one retained Arc, once.
        drop(unsafe { ManuallyDrop::take(&mut self.storage) });
        Ok(())
    }
}
impl<P: PhysicalAssignment> Drop for Use<P> {
    fn drop(&mut self) {
        if !self.released {
            ABANDONED_USES.fetch_add(1, Ordering::Relaxed);
        }
    }
}
pub fn abandoned_controls() -> usize {
    ABANDONED_CONTROLS.load(Ordering::Relaxed)
}
pub fn abandoned_uses() -> usize {
    ABANDONED_USES.load(Ordering::Relaxed)
}
#[cfg(test)]
mod tests;
