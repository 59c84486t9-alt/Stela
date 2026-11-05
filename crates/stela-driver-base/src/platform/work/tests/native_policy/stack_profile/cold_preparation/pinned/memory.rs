//! Owned RAM mappings and pin views used by the hosted preparation model.
use super::*;
pub(super) struct Source {
    pub(super) actual: Arc<Box<dyn StackBacking>>,
    pub(super) other: Option<Arc<Box<dyn StackBacking>>>,
    pub(super) scene: Arc<PinScene>,
    pub(super) index: usize,
    pub(super) last_epoch: AtomicU64,
    pub(super) active_epoch: Arc<AtomicU64>,
}
// SAFETY: this wrapper owns the original mmap object, not just bounds
// or a lifetime token. Its Arc keeps both real PROT_NONE guards and RAM alive.
// Exported page views share THAT allocation owner until exact release.
unsafe impl StackBacking for Source {
    fn bounds(&self) -> Range<usize> {
        self.actual.bounds()
    }
    fn guard(&self) -> Range<usize> {
        self.actual.guard()
    }
    unsafe fn pin_prepared_pages(&self, epoch: u64) -> Result<PinnedPages, MemoryError> {
        assert!(epoch != 0);
        self.scene.exports.fetch_add(1, Ordering::Relaxed);
        assert_eq!(self.scene.cpu.model.flags(), 0x202);
        assert_eq!(self.scene.entered.load(Ordering::Acquire), 1);
        let range = self.actual.bounds();
        assert!(
            // SAFETY: the cold caller holds the never-entered mapping in
            // Preparing and has zeroed its usable bytes. This reads only them.
            unsafe { core::slice::from_raw_parts(range.start as *const u8, range.len()) }
                .iter()
                .all(|byte| *byte == 0)
        );
        if self.scene.case == Case::Oom {
            return Err(MemoryError::OutOfMemory);
        }
        assert!(epoch > self.last_epoch.load(Ordering::Acquire));
        if self
            .active_epoch
            .compare_exchange(0, epoch, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(MemoryError::Unavailable);
        }
        let lease = EpochLease {
            active: self.active_epoch.clone(),
            epoch,
        };
        let actual = self.other.as_ref().unwrap_or(&self.actual).clone();
        let range = actual.bounds();
        let bytes = if self.scene.case == Case::Subset {
            range.len() / 2
        } else {
            range.len()
        };
        let shift = if self.scene.case == Case::Granule {
            14
        } else {
            12
        };
        // These independent symbolic PFNs model allocation granules; actual
        // CPU storage/ownership are real, but this is not native PA evidence.
        let physical = (0..(bytes >> shift))
            .map(|i| 0x6000_0000 + self.index as u64 * 0x10_0000 + ((i as u64) << shift))
            .collect();
        let view = View {
            actual,
            start: range.start,
            physical,
            shift,
            dropped: self.scene.pins_dropped.clone(),
            _epoch: lease,
        };
        let logical = if self.scene.case == Case::Logical {
            bytes - 1
        } else {
            bytes
        };
        let pin = PinnedPages::new(Box::new(view), logical, 1 << shift)?;
        self.last_epoch.store(epoch, Ordering::Release);
        if self.scene.case == Case::HeldView {
            *self.scene.held_view.lock().unwrap() =
                Some(pin.cpu_mapping(CacheAttribute::WriteBack)?);
        }
        if self.scene.case == Case::PostStale {
            self.scene.active.store(false, Ordering::Release);
        }
        Ok(pin)
    }
}
pub(super) struct EpochLease {
    pub(super) active: Arc<AtomicU64>,
    pub(super) epoch: u64,
}
impl Drop for EpochLease {
    fn drop(&mut self) {
        assert_eq!(
            self.active
                .compare_exchange(self.epoch, 0, Ordering::AcqRel, Ordering::Acquire),
            Ok(self.epoch)
        );
    }
}
pub(super) struct View {
    pub(super) actual: Arc<Box<dyn StackBacking>>,
    pub(super) start: usize,
    pub(super) physical: Vec<u64>,
    pub(super) shift: u8,
    pub(super) dropped: Arc<AtomicUsize>,
    pub(super) _epoch: EpochLease,
}
impl Drop for View {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: CPU-model view keeps the SAME real exclusively owned mmap object;
// its usable bytes are mapped/zeroed and guards excluded. Immutable PA
// labels/granule metadata are symbolic and never used for DMA/native evidence.
// Dropping the view cannot munmap while Runtime still holds the real owner.
unsafe impl PageBacking for View {
    fn cpu_base(&self) -> NonNull<u8> {
        assert!(self.actual.bounds().contains(&self.start));
        NonNull::new(self.start as *mut u8).unwrap()
    }
    fn physical_pages(&self) -> &[u64] {
        &self.physical
    }
    fn page_shift(&self) -> u8 {
        self.shift
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
pub(super) fn mappings(f: &Arc<PinScene>, dropped: &Arc<AtomicUsize>) -> Vec<Stack> {
    let other = if f.case == Case::Other {
        let Stack { backing, .. } = support::mapped(kernel(), 0, dropped);
        Some(Arc::new(backing))
    } else {
        None
    };
    support::stacks(dropped, 20)
        .into_iter()
        .enumerate()
        .map(|(index, stack)| {
            if f.case == Case::Missing {
                return stack;
            }
            let Stack { backing, .. } = stack;
            Stack::new(Box::new(Source {
                actual: Arc::new(backing),
                other: other.clone(),
                scene: f.clone(),
                index,
                last_epoch: AtomicU64::new(0),
                active_epoch: Arc::new(AtomicU64::new(0)),
            }))
            .unwrap()
        })
        .collect()
}
