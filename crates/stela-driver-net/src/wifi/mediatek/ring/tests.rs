extern crate std;
use super::*;
use crate::bus::dma::{
    mapping::DomainMapping,
    memory::{CacheAttribute, PageBacking, PinnedPages},
};
use alloc::{
    alloc::{alloc_zeroed, dealloc},
    boxed::Box,
    collections::BTreeMap,
};
use core::{alloc::Layout, ops::Range};
use std::sync::Mutex;
struct Pages {
    ptr: NonNull<u8>,
    layout: Layout,
    pages: Vec<u64>,
}
// SAFETY: model-owned aligned RAM; immutable allocation metadata. Only the
// serialized state model uses raw pointers; this is not physical DMA proof.
unsafe impl Send for Pages {}
// SAFETY: same model allocation rule; no concurrently exposed Rust slices.
unsafe impl Sync for Pages {}
// SAFETY: model allocation keeps its owned zeroed RAM and mapping until
// Drop; modeled physical pages are distinct from modeled IOVA addresses.
unsafe impl PageBacking for Pages {
    fn cpu_base(&self) -> NonNull<u8> {
        self.ptr
    }
    fn physical_pages(&self) -> &[u64] {
        &self.pages
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: the pointer came from the matching allocation with this layout and is freed
        // once.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) }
    }
}
pub(crate) struct Source;
impl PageSource for Source {
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert_eq!(attribute, CacheAttribute::WriteBack);
        let n = bytes.next_multiple_of(4096);
        let layout = Layout::from_size_align(n, alignment).unwrap();
        let ptr =
                // SAFETY: the layout has a nonzero size.
                NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
        let pages = (0..n / 4096)
            .map(|i| ptr.as_ptr() as u64 + i as u64 * 4096)
            .collect();
        PinnedPages::new(Box::new(Pages { ptr, layout, pages }), bytes, alignment)
    }
}
#[derive(Default)]
pub(crate) struct Memory {
    pub(crate) next: u64,
    pub(crate) mappings: BTreeMap<u64, (PinnedPages, usize, Direction)>,
    pub(crate) fail_unmap: bool,
    pub(crate) fail_unmap_at: Option<usize>,
    pub(crate) unmaps: usize,
    pub(crate) fail_sync_at: Option<usize>,
    pub(crate) syncs: Vec<(bool, u64, Range<usize>)>,
}
#[derive(Default)]
pub(crate) struct State {
    pub(crate) memory: Arc<Mutex<Memory>>,
    pub(crate) base: u64,
    pub(crate) count: u16,
    pub(crate) head: u16,
    pub(crate) index: u16,
    pub(crate) queue_drops: usize,
    pub(crate) fail_publish: bool,
    pub(crate) fail_configure: bool,
    pub(crate) invalid_index: bool,
    pub(crate) completed: Vec<Vec<u8>>,
}
pub(crate) struct Domain(pub(crate) Arc<Mutex<Memory>>);
// SAFETY: this domain is a stateful test IOVA/page-pin map, not a claim of
// privileged IOMMU effects. It keeps pins and serializes every access.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &crate::bus::dma::pages::DmaPages,
        direction: Direction,
        limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        let pages = pages.as_single().ok_or(DmaError::MappingFailed)?;
        let mut s = self.0.lock().unwrap();
        s.next += 0x10000;
        let address = 0x10000000 + s.next;
        assert!(address + pages.bytes() as u64 - 1 <= limit);
        let pointer = pages
            .cpu_mapping(CacheAttribute::WriteBack)
            .unwrap()
            .address(0, pages.bytes())
            .unwrap()
            .as_ptr() as usize;
        s.mappings
            .insert(address, (pages.clone(), pointer, direction));
        Ok(DomainMapping {
            id: address,
            address,
            bytes: pages.bytes(),
        })
    }
    unsafe fn unmap(&self, m: DomainMapping) -> Result<(), DmaError> {
        let mut s = self.0.lock().unwrap();
        s.unmaps += 1;
        if s.fail_unmap || s.fail_unmap_at == Some(s.unmaps) {
            return Err(DmaError::InvalidationFailed);
        }
        s.mappings.remove(&m.id).ok_or(DmaError::Unmapped)?;
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        m: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        let mut s = self.0.lock().unwrap();
        assert_eq!(s.mappings[&m.id].2, direction);
        assert!(range.start <= range.end && range.end <= m.bytes);
        s.syncs.push((false, m.id, range));
        if s.fail_sync_at == Some(s.syncs.len()) {
            return Err(DmaError::VisibilityFailed);
        }
        Ok(())
    }
    unsafe fn sync_for_cpu(
        &self,
        m: DomainMapping,
        range: Range<usize>,
        direction: Direction,
    ) -> Result<(), DmaError> {
        let mut s = self.0.lock().unwrap();
        assert_eq!(s.mappings[&m.id].2, direction);
        assert!(range.start <= range.end && range.end <= m.bytes);
        s.syncs.push((true, m.id, range));
        if s.fail_sync_at == Some(s.syncs.len()) {
            return Err(DmaError::VisibilityFailed);
        }
        Ok(())
    }
}
pub(crate) struct Io(pub(crate) Arc<Mutex<State>>);
impl Drop for Io {
    fn drop(&mut self) {
        self.0.lock().unwrap().queue_drops += 1;
    }
}
// SAFETY: serialized test device queues; completions advance only when the
// device model reads its separately mapped IOVA payload/descriptor.
unsafe impl QueueIo for Io {
    fn configure(&mut self, address: u32, count: u16) -> Result<(), Error> {
        let mut s = self.0.lock().unwrap();
        s.base = u64::from(address);
        s.count = count;
        s.head = 0;
        s.index = 0;
        if s.fail_configure {
            return Err(Error::RegisterFailure);
        }
        Ok(())
    }
    fn device_index(&mut self) -> Result<u16, Error> {
        let s = self.0.lock().unwrap();
        Ok(if s.invalid_index { u16::MAX } else { s.index })
    }
    fn publish(&mut self, head: u16) -> Result<(), Error> {
        let mut s = self.0.lock().unwrap();
        s.head = head;
        if s.fail_publish {
            return Err(Error::RegisterFailure);
        }
        Ok(())
    }
}
fn setup(count: usize) -> (TxRing<Io>, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State::default()));
    let domain: Arc<dyn DmaDomain> = Arc::new(Domain(state.lock().unwrap().memory.clone()));
    // SAFETY: no hardware; brand-new model queue is exclusively owned/idle.
    let ring = unsafe { TxRing::install(Io(state.clone()), &Source, domain, count) }.unwrap();
    (ring, state)
}
pub(crate) fn device_complete_one(state: &Arc<Mutex<State>>) {
    let mut s = state.lock().unwrap();
    assert_ne!(s.index, s.head);
    let ptr = s.memory.lock().unwrap().mappings[&s.base].1 + s.index as usize * DESC_BYTES;
    // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and nothing
    // accesses it concurrently.
    let descriptor = unsafe { core::slice::from_raw_parts(ptr as *const u32, 4) };
    let address = u64::from(u32::from_le(descriptor[0]));
    let ctrl = u32::from_le(descriptor[1]);
    assert_eq!(ctrl & (DONE | LAST), LAST);
    assert_eq!(descriptor[2], 0);
    assert_eq!(descriptor[3], 0);
    let len = (ctrl >> 16 & 0x3fff) as usize;
    let payload = s.memory.lock().unwrap().mappings[&address].1;
    assert_ne!(address, payload as u64);
    // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and nothing
    // accesses it concurrently.
    let bytes = unsafe { core::slice::from_raw_parts(payload as *const u8, len) }.to_vec();
    s.completed.push(bytes);
    s.index = (s.index + 1) % s.count;
}
#[test]
fn iova_payload_and_dma_index_ownership_survive_many_ring_wraps() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut ring, state) = setup(8);
    for i in 0..70u64 {
        let bytes = vec![i as u8; 4096 - i as usize];
        ring.submit(i, &bytes).unwrap();
        assert_eq!(ring.pending(), 1);
        assert_eq!(ring.poll().unwrap(), None); // enqueue/head is not completion
        device_complete_one(&state);
        assert_eq!(
            ring.poll().unwrap(),
            Some(Completion {
                cookie: i,
                bytes: bytes.len()
            })
        );
        assert_eq!(state.lock().unwrap().completed.last(), Some(&bytes));
    }
    let s = state.lock().unwrap();
    assert_eq!(s.completed.len(), 70);
    assert_eq!(
        s.memory
            .lock()
            .unwrap()
            .syncs
            .iter()
            .filter(|v| v.0)
            .count(),
        140
    );
    drop(s);
    // SAFETY: model stopped consuming and every submission is completed.
    unsafe { ring.release_after_quiesce() }.unwrap();
    assert!(
        state
            .lock()
            .unwrap()
            .memory
            .lock()
            .unwrap()
            .mappings
            .is_empty()
    );
    assert_eq!(ring.submit(1, &[1]), Err(Error::Poisoned));
}
#[test]
fn two_entry_reserve_and_bad_hardware_progress_fail_explicitly() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut ring, state) = setup(4);
    ring.submit(1, &[1]).unwrap();
    ring.submit(2, &[2]).unwrap();
    assert_eq!(ring.submit(3, &[3]), Err(Error::Full));
    assert!(!ring.is_poisoned());
    state.lock().unwrap().index = 3;
    assert_eq!(ring.poll(), Err(Error::InvalidDeviceIndex));
    assert!(ring.is_poisoned());
    assert_eq!(ring.poll(), Err(Error::Poisoned));
    // SAFETY: explicit model stop prevents any future descriptor/payload reads.
    unsafe { ring.release_after_quiesce() }.unwrap();
}
#[test]
fn failed_publication_keeps_pending_dma_and_retry_requires_quiescence() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut ring, state) = setup(4);
    state.lock().unwrap().fail_publish = true;
    assert_eq!(ring.submit(7, &[0xa5; 4096]), Err(Error::RegisterFailure));
    assert_eq!(ring.pending(), 1);
    assert_eq!(ring.submit(8, &[1]), Err(Error::Poisoned));
    assert_eq!(
        state.lock().unwrap().memory.lock().unwrap().mappings.len(),
        5
    );
    // SAFETY: device model explicitly stopped before attempting teardown.
    state.lock().unwrap().memory.lock().unwrap().fail_unmap = true;
    assert_eq!(
        // SAFETY: the model device is stopped and drained, so nothing still uses what this
        // releases.
        unsafe { ring.release_after_quiesce() },
        Err(Error::Dma(DmaError::InvalidationFailed))
    );
    assert_eq!(
        state.lock().unwrap().memory.lock().unwrap().mappings.len(),
        5
    );
    state.lock().unwrap().memory.lock().unwrap().fail_unmap = false;
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    unsafe { ring.release_after_quiesce() }.unwrap();
    assert!(
        state
            .lock()
            .unwrap()
            .memory
            .lock()
            .unwrap()
            .mappings
            .is_empty()
    );
}
#[test]
fn dropping_active_queue_quarantines_descriptor_and_exposed_payload_pins() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut ring, state) = setup(4);
    ring.submit(9, &[9]).unwrap();
    drop(ring);
    // Three never-published payload allocations unmap; active descriptor and
    // payload mappings keep their domain and pins through canonical Drop.
    assert_eq!(
        state.lock().unwrap().memory.lock().unwrap().mappings.len(),
        2
    );
    assert_eq!(state.lock().unwrap().queue_drops, 0);
    device_complete_one(&state);
    assert_eq!(state.lock().unwrap().completed[0], [9]);
}
#[test]
fn visibility_failures_poison_without_releasing_unknown_ownership() {
    if crate::test_process::isolate_model() {
        return;
    }
    for fail_at in [2, 3, 4, 5] {
        let (mut ring, state) = setup(4);
        state.lock().unwrap().memory.lock().unwrap().fail_sync_at = Some(fail_at);
        let submit = ring.submit(11, &[11; 4096]);
        if fail_at <= 3 {
            assert_eq!(submit, Err(Error::Dma(DmaError::VisibilityFailed)));
        } else {
            submit.unwrap();
            device_complete_one(&state);
            assert_eq!(ring.poll(), Err(Error::Dma(DmaError::VisibilityFailed)));
            assert_eq!(ring.pending(), 1);
        }
        assert!(ring.is_poisoned());
        assert_eq!(ring.submit(12, &[12]), Err(Error::Poisoned));
        assert_eq!(
            state.lock().unwrap().memory.lock().unwrap().mappings.len(),
            5
        );
        // SAFETY: model is explicitly stopped before mappings are removed.
        unsafe { ring.release_after_quiesce() }.unwrap();
        assert!(
            state
                .lock()
                .unwrap()
                .memory
                .lock()
                .unwrap()
                .mappings
                .is_empty()
        );
    }
}
#[test]
fn partial_unmap_failure_can_finish_after_acknowledged_quiescence() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut ring, state) = setup(4);
    ring.submit(20, &[20]).unwrap();
    state.lock().unwrap().memory.lock().unwrap().fail_unmap_at = Some(2);
    assert_eq!(
        // SAFETY: hardware model stopped; injected invalidation error keeps the still-mapped
        // resources for the explicit later retry.
        unsafe { ring.release_after_quiesce() },
        Err(Error::Dma(DmaError::InvalidationFailed))
    );
    assert_eq!(
        state.lock().unwrap().memory.lock().unwrap().mappings.len(),
        4
    );
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    unsafe { ring.release_after_quiesce() }.unwrap();
    assert_eq!(ring.pending(), 0);
    assert!(
        state
            .lock()
            .unwrap()
            .memory
            .lock()
            .unwrap()
            .mappings
            .is_empty()
    );
}
#[test]
fn uncertain_configuration_keeps_only_the_published_descriptor_mapping() {
    if crate::test_process::isolate_model() {
        return;
    }
    let state = Arc::new(Mutex::new(State {
        fail_configure: true,
        ..State::default()
    }));
    let domain: Arc<dyn DmaDomain> = Arc::new(Domain(state.lock().unwrap().memory.clone()));
    assert!(matches!(
        // SAFETY: exclusive brand-new idle model. Configure fails after base publication,
        // making its descriptor mapping conservatively uncertain.
        unsafe { TxRing::install(Io(state.clone()), &Source, domain, 4) },
        Err(Error::RegisterFailure)
    ));
    assert_eq!(
        state.lock().unwrap().memory.lock().unwrap().mappings.len(),
        1
    );
    assert_eq!(state.lock().unwrap().queue_drops, 0);
}
#[test]
fn requester_and_bar_owner_drop_only_after_full_quiescent_unmap() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut ring, state) = setup(4);
    ring.submit(1, &[1]).unwrap();
    state.lock().unwrap().memory.lock().unwrap().fail_unmap_at = Some(2);
    assert_eq!(
        // SAFETY: stopped model; partial invalidation fails and keeps Q alive.
        unsafe { ring.release_after_quiesce() },
        Err(Error::Dma(DmaError::InvalidationFailed))
    );
    assert_eq!(state.lock().unwrap().queue_drops, 0);
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    unsafe { ring.release_after_quiesce() }.unwrap();
    assert_eq!(state.lock().unwrap().queue_drops, 0);
    drop(ring);
    assert_eq!(state.lock().unwrap().queue_drops, 1);
}
