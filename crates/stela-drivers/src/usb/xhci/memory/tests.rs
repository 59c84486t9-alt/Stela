//! RAM with independent CPU/device caches and nonidentity labels.
//! This peer checks production core publication; it is not physical xHCI evidence.
use super::*;
use crate::bus::dma::{
    mapping::{DmaError, DomainMapping},
    memory::{MemoryError, PageBacking, PageGeometry, PinnedPages},
    pages::DmaPages,
};
use alloc::{
    alloc::{alloc_zeroed, dealloc},
    collections::BTreeMap,
};
use core::{
    alloc::Layout,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};
extern crate std;
use std::sync::Mutex;

mod address;

struct Backing {
    pointer: NonNull<u8>,
    layout: Layout,
    physical: Vec<u64>,
    drops: Arc<AtomicUsize>,
}
// SAFETY: fixture CPU effects are serialized by the peer; stable exclusive RAM.
unsafe impl Send for Backing {}
// SAFETY: same serialized peer, no concurrent device/CPU writers or safe slices.
unsafe impl Sync for Backing {}
// SAFETY: aligned zeroed fixture RAM keeps these immutable model pages.
unsafe impl PageBacking for Backing {
    fn cpu_base(&self) -> NonNull<u8> {
        self.pointer
    }
    fn physical_pages(&self) -> &[u64] {
        &self.physical
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
        // SAFETY: original unique fixture allocation after all pins end.
        unsafe {
            dealloc(self.pointer.as_ptr(), self.layout);
        }
    }
}
struct Binding {
    token: DomainMapping,
    pages: DmaPages,
    device: Vec<u8>,
}
struct State {
    next_iova: u64,
    next_physical: u64,
    bindings: BTreeMap<u64, Binding>,
    syncs: Vec<(bool, u64, Range<usize>, u32)>,
    observations: Vec<(u64, usize)>,
    coherent: bool,
    fail_sync: Option<usize>,
    fail_after_copy: bool,
}
struct Peer {
    state: Mutex<State>,
    drops: Arc<AtomicUsize>,
}
impl Peer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                next_iova: 0x1_0000_1000,
                next_physical: 0x2000_0000,
                bindings: BTreeMap::new(),
                syncs: Vec::new(),
                observations: Vec::new(),
                coherent: true,
                fail_sync: None,
                fail_after_copy: false,
            }),
            drops: Arc::new(AtomicUsize::new(0)),
        })
    }
    fn range(state: &State, address: u64, bytes: usize) -> (u64, usize) {
        state
            .bindings
            .iter()
            .find_map(|(id, b)| {
                address.checked_sub(b.token.address).and_then(|offset| {
                    let offset = usize::try_from(offset).ok()?;
                    (offset.checked_add(bytes)? <= b.token.bytes).then_some((*id, offset))
                })
            })
            .expect("actual mapped IOVA")
    }
    fn device(&self, address: u64, bytes: usize) -> Vec<u8> {
        let state = self.state.lock().unwrap();
        let (id, offset) = Self::range(&state, address, bytes);
        state.bindings[&id].device[offset..offset + bytes].to_vec()
    }
    fn post(&self, address: u64, bytes: &[u8]) {
        let mut state = self.state.lock().unwrap();
        let (id, offset) = Self::range(&state, address, bytes.len());
        state.bindings.get_mut(&id).unwrap().device[offset..offset + bytes.len()]
            .copy_from_slice(bytes);
    }
}
impl PageSource for Peer {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        PageGeometry::base_only(12)
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert_eq!(attribute, CacheAttribute::WriteBack);
        let bytes = bytes.next_multiple_of(4096);
        let layout = Layout::from_size_align(bytes, alignment).unwrap();
        // SAFETY: checked fixture layout and owned zeroed storage; null checked.
        let pointer =
            NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
        let mut state = self.state.lock().unwrap();
        let physical = (0..bytes / 4096)
            .map(|n| state.next_physical + n as u64 * 8192)
            .collect();
        state.next_physical += bytes as u64 * 2;
        PinnedPages::new(
            Box::new(Backing {
                pointer,
                layout,
                physical,
                drops: self.drops.clone(),
            }),
            bytes,
            alignment,
        )
    }
}
fn cpu(binding: &Binding, range: Range<usize>) -> NonNull<u8> {
    binding
        .pages
        .as_single()
        .unwrap()
        .cpu_mapping(CacheAttribute::WriteBack)
        .unwrap()
        .address(range.start, range.len())
        .unwrap()
}
// SAFETY: unique exact IOVAs/tokens, same original pins, real copy-based
// CPU/device visibility, failures keep ownership. Only serialized model I/O.
unsafe impl DmaDomain for Peer {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        _: Direction,
        limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        let mut state = self.state.lock().unwrap();
        let address = state.next_iova;
        if address
            .checked_add(pages.bytes() as u64)
            .is_none_or(|end| end - 1 > limit)
        {
            return Err(DmaError::AddressLimit);
        }
        let token = DomainMapping {
            id: address,
            address,
            bytes: pages.bytes(),
        };
        state.next_iova += pages.bytes() as u64;
        state.bindings.insert(
            address,
            Binding {
                token,
                pages: pages.clone(),
                device: vec![0xa6; pages.bytes()],
            },
        );
        Ok(token)
    }
    unsafe fn unmap(&self, token: DomainMapping) -> Result<(), DmaError> {
        let mut state = self.state.lock().unwrap();
        if state
            .bindings
            .get(&token.id)
            .is_none_or(|b| b.token != token)
        {
            return Err(DmaError::Unmapped);
        }
        state.bindings.remove(&token.id);
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        token: DomainMapping,
        range: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        let mut state = self.state.lock().unwrap();
        let failed = state.fail_sync == Some(state.syncs.len());
        let after = state.fail_after_copy;
        if !failed || after {
            let binding = state.bindings.get_mut(&token.id).unwrap();
            // SAFETY: same exact pins and checked range, CPU-owned writes.
            let data = unsafe {
                core::slice::from_raw_parts(cpu(binding, range.clone()).as_ptr(), range.len())
            };
            binding.device[range.clone()].copy_from_slice(data);
        }
        let binding = &state.bindings[&token.id];
        let cycle = if range.len() == 4 {
            u32::from_le_bytes(binding.device[range.clone()].try_into().unwrap())
        } else {
            0
        };
        state.syncs.push((true, token.id, range, cycle));
        if failed {
            Err(DmaError::VisibilityFailed)
        } else {
            Ok(())
        }
    }
    unsafe fn sync_for_cpu(
        &self,
        token: DomainMapping,
        range: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        let mut state = self.state.lock().unwrap();
        if state.fail_sync == Some(state.syncs.len()) {
            return Err(DmaError::VisibilityFailed);
        }
        let binding = &state.bindings[&token.id];
        // SAFETY: caller's completion owns this precise range; peer serial.
        unsafe {
            core::ptr::copy_nonoverlapping(
                binding.device[range.clone()].as_ptr(),
                cpu(binding, range.clone()).as_ptr(),
                range.len(),
            );
        }
        state.syncs.push((false, token.id, range, 0));
        Ok(())
    }
    unsafe fn read_coherent_u32(
        &self,
        token: DomainMapping,
        offset: usize,
        _: Direction,
    ) -> Result<u32, DmaError> {
        let mut state = self.state.lock().unwrap();
        if !state.coherent {
            return Err(DmaError::CoherenceUnavailable);
        }
        state.observations.push((token.id, offset));
        Ok(u32::from_le_bytes(
            state.bindings[&token.id].device[offset..offset + 4]
                .try_into()
                .unwrap(),
        ))
    }
}
struct NoBoot;
impl DmaAllocator for NoBoot {
    fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
        panic!("native core reached identity allocator")
    }
}
fn memory(peer: &Arc<Peer>) -> Rc<Native> {
    Rc::new(Native::new(
        peer.clone(),
        peer.clone(),
        Rc::new(()),
        Rc::new(Cell::new(None)),
    ))
}

#[test]
fn native_ring_publishes_real_iova_td_before_first_cycle_and_keeps_failed_visibility() {
    for failure in [None, Some(0), Some(1)] {
        let peer = Peer::new();
        let memory = memory(&peer);
        let profile = dma::Profile::pci(0x1106, 0x3483);
        let mut ring = Ring::with_memory(&mut NoBoot, profile, Some(&memory)).unwrap();
        assert_eq!(ring.buffer.len(), 8192);
        assert!(ring.buffer.device_address().is_multiple_of(8192));
        assert_ne!(ring.buffer.device_address(), ring.buffer.as_ptr() as u64);
        {
            let mut state = peer.state.lock().unwrap();
            state.fail_sync = failure;
            state.fail_after_copy = true;
            assert!(
                state
                    .bindings
                    .values()
                    .all(|b| b.pages.physical_pages()[0] != b.token.address)
            );
        }
        let address = ring.address();
        let result = ring.push(&[(0x1234_5000, 32, NORMAL << 10 | IOC)]);
        if failure.is_some() {
            assert!(result.is_err());
            assert_eq!(
                memory.error(),
                Some(region::Error::Dma(DmaError::VisibilityFailed))
            );
            assert!(memory.ready().is_err());
        } else {
            assert_eq!(result.unwrap(), [address]);
            let td = peer.device(address, TRB);
            assert_eq!(u64::from_le_bytes(td[..8].try_into().unwrap()), 0x1234_5000);
            assert_eq!(u32::from_le_bytes(td[8..12].try_into().unwrap()), 32);
            assert_eq!(
                u32::from_le_bytes(td[12..].try_into().unwrap()) & CYCLE,
                CYCLE
            );
            let state = peer.state.lock().unwrap();
            assert_eq!(state.syncs.len(), 2);
            assert_eq!(state.syncs[1].2.len(), 4);
            assert_eq!(state.syncs[1].3 & CYCLE, CYCLE);
        }
        let drops = peer.drops.clone();
        drop(ring);
        assert_eq!(
            drops.load(Ordering::Relaxed),
            0,
            "active original mapping/pins must remain quarantined"
        );
        assert_eq!(peer.state.lock().unwrap().bindings.len(), 1);
    }
}

#[derive(Default)]
struct RegistersState {
    running: bool,
    writes: Vec<(usize, u32)>,
}
struct CoreRegisters(Rc<RefCell<RegistersState>>);
impl Registers for CoreRegisters {
    fn read32(&mut self, at: usize) -> u32 {
        match at {
            0 => 0x0110_0040,
            HCSPARAMS1 => 1 << 24 | 8,
            HCSPARAMS2 => 2 << 27,
            HCCPARAMS1 => 1,
            DBOFF => 0x1000,
            RTSOFF => 0x800,
            0x48 => 1,
            0x44 => {
                if self.0.borrow().running {
                    0
                } else {
                    HCH
                }
            }
            0x40 if self.0.borrow().running => RUN,
            _ => 0,
        }
    }
    fn write32(&mut self, at: usize, value: u32) {
        let mut state = self.0.borrow_mut();
        state.writes.push((at, value));
        if at == 0x40 {
            state.running = value & RUN != 0;
        }
    }
    fn size(&self) -> Option<usize> {
        Some(0x4000)
    }
}
fn core(
    peer: &Arc<Peer>,
    registers: Rc<RefCell<RegistersState>>,
) -> Result<Controller, BlockError> {
    Controller::with_memory_profile(
        Box::new(CoreRegisters(registers)),
        Clock {
            ticks_per_microsecond: 1000,
        },
        &mut NoBoot,
        "native nonidentity model".into(),
        hardware::Policy {
            dma: dma::Profile::pci(0x1106, 0x3483),
            ..Default::default()
        },
        || Ok(()),
        Some(memory(peer)),
    )
}

#[test]
fn native_core_uses_real_dcbaa_erst_scratchpads_and_coherent_owned_event_trbs() {
    let peer = Peer::new();
    let registers = Rc::new(RefCell::new(RegistersState::default()));
    let mut controller = core(&peer, registers.clone()).unwrap();
    let dcbaa = controller.dcbaa.device_address();
    let table = controller._event_table.device_address();
    let events = controller.events.device_address();
    let scratch_array = u64::from_le_bytes(peer.device(dcbaa, 8).try_into().unwrap());
    assert_eq!(controller._scratchpads.len(), 3);
    for index in 0..2 {
        let page = u64::from_le_bytes(
            peer.device(scratch_array + index * 8, 8)
                .try_into()
                .unwrap(),
        );
        assert_eq!(peer.device(page, 4096), vec![0; 4096]);
    }
    assert_eq!(
        u64::from_le_bytes(peer.device(table, 8).try_into().unwrap()),
        events
    );
    assert_eq!(
        u32::from_le_bytes(peer.device(table + 8, 4).try_into().unwrap()),
        RING_TRBS as u32
    );
    assert_eq!(
        controller.events.read::<u32>(12),
        0,
        "CPU cache initially owns no posted event"
    );
    let mut event = [0u8; TRB];
    event[..8].copy_from_slice(&0x9876_5000u64.to_le_bytes());
    event[8..12].copy_from_slice(&(SUCCESS << 24).to_le_bytes());
    event[12..].copy_from_slice(&(COMMAND_COMPLETION << 10 | CYCLE).to_le_bytes());
    peer.post(events, &event);
    let observed = controller.next_event().unwrap();
    assert_eq!(observed.parameter, 0x9876_5000);
    assert_eq!(observed.code(), SUCCESS);
    let state = peer.state.lock().unwrap();
    assert!(
        state
            .observations
            .iter()
            .any(|(_, at)| *at == 12 || *at == 4108)
    );
    assert!(
        state
            .syncs
            .iter()
            .any(|(device, _, range, _)| !*device && range.len() == TRB)
    );
    assert_eq!(controller.event_index, 1);
    drop(state);
    // ERDP moves once the batch of events is taken.
    controller.publish_events();
    let writes = &registers.borrow().writes;
    assert!(writes.contains(&(0x40 + DCBAAP, dcbaa as u32)));
    assert!(writes.contains(&(0x800 + ERDP, (events + TRB as u64) as u32 | EHB as u32)));
}

#[test]
fn native_missing_coherence_refuses_before_pointer_publication_or_run_and_keeps_original_maps() {
    let peer = Peer::new();
    peer.state.lock().unwrap().coherent = false;
    let registers = Rc::new(RefCell::new(RegistersState::default()));
    assert!(core(&peer, registers.clone()).is_err());
    let state = registers.borrow();
    assert!(!state.running);
    assert!(
        !state
            .writes
            .iter()
            .any(|(at, _)| [0x40 + DCBAAP, 0x40 + CRCR, 0x800 + ERSTBA].contains(at))
    );
    assert!(!peer.state.lock().unwrap().bindings.is_empty());
    assert_eq!(peer.drops.load(Ordering::Relaxed), 0);
}
