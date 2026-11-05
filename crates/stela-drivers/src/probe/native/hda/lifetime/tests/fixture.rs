extern crate std;
use super::*;
use crate::bus::{
    dma::{
        mapping::{Direction, DmaDomain, DmaError, DomainMapping},
        memory::{CacheAttribute, MemoryError, PageBacking, PageGeometry, PageSource, PinnedPages},
        pages::DmaPages,
    },
    pci::{
        Address, Bar, ConfigSpace, Function,
        owned::test_support::{Counters, fixture as config_fixture},
        requester::{
            FunctionRole, RequesterBinding,
            preparation::{self, AttachmentBackend, PreparingRequester},
        },
    },
};
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{ops::Range, ptr::NonNull, sync::atomic::Ordering};
use std::sync::{Mutex, MutexGuard};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Write(usize, u8, u32),
    OriginalDrain,
    Bind,
    Allocate,
    PayloadDrain,
    DmaUnmap(u64),
    Detach,
    BarRetire,
    RootDrop,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    None,
    Stop,
    OriginalDrain,
    Bind,
    Allocate(usize),
    Payload,
    Unmap,
    Detach,
    Bar,
    Config,
    PanicStop,
    PanicOriginal,
    PanicPayload,
    PanicDetach,
    PanicNewRing,
    Minimum,
}
pub struct State {
    pub events: Vec<Event>,
    pub fault: Fault,
    pub inherited: Vec<u8>,
    pub live: Vec<DomainMapping>,
    pub page_drops: usize,
    cpu: Vec<(usize, usize)>,
    values: BTreeMap<usize, u32>,
    now: u64,
    allocations: usize,
    bound: bool,
    config: Arc<Counters>,
}
pub fn lock(state: &Arc<Mutex<State>>) -> MutexGuard<'_, State> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot {
    events: Vec<Event>,
    inherited: Vec<u8>,
    buffers: Vec<Vec<u8>>,
    page_drops: usize,
}
pub fn snapshot(state: &Arc<Mutex<State>>) -> Snapshot {
    let s = lock(state);
    let buffers = s
        .cpu
        .iter()
        .map(|(pointer, bytes)| {
            // SAFETY: serialized fixture lists only still-live Backing allocations,
            // removes them before deallocation and holds no concurrent DMA writer.
            unsafe { core::slice::from_raw_parts(*pointer as *const u8, *bytes).to_vec() }
        })
        .collect();
    Snapshot {
        events: s.events.clone(),
        inherited: s.inherited.clone(),
        buffers,
        page_drops: s.page_drops,
    }
}
#[derive(Clone)]
pub struct Clock(Arc<Mutex<State>>);
impl crate::bus::i2c::Timer for Clock {
    fn now_us(&self) -> u64 {
        lock(&self.0).now
    }
    fn relax(&self) {
        lock(&self.0).now += 100;
    }
}
// SAFETY: private software device fixture owns this exact virtual clock.
unsafe impl crate::bus::pci::power::Timer for Clock {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        if lock(&self.0).fault == Fault::Minimum {
            Err(crate::bus::pci::power::Error::Clock)
        } else {
            Ok(())
        }
    }
    fn wait_us(&self, microseconds: u64) -> Result<(), crate::bus::pci::power::Error> {
        self.check()?;
        let mut state = lock(&self.0);
        state.now = state
            .now
            .checked_add(microseconds)
            .ok_or(crate::bus::pci::power::Error::Clock)?;
        Ok(())
    }
}
pub struct ModelRegisters(Arc<Mutex<State>>);
impl hda::Registers for ModelRegisters {
    fn read8(&mut self, o: usize) -> u8 {
        let s = lock(&self.0);
        if s.fault == Fault::Stop && o == 0x80 {
            return 2;
        }
        *s.values.get(&o).unwrap_or(&0) as u8
    }
    fn read16(&mut self, o: usize) -> u16 {
        *lock(&self.0).values.get(&o).unwrap_or(&0) as u16
    }
    fn read32(&mut self, o: usize) -> u32 {
        *lock(&self.0).values.get(&o).unwrap_or(&0)
    }
    fn write8(&mut self, o: usize, v: u8) {
        self.write(o, 1, u32::from(v));
    }
    fn write16(&mut self, o: usize, v: u16) {
        self.write(o, 2, u32::from(v));
    }
    fn write32(&mut self, o: usize, v: u32) {
        self.write(o, 4, v);
    }
}
impl ModelRegisters {
    fn write(&mut self, o: usize, w: u8, v: u32) {
        let mut s = lock(&self.0);
        s.events.push(Event::Write(o, w, v));
        if (s.fault == Fault::PanicStop && o == 0x20)
            || (s.fault == Fault::PanicNewRing && o == 0x40)
        {
            drop(s);
            panic!("modeled protocol MMIO callback");
        }
        let v = if o == 0x58 && v == 0x8000 { 0 } else { v };
        if [0x0e, 0x4d, 0x5d, 0x83, 0xa3].contains(&o) {
            let previous = *s.values.get(&o).unwrap_or(&0);
            s.values.insert(o, previous & !v);
        } else {
            s.values.insert(o, v);
        }
    }
}
// SAFETY: isolated register storage is uniquely modeled with synchronous accesses;
// no actual device or remapper permission is supplied.
unsafe impl NativeRegisters for ModelRegisters {
    unsafe fn retire(&mut self) -> Result<(), MappingError> {
        let mut s = lock(&self.0);
        s.events.push(Event::BarRetire);
        if s.fault == Fault::Bar {
            return Err(MappingError::Unavailable);
        }
        if s.fault == Fault::Config {
            s.config.fail_context_at.store(
                s.config.contexts.load(Ordering::Relaxed) + 1,
                Ordering::Relaxed,
            );
        }
        Ok(())
    }
}
struct Root(Arc<Mutex<State>>);
impl Drop for Root {
    fn drop(&mut self) {
        lock(&self.0).events.push(Event::RootDrop);
    }
}
// SAFETY: same owned-config epoch and isolated synchronous root model. Actual
// initial root/engine/IRQ proof is supplied only by the explicit test fixture.
unsafe impl preparation::Root for Root {
    fn drain(&self) -> Result<(), DmaError> {
        let mut s = lock(&self.0);
        s.events.push(Event::OriginalDrain);
        assert_eq!(s.inherited, vec![0xa5; 8192]);
        assert_eq!(s.values[&0x80] & 0x1e, 0);
        assert_eq!(s.values[&0xa0] & 0x1e, 0);
        assert_eq!(s.values[&0x4c] & 3, 0);
        assert_eq!(s.values[&0x5c] & 7, 0);
        assert_eq!(s.values[&0x70], 0);
        if s.fault == Fault::PanicOriginal {
            drop(s);
            panic!("original root callback");
        }
        if s.fault == Fault::OriginalDrain {
            return Err(DmaError::DrainUnavailable);
        }
        Ok(())
    }
    unsafe fn bind(
        &self,
        binding: RequesterBinding,
    ) -> Result<Box<dyn AttachmentBackend>, DmaError> {
        let mut s = lock(&self.0);
        s.events.push(Event::Bind);
        if s.fault == Fault::Bind {
            core::mem::forget(binding);
            return Err(DmaError::MappingFailed);
        }
        s.bound = true;
        drop(s);
        Ok(Box::new(Attached {
            domain: Arc::new(Domain(self.0.clone())),
            binding: Some(binding),
        }))
    }
}
struct Attached {
    domain: Arc<Domain>,
    binding: Option<RequesterBinding>,
}
// SAFETY: this unique attachment keeps the actual RequesterBinding/config pin.
// Live modeled leases refuse before effects; successful detach ends admission.
unsafe impl AttachmentBackend for Attached {
    fn domain(&self) -> Arc<dyn DmaDomain> {
        self.domain.clone()
    }
    unsafe fn detach(&mut self) -> Result<(), preparation::DetachError> {
        let mut s = lock(&self.domain.0);
        if !s.live.is_empty() {
            return Err(DmaError::InvalidationFailed.into());
        }
        s.events.push(Event::Detach);
        if s.fault == Fault::PanicDetach {
            drop(s);
            panic!("modeled actual detach callback");
        }
        if s.fault == Fault::Detach {
            return Err(DmaError::InvalidationFailed.into());
        }
        s.bound = false;
        drop(s);
        drop(self.binding.take());
        Ok(())
    }
}
impl Drop for Attached {
    fn drop(&mut self) {
        if self.binding.is_some() {
            core::mem::forget(self.binding.take());
        }
    }
}
struct Domain(Arc<Mutex<State>>);
// SAFETY: tracked nonidentity symbolic IOVA/PA labels and synchronous exact
// leases. No numeric label is dereferenced as a CPU pointer or used by hardware.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        _: Direction,
        limit: u64,
    ) -> Result<DomainMapping, DmaError> {
        let mut s = lock(&self.0);
        if !s.bound {
            return Err(DmaError::IommuUnavailable);
        }
        let id = s.live.len() as u64 + 1;
        let address = 0x20000 + id * 0x10000;
        assert_ne!(address, pages.physical_pages()[0]);
        assert!(s.cpu.iter().all(|(pointer, _)| *pointer as u64 != address));
        if address + pages.bytes() as u64 - 1 > limit {
            return Err(DmaError::AddressLimit);
        }
        let mapping = DomainMapping {
            id,
            address,
            bytes: pages.bytes(),
        };
        s.live.push(mapping);
        Ok(mapping)
    }
    unsafe fn unmap(&self, m: DomainMapping) -> Result<(), DmaError> {
        let mut s = lock(&self.0);
        if !s.bound {
            return Err(DmaError::IommuUnavailable);
        }
        s.events.push(Event::DmaUnmap(m.id));
        if s.fault == Fault::Unmap {
            return Err(DmaError::InvalidationFailed);
        }
        let i = s
            .live
            .iter()
            .position(|v| *v == m)
            .ok_or(DmaError::Unmapped)?;
        s.live.remove(i);
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        m: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        if lock(&self.0).live.contains(&m) {
            Ok(())
        } else {
            Err(DmaError::Unmapped)
        }
    }
    unsafe fn sync_for_cpu(
        &self,
        m: DomainMapping,
        r: Range<usize>,
        d: Direction,
    ) -> Result<(), DmaError> {
        // SAFETY: the model checks exactly the same live token for either direction.
        unsafe { self.sync_for_device(m, r, d) }
    }
    unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
        let mut s = lock(&self.0);
        s.events.push(Event::PayloadDrain);
        if s.fault == Fault::PanicPayload {
            drop(s);
            panic!("modeled actual payload callback");
        }
        if s.fault == Fault::Payload {
            Err(DmaError::DrainUnavailable)
        } else {
            Ok(())
        }
    }
}
#[repr(align(4096))]
struct Bytes([u8; 8192]);
struct Backing {
    memory: Box<Bytes>,
    physical: Vec<u64>,
    state: Arc<Mutex<State>>,
}
// SAFETY: real stable CPU storage with independent noncontiguous physical
// labels. Label addresses are metadata and never native RAM pointers.
unsafe impl PageBacking for Backing {
    fn cpu_base(&self) -> NonNull<u8> {
        NonNull::from(&self.memory.0[0])
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
        let mut s = lock(&self.state);
        let pointer = self.memory.0.as_ptr() as usize;
        s.cpu.retain(|(p, _)| *p != pointer);
        s.page_drops += 1;
    }
}
struct Source(Arc<Mutex<State>>);
impl PageSource for Source {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        PageGeometry::base_only(12)
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        let mut s = lock(&self.0);
        s.allocations += 1;
        s.events.push(Event::Allocate);
        if s.fault == Fault::Allocate(s.allocations) {
            return Err(MemoryError::OutOfMemory);
        }
        let physical = 0x800000 + s.allocations as u64 * 0x400000;
        drop(s);
        assert_eq!(attribute, CacheAttribute::WriteBack);
        if bytes > 8192 {
            return Err(MemoryError::InvalidSize);
        }
        let memory = Box::new(Bytes([0; 8192]));
        assert_ne!(memory.0.as_ptr() as u64, physical);
        lock(&self.0).cpu.push((memory.0.as_ptr() as usize, bytes));
        PinnedPages::new(
            Box::new(Backing {
                memory,
                physical: (0..bytes.div_ceil(4096))
                    .map(|i| physical + i as u64 * 0x200000)
                    .collect(),
                state: self.0.clone(),
            }),
            bytes,
            alignment,
        )
    }
}
pub struct Fixture {
    pub inputs: Option<Inputs<ModelRegisters, Clock>>,
    pub state: Arc<Mutex<State>>,
    pub config: Arc<Counters>,
}
pub fn fixture(completed: bool) -> Fixture {
    let address = Address {
        segment: 0,
        bus: 2,
        device: 3,
        function: 0,
    };
    let (mut config, counters) = config_fixture(address);
    config.write32(0, 0x26688086).unwrap();
    config.write32(8, 0x04030000).unwrap();
    config.write16(4, 0x402).unwrap();
    config.write32(0x10, 0x40000000).unwrap();
    let mut values = BTreeMap::new();
    for (o, v) in [
        (0x03, 1),
        (0x02, 0),
        (0, 0x1101),
        (0x08, 0x101),
        (0x0c, 0x7fff),
        (0x20, 0xffff_ffff),
        (0x4c, 3),
        (0x5c, 7),
        (0x4d, 1),
        (0x5d, 5),
        (0x4e, 0x40),
        (0x5e, 0x40),
        (0x70, 0x12340001),
        (0x74, 0x80000000),
        (0x80, 0x1e),
        (0xa0, 0x1e),
        (0x83, 0x1c),
        (0xa3, 0x1c),
    ] {
        values.insert(o, v);
    }
    let state = Arc::new(Mutex::new(State {
        events: Vec::new(),
        fault: Fault::None,
        inherited: vec![0xa5; 8192],
        live: Vec::new(),
        page_drops: 0,
        cpu: Vec::new(),
        values,
        now: 0,
        allocations: 0,
        bound: false,
        config: counters.clone(),
    }));
    // SAFETY: independent, completely symbolic original firmware/IRQ/work
    // owner has no remaining users. This is not a native handoff producer.
    let users =
        completed.then(|| unsafe { OriginalUsers::diagnostic(config.retain_epoch().unwrap()) });
    let function = Function::new(address, config).unwrap();
    // SAFETY: independent owned config and symbolic original root; prior-user
    // retirement above is only an explicit diagnostic/model capability.
    let requester = match unsafe {
        PreparingRequester::new(
            function,
            FunctionRole::Physical,
            Box::new(Root(state.clone())),
        )
    } {
        Ok(r) => r,
        Err(_) => panic!("valid owned configuration fixture"),
    };
    let pages = Box::leak(Box::new(Source(state.clone())));
    Fixture {
        inputs: Some(Inputs {
            requester,
            registers: ModelRegisters(state.clone()),
            clock: Clock(state.clone()),
            pages,
            bar: Bar::Memory {
                address: 0x40000000,
                size: 0x1000,
                prefetchable: false,
                wide: false,
            },
            original_users: users,
        }),
        state,
        config: counters,
    }
}
