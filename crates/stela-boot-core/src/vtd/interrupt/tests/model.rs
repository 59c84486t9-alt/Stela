//! Independent RAM, queued-remapper and LAPIC peers for VT-d route ownership.
use super::std::sync::Mutex;
use super::*;
use alloc::alloc::{alloc_zeroed, dealloc};
use core::alloc::Layout;
use stela_drivers::bus::dma::memory::{MemoryError, PageBacking};

pub(super) struct Pool {
    next: AtomicU64,
    pub(super) fail_at: AtomicU64,
    pub(super) panic_at: AtomicU64,
    pub(super) released: Arc<AtomicU64>,
    addresses: Arc<Mutex<BTreeMap<u64, usize>>>,
}
impl Pool {
    pub(super) fn new() -> &'static Self {
        Box::leak(Box::new(Self {
            next: AtomicU64::new(0x100000),
            fail_at: AtomicU64::new(u64::MAX),
            panic_at: AtomicU64::new(u64::MAX),
            released: Arc::new(AtomicU64::new(0)),
            addresses: Arc::new(Mutex::new(BTreeMap::new())),
        }))
    }
}
struct Backing {
    pointer: NonNull<u8>,
    physical: [u64; 1],
    addresses: Arc<Mutex<BTreeMap<u64, usize>>>,
    released: Arc<AtomicU64>,
}
// SAFETY: exclusive immovable model RAM, no Rust references to its payload.
unsafe impl Send for Backing {}
// SAFETY: metadata/raw access only; model register effects are mutex serialized.
unsafe impl Sync for Backing {}
// SAFETY: checked page-aligned zeroed physical-memory peer held until Drop.
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
        self.addresses.lock().unwrap().remove(&self.physical[0]);
        self.released.fetch_add(1, Ordering::Relaxed);
        // SAFETY: sole original allocation, no active walker after allowed Drop.
        unsafe {
            dealloc(
                self.pointer.as_ptr(),
                Layout::from_size_align(PAGE, PAGE).unwrap(),
            )
        }
    }
}
impl PageSource for Pool {
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert_eq!(
            (bytes, alignment, attribute),
            (PAGE, PAGE, CacheAttribute::WriteBack)
        );
        let physical = self.next.fetch_add(PAGE as u64, Ordering::Relaxed);
        if physical == self.fail_at.load(Ordering::Relaxed) {
            return Err(MemoryError::OutOfMemory);
        }
        assert_ne!(
            physical,
            self.panic_at.load(Ordering::Relaxed),
            "injected allocator unwind"
        );
        // SAFETY: nonzero valid layout; PageBacking owns this unique allocation.
        let pointer =
            NonNull::new(unsafe { alloc_zeroed(Layout::from_size_align(PAGE, PAGE).unwrap()) })
                .unwrap();
        self.addresses
            .lock()
            .unwrap()
            .insert(physical, pointer.as_ptr() as usize);
        PinnedPages::new(
            Box::new(Backing {
                pointer,
                physical: [physical],
                addresses: self.addresses.clone(),
                released: self.released.clone(),
            }),
            PAGE,
            PAGE,
        )
    }
}

#[derive(Clone)]
pub(super) struct RegistersPeer(pub(super) Arc<Mutex<Hardware>>);
pub(super) struct Hardware {
    pub(super) values: BTreeMap<usize, u64>,
    pub(super) reads: usize,
    pub(super) writes: Vec<(usize, u64)>,
    pub(super) descriptors: Vec<[u64; 2]>,
    pub(super) events: Vec<&'static str>,
    pub(super) hold_fetch: bool,
    pub(super) hold_lookup: bool,
    pub(super) lookup_delay: usize,
    pub(super) hold_lapic: bool,
    pub(super) hold_status: bool,
    pub(super) bad_status: bool,
    pub(super) pending_status: Option<(u64, u32)>,
    pub(super) status_on_tail: Option<u32>,
    pub(super) status_at_tail: Vec<u32>,
    pub(super) hold_payload: bool,
    pub(super) pending_payload: bool,
    pub(super) fail_enable: u32,
    pub(super) panic_tail: bool,
    pub(super) lookup: Option<(u16, u8)>,
    pub(super) fabric: Vec<(u16, u8)>,
    pub(super) upstream: Vec<(u16, u16)>,
    pub(super) irr: Vec<u8>,
    pub(super) rejected: usize,
    pub(super) interrupt_faults: Vec<u8>,
    cache: BTreeMap<u16, [u64; 2]>,
    drains: Vec<Option<u16>>,
    visible: BTreeMap<u64, Vec<u64>>,
    coherent: bool,
    pool: &'static Pool,
    ticks: u64,
}
impl Hardware {
    fn word(&self, physical: u64) -> u64 {
        let page = physical & !0xfff;
        let index = ((physical & 0xfff) / 8) as usize;
        if !self.coherent {
            return self
                .visible
                .get(&page)
                .expect("unpublished noncoherent page")[index];
        }
        let pointer = self.pool.addresses.lock().unwrap()[&page];
        // SAFETY: owned model page retained by the root/queue pin.
        unsafe { ((pointer + index * 8) as *const u64).read_volatile() }
    }
    fn write_status(&self, physical: u64, data: u32) {
        let page = physical & !0xfff;
        let pointer = self.pool.addresses.lock().unwrap()[&page];
        // SAFETY: coherent hardware DWORD write to the still-pinned status RAM.
        unsafe { ((pointer + (physical & 0xfff) as usize) as *mut u32).write_volatile(data) }
    }
    fn read_status(&self, physical: u64) -> u32 {
        let page = physical & !0xfff;
        let pointer = self.pool.addresses.lock().unwrap()[&page];
        // SAFETY: same retained coherent status RAM, independent of CPU state.
        unsafe { ((pointer + (physical & 0xfff) as usize) as *const u32).read_volatile() }
    }
    pub(super) fn release_status(&mut self) {
        if let Some((physical, data)) = self.pending_status.take() {
            self.write_status(physical, data);
            self.events.push("late-status");
        }
    }
    fn reject_interrupt(&mut self, reason: u8, entry: Option<[u64; 2]>) {
        self.rejected += 1;
        self.events.push("rejected");
        let qualified = matches!(reason, 0x22 | 0x24 | 0x26);
        if qualified && entry.is_some_and(|entry| entry[0] & 2 != 0) {
            self.events.push("suppressed-fault");
            return;
        }
        self.interrupt_faults.push(reason);
        *self.values.entry(FSTS).or_default() |= 1 << 1;
        self.events.push("interrupt-fault");
    }
    pub(super) fn compatibility_request(&mut self) {
        // This fixture owns the explicit compatibility-blocked root policy.
        assert_ne!(self.values[&GSTS] & u64::from(INTERRUPT_REMAP), 0);
        assert_eq!(self.values[&GSTS] & u64::from(COMPATIBILITY), 0);
        self.reject_interrupt(0x25, None);
    }
    pub(super) fn request(&mut self, sid: u16, index: u16) {
        let irta = self.values[&IRTA];
        let entries = 1u32 << ((irta & 15) + 1);
        if u32::from(index) >= entries {
            self.reject_interrupt(0x21, None);
            return;
        }
        let base = irta & !0xfff;
        let entry = self.cache.get(&index).copied().unwrap_or_else(|| {
            [
                self.word(base + u64::from(index) * 16),
                self.word(base + u64::from(index) * 16 + 8),
            ]
        });
        if entry[0] & 1 == 0 {
            self.reject_interrupt(0x22, Some(entry));
            return;
        }
        if entry[1] & 0xffff != u64::from(sid)
            || (entry[1] >> 18) & 3 != 1
            || (entry[1] >> 16) & 3 != 0
        {
            self.reject_interrupt(0x26, Some(entry));
            return;
        }
        self.cache.insert(index, entry);
        self.fabric.push((index, (entry[0] >> 16) as u8));
        self.events.push("fabric");
    }
    pub(super) fn release_upstream(&mut self) {
        for (sid, index) in core::mem::take(&mut self.upstream) {
            self.request(sid, index)
        }
    }
    fn advance(&mut self) {
        if self.hold_fetch || self.values.get(&GSTS).copied().unwrap_or(0) & (1 << 26) == 0 {
            return;
        }
        let head = self.values.get(&IQH).copied().unwrap_or(0);
        let tail = self.values.get(&IQT).copied().unwrap_or(0);
        if head == tail {
            return;
        }
        let ring = self.values[&IQA] & !0xfff;
        let words = [self.word(ring + head), self.word(ring + head + 8)];
        let kind = words[0] & 15;
        match kind {
            1 => self.events.push("context"),
            2 => {
                if words[0] & (1 << 6) != 0 {
                    if self.pending_payload && self.hold_payload {
                        return;
                    }
                    self.pending_payload = false;
                    self.events.push("payload");
                }
            }
            4 => {
                let index = if words[0] & (1 << 4) != 0 {
                    Some((words[0] >> 32) as u16)
                } else {
                    None
                };
                if let Some((lookup_index, vector)) = self.lookup
                    && index.is_none_or(|index| index == lookup_index)
                {
                    if self.hold_lookup {
                        return;
                    }
                    if self.lookup_delay != 0 {
                        self.lookup_delay -= 1;
                        return;
                    }
                    self.fabric.push((lookup_index, vector));
                    self.lookup = None;
                    self.events.push("lookup");
                }
                self.cache
                    .retain(|entry, _| index.is_some_and(|index| index != *entry));
                self.drains.push(index);
                self.events.push("iec");
            }
            5 => {
                let matches = |entry: &(u16, u8)| {
                    self.drains
                        .iter()
                        .any(|index| index.is_none_or(|index| index == entry.0))
                };
                if self.hold_lapic && self.fabric.iter().any(matches) {
                    return;
                }
                let mut held = Vec::new();
                for entry in self.fabric.drain(..) {
                    if self
                        .drains
                        .iter()
                        .any(|index| index.is_none_or(|index| index == entry.0))
                    {
                        self.irr.push(entry.1);
                        self.events.push("lapic");
                    } else {
                        held.push(entry)
                    }
                }
                self.fabric = held;
                self.drains.clear();
                let token = (words[0] >> 32) as u32;
                if self.hold_status {
                    assert!(self.pending_status.replace((words[1], token)).is_none());
                } else {
                    let data = if self.bad_status {
                        if token == u32::MAX {
                            token - 1
                        } else {
                            token + 1
                        }
                    } else {
                        token
                    };
                    self.write_status(words[1], data);
                    self.events.push("status");
                }
            }
            _ => {
                self.values.insert(FSTS, 1 << 4);
                return;
            }
        }
        self.descriptors.push(words);
        self.values.insert(IQH, (head + 16) % PAGE as u64);
    }
}
impl RegistersPeer {
    pub(super) fn new(pool: &'static Pool, coherent: bool) -> Self {
        let mut values = BTreeMap::new();
        values.insert(
            CAP,
            (47 << 16) | (4 << 8) | (1 << 4) | (1 << 54) | (1 << 55),
        );
        values.insert(ECAP, u64::from(coherent) | 2 | 8 | (0x10 << 8));
        Self(Arc::new(Mutex::new(Hardware {
            values,
            reads: 0,
            writes: Vec::new(),
            descriptors: Vec::new(),
            events: Vec::new(),
            hold_fetch: false,
            hold_lookup: false,
            lookup_delay: 0,
            hold_lapic: false,
            hold_status: false,
            bad_status: false,
            pending_status: None,
            status_on_tail: None,
            status_at_tail: Vec::new(),
            hold_payload: false,
            pending_payload: false,
            fail_enable: 0,
            panic_tail: false,
            lookup: None,
            fabric: Vec::new(),
            upstream: Vec::new(),
            irr: Vec::new(),
            rejected: 0,
            interrupt_faults: Vec::new(),
            cache: BTreeMap::new(),
            drains: Vec::new(),
            visible: BTreeMap::new(),
            coherent,
            pool,
            ticks: 0,
        })))
    }
}
// SAFETY: isolated RAM/register/fabric peers. Independent controls can withhold
// fetch, lookup, payload, LAPIC acceptance and coherent completion separately.
unsafe impl Registers for RegistersPeer {
    fn bytes(&self) -> usize {
        PAGE
    }
    fn read32(&self, offset: usize) -> u32 {
        let mut h = self.0.lock().unwrap();
        h.reads += 1;
        h.values.get(&offset).copied().unwrap_or(0) as u32
    }
    fn read64(&self, offset: usize) -> u64 {
        let mut h = self.0.lock().unwrap();
        h.reads += 1;
        if offset == IQH {
            h.advance()
        }
        let value = h.values.get(&offset).copied().unwrap_or(0);
        let value = if offset == CCMD {
            value & !(1 << 63) | 1 << 59
        } else if offset == 0x108 {
            value & !(1 << 63) | 1 << 57
        } else {
            value
        };
        h.values.insert(offset, value);
        value
    }
    fn write32(&self, offset: usize, value: u32) {
        let mut h = self.0.lock().unwrap();
        h.writes.push((offset, u64::from(value)));
        h.values.insert(offset, u64::from(value));
        if offset == GCMD {
            let old = h.values.get(&GSTS).copied().unwrap_or(0) as u32;
            let mut status = value & PERSISTENT & !h.fail_enable;
            status |= old & (ROOT_POINTER | INTERRUPT_POINTER);
            status |= value & (ROOT_POINTER | INTERRUPT_POINTER);
            status &= !h.fail_enable;
            h.values.insert(GSTS, u64::from(status));
            if value & QUEUED_INVALIDATION == 0 {
                h.values.insert(IQH, 0);
            }
        }
    }
    fn write64(&self, offset: usize, value: u64) {
        let mut h = self.0.lock().unwrap();
        h.writes.push((offset, value));
        h.values.insert(offset, value);
        if offset == IQT
            && h.values.get(&GSTS).copied().unwrap_or(0) & QUEUED_INVALIDATION as u64 != 0
        {
            let ring = h.values[&IQA] & !0xfff;
            let wait = (value + PAGE as u64 - 16) % PAGE as u64;
            assert_eq!(h.word(ring + wait) & 15, 5);
            let status = h.word(ring + wait + 8);
            let observed = h.read_status(status);
            h.status_at_tail.push(observed);
            if let Some(stale) = h.status_on_tail.take() {
                h.write_status(status, stale);
                h.events.push("injected-status");
            }
        }
        if offset == IQT && h.panic_tail && value != 0 {
            drop(h);
            panic!("injected after tail publication");
        }
    }
    fn ticks(&self) -> u64 {
        let mut h = self.0.lock().unwrap();
        h.ticks += 1;
        h.ticks
    }
    fn timeout_ticks(&self) -> u64 {
        32
    }
    unsafe fn flush_table(&self, cpu: NonNull<u8>, bytes: usize, line: usize) {
        assert_eq!(bytes, PAGE);
        assert!(line.is_power_of_two());
        let mut h = self.0.lock().unwrap();
        let page = *h
            .pool
            .addresses
            .lock()
            .unwrap()
            .iter()
            .find(|(_, pointer)| **pointer == cpu.as_ptr() as usize)
            .unwrap()
            .0;
        // SAFETY: caller keeps this complete aligned WB model page mapped.
        let words =
            unsafe { core::slice::from_raw_parts(cpu.as_ptr().cast::<u64>(), PAGE / 8) }.to_vec();
        h.visible.insert(page, words);
        h.events.push("publish");
    }
}
