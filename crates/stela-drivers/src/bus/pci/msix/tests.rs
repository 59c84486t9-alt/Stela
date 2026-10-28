// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2003-2004 Intel
// Copyright (C) Tom Long Nguyen (tom.l.nguyen@intel.com)
// Copyright (C) 2016 Christoph Hellwig
// Copyright (C) 2026 Stela contributors
// The prior Stela peripheral fixture is MIT (repository LICENSE); this combined
// file retains the GPL-2.0-only legacy owner oracle and its original notices.
// Includes the unchanged pre-indexed GPL-2.0-only owner as a legacy trace oracle.
extern crate std;
use super::*;
use crate::bus::pci::ConfigSpace;
use alloc::{sync::Arc, vec, vec::Vec};
use std::sync::Mutex;

const TABLE: u64 = 0x100;
const PBA: u64 = 0xf000;
const BASE: u64 = 0x1_4000_0000;
const BYTES: u64 = 0x10000;
const MESSAGE: MsiMessage = MsiMessage {
    address: 0x1234_5678_fee0_1000,
    data: 0x8765_4321,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    ConfigRead(u16, u8),
    ConfigWrite(u16, u16),
    BarRead(u64),
    BarWrite(u64, u32),
}
// This software peripheral owns each new route's actual callback object until
// modeled source stop/drain. Its function is invoked on emitted messages; it
// grants no physical routing/remapping or kernel IRQ entry authority.
struct ModelRoute {
    expected: MsiMessage,
    calls: AtomicU64,
}
impl ModelRoute {
    fn interrupt(&self, actual: MsiMessage) {
        assert_eq!(actual, self.expected);
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}
struct Peripheral {
    config: [u8; 256],
    memory: Vec<u32>,
    events: Vec<Event>,
    fail: Option<usize>,
    after_effect: bool,
    failed_config_ack: bool,
    callback_published: bool,
    pending: bool,
    emitted: Vec<MsiMessage>,
    vectors: u16,
    routes: Vec<Option<ModelRoute>>,
    pending_entries: Vec<bool>,
    delivered_entries: Vec<u16>,
    queue_on_guard: Vec<u16>,
}
impl Peripheral {
    fn get(&self, offset: u16, bytes: usize) -> u32 {
        let mut word = [0; 4];
        word[..bytes]
            .copy_from_slice(&self.config[usize::from(offset)..usize::from(offset) + bytes]);
        u32::from_le_bytes(word)
    }
    fn put(&mut self, offset: u16, bytes: usize, value: u32) {
        self.config[usize::from(offset)..usize::from(offset) + bytes]
            .copy_from_slice(&value.to_le_bytes()[..bytes]);
    }
    fn event(&mut self, event: Event) -> bool {
        self.events.push(event);
        self.fail == Some(self.events.len())
    }
    fn queue(&mut self, index: u16) {
        assert!(index < self.vectors);
        if index == 0 {
            self.pending = true;
        } else {
            self.pending_entries[usize::from(index)] = true;
        }
        self.memory[(PBA / 4) as usize + usize::from(index / 32)] |= 1 << (index % 32);
    }
    fn publish(&mut self, index: u16) {
        if index == 0 {
            self.callback_published = true;
        }
        self.routes[usize::from(index)] = Some(ModelRoute {
            expected: message(index),
            calls: AtomicU64::new(0),
        });
    }
    fn deliver(&mut self) {
        if self.get(0x52, 2) & 0xc000 != 0x8000 {
            return;
        }
        for index in 0..self.vectors {
            let pending = if index == 0 {
                self.pending
            } else {
                self.pending_entries[usize::from(index)]
            };
            let entry = (TABLE / 4) as usize + usize::from(index) * 4;
            if pending && self.memory[entry + 3] & 1 == 0 {
                let actual = MsiMessage {
                    address: u64::from(self.memory[entry])
                        | u64::from(self.memory[entry + 1]) << 32,
                    data: self.memory[entry + 2],
                };
                if let Some(route) = &self.routes[usize::from(index)] {
                    route.interrupt(actual);
                } else {
                    // Only the pre-existing legacy entry-zero fixtures use
                    // their original boolean publication witness.
                    assert!(
                        index == 0 && self.callback_published,
                        "MSI-X arrived without an actual published route for entry {index}"
                    );
                }
                self.emitted.push(actual);
                self.delivered_entries.push(index);
                if index == 0 {
                    self.pending = false;
                } else {
                    self.pending_entries[usize::from(index)] = false;
                }
                self.memory[(PBA / 4) as usize + usize::from(index / 32)] &= !(1 << (index % 32));
            }
        }
    }
}
struct Config {
    model: Arc<Mutex<Peripheral>>,
    drops: Arc<AtomicU64>,
}
impl Config {
    fn read(&self, offset: u16, bytes: u8) -> u32 {
        let mut m = self.model.lock().unwrap();
        if m.event(Event::ConfigRead(offset, bytes)) || core::mem::take(&mut m.failed_config_ack) {
            return match bytes {
                1 => 255,
                2 => 65535,
                _ => u32::MAX,
            };
        }
        m.get(offset, usize::from(bytes))
    }
}
impl ConfigSpace for Config {
    fn read8(&self, offset: u16) -> u8 {
        self.read(offset, 1) as u8
    }
    fn read16(&self, offset: u16) -> u16 {
        self.read(offset, 2) as u16
    }
    fn read32(&self, offset: u16) -> u32 {
        self.read(offset, 4)
    }
    fn write16(&mut self, offset: u16, value: u16) {
        let mut m = self.model.lock().unwrap();
        let fail = m.event(Event::ConfigWrite(offset, value));
        if !fail || m.after_effect {
            m.put(offset, 2, u32::from(value));
            if offset == 0x52 && value & 0xc000 == 0xc000 {
                // Model device requests arriving DURING the temporary global
                // guard, not an artificial queue after unmask has completed.
                while let Some(index) = m.queue_on_guard.pop() {
                    m.queue(index);
                }
            }
            m.deliver();
        }
        if fail {
            m.failed_config_ack = true;
        }
    }
    fn write32(&mut self, _: u16, _: u32) {
        panic!("MSI-X must not replay adjacent config W1C with DWORD writes");
    }
}
unsafe impl MsiConfigSpace for Config {}
impl Drop for Config {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct Bar {
    model: Arc<Mutex<Peripheral>>,
    span: PhysicalSpan,
    drops: Arc<AtomicU64>,
}
unsafe impl BarAccess for Bar {
    fn physical_span(&self) -> PhysicalSpan {
        self.span
    }
    fn accessible(&self, offset: u64, bytes: u64) -> bool {
        offset
            .checked_add(bytes)
            .is_some_and(|end| end <= self.span.bytes())
    }
    fn read32(&self, offset: u64) -> Result<u32, IoError> {
        let mut m = self.model.lock().unwrap();
        if m.event(Event::BarRead(offset)) {
            return Err(IoError);
        }
        assert_ne!(
            m.get(0x52, 2) & 0x8000,
            0,
            "device table unavailable until MSI-X is enabled"
        );
        Ok(m.memory[(offset / 4) as usize])
    }
    fn write32(&mut self, offset: u64, value: u32) -> Result<(), IoError> {
        let mut m = self.model.lock().unwrap();
        let fail = m.event(Event::BarWrite(offset, value));
        assert!(offset < PBA, "PBA is device-owned read-only pending state");
        assert!(offset >= TABLE && offset < TABLE + u64::from(m.vectors) * 16);
        assert_eq!(offset % 4, 0);
        if (offset - TABLE) % 16 < 12 {
            let entry = (TABLE / 4) as usize + ((offset - TABLE) / 16) as usize * 4;
            assert_ne!(
                m.memory[entry + 3] & 1,
                0,
                "message changed before target entry was masked"
            );
        }
        assert_eq!(
            m.get(0x52, 2) & 0xc000,
            0xc000,
            "table update outside actual function mask"
        );
        if !fail || m.after_effect {
            m.memory[(offset / 4) as usize] = value;
            m.deliver();
        }
        if fail { Err(IoError) } else { Ok(()) }
    }
}
impl Drop for Bar {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct Root(Arc<AtomicU64>);
impl Drop for Root {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
struct Fixture {
    owners: Owners<Config, Bar>,
    model: Arc<Mutex<Peripheral>>,
    config_drops: Arc<AtomicU64>,
    root_drops: Arc<AtomicU64>,
    bar_drops: Arc<AtomicU64>,
}
fn fixture(vectors: u16) -> Fixture {
    let mut m = Peripheral {
        config: [0; 256],
        memory: vec![0; BYTES as usize / 4],
        events: Vec::new(),
        fail: None,
        after_effect: false,
        failed_config_ack: false,
        callback_published: false,
        pending: false,
        emitted: Vec::new(),
        vectors,
        routes: (0..vectors).map(|_| None).collect(),
        pending_entries: vec![false; usize::from(vectors)],
        delivered_entries: Vec::new(),
        queue_on_guard: Vec::new(),
    };
    m.put(0, 4, 0x1234_8086);
    m.put(4, 2, 0x107);
    m.put(6, 2, 0xa510);
    m.put(0x10, 4, (BASE as u32) | 4);
    m.put(0x14, 4, (BASE >> 32) as u32);
    m.put(0x34, 1, 0x50);
    m.put(0x50, 2, 0x11);
    m.put(0x52, 2, u32::from(vectors - 1));
    m.put(0x54, 4, TABLE as u32);
    m.put(0x58, 4, PBA as u32);
    for vector in 0..vectors {
        let base = (TABLE / 4) as usize + usize::from(vector) * 4;
        m.memory[base..base + 3].copy_from_slice(&[
            0xabc0_0000 | u32::from(vector),
            0x9876_0000,
            0x55aa_0000,
        ]);
    }
    let model = Arc::new(Mutex::new(m));
    let config_drops = Arc::new(AtomicU64::new(0));
    let root_drops = Arc::new(AtomicU64::new(0));
    let bar_drops = Arc::new(AtomicU64::new(0));
    let function = Function::new(
        Address {
            segment: 0,
            bus: 0,
            device: 2,
            function: 0,
        },
        Config {
            model: model.clone(),
            drops: config_drops.clone(),
        },
    )
    .unwrap();
    let mut bars = core::array::from_fn(|_| None);
    bars[0] = Some(Bar {
        model: model.clone(),
        span: PhysicalSpan::new(BASE, BYTES).unwrap(),
        drops: bar_drops.clone(),
    });
    Fixture {
        owners: (function, Arc::new(Root(root_drops.clone())), bars),
        model,
        config_drops,
        root_drops,
        bar_drops,
    }
}
fn attach(f: Fixture) -> (MsixConfig<Config, Bar>, Arc<Mutex<Peripheral>>) {
    let (function, retained, bars) = f.owners;
    let owner = match unsafe { MsixConfig::new(function, retained, bars) } {
        Ok(owner) => owner,
        Err((error, _)) => panic!("attach {error:?}"),
    };
    f.model.lock().unwrap().events.clear();
    (owner, f.model)
}

// Source-derived legacy oracle: complete original owner/Drop implementations
// copied from the packet's exact base msix.rs, with ONLY the type name changed.
// Discovery/UC mapping remain unchanged shared source, and the shared peripheral
// independently enforces actual mask/enable ordering and records every access.
mod original {
    use super::*;
    pub struct LegacyReference<C: MsiConfigSpace = EcamConfig, B: BarAccess = MappedBar> {
        owners: Option<Owners<C, B>>,
        layout: Layout,
        message: Option<MsiMessage>,
        poisoned: bool,
    }
    impl<C: MsiConfigSpace, B: BarAccess> LegacyReference<C, B> {
        /// # Safety
        /// Own the actual unique function/config/root/reset epoch and BAR resources,
        /// with memory decoding already enabled. BAR array indices are hardware
        /// BIRs. Retained ownership must be genuine, not an inert numeric token.
        /// Actual old MSI/MSI-X/INTx sources, callbacks, CPU pending/posted messages
        /// and work have drained. MSI-X disabled alone does not prove that. Native
        /// MSI routing must be qualified separately. Process/deferred context only.
        /// No hardware writes occur on constructor errors; all owners are returned.
        pub unsafe fn new(
            function: Function<C>,
            retained: RetainedOwner,
            bars: [Option<B>; 6],
        ) -> Result<Self, (Error, Owners<C, B>)> {
            let mut owners = (function, retained, bars);
            match discover(&mut owners.0, &owners.2) {
                Ok((layout, control)) if control & ENABLE == 0 => Ok(Self {
                    owners: Some(owners),
                    layout,
                    message: None,
                    poisoned: false,
                }),
                Ok(_) => Err((Error::ActiveMsix, owners)),
                Err(error) => Err((error, owners)),
            }
        }
        pub fn address(&self) -> Result<Address, Error> {
            Ok(self.owners.as_ref().ok_or(Error::Released)?.0.address)
        }
        pub fn vectors(&self) -> u16 {
            self.layout.vectors
        }
        pub fn needs_reset(&self) -> bool {
            self.poisoned
        }
        fn checked(&mut self) -> Result<u16, Error> {
            if self.poisoned {
                return Err(Error::Quarantined);
            }
            let owners = self.owners.as_mut().ok_or(Error::Released)?;
            let (layout, control) = discover(&mut owners.0, &owners.2)?;
            if layout != self.layout {
                return Err(Error::CapabilityChanged);
            }
            Ok(control)
        }
        fn fail<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
            if result.is_err() {
                self.message = None;
                self.poisoned = true;
            }
            result
        }
        fn config_write(&mut self, offset: u16, value: u16) -> Result<(), Error> {
            let config = self.owners.as_mut().ok_or(Error::Released)?.0.config();
            config.write16(offset, value);
            let actual = config.read16(offset);
            if actual != value {
                return Err(Error::Config(if actual == u16::MAX {
                    MsiError::FailedRead { offset }
                } else {
                    MsiError::Readback { offset }
                }));
            }
            Ok(())
        }
        fn read(&self, bar: u8, offset: u64) -> Result<u32, Error> {
            self.owners.as_ref().ok_or(Error::Released)?.2[usize::from(bar)]
                .as_ref()
                .ok_or(Error::InvalidBar)?
                .read32(offset)
                .map_err(|_| Error::Io { bar, offset })
        }
        fn write(&mut self, bar: u8, offset: u64, value: u32) -> Result<(), Error> {
            self.owners.as_mut().ok_or(Error::Released)?.2[usize::from(bar)]
                .as_mut()
                .ok_or(Error::InvalidBar)?
                .write32(offset, value)
                .map_err(|_| Error::Io { bar, offset })?;
            if self.read(bar, offset)? != value {
                return Err(Error::Readback { bar, offset });
            }
            Ok(())
        }
        fn mask_inner(&mut self) -> Result<(), Error> {
            let control = self.checked()?;
            let command = self.owners.as_mut().unwrap().0.config().read16(COMMAND);
            if command == u16::MAX {
                return Err(MsiError::FailedRead { offset: COMMAND }.into());
            }
            self.config_write(COMMAND, command | INTX_DISABLE)?;
            // Linux enables MSI-X under Function Mask before accessing table RAM:
            // some devices do not decode that RAM until MSI-X Enable is set.
            self.config_write(self.layout.offset + 2, control | ENABLE | FUNCTION_MASK)?;
            for vector in 0..self.layout.vectors {
                let offset = self.layout.table_offset + u64::from(vector) * ENTRY_BYTES + 12;
                self.write(self.layout.table_bar, offset, VECTOR_MASK)?;
            }
            Ok(())
        }
        /// Mask all vectors and fallback INTx. No cause/CPU/DMA drain is inferred.
        pub fn mask(&mut self) -> Result<(), Error> {
            let result = self.mask_inner();
            self.fail(result)
        }
        pub fn disable(&mut self) -> Result<(), Error> {
            self.message = None;
            let result = (|| {
                self.mask_inner()?;
                let control = self.checked()?;
                self.config_write(self.layout.offset + 2, (control | FUNCTION_MASK) & !ENABLE)
            })();
            self.fail(result)
        }
        /// Program vector zero; all unused vectors remain individually masked.
        /// # Safety
        /// Message belongs to the actual qualified IRQ registry/route. The source,
        /// old posted messages, callbacks and work have drained before retargeting;
        /// masking alone is insufficient. Keep all actual DMA/IRQ owners retained.
        pub unsafe fn program(&mut self, message: MsiMessage) -> Result<(), Error> {
            if message.address & 3 != 0 {
                return Err(Error::InvalidMessage);
            }
            self.message = None;
            let result = (|| {
                self.mask_inner()?;
                let bar = self.layout.table_bar;
                let offset = self.layout.table_offset;
                self.write(bar, offset, message.address as u32)?;
                self.write(bar, offset + 4, (message.address >> 32) as u32)?;
                self.write(bar, offset + 8, message.data)?;
                self.checked()?;
                Ok(())
            })();
            self.fail(result)?;
            self.message = Some(message);
            Ok(())
        }
        /// # Safety
        /// Actual callback/route is installed and published. The requester, all
        /// source/work/reset/DMA owners and real interrupt controller stay retained.
        pub unsafe fn unmask(&mut self) -> Result<(), Error> {
            if self.poisoned {
                return Err(Error::Quarantined);
            }
            let message = self.message.ok_or(Error::NotProgrammed)?;
            let result = (|| {
                self.mask_inner()?;
                let bar = self.layout.table_bar;
                let offset = self.layout.table_offset;
                for (part, value) in [
                    (0, message.address as u32),
                    (4, (message.address >> 32) as u32),
                    (8, message.data),
                ] {
                    if self.read(bar, offset + part)? != value {
                        return Err(Error::Readback {
                            bar,
                            offset: offset + part,
                        });
                    }
                }
                self.write(bar, offset + 12, 0)?;
                let control = self.checked()?;
                self.config_write(self.layout.offset + 2, (control | ENABLE) & !FUNCTION_MASK)
            })();
            self.fail(result)
        }
        /// Return exact owners only after independent real source/IRQ/work drain.
        /// # Safety
        /// Device is stopped; old pending/posted MSI-X writes, callbacks and all
        /// deferred/reset/timer users have drained and cannot restart. DMA lease,
        /// fence, coherency and IOMMU retirement remain independently owned. Mapped
        /// BARs must be explicitly retired by their actual owner after this return.
        pub unsafe fn release(&mut self) -> Result<Owners<C, B>, Error> {
            self.disable()?;
            self.owners.take().ok_or(Error::Released)
        }
    }
    impl<C: MsiConfigSpace, B: BarAccess> Drop for LegacyReference<C, B> {
        fn drop(&mut self) {
            if let Some(owners) = self.owners.take() {
                core::mem::forget(owners);
                let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    Some(n.saturating_add(1))
                });
            }
        }
    }
}

fn message(index: u16) -> MsiMessage {
    MsiMessage {
        address: MESSAGE.address + u64::from(index) * 4,
        data: MESSAGE.data ^ (u32::from(index) << 16),
    }
}
fn selected_masks(m: &Peripheral, selected: &[u16]) {
    for index in 0..m.vectors {
        let word = (TABLE / 4) as usize + usize::from(index) * 4 + 3;
        assert_eq!(
            m.memory[word] & 1,
            u32::from(!selected.contains(&index)),
            "entry {index}"
        );
    }
}

fn indexed_sequence(owner: &mut MsixConfig<Config, Bar>) -> Result<(), Error> {
    for index in [0, 1, 2] {
        unsafe { owner.program_indexed(index, message(index)) }?;
    }
    unsafe { owner.unmask_indices(&[0, 1]) }?;
    unsafe { owner.program_indexed(2, message(2)) }?;
    unsafe { owner.unmask_indices(&[0, 1, 2]) }?;
    owner.disable()
}

// Real allocator refusal, scoped to the child test thread. Other tests/threads
// retain System allocation. No production fault hook or allocator substitution
// appears in MsixConfig, and the armed phase cannot allocate event log storage.
#[cfg(not(all(
    feature = "linux-kernel",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
)))]
mod allocation {
    extern crate std;

    use core::cell::Cell;
    use std::alloc::{GlobalAlloc, Layout, System};
    std::thread_local! { static STATE: Cell<(bool, usize)> = const { Cell::new((false, 0)) }; }
    pub struct Allocator;
    fn reject() -> bool {
        STATE
            .try_with(|state| {
                let (armed, count) = state.get();
                if armed {
                    state.set((true, count + 1));
                }
                armed
            })
            .unwrap_or(false)
    }
    // SAFETY: armed calls return NULL before effects; unarmed allocations and
    // every deallocation use the same System owner and exact caller layout.
    unsafe impl GlobalAlloc for Allocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if reject() {
                return core::ptr::null_mut();
            }
            // SAFETY: forwarding the allocator's unchanged layout to System.
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            if reject() {
                return core::ptr::null_mut();
            }
            // SAFETY: forwarding the allocator's unchanged layout to System.
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, bytes: usize) -> *mut u8 {
            if reject() {
                return core::ptr::null_mut();
            }
            // SAFETY: forwarding the live allocation and original layout.
            unsafe { System.realloc(pointer, layout, bytes) }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: forwarding the live allocation and original layout.
            unsafe { System.dealloc(pointer, layout) }
        }
    }
    pub fn arm() {
        STATE.with(|state| state.set((true, 0)));
    }
    pub fn disarm() -> usize {
        STATE.with(|state| {
            let (_, count) = state.replace((false, 0));
            count
        })
    }
}
#[cfg(not(all(
    feature = "linux-kernel",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
)))]
#[global_allocator]
static ALLOCATOR: allocation::Allocator = allocation::Allocator;

// The hosted Linux unit binary already owns one canonical GlobalAlloc in
// gpu/linux/task.rs. Reuse its actual test-only counter/refusal boundary; never
// install another allocator in that binary. Only the isolated exact child arms
// it, excluding other controller fixtures and allocation-producing work.
#[cfg(all(
    feature = "linux-kernel",
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos")
))]
mod allocation {
    #[repr(C)]
    struct Counts {
        heap: u64,
        heap_try: u64,
        pages: u64,
    }
    unsafe extern "C" {
        fn stela_test_allocations_begin(refuse: bool);
        fn stela_test_allocations_end() -> Counts;
    }
    pub fn arm() {
        // SAFETY: the window covers this thread only, so the harness thread
        // keeps allocating; this is the existing canonical hosted-heap ABI.
        unsafe { stela_test_allocations_begin(true) };
    }
    pub fn disarm() -> usize {
        // SAFETY: same exclusive controller finishes before any test assertions.
        let counts = unsafe { stela_test_allocations_end() };
        assert_eq!((counts.heap_try, counts.pages), (0, 0));
        usize::try_from(counts.heap).unwrap()
    }
}

#[test]
fn metadata_allocation_failure() {
    const CHILD: &str = "STELA_MSIX_ALLOCATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "bus::pci::msix::tests::metadata_allocation_failure"
                ])
                .env(CHILD, "1")
                .env("RUST_TEST_THREADS", "1")
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    let (mut owner, m) = attach(fixture(2048));
    {
        let mut m = m.lock().unwrap();
        m.events.reserve(100_000);
        m.emitted.reserve(2048);
        m.delivered_entries.reserve(2048);
        m.publish(0);
    }
    unsafe { owner.program(MESSAGE) }.unwrap();
    unsafe { owner.unmask() }.unwrap();
    let before = m.lock().unwrap().memory.clone();
    let config = m.lock().unwrap().config;
    let events = m.lock().unwrap().events.len();
    allocation::arm();
    let result = unsafe { owner.program_indexed(2047, message(2047)) };
    let attempts = allocation::disarm();
    assert_eq!(result, Err(Error::Allocation));
    assert_eq!(attempts, 1);
    assert!(owner.messages.is_empty() && owner.message == Some(MESSAGE) && owner.live.contains(0));
    assert!(!owner.needs_reset());
    assert_eq!(m.lock().unwrap().events.len(), events);
    assert_eq!(m.lock().unwrap().memory, before);
    assert_eq!(m.lock().unwrap().config, config);
    allocation::arm();
    let programmed = unsafe { owner.program(MESSAGE) };
    let unmasked = unsafe { owner.unmask() };
    let indexed = unsafe { owner.program_indexed(0, MESSAGE) };
    let selected = unsafe { owner.unmask_indices(&[0]) };
    let attempts = allocation::disarm();
    assert_eq!(
        (programmed, unmasked, indexed, selected, attempts),
        (Ok(()), Ok(()), Ok(()), Ok(()), 0)
    );
    unsafe { owner.program_indexed(2047, message(2047)) }.unwrap();
    assert_eq!(owner.messages.len(), 2047);
    m.lock().unwrap().publish(2046);
    m.lock().unwrap().publish(2047);
    allocation::arm();
    let programmed = unsafe { owner.program_indexed(2046, message(2046)) };
    let unmasked = unsafe { owner.unmask_indices(&[0, 2046, 2047]) };
    let attempts = allocation::disarm();
    assert_eq!((programmed, unmasked, attempts), (Ok(()), Ok(()), 0));
    assert_eq!(core::mem::size_of::<EntrySet>(), 256);
    assert!(core::mem::size_of::<MsixConfig<Config, Bar>>() < 2048);
    drop(unsafe { owner.release() }.unwrap());
}

mod legacy;

mod mapped;

mod indexed;
