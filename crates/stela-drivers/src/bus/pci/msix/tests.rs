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
            let pending = if index == 0 { self.pending } else { self.pending_entries[usize::from(index)] };
            let entry = (TABLE / 4) as usize + usize::from(index) * 4;
            if pending && self.memory[entry + 3] & 1 == 0 {
                let actual = MsiMessage {
                    address: u64::from(self.memory[entry]) | u64::from(self.memory[entry + 1]) << 32,
                    data: self.memory[entry + 2],
                };
                if let Some(route) = &self.routes[usize::from(index)] {
                    route.interrupt(actual);
                } else {
                    // Only the pre-existing legacy entry-zero fixtures use
                    // their original boolean publication witness.
                    assert!(index == 0 && self.callback_published,
                        "MSI-X arrived without an actual published route for entry {index}");
                }
                self.emitted.push(actual);
                self.delivered_entries.push(index);
                if index == 0 { self.pending = false; } else { self.pending_entries[usize::from(index)] = false; }
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
            assert_ne!(m.memory[entry + 3] & 1, 0, "message changed before target entry was masked");
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

#[test]
fn actual_enable_mask_program_order_and_one_real_pending_delivery() {
    for vectors in [1, 2, 65, 2048] {
        let (mut owner, m) = attach(fixture(vectors));
        unsafe { owner.program(MESSAGE) }.unwrap();
        {
            let m = m.lock().unwrap();
            assert_eq!(m.get(4, 2), 0x507);
            assert_eq!(m.get(6, 2), 0xa510); // W1C never acknowledged.
            assert!(m.emitted.is_empty());
            assert_eq!(m.get(0x52, 2) & 0xc000, 0xc000);
            for vector in 1..vectors {
                let index = (TABLE / 4) as usize + usize::from(vector) * 4;
                assert_eq!(
                    &m.memory[index..index + 4],
                    &[0xabc0_0000 | u32::from(vector), 0x9876_0000, 0x55aa_0000, 1]
                );
            }
        }
        m.lock().unwrap().pending = true;
        m.lock().unwrap().callback_published = true;
        unsafe { owner.unmask() }.unwrap();
        assert_eq!(m.lock().unwrap().emitted, [MESSAGE]);
        owner.mask().unwrap();
        assert_eq!(m.lock().unwrap().get(0x52, 2) & 0xc000, 0xc000);
        owner.disable().unwrap();
        assert_eq!(m.lock().unwrap().get(0x52, 2) & 0xc000, 0x4000);
        let owners = unsafe { owner.release() }.unwrap();
        assert_eq!(owner.address(), Err(Error::Released));
        drop(owners);
    }
}

#[test]
fn errors_return_real_owners_before_any_writes_and_reject_malformed_extents() {
    for case in 0..12 {
        let f = fixture(2);
        {
            let mut m = f.model.lock().unwrap();
            match case {
                0 => m.put(0x52, 2, 0x8001),           // already active MSI-X
                1 => m.put(0x54, 4, TABLE as u32 | 6), // reserved BIR
                2 => m.put(0x54, 4, TABLE as u32 | 1), // high half of a wide BAR
                3 => m.put(0x58, 4, TABLE as u32 + 8), // overlaps table
                4 => m.put(0x54, 4, 0xfff8),           // outside actual BAR
                5 => m.put(4, 2, 1),                   // no actual memory decode
                6 => m.put(0x50, 2, 0x5011),           // capability cycle
                7 => m.put(0x50, 2, 0x5811),           // following capability inside current body
                8 => {
                    m.put(0x50, 2, 0x6011);
                    m.put(0x60, 2, 5);
                    m.put(0x62, 2, 1);
                } // active MSI
                9 => m.put(0x10, 4, (BASE as u32) | 1), // IO BAR
                10 => m.put(0x52, 2, 0x0801),          // reserved control bits
                _ => m.put(0, 4, 0x9999_8086),
            }
        }
        let (function, retained, bars) = f.owners;
        let result = unsafe { MsixConfig::new(function, retained, bars) };
        let (_, owners) = match result {
            Err(error) => error,
            Ok(_) => panic!("accepted malformed case {case}"),
        };
        assert!(
            !f.model
                .lock()
                .unwrap()
                .events
                .iter()
                .any(|e| matches!(e, Event::ConfigWrite(..) | Event::BarWrite(..)))
        );
        drop(owners);
        assert_eq!(f.config_drops.load(Ordering::Relaxed), 1);
        assert_eq!(f.root_drops.load(Ordering::Relaxed), 1);
        assert_eq!(f.bar_drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn every_failed_access_retains_actual_owners_and_prevents_replay() {
    let (mut baseline, m) = attach(fixture(2));
    m.lock().unwrap().callback_published = true;
    unsafe { baseline.program(MESSAGE) }.unwrap();
    unsafe { baseline.unmask() }.unwrap();
    baseline.disable().unwrap();
    let events = m.lock().unwrap().events.len();
    assert!(events > 100);
    for after_effect in [false, true] {
        for failure in 1..=events {
            let f = fixture(2);
            let drops = [
                f.config_drops.clone(),
                f.root_drops.clone(),
                f.bar_drops.clone(),
            ];
            let (mut owner, m) = attach(f);
            {
                let mut m = m.lock().unwrap();
                m.fail = Some(failure);
                m.after_effect = after_effect;
                m.callback_published = true;
            }
            let result = (|| {
                unsafe { owner.program(MESSAGE) }?;
                unsafe { owner.unmask() }?;
                owner.disable()
            })();
            assert!(result.is_err(), "failure not exercised at {failure}");
            assert!(owner.needs_reset());
            let count = m.lock().unwrap().events.len();
            assert_eq!(owner.mask(), Err(Error::Quarantined));
            assert_eq!(unsafe { owner.unmask() }, Err(Error::Quarantined));
            assert!(matches!(
                unsafe { owner.release() },
                Err(Error::Quarantined)
            ));
            assert_eq!(m.lock().unwrap().events.len(), count);
            drop(owner);
            assert!(drops.iter().all(|d| d.load(Ordering::Relaxed) == 0));
        }
    }
}

#[test]
fn changed_hardware_message_and_capability_cannot_be_unmasked() {
    let (mut owner, m) = attach(fixture(2));
    assert_eq!(unsafe { owner.unmask() }, Err(Error::NotProgrammed));
    assert_eq!(
        unsafe {
            owner.program(MsiMessage {
                address: 3,
                data: 0,
            })
        },
        Err(Error::InvalidMessage)
    );
    assert!(!owner.needs_reset());
    unsafe { owner.program(MESSAGE) }.unwrap();
    m.lock().unwrap().memory[(TABLE / 4) as usize + 2] ^= 1;
    assert!(matches!(
        unsafe { owner.unmask() },
        Err(Error::Readback { .. })
    ));
    assert!(owner.needs_reset());
    let (mut owner, m) = attach(fixture(2));
    unsafe { owner.program(MESSAGE) }.unwrap();
    m.lock().unwrap().put(0x58, 4, (PBA + 8) as u32);
    assert_eq!(unsafe { owner.unmask() }, Err(Error::CapabilityChanged));
    assert!(owner.needs_reset());
}

#[test]
fn native_mapped_bar_uses_owned_uc_windows_and_actual_volatile_words() {
    // The real authority is a boot singleton. Exercise actual owned mappings in
    // an isolated process, independently of other registry activation tests.
    const CHILD: &str = "STELA_MSIX_MAPPED_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "bus::pci::msix::tests::native_mapped_bar_uses_owned_uc_windows_and_actual_volatile_words"])
            .env(CHILD,"1").status().unwrap().success());
        return;
    }
    use crate::bus::mmio::owned::{
        self, AddressSpace, Authority, CacheAttribute, InstalledMapping, MapFailure, MapRequest,
        MappingPlatform, Protection, Resource, ResourceBacking, ResourceKind,
    };
    use alloc::boxed::Box;
    use core::ptr::NonNull;
    struct Backing;
    unsafe impl ResourceBacking for Backing {
        fn physical_span(&self) -> PhysicalSpan {
            PhysicalSpan::new(BASE, BYTES).unwrap()
        }
        fn kind(&self) -> ResourceKind {
            ResourceKind::Registers
        }
    }
    #[repr(align(4096))]
    #[derive(Clone)]
    struct Page([u32; 1024]);
    type Allocations = Vec<(u64, Box<[Page]>)>;
    struct Platform(Mutex<Allocations>);
    unsafe impl MappingPlatform for Platform {
        fn check_context(&self, _: AddressSpace) -> Result<(), owned::Error> {
            Ok(())
        }
        unsafe fn map(
            &self,
            _: &Resource,
            request: MapRequest,
        ) -> Result<InstalledMapping, MapFailure> {
            let mut words =
                vec![Page([0; 1024]); request.physical.bytes() as usize / 4096].into_boxed_slice();
            let pointer = NonNull::new(words.as_mut_ptr().cast()).unwrap();
            self.0.lock().unwrap().push((request.id, words));
            Ok(InstalledMapping {
                token: request.id,
                cpu_base: pointer,
                physical: request.physical,
                attribute: request.attribute,
                protection: request.protection,
            })
        }
        unsafe fn unmap(
            &self,
            request: MapRequest,
            mapping: InstalledMapping,
        ) -> Result<(), owned::Error> {
            assert_eq!(request.id, mapping.token);
            let mut rows = self.0.lock().unwrap();
            let index = rows.iter().position(|(id, _)| *id == request.id).unwrap();
            rows.remove(index);
            Ok(())
        }
    }
    let platform = Arc::new(Platform(Mutex::new(Vec::new())));
    let authority = unsafe {
        Authority::activate(
            platform.clone(),
            AddressSpace {
                identity: 0x1234,
                physical_bits: 48,
                virtual_bits: 48,
            },
            Vec::new(),
        )
    }
    .unwrap();
    let resource = Resource::new(Box::new(Backing));
    let first = authority
        .map(
            resource.clone(),
            0,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    let second = authority
        .map(
            resource.clone(),
            PBA as usize,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    let mut bar = match unsafe {
        MappedBar::new(
            PhysicalSpan::new(BASE, BYTES).unwrap(),
            [Some(first), Some(second)],
        )
    } {
        Ok(bar) => bar,
        Err(_) => panic!("real owned windows rejected"),
    };
    assert!(bar.accessible(TABLE, 32));
    assert!(bar.accessible(PBA, 256));
    assert!(!bar.accessible(4096, 4));
    assert!(!bar.accessible(u64::MAX, 4));
    bar.write32(TABLE, 0xdead_beef).unwrap();
    assert_eq!(bar.read32(TABLE), Ok(0xdead_beef));
    assert_eq!(
        platform.0.lock().unwrap()[0].1[0].0[(TABLE / 4) as usize],
        0xdead_beef
    );
    assert_eq!(bar.read32(TABLE + 1), Err(IoError));
    assert_eq!(bar.write32(4096, 1), Err(IoError));
    // Use those same actual UC windows through the indexed owner, not a second
    // MMIO provider. Entry64 crosses the 63/64 pending-word boundary and remains
    // inside the first retained window. The software config fixture grants no
    // physical interrupt delivery authority and has no pending source here.
    let f = fixture(65);
    f.model.lock().unwrap().publish(64);
    let (function, retained, old_bars) = f.owners;
    drop(old_bars);
    let mut actual_bars = core::array::from_fn(|_| None);
    actual_bars[0] = Some(bar);
    let mut owner = match unsafe { MsixConfig::new(function, retained, actual_bars) } {
        Ok(owner) => owner,
        Err(_) => panic!("actual UC indexed owner rejected"),
    };
    let actual_message = message(64);
    unsafe { owner.program_indexed(64, actual_message) }.unwrap();
    unsafe { owner.unmask_indices(&[64]) }.unwrap();
    {
        let pages = platform.0.lock().unwrap();
        let words = &pages[0].1[0].0;
        let entry = ((TABLE + 64 * 16) / 4) as usize;
        assert_eq!(words[entry], actual_message.address as u32);
        assert_eq!(words[entry + 1], (actual_message.address >> 32) as u32);
        assert_eq!(words[entry + 2], actual_message.data);
        assert_eq!(words[entry + 3], 0);
        assert_eq!(words[(TABLE / 4) as usize + 3], 1);
    }
    let (_, _, mut actual_bars) = unsafe { owner.release() }.unwrap();
    let bar = actual_bars[0].take().unwrap();
    let mut windows = bar.into_mappings();
    for mapping in windows.iter_mut().flatten() {
        unsafe { mapping.retire() }.unwrap();
    }
    assert!(platform.0.lock().unwrap().is_empty());
    let read_only = authority
        .map(
            resource,
            0,
            4096,
            CacheAttribute::Uncached,
            Protection::ReadOnly,
        )
        .unwrap();
    let mut returned = match unsafe {
        MappedBar::new(
            PhysicalSpan::new(BASE, BYTES).unwrap(),
            [Some(read_only), None],
        )
    } {
        Err((Error::Mapping, returned)) => returned,
        _ => panic!("read-only MSI-X backing accepted"),
    };
    unsafe { returned[0].as_mut().unwrap().retire() }.unwrap();
    assert!(platform.0.lock().unwrap().is_empty());
}

#[test]
fn actual_32_and_64_bit_bars_with_separate_pending_arrays() {
    for wide in [false, true] {
        let mut f = fixture(65);
        let base = if wide { BASE } else { 0x4000_0000 };
        let pending_base = 0x5000_0000;
        {
            let mut m = f.model.lock().unwrap();
            m.put(0x10, 4, base as u32 | if wide { 4 } else { 0 });
            m.put(0x14, 4, if wide { (base >> 32) as u32 } else { 0 });
            m.put(0x18, 4, pending_base as u32);
            m.put(0x58, 4, PBA as u32 | 2);
        }
        f.owners.2[0].as_mut().unwrap().span = PhysicalSpan::new(base, BYTES).unwrap();
        f.owners.2[2] = Some(Bar {
            model: f.model.clone(),
            span: PhysicalSpan::new(pending_base, BYTES).unwrap(),
            drops: f.bar_drops.clone(),
        });
        let drops = f.bar_drops.clone();
        let (mut owner, m) = attach(f);
        unsafe { owner.program(MESSAGE) }.unwrap();
        m.lock().unwrap().callback_published = true;
        unsafe { owner.unmask() }.unwrap();
        let owners = unsafe { owner.release() }.unwrap();
        drop(owners);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }
}

#[test]
fn actual_bar_relocation_never_accesses_old_table_or_revives_authority() {
    let (mut owner, m) = attach(fixture(2));
    unsafe { owner.program(MESSAGE) }.unwrap();
    m.lock().unwrap().put(0x10, 4, (BASE as u32 + 0x10000) | 4);
    let start = m.lock().unwrap().events.len();
    assert_eq!(unsafe { owner.unmask() }, Err(Error::Mapping));
    assert!(owner.needs_reset());
    assert!(
        !m.lock().unwrap().events[start..]
            .iter()
            .any(|event| matches!(event, Event::BarRead(..) | Event::BarWrite(..)))
    );
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
        assert_eq!(m.memory[word] & 1, u32::from(!selected.contains(&index)), "entry {index}");
    }
}

#[test]
fn legacy_wrappers_match_complete_original_owner_access_traces() {
    for vectors in [1, 2, 65, 2048] {
        let (mut owner, m) = attach(fixture(vectors));
        let f = fixture(vectors);
        let (function, retained, bars) = f.owners;
        let mut old = match unsafe { original::LegacyReference::new(function, retained, bars) } {
            Ok(owner) => owner,
            Err(_) => panic!("original attach"),
        };
        f.model.lock().unwrap().events.clear();
        let other = f.model;
        macro_rules! compare {
            ($new:expr, $old:expr) => {{
                assert_eq!($new, $old);
                let a = m.lock().unwrap();
                let b = other.lock().unwrap();
                assert_eq!(a.events, b.events);
                assert_eq!(a.config, b.config);
                assert_eq!(a.memory, b.memory);
                assert_eq!(a.emitted, b.emitted);
            }};
        }
        compare!(unsafe { owner.unmask() }, unsafe { old.unmask() });
        let invalid = MsiMessage { address: 3, data: 0 };
        compare!(unsafe { owner.program(invalid) }, unsafe { old.program(invalid) });
        compare!(unsafe { owner.program(MESSAGE) }, unsafe { old.program(MESSAGE) });
        for model in [&m, &other] {
            let mut model = model.lock().unwrap();
            model.callback_published = true;
            model.pending = true;
        }
        compare!(unsafe { owner.unmask() }, unsafe { old.unmask() });
        compare!(owner.mask(), old.mask());
        compare!(unsafe { owner.program(message(1)) }, unsafe { old.program(message(1)) });
        compare!(owner.disable(), old.disable());
        assert_eq!(owner.vectors(), old.vectors());
        assert_eq!(owner.needs_reset(), old.needs_reset());
        drop(unsafe { owner.release() }.unwrap());
        drop(unsafe { old.release() }.unwrap());
        assert_eq!(owner.address(), old.address());
        compare!(unsafe { owner.unmask() }, unsafe { old.unmask() });
        compare!(unsafe { owner.program(MESSAGE) }, unsafe { old.program(MESSAGE) });
        assert_eq!(owner.needs_reset(), old.needs_reset());
        compare!(owner.mask(), old.mask());
        assert_eq!(m.lock().unwrap().events, other.lock().unwrap().events);
    }
}

#[test]
fn indexed_sparse_boundary_payloads_and_simultaneous_pending_delivery() {
    for vectors in [1, 2, 65, 66, 2048] {
        let (mut owner, m) = attach(fixture(vectors));
        let mut indices: Vec<u16> = [0, 1, 63, 64, 65, 2047]
            .into_iter().filter(|index| *index < vectors).collect();
        indices.push(vectors - 1);
        indices.sort_unstable();
        indices.dedup();
        let before = m.lock().unwrap().memory.clone();
        for &index in &indices {
            unsafe { owner.program_indexed(index, message(index)) }.unwrap();
        }
        {
            let mut m = m.lock().unwrap();
            selected_masks(&m, &[]);
            for index in 0..vectors {
                let word = (TABLE / 4) as usize + usize::from(index) * 4;
                if indices.contains(&index) {
                    let expected = message(index);
                    assert_eq!(m.memory[word], expected.address as u32);
                    assert_eq!(m.memory[word + 1], (expected.address >> 32) as u32);
                    assert_eq!(m.memory[word + 2], expected.data);
                    m.publish(index);
                    m.queue(index);
                } else {
                    assert_eq!(m.memory[word..word + 3], before[word..word + 3]);
                }
            }
            assert!(m.emitted.is_empty());
        }
        unsafe { owner.unmask_indices(&indices) }.unwrap();
        {
            let m = m.lock().unwrap();
            selected_masks(&m, &indices);
            assert_eq!(m.delivered_entries, indices);
            for &index in &indices {
                assert_eq!(m.routes[usize::from(index)].as_ref().unwrap().calls.load(Ordering::Relaxed), 1);
            }
            assert_eq!(m.emitted, indices.iter().copied().map(message).collect::<Vec<_>>());
            assert!(m.memory[(PBA / 4) as usize..(PBA / 4) as usize + usize::from(vectors).div_ceil(32)].iter().all(|word| *word == 0));
            assert!(!m.events.iter().any(|event| matches!(event, Event::BarWrite(offset, _) if *offset >= PBA)));
            assert!(matches!(m.events.iter().rev().find(|event| matches!(event, Event::ConfigWrite(..))), Some(Event::ConfigWrite(0x52, control)) if control & 0xc000 == 0x8000));
        }
        drop(unsafe { owner.release() }.unwrap());
    }
}

#[test]
fn indexed_program_preserves_live_peers_and_real_pending_bits() {
    let (mut owner, m) = attach(fixture(66));
    for index in [0, 63, 64] {
        unsafe { owner.program_indexed(index, message(index)) }.unwrap();
        m.lock().unwrap().publish(index);
    }
    unsafe { owner.unmask_indices(&[0, 63, 64]) }.unwrap();
    let before = m.lock().unwrap().memory.clone();
    {
        let mut m = m.lock().unwrap();
        m.queue_on_guard.extend([0, 63, 64, 65]);
        // Target 65 has no published callback yet: it must never deliver while
        // its new message is being installed or peer delivery is restored.
    }
    let start = m.lock().unwrap().events.len();
    unsafe { owner.program_indexed(65, message(65)) }.unwrap();
    {
        let m = m.lock().unwrap();
        selected_masks(&m, &[0, 63, 64]);
        assert_eq!(m.delivered_entries, [0, 63, 64]);
        assert_eq!(m.emitted, [message(0), message(63), message(64)]);
        for index in [0, 63, 64] {
            assert_eq!(m.routes[usize::from(index)].as_ref().unwrap().calls.load(Ordering::Relaxed), 1);
            let word = (TABLE / 4) as usize + usize::from(index) * 4;
            assert_eq!(m.memory[word..word + 3], before[word..word + 3]);
        }
        assert_eq!(m.memory[(PBA / 4) as usize + 2], 2); // pending entry65 survives
        assert!(m.pending_entries[65]);
        assert!(m.events[start..].iter().all(|event| match event {
            Event::BarWrite(offset, _) => (TABLE + 65 * 16..TABLE + 66 * 16).contains(offset),
            _ => true,
        }));
    }
    m.lock().unwrap().publish(65);
    unsafe { owner.unmask_indices(&[0, 63, 64, 65]) }.unwrap();
    assert_eq!(m.lock().unwrap().delivered_entries, [0, 63, 64, 65]);
    owner.mask().unwrap();
    unsafe { owner.program_indexed(65, message(65)) }.unwrap();
    assert_eq!(m.lock().unwrap().get(0x52, 2) & 0xc000, 0xc000);
    selected_masks(&m.lock().unwrap(), &[]);
    // Retarget a formerly live entry under an explicitly modeled stopped target;
    // the unrelated live peer remains enabled; no stale target request exists.
    unsafe { owner.unmask_indices(&[0, 64]) }.unwrap();
    unsafe { owner.program_indexed(64, message(64)) }.unwrap();
    selected_masks(&m.lock().unwrap(), &[0]);
    drop(unsafe { owner.release() }.unwrap());
}

#[test]
fn mixed_legacy_calls_invalidate_nonzero_replay_without_reviving_old_routes() {
    for use_program in [false, true] {
        let (mut owner, m) = attach(fixture(65));
        for index in [0, 64] {
            unsafe { owner.program_indexed(index, message(index)) }.unwrap();
            m.lock().unwrap().publish(index);
        }
        unsafe { owner.unmask_indices(&[0, 64]) }.unwrap();
        if use_program {
            unsafe { owner.program(MESSAGE) }.unwrap();
            selected_masks(&m.lock().unwrap(), &[]);
            unsafe { owner.unmask() }.unwrap();
        } else {
            unsafe { owner.unmask() }.unwrap();
        }
        selected_masks(&m.lock().unwrap(), &[0]);
        let events = m.lock().unwrap().events.clone();
        assert_eq!(unsafe { owner.unmask_indices(&[0, 64]) }, Err(Error::NotProgrammed));
        assert_eq!(m.lock().unwrap().events, events);
        assert!(!owner.needs_reset());
        unsafe { owner.program_indexed(64, message(64)) }.unwrap();
        unsafe { owner.unmask_indices(&[0, 64]) }.unwrap();
        selected_masks(&m.lock().unwrap(), &[0, 64]);
        drop(unsafe { owner.release() }.unwrap());
    }
}

#[test]
fn invalid_index_selection_message_and_offset_leave_valid_state_unchanged() {
    let (mut owner, m) = attach(fixture(65));
    for index in [0, 64] {
        unsafe { owner.program_indexed(index, message(index)) }.unwrap();
        m.lock().unwrap().publish(index);
    }
    unsafe { owner.unmask_indices(&[0, 64]) }.unwrap();
    let memory = m.lock().unwrap().memory.clone();
    let config = m.lock().unwrap().config;
    let events = m.lock().unwrap().events.clone();
    for indices in [&[][..], &[0, 0][..], &[65][..], &[0, 1][..]] {
        assert!(unsafe { owner.unmask_indices(indices) }.is_err());
    }
    assert_eq!(unsafe { owner.program_indexed(65, message(1)) }, Err(Error::InvalidIndex));
    assert_eq!(unsafe { owner.program_indexed(u16::MAX, message(1)) }, Err(Error::InvalidIndex));
    assert_eq!(unsafe { owner.program(MsiMessage { address: 3, data: 0 }) }, Err(Error::InvalidMessage));
    assert_eq!(unsafe { owner.program_indexed(64, MsiMessage { address: 1, data: 0 }) }, Err(Error::InvalidMessage));
    assert!(!owner.needs_reset());
    assert_eq!(m.lock().unwrap().memory, memory);
    assert_eq!(m.lock().unwrap().config, config);
    assert_eq!(m.lock().unwrap().events, events);
    selected_masks(&m.lock().unwrap(), &[0, 64]);
    // The checked arithmetic also refuses an impossible internal corrupt layout
    // without touching MMIO. This fixture does not admit such a hardware layout.
    let saved = owner.layout;
    owner.layout.table_offset = u64::MAX - 7;
    assert_eq!(unsafe { owner.program_indexed(64, message(1)) }, Err(Error::InvalidTable));
    owner.layout = saved;
    assert_eq!(m.lock().unwrap().events, events);
    drop(unsafe { owner.release() }.unwrap());
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

#[test]
fn every_indexed_access_failure_before_or_after_effect_poisons_all_entries() {
    let (mut baseline, m) = attach(fixture(3));
    for index in 0..3 { m.lock().unwrap().publish(index); }
    m.lock().unwrap().queue_on_guard.extend([0, 1]);
    indexed_sequence(&mut baseline).unwrap();
    let count = m.lock().unwrap().events.len();
    drop(unsafe { baseline.release() }.unwrap());
    for after_effect in [false, true] {
        for failure in 1..=count {
            let f = fixture(3);
            let drops = [f.config_drops.clone(), f.root_drops.clone(), f.bar_drops.clone()];
            let (mut owner, m) = attach(f);
            {
                let mut m = m.lock().unwrap();
                m.fail = Some(failure);
                m.after_effect = after_effect;
                for index in 0..3 { m.publish(index); }
                m.queue_on_guard.extend([0, 1]);
            }
            assert!(indexed_sequence(&mut owner).is_err(), "unreached failure {failure}");
            assert!(owner.needs_reset());
            assert!(owner.message.is_none() && owner.messages.iter().all(Option::is_none));
            for index in 0..3 { assert!(!owner.live.contains(index)); }
            let events = m.lock().unwrap().events.len();
            assert_eq!(unsafe { owner.unmask_indices(&[0, 1]) }, Err(Error::Quarantined));
            assert_eq!(unsafe { owner.program_indexed(2, MESSAGE) }, Err(Error::Quarantined));
            assert_eq!(unsafe { owner.release() }.err(), Some(Error::Quarantined));
            assert_eq!(m.lock().unwrap().events.len(), events);
            drop(owner);
            assert!(drops.iter().all(|drop| drop.load(Ordering::Relaxed) == 0));
        }
    }
}

#[test]
fn selected_message_and_peer_corruption_never_reopen_the_global_guard() {
    for corrupt_peer in [false, true] {
        let (mut owner, m) = attach(fixture(3));
        for index in 0..3 {
            unsafe { owner.program_indexed(index, message(index)) }.unwrap();
            m.lock().unwrap().publish(index);
        }
        unsafe { owner.unmask_indices(&[0, 1]) }.unwrap();
        let word = (TABLE / 4) as usize + 4 + 2;
        m.lock().unwrap().memory[word] ^= 1;
        let start = m.lock().unwrap().events.len();
        let result = if corrupt_peer {
            unsafe { owner.program_indexed(2, message(2)) }
        } else {
            unsafe { owner.unmask_indices(&[0, 1, 2]) }
        };
        assert!(matches!(result, Err(Error::Readback { .. })));
        assert!(owner.needs_reset());
        let m = m.lock().unwrap();
        assert_eq!(m.get(0x52, 2) & 0xc000, 0xc000);
        assert!(!m.events[start..].iter().any(|event| matches!(event, Event::ConfigWrite(0x52, control) if control & 0xc000 == 0x8000)));
        if !corrupt_peer {
            assert!(!m.events[start..].iter().any(|event| matches!(event, Event::BarWrite(offset, 0) if (*offset - TABLE) % 16 == 12)));
        }
    }
}

// Real allocator refusal, scoped to the child test thread. Other tests/threads
// retain System allocation. No production fault hook or allocator substitution
// appears in MsixConfig, and the armed phase cannot allocate event log storage.
#[cfg(not(all(feature = "linux-kernel", target_arch = "x86_64", any(target_os = "linux", target_os = "macos"))))]
mod allocation {
    use core::cell::Cell;
    use std::alloc::{GlobalAlloc, Layout, System};
    std::thread_local! { static STATE: Cell<(bool, usize)> = const { Cell::new((false, 0)) }; }
    pub struct Allocator;
    fn reject() -> bool {
        STATE.try_with(|state| {
            let (armed, count) = state.get();
            if armed { state.set((true, count + 1)); }
            armed
        }).unwrap_or(false)
    }
    // SAFETY: armed calls return NULL before effects; unarmed allocations and
    // every deallocation use the same System owner and exact caller layout.
    unsafe impl GlobalAlloc for Allocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if reject() { return core::ptr::null_mut(); }
            // SAFETY: forwarding the allocator's unchanged layout to System.
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            if reject() { return core::ptr::null_mut(); }
            // SAFETY: forwarding the allocator's unchanged layout to System.
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, bytes: usize) -> *mut u8 {
            if reject() { return core::ptr::null_mut(); }
            // SAFETY: forwarding the live allocation and original layout.
            unsafe { System.realloc(pointer, layout, bytes) }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: forwarding the live allocation and original layout.
            unsafe { System.dealloc(pointer, layout) }
        }
    }
    pub fn arm() { STATE.with(|state| state.set((true, 0))); }
    pub fn disarm() -> usize { STATE.with(|state| { let (_, count) = state.replace((false, 0)); count }) }
}
#[cfg(not(all(feature = "linux-kernel", target_arch = "x86_64", any(target_os = "linux", target_os = "macos"))))]
#[global_allocator]
static ALLOCATOR: allocation::Allocator = allocation::Allocator;

// The hosted Linux unit binary already owns one canonical GlobalAlloc in
// gpu/linux/task.rs. Reuse its actual test-only counter/refusal boundary; never
// install another allocator in that binary. Only the isolated exact child arms
// it, excluding other controller fixtures and allocation-producing work.
#[cfg(all(feature = "linux-kernel", target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
mod allocation {
    #[repr(C)]
    struct Counts { heap: u64, heap_try: u64, pages: u64 }
    unsafe extern "C" {
        fn stela_test_allocations_begin(refuse: bool);
        fn stela_test_allocations_end() -> Counts;
    }
    pub fn arm() {
        // SAFETY: isolated exact child excludes concurrent allocation users;
        // this is the existing canonical hosted-heap fixture ABI.
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
fn actual_metadata_allocation_refusal_is_immutable_and_legacy_path_allocates_nothing() {
    const CHILD: &str = "STELA_MSIX_ALLOCATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "bus::pci::msix::tests::actual_metadata_allocation_refusal_is_immutable_and_legacy_path_allocates_nothing"])
            .env(CHILD, "1").env("RUST_TEST_THREADS", "1").status().unwrap().success());
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
    assert_eq!((programmed, unmasked, indexed, selected, attempts),
        (Ok(()), Ok(()), Ok(()), Ok(()), 0));
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

#[test]
fn indexed_layout_identity_control_and_peer_mask_changes_quarantine_one_owner() {
    for case in 0..7 {
        let f = fixture(3);
        let drops = [f.config_drops.clone(), f.root_drops.clone(), f.bar_drops.clone()];
        let (mut owner, m) = attach(f);
        for index in 0..3 {
            unsafe { owner.program_indexed(index, message(index)) }.unwrap();
            m.lock().unwrap().publish(index);
        }
        unsafe { owner.unmask_indices(&[0, 1]) }.unwrap();
        {
            let mut m = m.lock().unwrap();
            match case {
                0 => m.put(0, 4, 0x9999_8086),
                1 => m.put(0x58, 4, (PBA + 8) as u32),
                2 => m.put(0x54, 4, (TABLE + 16) as u32),
                3 => m.put(0x52, 2, 0x8003),
                4 => m.put(4, 2, 0x505),
                5 => m.put(0x52, 2, 0xc002),
                _ => m.memory[(TABLE / 4) as usize + 4 + 3] = 1,
            }
        }
        let start = m.lock().unwrap().events.len();
        assert!(unsafe { owner.program_indexed(2, message(2)) }.is_err());
        assert!(owner.needs_reset());
        if case < 6 {
            assert!(!m.lock().unwrap().events[start..].iter()
                .any(|event| matches!(event, Event::BarRead(..) | Event::BarWrite(..))));
        } else {
            assert_eq!(m.lock().unwrap().get(0x52, 2) & 0xc000, 0xc000);
        }
        assert_eq!(unsafe { owner.release() }.err(), Some(Error::Quarantined));
        drop(owner);
        assert!(drops.iter().all(|drop| drop.load(Ordering::Relaxed) == 0));
    }
}

#[test]
fn legacy_vector_zero_has_independently_stated_literal_access_order() {
    // Exact immutable fixture layout: one 64-bit BAR, table/PBA in BAR0, one
    // capability. This sequence comes from the source contract, not new helpers.
    let discovery = [
        Event::ConfigRead(0, 4), Event::ConfigRead(0x0e, 1),
        Event::ConfigRead(4, 2), Event::ConfigRead(6, 2),
        Event::ConfigRead(0x34, 1), Event::ConfigRead(0x50, 2),
        Event::ConfigRead(0x52, 2), Event::ConfigRead(0x54, 4),
        Event::ConfigRead(0x58, 4), Event::ConfigRead(0x10, 4),
        Event::ConfigRead(0x14, 4), Event::ConfigRead(0x10, 4),
        Event::ConfigRead(0x14, 4),
    ];
    let prefix = || {
        let mut expected = discovery.to_vec();
        expected.extend([
            Event::ConfigRead(4, 2), Event::ConfigWrite(4, 0x507),
            Event::ConfigRead(4, 2), Event::ConfigWrite(0x52, 0xc001),
            Event::ConfigRead(0x52, 2),
            Event::BarWrite(0x10c, 1), Event::BarRead(0x10c),
            Event::BarWrite(0x11c, 1), Event::BarRead(0x11c),
        ]);
        expected
    };
    let (mut owner, m) = attach(fixture(2));
    unsafe { owner.program(MESSAGE) }.unwrap();
    let mut expected = prefix();
    expected.extend([
        Event::BarWrite(0x100, 0xfee0_1000), Event::BarRead(0x100),
        Event::BarWrite(0x104, 0x1234_5678), Event::BarRead(0x104),
        Event::BarWrite(0x108, 0x8765_4321), Event::BarRead(0x108),
    ]);
    expected.extend(discovery);
    assert_eq!(m.lock().unwrap().events, expected);
    m.lock().unwrap().events.clear();
    m.lock().unwrap().publish(0);
    unsafe { owner.unmask() }.unwrap();
    let mut expected = prefix();
    expected.extend([
        Event::BarRead(0x100), Event::BarRead(0x104), Event::BarRead(0x108),
        Event::BarWrite(0x10c, 0), Event::BarRead(0x10c),
    ]);
    expected.extend(discovery);
    expected.extend([Event::ConfigWrite(0x52, 0x8001), Event::ConfigRead(0x52, 2)]);
    assert_eq!(m.lock().unwrap().events, expected);
    drop(unsafe { owner.release() }.unwrap());
}

#[test]
fn missing_legacy_zero_preflight_preserves_nonzero_live_replay() {
    let (mut owner, m) = attach(fixture(65));
    unsafe { owner.program_indexed(64, message(64)) }.unwrap();
    m.lock().unwrap().publish(64);
    unsafe { owner.unmask_indices(&[64]) }.unwrap();
    let events = m.lock().unwrap().events.clone();
    let memory = m.lock().unwrap().memory.clone();
    assert_eq!(unsafe { owner.unmask() }, Err(Error::NotProgrammed));
    assert!(owner.live.contains(64));
    assert_eq!(owner.message_at(64), Some(message(64)));
    assert!(!owner.needs_reset());
    assert_eq!(m.lock().unwrap().events, events);
    assert_eq!(m.lock().unwrap().memory, memory);
    unsafe { owner.unmask_indices(&[64]) }.unwrap();
    drop(unsafe { owner.release() }.unwrap());
}
