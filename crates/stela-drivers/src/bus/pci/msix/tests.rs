// SPDX-License-Identifier: MIT
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
    fn deliver(&mut self) {
        let control = self.get(0x52, 2);
        let entry = (TABLE / 4) as usize;
        if self.pending && control & 0xc000 == 0x8000 && self.memory[entry + 3] & 1 == 0 {
            assert!(
                self.callback_published,
                "MSI-X arrived without an actual published route"
            );
            self.emitted.push(MsiMessage {
                address: u64::from(self.memory[entry]) | u64::from(self.memory[entry + 1]) << 32,
                data: self.memory[entry + 2],
            });
            self.pending = false;
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
