// SPDX-License-Identifier: GPL-2.0-only
//! Mapped BAR windows, table placement and relocation.
use super::*;

#[test]
fn owned_mapping_windows() {
    // The real authority is a boot singleton. Exercise actual owned mappings in
    // an isolated process, independently of other registry activation tests.
    const CHILD: &str = "STELA_MSIX_MAPPED_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "bus::pci::msix::tests::mapped::owned_mapping_windows"
                ])
                .env(CHILD, "1")
                .status()
                .unwrap()
                .success()
        );
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
fn separate_pending_bar_layouts() {
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
fn relocated_bar_rejects_stale_access() {
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
