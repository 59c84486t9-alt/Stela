// SPDX-License-Identifier: GPL-2.0-only
//! Mapped BAR windows, table placement and relocation.
use super::*;

#[test]
fn owned_mapping_windows() {
    // Permission is a process singleton; isolate this Box-backed mapping provider
    // from other registry activation tests.
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
    // SAFETY: this immutable symbolic span belongs only to the private child
    // provider; its mappings are backed by the aligned Box pages below.
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
    // SAFETY: each request receives a distinct aligned Box allocation. Moving
    // the Box into the mutex-protected ID table leaves its buffer address stable;
    // only matching unmap removes it after the mapping has retired. Test buffer
    // inspections finish before BAR writes, so no Rust borrow aliases volatile mutation.
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
    // SAFETY: This exact child test is the only registry activator. The platform
    // keeps page-aligned Box buffers by mapping ID until acknowledged unmap.
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
    // SAFETY: Supplied windows refer to this isolated Box-backed resource and keep
    // their aligned buffers. Rejected read-only windows are returned without device access.
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
    // Reuse these owned windows through the indexed API. Entry64 crosses the
    // 63/64 pending-word boundary within the first buffer. The fixture
    // has no pending interrupt source during this mapping check.
    let f = fixture(65);
    f.model.lock().unwrap().publish(64);
    let (function, retained, old_bars) = f.owners;
    drop(old_bars);
    let mut actual_bars = core::array::from_fn(|_| None);
    actual_bars[0] = Some(bar);
    // SAFETY: The function and BARs are the fixture's Arc-backed peripheral owners.
    // There is no asynchronous source; invalid configuration returns owners before writes.
    let mut owner = match unsafe { MsixConfig::new(function, retained, actual_bars) } {
        Ok(owner) => owner,
        Err(_) => panic!("actual UC indexed owner rejected"),
    };
    let actual_message = message(64);
    // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
    // callbacks stay held; table writes and message emission run synchronously.
    unsafe { owner.program_indexed(64, actual_message) }.unwrap();
    // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
    // under its mutex, including failures injected after a modeled hardware effect.
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
    // SAFETY: All model deliveries finish synchronously while holding the peripheral
    // mutex. No hardware or background callback can race release of these owners.
    let (_, _, mut actual_bars) = unsafe { owner.release() }.unwrap();
    let bar = actual_bars[0].take().unwrap();
    let mut windows = bar.into_mappings();
    for mapping in windows.iter_mut().flatten() {
        // SAFETY: The owner returned these mappings and no BAR access remains. The
        // private platform keeps their Box buffers live until this retirement calls unmap.
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
    // SAFETY: Supplied windows refer to this isolated Box-backed resource and keep
    // their aligned buffers. Rejected read-only windows are returned without device access.
    let mut returned = match unsafe {
        MappedBar::new(
            PhysicalSpan::new(BASE, BYTES).unwrap(),
            [Some(read_only), None],
        )
    } {
        Err((Error::Mapping, returned)) => returned,
        _ => panic!("read-only MSI-X backing accepted"),
    };
    // SAFETY: The owner returned these mappings and no BAR access remains. The
    // private platform keeps their Box buffers live until this retirement calls unmap.
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
        // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
        // callbacks stay held; table writes and message emission run synchronously.
        unsafe { owner.program(MESSAGE) }.unwrap();
        m.lock().unwrap().callback_published = true;
        // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
        // under its mutex, including failures injected after a modeled hardware effect.
        unsafe { owner.unmask() }.unwrap();
        // SAFETY: All model deliveries finish synchronously while holding the peripheral
        // mutex. No hardware or background callback can race release of these owners.
        let owners = unsafe { owner.release() }.unwrap();
        drop(owners);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }
}

#[test]
fn relocated_bar_rejects_stale_access() {
    let (mut owner, m) = attach(fixture(2));
    // SAFETY: Config and Bar keep the same mutex-protected peripheral. Live route
    // callbacks stay held; table writes and message emission run synchronously.
    unsafe { owner.program(MESSAGE) }.unwrap();
    m.lock().unwrap().put(0x10, 4, (BASE as u32 + 0x10000) | 4);
    let start = m.lock().unwrap().events.len();
    // SAFETY: The fixture keeps published ModelRoute callbacks. Emission is synchronous
    // under its mutex, including failures injected after a modeled hardware effect.
    assert_eq!(unsafe { owner.unmask() }, Err(Error::Mapping));
    assert!(owner.needs_reset());
    assert!(
        !m.lock().unwrap().events[start..]
            .iter()
            .any(|event| matches!(event, Event::BarRead(..) | Event::BarWrite(..)))
    );
}
