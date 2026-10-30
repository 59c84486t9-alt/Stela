//! The owned-configuration model other drivers' tests attach functions to.
extern crate std;
use super::*;
use crate::bus::mmio::owned::{
    AddressSpace, Authority, InstalledMapping, MapFailure, MapRequest, MappingPlatform,
    PhysicalSpan, Resource, ResourceBacking, ResourceKind,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::sync::Mutex;

pub const SPACE: AddressSpace = AddressSpace {
    identity: 19,
    physical_bits: 48,
    virtual_bits: 48,
};
pub const BASE: u64 = 0x8000_0000;
pub const ADDRESS: Address = Address {
    segment: 0x1234,
    bus: 0xab,
    device: 0x1f,
    function: 7,
};

#[derive(Default)]
pub struct Counters {
    pub maps: AtomicUsize,
    pub unmaps: AtomicUsize,
    pub resource_drops: AtomicUsize,
    pub platform_drops: AtomicUsize,
    pub contexts: AtomicUsize,
    pub fail_context_at: AtomicUsize,
    pub fail_after_word: AtomicUsize,
    pub fail_after_value: AtomicUsize,
}

pub struct Backing {
    span: PhysicalSpan,
    kind: ResourceKind,
    counters: Arc<Counters>,
}
// SAFETY: isolated symbolic physical inventory, kept alongside
// owned CPU fixture storage; no hardware or production permission is used.
unsafe impl ResourceBacking for Backing {
    fn physical_span(&self) -> PhysicalSpan {
        self.span
    }
    fn kind(&self) -> ResourceKind {
        self.kind
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        self.counters.resource_drops.fetch_add(1, Ordering::Relaxed);
    }
}

#[repr(align(4096))]
pub struct Pages([u8; 8192]);
pub struct Model {
    memory: Box<UnsafeCell<Pages>>,
    installed: Mutex<Option<MapRequest>>,
    counters: Arc<Counters>,
}
// SAFETY: storage is stable and only accessed through raw volatile pointers;
// the fixture owns a single config handle, and metadata uses the mutex.
unsafe impl Send for Model {}
// SAFETY: no safe references to mutable storage; all mapping metadata is
// locked, and retirement requires the ordinary stopped-consumer contract.
unsafe impl Sync for Model {}
impl Model {
    fn pointer(&self) -> NonNull<u8> {
        // SAFETY: UnsafeCell permits volatile mutation without shared RAM
        // references. Box storage remains alive until acknowledged unmap.
        unsafe {
            NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.memory.get()).0).cast::<u8>())
        }
    }
}
impl Drop for Model {
    fn drop(&mut self) {
        self.counters.platform_drops.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: aligned CPU RAM models exactly the requested
// symbolic device pages. This proves registry/transport lifetimes only,
// not physical ECAM, effective cache attributes or native page tables.
unsafe impl MappingPlatform for Model {
    fn check_context(&self, space: AddressSpace) -> Result<(), MappingError> {
        assert_eq!(space, SPACE);
        let call = self.counters.contexts.fetch_add(1, Ordering::Relaxed) + 1;
        if self.counters.fail_context_at.load(Ordering::Relaxed) == call {
            return Err(MappingError::Unavailable);
        }
        let watched = self.counters.fail_after_word.load(Ordering::Relaxed);
        if watched != 0 {
            let offset = watched - 1;
            assert!(offset <= 8188 && offset.is_multiple_of(4));
            // SAFETY: isolated fixture owns this aligned RAM and
            // all operations are sequential; observe the real store.
            let value = unsafe {
                self.pointer()
                    .as_ptr()
                    .add(offset)
                    .cast::<u32>()
                    .read_volatile()
            };
            if value as usize == self.counters.fail_after_value.load(Ordering::Relaxed) {
                return Err(MappingError::Unavailable);
            }
        }
        Ok(())
    }
    unsafe fn map(
        &self,
        resource: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure> {
        assert!(resource.backing().is::<Backing>());
        let resource_span = resource.physical_span();
        assert!(
            resource_span.start() <= request.physical.start()
                && request.physical.end() <= resource_span.end()
        );
        assert!(request.physical.bytes() <= 8192);
        let mut installed = self.installed.lock().unwrap();
        assert!(installed.is_none());
        *installed = Some(request);
        self.counters.maps.fetch_add(1, Ordering::Relaxed);
        Ok(InstalledMapping {
            token: request.id,
            cpu_base: self.pointer(),
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(
        &self,
        request: MapRequest,
        mapping: InstalledMapping,
    ) -> Result<(), MappingError> {
        assert_eq!(self.installed.lock().unwrap().take(), Some(request));
        assert_eq!(mapping.token, request.id);
        assert_eq!(mapping.cpu_base, self.pointer());
        self.counters.unmaps.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

pub fn window(address: Address) -> EcamWindow {
    EcamWindow {
        base: BASE,
        segment: address.segment,
        start_bus: address.bus,
        end_bus: address.bus,
    }
}
pub fn physical(address: Address) -> u64 {
    BASE + (u64::from(address.bus) << 20)
        + (u64::from(address.device) << 15)
        + (u64::from(address.function) << 12)
}
pub fn mapped(
    span: PhysicalSpan,
    offset: usize,
    bytes: usize,
    attribute: CacheAttribute,
    protection: Protection,
) -> (Mapping, Arc<Counters>) {
    let counters = Arc::new(Counters::default());
    let platform = Arc::new(Model {
        memory: Box::new(UnsafeCell::new(Pages([0; 8192]))),
        installed: Mutex::new(None),
        counters: counters.clone(),
    });
    // SAFETY: independent fixture storage and symbolic resources cannot
    // overlap another model or the production activation inventory.
    let authority = unsafe { Authority::isolated_model(platform, SPACE, Vec::new()) }.unwrap();
    let resource = Resource::new(Box::new(Backing {
        span,
        // WC exists only for the unsuitable-resource case;
        // ordinary ECAM fixtures model conservative register resources.
        kind: if attribute == CacheAttribute::WriteCombining {
            ResourceKind::PrefetchableMemory
        } else {
            ResourceKind::Registers
        },
        counters: counters.clone(),
    }));
    let mapping = authority
        .map(resource, offset, bytes, attribute, protection)
        .unwrap();
    drop(authority);
    (mapping, counters)
}

/// Registry-owned transport fixture for sibling requester tests.
/// Program it through ConfigSpace and explicitly retire its returned mapping.
pub fn fixture(address: Address) -> (OwnedConfig, Arc<Counters>) {
    let span = PhysicalSpan::new(physical(address), FUNCTION_BYTES as u64).unwrap();
    let (mapping, counters) = mapped(
        span,
        0,
        FUNCTION_BYTES,
        CacheAttribute::Uncached,
        Protection::ReadWrite,
    );
    // SAFETY: this fixture owns its storage, exclusive config access
    // and symbolic resource epoch. It grants no production device permission.
    let config = match unsafe { OwnedConfig::attach(address, window(address), mapping) } {
        Ok(config) => config,
        Err((error, _)) => panic!("valid owned fixture: {error:?}"),
    };
    (config, counters)
}

pub fn fixture_pointer(config: &OwnedConfig, offset: u16) -> NonNull<u8> {
    config.try_register(offset).unwrap()
}

pub fn retire(mut mapping: Mapping, counters: &Counters) {
    // SAFETY: each test stopped all synchronous fixture accesses before
    // returning the original mapping; no worker/device can access storage.
    unsafe { mapping.retire() }.unwrap();
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
}
