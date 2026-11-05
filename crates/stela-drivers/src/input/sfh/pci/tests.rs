// SPDX-License-Identifier: GPL-2.0-or-later
extern crate std;
use super::*;
use crate::bus::{
    mmio::owned::{
        AddressSpace, Authority, Error as MapError, InstalledMapping, MapFailure, MapRequest,
        MappingPlatform, PhysicalSpan, Resource, ResourceBacking, ResourceKind,
    },
    pci::{owned::test_support::fixture, requester::FunctionRole},
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::sync::Mutex;
const BASE: u64 = 0x1_d000_0000;
const ADDRESS: Address = Address {
    segment: 0x1234,
    bus: 0xab,
    device: 3,
    function: 5,
};
#[repr(align(4096))]
struct Storage([u8; REGION_BYTES]);
struct ModelRam(UnsafeCell<Storage>);
// SAFETY: actual isolated raw RAM, serialized fixture users, no safe views.
unsafe impl Send for ModelRam {}
// SAFETY: same exclusive hosted-memory contract as Send, no native actor.
unsafe impl Sync for ModelRam {}
impl ModelRam {
    fn pointer(&self) -> NonNull<u8> {
        // SAFETY: retained exact UnsafeCell allocation, never a PA cast.
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.0.get()).0).cast()) }
    }
}
struct Reservation(
    Arc<AtomicUsize>,
    crate::bus::mmio::owned::model::MappingRetention<Arc<ModelRam>>,
);
// SAFETY: isolated symbolic BAR reservation paired with owned CPU RAM.
unsafe impl ResourceBacking for Reservation {
    fn begin_mapping(
        &self,
    ) -> Result<crate::bus::pci::assignment::OpaqueUse, crate::bus::mmio::owned::Error> {
        self.1.begin_mapping()
    }

    fn physical_span(&self) -> PhysicalSpan {
        PhysicalSpan::new(BASE, REGION_BYTES as u64).unwrap()
    }
    fn kind(&self) -> ResourceKind {
        ResourceKind::Registers
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
struct Platform {
    ram: Arc<ModelRam>,
    request: Mutex<Option<MapRequest>>,
    unmaps: Arc<AtomicUsize>,
}
// SAFETY: model storage remains pinned and only exclusive raw accesses occur.
unsafe impl Send for Platform {}
// SAFETY: fixture serializes metadata and no safe payload alias escapes.
unsafe impl Sync for Platform {}
// SAFETY: model resource is backed by owned stable CPU storage, with
// synchronous serialized install/retirement.
unsafe impl MappingPlatform for Platform {
    fn check_context(&self, _: AddressSpace) -> Result<(), MapError> {
        Ok(())
    }
    unsafe fn map(
        &self,
        resource: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure> {
        assert!(resource.backing().is::<Reservation>());
        assert_eq!(request.physical, resource.physical_span());
        assert!(self.request.lock().unwrap().replace(request).is_none());
        // SAFETY: same retained model allocation; UnsafeCell permits raw device accesses.
        let cpu_base = self.ram.pointer();
        Ok(InstalledMapping {
            token: request.id,
            cpu_base,
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(
        &self,
        request: MapRequest,
        installed: InstalledMapping,
    ) -> Result<(), MapError> {
        assert_eq!(self.request.lock().unwrap().take(), Some(request));
        assert_eq!(installed.token, request.id);
        self.unmaps.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
fn mapping() -> (
    Mapping,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    crate::bus::mmio::owned::model::MappingOwner<Arc<ModelRam>>,
) {
    let unmaps = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let platform = Arc::new(Platform {
        ram: Arc::new(ModelRam(UnsafeCell::new(Storage([0; REGION_BYTES])))),
        request: Mutex::new(None),
        unmaps: unmaps.clone(),
    });
    // SAFETY: isolated model resource and CPU fixture, no native activation.
    let authority = unsafe {
        Authority::isolated_model(
            platform.clone(),
            AddressSpace {
                identity: 99,
                physical_bits: 48,
                virtual_bits: 48,
            },
            Vec::new(),
        )
    }
    .unwrap();
    // SAFETY: the same isolated provider owns this exact aligned RAM;
    // all host threads are allowed, with exclusive raw model access.
    let mapping_owner = unsafe {
        crate::bus::mmio::owned::model::MappingOwner::from_owned(platform.ram.clone(), |owner| {
            if (owner.pointer().as_ptr() as usize).is_multiple_of(4096) {
                Ok(())
            } else {
                Err(crate::bus::pci::assignment::Error::Context)
            }
        })
    };
    let mapping = authority
        .map(
            Resource::new(Box::new(Reservation(
                drops.clone(),
                mapping_owner.retention().unwrap(),
            ))),
            0,
            REGION_BYTES,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    (mapping, unmaps, drops, mapping_owner)
}
fn requester(
    device: u16,
) -> (
    StoppedRequester,
    Arc<crate::bus::pci::owned::test_support::Counters>,
) {
    let (mut config, counters) = fixture(ADDRESS);
    config.write32(0, u32::from(device) << 16 | 0x1022).unwrap();
    config.write32(8, 0x11800001).unwrap();
    config.write16(4, 0x402).unwrap();
    config.write32(0x10, 0).unwrap();
    config.write32(0x14, 0).unwrap();
    config.write32(0x18, BASE as u32 | 4).unwrap();
    config.write32(0x1c, (BASE >> 32) as u32).unwrap();
    let function = Function::new(ADDRESS, config).unwrap();
    // SAFETY: isolated model has no active engines, aliases, IRQ or workers.
    let requester =
        match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
            Ok(value) => value,
            Err((error, _)) => panic!("requester {error:?}"),
        };
    (requester, counters)
}
fn bar() -> Bar {
    Bar::Memory {
        address: BASE,
        size: REGION_BYTES as u64,
        prefetchable: false,
        wide: true,
    }
}
struct OriginalRoot(Arc<AtomicUsize>);
impl Drop for OriginalRoot {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: isolated original-root peer; any attempted bind/drain is a test
// failure because no historical notification/root owner was supplied.
unsafe impl crate::bus::pci::requester::preparation::Root for OriginalRoot {
    fn drain(&self) -> Result<(), crate::bus::dma::mapping::DmaError> {
        panic!("no root receipt")
    }
    unsafe fn bind(
        &self,
        _: crate::bus::pci::requester::RequesterBinding,
    ) -> Result<
        Box<dyn crate::bus::pci::requester::preparation::AttachmentBackend>,
        crate::bus::dma::mapping::DmaError,
    > {
        panic!("no private root before independent prerequisites")
    }
}
#[test]
fn original_cold_graph_retains_actual_config_pin_root_and_bar_on_failure_or_active_drop() {
    use crate::bus::pci::requester::preparation::PreparingRequester;
    for prepare in [false, true] {
        let (requester, config) = requester(0x15e4);
        let (mapping, unmaps, drops, _mapping_owner) = mapping();
        let roots = Arc::new(AtomicUsize::new(0));
        // SAFETY: explicit isolated original ownership peer, no native use.
        let requester = match unsafe {
            PreparingRequester::new(
                requester.into_function(),
                FunctionRole::Physical,
                Box::new(OriginalRoot(roots.clone())),
            )
        } {
            Ok(r) => r,
            Err(_) => panic!("model original requester"),
        };
        // SAFETY: same original actual model config/BAR/root graph.
        let mut original = unsafe {
            super::super::cold::native::Original::new(
                requester,
                mapping,
                bar(),
                crate::Clock {
                    ticks_per_microsecond: 1000,
                },
            )
        };
        if prepare {
            // Zeroed ACS is an actual BAR read and rejects the dialect;
            // the whole graph remains with the one-shot attempt.
            let first = original.prepare().unwrap_err();
            assert_eq!(
                first,
                super::super::cold::Error::Controller(Error::UnsupportedDialect(0))
            );
            assert_eq!(original.prepare(), Err(first));
        }
        drop(original);
        assert_eq!(roots.load(Ordering::Relaxed), 0);
        assert_eq!(unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(config.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(config.resource_drops.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn native_bar2_owner_rechecks_identity_and_failed_drop_quarantines_both_resources() {
    let (requester, config) = requester(0x15e4);
    let (mapping, unmaps, drops, _mapping_owner) = mapping();
    // SAFETY: exclusive symbolic resource and stopped CPU model match BAR2.
    let mut native = match unsafe { NativeRegisters::attach(requester, mapping, bar()) } {
        Ok(value) => value,
        Err(f) => panic!("attach {:?}", f.error),
    };
    native.set_bus_master(true).unwrap();
    assert_eq!(native.function.config().read16(4).unwrap(), 0x406);
    native.write32(0x10500, 0xc8011011).unwrap();
    assert_eq!(native.read32(0x10500), Ok(0xc8011011));
    native.function.config().write32(0, 0x164a1022).unwrap();
    assert_eq!(native.check_authority(), Err(Error::PciAuthority));
    drop(native);
    assert_eq!(unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(config.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(config.resource_drops.load(Ordering::Relaxed), 0);
}
#[test]
fn native_wrong_generation_returns_unmodified_real_owners() {
    for device in [0x15e6, 0x164a] {
        let (requester, _) = requester(device);
        let (mapping, unmaps, _, mut mapping_owner) = mapping();
        // SAFETY: identity refusal is exercised on the model.
        let mut failure = match unsafe { NativeRegisters::attach(requester, mapping, bar()) } {
            Err(value) => value,
            Ok(_) => panic!("wrong SFH generation"),
        };
        assert_eq!(failure.error, Error::UnsupportedController);
        assert_eq!(failure.function.config().read16(4).unwrap(), 0x402);
        assert_eq!(unmaps.load(Ordering::Relaxed), 0);
        let config = failure.function.into_config();
        // SAFETY: attachment rejected without device accesses; model drained.
        unsafe { failure.mapping.retire() }.unwrap();
        // SAFETY: same model exclusion and final config owner.
        unsafe { crate::bus::pci::owned::test_support::retire_owned(config) }.unwrap();
        // SAFETY: returned BAR/config mappings both acknowledged final
        // retirement; original fixture raw users are stopped.
        unsafe { mapping_owner.retire() }.unwrap();
        assert_eq!(unmaps.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn resource_return_denial_retains_exact_cause_and_original_graph() {
    let (requester, config) = requester(0x15e4);
    let (mapping, unmaps, drops, _mapping_owner) = mapping();
    // SAFETY: this model owns the same symbolic BAR2 and stopped function.
    let native = match unsafe { NativeRegisters::attach(requester, mapping, bar()) } {
        Ok(native) => native,
        Err(failure) => panic!("attach {:?}", failure.error),
    };
    let denied = config.contexts.load(Ordering::Relaxed) + 1;
    config.fail_context_at.store(denied, Ordering::Relaxed);
    let failure = match native.into_stopped_resources() {
        Err(failure) => failure,
        Ok(_) => panic!("denied source access cannot return original resources"),
    };
    assert_eq!(
        failure.error,
        Error::Config(crate::bus::pci::ConfigError::before_effect(
            crate::bus::pci::ConfigFailure::Mapping(MapError::Unavailable),
        ))
    );
    assert_eq!(config.contexts.load(Ordering::Relaxed), denied);
    assert_eq!(failure.owner.address, ADDRESS);
    drop(failure);
    assert_eq!(unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(config.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(config.resource_drops.load(Ordering::Relaxed), 0);
}
