// SPDX-License-Identifier: GPL-2.0-only
//! One stopped-function and UC BAR fixture for every direct PDM profile.
extern crate std;
use super::*;
use crate::bus::{
    mmio::owned::{
        AddressSpace, Authority, Error as MapError, InstalledMapping, MapFailure, MapRequest,
        MappingPlatform, PhysicalSpan, Resource, ResourceBacking, ResourceKind,
    },
    pci::{owned::test_support::fixture, requester::FunctionRole},
};
use crate::{acp6x::YellowCarp, acp63::PinkSardine, acp70::Ps70, renoir::Renoir};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    cell::UnsafeCell,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::sync::Mutex;

const ADDRESS: Address = Address {
    segment: 0x1234,
    bus: 0xab,
    device: 3,
    function: 5,
};
const BASE: u64 = 0x1_d000_0000;
const BYTES: usize = 0x20000;
/// A revision/class dword no direct PDM profile admits.
const UNSUPPORTED: u32 = 0x0480_0050;

struct ResourceOwner {
    mapping: crate::bus::mmio::owned::model::MappingRetention<Arc<ModelRam>>,
}
// SAFETY: isolated model reservation; symbolic BAR labels are never physical
// pointers and its CPU storage is held by the mapping platform.

unsafe impl ResourceBacking for ResourceOwner {
    fn begin_mapping(
        &self,
    ) -> Result<crate::bus::pci::assignment::OpaqueUse, crate::bus::mmio::owned::Error> {
        self.mapping.begin_mapping()
    }

    fn physical_span(&self) -> PhysicalSpan {
        PhysicalSpan::new(BASE, BYTES as u64).unwrap()
    }
    fn kind(&self) -> ResourceKind {
        ResourceKind::Registers
    }
}
#[repr(align(4096))]
struct Storage([u8; BYTES]);
struct ModelRam(UnsafeCell<Storage>);
// SAFETY: actual isolated raw-only RAM; the fixture serializes model users
// and no safe references to mutable register bytes escape.
unsafe impl Send for ModelRam {}
// SAFETY: same exclusive model access contract as Send; no native owner.
unsafe impl Sync for ModelRam {}
impl ModelRam {
    fn pointer(&self) -> NonNull<u8> {
        // SAFETY: this retained UnsafeCell allocation covers exact Storage.
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.0.get()).0).cast()) }
    }
}
struct Platform {
    ram: Arc<ModelRam>,
    request: Mutex<Option<MapRequest>>,
    unmaps: Arc<AtomicUsize>,
}
// SAFETY: stable model RAM; exclusive raw register owner, mutex metadata.
unsafe impl Send for Platform {}
// SAFETY: no safe references into DMA/MMIO-mutated model RAM escape.
unsafe impl Sync for Platform {}
impl Platform {
    fn pointer(&self) -> NonNull<u8> {
        // Same original retained model allocation; only raw register pointers escape.
        self.ram.pointer()
    }
}
// SAFETY: independent model's real CPU storage backs exactly one kept
// symbolic BAR; all publication/retirement is synchronous and serialized.
unsafe impl MappingPlatform for Platform {
    fn check_context(&self, _: AddressSpace) -> Result<(), MapError> {
        Ok(())
    }
    unsafe fn map(
        &self,
        resource: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure> {
        assert!(resource.backing().is::<ResourceOwner>());
        assert_eq!(request.physical, resource.physical_span());
        assert_eq!(request.attribute, CacheAttribute::Uncached);
        assert_eq!(request.protection, Protection::ReadWrite);
        assert!(self.request.lock().unwrap().replace(request).is_none());
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
    crate::bus::mmio::owned::model::MappingOwner<Arc<ModelRam>>,
) {
    let unmaps = Arc::new(AtomicUsize::new(0));
    let platform = Arc::new(Platform {
        ram: Arc::new(ModelRam(UnsafeCell::new(Storage([0; BYTES])))),
        request: Mutex::new(None),
        unmaps: unmaps.clone(),
    });
    // SAFETY: entirely isolated CPU fixture/resources, not native activation.
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
            Resource::new(Box::new(ResourceOwner {
                mapping: mapping_owner.retention().unwrap(),
            })),
            0,
            BYTES,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        )
        .unwrap();
    (mapping, unmaps, mapping_owner)
}

/// A drained ACP function reporting `revision_class` at config offset 8.
fn stopped(revision_class: u32) -> StoppedRequester {
    let (mut config, _) = fixture(ADDRESS);
    config.write32(0, 0x15e2_1022).unwrap();
    config.write32(8, revision_class).unwrap();
    config.write16(4, 0x402).unwrap();
    config.write32(0x10, BASE as u32 | 4).unwrap();
    config.write32(0x14, (BASE >> 32) as u32).unwrap();
    let function = Function::new(ADDRESS, config).unwrap();
    // SAFETY: isolated model has no PF aliases, engines, IRQs or workers.
    match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
        Ok(owner) => owner,
        Err((error, _)) => panic!("stopped fixture {error:?}"),
    }
}

fn bar() -> Bar {
    Bar::Memory {
        address: BASE,
        size: BYTES as u64,
        wide: true,
        prefetchable: false,
    }
}

fn attach<P: Profile>(
    revision_class: u32,
) -> (
    NativeRegisters<P>,
    Arc<AtomicUsize>,
    crate::bus::mmio::owned::model::MappingOwner<Arc<ModelRam>>,
) {
    let (mapping, unmaps, mapping_owner) = mapping();
    // SAFETY: exact symbolic BAR0 plus canonical stopped fixture.
    match unsafe { NativeRegisters::attach(stopped(revision_class), mapping, bar()) } {
        Ok(registers) => (registers, unmaps, mapping_owner),
        Err(failure) => panic!("attachment {:?}", failure.error),
    }
}

/// The owners `into_stopped_resources` keeps while `why` still holds.
fn retained<P: Profile>(registers: NativeRegisters<P>, why: &str) -> NativeRegisters<P> {
    match registers.into_stopped_resources() {
        Err(retained) => retained.owner,
        Ok(_) => panic!("{why} released"),
    }
}

fn retire(
    function: Function<OwnedConfig>,
    mut mapping: Mapping,
    mut mapping_owner: crate::bus::mmio::owned::model::MappingOwner<Arc<ModelRam>>,
) {
    let config = function.into_config();
    // SAFETY: model owners have been consumed; no device/callback
    // or raw register accesses remain after the asserted stopped state.
    unsafe { mapping.retire() }.unwrap();
    // SAFETY: same final config-owner drain, registry retirement.
    unsafe { crate::bus::pci::owned::test_support::retire_owned(config) }.unwrap();
    // SAFETY: both original mappings acknowledged retirement and all raw
    // fixture users ended. No inventory contains this affine controller.
    unsafe { mapping_owner.retire() }.unwrap();
}

/// Release the stopped owners and check both mappings retire exactly once.
fn release<P: Profile>(
    registers: NativeRegisters<P>,
    unmaps: &AtomicUsize,
    mapping_owner: crate::bus::mmio::owned::model::MappingOwner<Arc<ModelRam>>,
) {
    let (function, mapping) = match registers.into_stopped_resources() {
        Ok(owners) => owners,
        Err(_) => panic!("stopped owners lost"),
    };
    assert_eq!(function.address, ADDRESS);
    assert_eq!(unmaps.load(Ordering::Relaxed), 0);
    retire(function, mapping, mapping_owner);
    assert_eq!(unmaps.load(Ordering::Relaxed), 1);
}

fn stopped_function_survives_dma_gating<P: Profile>(revision_class: u32) {
    let (mut registers, unmaps, mapping_owner) = attach::<P>(revision_class);
    assert_eq!(registers.identity().unwrap().revision, revision_class as u8);
    assert_eq!(registers.region_bytes(), BYTES);
    registers.set_bus_master(true).unwrap();
    assert_eq!(registers.function.config().read16(4).unwrap(), 0x406);
    // The same config rejects MSI activation without MMIO writes.
    registers.function.config().write16(6, 0x10).unwrap();
    registers.function.config().write8(0x34, 0x40).unwrap();
    registers.function.config().write16(0x40, 5).unwrap();
    registers.function.config().write16(0x42, 1).unwrap();
    assert_eq!(registers.identity(), Err(Error::PciAuthority));
    registers.function.config().write16(0x42, 0).unwrap();
    registers.set_bus_master(false).unwrap();
    registers.write32(PDM_ENABLE, 1);
    assert_eq!(registers.read32(PDM_ENABLE), 1);
    let mut registers = retained(registers, "active PDM");
    registers.write32(PDM_ENABLE, 0);
    if let Some(zsc) = P::ZSC_CONTROL {
        registers = retained(registers, "unparked ZSC");
        registers.write32(zsc, 1);
    }
    registers.write32(PAGE_BASE, GROUP_ENABLE | P::SRAM_TABLE);
    let mut registers = retained(registers, "enabled address group");
    registers.write32(PAGE_BASE, 0);
    // This raw UC RAM fixture supplies unspecified command readback. It is
    // not evidence for a cache ACK or a hardware value.
    registers.write32(ATU_CONTROL, u32::MAX);
    release(registers, &unmaps, mapping_owner);
}

#[test]
fn canonical_stopped_function_and_uc_bar_survive_native_width_dma_gating() {
    stopped_function_survives_dma_gating::<PinkSardine>(0x0480_0063);
    stopped_function_survives_dma_gating::<Renoir>(0x0480_0001);
    stopped_function_survives_dma_gating::<YellowCarp>(0x0480_0060);
}

fn attachment_rejection_returns_both_owners<P: Profile>(revision_class: u32) {
    let shifted = Bar::Memory {
        address: BASE + 4096,
        size: BYTES as u64,
        wide: true,
        prefetchable: false,
    };
    let io = Bar::Io {
        port: 0x100,
        size: 0x100,
    };
    for (revision_class, candidate, expected) in [
        (revision_class, io, Error::InvalidBar),
        (revision_class, shifted, Error::InvalidBar),
        (UNSUPPORTED, bar(), Error::UnsupportedController),
    ] {
        let (mapping, unmaps, mapping_owner) = mapping();
        // SAFETY: invalid association is rejected before writes.
        let mut failure = match unsafe {
            NativeRegisters::<P>::attach(stopped(revision_class), mapping, candidate)
        } {
            Err(failure) => failure,
            Ok(_) => panic!("invalid native resource admitted"),
        };
        assert_eq!(failure.error, expected);
        assert_eq!(unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(failure.function.config().read16(4).unwrap(), 0x402);
        retire(failure.function, failure.mapping, mapping_owner);
        assert_eq!(unmaps.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn native_attachment_rejection_returns_both_real_mapping_owners() {
    attachment_rejection_returns_both_owners::<PinkSardine>(0x0480_0063);
    attachment_rejection_returns_both_owners::<Renoir>(0x0480_0001);
    attachment_rejection_returns_both_owners::<YellowCarp>(0x0480_0060);
    attachment_rejection_returns_both_owners::<Ps70>(0x0480_0070);
}

/// Each `(revision_class, error)` fails before any MMIO or config mutation.
fn admission_refuses<P: Profile>(cases: &[(u32, Error)]) {
    for &(revision_class, expected) in cases {
        let (mapping, unmaps, mapping_owner) = mapping();
        // SAFETY: valid reservation, unsupported native class/revision.
        let mut failure = match unsafe {
            NativeRegisters::<P>::attach(stopped(revision_class), mapping, bar())
        } {
            Err(failure) => failure,
            Ok(_) => panic!("{revision_class:#x} admitted"),
        };
        assert_eq!(failure.error, expected, "{revision_class:#x}");
        assert_eq!(failure.function.config().read16(4).unwrap(), 0x402);
        assert_eq!(unmaps.load(Ordering::Relaxed), 0);
        retire(failure.function, failure.mapping, mapping_owner);
        assert_eq!(unmaps.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn native_class_revision_and_containment_are_admission_boundaries() {
    use Error::{PciAuthority, UnsupportedController};
    admission_refuses::<PinkSardine>(&[
        (0x0480_0000, UnsupportedController),
        (0x0480_0060, UnsupportedController),
        (0x0401_0063, PciAuthority),
        (0x0480_0163, PciAuthority),
    ]);
    admission_refuses::<Renoir>(&[
        (0x0480_0000, UnsupportedController),
        (0x0480_0060, UnsupportedController),
        (0x0401_0001, PciAuthority),
        (0x0480_0101, PciAuthority),
    ]);
    // ACP70 admits its exact class and three revisions, not an ACP family table.
    admission_refuses::<Ps70>(&[
        (0x0480_0063, UnsupportedController),
        (0x0480_007d, UnsupportedController),
        (0x0480_007e, UnsupportedController),
        (0x0480_007f, UnsupportedController),
        (0x0401_0070, PciAuthority),
        (0x0480_0171, PciAuthority),
    ]);
}

#[test]
fn acp70_native_parked_control_and_soundwire_exclusion_guard_resource_return() {
    for revision in 0x70..=0x72 {
        let (mut registers, unmaps, mapping_owner) = attach::<Ps70>(0x0480_0000 | revision);
        registers.write32(CONTROL, 1);
        let mut registers = retained(registers, "unparked ACP70 ZSC");
        registers.write32(Ps70::ZSC_CONTROL.unwrap(), 1);
        registers.write32(0x1460, 1);
        let mut registers = retained(registers, "wake-enabled SoundWire owner");
        registers.write32(0x1460, 0);
        registers.set_bus_master(true).unwrap();
        let mut registers = retained(registers, "bus-mastering function");
        registers.set_bus_master(false).unwrap();
        registers.write32(PAGE_BASE, GROUP_ENABLE | Ps70::SRAM_TABLE);
        let mut registers = retained(registers, "enabled ACP70 address group");
        registers.write32(PAGE_BASE, 0);
        registers.write32(ATU_CONTROL, u32::MAX);
        release(registers, &unmaps, mapping_owner);
    }
}
