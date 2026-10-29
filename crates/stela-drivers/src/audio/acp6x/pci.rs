// SPDX-License-Identifier: GPL-2.0-only
//! ACP6x native PCI/UC resource owner; behavior lives in the shared adapter.
//! Copyright (C) 2021 Advanced Micro Devices, Inc. All rights reserved.
pub use super::super::acp_pdm::pci::AttachFailure;
pub type NativeRegisters = super::super::acp_pdm::pci::NativeRegisters<super::YellowCarp>;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{Error, Registers};
    use super::*;
    use crate::bus::{
        mmio::owned::{CacheAttribute, Mapping, Protection},
        pci::{
            Address, Bar, ConfigSpace, Function, owned::OwnedConfig, requester::StoppedRequester,
        },
    };

    use crate::bus::{
        mmio::owned::{
            AddressSpace, Authority, Error as MapError, InstalledMapping, MapFailure, MapRequest,
            MappingPlatform, PhysicalSpan, Resource, ResourceBacking, ResourceKind,
        },
        pci::{owned::tests::fixture, requester::FunctionRole},
    };
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
    struct ResourceOwner;
    // SAFETY: isolated model reservation; symbolic BAR labels are never physical
    // pointers and its CPU storage is held by the mapping platform.
    unsafe impl ResourceBacking for ResourceOwner {
        fn physical_span(&self) -> PhysicalSpan {
            PhysicalSpan::new(BASE, BYTES as u64).unwrap()
        }
        fn kind(&self) -> ResourceKind {
            ResourceKind::Registers
        }
    }
    #[repr(align(4096))]
    struct Storage([u8; BYTES]);
    struct Platform {
        ram: Box<UnsafeCell<Storage>>,
        request: Mutex<Option<MapRequest>>,
        unmaps: Arc<AtomicUsize>,
    }
    // SAFETY: stable model RAM; exclusive raw register owner, mutex metadata.
    unsafe impl Send for Platform {}
    // SAFETY: no safe references into DMA/MMIO-mutated model RAM escape.
    unsafe impl Sync for Platform {}
    impl Platform {
        fn pointer(&self) -> NonNull<u8> {
            // SAFETY: stable Box storage and UnsafeCell permit raw MMIO accesses.
            unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.ram.get()).0).cast()) }
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
    fn mapping() -> (Mapping, Arc<AtomicUsize>) {
        let unmaps = Arc::new(AtomicUsize::new(0));
        let platform = Arc::new(Platform {
            ram: Box::new(UnsafeCell::new(Storage([0; BYTES]))),
            request: Mutex::new(None),
            unmaps: unmaps.clone(),
        });
        // SAFETY: entirely isolated CPU fixture/resources, not native activation.
        let authority = unsafe {
            Authority::isolated_model(
                platform,
                AddressSpace {
                    identity: 99,
                    physical_bits: 48,
                    virtual_bits: 48,
                },
                Vec::new(),
            )
        }
        .unwrap();
        let mapping = authority
            .map(
                Resource::new(Box::new(ResourceOwner)),
                0,
                BYTES,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .unwrap();
        (mapping, unmaps)
    }
    fn stopped() -> StoppedRequester {
        let (mut config, _) = fixture(ADDRESS);
        config.write32(0, 0x15e2_1022);
        config.write32(8, 0x0480_0060);
        config.write16(4, 0x402);
        config.write32(0x10, BASE as u32 | 4);
        config.write32(0x14, (BASE >> 32) as u32);
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
    fn retire(function: Function<OwnedConfig>, mut mapping: Mapping) {
        let mut config_mapping = function.into_config().into_mapping();
        // SAFETY: model owners have been consumed; no device/callback
        // or raw register accesses remain after the asserted stopped state.
        unsafe { mapping.retire() }.unwrap();
        // SAFETY: same final config-owner drain, registry retirement.
        unsafe { config_mapping.retire() }.unwrap();
    }
    #[test]
    fn canonical_stopped_function_and_uc_bar_survive_native_width_dma_gating() {
        let requester = stopped();
        let (mapping, unmaps) = mapping();
        // SAFETY: exact symbolic BAR0 plus canonical stopped fixture.
        let mut registers = match unsafe { NativeRegisters::attach(requester, mapping, bar()) } {
            Ok(registers) => registers,
            Err(failure) => panic!("attachment {:?}", failure.error),
        };
        assert_eq!(registers.identity().unwrap().revision, 0x60);
        assert_eq!(registers.region_bytes(), BYTES);
        registers.set_bus_master(true).unwrap();
        assert_eq!(registers.function.config().read16(4), 0x406);
        // The same config rejects MSI activation without MMIO writes.
        registers.function.config().write16(6, 0x10);
        registers.function.config().write8(0x34, 0x40);
        registers.function.config().write16(0x40, 5);
        registers.function.config().write16(0x42, 1);
        assert_eq!(registers.identity(), Err(Error::PciAuthority));
        registers.function.config().write16(0x42, 0);
        registers.set_bus_master(false).unwrap();
        registers.write32(0x2c04, 1);
        assert_eq!(registers.read32(0x2c04), 1);
        let mut registers = match registers.into_stopped_resources() {
            Err(retained) => retained,
            Ok(_) => panic!("active PDM released"),
        };
        registers.write32(0x2c04, 0);
        registers.write32(0xc04, 0x8380_0000);
        let mut registers = match registers.into_stopped_resources() {
            Err(retained) => retained,
            Ok(_) => panic!("enabled address group released"),
        };
        registers.write32(0xc04, 0);
        // This raw UC RAM fixture supplies unspecified command readback. It is
        // not evidence for a cache ACK or a hardware value.
        registers.write32(0xc40, u32::MAX);
        let (function, mapping) = match registers.into_stopped_resources() {
            Ok(owners) => owners,
            Err(_) => panic!("stopped owners lost"),
        };
        assert_eq!(function.address, ADDRESS);
        assert_eq!(unmaps.load(Ordering::Relaxed), 0);
        retire(function, mapping);
        assert_eq!(unmaps.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn native_attachment_rejection_returns_both_real_mapping_owners() {
        for cause in 0..3 {
            let mut requester = stopped();
            if cause == 2 {
                let mut function = requester.into_function();
                function.config().write32(8, 0x0480_0050);
                // SAFETY: read-only identity update in a drained isolated model.
                requester = match unsafe {
                    StoppedRequester::from_stopped_pci(function, FunctionRole::Physical)
                } {
                    Ok(owner) => owner,
                    Err((error, _)) => panic!("fixture {error:?}"),
                };
            }
            let (mapping, unmaps) = mapping();
            let candidate = if cause == 0 {
                Bar::Io {
                    port: 0x100,
                    size: 0x100,
                }
            } else if cause == 1 {
                Bar::Memory {
                    address: BASE + 4096,
                    size: BYTES as u64,
                    wide: true,
                    prefetchable: false,
                }
            } else {
                bar()
            };
            // SAFETY: invalid association is rejected before writes.
            let mut failure =
                match unsafe { NativeRegisters::attach(requester, mapping, candidate) } {
                    Err(failure) => failure,
                    Ok(_) => panic!("invalid native resource admitted"),
                };
            assert_eq!(
                failure.error,
                if cause == 2 {
                    Error::UnsupportedController
                } else {
                    Error::InvalidBar
                }
            );
            assert_eq!(unmaps.load(Ordering::Relaxed), 0);
            assert_eq!(failure.function.config().read16(4), 0x402);
            retire(failure.function, failure.mapping);
            assert_eq!(unmaps.load(Ordering::Relaxed), 1);
        }
    }
}
