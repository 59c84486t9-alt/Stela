// SPDX-License-Identifier: GPL-2.0-only
//! ACP6x adapter over the canonical stopped PCI function and owned UC mapping.
//! AMD identity/register facts: Linux sound/soc/amd/yc at a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright (C) 2021 Advanced Micro Devices, Inc. All rights reserved.
use super::{Error, Identity, Registers, registers::*};
use crate::bus::{
    mmio::owned::{CacheAttribute, Mapping, Protection},
    pci::{Address, Bar, ConfigSpace, Function, owned::OwnedConfig, requester::StoppedRequester},
};

/// Failure preserves both original native resource owners for retirement or
/// retry. No PCI/MMIO write occurs on attachment rejection.
pub struct AttachFailure {
    pub error: Error,
    pub function: Function<OwnedConfig>,
    pub mapping: Mapping,
}

/// Owns actual ECAM/configuration and UC/RW BAR0 resource leases. No raw PA or
/// generic physical map is accepted, and no mutable function accessor escapes.
pub struct NativeRegisters {
    function: Function<OwnedConfig>,
    mapping: Mapping,
    address: Address,
    identity: Identity,
    base: u64,
    wide: bool,
    master: Option<bool>,
}
impl NativeRegisters {
    /// Associate the original stopped owner and a real native BAR0 mapping.
    ///
    /// # Safety
    /// `bar` is this exact function's fully sized/reserved BAR0 in the retained
    /// assignment epoch. The mapping's real ResourceBacking reserves that BAR
    /// for this function (numeric equality alone is insufficient). The original
    /// stopped producer's engine/IRQ/work/firmware exclusion remains in force.
    /// The platform has selected direct ACP ownership and qualified WB capture
    /// DMA coherency; attachment does not infer either from PCI or pin mode.
    /// No cloned view/raw pointer or other owner accesses these mappings.
    /// Keep the native owners retained until controller shutdown succeeds.
    pub unsafe fn attach(
        mut requester: StoppedRequester,
        mapping: Mapping,
        bar: Bar,
    ) -> Result<Self, AttachFailure> {
        let result = (|| {
            requester.check_stopped().map_err(|_| Error::PciAuthority)?;
            let Bar::Memory {
                address,
                size,
                wide,
                ..
            } = bar
            else {
                return Err(Error::InvalidBar);
            };
            let span = mapping.physical_span().map_err(|_| Error::InvalidBar)?;
            if address == 0
                || !address.is_multiple_of(4096)
                || size < REGION_BYTES as u64
                || !size.is_power_of_two()
                || !address.is_multiple_of(size)
                || address.checked_add(size).is_none()
                || span.start() != address
                || span.bytes() != size
                || mapping.bytes().map_err(|_| Error::InvalidBar)? as u64 != size
                || mapping.attribute().map_err(|_| Error::InvalidBar)? != CacheAttribute::Uncached
                || mapping.protection().map_err(|_| Error::InvalidBar)? != Protection::ReadWrite
                || !(mapping
                    .address(0, 4)
                    .map_err(|_| Error::InvalidBar)?
                    .as_ptr() as usize)
                    .is_multiple_of(4)
            {
                return Err(Error::InvalidBar);
            }
            Ok((address, wide))
        })();
        let address = requester.address();
        let mut function = requester.into_function();
        let (base, wide) = match result {
            Ok(parts) => parts,
            Err(error) => {
                return Err(AttachFailure {
                    error,
                    function,
                    mapping,
                });
            }
        };
        let result = pci_identity(&mut function, address, base, wide, Some(false));
        let identity = match result {
            Ok(identity) if identity.supported() => identity,
            result => {
                let error = result.err().unwrap_or(Error::UnsupportedController);
                return Err(AttachFailure {
                    error,
                    function,
                    mapping,
                });
            }
        };
        Ok(Self {
            function,
            mapping,
            address,
            identity,
            base,
            wide,
            master: Some(false),
        })
    }
    fn associated(&mut self) -> Result<Identity, Error> {
        let identity = pci_identity(
            &mut self.function,
            self.address,
            self.base,
            self.wide,
            self.master,
        )?;
        if identity != self.identity {
            return Err(Error::PciAuthority);
        }
        Ok(identity)
    }
    /// Return exact native owners only after the controller acknowledged its
    /// shutdown and removed DMA. Failure retains this register provider intact.
    pub fn into_stopped_resources(mut self) -> Result<(Function<OwnedConfig>, Mapping), Self> {
        if self.associated().is_err()
            || self.master != Some(false)
            || self.read32(DMA_ENABLE) != 0
            || self.read32(PDM_ENABLE) != 0
            || self.read32(CONTROL) != 0
        {
            return Err(self);
        }
        Ok((self.function, self.mapping))
    }
}
impl Registers for NativeRegisters {
    fn region_bytes(&self) -> usize {
        self.mapping.bytes().unwrap_or(0)
    }
    fn identity(&mut self) -> Result<Identity, Error> {
        self.associated()
    }
    fn set_bus_master(&mut self, enabled: bool) -> Result<(), Error> {
        self.associated()?;
        let config = self.function.config();
        let previous = config.read16(4);
        let desired = if enabled { previous | 4 } else { previous & !4 };
        // Native word store preserves adjacent PCI W1C status.
        self.master = None;
        config.write16(4, desired);
        if config.read16(4) != desired {
            return Err(Error::PciAuthority);
        }
        self.master = Some(enabled);
        Ok(())
    }
    fn read32(&mut self, offset: usize) -> u32 {
        if !offset.is_multiple_of(4) {
            return u32::MAX;
        }
        let Ok(pointer) = self.mapping.address(offset, 4) else {
            return u32::MAX;
        };
        // SAFETY: checked native UC mapping, exclusive retained ACP function,
        // natural alignment and the device's actual 32-bit register width.
        unsafe { pointer.as_ptr().cast::<u32>().read_volatile() }
    }
    fn write32(&mut self, offset: usize, value: u32) {
        if !offset.is_multiple_of(4) {
            return;
        }
        let Ok(pointer) = self.mapping.address(offset, 4) else {
            return;
        };
        // SAFETY: same owned native register mapping and access width.
        unsafe { pointer.as_ptr().cast::<u32>().write_volatile(value) };
    }
}

fn pci_identity<C: ConfigSpace>(
    function: &mut Function<C>,
    address: Address,
    base: u64,
    wide: bool,
    master: Option<bool>,
) -> Result<Identity, Error> {
    if function.address != address {
        return Err(Error::PciAuthority);
    }
    let metadata = (function.vendor, function.device, function.class);
    let config = function.config();
    let id = config.read32(0);
    let revision_class = config.read32(8);
    if id == u32::MAX
        || (id as u16, (id >> 16) as u16) != (metadata.0, metadata.1)
        || [
            (revision_class >> 24) as u8,
            (revision_class >> 16) as u8,
            (revision_class >> 8) as u8,
        ] != metadata.2
        || revision_class == u32::MAX
        || config.read8(0x0e) & 0x7f != 0
    {
        return Err(Error::PciAuthority);
    }
    let identity = Identity {
        vendor: id as u16,
        device: (id >> 16) as u16,
        revision: revision_class as u8,
    };
    let command = config.read16(4);
    let status = config.read16(6);
    // INTx disabled; memory decode enabled by the platform. No PCI power
    // transition, BAR assignment or interrupt route is guessed here.
    if command == u16::MAX
        || status == u16::MAX
        || command & 0x402 != 0x402
        || master.is_some_and(|expected| (command & 4 != 0) != expected)
    {
        return Err(Error::PciAuthority);
    }
    let low = config.read32(0x10);
    if low == u32::MAX || low & 7 != if wide { 4 } else { 0 } {
        return Err(Error::InvalidBar);
    }
    let high = if wide { config.read32(0x14) } else { 0 };
    if u64::from(low & !15) | (u64::from(high) << 32) != base {
        return Err(Error::InvalidBar);
    }
    if status & 0x10 != 0 {
        let mut offset = u16::from(config.read8(0x34));
        let mut seen = [false; 64];
        while offset != 0 {
            if !(0x40..=0xfc).contains(&offset)
                || !offset.is_multiple_of(4)
                || seen[usize::from(offset / 4)]
            {
                return Err(Error::PciAuthority);
            }
            seen[usize::from(offset / 4)] = true;
            let control = config.read16(offset + 2);
            if control == u16::MAX {
                return Err(Error::PciAuthority);
            }
            match config.read8(offset) {
                1 if offset > 0xf8 || config.read16(offset + 4) & 3 != 0 => {
                    return Err(Error::PciAuthority);
                }
                5 if control & 1 != 0 => return Err(Error::PciAuthority),
                0x11 if control & 0x8000 != 0 => return Err(Error::PciAuthority),
                _ => (),
            }
            offset = u16::from(config.read8(offset + 1));
        }
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
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
    // pointers and its actual CPU storage is retained by the mapping platform.
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
    // SAFETY: independent model's real CPU storage backs exactly one retained
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
        // SAFETY: actual model owners have been consumed; no device/callback
        // or raw register accesses remain after the asserted stopped state.
        unsafe { mapping.retire() }.unwrap();
        // SAFETY: same final config-owner drain, actual registry retirement.
        unsafe { config_mapping.retire() }.unwrap();
    }
    #[test]
    fn canonical_stopped_function_and_uc_bar_survive_native_width_dma_gating() {
        let requester = stopped();
        let (mapping, unmaps) = mapping();
        // SAFETY: exact retained symbolic BAR0 plus canonical stopped fixture.
        let mut registers = match unsafe { NativeRegisters::attach(requester, mapping, bar()) } {
            Ok(registers) => registers,
            Err(failure) => panic!("attachment {:?}", failure.error),
        };
        assert_eq!(registers.identity().unwrap().revision, 0x60);
        assert_eq!(registers.region_bytes(), BYTES);
        registers.set_bus_master(true).unwrap();
        assert_eq!(registers.function.config().read16(4), 0x406);
        // The same actual config rejects MSI activation without MMIO writes.
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
            // SAFETY: invalid association is deliberately rejected before writes.
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
