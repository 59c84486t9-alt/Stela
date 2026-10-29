// SPDX-License-Identifier: GPL-2.0-only
//! Native ACP3x/5x serial-I2S PCI function and kept UC BAR0 ownership.
//! Copyright (C) 2016, 2021, 2023 Advanced Micro Devices, Inc.
use super::{Error, Generation, Identity, PORTS, Registers, registers::*};
use crate::bus::{
    mmio::owned::{CacheAttribute, Mapping, Protection},
    pci::{
        Address, Bar, ConfigSpace, Function, capability, owned::OwnedConfig,
        requester::StoppedRequester,
    },
};

/// Failure preserves both original native resource owners for retirement or
/// retry. No PCI/MMIO write occurs on attachment rejection.
pub struct AttachFailure {
    pub error: Error,
    pub function: Function<OwnedConfig>,
    pub mapping: Mapping,
}

/// Owns ECAM/configuration and UC/RW BAR0 resource leases. No raw PA or
/// generic physical map is accepted, and no mutable function accessor escapes.
pub struct NativeRegisters {
    generation: Generation,
    pub(in crate::audio) function: Function<OwnedConfig>,
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
    /// `bar` is this exact function's fully sized/reserved BAR0 in the kept
    /// assignment epoch. The mapping's real ResourceBacking reserves that BAR
    /// for this function (numeric equality alone is insufficient). The original
    /// stopped producer's engine/IRQ/work/firmware exclusion remains in force.
    /// The platform has selected direct serial-I2S ownership and checked WB
    /// DMA coherency; attachment does not infer board clocks/codecs from PCI.
    /// No cloned view/raw pointer or other owner accesses these mappings.
    /// Keep the native owners kept until controller shutdown succeeds.
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
            Ok(identity) if Generation::identify(identity).is_ok() => identity,
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
            generation: Generation::identify(identity).unwrap(),
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
    /// Return native owners only after the controller acknowledged its
    /// shutdown and removed DMA. Failure keeps this register provider intact.
    pub fn into_stopped_resources(mut self) -> Result<(Function<OwnedConfig>, Mapping), Self> {
        if self.associated().is_err()
            || self.master != Some(false)
            || self.read32(PAGE_BASE) & PTE_VALID != 0
            || self.read32(IRQ_ENABLE) != 0
            || self.read32(IRQ_CONTROL) != 0
            || self.read32(RESET) != 0
            || (self.generation == Generation::Vangogh
                && (self.read32(CONTROL) != 0 || self.read32(CLOCK) != 0))
        {
            return Err(self);
        }
        for port in PORTS {
            let regs = self.generation.stream(port);
            if self.read32(regs.enable) & STREAM_ENABLE != 0 || self.read32(regs.ier) != 0 {
                return Err(self);
            }
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
        self.master = None;
        if !self.function.set_bus_master(enabled) {
            return Err(Error::PciAuthority);
        }
        self.master = Some(enabled);
        Ok(())
    }
    /// An unmapped or misaligned register reads as all ones and ignores writes.
    fn read32(&mut self, offset: usize) -> u32 {
        self.mapping.read32(offset).unwrap_or(u32::MAX)
    }
    fn write32(&mut self, offset: usize, value: u32) {
        let _ = self.mapping.write32(offset, value);
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
        || metadata.2 != [4, 0x80, 0]
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
    if !capability::stopped_in_d0(config) {
        return Err(Error::PciAuthority);
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{Error, Registers};
    use super::*;
    use crate::bus::{
        mmio::owned::{
            AddressSpace, Authority, Error as MapError, InstalledMapping, MapFailure, MapRequest,
            MappingPlatform, PhysicalSpan, Resource, ResourceBacking, ResourceKind,
        },
        pci::{owned::tests::fixture, requester::FunctionRole},
    };
    use crate::bus::{
        mmio::owned::{CacheAttribute, Mapping, Protection},
        pci::{
            Address, Bar, ConfigSpace, Function, owned::OwnedConfig, requester::StoppedRequester,
        },
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
    fn stopped(revision: u8) -> StoppedRequester {
        let (mut config, _) = fixture(ADDRESS);
        config.write32(0, 0x15e2_1022);
        config.write32(8, 0x0480_0000 | u32::from(revision));
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

    // Authored SOURCE ONLY; parent owns finite native driver gate execution.
    #[test]
    fn actual_native_uc_function_and_all_serial_engines_gate_owner_return() {
        for revision in [0, 0x50] {
            let (mapping, unmaps) = mapping();
            // SAFETY: isolated canonical function and reserved UC BAR fixture.
            let mut registers =
                match unsafe { NativeRegisters::attach(stopped(revision), mapping, bar()) } {
                    Ok(owner) => owner,
                    Err(failure) => panic!("attach {:?}", failure.error),
                };
            let generation = if revision == 0 {
                super::super::Generation::Raven
            } else {
                super::super::Generation::Vangogh
            };
            for port in super::super::PORTS {
                let engine = generation.stream(port).enable;
                registers.write32(engine, 1);
                registers = match registers.into_stopped_resources() {
                    Err(owner) => owner,
                    Ok(_) => panic!("active serial stream released"),
                };
                registers.write32(engine, 0);
            }
            registers.write32(0xc04, 0x8205_0000);
            registers = match registers.into_stopped_resources() {
                Err(owner) => owner,
                Ok(_) => panic!("enabled address group released"),
            };
            registers.write32(0xc04, 0);
            registers.set_bus_master(true).unwrap();
            registers = match registers.into_stopped_resources() {
                Err(owner) => owner,
                Ok(_) => panic!("BME owner released"),
            };
            registers.set_bus_master(false).unwrap();
            let (function, mapping) = match registers.into_stopped_resources() {
                Ok(owners) => owners,
                Err(_) => panic!("stopped real owner lost"),
            };
            assert_eq!(function.address, ADDRESS);
            assert_eq!(unmaps.load(Ordering::Relaxed), 0);
            retire(function, mapping);
            assert_eq!(unmaps.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn native_identity_bar_irq_and_generation_failures_retain_both_actual_owners() {
        for fault in 0..4 {
            let mut requester = stopped(0x50);
            if fault == 0 {
                let mut function = requester.into_function();
                function.config().write32(8, 0x0480_0060);
                let config = function.into_config();
                let function = Function::new(ADDRESS, config).unwrap();
                // SAFETY: same isolated stopped fixture with fresh unsupported metadata.
                requester = match unsafe {
                    StoppedRequester::from_stopped_pci(function, FunctionRole::Physical)
                } {
                    Ok(owner) => owner,
                    Err((error, _)) => panic!("fixture {error:?}"),
                };
            }
            let (mapping, unmaps) = mapping();
            let candidate = if fault == 1 {
                Bar::Memory {
                    address: BASE + 4096,
                    size: BYTES as u64,
                    wide: true,
                    prefetchable: false,
                }
            } else {
                bar()
            };
            // SAFETY: isolated native owners; malformed metadata/BAR
            // associations are rejected before any hardware write.
            let mut registers =
                match unsafe { NativeRegisters::attach(requester, mapping, candidate) } {
                    Err(failure) => {
                        assert!(fault <= 1);
                        assert_eq!(unmaps.load(Ordering::Relaxed), 0);
                        retire(failure.function, failure.mapping);
                        continue;
                    }
                    Ok(owner) => owner,
                };
            if fault == 2 {
                registers.function.config().write16(4, 0x2);
            } else {
                registers.function.config().write16(6, 0x10);
                registers.function.config().write8(0x34, 0x40);
                registers.function.config().write16(0x40, 5);
                registers.function.config().write16(0x42, 1);
            }
            assert_eq!(registers.identity(), Err(Error::PciAuthority));
            registers.function.config().write16(4, 0x402);
            registers.function.config().write16(6, 0);
            let (function, mapping) = match registers.into_stopped_resources() {
                Ok(owners) => owners,
                Err(_) => panic!("repaired fixture could not retire"),
            };
            assert_eq!(unmaps.load(Ordering::Relaxed), 0);
            retire(function, mapping);
            assert_eq!(unmaps.load(Ordering::Relaxed), 1);
        }
    }
}
