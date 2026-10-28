// SPDX-License-Identifier: GPL-2.0-or-later
//! Exclusive native PCI configuration and UC BAR2 attachment for AMD SFHv2.
use super::{Error, REGION_BYTES, Registers};
use crate::bus::{
    mmio::owned::{CacheAttribute, Mapping, Protection},
    pci::{
        Address, Bar, ConfigSpace, Function, capability, owned::OwnedConfig,
        requester::StoppedRequester,
    },
};
/// Rejected attachment returns the exact original owners, without writes.
pub struct AttachFailure {
    pub error: Error,
    pub function: Function<OwnedConfig>,
    pub mapping: Mapping,
}
pub struct NativeRegisters {
    function: Function<OwnedConfig>,
    mapping: Mapping,
    address: Address,
    base: u64,
    wide: bool,
    master: Option<bool>,
    quiescent: bool,
    revision: u8,
}
impl NativeRegisters {
    /// # Safety
    /// `bar` is this function's actually sized/reserved BAR2; `mapping` retains
    /// this same actual exclusive resource/reset/assignment epoch. Numeric span
    /// equality is insufficient. The stopped requester's firmware/IRQ/work and
    /// physical alias exclusion continues until successful explicit shutdown.
    /// No other raw access, cloned view or configuration writer may interfere.
    pub unsafe fn attach(
        mut requester: StoppedRequester,
        mapping: Mapping,
        bar: Bar,
    ) -> Result<Self, AttachFailure> {
        let checked = (|| {
            requester.check_stopped().map_err(|_| Error::PciAuthority)?;
            let Bar::Memory {
                address,
                size,
                wide,
                prefetchable: false,
            } = bar
            else {
                return Err(Error::InvalidBar);
            };
            let span = mapping.physical_span().map_err(|_| Error::InvalidBar)?;
            if address == 0
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
        let revision = function.config().read8(8);
        let (base, wide) = match checked {
            Ok(value) => value,
            Err(error) => {
                return Err(AttachFailure {
                    error,
                    function,
                    mapping,
                });
            }
        };
        let mut owner = Self {
            function,
            mapping,
            address,
            base,
            wide,
            master: Some(false),
            quiescent: true,
            revision,
        };
        if let Err(error) = owner.check_authority() {
            return Err(AttachFailure {
                error,
                function: owner.function,
                mapping: owner.mapping,
            });
        }
        Ok(owner)
    }
    pub fn into_stopped_resources(mut self) -> Result<(Function<OwnedConfig>, Mapping), Self> {
        if !self.quiescent || self.master != Some(false) || self.check_authority().is_err() {
            return Err(self);
        }
        Ok((self.function, self.mapping))
    }
    fn pointer(&self, offset: usize) -> Result<core::ptr::NonNull<u32>, Error> {
        if !offset.is_multiple_of(4) {
            return Err(Error::RegisterUnavailable(offset));
        }
        self.mapping
            .address(offset, 4)
            .map(|p| p.cast())
            .map_err(|_| Error::RegisterUnavailable(offset))
    }
}
impl Registers for NativeRegisters {
    fn check_authority(&mut self) -> Result<(), Error> {
        if self.function.address != self.address || self.function.config().address() != self.address
        {
            return Err(Error::PciAuthority);
        }
        if (self.function.vendor, self.function.device) != (0x1022, 0x15e4) {
            return Err(Error::UnsupportedController);
        }
        let metadata = self.function.class;
        let config = self.function.config();
        let class = config.read32(8);
        if config.read32(0) != 0x15e41022
            || class == u32::MAX
            || class as u8 != self.revision
            || [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8] != metadata
            || config.read8(0x0e) & 0x7f != 0
        {
            return Err(Error::PciAuthority);
        }
        let command = config.read16(4);
        if command == u16::MAX
            || command & 0x402 != 0x402
            || self
                .master
                .is_some_and(|master| (command & 4 != 0) != master)
        {
            return Err(Error::PciAuthority);
        }
        // BAR0/1 may form a 64-bit pair. BAR2 itself begins at 0x18.
        let preceding = config.read32(0x14);
        let first = config.read32(0x10);
        if first & 7 != 4 && preceding & 7 == 4 {
            return Err(Error::InvalidBar);
        }
        let low = config.read32(0x18);
        let high = if self.wide { config.read32(0x1c) } else { 0 };
        if low == u32::MAX
            || low & 15 != if self.wide { 4 } else { 0 }
            || u64::from(low & !15) | (u64::from(high) << 32) != self.base
        {
            return Err(Error::InvalidBar);
        }
        let status = config.read16(6);
        if status == u16::MAX {
            return Err(Error::PciAuthority);
        }
        if !capability::stopped_in_d0(config) {
            return Err(Error::PciAuthority);
        }
        Ok(())
    }
    fn read32(&mut self, offset: usize) -> Result<u32, Error> {
        let pointer = self.pointer(offset)?;
        // SAFETY: retained exclusive native UC BAR2; checked aligned dword span.
        Ok(unsafe { pointer.as_ptr().read_volatile() })
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        let pointer = self.pointer(offset)?;
        self.quiescent = false;
        // SAFETY: same exact exclusive mapping and width, no safe RAM alias.
        unsafe { pointer.as_ptr().write_volatile(value) };
        Ok(())
    }
    fn set_bus_master(&mut self, enabled: bool) -> Result<(), Error> {
        self.check_authority()?;
        let config = self.function.config();
        let previous = config.read16(4);
        let desired = if enabled { previous | 4 } else { previous & !4 };
        self.master = None;
        config.write16(4, desired);
        if config.read16(4) != desired {
            return Err(Error::PciAuthority);
        }
        self.master = Some(enabled);
        Ok(())
    }
    unsafe fn mark_quiescent(&mut self) {
        self.quiescent = true;
    }
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
    const BASE: u64 = 0x1_d000_0000;
    const ADDRESS: Address = Address {
        segment: 0x1234,
        bus: 0xab,
        device: 3,
        function: 5,
    };
    #[repr(align(4096))]
    struct Storage([u8; REGION_BYTES]);
    struct Reservation(Arc<AtomicUsize>);
    // SAFETY: isolated symbolic BAR reservation paired with actual owned CPU RAM.
    unsafe impl ResourceBacking for Reservation {
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
        ram: Box<UnsafeCell<Storage>>,
        request: Mutex<Option<MapRequest>>,
        unmaps: Arc<AtomicUsize>,
    }
    // SAFETY: model storage remains pinned and only exclusive raw accesses occur.
    unsafe impl Send for Platform {}
    // SAFETY: fixture serializes metadata and no safe payload alias escapes.
    unsafe impl Sync for Platform {}
    // SAFETY: exact model resource is backed by owned stable CPU storage, with
    // synchronous serialized install/retirement; no native mapping claim.
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
            // SAFETY: stable Box storage; UnsafeCell permits raw device accesses.
            let cpu_base = unsafe {
                NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.ram.get()).0).cast())
            };
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
    fn mapping() -> (Mapping, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let unmaps = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let platform = Arc::new(Platform {
            ram: Box::new(UnsafeCell::new(Storage([0; REGION_BYTES]))),
            request: Mutex::new(None),
            unmaps: unmaps.clone(),
        });
        // SAFETY: isolated model resource and CPU fixture, no native activation.
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
                Resource::new(Box::new(Reservation(drops.clone()))),
                0,
                REGION_BYTES,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .unwrap();
        (mapping, unmaps, drops)
    }
    fn requester(
        device: u16,
    ) -> (
        StoppedRequester,
        Arc<crate::bus::pci::owned::tests::Counters>,
    ) {
        let (mut config, counters) = fixture(ADDRESS);
        config.write32(0, u32::from(device) << 16 | 0x1022);
        config.write32(8, 0x11800001);
        config.write16(4, 0x402);
        config.write32(0x10, 0);
        config.write32(0x14, 0);
        config.write32(0x18, BASE as u32 | 4);
        config.write32(0x1c, (BASE >> 32) as u32);
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
    #[test]
    fn native_bar2_owner_rechecks_identity_and_failed_drop_quarantines_both_resources() {
        let (requester, config) = requester(0x15e4);
        let (mapping, unmaps, drops) = mapping();
        // SAFETY: exclusive symbolic resource and stopped CPU model match BAR2.
        let mut native = match unsafe { NativeRegisters::attach(requester, mapping, bar()) } {
            Ok(value) => value,
            Err(f) => panic!("attach {:?}", f.error),
        };
        native.set_bus_master(true).unwrap();
        assert_eq!(native.function.config().read16(4), 0x406);
        native.write32(0x10500, 0xc8011011).unwrap();
        assert_eq!(native.read32(0x10500), Ok(0xc8011011));
        native.function.config().write32(0, 0x164a1022);
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
            let (mapping, unmaps, _) = mapping();
            // SAFETY: identity refusal is deliberately exercised on the model.
            let mut failure = match unsafe { NativeRegisters::attach(requester, mapping, bar()) } {
                Err(value) => value,
                Ok(_) => panic!("wrong SFH generation"),
            };
            assert_eq!(failure.error, Error::UnsupportedController);
            assert_eq!(failure.function.config().read16(4), 0x402);
            assert_eq!(unmaps.load(Ordering::Relaxed), 0);
            let mut config = failure.function.into_config().into_mapping();
            // SAFETY: attachment rejected without device accesses; model drained.
            unsafe { failure.mapping.retire() }.unwrap();
            // SAFETY: same model exclusion and final actual config owner.
            unsafe { config.retire() }.unwrap();
            assert_eq!(unmaps.load(Ordering::Relaxed), 1);
        }
    }
}
