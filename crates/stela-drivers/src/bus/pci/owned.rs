//! One exclusively owned ECAM function, retained through the native mapping
//! registry. Numeric MCFG geometry is checked here; actual device/resource and
//! configuration-writer exclusion come from the producer's attachment grant.
use super::{Address, ConfigSpace, EcamWindow, msi::MsiConfigSpace};
use crate::bus::mmio::owned::{
    CacheAttribute, Error as MappingError, Mapping, MappingView, Protection,
};
use core::{mem::size_of, ptr::NonNull};

const FUNCTION_BYTES: usize = 4096;
const BUS_SHIFT: u32 = 20;
const DEVICE_SHIFT: u32 = 15;
const FUNCTION_SHIFT: u32 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    Window,
    Address,
    PhysicalSpan,
    CacheAttribute,
    Protection,
    CpuAddress,
    Access { offset: u16, width: usize },
    Mapping(MappingError),
}

/// Retains the real resource, installed native mapping and address-space owner.
/// No clone or raw configuration view is exposed. Final mapping retirement is
/// explicit, after consuming this owner and draining all configuration access.
pub struct OwnedConfig {
    address: Address,
    window: EcamWindow,
    mapping: Mapping,
}

/// Opaque pin on this exact configuration mapping and native root/resource
/// epoch. It exposes no pointer or second configuration access path. Holding
/// it prevents mapping retirement; dropping it establishes no DMA completion.
/// The original driver's sole config owner must still honor the attachment's
/// reset/removal/assignment exclusion for every retained DMA binding lifetime.
pub struct ConfigRetention {
    view: MappingView,
}
impl ConfigRetention {
    /// Refuse an original mapping that was dropped, quarantined or retired.
    pub fn check_live(&self) -> Result<(), MappingError> {
        self.view.check_current()
    }

    /// Compare actual retained authorities, never caller-supplied numeric IDs.
    pub fn matches_mapping(&self, mapping: &Mapping) -> Result<bool, MappingError> {
        mapping.shares_mapping(&self.view)
    }
}

impl OwnedConfig {
    /// Attach one exact, live 4 KiB UC/RW function mapping. Failure returns that
    /// same mapping, including its retirement obligations, without device access.
    ///
    /// # Safety
    /// `window` is the actual immutable MCFG window for this function and epoch;
    /// the retained mapping's resource is this actual ECAM configuration space.
    /// Its native platform owner keeps the mapping valid in every access context.
    /// The producer holds exclusive configuration, reset/removal, root/bridge
    /// routing and assignment ownership until the mapping is retired. No other
    /// configuration writer, raw pointer, MappingView, firmware accessor or reset
    /// path may access/change this function concurrently or invalidate the grant.
    /// All accesses, final releases and retirement obey the platform's process/
    /// deferred-context rules. A matching physical number alone proves none of
    /// these ownership facts. This grants neither DMA quiescence nor coherency.
    pub unsafe fn attach(
        address: Address,
        window: EcamWindow,
        mapping: Mapping,
    ) -> Result<Self, (ConfigError, Mapping)> {
        if let Err(error) = Self::validate(address, window, &mapping) {
            return Err((error, mapping));
        }
        Ok(Self {
            address,
            window,
            mapping,
        })
    }

    fn validate(
        address: Address,
        window: EcamWindow,
        mapping: &Mapping,
    ) -> Result<(), ConfigError> {
        if window.start_bus > window.end_bus
            || !window.base.is_multiple_of(1u64 << BUS_SHIFT)
            || window
                .base
                .checked_add((u64::from(window.end_bus) + 1) << BUS_SHIFT)
                .is_none()
        {
            return Err(ConfigError::Window);
        }
        if address.segment != window.segment
            || address.bus < window.start_bus
            || address.bus > window.end_bus
            || address.device >= 32
            || address.function >= 8
        {
            return Err(ConfigError::Address);
        }
        // MCFG bases are relative to bus zero, including windows whose first
        // admitted bus is nonzero. Never subtract start_bus from this offset.
        let physical = window
            .base
            .checked_add(u64::from(address.bus) << BUS_SHIFT)
            .and_then(|base| base.checked_add(u64::from(address.device) << DEVICE_SHIFT))
            .and_then(|base| base.checked_add(u64::from(address.function) << FUNCTION_SHIFT))
            .ok_or(ConfigError::PhysicalSpan)?;
        let end = physical
            .checked_add(FUNCTION_BYTES as u64)
            .ok_or(ConfigError::PhysicalSpan)?;
        let span = mapping.physical_span().map_err(ConfigError::Mapping)?;
        if span.start() != physical
            || span.end() != end
            || mapping.bytes().map_err(ConfigError::Mapping)? != FUNCTION_BYTES
        {
            return Err(ConfigError::PhysicalSpan);
        }
        if mapping.attribute().map_err(ConfigError::Mapping)? != CacheAttribute::Uncached {
            return Err(ConfigError::CacheAttribute);
        }
        if mapping.protection().map_err(ConfigError::Mapping)? != Protection::ReadWrite {
            return Err(ConfigError::Protection);
        }
        let cpu = mapping
            .address(0, FUNCTION_BYTES)
            .map_err(ConfigError::Mapping)?;
        let base = cpu.as_ptr() as usize;
        if !base.is_multiple_of(FUNCTION_BYTES) || base.checked_add(FUNCTION_BYTES).is_none() {
            return Err(ConfigError::CpuAddress);
        }
        Ok(())
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn window(&self) -> EcamWindow {
        self.window
    }

    /// Compare an actual consumed requester binding with this exact retained
    /// configuration mapping. Matching numeric BDF/physical addresses do not
    /// qualify. This establishes no current device quiescence.
    pub fn matches_binding(
        &self,
        binding: &super::requester::RequesterBinding,
    ) -> Result<bool, MappingError> {
        if self.address != binding.address() {
            return Ok(false);
        }
        binding.matches_mapping(&self.mapping)
    }

    pub(super) fn retain_epoch(&self) -> Result<ConfigRetention, MappingError> {
        Ok(ConfigRetention {
            view: self.mapping.view(0..FUNCTION_BYTES)?,
        })
    }

    /// Transfer the original mapping back to its retirement owner. The unsafe
    /// attachment's epoch/context and access-drain obligations remain in force.
    pub fn into_mapping(self) -> Mapping {
        self.mapping
    }

    fn try_register<T>(&self, offset: u16) -> Result<NonNull<T>, ConfigError> {
        let start = usize::from(offset);
        let width = size_of::<T>();
        if !start.is_multiple_of(width)
            || !start
                .checked_add(width)
                .is_some_and(|end| end <= FUNCTION_BYTES)
        {
            return Err(ConfigError::Access { offset, width });
        }
        // Recheck live registry state for each operation instead of retaining
        // a raw pointer across a possible later mapping quarantine.
        self.mapping
            .address(start, width)
            .map(NonNull::cast)
            .map_err(ConfigError::Mapping)
    }

    fn register<T>(&self, offset: u16) -> NonNull<T> {
        self.try_register(offset)
            .expect("aligned live owned PCI configuration register")
    }

    /// Fallible exact-width accesses for native service boundaries. Revalidate
    /// the original mapping/context after the volatile effect as well. An error
    /// after a write does not establish that the write had no hardware effect.
    pub fn try_read8(&self, offset: u16) -> Result<u8, ConfigError> {
        // SAFETY: complete checked native byte, under the original attach grant.
        let value = unsafe { self.try_register::<u8>(offset)?.as_ptr().read_volatile() };
        self.try_register::<u8>(offset)?;
        Ok(value)
    }
    pub fn try_read16(&self, offset: u16) -> Result<u16, ConfigError> {
        // SAFETY: complete checked aligned native word.
        let value = unsafe { self.try_register::<u16>(offset)?.as_ptr().read_volatile() };
        self.try_register::<u16>(offset)?;
        Ok(u16::from_le(value))
    }
    pub fn try_read32(&self, offset: u16) -> Result<u32, ConfigError> {
        // SAFETY: complete checked aligned native dword.
        let value = unsafe { self.try_register::<u32>(offset)?.as_ptr().read_volatile() };
        self.try_register::<u32>(offset)?;
        Ok(u32::from_le(value))
    }
    pub fn try_write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        // SAFETY: a byte store never replays a neighboring W1C register.
        unsafe {
            self.try_register::<u8>(offset)?
                .as_ptr()
                .write_volatile(value)
        };
        self.try_register::<u8>(offset)?;
        Ok(())
    }
    pub fn try_write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        // SAFETY: an aligned word store never widens into adjacent Status.
        unsafe {
            self.try_register::<u16>(offset)?
                .as_ptr()
                .write_volatile(value.to_le())
        };
        self.try_register::<u16>(offset)?;
        Ok(())
    }
    pub fn try_write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        // SAFETY: complete checked aligned native dword store.
        unsafe {
            self.try_register::<u32>(offset)?
                .as_ptr()
                .write_volatile(value.to_le())
        };
        self.try_register::<u32>(offset)?;
        Ok(())
    }
}

impl ConfigSpace for OwnedConfig {
    fn read8(&self, offset: u16) -> u8 {
        // SAFETY: exact-width aligned live ECAM access under attachment grant.
        unsafe { self.register::<u8>(offset).as_ptr().read_volatile() }
    }
    fn read16(&self, offset: u16) -> u16 {
        // SAFETY: complete aligned native word read, with checked function bounds.
        unsafe { self.register::<u16>(offset).as_ptr().read_volatile() }
    }
    fn read32(&self, offset: u16) -> u32 {
        // SAFETY: complete aligned native dword read under exclusive config epoch.
        unsafe { self.register::<u32>(offset).as_ptr().read_volatile() }
    }
    fn write8(&mut self, offset: u16, value: u8) {
        // SAFETY: native byte store; no neighboring register is read or replayed.
        unsafe { self.register::<u8>(offset).as_ptr().write_volatile(value) };
    }
    fn write16(&mut self, offset: u16, value: u16) {
        // SAFETY: native word store; adjacent Status W1C bits are never replayed.
        unsafe { self.register::<u16>(offset).as_ptr().write_volatile(value) };
    }
    fn write32(&mut self, offset: u16, value: u32) {
        // SAFETY: complete aligned native dword write under exclusive config epoch.
        unsafe { self.register::<u32>(offset).as_ptr().write_volatile(value) };
    }
}

// SAFETY: the attachment grant establishes actual exclusive, retained config
// access in process/deferred context. write16 is a native volatile word store.
unsafe impl MsiConfigSpace for OwnedConfig {}

#[cfg(test)]
pub(crate) mod tests {
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
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::Mutex,
    };

    const SPACE: AddressSpace = AddressSpace {
        identity: 19,
        physical_bits: 48,
        virtual_bits: 48,
    };
    const BASE: u64 = 0x8000_0000;
    const ADDRESS: Address = Address {
        segment: 0x1234,
        bus: 0xab,
        device: 0x1f,
        function: 7,
    };

    #[derive(Default)]
    pub(crate) struct Counters {
        pub(crate) maps: AtomicUsize,
        pub(crate) unmaps: AtomicUsize,
        pub(crate) resource_drops: AtomicUsize,
        pub(crate) platform_drops: AtomicUsize,
        pub(crate) contexts: AtomicUsize,
        pub(crate) fail_context_at: AtomicUsize,
        pub(crate) fail_after_word: AtomicUsize,
        pub(crate) fail_after_value: AtomicUsize,
    }

    struct Backing {
        span: PhysicalSpan,
        kind: ResourceKind,
        counters: Arc<Counters>,
    }
    // SAFETY: isolated symbolic physical inventory, retained alongside actual
    // owned CPU fixture storage; no hardware or production authority is used.
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
    struct Pages([u8; 8192]);
    struct Model {
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
    // SAFETY: actual retained aligned CPU RAM models exactly the requested
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
                // SAFETY: isolated fixture owns this actual aligned RAM and
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

    fn window(address: Address) -> EcamWindow {
        EcamWindow {
            base: BASE,
            segment: address.segment,
            start_bus: address.bus,
            end_bus: address.bus,
        }
    }
    fn physical(address: Address) -> u64 {
        BASE + (u64::from(address.bus) << 20)
            + (u64::from(address.device) << 15)
            + (u64::from(address.function) << 12)
    }
    fn mapped(
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
            // WC exists only for the intentionally unsuitable-resource case;
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

    /// Actual registry-owned transport fixture for sibling requester tests.
    /// Program it through ConfigSpace and explicitly retire its returned mapping.
    pub(crate) fn fixture(address: Address) -> (OwnedConfig, Arc<Counters>) {
        let span = PhysicalSpan::new(physical(address), FUNCTION_BYTES as u64).unwrap();
        let (mapping, counters) = mapped(
            span,
            0,
            FUNCTION_BYTES,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        );
        // SAFETY: this fixture owns its actual storage, exclusive config access
        // and symbolic resource epoch. It grants no production device authority.
        let config = match unsafe { OwnedConfig::attach(address, window(address), mapping) } {
            Ok(config) => config,
            Err((error, _)) => panic!("valid owned fixture: {error:?}"),
        };
        (config, counters)
    }

    pub(crate) fn fixture_pointer(config: &OwnedConfig, offset: u16) -> NonNull<u8> {
        config.try_register(offset).unwrap()
    }

    fn retire(mut mapping: Mapping, counters: &Counters) {
        // SAFETY: each test stopped all synchronous fixture accesses before
        // returning the original mapping; no worker/device can access storage.
        unsafe { mapping.retire() }.unwrap();
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
        assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn full_mcfg_geometry_and_mapping_owners_survive_until_retirement() {
        let (mut config, counters) = fixture(ADDRESS);
        assert_eq!(config.address(), ADDRESS);
        assert_eq!(config.window(), window(ADDRESS));
        assert_eq!(counters.maps.load(Ordering::Relaxed), 1);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
        assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
        config.write32(0, 0xabcd1234);
        assert_eq!(config.read32(0), 0xabcd1234);
        let mapping = config.into_mapping();
        assert_eq!(mapping.physical_span().unwrap().start(), 0x8abff000);
        assert_eq!(mapping.bytes().unwrap(), FUNCTION_BYTES);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
        retire(mapping, &counters);
    }

    #[test]
    fn native_narrow_accesses_preserve_neighboring_status_and_tail_bytes() {
        // Actual volatile CPU RAM effects, not an emulation of PCI W1C status.
        // Hardware width is prescribed by each production write_volatile call.
        let (mut config, counters) = fixture(ADDRESS);
        config.write32(4, 0xa5c3_0102);
        config.write16(4, 0x3344);
        assert_eq!(config.read32(4), 0xa5c3_3344);
        config.write8(5, 0x77);
        assert_eq!(config.read32(4), 0xa5c3_7744);
        assert_eq!(config.read16(6), 0xa5c3);
        assert_eq!(config.read8(4), 0x44);
        config.write32(4092, 0x89ab_cdef);
        config.write16(4094, 0x1234);
        config.write8(4095, 0x56);
        assert_eq!(config.read32(4092), 0x5634_cdef);
        assert_eq!(config.read16(4094), 0x5634);
        assert_eq!(config.read8(4095), 0x56);
        retire(config.into_mapping(), &counters);
    }

    #[test]
    fn segment_and_bus_extremes_keep_full_function_offsets() {
        for (address, physical) in [
            (
                Address {
                    segment: 0,
                    bus: 0,
                    device: 0,
                    function: 0,
                },
                0x8000_0000,
            ),
            (
                Address {
                    segment: u16::MAX,
                    bus: u8::MAX,
                    device: 31,
                    function: 7,
                },
                0x8fff_f000,
            ),
        ] {
            let (config, counters) = fixture(address);
            assert_eq!(config.address(), address);
            let mapping = config.into_mapping();
            assert_eq!(mapping.physical_span().unwrap().start(), physical);
            retire(mapping, &counters);
        }
    }

    #[test]
    fn retired_mapping_is_returned_without_resurrecting_ownership() {
        let (config, counters) = fixture(ADDRESS);
        let mut mapping = config.into_mapping();
        // SAFETY: this synchronous fixture has no config, worker or device access.
        unsafe { mapping.retire() }.unwrap();
        // SAFETY: isolated fixture epoch; rejection must not resurrect the mapping.
        let (error, mapping) =
            match unsafe { OwnedConfig::attach(ADDRESS, window(ADDRESS), mapping) } {
                Err(failure) => failure,
                Ok(_) => panic!("retired mapping accepted"),
            };
        assert_eq!(error, ConfigError::Mapping(MappingError::Retired));
        assert_eq!(
            mapping.address(0, FUNCTION_BYTES),
            Err(MappingError::Retired)
        );
        drop(mapping);
        assert_eq!(counters.maps.load(Ordering::Relaxed), 1);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
        assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn invalid_width_alignment_and_complete_bounds_panic_before_access() {
        let (mut config, counters) = fixture(ADDRESS);
        config.write32(4092, 0x1234_5678);
        for offset in [1, 3, 4093, 4094, 4095, 4096, u16::MAX] {
            assert!(catch_unwind(AssertUnwindSafe(|| config.read32(offset))).is_err());
            assert!(catch_unwind(AssertUnwindSafe(|| config.write32(offset, 0))).is_err());
        }
        for offset in [1, 3, 4095, 4096, u16::MAX] {
            assert!(catch_unwind(AssertUnwindSafe(|| config.read16(offset))).is_err());
            assert!(catch_unwind(AssertUnwindSafe(|| config.write16(offset, 0))).is_err());
        }
        for offset in [4096, u16::MAX] {
            assert!(catch_unwind(AssertUnwindSafe(|| config.read8(offset))).is_err());
            assert!(catch_unwind(AssertUnwindSafe(|| config.write8(offset, 0))).is_err());
        }
        assert_eq!(config.read32(4092), 0x1234_5678);
        retire(config.into_mapping(), &counters);
    }

    #[test]
    fn rejected_metadata_returns_the_live_mapping_for_explicit_retirement() {
        let good = window(ADDRESS);
        let mut cases = Vec::new();
        let mut bad = good;
        bad.start_bus = bad.end_bus + 1;
        cases.push((ADDRESS, bad, ConfigError::Window));
        let mut bad = good;
        bad.base += 4096;
        cases.push((ADDRESS, bad, ConfigError::Window));
        let mut bad = good;
        bad.base = !((1u64 << BUS_SHIFT) - 1);
        cases.push((ADDRESS, bad, ConfigError::Window));
        let mut bad = ADDRESS;
        bad.segment ^= 1;
        cases.push((bad, good, ConfigError::Address));
        let mut bad = ADDRESS;
        bad.bus -= 1;
        cases.push((bad, good, ConfigError::Address));
        let mut bad = ADDRESS;
        bad.bus += 1;
        cases.push((bad, good, ConfigError::Address));
        let mut bad = ADDRESS;
        bad.device = 32;
        cases.push((bad, good, ConfigError::Address));
        let mut bad = ADDRESS;
        bad.function = 8;
        cases.push((bad, good, ConfigError::Address));
        for (address, ecam, expected) in cases {
            let (config, counters) = fixture(ADDRESS);
            let mapping = config.into_mapping();
            let original = mapping.address(0, FUNCTION_BYTES).unwrap();
            // SAFETY: fixture grants the ownership; malformed numeric metadata
            // is deliberately passed for rejection before any register access.
            let (error, mapping) = match unsafe { OwnedConfig::attach(address, ecam, mapping) } {
                Err(failure) => failure,
                Ok(_) => panic!("invalid config metadata accepted"),
            };
            assert_eq!(error, expected);
            assert_eq!(mapping.address(0, FUNCTION_BYTES).unwrap(), original);
            assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
            retire(mapping, &counters);
        }
        for (offset, bytes, attribute, protection, expected) in [
            (
                4096,
                4096,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
                ConfigError::PhysicalSpan,
            ),
            (
                0,
                8192,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
                ConfigError::PhysicalSpan,
            ),
            (
                0,
                2048,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
                ConfigError::PhysicalSpan,
            ),
            (
                0,
                4096,
                CacheAttribute::WriteCombining,
                Protection::ReadWrite,
                ConfigError::CacheAttribute,
            ),
            (
                0,
                4096,
                CacheAttribute::Uncached,
                Protection::ReadOnly,
                ConfigError::Protection,
            ),
        ] {
            let span = PhysicalSpan::new(physical(ADDRESS), 8192).unwrap();
            let (mapping, counters) = mapped(span, offset, bytes, attribute, protection);
            // SAFETY: owned fixture; constructor must reject the bad view/policy.
            let (error, mapping) = match unsafe { OwnedConfig::attach(ADDRESS, good, mapping) } {
                Err(failure) => failure,
                Ok(_) => panic!("invalid mapping accepted"),
            };
            assert_eq!(error, expected);
            assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
            retire(mapping, &counters);
        }
    }
}
