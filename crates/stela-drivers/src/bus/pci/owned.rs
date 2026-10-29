//! One exclusively owned ECAM function, kept through the native mapping
//! registry. Numeric MCFG geometry is checked here; device/resource and
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

/// Keeps the real resource, installed native mapping and address-space owner.
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
/// reset/removal/assignment exclusion for every DMA binding lifetime.
pub struct ConfigRetention {
    view: MappingView,
}
impl ConfigRetention {
    /// Refuse an original mapping that was dropped, quarantined or retired.
    pub fn check_live(&self) -> Result<(), MappingError> {
        self.view.check_current()
    }

    /// Compare kept permissions, never caller-supplied numeric IDs.
    pub fn matches_mapping(&self, mapping: &Mapping) -> Result<bool, MappingError> {
        mapping.shares_mapping(&self.view)
    }
}

impl OwnedConfig {
    /// Attach one exact, live 4 KiB UC/RW function mapping. Failure returns that
    /// same mapping, including its retirement obligations, without device access.
    ///
    /// # Safety
    /// `window` is the immutable MCFG window for this function and epoch;
    /// the mapping's resource is this ECAM configuration space.
    /// Its native platform owner keeps the mapping valid in every access context.
    /// The producer holds exclusive configuration, reset/removal, root/bridge
    /// routing and assignment ownership until the mapping is retired. No other
    /// configuration writer, raw pointer, MappingView, firmware accessor or reset
    /// path may access/change this function concurrently or invalidate the grant.
    /// Accesses may run in an interrupt handler; final releases and
    /// retirement require process or deferred context, as
    /// [`MappingPlatform`](crate::bus::mmio::owned::MappingPlatform) sets out.
    /// A matching physical number alone proves none of
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

    /// Compare a consumed requester binding with this kept
    /// configuration mapping. Matching numeric BDF/physical addresses do not
    /// check. This establishes no current device quiescence.
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
        // Recheck live registry state for each operation instead of keeping
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

// SAFETY: the attachment grant establishes exclusive config access for the
// grant's life, from any context the mapping permits. write16 is a native
// volatile word store.
unsafe impl MsiConfigSpace for OwnedConfig {}

#[cfg(test)]
pub(crate) mod tests;
