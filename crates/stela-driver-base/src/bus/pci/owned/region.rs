//! Common exact config mapping/IO algorithms; phase-specific original grants.
use super::{
    ConfigRetention,
    grant::{self, Grant, Operation},
};
use crate::bus::{
    mmio::owned::{CacheAttribute, Error as MappingError, Mapping, Protection},
    pci::{Address, ConfigError, ConfigFailure, EcamWindow},
};
use core::{mem::size_of, ptr::NonNull};
const FUNCTION_BYTES: usize = 4096;
const BUS_SHIFT: u32 = 20;
const DEVICE_SHIFT: u32 = 15;
const FUNCTION_SHIFT: u32 = 12;
pub(super) struct Region<G: Grant> {
    address: Address,
    window: EcamWindow,
    mapping: Mapping,
    grant: G,
}
impl<G: Grant> Region<G> {
    /// Join an actual owned source grant with its SAME original UC/RW mapping.
    /// Geometry derives only from that source, never a caller replacement.
    /// Failure returns every original owner intact before device access.
    pub fn attach(grant: G, mapping: Mapping) -> Result<Self, (ConfigError, G, Mapping)> {
        let address = grant.custody().address();
        let window = grant.custody().window();
        if let Err(error) = Self::validate(address, window, &mapping) {
            return Err((error, grant, mapping));
        }
        if let Err(error) = grant
            .custody()
            .retirement_context()
            .map_err(|e| ConfigError::before_effect(ConfigFailure::Mapping(e)))
        {
            return Err((error, grant, mapping));
        }
        match mapping.retains_resource(grant.custody().resource()) {
            Ok(true) => {}
            Ok(false) => return Err((grant::foreign_grant(), grant, mapping)),
            Err(error) => {
                return Err((
                    ConfigError::before_effect(ConfigFailure::Mapping(error)),
                    grant,
                    mapping,
                ));
            }
        }
        Ok(Self {
            grant,
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
            return Err(ConfigError::before_effect(ConfigFailure::Window));
        }
        if address.segment != window.segment
            || address.bus < window.start_bus
            || address.bus > window.end_bus
            || address.device >= 32
            || address.function >= 8
        {
            return Err(ConfigError::before_effect(ConfigFailure::Address));
        }
        // MCFG bases are relative to bus zero, including windows whose first
        // admitted bus is nonzero. Never subtract start_bus from this offset.
        let physical = window
            .base
            .checked_add(u64::from(address.bus) << BUS_SHIFT)
            .and_then(|base| base.checked_add(u64::from(address.device) << DEVICE_SHIFT))
            .and_then(|base| base.checked_add(u64::from(address.function) << FUNCTION_SHIFT))
            .ok_or(ConfigError::before_effect(ConfigFailure::PhysicalSpan))?;
        let end = physical
            .checked_add(FUNCTION_BYTES as u64)
            .ok_or(ConfigError::before_effect(ConfigFailure::PhysicalSpan))?;
        let span = mapping
            .physical_span()
            .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)))?;
        if span.start() != physical
            || span.end() != end
            || mapping
                .bytes()
                .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)))?
                != FUNCTION_BYTES
        {
            return Err(ConfigError::before_effect(ConfigFailure::PhysicalSpan));
        }
        if mapping
            .attribute()
            .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)))?
            != CacheAttribute::Uncached
        {
            return Err(ConfigError::before_effect(ConfigFailure::CacheAttribute));
        }
        if mapping
            .protection()
            .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)))?
            != Protection::ReadWrite
        {
            return Err(ConfigError::before_effect(ConfigFailure::Protection));
        }
        let cpu = mapping
            .address(0, FUNCTION_BYTES)
            .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)))?;
        let base = cpu.as_ptr() as usize;
        if !base.is_multiple_of(FUNCTION_BYTES) || base.checked_add(FUNCTION_BYTES).is_none() {
            return Err(ConfigError::before_effect(ConfigFailure::CpuAddress));
        }
        Ok(())
    }

    pub fn admission_close(
        &self,
    ) -> Result<crate::bus::pci::assignment::AdmissionClose, MappingError> {
        self.grant.custody().admission_close()
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
        binding: &crate::bus::pci::requester::RequesterBinding,
    ) -> Result<bool, MappingError> {
        if self.address != binding.address() {
            return Ok(false);
        }
        binding.matches_mapping(&self.mapping)
    }

    /// Compare the original retained configuration permission, not a BDF or
    /// physical label. This grants no device stop, drain or reset permission.
    pub fn matches_retention(&self, retained: &ConfigRetention) -> Result<bool, MappingError> {
        retained.matches_mapping(&self.mapping)
    }

    /// Keep a read-only epoch seal for this exact original configuration.
    /// It pins mapping retirement until dropped and exposes no register writer.
    pub fn retain_epoch(&self) -> Result<ConfigRetention, MappingError> {
        let custody = self.grant.custody().retain_epoch()?;
        Ok(ConfigRetention {
            custody,
            view: self.mapping.view(0..FUNCTION_BYTES)?,
        })
    }

    /// Transfer the original mapping back to its retirement owner. The unsafe
    /// attachment's epoch/context and access-drain obligations remain in force.
    pub fn into_parts(self) -> (G, Mapping) {
        (self.grant, self.mapping)
    }
    /// # Safety
    /// All actual config/device/raw-pointer/DMA/IRQ/callback users have ended;
    /// no new access may start. No assignment/grant release is implied. Failure
    /// retains THIS same complete owner; never reconstruct it from descriptors.
    pub unsafe fn retire(&mut self) -> Result<(), MappingError> {
        self.grant.custody().retirement_context()?;
        // SAFETY: exact original mapping under caller's complete retirement.
        unsafe { self.mapping.retire() }
    }

    pub fn seal_bus_master(&mut self) -> Result<(), ConfigError> {
        if self.try_read16(4)? & 4 != 0 {
            return Err(ConfigError::before_effect(ConfigFailure::BusMasterSealed));
        }
        self.grant.state().master_sealed.set(true);
        Ok(())
    }
    /// # Safety
    /// The owning driver acknowledged actual stop/reset without restart, and
    /// its current root/configuration binding and required payload completion
    /// finished. Old descriptors cannot resume when new mappings are enabled.
    pub unsafe fn release_bus_master_seal(&mut self) {
        self.grant.state().master_sealed.set(false);
    }
    /// Reopen ONLY qualified Type1 upstream forwarding after global containment.
    /// # Safety
    /// The actual complete descendant/source cohort has been contained and
    /// retired, new roots are blocked, every leaf BME seal remains enforced,
    /// and the real bridge routing/assignment owner remains frozen. This does
    /// not authorize an endpoint engine or arbitrary bridge reconfiguration.
    pub unsafe fn release_bus_forwarding_seal(&mut self) -> Result<(), ConfigError> {
        if self.try_read8(0x0e)? & 0x7f != 1 || self.grant.state().routing_seal.get().is_none() {
            return Err(ConfigError::before_effect(ConfigFailure::Address));
        }
        self.grant.state().master_sealed.set(false);
        Ok(())
    }
    /// Freeze actual Type1 bus/routing windows for this root cohort. Driver
    /// control can move, but safe config writes cannot reassign source routes.
    pub fn seal_bus_routing(&mut self) -> Result<(), ConfigError> {
        if self.try_read8(0x0e)? & 0x7f != 1 {
            return Err(ConfigError::before_effect(ConfigFailure::Address));
        }
        let mut words = [0; 7];
        for (index, word) in words.iter_mut().enumerate() {
            *word = self.try_read32(0x18 + index as u16 * 4)?;
        }
        self.grant
            .state()
            .routing_seal
            .set(Some((words, self.try_read16(0x3e)?)));
        Ok(())
    }
    fn check_write(&self, offset: u16, value: u32, bytes: usize) -> Result<(), ConfigError> {
        if let Some(error) = self.grant.state().terminal.get() {
            return Err(error);
        }
        if self.grant.state().master_sealed.get() && offset == 4 && value & 4 != 0 {
            return Err(ConfigError::before_effect(ConfigFailure::BusMasterSealed));
        }
        if let Some((words, _)) = &self.grant.state().routing_seal.get()
            && (0x18..0x34).contains(&offset)
        {
            let index = usize::from((offset - 0x18) / 4);
            let shift = u32::from(offset & 3) * 8;
            let mask = if bytes == 4 {
                u32::MAX
            } else {
                (1u32 << (bytes * 8)) - 1
            };
            if value & mask != (words[index] >> shift) & mask {
                return Err(ConfigError::before_effect(ConfigFailure::RoutingSealed));
            }
        }
        if let Some((_, control)) = &self.grant.state().routing_seal.get() {
            // Secondary-bus reset and ISA/VGA routing live outside 18h..30h.
            // Freeze that actual bridge-control word, while ordinary Interrupt
            // Line metadata at3Ch remains writable.
            for byte in 0..bytes {
                let at = usize::from(offset) + byte;
                if (0x3e..0x40).contains(&at)
                    && ((value >> (byte * 8)) as u8) != ((*control >> ((at - 0x3e) * 8)) as u8)
                {
                    return Err(ConfigError::before_effect(ConfigFailure::RoutingSealed));
                }
            }
        }
        Ok(())
    }
    fn try_register<T>(&self, offset: u16) -> Result<NonNull<T>, ConfigError> {
        if let Some(error) = self.grant.state().terminal.get() {
            return Err(error);
        }
        let start = usize::from(offset);
        let width = size_of::<T>();
        if !start.is_multiple_of(width)
            || !start
                .checked_add(width)
                .is_some_and(|end| end <= FUNCTION_BYTES)
        {
            return Err(ConfigError::before_effect(ConfigFailure::Access {
                offset,
                width,
            }));
        }
        // Recheck live registry state for each operation instead of keeping
        // a raw pointer across a possible later mapping quarantine.
        self.mapping
            .address(start, width)
            .map(NonNull::cast)
            .map_err(|error| ConfigError::before_effect(ConfigFailure::Mapping(error)))
    }

    fn stop_after_effect(&self, error: ConfigError) -> ConfigError {
        if let Some(first) = self.grant.state().terminal.get() {
            first
        } else {
            self.grant.state().terminal.set(Some(error));
            error
        }
    }
    fn postvalidate<T>(&self, offset: u16, width: u8, wrote: bool) -> Result<(), ConfigError> {
        self.try_register::<T>(offset).map(|_| ()).map_err(|error| {
            self.stop_after_effect(if wrote {
                ConfigError::write_may_have_applied(offset, width, error.reason)
            } else {
                error
            })
        })
    }

    /// Fallible exact-width accesses for native service boundaries. Revalidate
    /// the original mapping/context after the volatile effect as well. An error
    /// after a write does not establish that the write had no hardware effect.
    pub fn try_read8(&self, offset: u16) -> Result<u8, ConfigError> {
        let register = self.try_register::<u8>(offset)?;
        let operation = self
            .grant
            .custody()
            .begin(Operation::Read { offset, width: 1 })?;
        // SAFETY: complete checked native byte, under the original attach grant.
        let value = unsafe { register.as_ptr().read_volatile() };
        self.postvalidate::<u8>(offset, 1, false)?;
        // SAFETY: bounded volatile read and exact postvalidation completed;
        // no borrowed owner/entered permit survives or sleeps here.
        unsafe { operation.release() }.map_err(|(e, _kept)| {
            self.stop_after_effect(ConfigError::before_effect(ConfigFailure::Ownership(e)))
        })?;
        Ok(value)
    }
    pub fn try_read16(&self, offset: u16) -> Result<u16, ConfigError> {
        let register = self.try_register::<u16>(offset)?;
        let operation = self
            .grant
            .custody()
            .begin(Operation::Read { offset, width: 2 })?;
        // SAFETY: complete checked aligned native word.
        let value = unsafe { register.as_ptr().read_volatile() };
        self.postvalidate::<u16>(offset, 2, false)?;
        // SAFETY: bounded volatile read and exact postvalidation completed;
        // no borrowed owner/entered permit survives or sleeps here.
        unsafe { operation.release() }.map_err(|(e, _kept)| {
            self.stop_after_effect(ConfigError::before_effect(ConfigFailure::Ownership(e)))
        })?;
        Ok(u16::from_le(value))
    }
    pub fn try_read32(&self, offset: u16) -> Result<u32, ConfigError> {
        let register = self.try_register::<u32>(offset)?;
        let operation = self
            .grant
            .custody()
            .begin(Operation::Read { offset, width: 4 })?;
        // SAFETY: complete checked aligned native dword.
        let value = unsafe { register.as_ptr().read_volatile() };
        self.postvalidate::<u32>(offset, 4, false)?;
        // SAFETY: bounded volatile read and exact postvalidation completed;
        // no borrowed owner/entered permit survives or sleeps here.
        unsafe { operation.release() }.map_err(|(e, _kept)| {
            self.stop_after_effect(ConfigError::before_effect(ConfigFailure::Ownership(e)))
        })?;
        Ok(u32::from_le(value))
    }
    pub fn try_write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.check_write(offset, u32::from(value), 1)?;
        let register = self.try_register::<u8>(offset)?;
        let operation = self.grant.custody().begin(Operation::Write {
            offset,
            width: 1,
            value: u32::from(value),
        })?;
        // SAFETY: a byte store never replays a neighboring W1C register.
        unsafe { register.as_ptr().write_volatile(value) };
        self.postvalidate::<u8>(offset, 1, true)?;
        // SAFETY: exact bounded write/postvalidation ended. Uncertain failure
        // retains the operation count/graph, never a retry-as-unchanged proof.
        unsafe { operation.release() }.map_err(|(e, _kept)| {
            self.stop_after_effect(ConfigError::write_may_have_applied(
                offset,
                1,
                ConfigFailure::Ownership(e),
            ))
        })?;
        Ok(())
    }
    pub fn try_write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.check_write(offset, u32::from(value), 2)?;
        let register = self.try_register::<u16>(offset)?;
        let operation = self.grant.custody().begin(Operation::Write {
            offset,
            width: 2,
            value: u32::from(value),
        })?;
        // SAFETY: an aligned word store never widens into adjacent Status.
        unsafe { register.as_ptr().write_volatile(value.to_le()) };
        self.postvalidate::<u16>(offset, 2, true)?;
        // SAFETY: exact bounded write/postvalidation ended. Uncertain failure
        // retains the operation count/graph, never a retry-as-unchanged proof.
        unsafe { operation.release() }.map_err(|(e, _kept)| {
            self.stop_after_effect(ConfigError::write_may_have_applied(
                offset,
                2,
                ConfigFailure::Ownership(e),
            ))
        })?;
        Ok(())
    }
    pub fn try_write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.check_write(offset, value, 4)?;
        let register = self.try_register::<u32>(offset)?;
        let operation = self.grant.custody().begin(Operation::Write {
            offset,
            width: 4,
            value,
        })?;
        // SAFETY: complete checked aligned native dword store.
        unsafe { register.as_ptr().write_volatile(value.to_le()) };
        self.postvalidate::<u32>(offset, 4, true)?;
        // SAFETY: exact bounded write/postvalidation ended. Uncertain failure
        // retains the operation count/graph, never a retry-as-unchanged proof.
        unsafe { operation.release() }.map_err(|(e, _kept)| {
            self.stop_after_effect(ConfigError::write_may_have_applied(
                offset,
                4,
                ConfigFailure::Ownership(e),
            ))
        })?;
        Ok(())
    }
}
