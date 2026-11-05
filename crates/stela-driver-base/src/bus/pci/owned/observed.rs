//! A source-owned observation lease for one exact ECAM function.
use super::region::validate_mapping;
use crate::bus::{
    mmio::owned::{Error as MappingError, Mapping, Protection},
    pci::{Address, ConfigError, ConfigFailure, ConfigSpace, EcamWindow},
};
use core::ptr::NonNull;

/// An authentic UC, read-only function mapping. The original mapping keeps the
/// bus resource and validates the original context before each observation.
pub struct ObservedConfig {
    address: Address,
    mapping: Mapping,
}

fn mapping_error(error: MappingError) -> ConfigError {
    ConfigError::before_effect(ConfigFailure::Mapping(error))
}

fn read_only() -> ConfigError {
    ConfigError::before_effect(ConfigFailure::Protection)
}

impl ObservedConfig {
    /// # Safety
    /// The original ECAM producer issued this lease for the function in this
    /// window. The producer holds the physical decode and root stable through
    /// every read and keeps the original bus resource through retirement.
    pub unsafe fn attach(
        address: Address,
        window: EcamWindow,
        mapping: Mapping,
    ) -> Result<Self, (ConfigError, Mapping)> {
        match validate_mapping(address, window, &mapping, Protection::ReadOnly) {
            Ok(()) => Ok(Self { address, mapping }),
            Err(error) => Err((error, mapping)),
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    /// Finish this read-only observation. No raw pointer or view escapes.
    pub fn retire(&mut self) -> Result<(), MappingError> {
        // SAFETY: synchronous reads are complete, and the mapping is private.
        unsafe { self.mapping.retire() }
    }

    fn register(&self, offset: u16, width: usize) -> Result<NonNull<u8>, ConfigError> {
        if !usize::from(offset).is_multiple_of(width) {
            return Err(ConfigError::before_effect(ConfigFailure::Access {
                offset,
                width,
            }));
        }
        self.mapping
            .address(usize::from(offset), width)
            .map_err(mapping_error)
    }
}

impl ConfigSpace for ObservedConfig {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        let register = self.register(offset, 1)?;
        // SAFETY: the live mapping checked this exact byte.
        Ok(unsafe { register.as_ptr().read_volatile() })
    }

    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        let register = self.register(offset, 2)?.cast::<u16>();
        // SAFETY: attach checked page alignment and register checked width,
        // offset alignment and the live mapping.
        Ok(u16::from_le(unsafe { register.as_ptr().read_volatile() }))
    }

    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.mapping
            .read32(usize::from(offset))
            .map_err(mapping_error)
    }

    fn write8(&mut self, _: u16, _: u8) -> Result<(), ConfigError> {
        Err(read_only())
    }

    fn write16(&mut self, _: u16, _: u16) -> Result<(), ConfigError> {
        Err(read_only())
    }

    fn write32(&mut self, _: u16, _: u32) -> Result<(), ConfigError> {
        Err(read_only())
    }
}
