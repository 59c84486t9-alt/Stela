//! Read-only topology observations under the standalone ECAM assignment.
use super::*;
use core::ptr::NonNull;
use stela_drivers::bus::pci::{
    ConfigFailure, ConfigSpace, Function, FunctionError, Identity, InventoryError,
    InventoryReleaseFailure,
};

struct ReadOnlyConfig(owned::Mapping);

fn mapping_error(error: owned::Error) -> ConfigError {
    ConfigError::before_effect(ConfigFailure::Mapping(error))
}

fn read_only() -> ConfigError {
    ConfigError::before_effect(ConfigFailure::Protection)
}

impl ReadOnlyConfig {
    fn address(&self, offset: u16, width: usize) -> Result<NonNull<u8>, ConfigError> {
        if !usize::from(offset).is_multiple_of(width) {
            return Err(ConfigError::before_effect(ConfigFailure::Access {
                offset,
                width,
            }));
        }
        self.0
            .address(usize::from(offset), width)
            .map_err(mapping_error)
    }

    fn retire(&mut self) -> Result<(), Error> {
        // SAFETY: every read finished synchronously; no pointer, view or
        // DMA/IRQ work leaves this read-only observation.
        unsafe { self.0.retire() }.map_err(Error::Mapping)
    }
}

impl ConfigSpace for ReadOnlyConfig {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        let address = self.address(offset, 1)?;
        // SAFETY: exact live lease and byte width, before retirement.
        Ok(unsafe { address.as_ptr().read_volatile() })
    }

    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        let address = self.address(offset, 2)?.cast::<u16>();
        // SAFETY: aperture pages are aligned and address checked the offset
        // and live two-byte span. No pointer survives the read.
        Ok(u16::from_le(unsafe { address.as_ptr().read_volatile() }))
    }

    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.0.read32(usize::from(offset)).map_err(mapping_error)
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

impl Source {
    /// Observe bridge and ARI topology without issuing a configuration writer.
    /// The bus owner keeps every mapping until acknowledged retirement.
    pub(crate) fn inventory(&self, window: &EcamWindow) -> Result<Vec<Identity>, Error> {
        Function::inventory_with(
            window,
            |address| {
                let (_, mapping) = self.config_mapping(address, Protection::ReadOnly)?;
                match Function::new(address, ReadOnlyConfig(mapping)) {
                    Ok(function) => Ok(Some(function)),
                    Err(mut refused) => {
                        refused.config.retire()?;
                        match refused.reason {
                            FunctionError::Absent => Ok(None),
                            FunctionError::ConfigurationRetry => Err(Error::NotReady(address)),
                            FunctionError::Access(error) => Err(Error::Config(error)),
                        }
                    }
                }
            },
            |mut function| {
                function
                    .config()
                    .retire()
                    .map_err(|error| InventoryReleaseFailure { error, function })
            },
        )
        .map_err(|failure| match failure.error {
            InventoryError::Open(error) | InventoryError::Release(error) => error,
            InventoryError::Configuration(error) => Error::Discovery(error),
        })
    }
}
