//! Track a shared algorithm's published configuration prefix without rollback.
use super::{ConfigEffect, ConfigError, ConfigSpace};

pub(super) struct Transaction<'a, C: ConfigSpace> {
    config: &'a mut C,
    last_write: Option<(u16, u8)>,
}
impl<'a, C: ConfigSpace> Transaction<'a, C> {
    pub(super) fn new(config: &'a mut C) -> Self {
        Self {
            config,
            last_write: None,
        }
    }
    fn failure(&self, mut error: ConfigError) -> ConfigError {
        if error.effect == ConfigEffect::None
            && let Some((offset, width)) = self.last_write
        {
            error.effect = ConfigEffect::WriteMayHaveApplied { offset, width };
        }
        error
    }
    fn checked_read<T>(
        &self,
        read: impl FnOnce(&C) -> Result<T, ConfigError>,
    ) -> Result<T, ConfigError> {
        read(self.config).map_err(|error| self.failure(error))
    }
    fn checked_write(
        &mut self,
        offset: u16,
        width: u8,
        write: impl FnOnce(&mut C) -> Result<(), ConfigError>,
    ) -> Result<(), ConfigError> {
        let result = write(self.config);
        result.map_err(|error| self.failure(error))?;
        self.last_write = Some((offset, width));
        Ok(())
    }
}
impl<C: ConfigSpace> ConfigSpace for Transaction<'_, C> {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.checked_read(|config| config.read8(offset))
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.checked_read(|config| config.read16(offset))
    }
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.checked_read(|config| config.read32(offset))
    }
    fn write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.checked_write(offset, 1, |config| config.write8(offset, value))
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.checked_write(offset, 2, |config| config.write16(offset, value))
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.checked_write(offset, 4, |config| config.write32(offset, value))
    }
}
