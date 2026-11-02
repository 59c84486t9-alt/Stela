//! Original phase-specific configuration ownership; no naked native attach.
use super::{Address, ConfigError, ConfigSpace, EcamWindow, msi::MsiConfigSpace};
use crate::bus::mmio::owned::{Error as MappingError, Mapping, MappingView};
pub mod grant;
mod region;
use grant::{DriverGrant, PrepublicationGrant};
use region::Region;
pub struct OwnedConfig {
    region: Region<DriverGrant>,
}
pub struct UnpublishedConfig {
    region: Region<PrepublicationGrant>,
}
pub struct ConfigRetention {
    view: MappingView,
    custody: alloc::boxed::Box<dyn grant::ConfigEpoch>,
}
impl ConfigRetention {
    /// Refuse an original mapping that was dropped, quarantined or retired.
    pub fn check_live(&self) -> Result<(), MappingError> {
        self.custody.check()?;
        self.view.check_current()
    }

    /// Retain another view of this same original mapping in its checked
    /// context. This supplies no second writer or new reset/root permission.
    pub fn retain_epoch(&self) -> Result<Self, MappingError> {
        self.check_live()?;
        Ok(Self {
            custody: self.custody.retain()?,
            view: self.view.clone(),
        })
    }

    /// Compare this actual original configuration allocation/epoch, never
    /// equal BDFs, resource numbers or merely a shared mapping platform.
    pub fn same_allocation(&self, other: &Self) -> Result<bool, MappingError> {
        if !self.custody.same_epoch(other.custody.as_ref())? {
            return Ok(false);
        }
        self.view.shares_mapping(&other.view)
    }

    /// Compare actual installed mapping-platform provenance only. This
    /// establishes no endpoint/BAR, I/O, writer, stop or completion permission.
    pub fn shares_authority(&self, mapping: &Mapping) -> Result<bool, MappingError> {
        self.custody.check()?;
        mapping.shares_authority(&self.view)
    }
    /// Compare kept permissions, never caller-supplied numeric IDs.
    pub fn matches_mapping(&self, mapping: &Mapping) -> Result<bool, MappingError> {
        self.custody.check()?;
        mapping.shares_mapping(&self.view)
    }
}

impl OwnedConfig {
    /// Retain only actual endpoint metadata-denial storage before publication.
    /// It exposes no I/O, source/config backedge or completion/release proof.
    pub fn admission_close(&self) -> Result<super::assignment::AdmissionClose, MappingError> {
        self.region.admission_close()
    }
    pub fn seal_bus_master(&mut self) -> Result<(), ConfigError> {
        self.region.seal_bus_master()
    }
    pub fn seal_bus_routing(&mut self) -> Result<(), ConfigError> {
        self.region.seal_bus_routing()
    }
    /// # Safety
    /// Actual owning driver stop/reset, no old restart, current root/config
    /// binding and required payload completion have all been acknowledged.
    /// Native source still validates real requester/engine admission separately.
    pub unsafe fn release_bus_master_seal(&mut self) {
        // SAFETY: caller holds actual original admission/retirement receipts.
        unsafe { self.region.release_bus_master_seal() }
    }
    /// # Safety
    /// Complete original descendant cohort is contained/retired, new roots
    /// blocked, leaf seals enforced and actual bridge assignment remains frozen.
    pub unsafe fn release_bus_forwarding_seal(&mut self) -> Result<(), ConfigError> {
        // SAFETY: actual whole-source retirement proof, never endpoint stop.
        unsafe { self.region.release_bus_forwarding_seal() }
    }

    #[expect(
        clippy::result_large_err,
        reason = "attachment refusal returns the exact grant and mapping without failure-path allocation"
    )]
    pub fn attach(
        grant: DriverGrant,
        mapping: Mapping,
    ) -> Result<Self, (ConfigError, DriverGrant, Mapping)> {
        Region::attach(grant, mapping).map(|region| Self { region })
    }
    pub fn address(&self) -> Address {
        self.region.address()
    }
    pub fn window(&self) -> EcamWindow {
        self.region.window()
    }
    pub fn matches_binding(
        &self,
        binding: &super::requester::RequesterBinding,
    ) -> Result<bool, MappingError> {
        self.region.matches_binding(binding)
    }
    pub fn matches_retention(&self, retained: &ConfigRetention) -> Result<bool, MappingError> {
        self.region.matches_retention(retained)
    }
    pub fn retain_epoch(&self) -> Result<ConfigRetention, MappingError> {
        self.region.retain_epoch()
    }
    pub fn into_parts(self) -> (DriverGrant, Mapping) {
        self.region.into_parts()
    }
    /// # Safety
    /// Every actual config/device/raw pointer/DMA/IRQ/callback user has ended;
    /// caller owns complete original retirement, no new access may start.
    /// Failure keeps SAME owner and no actual grant/assignment release follows.
    pub unsafe fn retire(&mut self) -> Result<(), MappingError> {
        // SAFETY: caller supplies this exact original mapping retirement.
        unsafe { self.region.retire() }
    }
    pub fn try_read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.region.try_read8(offset)
    }
    pub fn try_write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.region.try_write8(offset, value)
    }
    pub fn try_read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.region.try_read16(offset)
    }
    pub fn try_write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.region.try_write16(offset, value)
    }
    pub fn try_read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.region.try_read32(offset)
    }
    pub fn try_write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.region.try_write32(offset, value)
    }
}
impl ConfigSpace for OwnedConfig {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.try_read8(offset)
    }
    fn write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.try_write8(offset, value)
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.try_read16(offset)
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.try_write16(offset, value)
    }
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.try_read32(offset)
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.try_write32(offset, value)
    }
}
impl UnpublishedConfig {
    pub fn seal_bus_master(&mut self) -> Result<(), ConfigError> {
        self.region.seal_bus_master()
    }
    pub fn seal_bus_routing(&mut self) -> Result<(), ConfigError> {
        self.region.seal_bus_routing()
    }

    #[expect(
        clippy::result_large_err,
        reason = "attachment refusal returns the exact unpublished grant and mapping without failure-path allocation"
    )]
    pub fn attach(
        grant: PrepublicationGrant,
        mapping: Mapping,
    ) -> Result<Self, (ConfigError, PrepublicationGrant, Mapping)> {
        Region::attach(grant, mapping).map(|region| Self { region })
    }
    pub fn address(&self) -> Address {
        self.region.address()
    }
    pub fn window(&self) -> EcamWindow {
        self.region.window()
    }
    pub fn matches_binding(
        &self,
        binding: &super::requester::RequesterBinding,
    ) -> Result<bool, MappingError> {
        self.region.matches_binding(binding)
    }
    pub fn matches_retention(&self, retained: &ConfigRetention) -> Result<bool, MappingError> {
        self.region.matches_retention(retained)
    }
    pub fn retain_epoch(&self) -> Result<ConfigRetention, MappingError> {
        self.region.retain_epoch()
    }
    pub fn into_parts(self) -> (PrepublicationGrant, Mapping) {
        self.region.into_parts()
    }
    /// # Safety
    /// Every actual config/device/raw pointer/DMA/IRQ/callback user has ended;
    /// caller owns complete original retirement, no new access may start.
    /// Failure keeps SAME owner and no actual grant/assignment release follows.
    pub unsafe fn retire(&mut self) -> Result<(), MappingError> {
        // SAFETY: caller supplies this exact original mapping retirement.
        unsafe { self.region.retire() }
    }
    pub fn try_read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.region.try_read8(offset)
    }
    pub fn try_write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.region.try_write8(offset, value)
    }
    pub fn try_read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.region.try_read16(offset)
    }
    pub fn try_write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.region.try_write16(offset, value)
    }
    pub fn try_read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.region.try_read32(offset)
    }
    pub fn try_write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.region.try_write32(offset, value)
    }
}
impl ConfigSpace for UnpublishedConfig {
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.try_read8(offset)
    }
    fn write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.try_write8(offset, value)
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.try_read16(offset)
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.try_write16(offset, value)
    }
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.try_read32(offset)
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.try_write32(offset, value)
    }
}
// SAFETY: actual final DriverGrant owns exclusive exact-width config access
// and source-owned operation/phase permissions. No unpublished IRQ admission.
unsafe impl MsiConfigSpace for OwnedConfig {}
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
#[cfg(test)]
mod tests;
