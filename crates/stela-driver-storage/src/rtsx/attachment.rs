// SPDX-License-Identifier: GPL-2.0-or-later
//! Same original RTSX graph retained before safe callbacks and on failed attachment.
use super::*;
pub struct AttachFailure {
    pub error: BlockError,
    pub owner: crate::Retained<FailedAttachment>,
}
impl core::fmt::Debug for AttachFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttachFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
pub enum FailedAttachment {
    Preparation(Preparation),
    Host(FailedHost),
}
pub struct Preparation {
    pub(super) function: Function,
    pub(super) registers: Option<crate::bus::mmio::Mmio>,
    pub(super) minimum: Rc<dyn crate::bus::pci::power::Timer>,
}
pub struct EnginePreparation {
    pub(super) pci: Box<dyn Pci>,
    pub(super) registers: Box<dyn Registers>,
    pub(super) config: controller::Configuration,
    pub(super) clock: Clock,
    pub(super) minimum: Rc<dyn crate::bus::pci::power::Timer>,
    pub(super) location: String,
}
pub enum FailedHost {
    Preparation(EnginePreparation),
    Host(Host),
}
pub struct HostFailure {
    pub error: BlockError,
    pub owner: crate::Retained<FailedHost>,
}
impl core::fmt::Debug for HostFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HostFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
