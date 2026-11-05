// SPDX-License-Identifier: GPL-2.0-or-later
//! Original SDHCI preparation and failed graph owners; no live host authority.
use super::*;

pub use crate::Retained;

/// Exact owned failure, including the same PCI/mapping/minimum graph.
pub struct OwnedAttachFailure {
    pub error: BlockError,
    pub owner: Retained<FailedAttachment>,
}
impl core::fmt::Debug for OwnedAttachFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnedAttachFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
pub enum FailedAttachment {
    Function(FunctionPreparation),
    Preparation(OwnedPreparation),
    Host(FailedHost),

    ControlledSlots(ControlledSlots),
}
pub struct ControlledSlots {
    pub(super) control: Control,
    pub(super) mappings: Vec<crate::bus::mmio::Mmio>,
    pub(super) minimum: Rc<dyn crate::bus::pci::power::Timer>,
}
impl ControlledSlots {
    pub fn slot_count(&self) -> usize {
        self.mappings.len()
    }
    pub fn minimum_delay(&self) -> &Rc<dyn crate::bus::pci::power::Timer> {
        &self.minimum
    }
    pub fn last_failure(&self) -> Option<BlockError> {
        self.control.borrow().healthy().err()
    }
}

/// A failed preparation retains every actual resource acquired so far.
#[must_use]
pub struct SlotPreparation {
    pub(super) registers: Box<dyn Registers>,
    pub(super) clock: Clock,
    pub(super) minimum: Rc<dyn crate::bus::pci::power::Timer>,
    pub(super) location: String,
    pub(super) profile: Profile,
    pub(super) controller: Option<Control>,
    pub(super) data: Option<DmaBuffer>,
    pub(super) descriptors: Option<DmaBuffer>,
}
impl core::fmt::Debug for SlotPreparation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlotPreparation")
            .field("location", &self.location)
            .field("data_allocated", &self.data.is_some())
            .field("descriptors_allocated", &self.descriptors.is_some())
            .finish_non_exhaustive()
    }
}
#[must_use]
pub enum FailedHost {
    Preparation(SlotPreparation),
    Host(Host),
}
pub struct HostFailure {
    pub error: BlockError,
    pub owner: Retained<FailedHost>,
}
impl core::fmt::Debug for HostFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HostFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
/// Real mapped GLI inputs before preparation grants a usable host.
pub struct OwnedPreparation {
    pub(super) function: Function,
    pub(super) registers: crate::bus::mmio::Mmio,
    pub(super) minimum: Rc<dyn crate::bus::pci::power::Timer>,
    pub(super) clock: Clock,
    pub(super) stage: PreparationStage,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationStage {
    Mapped,
    ProfileInitialization,
}
impl OwnedPreparation {
    pub fn stage(&self) -> PreparationStage {
        self.stage
    }
}
pub struct FunctionPreparation {
    pub(super) function: Function,
    pub(super) minimum: Rc<dyn crate::bus::pci::power::Timer>,
    pub(super) mappings: Vec<crate::bus::mmio::Mmio>,
}
pub(super) fn refused_preparation(
    error: BlockError,
    owner: Retained<FunctionPreparation>,
) -> OwnedAttachFailure {
    OwnedAttachFailure {
        error,
        owner: Retained::new(FailedAttachment::Function(owner.into_inner())),
    }
}
