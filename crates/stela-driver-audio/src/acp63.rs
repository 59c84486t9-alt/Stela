// SPDX-License-Identifier: GPL-2.0-only
//! ACP6.3 dedicated Pink Sardine direct-PDM driver (AMD1022:15e2 revision63).
//! Adapted from Linux sound/soc/amd/ps/{pci-ps,ps-common,ps-pdm-dma}.c and
//! acp63.h at a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//! Copyright (C) 2022, 2023, 2025 Advanced Micro Devices, Inc.
//!
//! This is the selector-zero dedicated PDM path, not the separately selected
//! generic LEGACY/I2S/SOF/SoundWire drivers or ACP70/71/72 hardware. It keeps
//! a whole-function PCI D0/board/firmware epoch, checked requester DMA,
//! real ACPI child evidence and SoundWire exclusion. No CLKMUX access exists:
//! ACP63 uses the ZSC DSP control boundary during init/retirement.
use super::acp_pdm::{self, DmaConfig, Profile};
pub use super::acp_pdm::{
    CAPTURE_FORMAT, CapturePeriod, Error, Identity, Phase, Position, Registers, State,
};
pub use super::acp6x::Ownership;
use crate::bus::{dma::mapping::DmaDomain, i2c::Timer};
use alloc::sync::Arc;
pub mod pci;
pub(super) mod registers;
use registers::*;

#[doc(hidden)]
pub struct PinkSardine;
impl Profile for PinkSardine {
    const POWER_CONTROL: usize = POWER_CONTROL;
    const POWER_STATUS: usize = POWER_STATUS;
    const CLOCK: Option<usize> = None;
    const ZSC_CONTROL: Option<usize> = Some(ZSC_CONTROL);
    const PRESERVE_INITIAL_IRQ_CONTROL: bool = false;
    const CLEAR_IRQ_CONTROL_ON_DISABLE: bool = true;
    const IRQ_ENABLE: usize = IRQ_ENABLE;
    const IRQ_CONTROL: usize = IRQ_CONTROL;
    const IRQ_STATUS: usize = IRQ_STATUS;
    const SRAM_TABLE: u32 = SRAM_TABLE;
    const ERROR_ENABLE: u32 = ERROR_IRQ;
    const REQUIRE_DRAIN: bool = true;
    const PERIOD_DELIVERY: bool = true;
    fn supported(identity: Identity) -> bool {
        identity.vendor == 0x1022 && identity.device == 0x15e2 && identity.revision == 0x63
    }
    fn class_allowed(class: [u8; 3]) -> bool {
        class == [4, 0x80, 0]
    }
    fn pin_mode<R: Registers>(registers: &mut R) -> Result<Option<u32>, Error> {
        let mode = registers.read32(PIN_CONFIG);
        if mode == u32::MAX {
            return Err(Error::RegisterUnavailable(PIN_CONFIG));
        }
        Ok(Some(mode))
    }
    fn validate_pin(mode: Option<u32>, _: Identity) -> Result<(), Error> {
        let mode = mode.unwrap();
        if !matches!(mode, 4..=8 | 10..=14) {
            return Err(Error::UnsupportedPinMode(mode));
        }
        Ok(())
    }
}

/// The child at _ADR2 of this exact PCI function's ACPI companion.
/// A matching string/ID from another namespace or an invented child is no grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmicChild {
    pub address: u64,
    pub audio_device_type: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WovObservation {
    Value(u64),
    /// ACPI was evaluated; missing method or evaluation
    /// failure uses the pinned source's default-on policy AFTER child discovery.
    EvaluatedFailure,
    /// No working native evaluation service/evidence: never default-on.
    Unavailable,
}

/// Same-function SoundWire enumeration and whole-function arbitration.
/// A pin-mode value by itself supplies neither absence nor idle ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoundWireOwnership {
    EnumeratedAbsent,
    /// The real controller/firmware/worker owner has quiesced every SoundWire
    /// engine and kept exclusive exclusion throughout this PDM ownership.
    QuiescedExclusive,
    ActiveOrUnknown,
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub ownership: Ownership,
    /// Result of snd_amd_acp_find_config for this function: only zero
    /// selects the dedicated ps PCI driver, not LEGACY8/DMIC16 or SOF flags.
    pub acp_config: Option<u32>,
    pub child: Option<DmicChild>,
    pub wov: WovObservation,
    pub soundwire: SoundWireOwnership,
    pub dma_address_bits: u8,
    pub gain: u8,
}

impl Config {
    /// The direct-PDM claim conditions shared by ACP6.3 and ACP7.x: exclusive
    /// direct ownership with selector zero and SoundWire quiet, the DMIC child
    /// (address 2, audio device type 2) and a nonzero evaluated `_WOV`.
    pub(super) fn direct(&self) -> Result<DmaConfig, Error> {
        if self.ownership != Ownership::ExclusiveDirect
            || self.acp_config != Some(0)
            || self.soundwire == SoundWireOwnership::ActiveOrUnknown
        {
            return Err(Error::Ownership);
        }
        if self.child
            != Some(DmicChild {
                address: 2,
                audio_device_type: 2,
            })
            || matches!(
                self.wov,
                WovObservation::Value(0) | WovObservation::Unavailable
            )
        {
            return Err(Error::MicrophoneAbsent);
        }
        Ok(DmaConfig {
            dma_address_bits: self.dma_address_bits,
            gain: self.gain,
        })
    }
}

pub type Controller<R, T> = acp_pdm::Controller<R, T, PinkSardine>;
impl<R: Registers, T: Timer> acp_pdm::Controller<R, T, PinkSardine> {
    /// Claim without hardware effects or inferred firmware/platform resources.
    ///
    /// # Safety
    /// The kept native requester/BAR/domain must name this exact rev63,
    /// class048000 function and coherent RAM/root path. The platform owns
    /// PCI D0, board power/clocks, firmware/SOF/AML/SMM and other-CPU
    /// exclusion throughout the epoch. Child/_WOV/selector observations must
    /// come from this function's evaluated ACPI and source policy.
    /// SoundWire exclusion must be established by its controller/worker
    /// owner and same-function inventory, including mixed pin modes; no parallel
    /// SoundWire child can run under this whole-function reset/ATU/IRQ owner.
    /// Contain native INTx/MSI/MSI-X delivery and keep all roots, mappings,
    /// pins and firmware exclusion through failed stop/reset/drain or drop.
    pub unsafe fn claim(
        registers: R,
        timer: T,
        config: Config,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        Self::claim_profile(registers, timer, config.direct()?, domain)
    }
    /// Poll source period completion and copy one ordered period while
    /// DMA runs. Coalesced events, consumed position and pre/post-copy overwrite
    /// checks use the source ISR->PCM-pointer/coherent-buffer contract. Discard
    /// the entire destination on failure; it may be partly modified. No active
    /// buffer invalidation, CPU ownership or atomic stereo snapshot is promised.
    pub fn capture_period(
        &mut self,
        destination: &mut [u8],
    ) -> Result<Option<CapturePeriod>, Error> {
        self.read_completed_period(destination)
    }
    /// Source PDM/controller quiet with original PCI D0/board epoch kept.
    /// This dedicated source parks ZSC, without an invented CLKMUX or optional
    /// PGFSM power-off policy borrowed from a different generation's driver.
    pub fn suspend_held_d0(&mut self) -> Result<(), Error> {
        self.suspend_retained(false)
    }
    /// Restore the original PCI/domain epoch and PTE/ring into Prepared;
    /// explicit start is source trigger RESUME and begins a new capture epoch.
    pub fn resume_held_d0(&mut self) -> Result<(), Error> {
        self.resume_retained()
    }
}

#[cfg(test)]
mod tests;
