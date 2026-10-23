// SPDX-License-Identifier: GPL-2.0-only
//! Dedicated ACP7.0/7.1/7.2 direct PDM: AMD 1022:15e2 revisions 70/71/72.
//! Native sequencing adapts Linux sound/soc/amd/ps/{pci-ps,ps-common,ps-pdm-dma}.c
//! and acp63.h at a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright (C) 2022, 2023, 2025 Advanced Micro Devices, Inc.
//!
//! The PS DMA engine shares ACP63 PTE/PCM layout; its power and ZSC/IRQ/PME
//! sequencing is distinct. This whole-function owner admits no active or
//! wake-enabled SoundWire manager. Mixed SoundWire/PDM service requires the
//! separate shared controller authority and is deliberately refused here.
//! SOF, I2S, ACP7D/E/F and an Apple audio frontend are separate backends.
use super::acp_pdm::{self, DmaConfig, Profile};
pub use super::acp_pdm::{
    CAPTURE_FORMAT, CapturePeriod, Error, Identity, Phase, Position, Registers, State,
};
pub use super::acp6x::Ownership;
pub use super::acp63::{Config, DmicChild, SoundWireOwnership, WovObservation};
use crate::bus::{dma::mapping::DmaDomain, i2c::Timer};
use alloc::sync::Arc;
pub mod pci;
mod registers;
use registers::*;

#[doc(hidden)]
pub struct Ps70;
impl Profile for Ps70 {
    const POWER_CONTROL: usize = POWER_CONTROL;
    const POWER_STATUS: usize = POWER_STATUS;
    const POWER_TIMEOUT_US: u64 = 2_000;
    const POWER_ON_REQUEST: u32 = registers::POWER_ON_REQUEST;
    fn power_on_request(status: u32) -> bool {
        status & POWER_STATUS_MASK != 0
    }
    const CLOCK: Option<usize> = None;
    const ZSC_CONTROL: Option<usize> = Some(ZSC_CONTROL);
    const CLEAR_CONTROL_ON_QUIET: bool = false;
    fn parked_control(control: u32) -> bool {
        // A failed init before CONTROL was enabled can still retire after an
        // actual reset, disabled address group1/BME, domain drain and parked ZSC.
        matches!(control, 0 | 1)
    }
    const ZSC_BEFORE_INTERRUPTS: bool = true;
    const PME_ENABLE: Option<usize> = Some(PME_ENABLE);
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
        identity.vendor == 0x1022
            && identity.device == 0x15e2
            && matches!(identity.revision, 0x70..=0x72)
    }
    fn class_allowed(class: [u8; 3]) -> bool {
        class == [4, 0x80, 0]
    }
    fn exclusive<R: Registers>(registers: &mut R) -> Result<(), Error> {
        for register in SOUNDWIRE_EXCLUSION {
            let value = registers.read32(register);
            if value == u32::MAX {
                return Err(Error::RegisterUnavailable(register));
            }
            if value != 0 {
                return Err(Error::Ownership);
            }
        }
        Ok(())
    }
    fn pin_mode<R: Registers>(registers: &mut R) -> Result<Option<u32>, Error> {
        let value = registers.read32(PIN_CONFIG);
        if value == u32::MAX {
            return Err(Error::RegisterUnavailable(PIN_CONFIG));
        }
        Ok(Some(value))
    }
    fn validate_pin(mode: Option<u32>, _: Identity) -> Result<(), Error> {
        let mode = mode.ok_or(Error::InvalidConfiguration)?;
        if matches!(mode, 4..=8 | 10..=14 | 17..=20) {
            Ok(())
        } else {
            Err(Error::UnsupportedPinMode(mode))
        }
    }
}

pub type Controller<R, T> = acp_pdm::Controller<R, T, Ps70>;
impl<R: Registers, T: Timer> acp_pdm::Controller<R, T, Ps70> {
    /// Claim the exact retained direct-PS function without hardware effects.
    ///
    /// # Safety
    /// The platform owns the exact class048000 function, actual PCI D0 and
    /// board power/clocks, coherent DMA root/domain and complete firmware/SOF/
    /// AML/SMM/CPU exclusion throughout the epoch. The real same-function
    /// selector, child and evaluated _WOV observations must satisfy Config's
    /// source contract. SoundWire absence/exclusion must come from its actual
    /// enumerator/controller owner, never an ID or a caller-invented boolean.
    /// The register check additionally refuses active/wake-enabled managers;
    /// no SoundWire owner may enable them after this check. Native interrupts
    /// must remain contained. Keep all roots/pins/native owners through failed
    /// stop/reset/drain or drop, until actual acknowledged retirement.
    pub unsafe fn claim(
        registers: R,
        timer: T,
        config: Config,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        if config.ownership != Ownership::ExclusiveDirect
            || config.acp_config != Some(0)
            || config.soundwire == SoundWireOwnership::ActiveOrUnknown
        {
            return Err(Error::Ownership);
        }
        if config.child
            != Some(DmicChild {
                address: 2,
                audio_device_type: 2,
            })
            || matches!(
                config.wov,
                WovObservation::Value(0) | WovObservation::Unavailable
            )
        {
            return Err(Error::MicrophoneAbsent);
        }
        Self::claim_profile(
            registers,
            timer,
            DmaConfig {
                dma_address_bits: config.dma_address_bits,
                gain: config.gain,
            },
            domain,
        )
    }
    /// Copy one source-completed period using the actual retained coherent
    /// domain, with pre/post-copy overrun checks. Discard destination on error.
    pub fn capture_period(
        &mut self,
        destination: &mut [u8],
    ) -> Result<Option<CapturePeriod>, Error> {
        self.read_completed_period(destination)
    }
    /// Quiet direct PDM and park ZSC under the same actual PCI D0/board epoch.
    /// This is controller PM; D3cold, S3/S0ix and SoundWire wake are not granted.
    /// CONTROL remains asserted as required by acp70_deinit, not ACP63's zero.
    pub fn suspend_held_d0(&mut self) -> Result<(), Error> {
        self.suspend_retained(false)
    }
    /// Revalidate the original native/domain epoch, perform ACP70 init and
    /// restore its retained PTE/ring. Explicit start begins a new PCM epoch.
    pub fn resume_held_d0(&mut self) -> Result<(), Error> {
        self.resume_retained()
    }
}
