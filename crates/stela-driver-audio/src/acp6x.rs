// SPDX-License-Identifier: GPL-2.0-only
//! Native ACP6x Yellow Carp direct PDM capture. Register sequencing adapts AMD
//! Linux sound/soc/amd/yc/{pci-acp6x.c,acp6x-pdm-dma.c,acp6x-mach.c,acp6x.h}
//! at a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//! Copyright (C) 2021 Advanced Micro Devices, Inc. All rights reserved.
//!
//! This is the held-D0 direct path, not SOF firmware/IPC, ACP3x/5x, I2S or an
//! Apple audio frontend. Only 48kHz stereo signed 32-bit little-endian capture
//! is admitted. The caller supplies evaluated ACPI presence evidence;
//! DMI-only machine selection and system/runtime suspend remain separate.
//! DMA uses kept native RAM and an attached device domain. After an error or drop, mappings,
//! power and exclusive ownership must remain pinned until acknowledged reset
//! or shutdown. No destructor attempts device access or frees active DMA.
use super::acp_pdm::{self, DmaConfig, Profile};
pub use super::acp_pdm::{CAPTURE_FORMAT, Error, Identity, Phase, Position, Registers, State};
use crate::bus::{dma::mapping::DmaDomain, i2c::Timer};
use alloc::sync::Arc;
pub mod pci;
mod registers;
use registers::*;

#[doc(hidden)]
pub struct YellowCarp;
impl Profile for YellowCarp {
    const POWER_CONTROL: usize = POWER_CONTROL;
    const POWER_STATUS: usize = POWER_STATUS;
    const CLOCK: Option<usize> = Some(CLOCK);
    const ZSC_CONTROL: Option<usize> = None;
    const PRESERVE_INITIAL_IRQ_CONTROL: bool = true;
    const CLEAR_IRQ_CONTROL_ON_DISABLE: bool = false;
    const IRQ_ENABLE: usize = IRQ_ENABLE;
    const IRQ_CONTROL: usize = IRQ_CONTROL;
    const IRQ_STATUS: usize = IRQ_STATUS;
    const SRAM_TABLE: u32 = SRAM_TABLE;
    const ERROR_ENABLE: u32 = 0;
    const REQUIRE_DRAIN: bool = true;
    const PERIOD_DELIVERY: bool = false;
    fn supported(identity: Identity) -> bool {
        identity.supported()
    }
    fn class_allowed(_: [u8; 3]) -> bool {
        true
    }
    fn pin_mode<R: Registers>(registers: &mut R) -> Result<Option<u32>, Error> {
        let mode = registers.read32(PIN_CONFIG);
        if mode == u32::MAX {
            return Err(Error::RegisterUnavailable(PIN_CONFIG));
        }
        Ok(Some(mode))
    }
    fn validate_pin(mode: Option<u32>, identity: Identity) -> Result<(), Error> {
        let mode = mode.unwrap();
        if !matches!(mode, 4..=8 | 10..=14) || (identity.revision == 0x62 && mode >= 10) {
            return Err(Error::UnsupportedPinMode(mode));
        }
        Ok(())
    }
}
pub type Controller<R, T> = acp_pdm::Controller<R, T, YellowCarp>;

impl Identity {
    fn supported(self) -> bool {
        self.vendor == 0x1022
            && self.device == 0x15e2
            && matches!(self.revision, 0x60 | 0x6f | 0x62)
    }
}

/// Firmware observations for this function, not an ID-derived guess.
/// Pinned machine policy refuses `_WOV=0` even for its DMI overrides. This
/// bounded path requires successful nonzero `_WOV` and `AcpDmicConnected=1`;
/// the upstream positive DMI fallback is not implemented here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmicPresence {
    pub wov: Option<u64>,
    pub acp_dmic_connected: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ownership {
    ExclusiveDirect,
    FirmwareDsp,
    Unknown,
}
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub ownership: Ownership,
    pub presence: DmicPresence,
    /// Platform/IOMMU reachability ceiling. Bit63 is PTE validity, so
    /// the hardware encoding can represent at most 63 address bits.
    pub dma_address_bits: u8,
    /// Source WOV gain encoding 0..=3, applied preserving other MISC bits.
    pub gain: u8,
}

impl<R: Registers, T: Timer> acp_pdm::Controller<R, T, YellowCarp> {
    /// Claim without writing hardware. Initialization errors keep this owner.
    ///
    /// # Safety
    /// The platform must arbitrate the whole function away from firmware, SOF,
    /// AML/SMM and other CPUs and hold it in PCI D0 with coherent DMA/IOMMU
    /// reachability. Presence must come from this function's evaluated ACPI.
    /// `domain` is the isolated domain attached to this PCI requester.
    /// Registers and DMA RAM stay mapped while kept, including after errors
    /// or drop; release ownership only after acknowledged shutdown/reset.
    /// `domain` must provide posted-payload completion after engine stop;
    /// missing completion refuses before any capture mapping is published.
    /// Native PCI interrupt delivery must be contained (the supplied adapter
    /// requires INTx disabled and MSI/MSI-X disabled). This backend polls W1C
    /// status rather than registering an interrupt handler.
    pub unsafe fn claim(
        registers: R,
        timer: T,
        config: Config,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        if config.ownership != Ownership::ExclusiveDirect {
            return Err(Error::Ownership);
        }
        if !config.presence.wov.is_some_and(|value| value != 0)
            || config.presence.acp_dmic_connected != Some(1)
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
}

#[cfg(test)]
mod tests;
