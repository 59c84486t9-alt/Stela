// SPDX-License-Identifier: GPL-2.0-only
//! AMD Renoir ACP3.1 direct PDM capture, PCI 1022:15e2 revision01 class048000.
//! Adapted from Linux sound/soc/amd/renoir and amd/acp-config.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//! Copyright (C) 2020 Advanced Micro Devices, Inc.
//!
//! Explicit held-D0, polled continuous capture: 48kHz stereo S32_LE. The source PCM
//! hardware descriptor excludes S24_LE despite its broader DAI declaration.
//! Actual platform power, coherent requester DMA and firmware arbitration are
//! supplied by the native owner; firmware/SOF, I2S, PM and guest publication
//! remain separate. Raven revision00 is a different driver and never admitted.
use super::acp_pdm::{self, DmaConfig, Profile};
pub use super::acp_pdm::{
    CAPTURE_FORMAT, CapturePeriod, Error, Identity, Phase, Position, Registers, State,
};
pub use super::acp6x::Ownership;
use crate::bus::{dma::mapping::DmaDomain, i2c::Timer};
use alloc::sync::Arc;
pub mod pci;
mod registers;
use registers::*;

#[doc(hidden)]
pub struct Renoir;
impl Profile for Renoir {
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
    const ERROR_ENABLE: u32 = ERROR_IRQ;
    const REQUIRE_DRAIN: bool = true;
    const PERIOD_DELIVERY: bool = true;
    fn supported(identity: Identity) -> bool {
        identity.vendor == 0x1022 && identity.device == 0x15e2 && identity.revision == 1
    }
    fn class_allowed(class: [u8; 3]) -> bool {
        class == [4, 0x80, 0]
    }
    fn pin_mode<R: Registers>(_: &mut R) -> Result<Option<u32>, Error> {
        Ok(None)
    }
    fn validate_pin(_: Option<u32>, _: Identity) -> Result<(), Error> {
        Ok(())
    }
}

/// Actual SMBIOS strings. All fields are observed, including genuinely empty
/// strings; missing/unavailable SMBIOS does not grant the default board profile.
/// This information only excludes known source boards; it never grants a mic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoardIdentity<'a> {
    pub board_vendor: &'a str,
    pub product_name: &'a str,
    pub board_name: &'a str,
}
impl BoardIdentity<'_> {
    fn microphone_excluded(self) -> bool {
        self.board_vendor == "LENOVO"
            && (matches!(self.product_name, "81NB" | "81X2" | "81YQ")
                || matches!(self.board_name, "20T6CTO1WW" | "20NLCTO1WW"))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config<'a> {
    pub ownership: Ownership,
    /// Successful _WOV evaluation on this exact PCI function's ACPI handle.
    pub wov: Option<u64>,
    pub board: Option<BoardIdentity<'a>>,
    /// Actual result of source snd_amd_acp_find_config policy for this function.
    /// Only successful zero selects rn-pci-acp3x. Nonzero legacy/SOF selectors
    /// choose different drivers; unavailable selector evidence refuses too.
    pub acp_config: Option<u32>,
    pub dma_address_bits: u8,
    /// Source WOV gain field 0..=3; unrelated MISC bits are preserved.
    pub gain: u8,
}

pub type Controller<R, T> = acp_pdm::Controller<R, T, Renoir>;
impl<R: Registers, T: Timer> acp_pdm::Controller<R, T, Renoir> {
    /// Claim without hardware writes, allocations or inferred board services.
    ///
    /// # Safety
    /// The platform must exclusively arbitrate this exact revision01/class048000
    /// PCI function away from SOF/firmware, AML/SMM, other CPUs and workers. It
    /// must hold actual PCI D0 and board power/clocks throughout the owned epoch,
    /// and supply current same-function ACPI/selector and genuine SMBIOS facts.
    /// `domain` must be the actual isolated, coherent DMA domain attached to
    /// this requester; no PA/CPU/IOVA equality is inferred. The register provider
    /// retains the real UC/RW BAR, original stopped PCI owner and contained
    /// INTx/MSI/MSI-X delivery. Power, firmware exclusion and every resource stay
    /// retained after failures/drop until an acknowledged reset or shutdown.
    pub unsafe fn claim(
        registers: R,
        timer: T,
        config: Config<'_>,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        if config.ownership != Ownership::ExclusiveDirect || config.acp_config != Some(0) {
            return Err(Error::Ownership);
        }
        if !config.wov.is_some_and(|value| value != 0)
            || config.board.is_none_or(BoardIdentity::microphone_excluded)
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
    /// Quiesce and retain the original capture/DMA/native owners in PCI D0.
    /// The platform must keep the original board/firmware/resource epoch held.
    /// Default source policy uses `power_gate=false`; true additionally performs
    /// the pinned optional ACP PGFSM power-off handshake, with a real deadline.
    /// No PCI D-state, board-rail transition or system/runtime policy is inferred.
    pub fn suspend_held_d0(&mut self, power_gate: bool) -> Result<(), Error> {
        self.suspend_retained(power_gate)
    }
    /// Restore source power/reset/clock/IRQs and the same retained PTE/ring.
    /// A retained capture returns Prepared; explicit start performs source
    /// trigger RESUME in a new position/consumer epoch. No automatic DMA start,
    /// new allocation or fabricated interrupted PCM continuity is introduced.
    pub fn resume_held_d0(&mut self) -> Result<(), Error> {
        self.resume_retained()
    }
    /// Deliver one actual source-completed period while PDM/DMA keep running.
    /// Returns None until an acknowledged period IRQ and the source hardware
    /// pointer establish a whole available period. Coalesced events may expose
    /// multiple periods, each returned once in capture order. `destination`
    /// must have exactly the prepared period size.
    ///
    /// This follows the pinned Linux period-IRQ/ALSA-pointer/coherent-buffer
    /// contract. It does not infer completion from a bare counter, transfer
    /// exclusive CPU ownership, invalidate an active ring, or promise an atomic
    /// stereo-frame read. Actual coherent words are copied through the retained
    /// domain; pointer checks before/after detect producer wrap into the copied
    /// period. On any error discard the entire destination (it may be partly
    /// modified); no period is consumed, the first error and all owners remain,
    /// and an overrun needs explicit reset/reprepare before another start.
    pub fn capture_period(
        &mut self,
        destination: &mut [u8],
    ) -> Result<Option<CapturePeriod>, Error> {
        self.read_completed_period(destination)
    }
}

#[cfg(test)]
mod tests;
