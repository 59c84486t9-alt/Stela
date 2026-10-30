//! The `sgx` register block: the registers the AP touches directly. Offsets
//! are relative to the node's `reg[0]` base, as `readGFXReg32` takes them;
//! on T8112 `reg[0]` (`0x2_0400_0000` + 64 MiB) spans them all, while on the
//! Pro/Max SoCs `reg[0]` is 1 MiB and they lie in `reg[1]`
//! (`0x2_04d0_0000`.., docs/research/agx.md §6). Everything else the GPU
//! has is driven by the GFX firmware, which Stela models natively, so every
//! other offset refuses.
//!
//! Known (26A434 `AGXG14G`; every AP access goes through
//! `AGXAccelerator::readGFXReg32` 0x1b7f868 / `writeGFXReg32` 0x1b80ce0,
//! whose callers are listed in docs/research/agx.md §4; the other families'
//! readings are in §6 and [`generation`]):
//! - `AGXAcceleratorG14::readChipInfo` (0x1b62f88) reads the identification
//!   words 0xd04000, 0xd04010, 0xd04014, 0xd04018 and 0xd0401c and the core
//!   mask at 0xd01500. It requires generation 5 (bits 31:24 of 0xd04000),
//!   takes the variant from bits 23:16 and the revision from bits 15:8, and
//!   publishes `num_cores` (0xd04010 bits 7:0), `num_frags` (bits 15:8),
//!   `num_gps` (0xd04014 bits 23:16) and `num_mgpus` (0xd0401c bits 19:12)
//!   (`getPropertyCoreConfigImpl` 0x1b08188..0x1b082c8).
//! - `AGXSecureMonitorG14::setupMMUConfig` (0x1b67828) returns at once when
//!   0xd08000 reads nonzero; otherwise it writes the TTBAT page number
//!   (`PA >> 14`, 26 bits) to 0xd0802c, 0x80d8 to 0xd08014 and 0xd08018, 0 to
//!   0xd0800c, 0xd08010, 0xd0801c..0xd08028, 1 to 0xd08008, 0x3ff to 0xd08004
//!   and finally 1 to 0xd08000, reading each back.
//!   `invalidateGPUTTBACache(a, b)` (0x1b67788) writes `a << 8 | b` to 0xd08030
//!   and reads it back. The family's [`Mmu`] gives these per kext.
//! - `G14::AGXFenderCommon` reads the GPC performance state from 0xd01000
//!   bits 3:0 (`getGPCPerformanceState` 0x1b64b0c), sets host-interrupt
//!   enables 0xd01010 bits 0..2 by type (`enableGPCHostInterrupts`
//!   0x1b649f0), and acknowledges 0xd01014 by writing back the nonzero
//!   status it read (`handleGPCHostInterrupts` 0x1b648dc). The G14X kext's
//!   Fender does the same at 0xe01000, 0xe01010 and 0xe01014
//!   ([`super::generation::Model::gpc`]).
//! - The G14X kext's identification words carry the dies, the clusters per
//!   die and the cores per cluster in 0xd04010
//!   ([`super::generation::Identification::Dies`]); its only other register
//!   read, the MCW status 0xd40e10 of `AGXAcceleratorG14X::handleMCWInterrupt`
//!   (an override the G14G kext stubs to return 0), is reached from the
//!   GPU's interrupt service, which the model never raises, so it refuses.
//!   `AGXArmFenderChinook::disable/enableDynamicFenderGating` (0x1b643cc,
//!   0x1b644c0) set 0xd06030 bit 2, or clear bits 2:1.
//!
//! Model decisions:
//! - The GPU must be admitted ([`generation::Gpu::admitted`]): its identity
//!   comes from the census, its MMU and core-mask registers from its family.
//! - Identification subfields no source names read as zero: 0xd04010 bits
//!   31:16 (31:20 under [`Identification::Dies`]), 0xd04014 bits 15:0 and
//!   31:24, 0xd04018, and 0xd0401c outside bits 19:12 (all of it under
//!   `Dies`).
//!   The kext multiplies some of them into its core configuration
//!   (`AGXGPUCoreConfig` +0x34, +0x38, +0x40, +0x48..+0x5c); a boot run shows
//!   whether zero is tolerated. **Unknown**, recorded in the research doc.
//! - The MMU accepts only the configuration `setupMMUConfig` writes; any other
//!   value refuses. Enabling it roots the [`Uat`] at the programmed TTBAT;
//!   reconfiguring an enabled MMU refuses. The UAT caches no walk, so a
//!   TTBA-cache invalidation has nothing to discard.
//! - The boot stage hands the GPU off with its MMU enabled at the TTBAT in
//!   `gpu-region-base` ([`Sgx::handed_off`]), as iBoot does for the GFX
//!   firmware it starts: the nub is `pre-loaded` and `running`, the kext sends
//!   the initdata pointer (`notifyFirmwareStarted`) without writing these
//!   registers, and SPTM's `uat_bootstrap` and Asahi's driver take the TTBAT
//!   from `gpu-region-base`. 0xd08000 then reads nonzero and `setupMMUConfig`
//!   returns at once.
//! - The model has one performance state (0), no GPC power transitions and
//!   so no GPC host interrupts; none of the `sgx` interrupt lines is raised.
//!   Enables and dynamic gating are held as written.
use super::generation::{Family, Gpu, MMU_ENABLE, Mmu, Model};
use super::uat::{self, Uat};
use crate::Result;
use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use stela_contracts::Refusal;
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};

const NAME: &str = "agx-sgx";

/// The GPC registers' offsets in the family's GPC block.
const GPC_PERFORMANCE_STATE: u64 = 0;
const GPC_HOST_INTERRUPT_ENABLE: u64 = 0x10;
const GPC_HOST_INTERRUPT_STATUS: u64 = 0x14;
/// Host-interrupt types 0..2 (`GPCHostInterruptType`).
const GPC_HOST_INTERRUPTS: u32 = 0b111;

const ID_VERSION: u64 = 0xd0_4000;
const ID_COUNTS_1: u64 = 0xd0_4010;
const ID_COUNTS_2: u64 = 0xd0_4014;
const ID_UNK18: u64 = 0xd0_4018;
const ID_CLUSTERS: u64 = 0xd0_401c;

const GATING_CONTROL: u64 = 0xd0_6030;
const FENDER_SLEEP: u64 = 0xd0_4074;
const FENDER_WAKE: u64 = 0xd0_6020;
const GIFAF_IDLE_STATUS_G13_G14: u64 = 0xd6_1090;
const GIFAF_IDLE_STATUS_G15: u64 = 0xd0_d090;
const GIFAF_SLEEP_COMPLETE: u32 = 0x204;
fn fender_sleep_supported(family: &Family) -> bool {
    matches!(family.name, "G13G" | "G14G" | "G15G")
}
fn gifaf_status(family: &Family) -> Option<u64> {
    match family.name {
        "G13G" | "G14G" => Some(GIFAF_IDLE_STATUS_G13_G14),
        "G15G" => Some(GIFAF_IDLE_STATUS_G15),
        _ => None,
    }
}
/// The dynamic-gating bits the Fender writes (bit 2 disables).
const GATING_BITS: u32 = 0b110;

/// Check that `banks` (`(physical base, bytes, register offset)`) cover
/// every register the model serves for `family`, which must be modeled.
pub fn covers(family: &Family, banks: &[(u64, u64, u64)]) -> Result<()> {
    let gpc = family.model()?.gpc;
    let fixed = [
        gpc + GPC_PERFORMANCE_STATE,
        gpc + GPC_HOST_INTERRUPT_ENABLE,
        gpc + GPC_HOST_INTERRUPT_STATUS,
        ID_VERSION,
        ID_COUNTS_1,
        ID_COUNTS_2,
        ID_UNK18,
        ID_CLUSTERS,
        GATING_CONTROL,
        MMU_ENABLE,
        family.mmu.ttbat,
        family.mmu.invalidate,
    ];
    let mut registers = fixed
        .into_iter()
        .chain(family.core_masks.iter().copied())
        .chain(family.mmu.configuration.iter().map(|&(offset, _)| offset))
        .chain(
            fender_sleep_supported(family)
                .then_some([FENDER_SLEEP, FENDER_WAKE])
                .into_iter()
                .flatten(),
        )
        .chain(gifaf_status(family));
    let covered = |offset: u64| {
        banks.iter().any(|&(_, bytes, at)| {
            at.checked_add(bytes).is_some_and(|end| {
                offset >= at
                    && offset
                        .checked_add(4)
                        .is_some_and(|word_end| word_end <= end)
            })
        })
    };
    if registers.all(covered) {
        Ok(())
    } else {
        Err(refuse!("the sgx banks leave a modeled register unmapped"))
    }
}

use stela_soc_data::agx::Identity;

/// Registers shared by the AP aperture and the native firmware callbacks.
#[derive(Debug)]
struct Native {
    gating: u32,
    available: bool,
    sleep_request: u32,
    wake: u32,
    gpu_awake: Rc<Cell<bool>>,
}
impl Default for Native {
    fn default() -> Self {
        Self {
            gating: 0,
            available: true,
            sleep_request: 0,
            wake: 0,
            gpu_awake: Rc::new(Cell::new(true)),
        }
    }
}

impl Native {
    fn read(&self, family: &Family, offset: u64) -> Result<u32> {
        match offset {
            GATING_CONTROL => Ok(self.gating),
            FENDER_SLEEP if fender_sleep_supported(family) => Ok(self.sleep_request),
            FENDER_WAKE if fender_sleep_supported(family) => Ok(self.wake),
            _ if gifaf_status(family) == Some(offset) => Ok(if self.gpu_awake.get() {
                0
            } else {
                GIFAF_SLEEP_COMPLETE
            }),
            _ => Err(refuse!("GFX native callback register read is not modeled")),
        }
    }
    fn write(&mut self, family: &Family, offset: u64, value: u32) -> Result<()> {
        match offset {
            GATING_CONTROL if value & !GATING_BITS == 0 => self.gating = value,
            GATING_CONTROL => return Err(refuse!("GPU gating control bit is not modeled")),
            FENDER_SLEEP if fender_sleep_supported(family) => {
                if value > 1 {
                    return Err(refuse!("GPU Fender sleep request is not zero or one"));
                }
                self.sleep_request = value;
                if value == 1 {
                    // Execution is synchronous and no unit keeps an in-flight
                    // memory request at this hardware boundary. Completion is
                    // visible only after the GPU agent has been gated.
                    self.gpu_awake.set(false);
                }
            }
            FENDER_WAKE if fender_sleep_supported(family) => {
                if self.sleep_request != 0 {
                    return Err(refuse!(
                        "GPU Fender wake while the sleep request remains asserted is not qualified"
                    ));
                }
                if value != 1 {
                    return Err(refuse!("GPU Fender wake operation is not modeled"));
                }
                self.wake = value;
                self.gpu_awake.set(true);
            }
            _ => return Err(refuse!("GFX native callback register write is not modeled")),
        }
        Ok(())
    }
}

/// Firmware access to the SGX instance, checked by its physical banks.
/// This is not an independent shadow register bank. Unsupported target registers
/// remain refusals, including all protected reset and rail-loss operations.
#[derive(Clone)]
pub struct FirmwarePower {
    family: &'static Family,
    banks: Vec<(u64, u64, u64)>,
    asc_wrapper: Option<u64>,
    native: Rc<RefCell<Native>>,
}

impl FirmwarePower {
    /// Bind the ASC's configured wrapper physical base. RTBuddy writes
    /// it into the WrAd firmware patch. A recovered family-specific callback
    /// additionally checks its private control word against the SGX banks.
    /// This checks ownership only; it does not model control-field effects.
    pub fn with_asc_wrapper(mut self, physical: u64) -> Result<Self> {
        physical
            .checked_add(super::super::asc::WRAPPER_BYTES)
            .ok_or(refuse!("GFX ASC wrapper physical aperture wraps"))?;
        if self.asc_wrapper.is_some_and(|held| held != physical) {
            return Err(refuse!(
                "GFX native power owner cannot be rebound to a different ASC wrapper"
            ));
        }
        if let Some(offset) = self.family.model()?.native_asc_control {
            let control = physical
                .checked_add(offset)
                .ok_or(refuse!("GFX native ASC control physical address wraps"))?;
            if !self.banks.iter().any(|&(base, bytes, _)| {
                control
                    .checked_sub(base)
                    .and_then(|at| at.checked_add(8))
                    .is_some_and(|end| end <= bytes)
            }) {
                return Err(refuse!(
                    "GFX native ASC control is not wholly inside a qualified SGX bank"
                ));
            }
        }
        self.asc_wrapper = Some(physical);
        Ok(self)
    }

    /// The declared physical ASC wrapper used by the original native mapping.
    #[cfg(test)]
    pub fn asc_wrapper(&self) -> Option<u64> {
        self.asc_wrapper
    }

    /// The family's complete eight-byte native control word, if a recovered
    /// callback needs it. The mount must also check its final bus route.
    /// Absence does not check any other family's native control effects.
    pub fn native_asc_control(&self) -> Option<u64> {
        self.asc_wrapper?
            .checked_add(self.family.model().ok()?.native_asc_control?)
    }

    pub(super) fn family(&self) -> &'static Family {
        self.family
    }

    pub(super) fn check_reset(&self) -> Result<()> {
        if !self.native.borrow().gpu_awake.get() {
            return Err(refuse!(
                "GFX firmware reset while native GPU sleep retains restore ownership"
            ));
        }
        Ok(())
    }
    #[cfg(test)]
    fn logical(&self, physical: u64) -> Result<u64> {
        self.logical_range(physical, 4)
    }
    #[cfg(test)]
    fn logical_range(&self, physical: u64, width: u64) -> Result<u64> {
        for &(base, bytes, offset) in &self.banks {
            if let Some(at) = physical.checked_sub(base)
                && at.checked_add(width).is_some_and(|end| end <= bytes)
            {
                return Ok(offset + at);
            }
        }
        Err(refuse!(
            "GFX firmware PIO does not target a mounted SGX bank"
        ))
    }

    /// Resolve a PIO word through the firmware's UAT permissions before any
    /// device effect. The AP descriptor's physical base is checked against the
    /// translation and then the concrete device geometry, never trusted as DMA.
    #[cfg(test)]
    fn target(
        &self,
        port: &mut stela_contracts::dma::Port<'_, '_>,
        region: &crate::research::agx_pio::Region,
        offset: u32,
        write: bool,
    ) -> Result<u64> {
        if !self.native.borrow().available {
            return Err(refuse!(
                "GFX firmware PIO while PMGR inhibits SGX execution"
            ));
        }
        if !matches!(
            region.kind,
            crate::research::agx_pio::Kind::GFender | crate::research::agx_pio::Kind::GmGifaf
        ) {
            return Err(refuse!("GFX native callback PIO region is not modeled"));
        }
        let (va, expected) = region.word(offset, write)?;
        let physical = port
            .iommu
            .translate(port.memory, port.stream, va, va + 3, write, port.access)
            .map_err(|error| match error {
                stela_contracts::dma::DmaError::Fault(code) => {
                    refuse!("GFX firmware PIO faults in the UAT", code)
                }
                stela_contracts::dma::DmaError::Memory => {
                    refuse!("GFX firmware PIO page table is not RAM")
                }
                stela_contracts::dma::DmaError::Unsupported(reason) => reason,
            })?;
        if physical != expected {
            return Err(refuse!(
                "GFX firmware PIO translation disagrees with its AP physical descriptor"
            ));
        }
        let logical = self.logical(physical)?;
        let kind_matches = match region.kind {
            crate::research::agx_pio::Kind::GFender => {
                matches!(logical, GATING_CONTROL | FENDER_SLEEP | FENDER_WAKE)
            }
            crate::research::agx_pio::Kind::GmGifaf => gifaf_status(self.family) == Some(logical),
            _ => false,
        };
        if !kind_matches {
            return Err(refuse!(
                "GFX native callback PIO kind disagrees with its target register"
            ));
        }
        Ok(logical)
    }

    /// Read a source-checked native callback register. Unknown registers
    /// refuse; the RAM DMA port is used only for the UAT table walk.
    #[cfg(test)]
    pub fn read(
        &self,
        port: &mut stela_contracts::dma::Port<'_, '_>,
        region: &crate::research::agx_pio::Region,
        offset: u32,
    ) -> Result<u32> {
        let logical = self.target(port, region, offset, false)?;
        self.native.borrow().read(self.family, logical)
    }
    #[cfg(test)]
    pub fn write(
        &self,
        port: &mut stela_contracts::dma::Port<'_, '_>,
        region: &crate::research::agx_pio::Region,
        offset: u32,
        value: u32,
    ) -> Result<()> {
        let logical = self.target(port, region, offset, true)?;
        self.native.borrow_mut().write(self.family, logical, value)
    }
}

/// The `sgx` registers and the UAT they configure.
pub struct Sgx {
    lifecycle: LifecycleState,
    identity: Identity,
    family: &'static Family,
    model: &'static Model,
    interrupt_enable: u32,
    native: Rc<RefCell<Native>>,
    mmu_enabled: bool,
    ttbat_page: u32,
    configuration: Vec<u32>,
    last_invalidate: u32,
    uat: Uat,
}

impl Sgx {
    /// The registers of `gpu`, which must be admitted.
    pub fn new(gpu: &'static Gpu) -> Result<Self> {
        let identity = gpu.admitted()?;
        let model = gpu.family.model()?;
        let native = Rc::new(RefCell::new(Native::default()));
        let mut uat = Uat::new(model.uat_output_bits);
        uat.set_gpu_availability(Rc::clone(&native.borrow().gpu_awake));
        Ok(Self {
            lifecycle: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: false,
            },
            identity,
            family: gpu.family,
            model,
            interrupt_enable: 0,
            native,
            mmu_enabled: false,
            ttbat_page: 0,
            configuration: vec![0; gpu.family.mmu.configuration.len()],
            last_invalidate: 0,
            uat,
        })
    }

    /// The GPU as the boot stage hands it off: the MMU configured as
    /// `setupMMUConfig` would and enabled at the 16 KiB-aligned `ttbat`,
    /// with the shared TTBR1 window resolving from the page-directory page
    /// `shared_l2` (`gfx-shared-l2-region`, [`uat::SHARED_INDEX`]).
    pub fn handed_off(gpu: &'static Gpu, ttbat: u64, shared_l2: u64) -> Result<Self> {
        let mut sgx = Self::new(gpu)?;
        let page = ttbat >> uat::PAGE_SHIFT;
        if ttbat == 0 || page >> sgx.mmu().ttbat_page_bits != 0 {
            return Err(refuse!("GPU TTBAT outside the MMU's page field"));
        }
        sgx.uat.configure(ttbat)?;
        sgx.uat.share_kernel_window(shared_l2)?;
        sgx.ttbat_page = page as u32;
        sgx.configuration = sgx
            .mmu()
            .configuration
            .iter()
            .map(|&(_, value)| value)
            .collect();
        sgx.mmu_enabled = true;
        Ok(sgx)
    }

    /// The GPU address translator, for the GFX firmware's and the GPU's DMA.
    pub fn uat(&mut self) -> &mut Uat {
        &mut self.uat
    }

    /// Bind firmware PIO to this exact GPU instance and its mounted banks.
    /// The geometry alone grants no additional register semantics.
    pub fn firmware_power(&self, banks: &[(u64, u64, u64)]) -> Result<FirmwarePower> {
        for (index, &(physical, bytes, offset)) in banks.iter().enumerate() {
            if bytes == 0
                || physical.checked_add(bytes).is_none()
                || offset.checked_add(bytes).is_none()
            {
                return Err(refuse!(
                    "GFX firmware PIO bank has an empty or wrapping range"
                ));
            }
            for &(other, length, logical) in &banks[..index] {
                if physical < other + length && other < physical + bytes
                    || offset < logical + length && logical < offset + bytes
                {
                    return Err(refuse!("GFX firmware PIO banks overlap"));
                }
            }
        }
        covers(self.family, banks)?;
        Ok(FirmwarePower {
            family: self.family,
            banks: banks.to_vec(),
            asc_wrapper: None,
            native: Rc::clone(&self.native),
        })
    }

    fn mmu(&self) -> &'static Mmu {
        &self.family.mmu
    }

    fn accessible(&self) -> Result<()> {
        if !self.lifecycle.powered {
            return Err(refuse!("SGX power is gated"));
        }
        if !self.lifecycle.clocked {
            return Err(refuse!("SGX clock is gated"));
        }
        if self.lifecycle.reset {
            return Err(refuse!("SGX reset is asserted"));
        }
        Ok(())
    }

    fn configuration_slot(&self, offset: u64) -> Option<(usize, u32)> {
        self.mmu()
            .configuration
            .iter()
            .enumerate()
            .find(|(_, (register, _))| *register == offset)
            .map(|(slot, &(_, value))| (slot, value))
    }

    fn core_mask_slot(&self, offset: u64) -> Option<usize> {
        self.family
            .core_masks
            .iter()
            .position(|&register| register == offset)
    }

    fn read32(&self, offset: u64) -> Result<u32> {
        let id = &self.identity;
        let mmu = self.mmu();
        let identification = self.model.identification;
        if let Some(word) = offset.checked_sub(self.model.gpc) {
            match word {
                GPC_PERFORMANCE_STATE | GPC_HOST_INTERRUPT_STATUS => return Ok(0),
                GPC_HOST_INTERRUPT_ENABLE => return Ok(self.interrupt_enable),
                _ => {}
            }
        }
        if let Some(slot) = self.core_mask_slot(offset) {
            return Ok(id.core_mask[slot]);
        }
        if let Some((slot, _)) = self.configuration_slot(offset) {
            return Ok(self.configuration[slot]);
        }
        Ok(match offset {
            ID_VERSION => id.version(),
            ID_COUNTS_1 => id.counts_1(identification),
            ID_COUNTS_2 => id.counts_2(),
            ID_UNK18 => 0,
            ID_CLUSTERS => id.clusters(identification),
            GATING_CONTROL | FENDER_SLEEP | FENDER_WAKE => {
                return self.native.borrow().read(self.family, offset);
            }
            _ if gifaf_status(self.family) == Some(offset) => {
                return self.native.borrow().read(self.family, offset);
            }
            MMU_ENABLE => u32::from(self.mmu_enabled),
            _ if offset == mmu.ttbat => self.ttbat_page,
            _ if offset == mmu.invalidate => self.last_invalidate,
            _ => return Err(refuse!("sgx register is not modeled")),
        })
    }

    fn write32(&mut self, offset: u64, value: u32) -> Result<()> {
        let mmu = self.mmu();
        let mmu_register = offset == MMU_ENABLE
            || offset == mmu.ttbat
            || self.configuration_slot(offset).is_some();
        let gpc = self.model.gpc;
        match offset {
            _ if offset == gpc + GPC_HOST_INTERRUPT_ENABLE => {
                if value & !GPC_HOST_INTERRUPTS != 0 {
                    return Err(refuse!("GPC host-interrupt enable bit is not modeled"));
                }
                self.interrupt_enable = value;
            }
            _ if offset == gpc + GPC_HOST_INTERRUPT_STATUS => {
                // Nothing is ever pending, so an acknowledgement clears nothing.
                if value & !GPC_HOST_INTERRUPTS != 0 {
                    return Err(refuse!("GPC host-interrupt status bit is not modeled"));
                }
            }
            GATING_CONTROL | FENDER_SLEEP | FENDER_WAKE => {
                self.native.borrow_mut().write(self.family, offset, value)?
            }
            _ if offset == mmu.invalidate => self.last_invalidate = value,
            _ if self.mmu_enabled && mmu_register => {
                return Err(refuse!("reconfiguring an enabled GPU MMU is not modeled"));
            }
            _ if offset == mmu.ttbat => {
                if value >> mmu.ttbat_page_bits != 0 {
                    return Err(refuse!("TTBAT page number wider than the MMU's field"));
                }
                self.ttbat_page = value;
            }
            MMU_ENABLE => match value {
                0 => {}
                1 => {
                    let ttbat = u64::from(self.ttbat_page) << uat::PAGE_SHIFT;
                    let configured = mmu
                        .configuration
                        .iter()
                        .zip(&self.configuration)
                        .all(|(&(_, wanted), &held)| wanted == held);
                    if !configured || ttbat == 0 {
                        return Err(refuse!(
                            "GPU MMU enabled before its configuration is written"
                        ));
                    }
                    self.uat.configure(ttbat)?;
                    self.mmu_enabled = true;
                }
                _ => return Err(refuse!("GPU MMU enable value is not modeled")),
            },
            _ => match self.configuration_slot(offset) {
                Some((slot, wanted)) if value == wanted => self.configuration[slot] = value,
                Some(_) => return Err(refuse!("GPU MMU configuration value is not modeled")),
                None => return Err(refuse!("sgx register is not modeled")),
            },
        }
        Ok(())
    }
}

impl Lifecycle for Sgx {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<()> {
        if proposed.reset && !self.lifecycle.reset
            || !proposed.powered && self.lifecycle.powered && !proposed.retention
        {
            return Err(refuse!(
                "SGX physical reset or nonretained power loss requires protected UAT and firmware restore semantics"
            ));
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, _access: &mut Access<'_>) {
        self.lifecycle = proposed;
        self.native.borrow_mut().available =
            proposed.powered && proposed.clocked && !proposed.quiesced && !proposed.reset;
        self.uat.set_available(
            proposed.powered && proposed.clocked && !proposed.quiesced && !proposed.reset,
        );
    }
}

impl MmioDevice for Sgx {
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(
        &mut self,
        offset: u64,
        width: Width,
        _access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        self.accessible()
            .map_err(|reason| refuse(NAME, offset, width, Direction::Read, reason))?;
        if width != Width::Word {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Read,
                "sgx register access width is not qualified",
            ));
        }
        self.read32(offset)
            .map(u64::from)
            .map_err(|reason| refuse(NAME, offset, width, Direction::Read, reason))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason: Refusal| refuse(NAME, offset, width, Direction::Write, reason);
        self.accessible().map_err(fail)?;
        if width != Width::Word {
            return Err(fail(refuse!("sgx register access width is not qualified")));
        }
        self.write32(offset, value as u32).map_err(fail)
    }
}

#[cfg(test)]
mod tests;
