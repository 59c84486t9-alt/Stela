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
use super::super::bus::{
    Access, Direction, Lifecycle, LifecycleState, MmioDevice, MmioError, Width, refuse,
};
use super::generation::{Family, Gpu, Identification, MMU_ENABLE, Mmu, Model};
use super::uat::{self, Uat};
use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

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
pub fn covers(family: &Family, banks: &[(u64, u64, u64)]) -> Result<(), &'static str> {
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
        Err("the sgx banks leave a modeled register unmapped")
    }
}

/// A GPU's identification registers ([`super::generation`] states each
/// SoC's values and their sources).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub generation: u8,
    pub variant: u8,
    pub revision: u8,
    /// Dies the clusters span; only [`Identification::Dies`] reports them.
    pub dies: u8,
    /// Clusters over every die.
    pub clusters: u8,
    pub cores: u8,
    pub frags: u8,
    pub gps: u8,
    /// Enabled cores, cluster 0 first, packed `cores` bits per cluster, one
    /// word per core-mask register of the family.
    pub core_mask: [u32; 3],
}

impl Identity {
    fn version(&self) -> u32 {
        u32::from(self.generation) << 24
            | u32::from(self.variant) << 16
            | u32::from(self.revision) << 8
    }
    fn counts_1(&self, identification: Identification) -> u32 {
        let middle = match identification {
            Identification::Clusters => u32::from(self.frags) << 8,
            Identification::Dies => {
                u32::from(self.dies) << 16 | u32::from(self.clusters / self.dies) << 8
            }
        };
        middle | u32::from(self.cores)
    }
    fn counts_2(&self) -> u32 {
        u32::from(self.gps) << 16
    }
    fn clusters(&self, identification: Identification) -> u32 {
        match identification {
            Identification::Clusters => u32::from(self.clusters) << 12,
            Identification::Dies => 0,
        }
    }
}

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
    fn read(&self, family: &Family, offset: u64) -> Result<u32, &'static str> {
        match offset {
            GATING_CONTROL => Ok(self.gating),
            FENDER_SLEEP if fender_sleep_supported(family) => Ok(self.sleep_request),
            FENDER_WAKE if fender_sleep_supported(family) => Ok(self.wake),
            _ if gifaf_status(family) == Some(offset) => Ok(if self.gpu_awake.get() {
                0
            } else {
                GIFAF_SLEEP_COMPLETE
            }),
            _ => Err("GFX native callback register read is not modeled"),
        }
    }
    fn write(&mut self, family: &Family, offset: u64, value: u32) -> Result<(), &'static str> {
        match offset {
            GATING_CONTROL if value & !GATING_BITS == 0 => self.gating = value,
            GATING_CONTROL => return Err("GPU gating control bit is not modeled"),
            FENDER_SLEEP if fender_sleep_supported(family) => {
                if value > 1 {
                    return Err("GPU Fender sleep request is not zero or one");
                }
                self.sleep_request = value;
                if value == 1 {
                    // Execution is synchronous and no unit retains an in-flight
                    // memory request at this hardware boundary. Completion is
                    // visible only after the actual GPU agent has been gated.
                    self.gpu_awake.set(false);
                }
            }
            FENDER_WAKE if fender_sleep_supported(family) => {
                if self.sleep_request != 0 {
                    return Err(
                        "GPU Fender wake while the sleep request remains asserted is not qualified",
                    );
                }
                if value != 1 {
                    return Err("GPU Fender wake operation is not modeled");
                }
                self.wake = value;
                self.gpu_awake.set(true);
            }
            _ => return Err("GFX native callback register write is not modeled"),
        }
        Ok(())
    }
}

/// Firmware access to the actual SGX instance, qualified by its physical banks.
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
    /// Bind the ASC's actual configured wrapper physical base. RTBuddy writes
    /// it into the WrAd firmware patch. A recovered family-specific callback
    /// additionally qualifies its private control word against the SGX banks.
    /// This qualifies ownership only; it does not model control-field effects.
    pub fn with_asc_wrapper(mut self, physical: u64) -> Result<Self, &'static str> {
        physical
            .checked_add(super::super::asc::WRAPPER_BYTES)
            .ok_or("GFX ASC wrapper physical aperture wraps")?;
        if self.asc_wrapper.is_some_and(|held| held != physical) {
            return Err("GFX native power owner cannot be rebound to a different ASC wrapper");
        }
        if let Some(offset) = self.family.model()?.native_asc_control {
            let control = physical
                .checked_add(offset)
                .ok_or("GFX native ASC control physical address wraps")?;
            if !self.banks.iter().any(|&(base, bytes, _)| {
                control
                    .checked_sub(base)
                    .and_then(|at| at.checked_add(8))
                    .is_some_and(|end| end <= bytes)
            }) {
                return Err("GFX native ASC control is not wholly inside a qualified SGX bank");
            }
        }
        self.asc_wrapper = Some(physical);
        Ok(self)
    }

    /// The declared physical ASC wrapper used by the original native mapping.
    pub fn asc_wrapper(&self) -> Option<u64> {
        self.asc_wrapper
    }

    /// The family's complete eight-byte native control word, if a recovered
    /// callback needs it. The mount must also check its final bus route.
    /// Absence does not qualify any other family's native control effects.
    pub fn native_asc_control(&self) -> Option<u64> {
        self.asc_wrapper?
            .checked_add(self.family.model().ok()?.native_asc_control?)
    }

    pub(super) fn family(&self) -> &'static Family {
        self.family
    }

    pub(super) fn check_reset(&self) -> Result<(), &'static str> {
        if !self.native.borrow().gpu_awake.get() {
            return Err("GFX firmware reset while native GPU sleep retains restore ownership");
        }
        Ok(())
    }

    fn logical(&self, physical: u64) -> Result<u64, &'static str> {
        self.logical_range(physical, 4)
    }

    fn logical_range(&self, physical: u64, width: u64) -> Result<u64, &'static str> {
        for &(base, bytes, offset) in &self.banks {
            if let Some(at) = physical.checked_sub(base)
                && at.checked_add(width).is_some_and(|end| end <= bytes)
            {
                return Ok(offset + at);
            }
        }
        Err("GFX firmware PIO does not target a mounted SGX bank")
    }

    /// Resolve a PIO word through the firmware's UAT permissions before any
    /// device effect. The AP descriptor's physical base is checked against the
    /// translation and then the concrete device geometry, never trusted as DMA.
    fn target(
        &self,
        port: &mut crate::platform::dma::Port<'_, '_>,
        region: &super::pio::Region,
        offset: u32,
        write: bool,
    ) -> Result<u64, &'static str> {
        if !self.native.borrow().available {
            return Err("GFX firmware PIO while PMGR inhibits SGX execution");
        }
        if !matches!(
            region.kind,
            super::pio::Kind::GFender | super::pio::Kind::GmGifaf
        ) {
            return Err("GFX native callback PIO region is not modeled");
        }
        let (va, expected) = region.word(offset, write)?;
        let physical = port
            .iommu
            .translate(port.memory, port.stream, va, va + 3, write, port.access)
            .map_err(|error| match error {
                crate::platform::dma::DmaError::Fault(_) => "GFX firmware PIO faults in the UAT",
                crate::platform::dma::DmaError::Memory => "GFX firmware PIO page table is not RAM",
                crate::platform::dma::DmaError::Unsupported(reason) => reason,
            })?;
        if physical != expected {
            return Err("GFX firmware PIO translation disagrees with its AP physical descriptor");
        }
        let logical = self.logical(physical)?;
        let kind_matches = match region.kind {
            super::pio::Kind::GFender => {
                matches!(logical, GATING_CONTROL | FENDER_SLEEP | FENDER_WAKE)
            }
            super::pio::Kind::GmGifaf => gifaf_status(self.family) == Some(logical),
            _ => false,
        };
        if !kind_matches {
            return Err("GFX native callback PIO kind disagrees with its target register");
        }
        Ok(logical)
    }

    /// Read a source-qualified native callback register. Unknown registers
    /// refuse; the RAM DMA port is used only for the UAT table walk.
    pub fn read(
        &self,
        port: &mut crate::platform::dma::Port<'_, '_>,
        region: &super::pio::Region,
        offset: u32,
    ) -> Result<u32, &'static str> {
        let logical = self.target(port, region, offset, false)?;
        self.native.borrow().read(self.family, logical)
    }

    pub fn write(
        &self,
        port: &mut crate::platform::dma::Port<'_, '_>,
        region: &super::pio::Region,
        offset: u32,
        value: u32,
    ) -> Result<(), &'static str> {
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
    pub fn new(gpu: &'static Gpu) -> Result<Self, &'static str> {
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
    pub fn handed_off(gpu: &'static Gpu, ttbat: u64, shared_l2: u64) -> Result<Self, &'static str> {
        let mut sgx = Self::new(gpu)?;
        let page = ttbat >> uat::PAGE_SHIFT;
        if ttbat == 0 || page >> sgx.mmu().ttbat_page_bits != 0 {
            return Err("GPU TTBAT outside the MMU's page field");
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
    pub fn firmware_power(&self, banks: &[(u64, u64, u64)]) -> Result<FirmwarePower, &'static str> {
        for (index, &(physical, bytes, offset)) in banks.iter().enumerate() {
            if bytes == 0
                || physical.checked_add(bytes).is_none()
                || offset.checked_add(bytes).is_none()
            {
                return Err("GFX firmware PIO bank has an empty or wrapping range");
            }
            for &(other, length, logical) in &banks[..index] {
                if physical < other + length && other < physical + bytes
                    || offset < logical + length && logical < offset + bytes
                {
                    return Err("GFX firmware PIO banks overlap");
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

    fn accessible(&self) -> Result<(), &'static str> {
        if !self.lifecycle.powered {
            return Err("SGX power is gated");
        }
        if !self.lifecycle.clocked {
            return Err("SGX clock is gated");
        }
        if self.lifecycle.reset {
            return Err("SGX reset is asserted");
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

    fn read32(&self, offset: u64) -> Result<u32, &'static str> {
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
            _ => return Err("sgx register is not modeled"),
        })
    }

    fn write32(&mut self, offset: u64, value: u32) -> Result<(), &'static str> {
        let mmu = self.mmu();
        let mmu_register = offset == MMU_ENABLE
            || offset == mmu.ttbat
            || self.configuration_slot(offset).is_some();
        let gpc = self.model.gpc;
        match offset {
            _ if offset == gpc + GPC_HOST_INTERRUPT_ENABLE => {
                if value & !GPC_HOST_INTERRUPTS != 0 {
                    return Err("GPC host-interrupt enable bit is not modeled");
                }
                self.interrupt_enable = value;
            }
            _ if offset == gpc + GPC_HOST_INTERRUPT_STATUS => {
                // Nothing is ever pending, so an acknowledgement clears nothing.
                if value & !GPC_HOST_INTERRUPTS != 0 {
                    return Err("GPC host-interrupt status bit is not modeled");
                }
            }
            GATING_CONTROL | FENDER_SLEEP | FENDER_WAKE => {
                self.native.borrow_mut().write(self.family, offset, value)?
            }
            _ if offset == mmu.invalidate => self.last_invalidate = value,
            _ if self.mmu_enabled && mmu_register => {
                return Err("reconfiguring an enabled GPU MMU is not modeled");
            }
            _ if offset == mmu.ttbat => {
                if value >> mmu.ttbat_page_bits != 0 {
                    return Err("TTBAT page number wider than the MMU's field");
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
                        return Err("GPU MMU enabled before its configuration is written");
                    }
                    self.uat.configure(ttbat)?;
                    self.mmu_enabled = true;
                }
                _ => return Err("GPU MMU enable value is not modeled"),
            },
            _ => match self.configuration_slot(offset) {
                Some((slot, wanted)) if value == wanted => self.configuration[slot] = value,
                Some(_) => return Err("GPU MMU configuration value is not modeled"),
                None => return Err("sgx register is not modeled"),
            },
        }
        Ok(())
    }
}

impl Lifecycle for Sgx {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        if proposed.reset && !self.lifecycle.reset
            || !proposed.powered && self.lifecycle.powered && !proposed.retention
        {
            return Err(
                "SGX physical reset or nonretained power loss requires protected UAT and firmware restore semantics",
            );
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
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        self.accessible().map_err(fail)?;
        if width != Width::Word {
            return Err(fail("sgx register access width is not qualified"));
        }
        self.write32(offset, value as u32).map_err(fail)
    }
}

#[cfg(test)]
mod tests {
    use super::super::generation::{self, GPUS};
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    const MMU_TTBAT: u64 = 0xd0_802c;
    const MMU_TTBA_INVALIDATE: u64 = 0xd0_8030;
    const CORE_MASK_0: u64 = 0xd0_1500;
    const CORE_MASK_1: u64 = 0xd0_1514;

    fn t8112() -> &'static Gpu {
        generation::by_chip(0x8112).unwrap()
    }

    fn read(sgx: &mut Sgx, offset: u64) -> Result<u64, MmioError> {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        sgx.read(offset, Width::Word, &mut access)
    }

    fn write(sgx: &mut Sgx, offset: u64, value: u32) -> Result<(), MmioError> {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        sgx.write(offset, Width::Word, u64::from(value), &mut access)
    }

    fn firmware_region_at(
        kind: super::super::pio::Kind,
        physical: u64,
        va: u64,
    ) -> super::super::pio::Region {
        use super::super::pio::Region;
        use super::super::ring::tests::Flat;
        let mut flat = Flat::new(0x1000, 0x2000);
        let descriptor = 0x1000 + 0x640 + kind as u64 * 0x28;
        flat.put_u64(descriptor, physical);
        flat.put_u64(descriptor + 8, va);
        flat.put_u32(descriptor + 0x10, 0xc000);
        flat.put_u32(descriptor + 0x14, 0xc000);
        flat.put_u32(descriptor + 0x20, 2);
        Region::read(&mut flat, 0x1000, kind).unwrap()
    }

    #[test]
    fn native_firmware_pio_walks_the_uat_and_shares_the_actual_ap_register() {
        use super::super::generation::{G13G, G13X, G14G, G14X, G15G};
        use crate::platform::dma::{Port, tests::Ram};
        let physical = 0x204000000;
        let base = 0x800000000;
        for family in [&G13G, &G13X, &G14G, &G14X, &G15G] {
            let gpu = if family == &G15G {
                // G15G's interface is recovered, but its real identity is not
                // admitted. Exercise that layout on an explicit test fixture.
                t8112()
            } else {
                GPUS.iter()
                    .find(|gpu| gpu.family == family && gpu.admitted().is_ok())
                    .unwrap()
            };
            let mut sgx = Sgx::handed_off(gpu, base, base + 0x8000).unwrap();
            sgx.family = family;
            sgx.model = family.model().unwrap();
            let power = sgx.firmware_power(&[(physical, 0x4000000, 0)]).unwrap();
            let region = firmware_region_at(
                super::super::pio::Kind::GFender,
                physical + 0xd04000,
                0x10000,
            );
            let mut ram = Ram::new(base, 0x10000);
            let [ttbr0, ttbr1] = uat::encode_gptbat(0, base + 0x4000, 0);
            ram.put_u64(base, ttbr0);
            ram.put_u64(base + 8, ttbr1);
            ram.put_u64(base + 0x4000, uat::encode_table(base + 0x8000));
            ram.put_u64(base + 0x8000, uat::encode_table(base + 0xc000));
            let pte = base + 0xc000 + 4 * 8;
            let flags = uat::Flags {
                access: uat::Access::Firmware,
                memory: uat::MemoryAttr::Device,
                global: true,
                pxn: true,
                uxn: true,
                gpu_access: true,
            };
            // RAM holds only page tables. A successful native MMIO access
            // therefore proves the target was not sent through DMA Memory.
            ram.put_u64(pte, uat::encode_pte(physical + 0xd04000, &flags));
            write(&mut sgx, GATING_CONTROL, 2).unwrap();
            let mut latch = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut latch);
            let mut access_native = |sgx: &mut Sgx, ram: &mut Ram, value| {
                let mut view = sgx.uat().agent(uat::Agent::Firmware);
                let mut port = Port {
                    iommu: &mut view,
                    stream: 0,
                    memory: ram,
                    access: &mut access,
                };
                if let Some(value) = value {
                    power.write(&mut port, &region, 0x2030, value)
                } else {
                    assert_eq!(power.read(&mut port, &region, 0x2030), Ok(2));
                    Ok(())
                }
            };
            access_native(&mut sgx, &mut ram, None).unwrap();
            // Missing PTE: no register effect; retry after fixing the table
            // succeeds without re-authoring or weakening the descriptor.
            ram.put_u64(pte, 0);
            assert!(
                access_native(&mut sgx, &mut ram, Some(4))
                    .unwrap_err()
                    .contains("UAT")
            );
            assert_eq!(read(&mut sgx, GATING_CONTROL), Ok(2));
            ram.put_u64(pte, uat::encode_pte(physical + 0xd08000, &flags));
            assert!(
                access_native(&mut sgx, &mut ram, Some(4))
                    .unwrap_err()
                    .contains("disagrees")
            );
            assert_eq!(read(&mut sgx, GATING_CONTROL), Ok(2));
            ram.put_u64(pte, uat::encode_pte(physical + 0xd04000, &flags));
            access_native(&mut sgx, &mut ram, Some(4)).unwrap();
            assert_eq!(read(&mut sgx, GATING_CONTROL), Ok(4));
            assert!(access_native(&mut sgx, &mut ram, Some(8)).is_err());
            assert_eq!(read(&mut sgx, GATING_CONTROL), Ok(4));
            // Retained PMGR gating inhibits this physical owner too.
            let paused = LifecycleState {
                clocked: false,
                retention: true,
                ..sgx.lifecycle
            };
            sgx.check_lifecycle(paused).unwrap();
            let mut latch = InterruptLatch::new();
            sgx.set_lifecycle(paused, &mut Access::new(0, 0, &mut latch));
            assert!(
                access_native(&mut sgx, &mut ram, Some(0))
                    .unwrap_err()
                    .contains("PMGR")
            );
            let running = LifecycleState {
                clocked: true,
                ..paused
            };
            sgx.set_lifecycle(running, &mut Access::new(0, 0, &mut latch));
            assert_eq!(read(&mut sgx, GATING_CONTROL), Ok(4));

            let mut latch = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut latch);
            let native_write =
                |sgx: &mut Sgx, ram: &mut Ram, access: &mut Access<'_>, offset, value| {
                    let mut view = sgx.uat().agent(uat::Agent::Firmware);
                    let mut port = Port {
                        iommu: &mut view,
                        stream: 0,
                        memory: ram,
                        access,
                    };
                    power.write(&mut port, &region, offset, value)
                };
            let translate = |sgx: &mut Sgx, ram: &mut Ram, access: &mut Access<'_>, agent| {
                use crate::platform::dma::Iommu;
                sgx.uat()
                    .agent(agent)
                    .translate(ram, 0, 0x12030, 0x12033, false, access)
            };
            assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_ok());
            if !fender_sleep_supported(family) {
                assert!(native_write(&mut sgx, &mut ram, &mut access, 0x74, 1).is_err());
                assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_ok());
                continue;
            }
            assert!(native_write(&mut sgx, &mut ram, &mut access, 0x74, 2).is_err());
            assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_ok());
            native_write(&mut sgx, &mut ram, &mut access, 0x74, 1).unwrap();
            assert!(
                power
                    .check_reset()
                    .unwrap_err()
                    .contains("restore ownership")
            );
            assert!(
                matches!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu),
                Err(crate::platform::dma::DmaError::Unsupported(reason)) if reason.contains("Fender sleep"))
            );
            assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Firmware).is_ok());
            assert!(
                native_write(&mut sgx, &mut ram, &mut access, 0x2020, 1)
                    .unwrap_err()
                    .contains("remains asserted")
            );
            assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_err());
            // Clearing the request is distinct from waking the GPU. The
            // original callback clears this request after polling completion.
            native_write(&mut sgx, &mut ram, &mut access, 0x74, 0).unwrap();
            assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_err());
            let status = gifaf_status(family).unwrap();
            let status_pte = base + 0xc000 + 8 * 8;
            ram.put_u64(
                status_pte,
                uat::encode_pte((physical + status) & !0x3fff, &flags),
            );
            // Account for the PIO base's sub-page offset; it is not a new
            // physical range and must survive the source mapping unchanged.
            let subpage = (status & !0xfff) & 0x3fff;
            let gifaf = firmware_region_at(
                super::super::pio::Kind::GmGifaf,
                physical + (status & !0xfff),
                0x20000 + subpage,
            );
            let native_status = |sgx: &mut Sgx, ram: &mut Ram, access: &mut Access<'_>| {
                let mut view = sgx.uat().agent(uat::Agent::Firmware);
                let mut port = Port {
                    iommu: &mut view,
                    stream: 0,
                    memory: ram,
                    access,
                };
                power.read(&mut port, &gifaf, 0x90)
            };
            assert_eq!(
                native_status(&mut sgx, &mut ram, &mut access),
                Ok(GIFAF_SLEEP_COMPLETE)
            );
            // A fault at the later wake PIO never clears retained inhibition.
            ram.put_u64(pte, 0);
            assert!(native_write(&mut sgx, &mut ram, &mut access, 0x2020, 1).is_err());
            assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_err());
            assert_eq!(
                native_status(&mut sgx, &mut ram, &mut access),
                Ok(GIFAF_SLEEP_COMPLETE)
            );
            ram.put_u64(pte, uat::encode_pte(physical + 0xd04000, &flags));
            native_write(&mut sgx, &mut ram, &mut access, 0x2020, 1).unwrap();
            assert!(translate(&mut sgx, &mut ram, &mut access, uat::Agent::Gpu).is_ok());
            assert_eq!(native_status(&mut sgx, &mut ram, &mut access), Ok(0));
            assert_eq!(power.check_reset(), Ok(()));
        }
    }

    #[test]
    fn native_asc_binding_uses_declared_placement_and_qualifies_the_whole_private_word() {
        let mut sgx = Sgx::new(t8112()).unwrap();
        write(&mut sgx, GATING_CONTROL, 4).unwrap();
        let power = sgx.firmware_power(&[(0x204000000, 0x4000000, 0)]).unwrap();
        assert_eq!(power.asc_wrapper(), None);
        assert_eq!(power.native_asc_control(), None);
        let bound = power.clone().with_asc_wrapper(0x206400000).unwrap();
        assert_eq!(bound.asc_wrapper(), Some(0x206400000));
        assert_eq!(bound.native_asc_control(), Some(0x206540120));
        assert_eq!(bound.logical(0x206540120), Ok(0x2540120));
        assert!(bound.clone().with_asc_wrapper(0x206400000).is_ok());
        assert!(bound.clone().with_asc_wrapper(0x206500000).is_err());
        assert!(power.clone().with_asc_wrapper(0x304000000).is_err());
        assert!(power.with_asc_wrapper(u64::MAX).is_err());
        // The first byte alone cannot qualify an eight-byte native register.
        let short = sgx.firmware_power(&[(0x204000000, 0x2540124, 0)]).unwrap();
        assert!(short.with_asc_wrapper(0x206400000).is_err());
        assert_eq!(read(&mut sgx, GATING_CONTROL), Ok(4));
    }

    #[test]
    fn firmware_power_owner_requires_complete_unambiguous_physical_geometry() {
        let sgx = Sgx::new(t8112()).unwrap();
        for banks in [
            vec![],
            vec![(0x204000000, 0x1000, 0)],
            vec![(0x204000000, GIFAF_IDLE_STATUS_G13_G14 + 1, 0)],
            vec![(0x204000000, 0x4000000, 0), (0x204000004, 4, 0x5000000)],
            vec![(0x204000000, 0x4000000, 0), (0x304000000, 4, 4)],
            vec![(0x204000000, 0x4000000, 0), (u64::MAX, 2, 0x5000000)],
        ] {
            assert!(sgx.firmware_power(&banks).is_err());
        }
        let power = sgx.firmware_power(&[(0x204000000, 0x4000000, 0)]).unwrap();
        assert!(power.logical(0x304d06030).is_err());
    }

    #[test]
    fn physical_gates_inhibit_the_mmu_and_preserve_boot_roots_until_released() {
        use crate::platform::dma::{Iommu, tests::Ram};
        let mut sgx = Sgx::handed_off(t8112(), 0x8_0000_0000, 0x8_0000_4000).unwrap();
        let active = sgx.lifecycle;
        let mut ram = Ram::new(0, 0x1000);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for gated in [
            LifecycleState {
                clocked: false,
                ..active
            },
            LifecycleState {
                quiesced: true,
                ..active
            },
            LifecycleState {
                powered: false,
                retention: true,
                ..active
            },
        ] {
            sgx.check_lifecycle(gated).unwrap();
            sgx.set_lifecycle(gated, &mut access);
            assert!(matches!(
                sgx.uat().agent(uat::Agent::Firmware).translate(
                    &mut ram,
                    0,
                    0x4000,
                    0x4007,
                    false,
                    &mut access
                ),
                Err(crate::platform::dma::DmaError::Unsupported(
                    "SGX DMA while PMGR inhibits execution"
                ))
            ));
            assert_eq!(sgx.uat().ttbat(), Some(0x8_0000_0000));
            assert_eq!(sgx.uat().shared_l2(), Some(0x8_0000_4000));
            assert!(
                sgx.check_lifecycle(LifecycleState {
                    reset: true,
                    ..active
                })
                .is_err()
            );
            sgx.set_lifecycle(active, &mut access);
            assert_eq!(sgx.read(MMU_ENABLE, Width::Word, &mut access), Ok(1));
        }
    }

    #[test]
    fn identification_decodes_as_readchipinfo_reads_it() {
        let mut sgx = Sgx::new(t8112()).unwrap();
        let version = read(&mut sgx, ID_VERSION).unwrap();
        assert_eq!(version >> 24, 5);
        assert_eq!((version >> 16) & 0xff, 2);
        // Revision B0: major 1 in bits 15:12, minor 0 in bits 11:8.
        assert_eq!((version >> 8) & 0xff, 0x10);
        let counts = read(&mut sgx, ID_COUNTS_1).unwrap();
        assert_eq!((counts & 0xff, (counts >> 8) & 0xff), (10, 10));
        assert_eq!((read(&mut sgx, ID_COUNTS_2).unwrap() >> 16) & 0xff, 4);
        assert_eq!((read(&mut sgx, ID_CLUSTERS).unwrap() >> 12) & 0xff, 1);
        assert_eq!(read(&mut sgx, CORE_MASK_0).unwrap(), 0x3ff);
        assert_eq!(read(&mut sgx, CORE_MASK_1).unwrap(), 0);
        // A word no AP code reads refuses, as do other widths and the
        // core-mask words of another family.
        assert!(read(&mut sgx, 0xd0_4008).is_err());
        assert!(read(&mut sgx, 0xe0_1500).is_err());
        assert!(read(&mut sgx, 0).is_err());
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert!(sgx.read(ID_VERSION, Width::Double, &mut access).is_err());
    }

    #[test]
    fn a_gpu_whose_family_is_not_modeled_has_no_registers() {
        for gpu in GPUS.iter().filter(|gpu| gpu.admitted().is_err()) {
            assert!(Sgx::new(gpu).is_err(), "{}", gpu.compatible);
        }
    }

    /// The register writes of `setupMMUConfig`, in its order.
    fn setup_mmu(sgx: &mut Sgx, ttbat: u64) -> Result<(), MmioError> {
        assert_eq!(read(sgx, MMU_ENABLE)?, 0);
        write(sgx, MMU_TTBAT, (ttbat >> 14) as u32 & ((1 << 26) - 1))?;
        for (offset, value) in [
            (0xd0_8014, 0x80d8),
            (0xd0_8018, 0x80d8),
            (0xd0_800c, 0),
            (0xd0_8010, 0),
            (0xd0_801c, 0),
            (0xd0_8020, 0),
            (0xd0_8024, 0),
            (0xd0_8028, 0),
            (0xd0_8008, 1),
            (0xd0_8004, 0x3ff),
        ] {
            write(sgx, offset, value)?;
            assert_eq!(read(sgx, offset)?, u64::from(value));
        }
        write(sgx, MMU_ENABLE, 1)
    }

    #[test]
    fn the_mmu_configuration_roots_the_uat_at_the_programmed_ttbat() {
        let mut sgx = Sgx::new(t8112()).unwrap();
        assert_eq!(sgx.uat().ttbat(), None);
        setup_mmu(&mut sgx, 0x8_1234_4000).unwrap();
        assert_eq!(read(&mut sgx, MMU_ENABLE).unwrap(), 1);
        assert_eq!(sgx.uat().ttbat(), Some(0x8_1234_4000));
        // A second setup sees the MMU enabled; reconfiguring refuses.
        assert!(write(&mut sgx, MMU_TTBAT, 0x1).is_err());
        // TTBA-cache invalidations are accepted and read back.
        write(&mut sgx, MMU_TTBA_INVALIDATE, 3 << 8 | 1).unwrap();
        assert_eq!(read(&mut sgx, MMU_TTBA_INVALIDATE).unwrap(), 0x301);
    }

    #[test]
    fn the_boot_stage_hands_off_the_mmu_setup_would_have_configured() {
        let mut configured = Sgx::new(t8112()).unwrap();
        setup_mmu(&mut configured, 0x8_0004_4000).unwrap();
        let mut handed = Sgx::handed_off(t8112(), 0x8_0004_4000, 0x8_0008_8000).unwrap();
        for offset in [MMU_ENABLE, MMU_TTBAT]
            .into_iter()
            .chain(t8112().family.mmu.configuration.iter().map(|&(o, _)| o))
        {
            assert_eq!(read(&mut handed, offset), read(&mut configured, offset));
        }
        assert_eq!(handed.uat().ttbat(), Some(0x8_0004_4000));
        // setupMMUConfig then returns at once; a rewrite refuses.
        assert!(write(&mut handed, MMU_TTBAT, 0x1).is_err());
        assert!(Sgx::handed_off(t8112(), 0, 0x8_0008_8000).is_err());
        assert!(Sgx::handed_off(t8112(), 0x8_0004_4001, 0x8_0008_8000).is_err());
        assert!(Sgx::handed_off(t8112(), 1 << 40, 0x8_0008_8000).is_err());
        assert!(Sgx::handed_off(t8112(), 0x8_0004_4000, 0x8_0008_8001).is_err());
    }

    #[test]
    fn an_unknown_mmu_configuration_refuses() {
        let mut sgx = Sgx::new(t8112()).unwrap();
        assert!(write(&mut sgx, 0xd0_8014, 0x80d9).is_err());
        // Enabling before the configuration is written refuses.
        write(&mut sgx, MMU_TTBAT, 0x2_0000).unwrap();
        assert!(write(&mut sgx, MMU_ENABLE, 1).is_err());
        assert!(write(&mut sgx, MMU_TTBAT, 1 << 26).is_err());
    }

    #[test]
    fn g14x_identification_counts_dies_and_its_fender_moves() {
        let gpu = generation::by_chip(0x6022).unwrap();
        let mut sgx = Sgx::new(gpu).unwrap();
        let version = read(&mut sgx, ID_VERSION).unwrap();
        assert_eq!((version >> 24, (version >> 16) & 0xff), (6, 4));
        // Two dies of four 10-core clusters; 0xd0401c names no count.
        assert_eq!(read(&mut sgx, ID_COUNTS_1).unwrap(), 2 << 16 | 4 << 8 | 10);
        assert_eq!(read(&mut sgx, ID_CLUSTERS).unwrap(), 0);
        let masks: alloc::vec::Vec<_> = [0xe0_1500, 0xe0_1504, 0xe0_1508]
            .into_iter()
            .map(|offset| read(&mut sgx, offset).unwrap())
            .collect();
        assert_eq!(masks, [0xffff_ffff, 0xffff_ffff, 0xffff]);
        write(&mut sgx, 0xe0_1010, 0b11).unwrap();
        assert_eq!(read(&mut sgx, 0xe0_1010).unwrap(), 0b11);
        assert_eq!(read(&mut sgx, 0xe0_1000).unwrap(), 0);
        assert!(read(&mut sgx, 0xd0_1000).is_err());
        assert!(read(&mut sgx, 0xd4_0e10).is_err());
    }

    #[test]
    fn fender_controls_hold_their_bits_and_raise_nothing() {
        const GPC: u64 = 0xd0_1000;
        let mut sgx = Sgx::new(t8112()).unwrap();
        assert_eq!(read(&mut sgx, GPC + GPC_PERFORMANCE_STATE).unwrap(), 0);
        write(&mut sgx, GPC + GPC_HOST_INTERRUPT_ENABLE, 0b101).unwrap();
        assert_eq!(
            read(&mut sgx, GPC + GPC_HOST_INTERRUPT_ENABLE).unwrap(),
            0b101
        );
        assert!(write(&mut sgx, GPC + GPC_HOST_INTERRUPT_ENABLE, 0b1000).is_err());
        assert_eq!(read(&mut sgx, GPC + GPC_HOST_INTERRUPT_STATUS).unwrap(), 0);
        assert!(read(&mut sgx, 0xe0_1000).is_err());
        // Disable then enable dynamic gating, as the Fender does.
        let gating = read(&mut sgx, GATING_CONTROL).unwrap() as u32;
        write(&mut sgx, GATING_CONTROL, gating | 0b100).unwrap();
        let gating = read(&mut sgx, GATING_CONTROL).unwrap() as u32;
        write(&mut sgx, GATING_CONTROL, gating & !0b110).unwrap();
        assert_eq!(read(&mut sgx, GATING_CONTROL).unwrap(), 0);
        assert!(write(&mut sgx, GATING_CONTROL, 1).is_err());
    }
}
