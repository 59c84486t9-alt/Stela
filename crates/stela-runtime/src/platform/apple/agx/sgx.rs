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
use alloc::vec;
use alloc::vec::Vec;

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
        .chain(family.mmu.configuration.iter().map(|&(offset, _)| offset));
    let covered = |offset: u64| {
        banks
            .iter()
            .any(|&(_, bytes, at)| (at..at + bytes).contains(&offset))
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

/// The `sgx` registers and the UAT they configure.
pub struct Sgx {
    lifecycle: LifecycleState,
    identity: Identity,
    family: &'static Family,
    model: &'static Model,
    interrupt_enable: u32,
    gating: u32,
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
            gating: 0,
            mmu_enabled: false,
            ttbat_page: 0,
            configuration: vec![0; gpu.family.mmu.configuration.len()],
            last_invalidate: 0,
            uat: Uat::new(model.uat_output_bits),
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
            GATING_CONTROL => self.gating,
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
            GATING_CONTROL => {
                if value & !GATING_BITS != 0 {
                    return Err("GPU gating control bit is not modeled");
                }
                self.gating = value;
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
                "sgx registers are 32-bit",
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
            return Err(fail("sgx registers are 32-bit"));
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
