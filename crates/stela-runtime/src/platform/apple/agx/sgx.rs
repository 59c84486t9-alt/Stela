//! The `sgx` register block (`gpu,t8112`, ADT `reg[0]` `0x2_0400_0000` +
//! 64 MiB; `reg[1]` `0x2_04d0_0000` + 128 KiB lies inside it): the registers
//! the AP touches directly. Everything else the GPU has is driven by the GFX
//! firmware, which Stela models natively, so every other offset refuses.
//!
//! Known (26A434 `AGXG14G`; every AP access goes through
//! `AGXAccelerator::readGFXReg32` 0x1b7f868 / `writeGFXReg32` 0x1b80ce0,
//! whose callers are listed in docs/research/agx.md §4):
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
//!   and reads it back.
//! - `G14::AGXFenderCommon` reads the GPC performance state from 0xd01000
//!   bits 3:0 (`getGPCPerformanceState` 0x1b64b0c), sets host-interrupt
//!   enables 0xd01010 bits 0..2 by type (`enableGPCHostInterrupts`
//!   0x1b649f0), and acknowledges 0xd01014 by writing back the nonzero
//!   status it read (`handleGPCHostInterrupts` 0x1b648dc).
//!   `AGXArmFenderChinook::disable/enableDynamicFenderGating` (0x1b643cc,
//!   0x1b644c0) set 0xd06030 bit 2, or clear bits 2:1.
//!
//! Public (Asahi `regs.rs`, `hw/t8112.rs` and m1n1 `agx/initdata.py`, pinned
//! in docs/research/agx.md): T8112 is G14 generation 5, variant G (2),
//! revision B0 (0x10), one cluster of 10 cores, 10 fragment units, 4 GPs.
//!
//! Model decisions:
//! - Identification subfields no source names (0xd04010 bits 31:16, 0xd04014
//!   bits 15:0 and 31:24, 0xd04018, 0xd0401c outside bits 19:12) read as zero.
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
//!   so no GPC host interrupts; none of the five `sgx` interrupt lines is
//!   raised. Enables and dynamic gating are held as written.
use super::super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::uat::{self, Uat};

const NAME: &str = "agx-sgx";

/// The block's span (ADT `reg[0]`).
pub const BYTES: u64 = 0x400_0000;

const GPC_PERFORMANCE_STATE: u64 = 0xd0_1000;
const GPC_HOST_INTERRUPT_ENABLE: u64 = 0xd0_1010;
const GPC_HOST_INTERRUPT_STATUS: u64 = 0xd0_1014;
/// Host-interrupt types 0..2 (`GPCHostInterruptType`).
const GPC_HOST_INTERRUPTS: u32 = 0b111;
const CORE_MASK_0: u64 = 0xd0_1500;
const CORE_MASK_1: u64 = 0xd0_1514;

const ID_VERSION: u64 = 0xd0_4000;
const ID_COUNTS_1: u64 = 0xd0_4010;
const ID_COUNTS_2: u64 = 0xd0_4014;
const ID_UNK18: u64 = 0xd0_4018;
const ID_CLUSTERS: u64 = 0xd0_401c;

const GATING_CONTROL: u64 = 0xd0_6030;
/// The dynamic-gating bits the Fender writes (bit 2 disables).
const GATING_BITS: u32 = 0b110;

const MMU_ENABLE: u64 = 0xd0_8000;
const MMU_TTBAT: u64 = 0xd0_802c;
const MMU_TTBA_INVALIDATE: u64 = 0xd0_8030;
/// The TTBAT page number field (`ubfx x2, x0, #14, #26`).
const TTBAT_PAGE_BITS: u32 = 26;

/// The fixed MMU configuration words and the only value each accepts.
const MMU_CONFIGURATION: [(u64, u32); 10] = [
    (0xd0_8004, 0x3ff),
    (0xd0_8008, 1),
    (0xd0_800c, 0),
    (0xd0_8010, 0),
    (0xd0_8014, 0x80d8),
    (0xd0_8018, 0x80d8),
    (0xd0_801c, 0),
    (0xd0_8020, 0),
    (0xd0_8024, 0),
    (0xd0_8028, 0),
];

/// The T8112 GPU's identity (see the module documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub generation: u8,
    pub variant: u8,
    pub revision: u8,
    pub clusters: u8,
    pub cores: u8,
    pub frags: u8,
    pub gps: u8,
    /// Enabled cores, cluster 0 first, packed `cores` bits per cluster.
    pub core_mask: [u32; 2],
}

/// T8112: G14G B0, one cluster of 10 cores.
pub const T8112: Identity = Identity {
    generation: 5,
    variant: 2,
    revision: 0x10,
    clusters: 1,
    cores: 10,
    frags: 10,
    gps: 4,
    core_mask: [0x3ff, 0],
};

impl Identity {
    fn version(&self) -> u32 {
        u32::from(self.generation) << 24
            | u32::from(self.variant) << 16
            | u32::from(self.revision) << 8
    }
    fn counts_1(&self) -> u32 {
        u32::from(self.frags) << 8 | u32::from(self.cores)
    }
    fn counts_2(&self) -> u32 {
        u32::from(self.gps) << 16
    }
    fn clusters(&self) -> u32 {
        u32::from(self.clusters) << 12
    }
}

/// The `sgx` registers and the UAT they configure.
pub struct Sgx {
    identity: Identity,
    interrupt_enable: u32,
    gating: u32,
    mmu_enabled: bool,
    ttbat_page: u32,
    configuration: [u32; MMU_CONFIGURATION.len()],
    last_invalidate: u32,
    uat: Uat,
}

impl Sgx {
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            interrupt_enable: 0,
            gating: 0,
            mmu_enabled: false,
            ttbat_page: 0,
            configuration: [0; MMU_CONFIGURATION.len()],
            last_invalidate: 0,
            uat: Uat::default(),
        }
    }

    /// The GPU as the boot stage hands it off: the MMU configured as
    /// `setupMMUConfig` would and enabled at the 16 KiB-aligned `ttbat`,
    /// with the shared TTBR1 window resolving from the page-directory page
    /// `shared_l2` (`gfx-shared-l2-region`, [`uat::SHARED_INDEX`]).
    pub fn handed_off(
        identity: Identity,
        ttbat: u64,
        shared_l2: u64,
    ) -> Result<Self, &'static str> {
        let page = ttbat >> uat::PAGE_SHIFT;
        if ttbat == 0 || page >> TTBAT_PAGE_BITS != 0 {
            return Err("GPU TTBAT outside the MMU's 26-bit page field");
        }
        let mut sgx = Self::new(identity);
        sgx.uat.configure(ttbat)?;
        sgx.uat.share_kernel_window(shared_l2)?;
        sgx.ttbat_page = page as u32;
        sgx.configuration = MMU_CONFIGURATION.map(|(_, value)| value);
        sgx.mmu_enabled = true;
        Ok(sgx)
    }

    /// The GPU address translator, for the GFX firmware's and the GPU's DMA.
    pub fn uat(&mut self) -> &mut Uat {
        &mut self.uat
    }

    fn configuration_slot(offset: u64) -> Option<(usize, u32)> {
        MMU_CONFIGURATION
            .iter()
            .enumerate()
            .find(|(_, (register, _))| *register == offset)
            .map(|(slot, &(_, value))| (slot, value))
    }

    fn read32(&self, offset: u64) -> Result<u32, &'static str> {
        let id = &self.identity;
        Ok(match offset {
            GPC_PERFORMANCE_STATE => 0,
            GPC_HOST_INTERRUPT_ENABLE => self.interrupt_enable,
            GPC_HOST_INTERRUPT_STATUS => 0,
            CORE_MASK_0 => id.core_mask[0],
            CORE_MASK_1 => id.core_mask[1],
            ID_VERSION => id.version(),
            ID_COUNTS_1 => id.counts_1(),
            ID_COUNTS_2 => id.counts_2(),
            ID_UNK18 => 0,
            ID_CLUSTERS => id.clusters(),
            GATING_CONTROL => self.gating,
            MMU_ENABLE => u32::from(self.mmu_enabled),
            MMU_TTBAT => self.ttbat_page,
            MMU_TTBA_INVALIDATE => self.last_invalidate,
            _ => match Self::configuration_slot(offset) {
                Some((slot, _)) => self.configuration[slot],
                None => return Err("sgx register is not modeled"),
            },
        })
    }

    fn write32(&mut self, offset: u64, value: u32) -> Result<(), &'static str> {
        match offset {
            GPC_HOST_INTERRUPT_ENABLE => {
                if value & !GPC_HOST_INTERRUPTS != 0 {
                    return Err("GPC host-interrupt enable bit is not modeled");
                }
                self.interrupt_enable = value;
            }
            GPC_HOST_INTERRUPT_STATUS => {
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
            MMU_TTBA_INVALIDATE => self.last_invalidate = value,
            _ if self.mmu_enabled && (MMU_ENABLE..MMU_TTBA_INVALIDATE).contains(&offset) => {
                return Err("reconfiguring an enabled GPU MMU is not modeled");
            }
            MMU_TTBAT => {
                if value >> TTBAT_PAGE_BITS != 0 {
                    return Err("TTBAT page number above 26 bits");
                }
                self.ttbat_page = value;
            }
            MMU_ENABLE => match value {
                0 => {}
                1 => {
                    let ttbat = u64::from(self.ttbat_page) << uat::PAGE_SHIFT;
                    let configured = MMU_CONFIGURATION
                        .iter()
                        .zip(self.configuration)
                        .all(|(&(_, wanted), held)| wanted == held);
                    if !configured || ttbat == 0 {
                        return Err("GPU MMU enabled before its configuration is written");
                    }
                    self.uat.configure(ttbat)?;
                    self.mmu_enabled = true;
                }
                _ => return Err("GPU MMU enable value is not modeled"),
            },
            _ => match Self::configuration_slot(offset) {
                Some((slot, wanted)) if value == wanted => self.configuration[slot] = value,
                Some(_) => return Err("GPU MMU configuration value is not modeled"),
                None => return Err("sgx register is not modeled"),
            },
        }
        Ok(())
    }
}

impl MmioDevice for Sgx {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(
        &mut self,
        offset: u64,
        width: Width,
        _access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
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
        if width != Width::Word {
            return Err(fail("sgx registers are 32-bit"));
        }
        self.write32(offset, value as u32).map_err(fail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

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
    fn identification_decodes_as_readchipinfo_reads_it() {
        let mut sgx = Sgx::new(T8112);
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
        // A word no AP code reads refuses, as do other widths.
        assert!(read(&mut sgx, 0xd0_4008).is_err());
        assert!(read(&mut sgx, 0).is_err());
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert!(sgx.read(ID_VERSION, Width::Double, &mut access).is_err());
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
        let mut sgx = Sgx::new(T8112);
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
        let mut configured = Sgx::new(T8112);
        setup_mmu(&mut configured, 0x8_0004_4000).unwrap();
        let mut handed = Sgx::handed_off(T8112, 0x8_0004_4000, 0x8_0008_8000).unwrap();
        for offset in [MMU_ENABLE, MMU_TTBAT]
            .into_iter()
            .chain(MMU_CONFIGURATION.map(|(offset, _)| offset))
        {
            assert_eq!(read(&mut handed, offset), read(&mut configured, offset));
        }
        assert_eq!(handed.uat().ttbat(), Some(0x8_0004_4000));
        // setupMMUConfig then returns at once; a rewrite refuses.
        assert!(write(&mut handed, MMU_TTBAT, 0x1).is_err());
        assert!(Sgx::handed_off(T8112, 0, 0x8_0008_8000).is_err());
        assert!(Sgx::handed_off(T8112, 0x8_0004_4001, 0x8_0008_8000).is_err());
        assert!(Sgx::handed_off(T8112, 1 << 40, 0x8_0008_8000).is_err());
        assert!(Sgx::handed_off(T8112, 0x8_0004_4000, 0x8_0008_8001).is_err());
    }

    #[test]
    fn an_unknown_mmu_configuration_refuses() {
        let mut sgx = Sgx::new(T8112);
        assert!(write(&mut sgx, 0xd0_8014, 0x80d9).is_err());
        // Enabling before the configuration is written refuses.
        write(&mut sgx, MMU_TTBAT, 0x2_0000).unwrap();
        assert!(write(&mut sgx, MMU_ENABLE, 1).is_err());
        assert!(write(&mut sgx, MMU_TTBAT, 1 << 26).is_err());
    }

    #[test]
    fn fender_controls_hold_their_bits_and_raise_nothing() {
        let mut sgx = Sgx::new(T8112);
        assert_eq!(read(&mut sgx, GPC_PERFORMANCE_STATE).unwrap(), 0);
        write(&mut sgx, GPC_HOST_INTERRUPT_ENABLE, 0b101).unwrap();
        assert_eq!(read(&mut sgx, GPC_HOST_INTERRUPT_ENABLE).unwrap(), 0b101);
        assert!(write(&mut sgx, GPC_HOST_INTERRUPT_ENABLE, 0b1000).is_err());
        assert_eq!(read(&mut sgx, GPC_HOST_INTERRUPT_STATUS).unwrap(), 0);
        // Disable then enable dynamic gating, as the Fender does.
        let gating = read(&mut sgx, GATING_CONTROL).unwrap() as u32;
        write(&mut sgx, GATING_CONTROL, gating | 0b100).unwrap();
        let gating = read(&mut sgx, GATING_CONTROL).unwrap() as u32;
        write(&mut sgx, GATING_CONTROL, gating & !0b110).unwrap();
        assert_eq!(read(&mut sgx, GATING_CONTROL).unwrap(), 0);
        assert!(write(&mut sgx, GATING_CONTROL, 1).is_err());
    }
}
