//! The Apple GPUs 26A434 supports: each SoC's `sgx` compatible, the AGX kext
//! its kernelcache links, the GFX firmware its BuildManifest names, and the
//! facts each kext fixes about the AP-visible interface (docs/research/agx.md
//! §6, the census of all 59 board DeviceTrees and all 13 AGX kexts).
//!
//! Known (every 26A434 kernelcache, `AGXAccelerator*::readChipInfo`,
//! `AGXSecureMonitor*::setupMMUConfig`/`invalidateGPUTTBACache` and
//! `AGXArmFirmware::initFirmwareData` of each kext; offsets per kext in §6):
//! - every kext reads the identification words at 0xd04000.. and requires
//!   one generation in bits 31:24 of 0xd04000 ([`Family::generations`]);
//! - G13's MMU block puts the TTBAT page at 0xd08024 and the TTBA-cache
//!   invalidation at 0xd08028 behind eight fixed words; G14 onwards use
//!   0xd0802c and 0xd08030 behind ten ([`Mmu`]). The page field is 26 bits on
//!   the G13G and G14G kexts and 28 bits on every other;
//! - the initdata root's first word differs between interface revisions; the
//!   G13G, G13X and G14G kexts write the same one ([`Family::initdata_magic`]).
//!
//! A family is admitted ([`Gpu::admitted`]) only when every layout the GFX
//! firmware model and the `sgx` model use has been checked against that
//! family's own kext and firmware. Today that is G14G alone; every other
//! family is named here with the facts recovered so far and stays hidden
//! by the loader, its refusal naming what is missing.

use super::sgx::Identity;

/// The MMU block's layout (`setupMMUConfig`, `invalidateGPUTTBACache`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mmu {
    /// The TTBAT physical page number register.
    pub ttbat: u64,
    /// Width of its page-number field (`ubfx x2, x0, #14, #bits`).
    pub ttbat_page_bits: u32,
    /// The TTBA-cache invalidation register (`a << 8 | b`).
    pub invalidate: u64,
    /// The fixed configuration words `setupMMUConfig` writes, with the only
    /// value each accepts.
    pub configuration: &'static [(u64, u32)],
}

/// The MMU enable, read first by every `setupMMUConfig` (nonzero skips it).
pub const MMU_ENABLE: u64 = 0xd0_8000;

/// G13's fixed words (`AGXSecureMonitorG13::setupMMUConfig`).
const G13_MMU_CONFIGURATION: [(u64, u32); 8] = [
    (0xd0_800c, 0x80d8),
    (0xd0_8010, 0x80d8),
    (0xd0_8004, 0),
    (0xd0_8008, 0),
    (0xd0_8014, 0),
    (0xd0_8018, 0),
    (0xd0_801c, 0),
    (0xd0_8020, 0),
];

/// G14 and later (`AGXSecureMonitorG14::setupMMUConfig` and its successors).
const G14_MMU_CONFIGURATION: [(u64, u32); 10] = [
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
];

const fn g13_mmu(ttbat_page_bits: u32) -> Mmu {
    Mmu {
        ttbat: 0xd0_8024,
        ttbat_page_bits,
        invalidate: 0xd0_8028,
        configuration: &G13_MMU_CONFIGURATION,
    }
}

const fn g14_mmu(ttbat_page_bits: u32) -> Mmu {
    Mmu {
        ttbat: 0xd0_802c,
        ttbat_page_bits,
        invalidate: 0xd0_8030,
        configuration: &G14_MMU_CONFIGURATION,
    }
}

/// The core-mask words of G13 and G14G (`AGXAcceleratorG13/G14::
/// readChipInfo`: 0xd01500 and the word 0x14 above it) and of G14X onwards
/// (0xe01500 and the two words after it; Public, Asahi `regs.rs`
/// `CORE_MASKS_G14X`).
const G13_G14G_CORE_MASKS: [u64; 2] = [0xd0_1500, 0xd0_1514];
const G14X_CORE_MASKS: [u64; 3] = [0xe0_1500, 0xe0_1504, 0xe0_1508];

/// The initdata root magic of the G13G, G13X and G14G kexts.
pub const MAGIC_G13_G14G: u64 = 0x0c8a_6342_8392_04c8;

/// Whether the model implements a family's interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interface {
    /// Every layout the models use is checked against this family.
    Modeled,
    /// Not admitted, for the stated reason.
    Unrecovered(&'static str),
}

/// One AGX kext of the 26A434 kernelcaches and the interface it fixes.
#[derive(Debug, PartialEq, Eq)]
pub struct Family {
    /// The kext's family name (`AGX<name>`).
    pub name: &'static str,
    /// The kext's bundle identifier.
    pub kext: &'static str,
    /// The kernelcache that links it (`kernelcache.release.<kernelcache>`).
    pub kernelcache: &'static str,
    /// The generations `readChipInfo` accepts in 0xd04000 bits 31:24.
    pub generations: &'static [u8],
    /// The core-mask words, cluster 0's cores first (`readChipInfo`).
    pub core_masks: &'static [u64],
    pub mmu: Mmu,
    /// The initdata root's first word, when it is a constant the kext
    /// writes (`AGXArmFirmware::initFirmwareData`); `None` when the kext
    /// builds it otherwise and the census has not recovered it.
    pub initdata_magic: Option<u64>,
    pub interface: Interface,
}

/// One SoC's GPU.
#[derive(Debug, PartialEq, Eq)]
pub struct Gpu {
    /// The `sgx` node's `compatible`.
    pub compatible: &'static str,
    /// The SoC's ApChipID.
    pub chip_id: u16,
    pub family: &'static Family,
    /// The GFX firmware the BuildManifest names (`Firmware/agx/<name>.im4p`).
    pub firmware: &'static str,
    /// The identification the `sgx` registers report, when a source states
    /// it.
    pub identity: Option<Identity>,
}

const NOT_CHECKED: &str = "its GFX firmware layouts have not been checked against the model's";

pub const G13G: Family = Family {
    name: "G13G",
    kext: "com.apple.AGXG13G",
    kernelcache: "mac13g",
    generations: &[4],
    core_masks: &G13_G14G_CORE_MASKS,
    mmu: g13_mmu(26),
    initdata_magic: Some(MAGIC_G13_G14G),
    interface: Interface::Unrecovered(NOT_CHECKED),
};
pub const G13X: Family = Family {
    name: "G13X",
    kext: "com.apple.AGXG13X",
    kernelcache: "mac13j",
    generations: &[4],
    core_masks: &G13_G14G_CORE_MASKS,
    mmu: g13_mmu(28),
    initdata_magic: Some(MAGIC_G13_G14G),
    interface: Interface::Unrecovered(NOT_CHECKED),
};
pub const G14G: Family = Family {
    name: "G14G",
    kext: "com.apple.AGXG14G",
    kernelcache: "mac14g",
    generations: &[5],
    core_masks: &G13_G14G_CORE_MASKS,
    mmu: g14_mmu(26),
    initdata_magic: Some(MAGIC_G13_G14G),
    interface: Interface::Modeled,
};
pub const G14X: Family = Family {
    name: "G14X",
    kext: "com.apple.AGXG14X",
    kernelcache: "mac14j",
    generations: &[6],
    core_masks: &G14X_CORE_MASKS,
    mmu: g14_mmu(28),
    initdata_magic: Some(0x0c8a_636f_0494_04b8),
    interface: Interface::Unrecovered(NOT_CHECKED),
};
pub const G15G: Family = Family {
    name: "G15G",
    kext: "com.apple.AGXG15G",
    kernelcache: "mac15g",
    generations: &[7],
    core_masks: &G14X_CORE_MASKS,
    mmu: g14_mmu(28),
    initdata_magic: Some(0x0c8a_636f_0394_04b8),
    interface: Interface::Unrecovered(NOT_CHECKED),
};
pub const G15S: Family = Family {
    name: "G15S",
    kext: "com.apple.AGXG15S",
    kernelcache: "mac15s",
    generations: &[7],
    core_masks: &G14X_CORE_MASKS,
    mmu: g14_mmu(28),
    initdata_magic: Some(0x0c8a_636f_0394_04b8),
    interface: Interface::Unrecovered(NOT_CHECKED),
};
pub const G15C: Family = Family {
    name: "G15C",
    kext: "com.apple.AGXG15C",
    kernelcache: "mac15j",
    generations: &[7],
    core_masks: &G14X_CORE_MASKS,
    mmu: g14_mmu(28),
    initdata_magic: Some(0x0c8a_636f_0496_04b8),
    interface: Interface::Unrecovered(NOT_CHECKED),
};
pub const G16G: Family = Family {
    name: "G16G",
    kext: "com.apple.AGXG16G",
    kernelcache: "mac16g",
    generations: &[8, 0xa],
    core_masks: &G14X_CORE_MASKS,
    mmu: g14_mmu(28),
    initdata_magic: Some(0x0c8a_636f_0392_04b8),
    interface: Interface::Unrecovered(NOT_CHECKED),
};
pub const G16X: Family = Family {
    name: "G16X",
    kext: "com.apple.AGXG16X",
    kernelcache: "mac16j",
    generations: &[8, 0xa],
    core_masks: &G14X_CORE_MASKS,
    mmu: g14_mmu(28),
    initdata_magic: None,
    interface: Interface::Unrecovered(NOT_CHECKED),
};
pub const G17G: Family = Family {
    name: "G17G",
    kext: "com.apple.AGXG17G",
    kernelcache: "mac17g",
    generations: &[0xb],
    core_masks: &G14X_CORE_MASKS,
    mmu: g14_mmu(28),
    initdata_magic: None,
    interface: Interface::Unrecovered(NOT_CHECKED),
};
pub const G17X: Family = Family {
    name: "G17X",
    kext: "com.apple.AGXG17X",
    kernelcache: "mac17j",
    generations: &[0xb],
    core_masks: &G14X_CORE_MASKS,
    mmu: g14_mmu(28),
    initdata_magic: None,
    interface: Interface::Unrecovered(NOT_CHECKED),
};
pub const G17P: Family = Family {
    name: "G17P",
    kext: "com.apple.AGXG17P",
    kernelcache: "mac17p",
    generations: &[8, 0xa],
    core_masks: &G14X_CORE_MASKS,
    mmu: g14_mmu(28),
    initdata_magic: None,
    interface: Interface::Unrecovered(NOT_CHECKED),
};
pub const G18G: Family = Family {
    name: "G18G",
    kext: "com.apple.AGXG18G",
    kernelcache: "mac18g",
    generations: &[0xc],
    core_masks: &G14X_CORE_MASKS,
    mmu: g14_mmu(28),
    initdata_magic: None,
    interface: Interface::Unrecovered(NOT_CHECKED),
};

/// T8112: G14G B0, one cluster of 10 cores, 10 fragment units and 4 GPs
/// (Public: Asahi `hw/t8112.rs` for the counts, `regs.rs` for variant G =
/// 2; revision B0 is m1n1's `gpu_rev`, read before m1n1's AI notice).
pub const T8112: Identity = Identity {
    generation: 5,
    variant: 2,
    revision: 0x10,
    clusters: 1,
    cores: 10,
    frags: 10,
    gps: 4,
    core_mask: [0x3ff, 0, 0],
};

const fn gpu(
    compatible: &'static str,
    chip_id: u16,
    family: &'static Family,
    firmware: &'static str,
) -> Gpu {
    Gpu {
        compatible,
        chip_id,
        family,
        firmware,
        identity: None,
    }
}

/// Every `sgx` of the 26A434 board DeviceTrees, by ApChipID.
pub const GPUS: [Gpu; 20] = [
    gpu("gpu,t8103", 0x8103, &G13G, "armfw_g13g"),
    gpu("gpu,t6000", 0x6000, &G13X, "armfw_g13x"),
    gpu("gpu,t6001", 0x6001, &G13X, "armfw_g13x"),
    gpu("gpu,t6002", 0x6002, &G13X, "armfw_g13x"),
    Gpu {
        compatible: "gpu,t8112",
        chip_id: 0x8112,
        family: &G14G,
        firmware: "armfw_g14g",
        identity: Some(T8112),
    },
    gpu("gpu,t6020", 0x6020, &G14X, "armfw_g14s"),
    gpu("gpu,t6021", 0x6021, &G14X, "armfw_g14c"),
    gpu("gpu,t6022", 0x6022, &G14X, "armfw_g14d"),
    gpu("gpu,t8122", 0x8122, &G15G, "armfw_g15g"),
    gpu("gpu,t6030", 0x6030, &G15S, "armfw_g15s"),
    gpu("gpu,t6031", 0x6031, &G15C, "armfw_g15c"),
    gpu("gpu,t6032", 0x6032, &G15C, "armfw_g15d"),
    gpu("gpu,t6034", 0x6034, &G15C, "armfw_g15c"),
    gpu("gpu,t8132", 0x8132, &G16G, "armfw_g16g"),
    gpu("gpu,t6040", 0x6040, &G16X, "armfw_g16s"),
    gpu("gpu,t6041", 0x6041, &G16X, "armfw_g16c"),
    gpu("gpu,t8140", 0x8140, &G17P, "armfw_g17p"),
    gpu("gpu,t8142", 0x8142, &G17G, "armfw_g17g"),
    gpu("gpu,t6050", 0x6050, &G17X, "armfw_g17x"),
    gpu("gpu,t8152", 0x8152, &G18G, "armfw_g18g"),
];

/// The GPU whose `sgx` carries `compatible`.
pub fn by_compatible(compatible: &str) -> Option<&'static Gpu> {
    GPUS.iter().find(|gpu| gpu.compatible == compatible)
}

impl Gpu {
    /// The identification the model reports, when the GPU's whole interface
    /// is modeled; otherwise why it is not.
    pub fn admitted(&self) -> Result<Identity, &'static str> {
        if let Interface::Unrecovered(reason) = self.family.interface {
            return Err(reason);
        }
        let identity = self
            .identity
            .ok_or("no source states the GPU's identification registers")?;
        if !self.family.generations.contains(&identity.generation) {
            return Err("the GPU's generation is not one its kext accepts");
        }
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_census_gpu_is_named_once_and_only_t8112_is_admitted() {
        for (index, gpu) in GPUS.iter().enumerate() {
            assert!(gpu.compatible.starts_with("gpu,t"));
            assert_eq!(
                gpu.compatible[5..],
                alloc::format!("{:x}", gpu.chip_id),
                "{} names its own chip",
                gpu.compatible
            );
            assert!(
                GPUS[..index]
                    .iter()
                    .all(|other| other.chip_id != gpu.chip_id)
            );
            assert!(gpu.firmware.starts_with("armfw_g"));
            assert!(gpu.family.kext.ends_with(gpu.family.name));
        }
        let admitted: alloc::vec::Vec<_> = GPUS
            .iter()
            .filter(|gpu| gpu.admitted().is_ok())
            .map(|gpu| gpu.compatible)
            .collect();
        assert_eq!(admitted, ["gpu,t8112"]);
        assert_eq!(by_compatible("gpu,t8112").unwrap().admitted(), Ok(T8112));
        assert_eq!(
            by_compatible("gpu,t8103").unwrap().admitted(),
            Err(NOT_CHECKED)
        );
        assert!(by_compatible("gpu,t9999").is_none());
    }

    #[test]
    fn mmu_layouts_follow_the_two_secure_monitor_generations() {
        for gpu in &GPUS {
            let mmu = gpu.family.mmu;
            let g13 = gpu.family.generations == [4];
            assert_eq!(mmu.ttbat, if g13 { 0xd0_8024 } else { 0xd0_802c });
            assert_eq!(mmu.invalidate, mmu.ttbat + 4);
            assert!(mmu.configuration.iter().all(|&(offset, _)| {
                (MMU_ENABLE + 4..mmu.ttbat).contains(&offset) && offset % 4 == 0
            }));
            let narrow = ["G13G", "G14G"].contains(&gpu.family.name);
            assert_eq!(mmu.ttbat_page_bits, if narrow { 26 } else { 28 });
        }
    }
}
