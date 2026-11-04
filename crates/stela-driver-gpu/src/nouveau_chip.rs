//! Discrete NVIDIA chipset identity shared by boot and the NVK device path.
//! The table follows nouveau's `nvkm_device_ctor` in
//! `drivers/gpu/drm/nouveau/nvkm/engine/device/base.c` (Linux v7.2.12)
//! for the GSP-RM chipsets starting at Turing.

/// The GPU generation, which fixes NVK's 3D class and NAK's shader model.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Architecture {
    Turing,
    Ampere,
    Ada,
    Hopper,
    Blackwell,
}

/// One chipset from nouveau's table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Chip {
    /// `PMC_BOOT_0` bits 20-28, as nouveau's `device->chipset`.
    pub chipset: u16,
    /// nouveau's chipset name, which is also NVK's `chipset_name`.
    pub name: &'static str,
    pub architecture: Architecture,
    /// nouveau instantiates a display engine for this chipset.
    pub display: bool,
}

const fn chip(chipset: u16, name: &'static str, architecture: Architecture, display: bool) -> Chip {
    Chip {
        chipset,
        name,
        architecture,
        display,
    }
}

use Architecture::{Ada, Ampere, Blackwell, Hopper, Turing};

/// nouveau's Turing and later chipsets; GA100, GH100, GB100 and GB102 are
/// compute parts without a display engine.
pub static CHIPS: [Chip; 24] = [
    chip(0x162, "TU102", Turing, true),
    chip(0x164, "TU104", Turing, true),
    chip(0x166, "TU106", Turing, true),
    chip(0x167, "TU117", Turing, true),
    chip(0x168, "TU116", Turing, true),
    chip(0x170, "GA100", Ampere, false),
    chip(0x172, "GA102", Ampere, true),
    chip(0x173, "GA103", Ampere, true),
    chip(0x174, "GA104", Ampere, true),
    chip(0x176, "GA106", Ampere, true),
    chip(0x177, "GA107", Ampere, true),
    chip(0x180, "GH100", Hopper, false),
    chip(0x192, "AD102", Ada, true),
    chip(0x193, "AD103", Ada, true),
    chip(0x194, "AD104", Ada, true),
    chip(0x196, "AD106", Ada, true),
    chip(0x197, "AD107", Ada, true),
    chip(0x1a0, "GB100", Blackwell, false),
    chip(0x1a2, "GB102", Blackwell, false),
    chip(0x1b2, "GB202", Blackwell, true),
    chip(0x1b3, "GB203", Blackwell, true),
    chip(0x1b5, "GB205", Blackwell, true),
    chip(0x1b6, "GB206", Blackwell, true),
    chip(0x1b7, "GB207", Blackwell, true),
];

impl Chip {
    pub fn find(chipset: u16) -> Option<&'static Chip> {
        CHIPS.iter().find(|chip| chip.chipset == chipset)
    }

    /// Decode the little-endian PMC_BOOT_0 of the actual register BAR.
    pub fn from_boot0(boot0: u32) -> Option<&'static Chip> {
        Self::find(((boot0 >> 20) & 0x1ff) as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot0_selects_the_silicon_chipset_independently_of_revision() {
        for chip in CHIPS {
            let field = u32::from(chip.chipset) << 20;
            assert_eq!(Chip::from_boot0(field | 0x91), Some(&chip));
            assert_eq!(Chip::from_boot0(field | 0xa1), Some(&chip));
        }
        assert_eq!(Chip::from_boot0(u32::MAX), None);
        assert_eq!(Chip::from_boot0(0), None);
    }
}
