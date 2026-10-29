// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Exact PCI candidates and kept chip observations. This is not
//! controller admission; callers still need mapped/owned PCI and WFDMA setup.
use alloc::{format, string::String};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Chip {
    Mt7921,
    Mt7922,
    Mt7925,
}

impl Chip {
    pub fn patch_name(self) -> &'static str {
        match self {
            Self::Mt7921 => "mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin",
            Self::Mt7922 => "mediatek/WIFI_MT7922_patch_mcu_1_1_hdr.bin",
            Self::Mt7925 => "mediatek/mt7925/WIFI_MT7925_PATCH_MCU_1_1_hdr.bin",
        }
    }

    pub fn ram_name(self) -> &'static str {
        match self {
            Self::Mt7921 => "mediatek/WIFI_RAM_CODE_MT7961_1.bin",
            Self::Mt7922 => "mediatek/WIFI_RAM_CODE_MT7922_1.bin",
            Self::Mt7925 => "mediatek/mt7925/WIFI_RAM_CODE_MT7925_1_1.bin",
        }
    }

    pub(crate) fn uses_patch_start(self, address: u32) -> bool {
        address == 0x0020_0000
            || address == 0x0090_0000
            || (self == Self::Mt7925 && address == 0xe000_2800)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciIdentity {
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    pub revision: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub pci: PciIdentity,
    pub chip: Chip,
    /// Unmodified MT_HW_CHIPID, MT_HW_REV and conditional MT_HW_BOUND reads.
    pub raw_chip: u32,
    pub raw_revision: u32,
    pub raw_bound: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    UnsupportedPci(PciIdentity),
    FailedRegisterRead,
    MissingBoundObservation,
    UnsupportedChip {
        raw_chip: u32,
        raw_bound: Option<u32>,
    },
}

impl Identity {
    /// Classify observations without substituting a chip identity from
    /// PCI marketing names. MT7961's bound bit 7 selects the distinct MT7920
    /// firmware family, which this initial slice does not admit.
    pub fn observed(
        pci: PciIdentity,
        raw_chip: u32,
        raw_revision: u32,
        raw_bound: Option<u32>,
    ) -> Result<Self, IdentityError> {
        let candidate = if pci.vendor == 0x14c3 {
            match pci.device {
                0x7961 | 0x0608 => Some((Chip::Mt7921, 0x7961)),
                0x7922 | 0x0616 => Some((Chip::Mt7922, 0x7922)),
                0x7925 | 0x0717 => Some((Chip::Mt7925, 0x7925)),
                _ => None,
            }
        } else {
            None
        };
        let Some((chip, expected)) = candidate else {
            return Err(IdentityError::UnsupportedPci(pci));
        };
        if raw_chip == u32::MAX || raw_revision == u32::MAX || raw_bound == Some(u32::MAX) {
            return Err(IdentityError::FailedRegisterRead);
        }
        if chip == Chip::Mt7921 && raw_bound.is_none() {
            return Err(IdentityError::MissingBoundObservation);
        }
        if raw_chip != expected
            || (chip == Chip::Mt7921 && raw_bound.is_some_and(|v| v & 0x80 != 0))
        {
            return Err(IdentityError::UnsupportedChip {
                raw_chip,
                raw_bound,
            });
        }
        Ok(Self {
            pci,
            chip,
            raw_chip,
            raw_revision,
            raw_bound,
        })
    }

    pub fn hardware_key(&self) -> String {
        let p = self.pci;
        format!(
            "pci:{:04x}:{:04x}:subsys:{:04x}:{:04x}:rev:{:02x}",
            p.vendor, p.device, p.subsystem_vendor, p.subsystem_device, p.revision
        )
    }

    pub fn revision_key(&self) -> String {
        match self.raw_bound {
            Some(bound) => format!(
                "chip-{:08x}-hwrev-{:08x}-bound-{bound:08x}",
                self.raw_chip, self.raw_revision
            ),
            None => format!(
                "chip-{:08x}-hwrev-{:08x}-bound-unobserved",
                self.raw_chip, self.raw_revision
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pci(device: u16) -> PciIdentity {
        PciIdentity {
            vendor: 0x14c3,
            device,
            subsystem_vendor: 0x1028,
            subsystem_device: 0x1234,
            revision: 3,
        }
    }
    #[test]
    fn exact_ids_require_real_chip_and_bound_observations() {
        for (device, raw, chip) in [
            (0x7961, 0x7961, Chip::Mt7921),
            (0x0608, 0x7961, Chip::Mt7921),
            (0x7922, 0x7922, Chip::Mt7922),
            (0x0616, 0x7922, Chip::Mt7922),
            (0x7925, 0x7925, Chip::Mt7925),
            (0x0717, 0x7925, Chip::Mt7925),
        ] {
            let identity =
                Identity::observed(pci(device), raw, 0x1234_0010, Some(0x1111_1100)).unwrap();
            assert_eq!(identity.chip, chip);
            assert_eq!(identity.raw_revision, 0x1234_0010);
            assert!(matches!(
                Identity::observed(pci(device), raw ^ 1, 1, Some(0)),
                Err(IdentityError::UnsupportedChip { .. })
            ));
        }
        assert_eq!(
            Identity::observed(pci(0x0608), 0x7961, 1, None),
            Err(IdentityError::MissingBoundObservation)
        );
        assert!(matches!(
            Identity::observed(pci(0x0608), 0x7961, 1, Some(0x80)),
            Err(IdentityError::UnsupportedChip { .. })
        ));
        for (raw, rev, bound) in [
            (u32::MAX, 1, Some(0)),
            (0x7961, u32::MAX, Some(0)),
            (0x7961, 1, Some(u32::MAX)),
        ] {
            assert_eq!(
                Identity::observed(pci(0x0608), raw, rev, bound),
                Err(IdentityError::FailedRegisterRead)
            );
        }
        assert_ne!(
            Identity::observed(pci(0x0608), 0x7961, 1, Some(0))
                .unwrap()
                .hardware_key(),
            Identity::observed(pci(0x7961), 0x7961, 1, Some(0))
                .unwrap()
                .hardware_key()
        );
    }
}
