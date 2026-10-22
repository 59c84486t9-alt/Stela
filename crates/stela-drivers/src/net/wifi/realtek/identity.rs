// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
// Copyright(c) 2019-2020 Realtek Corporation
// Copyright(c) 2020-2022 Realtek Corporation
//! Exact PCI candidates and actual SYS_CFG1 observations from pinned rtw88/89.
use super::firmware::{Layout, ParseError};
use crate::firmware::{self, Image, Provider, Requirement, Target};
use alloc::{format, string::String};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Chip {
    Rtl8822C,
    Rtl8852B,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observed {
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
    pub pci_revision: u8,
    /// Actual 32-bit SYS_CFG1 at 0xf0, with every bit retained.
    pub sys_cfg1: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    observed: Observed,
    chip: Chip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    UnsupportedPci,
    FailedRead,
    TestChip,
}

#[derive(Debug)]
pub enum StageError {
    Resource(firmware::Error),
    Format(ParseError),
}

#[derive(Debug)]
pub struct Staged<'a> {
    pub profile: Profile,
    pub image: Image<'a>,
    pub layout: Layout<'a>,
}

impl Profile {
    pub fn select(observed: Observed) -> Result<Self, IdentityError> {
        if observed.vendor != 0x10ec {
            return Err(IdentityError::UnsupportedPci);
        }
        let chip = match observed.device {
            0xc822 | 0xc82f => Chip::Rtl8822C,
            0xb852 | 0xb85b => Chip::Rtl8852B,
            _ => return Err(IdentityError::UnsupportedPci),
        };
        if observed.sys_cfg1 == u32::MAX {
            return Err(IdentityError::FailedRead);
        }
        // rtw88's BIT_RTL_ID distinguishes non-production silicon. Its test
        // firmware path is not interchangeable with the production image.
        if chip == Chip::Rtl8822C && observed.sys_cfg1 & (1 << 23) != 0 {
            return Err(IdentityError::TestChip);
        }
        Ok(Self { observed, chip })
    }

    pub fn observed(self) -> Observed {
        self.observed
    }
    pub fn chip(self) -> Chip {
        self.chip
    }
    pub fn cut(self) -> u8 {
        ((self.observed.sys_cfg1 >> 12) & 15) as u8
    }
    pub fn firmware_name(self) -> &'static str {
        match self.chip {
            Chip::Rtl8822C => "rtw88/rtw8822c_fw.bin",
            Chip::Rtl8852B => "rtw89/rtw8852b_fw-2.bin",
        }
    }
    pub fn hardware_key(self) -> String {
        let p = self.observed;
        format!(
            "pci:{:04x}:{:04x}:subsys:{:04x}:{:04x}:rev:{:02x}",
            p.vendor, p.device, p.subsystem_vendor, p.subsystem_device, p.pci_revision
        )
    }
    pub fn revision_key(self) -> String {
        format!(
            "syscfg1-{:08x}:cut-{:02x}",
            self.observed.sys_cfg1,
            self.cut()
        )
    }
    pub fn stage(self, provider: &dyn Provider) -> Result<Staged<'_>, StageError> {
        let hardware = self.hardware_key();
        let revision = self.revision_key();
        let image = provider
            .load(Requirement {
                name: self.firmware_name(),
                target: Target {
                    driver: "realtek-wifi",
                    hardware: &hardware,
                    revision: &revision,
                    board: None,
                },
                minimum_bytes: match self.chip {
                    Chip::Rtl8822C => 64,
                    Chip::Rtl8852B => 32,
                },
            })
            .map_err(StageError::Resource)?;
        let layout = match self.chip {
            Chip::Rtl8822C => Layout::Rtw88(super::firmware::Rtw88::parse(image.bytes())?),
            Chip::Rtl8852B => {
                Layout::Rtw89(super::firmware::Rtw89::parse(image.bytes(), self.cut())?)
            }
        };
        Ok(Staged {
            profile: self,
            image,
            layout,
        })
    }
}
impl From<ParseError> for StageError {
    fn from(error: ParseError) -> Self {
        Self::Format(error)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::firmware::{Catalog, Provenance, Resource};
    use sha2::{Digest, Sha256};
    pub(crate) fn observed(device: u16, cut: u8) -> Observed {
        Observed {
            vendor: 0x10ec,
            device,
            subsystem_vendor: 0x17aa,
            subsystem_device: 0x1234,
            pci_revision: 1,
            sys_cfg1: u32::from(cut) << 12,
        }
    }
    pub(crate) fn profile() -> Profile {
        Profile::select(observed(0xc822, 0)).unwrap()
    }
    #[test]
    fn exact_pci_cut_and_raw_identity_are_not_replaced_by_a_marketing_name() {
        for device in [0xc822, 0xc82f, 0xb852, 0xb85b] {
            for cut in 0..16 {
                let o = observed(device, cut);
                let p = Profile::select(o).unwrap();
                assert_eq!(p.observed(), o);
                assert_eq!(p.cut(), cut);
                assert!(p.hardware_key().contains(&format!(":{device:04x}:")));
                assert!(p.revision_key().contains(&format!("cut-{cut:02x}")));
            }
        }
        let mut o = observed(0xb852, 1);
        for device in [0x8852, 0xc821, 0xb822, 0xffff] {
            o.device = device;
            assert_eq!(Profile::select(o), Err(IdentityError::UnsupportedPci));
        }
        o = observed(0xb852, 1);
        o.sys_cfg1 = u32::MAX;
        assert_eq!(Profile::select(o), Err(IdentityError::FailedRead));
        o = observed(0xc822, 1);
        o.sys_cfg1 |= 1 << 23;
        assert_eq!(Profile::select(o), Err(IdentityError::TestChip));
        o = observed(0xb852, 1);
        o.vendor = 0x8086;
        assert_eq!(Profile::select(o), Err(IdentityError::UnsupportedPci));
    }

    #[test]
    fn provider_binding_is_exact_and_staged_sections_keep_the_original_bytes() {
        let profile = Profile::select(observed(0xc822, 1)).unwrap();
        let hardware = profile.hardware_key();
        let revision = profile.revision_key();
        let data = super::super::firmware::tests::legacy_fixture();
        let original = data.as_ptr();
        let hash = Sha256::digest(&data).into();
        let catalog = Catalog::from_handoff(vec![Resource {
            name: profile.firmware_name(),
            target: Target {
                driver: "realtek-wifi",
                hardware: &hardware,
                revision: &revision,
                board: None,
            },
            provenance: Provenance {
                source: "synthetic-test",
                revision: "1",
                member: profile.firmware_name(),
                license: "MIT",
            },
            expected_length: data.len(),
            expected_sha256: hash,
            bytes: data,
        }])
        .unwrap();
        let staged = profile.stage(&catalog).unwrap();
        assert_eq!(staged.image.bytes().as_ptr(), original);
        let Layout::Rtw88(layout) = staged.layout else {
            panic!("wrong chip layout")
        };
        assert_eq!(layout.sections[0].data.as_ptr(), original.wrapping_add(64));
        for field in 0..5 {
            let mut observation = profile.observed();
            match field {
                0 => observation.device = 0xc82f,
                1 => observation.subsystem_vendor ^= 1,
                2 => observation.subsystem_device ^= 1,
                3 => observation.pci_revision ^= 1,
                _ => observation.sys_cfg1 ^= 1,
            }
            let wrong = Profile::select(observation).unwrap();
            assert!(matches!(
                wrong.stage(&catalog),
                Err(StageError::Resource(firmware::Error {
                    kind: firmware::ErrorKind::WrongTarget,
                    ..
                }))
            ));
        }
        assert!(matches!(
            profile.stage(&Catalog::from_handoff(vec![]).unwrap()),
            Err(StageError::Resource(firmware::Error {
                kind: firmware::ErrorKind::Missing,
                ..
            }))
        ));
    }
}
