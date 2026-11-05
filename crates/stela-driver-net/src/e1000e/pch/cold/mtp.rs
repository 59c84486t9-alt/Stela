// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Exact MTP/ARL/LNP and PTP/NVL source cohorts. Board observations belong to
//! the physical host, never translated macOS or the development machine.
use super::super::{Fault, Phy, Register};
use super::{Controller, Delay, Error, Profile, Registers, lpt, nvm};

const CTRL_EXT: u32 = 0x18;
const DYNAMIC_POWER_GATING: u32 = 8;
const KMRN: u32 = 0x34;
const KMRN_K1_CONFIG: u32 = 7 << 16;
const KMRN_READ: u32 = 1 << 21;
const KMRN_K1_ENABLE: u16 = 2;
const FEXTNVM12: u32 = 0x5bc0;
const PHY_POWER_STATE_MASK: u32 = 0x00c0_0000;
const PHY_POWER_STATE_P1: u32 = 0x0080_0000;
const FORCE_SPEED: u32 = 0x800;
const SPEED_BITS: u32 = 0x300;
const SPEED_BYPASS: u32 = 0x8000;
const PHY_TIMEOUT: Register = Register {
    page: 770,
    index: 21,
};
const K1_EXIT_TIMEOUT_MASK: u16 = 0xfc0;
const K1_EXIT_TIMEOUT: u16 = 0xf00;
pub(super) const GIGABIT_PLL_CLOCK_GATE: u16 = 0x1d5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Family {
    Mtp,
    Ptp,
}
impl Family {
    pub(super) fn from_device(device: u16) -> Option<Self> {
        match device {
            0x550a | 0x550b | 0x550e | 0x550f | 0x5510 | 0x5511 | 0x57a0 | 0x57a1 => {
                Some(Self::Mtp)
            }
            0x57b3 | 0x57b4 | 0x57b7 | 0x57b8 | 0x57b9 | 0x57ba => Some(Self::Ptp),
            _ => None,
        }
    }
}
/// A target-machine SMBIOS/DMI string observation. An observed missing
/// field is distinct from an unread/unavailable/invalid table or field.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Observation<'a> {
    #[default]
    NotObserved,
    Absent,
    /// Exact bounded bytes, including an optional first NUL and bytes after it.
    /// No UTF-8 conversion, case folding or vendor normalization is performed.
    Value(&'a [u8]),
}
/// The three physical system fields used by the pinned donor quirks.
/// Native admission must supply validated table observations; this
/// type neither discovers firmware nor gives an address-mapping permission.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostIdentity<'a> {
    pub system_vendor: Observation<'a>,
    pub product_name: Observation<'a>,
    pub product_version: Observation<'a>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Decision {
    NotObserved,
    NoMatch,
    Match,
}
impl Observation<'_> {
    fn matches(self, needle: &[u8]) -> Decision {
        match self {
            Self::NotObserved => Decision::NotObserved,
            Self::Absent => Decision::NoMatch,
            Self::Value(value) => {
                let value = &value[..value.iter().position(|b| *b == 0).unwrap_or(value.len())];
                if value.windows(needle.len()).any(|part| part == needle) {
                    Decision::Match
                } else {
                    Decision::NoMatch
                }
            }
        }
    }
}
impl HostIdentity<'_> {
    fn decision(self) -> Decision {
        if self.system_vendor == Observation::NotObserved {
            return Decision::NotObserved;
        }
        fn and(a: Decision, b: Decision) -> Decision {
            if a == Decision::NoMatch || b == Decision::NoMatch {
                Decision::NoMatch
            } else if a == Decision::Match && b == Decision::Match {
                Decision::Match
            } else {
                Decision::NotObserved
            }
        }
        let dell = and(
            self.system_vendor.matches(b"Dell Inc."),
            self.product_name.matches(b"Dell Pro 16 Plus PB16250"),
        );
        let lenovo = and(
            self.system_vendor.matches(b"LENOVO"),
            self.product_version.matches(b"ThinkPad P14s Gen 5"),
        );
        if dell == Decision::Match || lenovo == Decision::Match {
            Decision::Match
        } else if dell == Decision::NotObserved || lenovo == Decision::NotObserved {
            Decision::NotObserved
        } else {
            Decision::NoMatch
        }
    }
}
impl<R: lpt::LptRegisters, D: Delay + Clone> Controller<R, D> {
    /// Construct only the source-selected fourteen MTP/PTP-family IDs.
    ///
    /// # Safety
    /// All `Controller::new_spt` powered same-Function/config/MMIO/flash/
    /// PHY/reset-epoch/exclusion/delay requirements hold. `device` is the
    /// vendor8086/class020000 config identity. `host` contains physical
    /// SMBIOS/DMI observations from this host and epoch, with validated field
    /// extents/absence, never inferred strings or a development/guest identity.
    /// Unknown required observations refuse before any config/MMIO access.
    /// The evaluated quirk is held privately with this consumed owner.
    /// Initially inaccessible PHY/deep recovery and managed firmware refuse.
    pub unsafe fn new_mtp(
        device: u16,
        io: R,
        delay: D,
        host: HostIdentity<'_>,
    ) -> Result<Self, Error> {
        // SAFETY: same-host identity and physical ownership grant above.
        let mut this = unsafe { Self::claim_mtp(device, io, delay, host) }?;
        if let Err(error) = this.initialize_i219() {
            this.poisoned = true;
            this.phy.poisoned = true;
            return Err(error);
        }
        Ok(this)
    }
    pub(super) unsafe fn claim_mtp(
        device: u16,
        io: R,
        delay: D,
        host: HostIdentity<'_>,
    ) -> Result<Self, Error> {
        let family = Family::from_device(device).ok_or(Error::UnsupportedDevice(device))?;
        let disable_k1 = match host.decision() {
            Decision::NotObserved => return Err(Error::HostIdentityNotObserved),
            Decision::NoMatch => false,
            Decision::Match => true,
        };
        // SAFETY: source-selected family and same physical host grant.
        let mut this = unsafe {
            Self::claim_integrated(io, delay, |limits| Profile::Mtp(limits, family, disable_k1))
        }?;
        this.phy.retry_count = 2;
        this.phy.retry_enabled = true;
        Ok(this)
    }
}
impl<R: Registers + nvm::Registers, D: Delay + Clone> Controller<R, D> {
    pub(super) fn mtp_family(&self) -> Option<Family> {
        match self.profile {
            Profile::Mtp(_, family, _) => Some(family),
            _ => None,
        }
    }
    pub(super) fn mtp_initial_k1(&mut self, before_reset: bool) -> Result<(), Error> {
        if self.mtp_family().is_some() {
            self.phy.transaction(|p| {
                // Initial source flow predates board-quirk selection in probe.
                // Interconnect recovery disables protocol retries, not faults.
                if before_reset {
                    p.retry_enabled = false;
                }
                p.mtp_k1(false)?;
                p.retry_enabled = true;
                Ok(())
            })?;
        }
        Ok(())
    }
    pub(super) fn mtp_init_k1(&mut self) -> Result<(), Error> {
        if let Profile::Mtp(_, _, disable_k1) = self.profile {
            self.phy.transaction(|p| p.mtp_k1(disable_k1))?;
        }
        Ok(())
    }
    pub(super) fn mtp_reset_finish(&mut self) -> Result<(), Error> {
        if self.mtp_family() == Some(Family::Ptp) {
            let value = self.read(CTRL_EXT)?;
            self.write(CTRL_EXT, value & !DYNAMIC_POWER_GATING)?;
        }
        Ok(())
    }
}
impl<R: Registers, D: Delay> Phy<R, D> {
    fn mtp_kmrn(&mut self, value: Option<u16>) -> Result<u16, Fault> {
        self.write_mac(KMRN, KMRN_K1_CONFIG | value.map_or(KMRN_READ, u32::from))?;
        self.read_mac(super::STATUS)?;
        self.wait_minimum(2)?;
        if value.is_none() {
            Ok(self.read_mac(KMRN)? as u16)
        } else {
            Ok(0)
        }
    }
    fn mtp_k1(&mut self, disable: bool) -> Result<(), Fault> {
        let value = self.read_mac(FEXTNVM12)?;
        self.write_mac(
            FEXTNVM12,
            (value & !PHY_POWER_STATE_MASK) | PHY_POWER_STATE_P1,
        )?;
        self.wait_minimum(1000)?;
        if disable {
            let value = self.mtp_kmrn(None)?;
            self.mtp_kmrn(Some(value & !KMRN_K1_ENABLE))?;
            self.wait_minimum(20)?;
            let ext = self.read_mac(CTRL_EXT)?;
            let ctrl = self.read_mac(super::CTRL)?;
            self.write_mac(super::CTRL, (ctrl & !SPEED_BITS) | FORCE_SPEED)?;
            self.write_mac(CTRL_EXT, ext | SPEED_BYPASS)?;
            self.read_mac(super::STATUS)?;
            self.wait_minimum(20)?;
            self.write_mac(super::CTRL, ctrl)?;
            self.write_mac(CTRL_EXT, ext)?;
            self.read_mac(super::STATUS)?;
            self.wait_minimum(20)?;
        } else {
            let value = self.access(PHY_TIMEOUT, None)?;
            self.access(
                PHY_TIMEOUT,
                Some((value & !K1_EXIT_TIMEOUT_MASK) | K1_EXIT_TIMEOUT),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests;
