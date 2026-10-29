// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Unmanaged LPT I217 LM/V (153a/153b) and I218 LM2/V2 (15a0/15a1).
//! These exact IDs are exempted by the donor's ULP entry/exit helpers and do
//! not select the LPT-LP/I218-3 K1 hang sequence. No I219/SPT or other I218 is
//! admitted by similarity of PHY IDs. Initial MAC/PHY PCIe mode is required;
//! SMBus switching, LANPHYPC recovery and managed firmware remain separate.
use super::{
    Bus, Controller, Delay, Error, Fault, Identity, Kind, Phy, Profile, Register, Registers, nvm,
    spt,
};
use alloc::rc::Rc;
use core::cell::RefCell;

const CTRL_EXT: u32 = 0x18;
const FORCE_SMBUS: u32 = 1 << 11;
const LTR_SNOOP: u16 = 0xa8;
const LTR_NOSNOOP: u16 = 0xaa;
const LTRV: u32 = 0xf8;
const LTR_SEND: u32 = 1 << 30;
const LTR_REQUEST: u32 = (1 << 15) | (1 << 31);
const LTR_VALUE: u16 = 0x3ff;
const LTR_SCALE: u16 = 0x1c00;
const LTR_SCALE_SHIFT: u32 = 10;
const LTR_SCALE_FACTOR: u32 = 5;
const LTR_MAX_SCALE: u16 = 5;
const FEXTNVM4: u32 = 0x24;
const FEXTNVM6: u32 = 0x10;
pub(super) const EEE_ADVERTISEMENT: u16 = 0x8001;
pub(super) const EEE_PCS_STATUS: u16 = 0x9401;
pub(super) const RX_CONFIG: u16 = 0xb20c;
pub(super) const PLL_CLOCK_GATE: Register = Register {
    page: 772,
    index: 28,
};
pub(super) const PLL_CLOCK_GATE_MASK: u16 = 0x7ff;
pub(super) const PLL_CLOCK_GATE_GIGABIT: u16 = 0xfa;
pub(super) const PLL_CLOCK_GATE_SLOW: u16 = 0x3e8;
pub(super) const K1_CLOCK_REQUEST: u16 = 1 << 9;

/// Same-function config access required by LPT's platform LTR limits.
///
/// # Safety
/// Both supertraits and these reads keep and access the **same PCI
/// Function and reset epoch**, not a separate function or supplied substitute.
/// Config offsets are bounded/aligned little-endian 16-bit reads;
/// access/removal errors never manufacture a value. The real reservation,
/// power, config access and MAC/flash mappings remain owned together. LTR
/// config words are immutable during this exclusive epoch: firmware/SMM,
/// other users and config writes are excluded. SPT additionally uses
/// live reads at e4 for descriptor flush status; that status is never cached.
/// No provider is supplied here.
pub unsafe trait LptRegisters: Registers + nvm::Registers {
    fn read_config16(&mut self, offset: u16) -> Result<u16, Fault>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Limits {
    snoop: u16,
    nosnoop: u16,
}
impl Limits {
    pub(super) fn new(snoop: u16, nosnoop: u16) -> Result<Self, Error> {
        for value in [snoop, nosnoop] {
            // Bits13:14 and scales6:7 are reserved. Bit15 is the
            // requirement indication and is preserved as in the source.
            if value & 0x6000 != 0 || ((value & LTR_SCALE) >> LTR_SCALE_SHIFT) > LTR_MAX_SCALE {
                return Err(Error::LtrLimit(value));
            }
        }
        Ok(Self { snoop, nosnoop })
    }
    fn decode(value: u16) -> u64 {
        u64::from(value & LTR_VALUE)
            << (u32::from((value & LTR_SCALE) >> LTR_SCALE_SHIFT) * LTR_SCALE_FACTOR)
    }
    fn latency(self, receive_kib: u32, speed: u32) -> Result<u16, Error> {
        let receive = u64::from(receive_kib) * 512;
        let frame = (crate::net::MAX_FRAME + 4) as u64;
        let mut value = receive.saturating_sub(frame) * u64::from(16000 / speed);
        let mut scale = 0u16;
        while value > u64::from(LTR_VALUE) {
            scale += 1;
            value = value.div_ceil(32);
        }
        if scale > LTR_MAX_SCALE {
            return Err(Error::Configuration);
        }
        let mut encoded = (scale << LTR_SCALE_SHIFT) | value as u16;
        // Donor selects the larger encoded maximum first, then compares its
        // decoded latency with the device requirement. Preserve that policy.
        let maximum = self.snoop.max(self.nosnoop);
        if Self::decode(encoded) > Self::decode(maximum) {
            encoded = maximum;
        }
        Ok(encoded)
    }
}

pub(super) fn shared_count(fwsm: u32) -> u32 {
    let locked = (fwsm & 0x380) >> 7;
    match locked {
        0 => 11,
        1 => 0,
        _ => locked,
    }
}

impl<R: LptRegisters, D: Delay + Clone> Controller<R, D> {
    /// Construct the exact ULP-exempt LPT cohort in its accessible unmanaged
    /// PCIe mode. The original [`Controller::new`] remains 82579-only.
    ///
    /// # Safety
    /// All `Controller::new` physical ownership, exclusion, reset and delay
    /// requirements hold, with exact vendor8086/class020000 and one of
    /// 153a/153b/15a0/15a1. `LptRegisters` binds immutable config limits
    /// to the very same PCI Function/reset epoch as MAC/flash/PHY access. No
    /// config/MMIO/DMA provider, probe admission or identity fallback is implied.
    pub unsafe fn new_lpt(device: u16, io: R, delay: D) -> Result<Self, Error> {
        // SAFETY: caller supplies the stated real same-function cold epoch.
        let mut this = unsafe { Self::claim_lpt(device, io, delay) }?;
        if let Err(error) = this.initialize_lpt() {
            this.poisoned = true;
            this.phy.poisoned = true;
            return Err(error);
        }
        Ok(this)
    }
    unsafe fn claim_lpt(device: u16, io: R, delay: D) -> Result<Self, Error> {
        // The donor explicitly returns before ULP accesses for these four
        // devices. LPT-LP and I218-3 variants are not aliases of this profile.
        if !matches!(device, 0x153a | 0x153b | 0x15a0 | 0x15a1) {
            return Err(Error::UnsupportedDevice(device));
        }
        let bus = Bus(Rc::new(RefCell::new(io)));
        let limits = (|| {
            let snoop = bus.0.borrow_mut().read_config16(LTR_SNOOP)?;
            let nosnoop = bus.0.borrow_mut().read_config16(LTR_NOSNOOP)?;
            Limits::new(snoop, nosnoop)
        })();
        let limits = match limits {
            Ok(limits) => limits,
            Err(error) => {
                // Keep the function/config/mapping owner on observed
                // access failure or invalid platform limits, before mutation.
                core::mem::forget(bus);
                return Err(error);
            }
        };
        // SAFETY: same LPT function/config/reset epoch, with
        // exclusive serialized MAC/flash adapters and delay clones.
        let nvm = unsafe { nvm::Nvm::new(nvm::Layout::Lpt, bus.clone(), delay.clone()) }?;
        // SAFETY: observed exact PCI cohort selects the I217 PHY path.
        let phy = unsafe { Phy::new(Kind::I217, bus, delay) };
        Ok(Self {
            phy,
            nvm,
            station: crate::net::Mac([0; 6]),
            identity: Identity {
                kind: Kind::I217,
                id: 0,
                revision: 0,
            },
            poisoned: false,
            profile: Profile::Lpt(limits),
            config_read: None,
        })
    }
}

impl<R: Registers + nvm::Registers, D: Delay + Clone> Controller<R, D> {
    fn initialize_lpt(&mut self) -> Result<(), Error> {
        self.qualify()?;
        if self.read(CTRL_EXT)? & FORCE_SMBUS != 0 {
            return Err(Error::SmbusMode);
        }
        self.identity = self.phy.identify()?;
        if self.phy.read(Register::new(769, 23)?)? & 1 != 0 {
            return Err(Error::SmbusMode);
        }
        self.nvm.validate()?;
        self.station = self.nvm.station()?;
        self.gate(true)?;
        self.phy_reset()?;
        self.configuration_done()?;
        self.qualify()?;
        self.identity = self.phy.identify()?;
        self.write(super::PBA, super::RX_ALLOCATION_KIB)?;
        self.global_reset()?;
        self.configuration_done()?;
        self.post_reset()?;
        self.write(super::IMC, u32::MAX)?;
        self.read(super::ICR)?;
        let bias = self.read(super::KABGTXD)?;
        self.write(super::KABGTXD, bias | super::BGSQLBIAS)?;
        self.identity = self.phy.identify()?;
        Ok(())
    }

    pub(super) fn lpt_platform_pm(&mut self, status: Option<u32>) -> Result<(), Error> {
        let (Profile::Lpt(limits) | Profile::I219(limits, _) | Profile::Mtp(limits, _, _)) =
            self.profile
        else {
            return Ok(());
        };
        let mut value = LTR_SEND;
        if let Some(status) = status {
            let speed = if status & (1 << 7) != 0 {
                1000
            } else if status & (1 << 6) != 0 {
                100
            } else {
                10
            };
            let receive = self.read(super::PBA)? & 0xffff;
            let latency = u32::from(limits.latency(receive, speed)?);
            value |= LTR_REQUEST | latency | (latency << 16);
        }
        self.write(LTRV, value)
    }

    pub(super) fn lpt_link_common(&mut self, status: Option<u32>) -> Result<(), Error> {
        if !self.profile.is_lpt_or_newer() {
            return Ok(());
        }
        let beacon = self.read(FEXTNVM4)?;
        self.write(FEXTNVM4, (beacon & !7) | 7)?;
        self.lpt_platform_pm(status)?;
        // SPT mirrors the analog K1-off enable bit. LPT preserves it;
        // the LPT-LP/I218-3 hang workaround is a separate device profile.
        let value = self.read(FEXTNVM6)?;
        let value = if self.is_spt_mac() {
            let analog = self.read(spt::PCIE_ANALOG)?;
            (value & !spt::K1_OFF_ENABLE) | (analog & spt::K1_OFF_ENABLE)
        } else {
            value
        };
        self.write(FEXTNVM6, value)?;
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests;
