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

/// Same-function config access required by LPT's actual platform LTR limits.
///
/// # Safety
/// Both supertraits and these reads retain and access the **same actual PCI
/// Function and reset epoch**, not a separate function or supplied substitute.
/// Config offsets are bounded/aligned actual little-endian 16-bit reads;
/// access/removal errors never manufacture a value. The real reservation,
/// power, config access and MAC/flash mappings remain owned together. LTR
/// config words are immutable during this exclusive epoch: firmware/SMM,
/// other users and config writes are excluded. SPT additionally uses actual
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
            // Bits13:14 and scales6:7 are reserved. Bit15 is the actual
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
    /// requirements hold, with exact actual vendor8086/class020000 and one of
    /// 153a/153b/15a0/15a1. `LptRegisters` binds actual immutable config limits
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
                // Keep the actual function/config/mapping owner on observed
                // access failure or invalid platform limits, before mutation.
                core::mem::forget(bus);
                return Err(error);
            }
        };
        // SAFETY: exact same retained LPT function/config/reset epoch, with
        // exclusive serialized MAC/flash adapters and actual delay clones.
        let nvm = unsafe { nvm::Nvm::new(nvm::Layout::Lpt, bus.clone(), delay.clone()) }?;
        // SAFETY: observed exact PCI cohort selects the actual I217 PHY path.
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
        // SPT mirrors the actual analog K1-off enable bit. LPT preserves it;
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
pub(super) mod tests {
    extern crate std;
    use super::super::tests::{fixture_lpt, start_lpt};
    use super::*;
    use alloc::vec::Vec;
    use core::sync::atomic::Ordering;

    pub(in crate::net::e1000e::pch::cold) fn oracle_cases(
        mode: u32,
    ) -> Vec<([u32; 4], Vec<[u32; 3]>)> {
        oracle_cases_for(mode, "STELA_E1000E_PCH_LPT_ORACLE")
    }
    pub(in crate::net::e1000e::pch::cold) fn oracle_cases_for(
        mode: u32,
        environment: &str,
    ) -> Vec<([u32; 4], Vec<[u32; 3]>)> {
        let path = std::env::var_os(environment).expect("LPT trace path");
        let bytes = std::fs::read(path).expect("read LPT trace");
        assert_eq!(bytes.len() % 4, 0);
        let words: Vec<_> = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|v| u32::from_le_bytes(*v))
            .collect();
        let mut result = Vec::new();
        let mut cursor = 0;
        while cursor < words.len() {
            let [phase, a, b, c, d, count] = *words[cursor..cursor + 6].first_chunk::<6>().unwrap();
            cursor += 6;
            let operations = words[cursor..cursor + count as usize * 3]
                .as_chunks::<3>()
                .0
                .to_vec();
            cursor += count as usize * 3;
            if phase == mode {
                result.push(([a, b, c, d], operations));
            }
        }
        result
    }

    #[test]
    #[ignore = "set STELA_E1000E_PCH_LPT_ORACLE to an unchanged helper trace"]
    fn unchanged_linux_lpt_post_reset_lcd_smbus_and_oem_effects() {
        replay_post(false);
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_post(spt: bool) {
        let cases = if spt {
            super::super::spt::tests::oracle_cases(0)
        } else {
            oracle_cases(0)
        };
        replay_post_cases(spt.then_some(0x156f), cases);
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_post_family(
        family: super::super::i219::Family,
    ) {
        replay_post_cases(
            Some(super::super::i219::tests::sample_device(family)),
            super::super::i219::tests::oracle_cases(family, 0),
        );
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_post_cases(
        profile: Option<u16>,
        cases: Vec<([u32; 4], Vec<[u32; 3]>)>,
    ) {
        assert_eq!(cases.len(), 48);
        for ([sw, count, oem, freq], expected) in cases {
            let (state, _, io, timer) = if profile.is_some() {
                super::super::spt::tests::fixture_spt()
            } else {
                fixture_lpt()
            };
            // SAFETY: the one synchronous same-function model owns all observations.
            let mut controller = unsafe {
                if let Some(device) = profile {
                    super::super::mtp::tests::claim_any(device, io, timer)
                } else {
                    Controller::claim_lpt(0x153b, io, timer)
                }
            }
            .unwrap();
            let initial_ext = (64 << 16) | super::super::GATE_PHY;
            {
                let mut m = state.borrow_mut();
                m.operations.clear();
                m.mac.insert(super::super::super::EXTCNF_CTRL, initial_ext);
                m.mac.insert(
                    super::super::FEXTNVM,
                    if sw == 0 { 0 } else { super::super::SW_CONFIG },
                );
                m.mac.insert(super::super::EXTCNF_SIZE, count << 16);
                m.mac.insert(
                    super::super::PHY_CTRL,
                    if oem & 1 == 0 { 0 } else { 2 } | if oem & 2 == 0 { 0 } else { 0x40 },
                );
                m.mac.insert(
                    super::super::STRAP,
                    (freq << 12) | if freq & 1 == 0 { 0 } else { 0x55 << 17 },
                );
                m.mac.insert(
                    super::super::LEDCTL,
                    if freq & 1 == 0 { 0x5a38 } else { 0xa5c7 },
                );
                m.phy.clear();
                for (page, index, value) in [
                    (769, 16, 0x5252),
                    (769, 17, 0x77f7),
                    (0, 26, 0xa511),
                    (0, 30, 0x9632),
                    (0, 25, 0xa09c),
                ] {
                    m.phy.insert((1, page, index), value);
                }
            }
            controller.post_reset().unwrap();
            let actual = super::super::tests::post_effects(&state.borrow().operations, initial_ext);
            assert_eq!(
                actual, expected,
                "sw={sw} count={count} oem={oem} freq={freq}"
            );
        }
    }

    #[test]
    #[ignore = "set STELA_E1000E_PCH_LPT_ORACLE to an unchanged helper trace"]
    fn unchanged_linux_lpt_platform_ltr_effects() {
        replay_ltr(false);
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_ltr(spt: bool) {
        let cases = if spt {
            super::super::spt::tests::oracle_cases(1)
        } else {
            oracle_cases(1)
        };
        replay_ltr_cases(spt.then_some(0x156f), cases);
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_ltr_family(family: super::super::i219::Family) {
        replay_ltr_cases(
            Some(super::super::i219::tests::sample_device(family)),
            super::super::i219::tests::oracle_cases(family, 1),
        );
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_ltr_cases(
        profile: Option<u16>,
        cases: Vec<([u32; 4], Vec<[u32; 3]>)>,
    ) {
        assert_eq!(cases.len(), 325);
        for ([speed, receive, snoop, nosnoop], expected) in cases {
            let (state, _, io, timer) = if profile.is_some() {
                super::super::spt::tests::fixture_spt()
            } else {
                fixture_lpt()
            };
            {
                let mut m = state.borrow_mut();
                m.config.insert(LTR_SNOOP, snoop as u16);
                m.config.insert(LTR_NOSNOOP, nosnoop as u16);
                m.mac.insert(super::super::PBA, receive);
            }
            // SAFETY: actual modeled config and registers share one owner/epoch.
            let mut controller = unsafe {
                if let Some(device) = profile {
                    super::super::mtp::tests::claim_any(device, io, timer)
                } else {
                    Controller::claim_lpt(0x153a, io, timer)
                }
            }
            .unwrap();
            state.borrow_mut().operations.clear();
            let status = match speed {
                0 => None,
                10 => Some(0),
                100 => Some(1 << 6),
                1000 => Some(1 << 7),
                _ => panic!("unexpected source speed"),
            };
            controller.lpt_platform_pm(status).unwrap();
            let actual: Vec<_> = state
                .borrow()
                .operations
                .iter()
                .copied()
                .filter(|o| (o[0] == 0 && o[1] == super::super::PBA) || (o[0] == 1 && o[1] == LTRV))
                .collect();
            assert_eq!(
                actual, expected,
                "speed={speed} PBA={receive} snoop={snoop:x} nosnoop={nosnoop:x}"
            );
        }
    }

    #[test]
    fn legal_ltr_platform_limits_above_u32_range_never_wrap_to_a_smaller_limit() {
        // Donor uses u32 for decoded platform limits; scale5,value128 wraps
        // 2^32ns to zero. Preserve the legal PCIe latency in u64 instead.
        for limit in [0x1480, 0x1500, 0x17ff] {
            let limits = Limits::new(limit, limit).unwrap();
            assert!(Limits::decode(limit) >= 1u64 << 32);
            assert_eq!(limits.latency(26, 1000).unwrap(), 0x08b9);
        }
    }

    #[test]
    #[ignore = "set STELA_E1000E_PCH_LPT_ORACLE to an unchanged helper trace"]
    fn unchanged_linux_lpt_global_reset_prefix_and_forbidden_flush_boundary() {
        replay_reset(false);
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_reset(spt: bool) {
        let cases = if spt {
            super::super::spt::tests::oracle_cases(4)
        } else {
            oracle_cases(4)
        };
        replay_reset_cases(spt.then_some(0x156f), cases);
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_reset_family(
        family: super::super::i219::Family,
    ) {
        replay_reset_cases(
            Some(super::super::i219::tests::sample_device(family)),
            super::super::i219::tests::oracle_cases(family, 4),
        );
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_reset_cases(
        profile: Option<u16>,
        cases: Vec<([u32; 4], Vec<[u32; 3]>)>,
    ) {
        assert_eq!(cases.len(), 3);
        for ([busy, _, _, _], expected) in cases {
            let (state, _, io, timer) = if profile.is_some() {
                super::super::spt::tests::fixture_spt()
            } else {
                fixture_lpt()
            };
            // SAFETY: exclusively owned same-function cold software model.
            let mut controller = unsafe {
                if let Some(device) = profile {
                    super::super::mtp::tests::claim_any(device, io, timer)
                } else {
                    Controller::claim_lpt(0x15a0, io, timer)
                }
            }
            .unwrap();
            {
                let mut m = state.borrow_mut();
                m.mac.insert(
                    super::super::super::EXTCNF_CTRL,
                    (64 << 16) | super::super::GATE_PHY,
                );
                m.master_busy = busy as usize;
                m.operations.clear();
            }
            controller.global_reset().unwrap();
            let actual: Vec<_> = state
                .borrow()
                .operations
                .iter()
                .copied()
                .filter(|o| o[0] == 1 || o[0] == 2 || (o[0] == 0 && o[1] == super::super::STATUS))
                .collect();
            assert_eq!(actual, expected, "LPT master-busy polls={busy}");
        }
    }

    #[test]
    fn lpt_reset_readiness_and_bus_master_timeouts_are_terminal() {
        for failure in 0..4 {
            let (state, released, io, timer) = fixture_lpt();
            {
                let mut m = state.borrow_mut();
                match failure {
                    0 => m.reset_stuck = true,
                    1 => m.init_missing = true,
                    2 => m.reset_missing = true,
                    3 => m.master_busy = 1000,
                    _ => unreachable!(),
                }
            }
            assert!(start_lpt(0x153a, io, timer).is_err());
            assert_eq!(released.load(Ordering::SeqCst), 0);
            assert!(state.borrow().operations.len() < 40_000);
        }
    }

    #[test]
    fn exact_ulp_exempt_lpt_cohort_has_generation_correct_cold_reset_and_nvm() {
        for device in [0x153a, 0x153b, 0x15a0, 0x15a1] {
            let (state, released, io, timer) = fixture_lpt();
            let controller = start_lpt(device, io, timer).unwrap();
            assert_eq!(
                controller.identity(),
                Identity {
                    kind: Kind::I217,
                    id: 0x015400a0,
                    revision: 7
                }
            );
            assert_eq!(controller.station().0, [2, 0x11, 0x22, 0x33, 0x44, 0x55]);
            assert!(!controller.is_poisoned());
            let m = state.borrow();
            assert_eq!(&m.operations[..2], &[[7, 0xa8, 0x1003], [7, 0xaa, 0x1003]]);
            assert_eq!(
                m.mac[&super::super::super::EXTCNF_CTRL]
                    & (super::super::GATE_PHY | super::super::super::SWFLAG),
                super::super::GATE_PHY
            );
            assert_eq!(m.phy[&(1, 0, 26)] & 0x7ff, 0x3d5);
            assert_eq!(m.phy[&(1, 769, 20)], 0x125a);
            assert!(
                !m.operations
                    .iter()
                    .any(|o| o[0] == 1 && o[1] == super::super::FEXTNVM3)
            );
            assert!(!m.emi.contains_key(&super::super::MSE_THRESHOLD));
            assert!(!m.emi.contains_key(&super::super::LPI_UPDATE_TIMER));
            let at = m
                .operations
                .iter()
                .position(|o| {
                    o[0] == 1 && o[1] == super::super::CTRL && o[2] & super::super::RESET != 0
                })
                .unwrap();
            assert_eq!(m.operations[at + 1], [2, 20_000, 0]);
            drop(m);
            drop(controller);
            assert_eq!(released.load(Ordering::SeqCst), 1);
        }
        for unsupported in [0x1502, 0x1559, 0x155a, 0x15a2, 0x15a3, 0x156f, 0x1570] {
            let (state, released, io, timer) = fixture_lpt();
            assert!(
                matches!(start_lpt(unsupported, io, timer), Err(Error::UnsupportedDevice(id)) if id == unsupported)
            );
            assert!(state.borrow().operations.is_empty());
            assert_eq!(released.load(Ordering::SeqCst), 1);
        }
    }
    #[test]
    fn actual_config_access_failures_and_reserved_limits_refuse_before_mutation() {
        for at in 0..2 {
            for fault in [Fault::Access, Fault::Removed] {
                let (state, released, io, timer) = fixture_lpt();
                state.borrow_mut().fail_at = Some(at);
                state.borrow_mut().fail_with = fault;
                assert!(
                    matches!(start_lpt(0x153a,io,timer), Err(Error::Phy(super::super::super::Error { primary, .. })) if primary == fault)
                );
                assert!(state.borrow().operations.iter().all(|o| o[0] == 7));
                assert_eq!(released.load(Ordering::SeqCst), 0);
            }
        }
        for bad in [0xffff, 0x1800, 0x1c00, 0x2000, 0x4000] {
            for offset in [LTR_SNOOP, LTR_NOSNOOP] {
                let (state, released, io, timer) = fixture_lpt();
                state.borrow_mut().config.insert(offset, bad);
                assert!(
                    matches!(start_lpt(0x15a0,io,timer), Err(Error::LtrLimit(value)) if value == bad)
                );
                assert!(state.borrow().operations.iter().all(|o| o[0] == 7));
                assert_eq!(released.load(Ordering::SeqCst), 0);
            }
        }
    }
    #[test]
    fn forced_smbus_wrong_phy_and_invalid_smbus_frequency_are_not_recovery_success() {
        for failure in 0..4 {
            let (state, released, io, timer) = fixture_lpt();
            {
                let mut m = state.borrow_mut();
                match failure {
                    0 => {
                        m.mac.insert(CTRL_EXT, FORCE_SMBUS);
                    }
                    1 => {
                        m.phy.insert((1, 769, 23), 1);
                    }
                    2 => {
                        m.phy.insert((2, 0, 3), 0x93);
                    }
                    3 => {
                        let strap = m.mac[&super::super::STRAP] & !0x3000;
                        m.mac.insert(super::super::STRAP, strap);
                    }
                    _ => unreachable!(),
                }
            }
            assert!(start_lpt(0x153b, io, timer).is_err());
            assert_eq!(released.load(Ordering::SeqCst), 0);
            if failure == 3 {
                assert!(!state.borrow().phy.contains_key(&(1, 769, 20)));
            }
        }
    }
    #[test]
    fn every_lpt_cold_access_failure_retains_the_same_function_without_packet_dma() {
        let (state, _, io, timer) = fixture_lpt();
        let controller = start_lpt(0x15a1, io, timer).unwrap();
        let count = state.borrow().accesses;
        drop(controller);
        for at in 0..count {
            let (state, released, io, timer) = fixture_lpt();
            state.borrow_mut().fail_at = Some(at);
            assert!(
                start_lpt(0x15a1, io, timer).is_err(),
                "lost LPT cold fault{at}"
            );
            assert_eq!(
                released.load(Ordering::SeqCst),
                0,
                "released actual owner at{at}"
            );
            assert!(state.borrow().operations.iter().all(|o| !(o[0] == 1
                && matches!(o[1], super::super::RCTL | super::super::TCTL)
                && o[2] & 2 != 0)));
        }
    }
}
