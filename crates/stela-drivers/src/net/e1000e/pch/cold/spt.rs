// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Initial SPT I219 LM/V (156f/1570), with the actual integrated flash window,
//! unmanaged force-ULP exit and descriptor-flush status. Later I219 generations
//! are not selected by their common I217 PHY ID. Initial PHY identity must be
//! accessible; firmware/SMM, ME ownership and other users remain excluded.
use super::{
    Bus, Controller, Delay, Error, Fault, Identity, Kind, Phy, Profile, Register, Registers, i219,
    lpt, nvm,
};
use alloc::rc::Rc;
use core::cell::RefCell;

pub(super) const DESCRIPTOR_STATUS: u16 = 0xe4;
pub(super) const FLUSH_REQUIRED: u16 = 0x100;
pub(super) const FEXTNVM11: u32 = 0x5bbc;
pub(super) const DISABLE_MULR_FIX: u32 = 0x2000;
pub(super) const FEXTNVM7: u32 = 0xe4;
pub(super) const SIDE_CLOCK_UNGATE: u32 = 4;
pub(super) const FEXTNVM9: u32 = 0x5bb4;
pub(super) const IOSF_CLOCK_GATING_DISABLE: u32 = 0x1800;
pub(super) const IOSFPC: u32 = 0xf28;
pub(super) const CORRUPTION_THRESHOLD: u32 = 1 << 16;
pub(super) const TARC_REQUEST_MASK: u32 = 0x3000_0000;
pub(super) const TARC_TWO_REQUESTS: u32 = 0x2000_0000;
pub(super) const PCIE_ANALOG: u32 = 0xf18;
pub(super) const K1_OFF_ENABLE: u32 = 1 << 31;
pub(super) const FLUSH_BYTES: u32 = 512;
const DISABLE_SMB_PERST: u32 = 0x20;
const CTRL_EXT: u32 = 0x18;
const FORCE_SMBUS: u32 = 1 << 11;
const POWER_CYCLE_DONE: u32 = 4;
const LANPHYPC_OVERRIDE: u32 = 1 << 16;
const LANPHYPC_VALUE: u32 = 1 << 17;
const SMB_CONTROL: Register = Register {
    page: 769,
    index: 23,
};
const PM_CONTROL: Register = Register {
    page: 770,
    index: 17,
};
const K1_ENABLE: u16 = 1 << 14;
const ULP_CONFIG: Register = Register {
    page: 779,
    index: 16,
};
const ULP_CLEAR: u16 = 0x4 | 0x10 | 0x20 | 0x40 | 0x100 | 0x400 | 0x800 | 0x1000;
const ULP_START: u16 = 1;

impl<R: lpt::LptRegisters, D: Delay + Clone> Controller<R, D> {
    /// Construct only the initial SPT I219 LM/V cohort.
    ///
    /// # Safety
    /// All `Controller::new` same-function physical ownership/reset/exclusion
    /// requirements apply, with actual vendor8086/class020000/device156f/1570.
    /// Actual config/MMIO/integrated MAC+e000 flash/PHY share one retained
    /// Function/reset epoch. LTR words remain immutable, while config e4 is a
    /// real live read at every required reset/stop point. The initial PHY is
    /// accessible and identifies as I217 before the forced interconnect cycle.
    /// A foreign ring requiring flush is refused without touching foreign RAM.
    /// No native config/MMIO/DMA provider or probe admission is supplied here.
    pub unsafe fn new_spt(device: u16, io: R, delay: D) -> Result<Self, Error> {
        // SAFETY: caller supplies the exact live same-function cold epoch.
        let mut this = unsafe { Self::claim_spt(device, io, delay) }?;
        if let Err(error) = this.initialize_i219() {
            this.poisoned = true;
            this.phy.poisoned = true;
            return Err(error);
        }
        Ok(this)
    }
    pub(super) unsafe fn claim_spt(device: u16, io: R, delay: D) -> Result<Self, Error> {
        if !matches!(device, 0x156f | 0x1570) {
            return Err(Error::UnsupportedDevice(device));
        }
        // SAFETY: same exact actual initial SPT grant passed to the shared owner.
        unsafe { Self::claim_i219(device, io, delay) }
    }
    pub(super) unsafe fn claim_i219(device: u16, io: R, delay: D) -> Result<Self, Error> {
        let family = i219::Family::from_device(device).ok_or(Error::UnsupportedDevice(device))?;
        // SAFETY: exact source-selected actual family under the same owner grant.
        unsafe { Self::claim_integrated(io, delay, |limits| Profile::I219(limits, family)) }
    }
    pub(super) unsafe fn claim_integrated(
        io: R,
        delay: D,
        profile: impl FnOnce(lpt::Limits) -> Profile,
    ) -> Result<Self, Error> {
        let bus = Bus(Rc::new(RefCell::new(io)));
        let limits = (|| {
            let snoop = bus.0.borrow_mut().read_config16(0xa8)?;
            let nosnoop = bus.0.borrow_mut().read_config16(0xaa)?;
            lpt::Limits::new(snoop, nosnoop)
        })();
        let limits = match limits {
            Ok(value) => value,
            Err(error) => {
                core::mem::forget(bus);
                return Err(error);
            }
        };
        // SAFETY: the retained actual SPT function owns its integrated window.
        let nvm = unsafe { nvm::Nvm::new(nvm::Layout::Spt, bus.clone(), delay.clone()) }?;
        // SAFETY: exact actual PCI cohort selects the reviewed I217 transport.
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
            profile: profile(limits),
            config_read: Some(R::read_config16),
        })
    }
}

impl<R: Registers + nvm::Registers, D: Delay + Clone> Controller<R, D> {
    pub(super) fn i219_family(&self) -> Option<i219::Family> {
        match self.profile {
            Profile::I219(_, family) => Some(family),
            _ => None,
        }
    }
    pub(super) fn is_i219(&self) -> bool {
        self.i219_family().is_some() || self.mtp_family().is_some()
    }
    pub(super) fn is_spt_mac(&self) -> bool {
        self.i219_family() == Some(i219::Family::Spt)
    }
    pub(super) fn spt_config_status(&mut self) -> Result<u16, Error> {
        let read = self.config_read.ok_or(Error::Configuration)?;
        let io = self.phy.io.as_ref().expect("retained same-function owner");
        let value = read(&mut *io.0.borrow_mut(), DESCRIPTOR_STATUS)?;
        if value == u16::MAX {
            return Err(Fault::Removed.into());
        }
        Ok(value)
    }
    fn inherited_ring_check(&mut self) -> Result<(), Error> {
        let length = self.read(0x3808)?;
        let status = self.spt_config_status()?;
        if length != 0 && status & FLUSH_REQUIRED != 0 {
            return Err(Error::DescriptorFlushRequired);
        }
        Ok(())
    }
    pub(super) fn initialize_i219(&mut self) -> Result<(), Error> {
        self.qualify()?;
        self.inherited_ring_check()?;
        self.identity = self.phy.identify()?;
        self.validate_nvm()?;
        self.station = self.nvm.station()?;
        self.gate(true)?;
        self.spt_ulp_exit()?;
        // The donor releases SWFLAG before this hardware PHY reset. No PHY
        // transaction wrapper may span it, or the later full-chip reset.
        self.phy_reset()?;
        self.configuration_done()?;
        self.post_reset()?;
        self.phy.delay.delay(50_000);
        self.qualify()?;
        self.identity = self.phy.identify()?;
        if self.phy.read(ULP_CONFIG)? & ULP_CLEAR != 0 {
            return Err(Error::UlpState);
        }
        if self.phy.read(SMB_CONTROL)? & 1 != 0 || self.read(CTRL_EXT)? & FORCE_SMBUS != 0 {
            return Err(Error::SmbusMode);
        }
        self.mtp_initial_k1(true)?;
        // The source initialization flow follows forced ULP exit with another
        // generic PHY reset before normal MAC reset/PHY post-configuration.
        self.phy_reset()?;
        self.configuration_done()?;
        self.mtp_initial_k1(false)?;
        self.qualify()?;
        self.identity = self.phy.identify()?;
        self.write(super::PBA, super::RX_ALLOCATION_KIB)?;
        self.inherited_ring_check()?;
        let value = self.read(FEXTNVM11)?;
        self.write(FEXTNVM11, value | DISABLE_MULR_FIX)?;
        self.global_reset()?;
        self.configuration_done()?;
        self.post_reset()?;
        self.write(super::IMC, u32::MAX)?;
        self.read(super::ICR)?;
        let bias = self.read(super::KABGTXD)?;
        self.write(super::KABGTXD, bias | super::BGSQLBIAS)?;
        self.mtp_reset_finish()?;
        self.identity = self.phy.identify()?;
        Ok(())
    }
    fn spt_ulp_exit(&mut self) -> Result<(), Error> {
        let cycle_done = self.phy.transaction(|p| {
            let value = p.read_mac(super::FEXTNVM3)?;
            p.write_mac(
                super::FEXTNVM3,
                (value & !super::CONFIG_COUNTER) | super::CONFIG_50MS,
            )?;
            let value = p.read_mac(super::CTRL)?;
            let value = (value | LANPHYPC_OVERRIDE) & !LANPHYPC_VALUE;
            p.write_mac(super::CTRL, value)?;
            p.read_mac(super::STATUS)?;
            p.delay.delay(10);
            p.write_mac(super::CTRL, value & !LANPHYPC_OVERRIDE)?;
            p.read_mac(super::STATUS)?;
            let mut done = false;
            for _ in 0..=20 {
                p.delay.delay(5_000);
                if p.read_mac(CTRL_EXT)? & POWER_CYCLE_DONE != 0 {
                    done = true;
                    break;
                }
            }
            p.delay.delay(30_000);
            if !done {
                return Ok(false);
            }
            p.retry_enabled = false;
            // A mode-switch MDIC error is a source-defined transition, not an
            // access/removal fault. Only the exact CV_SMB_CTRL response may
            // take this path; final actual readback must prove PCIe mode.
            p.page(SMB_CONTROL.page)?;
            let mut word = match p.mdic(1, SMB_CONTROL.index, None) {
                Ok(value) => value,
                Err(error) if smbus_read_unavailable(error) => {
                    let value = p.read_mac(CTRL_EXT)?;
                    p.write_mac(CTRL_EXT, value | FORCE_SMBUS)?;
                    p.delay.delay(50_000);
                    p.page(SMB_CONTROL.page)?;
                    p.mdic(1, SMB_CONTROL.index, None)?
                }
                Err(error) => return Err(error),
            };
            let switching = word & 1 != 0;
            word &= !1;
            match p.mdic(1, SMB_CONTROL.index, Some(word)) {
                Ok(_) => {}
                Err(error) if switching && smbus_response_error(error) => {}
                Err(error) => return Err(error),
            }
            p.retry_enabled = true;
            let value = p.read_mac(CTRL_EXT)?;
            p.write_mac(CTRL_EXT, value & !FORCE_SMBUS)?;
            let value = p.access(PM_CONTROL, None)?;
            p.access(PM_CONTROL, Some(value | K1_ENABLE))?;
            let value = p.access(ULP_CONFIG, None)? & !ULP_CLEAR;
            p.access(ULP_CONFIG, Some(value))?;
            p.access(ULP_CONFIG, Some(value | ULP_START))?;
            let value = p.read_mac(FEXTNVM7)?;
            p.write_mac(FEXTNVM7, value & !DISABLE_SMB_PERST)?;
            Ok(true)
        })?;
        if !cycle_done {
            return Err(Error::PowerCycleTimeout);
        }
        Ok(())
    }
}
fn smbus_response_error(error: Fault) -> bool {
    let Fault::MdicResponse(response) = error else {
        return false;
    };
    let mask = super::super::MDIC_READY
        | super::super::MDIC_ERROR
        | super::super::MDIC_REG_MASK
        | (31 << 21);
    let expected = super::super::MDIC_READY
        | super::super::MDIC_ERROR
        | (u32::from(SMB_CONTROL.index) << 16)
        | (1 << 21);
    response & mask == expected
}
fn smbus_read_unavailable(error: Fault) -> bool {
    matches!(error, Fault::MdicTimeout) || smbus_response_error(error)
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::{Io, Model, Timer, fixture_lpt};
    use super::*;
    use alloc::{rc::Rc, sync::Arc};
    use core::{
        cell::RefCell,
        sync::atomic::{AtomicUsize, Ordering},
    };

    pub(in crate::net::e1000e::pch::cold) fn fixture_spt()
    -> (Rc<RefCell<Model>>, Arc<AtomicUsize>, Io, Timer) {
        let (state, released, io, timer) = fixture_lpt();
        {
            let mut m = state.borrow_mut();
            m.spt = true;
            m.phy.insert((1, 779, 16), 0xffff);
            m.phy.insert((1, 769, 23), 0x7f00);
            m.mac.insert(FEXTNVM7, 0xaaaa_003f);
        }
        (state, released, io, timer)
    }
    pub(in crate::net::e1000e::pch::cold) fn start_spt(
        device: u16,
        io: Io,
        timer: Timer,
    ) -> Result<Controller<Io, Timer>, Error> {
        // SAFETY: one actual synchronous modeled Function/config/PHY/flash.
        unsafe { Controller::new_spt(device, io, timer) }
    }
    pub(in crate::net::e1000e::pch::cold) fn oracle_cases(
        mode: u32,
    ) -> alloc::vec::Vec<([u32; 4], alloc::vec::Vec<[u32; 3]>)> {
        super::super::lpt::tests::oracle_cases_for(mode, "STELA_E1000E_PCH_SPT_ORACLE")
    }
    #[test]
    #[ignore = "set STELA_E1000E_PCH_SPT_ORACLE to an unchanged helper trace"]
    fn unchanged_linux_spt_post_reset_ltr_and_global_reset_effects() {
        super::super::lpt::tests::replay_post(true);
        super::super::lpt::tests::replay_ltr(true);
        super::super::lpt::tests::replay_reset(true);
    }

    pub(in crate::net::e1000e::pch::cold) fn source_effects(
        operations: &[[u32; 3]],
        mode: u32,
    ) -> alloc::vec::Vec<[u32; 3]> {
        let mut result = alloc::vec::Vec::new();
        let mut page = 0;
        let mut pending = None;
        for &[kind, at, value] in operations {
            if kind == 2
                && ((mode == 5 && (at == 10 || at >= 5000))
                    || (mode == 11 && matches!(at, 2 | 20 | 1000)))
            {
                result.push([kind, at, value]);
            }
            let mac = match mode {
                5 => matches!(at, 0 | 8 | 0x18 | 0x3c | 0xe4),
                11 => matches!(at, 0 | 8 | 0x18 | 0x34 | 0x5bc0),
                6 => matches!(at, 0x410 | 0x24 | 0x10 | 0xf18 | 0x1000 | 0xf8),
                _ => false,
            };
            if kind <= 1 && mac {
                result.push([kind, at, value]);
            }
            if at != super::super::super::MDIC {
                continue;
            }
            if kind == 1 {
                let index = (value >> 16) & 31;
                if index == 31 {
                    page = (value & 0xffff) >> 5;
                    continue;
                }
                let address = (value >> 21) & 31;
                let logical = if index <= 15 {
                    index
                } else {
                    ((if address == 1 && page == 0 { 768 } else { page }) << 5) | index
                };
                if value & super::super::super::MDIC_WRITE != 0 {
                    result.push([11, logical, value & 0xffff]);
                } else {
                    pending = Some(logical);
                }
            } else if kind == 0
                && let Some(logical) = pending.take()
            {
                result.push(if value & (1 << 30) != 0 {
                    [12, logical, 0]
                } else {
                    [10, logical, value & 0xffff]
                });
            }
        }
        if mode == 6 {
            // Stela reasserts the previously source-compared EEE advertisement
            // disable policy on each link change. The source check-link helper
            // only runs its LPI disable operation; advertisement was set at reset.
            let mut filtered = alloc::vec::Vec::new();
            let mut at = 0;
            while at < result.len() {
                if result[at] == [11, 16, 0x8001] && result.get(at + 1) == Some(&[11, 17, 0]) {
                    at += 2;
                } else {
                    filtered.push(result[at]);
                    at += 1;
                }
            }
            result = filtered;
        }
        result
    }
    #[test]
    #[ignore = "set STELA_E1000E_PCH_SPT_ORACLE to an unchanged helper trace"]
    fn unchanged_linux_spt_forced_ulp_exit_ordered_effects() {
        replay_ulp(0x156f, oracle_cases(5));
    }
    pub(in crate::net::e1000e::pch::cold) fn replay_ulp(
        device: u16,
        cases: alloc::vec::Vec<([u32; 4], alloc::vec::Vec<[u32; 3]>)>,
    ) {
        assert_eq!(cases.len(), 36);
        for ([busy, hidden, force, ulp], expected) in cases {
            let (state, _, io, timer) = fixture_spt();
            // SAFETY: actual same-function model with integrated flash geometry.
            let mut controller =
                unsafe { super::super::mtp::tests::claim_any(device, io, timer) }.unwrap();
            {
                let mut m = state.borrow_mut();
                m.power_busy = busy as usize;
                m.smb_hidden_after_power = hidden != 0;
                m.mac.insert(CTRL_EXT, 0x1000);
                m.mac.insert(super::super::FEXTNVM3, 0x5abc1234);
                m.mac.insert(FEXTNVM7, 0xaaaa00ff);
                m.phy.insert((1, 769, 23), 0xa500 | force as u16);
                m.phy.insert((1, 770, 17), 0x9332);
                m.phy.insert((1, 779, 16), ulp as u16);
                m.operations.clear();
            }
            controller.spt_ulp_exit().unwrap();
            let actual = source_effects(&state.borrow().operations, 5);
            assert_eq!(
                actual, expected,
                "busy={busy} hidden={hidden} force={force} ulp={ulp:x}"
            );
        }
    }
    #[test]
    fn exact_initial_i219_cohort_uses_integrated_nvm_and_forced_ulp_exit() {
        for device in [0x156f, 0x1570] {
            let (state, released, io, timer) = fixture_spt();
            let controller = start_spt(device, io, timer).unwrap();
            assert_eq!(controller.identity().id, 0x0154_00a0);
            assert_eq!(controller.station().0, [2, 0x11, 0x22, 0x33, 0x44, 0x55]);
            assert_eq!(controller.nvm.geometry().bank_words, 1024);
            let m = state.borrow();
            assert_eq!(m.phy[&(1, 779, 16)] & ULP_CLEAR, 0);
            assert_ne!(m.phy[&(1, 770, 17)] & K1_ENABLE, 0);
            assert_eq!(m.mac[&FEXTNVM7] & DISABLE_SMB_PERST, 0);
            assert_ne!(m.mac[&FEXTNVM11] & DISABLE_MULR_FIX, 0);
            assert!(
                m.operations
                    .iter()
                    .any(|o| o[0] == 6 && o[1] == 4 && o[2] >> 16 != 0)
            );
            assert!(!m.operations.iter().any(|o| o[0] == 4 && o[1] == 0));
            assert!(!m.operations.iter().any(|o| o[0] == 5 && o[1] == 6));
            let power = m
                .operations
                .iter()
                .position(|o| {
                    o[0] == 1 && o[1] == super::super::CTRL && o[2] & LANPHYPC_OVERRIDE != 0
                })
                .unwrap();
            assert_eq!(m.operations[power + 1][..2], [0, super::super::STATUS]);
            assert_eq!(m.operations[power + 2], [2, 10, 0]);
            let reset = m
                .operations
                .iter()
                .position(|o| {
                    o[0] == 1 && o[1] == super::super::CTRL && o[2] & super::super::RESET != 0
                })
                .unwrap();
            assert_eq!(m.operations[reset + 1], [2, 20_000, 0]);
            drop(m);
            drop(controller);
            assert_eq!(released.load(Ordering::SeqCst), 1);
        }
        for device in [
            0x1502, 0x153a, 0x1559, 0x15b7, 0x15b8, 0x15b9, 0x15d7, 0x15e3, 0x15bd,
        ] {
            let (state, released, io, timer) = fixture_spt();
            assert!(
                matches!(start_spt(device,io,timer),Err(Error::UnsupportedDevice(id))if id==device)
            );
            assert!(state.borrow().operations.is_empty());
            assert_eq!(released.load(Ordering::SeqCst), 1);
        }
    }
    #[test]
    fn foreign_required_flush_and_live_config_failures_refuse_without_foreign_dma() {
        for failure in 0..4 {
            let (state, released, io, timer) = fixture_spt();
            {
                let mut m = state.borrow_mut();
                m.mac.insert(0x3808, 512);
                match failure {
                    0 => {
                        m.config.insert(DESCRIPTOR_STATUS, FLUSH_REQUIRED);
                    }
                    1 => {
                        m.config.insert(DESCRIPTOR_STATUS, 0xffff);
                    }
                    2 => {
                        m.fail_at = Some(5);
                    }
                    3 => {
                        m.power_stuck = true;
                    }
                    _ => unreachable!(),
                }
            }
            assert!(start_spt(0x156f, io, timer).is_err());
            let m = state.borrow();
            if failure < 3 {
                assert!(
                    !m.operations
                        .iter()
                        .any(|o| o[0] == 1 && matches!(o[1], super::super::CTRL | 0x3818))
                );
            }
            assert_eq!(released.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn ulp_mode_switch_recovers_only_the_specific_mdi_transition_and_verifies_state() {
        let (state, released, io, timer) = fixture_spt();
        state.borrow_mut().smb_hidden_after_power = true;
        let controller = start_spt(0x156f, io, timer).unwrap();
        assert_eq!(state.borrow().phy[&(1, 769, 23)] & 1, 0);
        assert_eq!(state.borrow().mac[&CTRL_EXT] & FORCE_SMBUS, 0);
        assert!(
            state
                .borrow()
                .operations
                .iter()
                .any(|o| o[0] == 1 && o[1] == CTRL_EXT && o[2] & FORCE_SMBUS != 0)
        );
        assert!(
            state
                .borrow()
                .operations
                .iter()
                .filter(|o| **o == [2, 50_000, 0])
                .count()
                >= 2
        );
        drop(controller);
        assert_eq!(released.load(Ordering::SeqCst), 1);
        for stuck in [false, true] {
            let (state, released, io, timer) = fixture_spt();
            if stuck {
                let mut m = state.borrow_mut();
                m.smb_hidden_after_power = true;
                m.smb_stuck = true;
            } else {
                state.borrow_mut().ulp_stuck = true;
            }
            assert!(matches!(
                start_spt(0x1570, io, timer),
                Err(Error::SmbusMode | Error::UlpState)
            ));
            assert_eq!(released.load(Ordering::SeqCst), 0);
        }
        let expected = (1 << 28) | (1 << 30) | (23 << 16) | (1 << 21);
        assert!(smbus_response_error(Fault::MdicResponse(expected)));
        for bad in [
            expected ^ (1 << 30),
            expected ^ (1 << 28),
            expected ^ (1 << 16),
            expected ^ (1 << 21),
        ] {
            assert!(!smbus_response_error(Fault::MdicResponse(bad)));
        }
        for bad in [
            Fault::Access,
            Fault::Removed,
            Fault::OutsideBar,
            Fault::ResetBlocked,
        ] {
            assert!(!smbus_read_unavailable(bad));
        }
    }
    #[test]
    fn each_mode_switch_access_failure_is_terminal_and_retains_actual_owner() {
        let (state, _, io, timer) = fixture_spt();
        state.borrow_mut().smb_hidden_after_power = true;
        let controller = start_spt(0x156f, io, timer).unwrap();
        let count = state.borrow().accesses;
        drop(controller);
        for at in 0..count {
            let (state, released, io, timer) = fixture_spt();
            let mut m = state.borrow_mut();
            m.smb_hidden_after_power = true;
            m.fail_at = Some(at);
            drop(m);
            assert!(
                start_spt(0x156f, io, timer).is_err(),
                "lost mode-switch fault{at}"
            );
            assert_eq!(released.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    fn every_spt_cold_access_failure_retains_actual_owner_and_prevents_packet_dma() {
        let (state, _, io, timer) = fixture_spt();
        let controller = start_spt(0x1570, io, timer).unwrap();
        let count = state.borrow().accesses;
        drop(controller);
        for at in 0..count {
            let (state, released, io, timer) = fixture_spt();
            state.borrow_mut().fail_at = Some(at);
            assert!(
                start_spt(0x1570, io, timer).is_err(),
                "lost SPT cold access{at}"
            );
            assert_eq!(released.load(Ordering::SeqCst), 0, "released SPT owner{at}");
            assert!(!state.borrow().operations.iter().any(|o| o[0] == 1
                && matches!(o[1], super::super::RCTL | super::super::TCTL)
                && o[2] & 2 != 0));
        }
    }
    #[test]
    fn spt_firmware_reset_phy_nvm_and_readiness_failures_never_enable_packet_dma() {
        for failure in 0..7 {
            let (state, released, io, timer) = fixture_spt();
            {
                let mut m = state.borrow_mut();
                match failure {
                    0 => {
                        m.mac.insert(
                            super::super::super::FWSM,
                            super::super::super::FW_VALID | super::super::super::RESET_PERMITTED,
                        );
                    }
                    1 => {
                        m.mac.insert(super::super::super::FWSM, 0);
                    }
                    2 => {
                        m.phy.insert((2, 0, 3), 0x93);
                    }
                    3 => {
                        m.words[63] ^= 1;
                    }
                    4 => m.init_missing = true,
                    5 => m.reset_missing = true,
                    6 => m.reset_stuck = true,
                    _ => unreachable!(),
                }
            }
            assert!(start_spt(0x156f, io, timer).is_err());
            assert_eq!(released.load(Ordering::SeqCst), 0);
            assert!(!state.borrow().operations.iter().any(|o| o[0] == 1
                && matches!(o[1], super::super::RCTL | super::super::TCTL)
                && o[2] & 2 != 0));
        }
    }
}
