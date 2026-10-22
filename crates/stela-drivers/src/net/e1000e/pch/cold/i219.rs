// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Exact PCI-table-selected I219 SPT/CNP/TGP/ADP cohorts. Family selection is
//! pinned to the donor's actual PCI table, not the product suffix or PHY ID.
//! In particular CMP12 selects SPT; CMP10/11 select CNP. MTP and later MACs
//! require additional PHY/K1/retry and real platform-quirk authority and refuse.
use super::{Controller, Delay, Error, lpt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Family {
    Spt,
    Cnp,
    Tgp,
    Adp,
}
impl Family {
    pub(super) fn from_device(device: u16) -> Option<Self> {
        Some(match device {
            0x156f | 0x1570 | 0x15b7 | 0x15b8 | 0x15b9 | 0x15d7 | 0x15d8 | 0x15e3 | 0x15d6
            | 0x0d53 | 0x0d55 => Self::Spt,
            0x15bd | 0x15be | 0x15bb | 0x15bc | 0x15df | 0x15e0 | 0x15e1 | 0x15e2 | 0x0d4e
            | 0x0d4f | 0x0d4c | 0x0d4d => Self::Cnp,
            0x15fb | 0x15fc | 0x15f9 | 0x15fa | 0x15f4 | 0x15f5 => Self::Tgp,
            0x0dc5 | 0x0dc6 | 0x1a1e | 0x1a1f | 0x1a1c | 0x1a1d | 0x0dc7 | 0x0dc8 | 0x550c
            | 0x550d => Self::Adp,
            _ => return None,
        })
    }
    pub(super) fn dma_clock_workaround(self) -> bool {
        matches!(self, Self::Tgp | Self::Adp)
    }
}
pub(super) const DONT_GATE_WAKE_DMA_CLOCK: u32 = 0x1000;

impl<R: lpt::LptRegisters, D: Delay + Clone> Controller<R, D> {
    /// Construct the exact reviewed I219 SPT/CNP/TGP/ADP PCI cohorts.
    ///
    /// # Safety
    /// The same actual powered PCI Function/reset epoch, aligned live config,
    /// MAC/integrated flash/PHY, exclusion, elapsed delays and initially
    /// accessible PHY requirements of `Controller::new_spt` apply. `device`
    /// comes from actual vendor8086/class020000 config identity and must be
    /// one of the exact source-table IDs. It is never inferred from PHY ID or
    /// board naming. The source's actual family chooses NVM validation and
    /// register policy. No native provider/probe or firmware/power transition
    /// authority is manufactured by this constructor.
    pub unsafe fn new_i219(device: u16, io: R, delay: D) -> Result<Self, Error> {
        // SAFETY: caller retains the actual same-function cold ownership epoch.
        let mut this = unsafe { Self::claim_i219(device, io, delay) }?;
        if let Err(error) = this.initialize_i219() {
            this.poisoned = true;
            this.phy.poisoned = true;
            return Err(error);
        }
        Ok(this)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::{
        nvm, spt,
        tests::{Io, Model, Timer},
    };
    use super::*;
    use alloc::{rc::Rc, sync::Arc, vec::Vec};
    use core::{
        cell::RefCell,
        sync::atomic::{AtomicUsize, Ordering},
    };
    pub(in crate::net::e1000e::pch::cold) fn sample_device(family: Family) -> u16 {
        match family {
            Family::Spt => 0x156f,
            Family::Cnp => 0x15bd,
            Family::Tgp => 0x15fb,
            Family::Adp => 0x0dc5,
        }
    }
    pub(in crate::net::e1000e::pch::cold) fn families() -> [Family; 4] {
        [Family::Spt, Family::Cnp, Family::Tgp, Family::Adp]
    }
    pub(in crate::net::e1000e::pch::cold) fn inventory() -> Vec<(u16, Family)> {
        (0..=u16::MAX)
            .filter_map(|id| Family::from_device(id).map(|family| (id, family)))
            .collect()
    }
    pub(in crate::net::e1000e::pch::cold) fn oracle_cases(
        family: Family,
        mode: u32,
    ) -> Vec<([u32; 4], Vec<[u32; 3]>)> {
        let name = match family {
            Family::Spt => "STELA_E1000E_PCH_I219_SPT_ORACLE",
            Family::Cnp => "STELA_E1000E_PCH_I219_CNP_ORACLE",
            Family::Tgp => "STELA_E1000E_PCH_I219_TGP_ORACLE",
            Family::Adp => "STELA_E1000E_PCH_I219_ADP_ORACLE",
        };
        super::super::lpt::tests::oracle_cases_for(mode, name)
    }
    pub(in crate::net::e1000e::pch::cold) fn fixture()
    -> (Rc<RefCell<Model>>, Arc<AtomicUsize>, Io, Timer) {
        spt::tests::fixture_spt()
    }
    pub(in crate::net::e1000e::pch::cold) fn start(
        device: u16,
        io: Io,
        timer: Timer,
    ) -> Result<Controller<Io, Timer>, Error> {
        // SAFETY: one actual isolated same-function cold/config/flash model.
        unsafe { Controller::new_i219(device, io, timer) }
    }
    #[test]
    #[ignore = "set all four STELA_E1000E_PCH_I219_*_ORACLE paths"]
    fn unchanged_source_pci_board_mac_join_is_exact_and_exhaustive() {
        let mut seen = Vec::new();
        for (code, family) in families().into_iter().enumerate() {
            for ([device, source_family, _, _], ops) in oracle_cases(family, 10) {
                assert!(ops.is_empty());
                assert_eq!(source_family, code as u32);
                assert_eq!(Family::from_device(device as u16), Some(family));
                assert!(!seen.contains(&(device as u16)));
                seen.push(device as u16);
            }
        }
        assert_eq!(seen.len(), 39);
        for id in 0..=u16::MAX {
            assert_eq!(
                Family::from_device(id).is_some(),
                seen.contains(&id),
                "unexpected PCI admission{id:04x}"
            );
        }
        // Suffix alone is not family authority: the source sends CMP12 to SPT.
        assert_eq!(Family::from_device(0x0d53), Some(Family::Spt));
        assert_eq!(Family::from_device(0x0d4e), Some(Family::Cnp));
    }
    #[test]
    #[ignore = "set all four STELA_E1000E_PCH_I219_*_ORACLE paths"]
    fn unchanged_family_nvm_policies_keep_repair_checksum_and_tgp_exemptions_distinct() {
        for family in families() {
            let cases = oracle_cases(family, 9);
            assert_eq!(cases.len(), 6);
            for ([marker, check, expected, _], _) in cases {
                let (state, _, io, timer) = fixture();
                {
                    let mut m = state.borrow_mut();
                    m.words[3] = (m.words[3] & !1) | marker as u16;
                    let sum = m.words[..63].iter().copied().fold(0u16, u16::wrapping_add);
                    m.words[63] = 0xbabau16.wrapping_sub(sum);
                    if check == 1 {
                        m.words[63] ^= 1;
                    }
                    if check == 2 {
                        m.words[63] = 0xffff;
                    }
                }
                // SAFETY: exact observed modeled PCI ID chooses actual NVM policy.
                let mut controller =
                    unsafe { Controller::claim_i219(sample_device(family), io, timer) }.unwrap();
                let result = controller.validate_nvm();
                let kind = match result {
                    Ok(()) => 0,
                    Err(Error::Nvm(nvm::Error::Checksum(_))) => 1,
                    Err(Error::Nvm(nvm::Error::RepairRequired)) => 2,
                    Err(other) => panic!("unexpected family NVM error{other:?}"),
                };
                assert_eq!(
                    kind, expected,
                    "family={family:?} marker={marker} check={check}"
                );
                if kind == 0 {
                    assert_eq!(
                        controller.nvm.station().unwrap().0,
                        [2, 0x11, 0x22, 0x33, 0x44, 0x55]
                    );
                }
                assert!(
                    state
                        .borrow()
                        .operations
                        .iter()
                        .filter(|o| o[0] == 6 && o[1] == 4)
                        .all(|o| ((o[2] >> 16) & 6) == 0)
                );
            }
        }
    }
    #[test]
    fn source_exempt_nvm_still_requires_real_bank_station_and_successful_access() {
        for family in [Family::Tgp, Family::Adp] {
            for failure in 0..3 {
                let (state, released, io, timer) = fixture();
                {
                    let mut m = state.borrow_mut();
                    m.words[3] &= !1;
                    match failure {
                        0 => {
                            m.words[19] = 0xffff;
                            m.words[1043] = 0xffff;
                        }
                        1 => {
                            m.words[..3].fill(0);
                            let sum = m.words[..63].iter().copied().fold(0u16, u16::wrapping_add);
                            m.words[63] = 0xbabau16.wrapping_sub(sum);
                        }
                        2 => {
                            m.fail_at = Some(8);
                        }
                        _ => unreachable!(),
                    }
                }
                assert!(start(sample_device(family), io, timer).is_err());
                assert_eq!(released.load(Ordering::SeqCst), 0);
                assert!(
                    !state
                        .borrow()
                        .operations
                        .iter()
                        .any(|o| o[0] == 1 && matches!(o[1], 0x100 | 0x400) && o[2] & 2 != 0)
                );
            }
        }
    }
    #[test]
    fn mtp_plus_initial_recovery_and_unknown_ids_refuse_before_config_or_dma() {
        for id in [
            0x550a, 0x550b, 0x550e, 0x550f, 0x5510, 0x5511, 0x57a0, 0x57a1, 0x57b3, 0x57b4, 0x57b7,
            0x57b8, 0x57b9, 0x57ba, 0x15a2, 0xffff,
        ] {
            let (state, released, io, timer) = fixture();
            assert!(
                matches!(start(id,io,timer),Err(Error::UnsupportedDevice(device))if device==id)
            );
            assert!(state.borrow().operations.is_empty());
            assert_eq!(released.load(Ordering::SeqCst), 1);
        }
        for family in families() {
            let (state, released, io, timer) = fixture();
            state.borrow_mut().phy.insert((2, 0, 3), 0x93);
            assert!(start(sample_device(family), io, timer).is_err());
            assert_eq!(released.load(Ordering::SeqCst), 0);
        }
    }
    #[test]
    #[ignore = "set all four STELA_E1000E_PCH_I219_*_ORACLE paths"]
    fn unchanged_family_reset_post_phy_ulp_and_platform_effects() {
        for family in families() {
            super::super::lpt::tests::replay_post_family(family);
            super::super::lpt::tests::replay_ltr_family(family);
            super::super::lpt::tests::replay_reset_family(family);
            spt::tests::replay_ulp(sample_device(family), oracle_cases(family, 5));
        }
    }
    #[test]
    fn each_exempt_nvm_validation_access_fault_fails_before_a_valid_observation() {
        for family in [Family::Tgp, Family::Adp] {
            let (state, _, io, timer) = fixture();
            {
                let mut m = state.borrow_mut();
                m.words[3] &= !1;
                let sum = m.words[..63].iter().copied().fold(0u16, u16::wrapping_add);
                m.words[63] = 0xbabau16.wrapping_sub(sum);
            }
            // SAFETY: actual modeled same-function generation/flash grant.
            let mut controller =
                unsafe { Controller::claim_i219(sample_device(family), io, timer) }.unwrap();
            let first = state.borrow().accesses;
            controller.validate_nvm().unwrap();
            let last = state.borrow().accesses;
            drop(controller);
            for at in first..last {
                let (state, released, io, timer) = fixture();
                {
                    let mut m = state.borrow_mut();
                    m.words[3] &= !1;
                    let sum = m.words[..63].iter().copied().fold(0u16, u16::wrapping_add);
                    m.words[63] = 0xbabau16.wrapping_sub(sum);
                }
                // SAFETY: fresh actual isolated model owner, not retrying failure.
                let mut controller =
                    unsafe { Controller::claim_i219(sample_device(family), io, timer) }.unwrap();
                state.borrow_mut().fail_at = Some(at);
                assert!(
                    controller.validate_nvm().is_err(),
                    "accepted failed {family:?} observation{at}"
                );
                drop(controller);
                assert_eq!(released.load(Ordering::SeqCst), 0);
            }
        }
    }
}
