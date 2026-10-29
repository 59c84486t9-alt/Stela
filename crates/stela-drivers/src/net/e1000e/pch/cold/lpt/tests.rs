extern crate std;
use super::super::tests::{fixture_lpt, start_lpt};
use super::*;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

pub(in crate::net::e1000e::pch::cold) fn oracle_cases(mode: u32) -> Vec<([u32; 4], Vec<[u32; 3]>)> {
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
#[ignore = "oracle: STELA_E1000E_PCH_LPT_ORACLE"]
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
pub(in crate::net::e1000e::pch::cold) fn replay_post_family(family: super::super::i219::Family) {
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
#[ignore = "oracle: STELA_E1000E_PCH_LPT_ORACLE"]
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
        // SAFETY: modeled config and registers share one owner/epoch.
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
#[ignore = "oracle: STELA_E1000E_PCH_LPT_ORACLE"]
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
pub(in crate::net::e1000e::pch::cold) fn replay_reset_family(family: super::super::i219::Family) {
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
fn config_access_failures_and_reserved_limits_refuse_before_mutation() {
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
fn every_lpt_cold_access_failure_keeps_the_same_function_without_packet_dma() {
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
