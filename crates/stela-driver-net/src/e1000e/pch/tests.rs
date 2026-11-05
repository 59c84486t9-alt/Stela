extern crate std;

use super::*;
use alloc::{collections::BTreeMap, rc::Rc, sync::Arc, vec::Vec};
use core::{
    cell::RefCell,
    sync::atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct State {
    timing_failure: Option<crate::bus::pci::power::Error>,
    fail_delay_at: Option<usize>,
    delay_calls: usize,
    timer_drops: Arc<AtomicUsize>,

    operations: Vec<[u32; 3]>,
    accesses: usize,
    fail_at: Option<usize>,
    fail_with: Option<Fault>,
    ext: u32,
    fw: u32,
    command: u32,
    page: u16,
    debug: u16,
    wake: u16,
    words: BTreeMap<(u8, u16, u16), u16>,
    unacknowledged: bool,
    timeout: bool,
    bad_response: u32,
    removed: Option<u32>,
}
impl State {
    fn new() -> Self {
        Self {
            ext: 0xa500_0800,
            fw: RESET_PERMITTED,
            ..Self::default()
        }
    }
    fn enter(&mut self) -> Result<(), Fault> {
        let at = self.accesses;
        self.accesses += 1;
        if self.fail_at == Some(at) {
            Err(self.fail_with.unwrap_or(Fault::Access))
        } else {
            Ok(())
        }
    }
    fn word(&self, address: u8, index: u16) -> u16 {
        let page = if index <= 15 { 0 } else { self.page };
        let key = if address == 1 && self.page == WAKE_PAGE && index == WAKE_DATA {
            (address, WAKE_PAGE, self.wake)
        } else if address == 2 && index == 17 {
            (2, 0xffff, self.debug)
        } else {
            (address, page, index)
        };
        self.words
            .get(&key)
            .copied()
            .unwrap_or_else(|| 0xa55a ^ (u16::from(address) << 8) ^ key.1.wrapping_mul(5) ^ key.2)
    }
    fn store(&mut self, address: u8, index: u16, data: u16) {
        if address == 1 && index == PHY_PAGE {
            self.page = data >> 5;
            return;
        }
        if address == 1 && self.page == WAKE_PAGE && index == WAKE_ADDRESS {
            self.wake = data;
            return;
        }
        if address == 2 && index == 16 {
            self.debug = data;
            return;
        }
        let page = if index <= 15 { 0 } else { self.page };
        let key = if address == 1 && page == WAKE_PAGE && index == WAKE_DATA {
            (address, page, self.wake)
        } else if address == 2 && index == 17 {
            (address, 0xffff, self.debug)
        } else {
            (address, page, index)
        };
        self.words.insert(key, data);
    }
}
struct Io {
    state: Rc<RefCell<State>>,
    released: Arc<AtomicUsize>,
}
impl Drop for Io {
    fn drop(&mut self) {
        self.released.fetch_add(1, Ordering::SeqCst);
    }
}
// SAFETY: this test owns one deterministic register model; no concurrent
// user accesses it during an operation and no device is touched.
unsafe impl Registers for Io {
    fn read32(&mut self, at: u32) -> Result<u32, Fault> {
        let mut s = self.state.borrow_mut();
        s.enter()?;
        let value = if s.removed == Some(at) {
            u32::MAX
        } else {
            match at {
                FWSM => s.fw,
                EXTCNF_CTRL => s.ext,
                MDIC => s.command,
                _ => panic!("unknown register"),
            }
        };
        s.operations.push([0, at, value]);
        Ok(value)
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Fault> {
        let mut s = self.state.borrow_mut();
        s.enter()?;
        s.operations.push([1, at, value]);
        match at {
            EXTCNF_CTRL => {
                s.ext = if s.unacknowledged {
                    value & !SWFLAG
                } else {
                    value
                }
            }
            MDIC => {
                let address = ((value >> 21) & 31) as u8;
                let index = ((value >> 16) & 31) as u16;
                let data = if value & MDIC_WRITE != 0 {
                    s.store(address, index, value as u16);
                    value as u16
                } else {
                    s.word(address, index)
                };
                s.command =
                    (value & !0xffff) | u32::from(data) | if s.timeout { 0 } else { MDIC_READY };
                s.command ^= s.bad_response;
            }
            _ => panic!("unknown write"),
        }
        Ok(())
    }
}
struct Timer(Rc<RefCell<State>>, Arc<AtomicUsize>);
impl Timer {
    fn new(state: Rc<RefCell<State>>) -> Self {
        let drops = state.borrow().timer_drops.clone();
        Self(state, drops)
    }
}
// SAFETY: isolated owned virtual-time model; this grants no native permission.
unsafe impl Delay for Timer {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        if let Some(error) = self.0.borrow().timing_failure {
            Err(error)
        } else {
            Ok(())
        }
    }
    fn wait_us(&self, microseconds: u64) -> Result<(), crate::bus::pci::power::Error> {
        self.check()?;
        {
            let mut state = self.0.borrow_mut();
            let at = state.delay_calls;
            state.delay_calls += 1;
            if state.fail_delay_at == Some(at) {
                let error = crate::bus::pci::power::Error::Clock;
                state.timing_failure = Some(error);
                return Err(error);
            }
        }
        self.0
            .borrow_mut()
            .operations
            .push([2, microseconds as u32, 0]);
        Ok(())
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        self.1.fetch_add(1, Ordering::Relaxed);
    }
}

type Fixture = (Phy<Io, Timer>, Rc<RefCell<State>>, Arc<AtomicUsize>);
fn fixture(kind: Kind) -> Fixture {
    let state = Rc::new(RefCell::new(State::new()));
    let released = Arc::new(AtomicUsize::new(0));
    let io = Io {
        state: state.clone(),
        released: released.clone(),
    };
    // SAFETY: fixture's exact PHY kind and sole model owner are controlled.
    (
        unsafe { Phy::new(kind, io, Timer::new(state.clone())) },
        state,
        released,
    )
}

#[test]
fn phy_identity_is_observed_under_one_semaphore_and_revision_kept() {
    for kind in [Kind::I82579, Kind::I217] {
        for revision in 0..16 {
            let (mut phy, state, _) = fixture(kind);
            state.borrow_mut().words.insert((2, 0, 2), 0x0154);
            state.borrow_mut().words.insert(
                (2, 0, 3),
                if kind == Kind::I82579 { 0x90 } else { 0xa0 } | revision,
            );
            assert_eq!(
                phy.identify().unwrap(),
                Identity {
                    kind,
                    id: if kind == Kind::I82579 {
                        0x0154_0090
                    } else {
                        0x0154_00a0
                    },
                    revision: revision as u8
                }
            );
            assert_eq!(state.borrow().ext, 0xa500_0800);
            let writes = state
                .borrow()
                .operations
                .iter()
                .filter(|op| op[0] == 1 && op[1] == EXTCNF_CTRL)
                .count();
            assert_eq!(writes, 2);
        }
    }
    let (mut phy, state, _) = fixture(Kind::I217);
    state.borrow_mut().words.insert((2, 0, 2), 0x0154);
    state.borrow_mut().words.insert((2, 0, 3), 0x90);
    assert!(matches!(
        phy.identify(),
        Err(Error {
            primary: Fault::WrongPhy(0x0154_0090),
            ..
        })
    ));
    assert!(phy.is_poisoned());
}

#[test]
fn wakeup_preserves_enable_and_unrelated_bits_with_extended_index() {
    let (mut phy, state, _) = fixture(Kind::I217);
    state
        .borrow_mut()
        .words
        .insert((1, PORT_PAGE, WAKE_ENABLE), 0xd5f3);
    let register = Register::new(WAKE_PAGE, 0x1234).unwrap();
    phy.write(register, 0x789a).unwrap();
    assert_eq!(phy.read(register).unwrap(), 0x789a);
    assert_eq!(state.borrow().words[&(1, PORT_PAGE, WAKE_ENABLE)], 0xd5f3);
    assert_eq!(state.borrow().ext, 0xa500_0800);
    assert!(!phy.is_poisoned());
}

#[test]
fn me_reset_and_occupied_semaphore_refuse_before_mutating_shared_registers() {
    for (fw, ext, expected) in [
        (RESET_PERMITTED | FW_VALID, 0, Fault::FirmwareOwned),
        (0, 0, Fault::ResetBlocked),
        (RESET_PERMITTED, SWFLAG, Fault::SemaphoreBusy),
    ] {
        let (mut phy, state, _) = fixture(Kind::I217);
        state.borrow_mut().fw = fw;
        state.borrow_mut().ext = ext;
        assert_eq!(
            phy.read(Register::new(0, 2).unwrap()).unwrap_err().primary,
            expected
        );
        assert!(!state.borrow().operations.iter().any(|op| op[0] == 1));
        let accesses = state.borrow().accesses;
        assert_eq!(
            phy.read(Register::new(0, 2).unwrap()).unwrap_err().primary,
            Fault::Poisoned
        );
        assert_eq!(state.borrow().accesses, accesses);
    }
}

#[test]
fn bounded_mdic_failure_releases_semaphore_and_never_reuses_epoch() {
    for kind in [Kind::I82579, Kind::I217] {
        for bad in [0, MDIC_ERROR, 1 << 16] {
            let (mut phy, state, _) = fixture(kind);
            state.borrow_mut().timeout = bad == 0;
            state.borrow_mut().bad_response = bad;
            let result = phy.read(Register::new(0, 2).unwrap()).unwrap_err();
            assert!(matches!(
                result.primary,
                Fault::MdicTimeout | Fault::MdicResponse(_)
            ));
            assert_eq!(state.borrow().ext & SWFLAG, 0);
            assert!(phy.is_poisoned());
            if bad == 0 {
                assert_eq!(
                    state
                        .borrow()
                        .operations
                        .iter()
                        .filter(|op| **op == [2, 50, 0])
                        .count(),
                    MDIC_POLLS
                );
            }
            let waits = state
                .borrow()
                .operations
                .iter()
                .filter(|op| **op == [2, 100, 0])
                .count();
            assert_eq!(waits, usize::from(kind == Kind::I82579));
        }
    }
    let (mut phy, state, _) = fixture(Kind::I217);
    state.borrow_mut().unacknowledged = true;
    assert_eq!(
        phy.read(Register::new(0, 2).unwrap()).unwrap_err().primary,
        Fault::SemaphoreTimeout
    );
    assert_eq!(
        state
            .borrow()
            .operations
            .iter()
            .filter(|op| **op == [2, 1000, 0])
            .count(),
        1000
    );
    assert!(
        !state
            .borrow()
            .operations
            .iter()
            .any(|op| op[0] == 1 && op[1] == MDIC)
    );
}

#[test]
fn exhausted_claim_keeps_timeout_and_separate_cleanup_error() {
    // FWSM read, initial SWFLAG read, claim write, then 1000 claim polls.
    // Failure at either final cleanup access must not replace that timeout.
    for fail_at in [1003, 1004] {
        for failure in [Fault::Access, Fault::Removed] {
            let (mut phy, state, released) = fixture(Kind::I217);
            {
                let mut state = state.borrow_mut();
                state.unacknowledged = true;
                state.fail_at = Some(fail_at);
                state.fail_with = Some(failure);
            }
            assert_eq!(
                phy.read(Register::new(0, 2).unwrap()).unwrap_err(),
                Error {
                    primary: Fault::SemaphoreTimeout,
                    cleanup: Some(failure)
                },
            );
            assert_eq!(
                state
                    .borrow()
                    .operations
                    .iter()
                    .filter(|op| **op == [2, 1000, 0])
                    .count(),
                1000
            );
            assert!(
                !state
                    .borrow()
                    .operations
                    .iter()
                    .any(|op| op[0] == 1 && op[1] == MDIC)
            );
            let accesses = state.borrow().accesses;
            assert!(phy.is_poisoned());
            assert_eq!(phy.identify().unwrap_err().primary, Fault::Poisoned);
            assert_eq!(state.borrow().accesses, accesses);
            drop(phy);
            assert_eq!(released.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn every_wakeup_access_failure_is_terminal_and_keeps_owner() {
    let (mut good, state, released) = fixture(Kind::I217);
    good.write(Register::new(WAKE_PAGE, 0x1234).unwrap(), 0x9876)
        .unwrap();
    let count = state.borrow().accesses;
    drop(good);
    assert_eq!(released.load(Ordering::SeqCst), 1);
    for fail in 0..count {
        let (mut phy, state, released) = fixture(Kind::I217);
        state.borrow_mut().fail_at = Some(fail);
        let error = phy
            .write(Register::new(WAKE_PAGE, 0x1234).unwrap(), 0x9876)
            .unwrap_err();
        assert!(error.primary == Fault::Access || error.cleanup == Some(Fault::Access));
        assert!(phy.is_poisoned());
        let count = state.borrow().accesses;
        assert_eq!(phy.identify().unwrap_err().primary, Fault::Poisoned);
        assert_eq!(state.borrow().accesses, count);
        drop(phy);
        assert_eq!(released.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn all_ones_is_removed_and_invalid_pages_never_alias_another_register() {
    for at in [FWSM, EXTCNF_CTRL, MDIC] {
        let (mut phy, state, _) = fixture(Kind::I217);
        state.borrow_mut().removed = Some(at);
        assert_eq!(
            phy.read(Register::new(0, 2).unwrap()).unwrap_err().primary,
            Fault::Removed
        );
        assert!(phy.is_poisoned());
    }
    for (page, index) in [(2048, 0), (0, 32), (769, 32), (767, 0xffff)] {
        assert_eq!(Register::new(page, index), Err(Fault::InvalidRegister));
    }
    assert!(Register::new(2047, 31).is_ok());
    assert!(Register::new(WAKE_PAGE, 0xffff).is_ok());
}

#[test]
fn native_window_checks_full_bounds_and_never_treats_physical_address_as_mapping() {
    let mut bytes = alloc::vec![0u32;8];
    let base = core::ptr::NonNull::new(bytes.as_mut_ptr().cast::<u8>()).unwrap();
    let owner: Arc<dyn core::any::Any> = Arc::new(());
    // SAFETY: this test supplies a stable exclusive native allocation,
    // which stands in for a prequalified UC mapping only here.
    let mut io = unsafe { io::Mmio::from_owned_window(base, 32, owner) }.unwrap();
    io.write32(28, 0x1234_5678).unwrap();
    assert_eq!(io.read32(28).unwrap(), 0x1234_5678);
    assert_eq!(io.write32(30, 0).unwrap_err(), Fault::Misaligned);
    assert_eq!(io.write32(32, 0).unwrap_err(), Fault::OutsideBar);
    assert_eq!(io.read32(u32::MAX - 3).unwrap_err(), Fault::OutsideBar);
    assert_eq!(bytes[6], 0);
}

#[test]
#[ignore = "oracle: STELA_E1000E_PCH_ORACLE"]
fn unchanged_linux_pch_phy_register_effects() {
    let path = std::env::var("STELA_E1000E_PCH_ORACLE").expect("oracle trace");
    let bytes = std::fs::read(path).unwrap();
    let words: Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| u32::from_le_bytes(*b))
        .collect();
    assert_eq!(bytes.len() % 4, 0);
    let mut at = 0;
    let mut cases = 0;
    while at < words.len() {
        let h = &words[at..at + 7];
        at += 7;
        let kind = if h[0] == 0 {
            Kind::I82579
        } else {
            assert_eq!(h[0], 1);
            Kind::I217
        };
        let (mut phy, state, _) = fixture(kind);
        let register = Register::new(h[1] as u16, h[2] as u16).unwrap();
        let result = if h[3] == 0 {
            phy.read(register).unwrap()
        } else {
            phy.write(register, h[4] as u16).unwrap();
            h[4] as u16
        };
        assert_eq!(u32::from(result), h[5]);
        let operations: Vec<[u32; 3]> = words[at..at + h[6] as usize * 3]
            .as_chunks::<3>()
            .0
            .to_vec();
        at += h[6] as usize * 3;
        assert_eq!(
            state.borrow().operations,
            operations,
            "case {cases}: {kind:?} {register:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 264);
}

#[test]
fn minimum_preflight_failure_has_no_register_effect_and_keeps_both_owners() {
    let (mut phy, state, released) = fixture(Kind::I82579);
    let cause = crate::bus::pci::power::Error::Clock;
    state.borrow_mut().timing_failure = Some(cause);
    let register = Register::new(0, 1).unwrap();
    assert_eq!(phy.read(register), Err(Fault::Minimum(cause).into()));
    assert!(phy.is_poisoned());
    assert!(state.borrow().operations.is_empty());
    state.borrow_mut().timing_failure = None;
    for _ in 0..3 {
        assert_eq!(phy.read(register), Err(Fault::Minimum(cause).into()));
    }
    assert!(state.borrow().operations.is_empty());
    drop(phy);
    assert_eq!(released.load(Ordering::SeqCst), 0);
    assert_eq!(state.borrow().timer_drops.load(Ordering::SeqCst), 0);
}
#[test]
fn minimum_wait_failure_does_not_clear_uncertain_semaphore_or_retry() {
    let (mut phy, state, released) = fixture(Kind::I82579);
    state.borrow_mut().fail_delay_at = Some(0);
    let cause = crate::bus::pci::power::Error::Clock;
    let register = Register::new(0, 1).unwrap();
    assert_eq!(
        phy.read(register),
        Err(Error {
            primary: Fault::Minimum(cause),
            cleanup: Some(Fault::Minimum(cause))
        })
    );
    assert_eq!(state.borrow().ext & SWFLAG, SWFLAG);
    let observed = state.borrow().operations.clone();
    state.borrow_mut().timing_failure = None;
    for _ in 0..3 {
        assert_eq!(phy.read(register), Err(Fault::Minimum(cause).into()));
    }
    assert_eq!(state.borrow().operations, observed);
    assert_eq!(state.borrow().delay_calls, 1);
    drop(phy);
    assert_eq!(released.load(Ordering::SeqCst), 0);
    assert_eq!(state.borrow().timer_drops.load(Ordering::SeqCst), 0);
}
