// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Owned PCH PHY transport for the 82579 and I217/I218/I219 paths.
//!
//! SWFLAG, MDIC, HV paging, debug ports and host-wakeup access follow the
//! pinned Linux e1000e shared code. This component does not admit a PCH MAC
//! to the network probe. [`cold`] composes only its declared unmanaged 82579
//! reset/NVM/PHY/MAC/queue profile behind owned unsafe grants. Other
//! generations and canonical native admission remain separate. It never applies the
//! discrete 82574L's PHY page or RAR policy to an integrated PCH controller.

use crate::Clock;

pub mod cold;
pub mod io;
pub mod nvm;

const MDIC: u32 = 0x20;
const FWSM: u32 = 0x5b54;
const EXTCNF_CTRL: u32 = 0xf00;
const SWFLAG: u32 = 1 << 5;
const FW_VALID: u32 = 1 << 15;
const RESET_PERMITTED: u32 = 1 << 6;
const MDIC_READ: u32 = 1 << 27;
const MDIC_WRITE: u32 = 1 << 26;
const MDIC_READY: u32 = 1 << 28;
const MDIC_ERROR: u32 = 1 << 30;
const MDIC_REG_MASK: u32 = 0x1f << 16;
const MDIC_POLLS: usize = 640 * 3;
const PHY_PAGE: u16 = 31;
const PORT_PAGE: u16 = 769;
const WAKE_PAGE: u16 = 800;
const WAKE_ENABLE: u16 = 17;
const WAKE_ADDRESS: u16 = 17;
const WAKE_DATA: u16 = 18;
const WAKE_ACCESS: u16 = 1 << 2;
const WAKE_ME_HOST: u16 = (1 << 4) | (1 << 5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    I82579,
    I217,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    Access,
    OutsideBar,
    Misaligned,
    Removed,
    FirmwareOwned,
    ResetBlocked,
    SemaphoreBusy,
    SemaphoreTimeout,
    SemaphoreLost,
    MdicTimeout,
    MdicResponse(u32),
    WrongPhy(u32),
    InvalidRegister,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    pub primary: Fault,
    pub cleanup: Option<Fault>,
}
impl From<Fault> for Error {
    fn from(primary: Fault) -> Self {
        Self {
            primary,
            cleanup: None,
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PCH PHY: {:?}", self.primary)?;
        if let Some(cleanup) = self.cleanup {
            write!(f, "; cleanup: {cleanup:?}")?;
        }
        Ok(())
    }
}
impl core::error::Error for Error {}

/// Complete PCH MAC register accesses with the real reservation kept.
///
/// # Safety
/// The implementation owns the powered, exclusively claimed PCH MAC,
/// uncached mapping and PCI resource through its lifetime, with DMA/IRQ/work
/// already stopped. No SMM, firmware or other user accesses these registers or
/// resets the PHY concurrently. Accesses are bounded, aligned, little-endian,
/// volatile and ordered; an error never invents an observation or successful
/// write. Reads flush this function's posted writes. Resource release must not
/// abandon pending native CPU accesses. An unrelated token is insufficient.
pub unsafe trait Registers: 'static {
    fn read32(&mut self, offset: u32) -> Result<u32, Fault>;
    fn write32(&mut self, offset: u32, value: u32) -> Result<(), Fault>;
}

/// Minimum hardware delays; polling is additionally bounded by count.
pub trait Delay {
    fn delay(&mut self, microseconds: u64);
}
impl Delay for Clock {
    fn delay(&mut self, microseconds: u64) {
        Clock::delay(self, microseconds);
    }
}

/// A checked HV register. Wakeup registers use the source's extended u16 index;
/// all other pages expose only their 32 MDIO register lanes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Register {
    page: u16,
    index: u16,
}
impl Register {
    pub fn new(page: u16, index: u16) -> Result<Self, Fault> {
        if page > 2047 || (page != WAKE_PAGE && index > 31) {
            return Err(Fault::InvalidRegister);
        }
        Ok(Self { page, index })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub kind: Kind,
    pub id: u32,
    pub revision: u8,
}

/// One exclusive PHY-access epoch. Any hardware/control failure poisons it;
/// Drop keeps the register owner after an uncertain operation. A fresh
/// object requires the constructor's reset/quiescence ownership grant.
pub struct Phy<R: Registers, D: Delay> {
    io: Option<R>,
    delay: D,
    kind: Kind,
    poisoned: bool,
    retry_count: u8,
    retry_enabled: bool,
}
impl<R: Registers, D: Delay> Phy<R, D> {
    /// # Safety
    /// `kind` describes the observed PCH PCI cohort: 82579 (PCH2) or
    /// I217/I218/I219 using the I217 PHY. The caller owns the exact physical
    /// requester's reset epoch exclusively, has drained DMA/IRQ/work and has
    /// not reused a prior failed PHY access epoch without real reset/recovery.
    /// `delay` must provide the requested minimum elapsed hardware time.
    /// This grant neither proves full MAC initialization nor admits network I/O.
    pub unsafe fn new(kind: Kind, io: R, delay: D) -> Self {
        Self {
            io: Some(io),
            delay,
            kind,
            poisoned: false,
            retry_count: 0,
            retry_enabled: false,
        }
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn read_mac(&mut self, at: u32) -> Result<u32, Fault> {
        let value = self
            .io
            .as_mut()
            .expect("live PHY register owner")
            .read32(at)?;
        if value == u32::MAX {
            Err(Fault::Removed)
        } else {
            Ok(value)
        }
    }
    fn write_mac(&mut self, at: u32, value: u32) -> Result<(), Fault> {
        self.io
            .as_mut()
            .expect("live PHY register owner")
            .write32(at, value)
    }

    fn acquire(&mut self) -> Result<(), Error> {
        // This first boot profile refuses ME-owned/reset-blocked
        // hardware before any write; it does not claim coexistence with ME.
        let fw = self.read_mac(FWSM)?;
        if fw & FW_VALID != 0 {
            return Err(Fault::FirmwareOwned.into());
        }
        if fw & RESET_PERMITTED == 0 {
            return Err(Fault::ResetBlocked.into());
        }
        let mut value = 0;
        let mut available = false;
        for _ in 0..100 {
            value = self.read_mac(EXTCNF_CTRL)?;
            if value & SWFLAG == 0 {
                available = true;
                break;
            }
            self.delay.delay(1000);
        }
        if !available {
            return Err(Fault::SemaphoreBusy.into());
        }
        self.write_mac(EXTCNF_CTRL, value | SWFLAG)?;
        for _ in 0..1000 {
            if self.read_mac(EXTCNF_CTRL)? & SWFLAG != 0 {
                return Ok(());
            }
            self.delay.delay(1000);
        }
        // An unacknowledged claim is uncertain. Try the source's clear, keep
        // the owner on the final failure, and never retry this access epoch.
        let cleanup = (|| {
            let value = self.read_mac(EXTCNF_CTRL)?;
            self.write_mac(EXTCNF_CTRL, value & !SWFLAG)
        })();
        Err(Error {
            primary: Fault::SemaphoreTimeout,
            cleanup: cleanup.err(),
        })
    }

    fn release(&mut self) -> Result<(), Fault> {
        let value = self.read_mac(EXTCNF_CTRL)?;
        if value & SWFLAG == 0 {
            return Err(Fault::SemaphoreLost);
        }
        self.write_mac(EXTCNF_CTRL, value & !SWFLAG)?;
        if self.read_mac(EXTCNF_CTRL)? & SWFLAG != 0 {
            return Err(Fault::SemaphoreLost);
        }
        Ok(())
    }

    fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Fault>,
    ) -> Result<T, Error> {
        if self.poisoned {
            return Err(Fault::Poisoned.into());
        }
        if let Err(error) = self.acquire() {
            self.poisoned = true;
            return Err(error);
        }
        let result = operation(self);
        let cleanup = self.release();
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(primary), cleanup) => {
                self.poisoned = true;
                Err(Error {
                    primary,
                    cleanup: cleanup.err(),
                })
            }
            (Ok(_), Err(primary)) => {
                self.poisoned = true;
                Err(primary.into())
            }
        }
    }

    fn mdic(&mut self, address: u8, index: u16, write: Option<u16>) -> Result<u16, Fault> {
        let retries = if self.retry_enabled {
            self.retry_count
        } else {
            0
        };
        for attempt in 0..=retries {
            match self.mdic_once(address, index, write) {
                Err(Fault::MdicTimeout | Fault::MdicResponse(_)) if attempt < retries => {
                    self.delay.delay(10_000);
                }
                result => return result,
            }
        }
        unreachable!("bounded MDIC loop returns its last actual outcome")
    }
    fn mdic_once(&mut self, address: u8, index: u16, write: Option<u16>) -> Result<u16, Fault> {
        if address > 31 || index > 31 {
            return Err(Fault::InvalidRegister);
        }
        let command = (u32::from(address) << 21)
            | (u32::from(index) << 16)
            | write.map_or(MDIC_READ, |value| MDIC_WRITE | u32::from(value));
        self.write_mac(MDIC, command)?;
        let mut response = 0;
        let mut ready = false;
        for _ in 0..MDIC_POLLS {
            self.delay.delay(50);
            response = self.read_mac(MDIC)?;
            if response & MDIC_READY != 0 {
                ready = true;
                break;
            }
        }
        // 82579 requires this quiet interval even when the transaction fails.
        if self.kind == Kind::I82579 {
            self.delay.delay(100);
        }
        if !ready {
            return Err(Fault::MdicTimeout);
        }
        if response & MDIC_ERROR != 0 || response & MDIC_REG_MASK != command & MDIC_REG_MASK {
            return Err(Fault::MdicResponse(response));
        }
        Ok(response as u16)
    }

    fn page(&mut self, page: u16) -> Result<(), Fault> {
        self.mdic(1, PHY_PAGE, Some(page << 5)).map(|_| ())
    }

    fn access(&mut self, register: Register, value: Option<u16>) -> Result<u16, Fault> {
        let Register { page, index } = register;
        if page == WAKE_PAGE {
            return self.wakeup(index, value);
        }
        if page > 0 && page < 768 {
            // All supported PHY types use I82577's debug address/data pair.
            self.mdic(2, 16, Some(((page << 5) | index) & 0x3f))?;
            return self.mdic(2, 17, value);
        }
        let address = if page >= 768 { 1 } else { 2 };
        if index > 15 {
            self.page(if page == 768 { 0 } else { page })?;
        }
        self.mdic(address, index, value)
    }

    fn wakeup(&mut self, index: u16, value: Option<u16>) -> Result<u16, Fault> {
        self.page(PORT_PAGE)?;
        let saved = self.mdic(1, WAKE_ENABLE, None)?;
        self.mdic(1, WAKE_ENABLE, Some((saved | WAKE_ACCESS) & !WAKE_ME_HOST))?;
        self.page(WAKE_PAGE)?;
        self.mdic(1, WAKE_ADDRESS, Some(index))?;
        let result = self.mdic(1, WAKE_DATA, value)?;
        self.page(PORT_PAGE)?;
        self.mdic(1, WAKE_ENABLE, Some(saved))?;
        Ok(result)
    }

    pub fn read(&mut self, register: Register) -> Result<u16, Error> {
        self.transaction(|this| this.access(register, None))
    }
    pub fn write(&mut self, register: Register, value: u16) -> Result<(), Error> {
        self.transaction(|this| this.access(register, Some(value)).map(|_| ()))
    }
    pub fn identify(&mut self) -> Result<Identity, Error> {
        self.transaction(|this| {
            let high = this.access(Register { page: 0, index: 2 }, None)?;
            let low = this.access(Register { page: 0, index: 3 }, None)?;
            let raw = (u32::from(high) << 16) | u32::from(low);
            let expected = match this.kind {
                Kind::I82579 => 0x0154_0090,
                Kind::I217 => 0x0154_00a0,
            };
            if raw & !0xf != expected {
                return Err(Fault::WrongPhy(raw));
            }
            Ok(Identity {
                kind: this.kind,
                id: raw & !0xf,
                revision: (raw & 0xf) as u8,
            })
        })
    }
}
impl<R: Registers, D: Delay> Drop for Phy<R, D> {
    fn drop(&mut self) {
        if self.poisoned {
            // Preserve the reservation/mapping, including an uncertain
            // semaphore/page state. Only an external real reset can recover it.
            if let Some(owner) = self.io.take() {
                core::mem::forget(owner);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::{collections::BTreeMap, rc::Rc, sync::Arc, vec::Vec};
    use core::{
        cell::RefCell,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct State {
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
            self.words.get(&key).copied().unwrap_or_else(|| {
                0xa55a ^ (u16::from(address) << 8) ^ key.1.wrapping_mul(5) ^ key.2
            })
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
                    s.command = (value & !0xffff)
                        | u32::from(data)
                        | if s.timeout { 0 } else { MDIC_READY };
                    s.command ^= s.bad_response;
                }
                _ => panic!("unknown write"),
            }
            Ok(())
        }
    }
    struct Timer(Rc<RefCell<State>>);
    impl Delay for Timer {
        fn delay(&mut self, microseconds: u64) {
            self.0
                .borrow_mut()
                .operations
                .push([2, microseconds as u32, 0]);
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
            unsafe { Phy::new(kind, io, Timer(state.clone())) },
            state,
            released,
        )
    }

    #[test]
    fn actual_phy_identity_is_observed_under_one_semaphore_and_revision_retained() {
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
    fn exhausted_claim_retains_timeout_and_separate_cleanup_error() {
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
    fn every_wakeup_access_failure_is_terminal_and_retains_actual_owner() {
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
}
