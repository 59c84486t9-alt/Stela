// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2015, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Standalone AX200/AX210 ownership, persistence, reset and MAC-clock wake.
//! Adapted from pcie/gen1_2/trans.c, iwl-io.c and the pinned MAC configurations.
//! This leaves interrupts masked. It never starts ROM self-load, authenticates
//! firmware, calibrates a radio or claims station/carrier readiness.
use super::{firmware::Family, identity::Profile};
use crate::{
    Clock, Handoff,
    bus::{mmio::Mmio, pci::Bar},
};

const HW_IF: u32 = 0;
const INT: u32 = 8;
const INT_MASK: u32 = 12;
const FH_INT: u32 = 16;
const RESET: u32 = 0x20;
const GP: u32 = 0x24;
const HW_REV: u32 = 0x28;
const GIO: u32 = 0x3c;
const MAILBOX: u32 = 0x88;
const RF_ID: u32 = 0x9c;
const CHICKEN: u32 = 0x100;
const HPET: u32 = 0x240;
const LINK_PWR: u32 = 0x250;
const PRPH_WADDR: u32 = 0x444;
const PRPH_RADDR: u32 = 0x448;
const PRPH_WDATA: u32 = 0x44c;
const PRPH_RDATA: u32 = 0x450;
const OWN: u32 = 0x00400000;
const WAKE_ME: u32 = 0x08000000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessError {
    Unavailable,
    Bounds,
    Mapping,
    Clock,
}

/// Exclusive process-context CSR access and a real advancing delay source.
/// Native construction requires a qualified MMIO/PCI ownership contract.
pub trait Csr {
    fn read32(&mut self, register: u32) -> Result<u32, AccessError>;
    fn write32(&mut self, register: u32, value: u32) -> Result<(), AccessError>;
    fn delay_us(&mut self, microseconds: u32) -> Result<(), AccessError>;
}

/// Direct access to an already mapped BAR. This does not manufacture an
/// exclusive PCI claim or attach a DMA domain/interrupt route.
pub struct NativeCsr {
    registers: Mmio,
    clock: Clock,
}
impl NativeCsr {
    /// # Safety
    /// The caller owns this exact standalone Intel PCI function exclusively,
    /// including its BAR and reset/power state. All old DMA/submissions/IRQ work
    /// are stopped and drained, PCI MSI/MSI-X/legacy interrupt delivery is
    /// disabled, no firmware/AML/other driver accesses the BAR,
    /// and the real mapped uncached BAR stays reserved for this object's life.
    /// The supplied clock is calibrated and keeps advancing in this context.
    pub unsafe fn new(
        handoff: &Handoff,
        bar: Option<Bar>,
        clock: Clock,
    ) -> Result<Self, AccessError> {
        if clock.ticks_per_microsecond == 0 {
            return Err(AccessError::Clock);
        }
        let registers =
            crate::registers(handoff, bar, 0, 4096).map_err(|_| AccessError::Mapping)?;
        Ok(Self { registers, clock })
    }
}
impl Csr for NativeCsr {
    fn read32(&mut self, register: u32) -> Result<u32, AccessError> {
        if !register.is_multiple_of(4) || register > 4092 {
            return Err(AccessError::Bounds);
        }
        Ok(self.registers.read32(register as usize))
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), AccessError> {
        if !register.is_multiple_of(4) || register > 4092 {
            return Err(AccessError::Bounds);
        }
        self.registers.write32(register as usize, value);
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u32) -> Result<(), AccessError> {
        self.clock.delay(u64::from(microseconds));
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Access(AccessError),
    FailedRead { register: u32, value: u32 },
    IdentityChanged,
    Timeout { register: u32, mask: u32 },
    Rejected { register: u32, mask: u32 },
    ManagementUnknown,
    ManagementConnected,
    PersistenceProtected,
    State,
}
impl From<AccessError> for Error {
    fn from(value: AccessError) -> Self {
        Self::Access(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementSession {
    NotConnected,
    Connected,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Awake {
    pub family: Family,
    pub rf_killed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Cold,
    Awake(Awake),
    Poisoned,
}

pub struct Power<C: Csr> {
    io: C,
    profile: Profile,
    state: State,
}
impl<C: Csr> Power<C> {
    pub fn new(io: C, profile: Profile) -> Self {
        Self {
            io,
            profile,
            state: State::Cold,
        }
    }
    fn read(&mut self, register: u32) -> Result<u32, Error> {
        let value = self.io.read32(register)?;
        if value == u32::MAX || matches!(value & !0xf, 0xa5a5a5a0 | 0x5a5a5a50) {
            return Err(Error::FailedRead { register, value });
        }
        Ok(value)
    }
    fn write(&mut self, register: u32, value: u32) -> Result<(), Error> {
        self.io.write32(register, value)?;
        Ok(())
    }
    fn set(&mut self, register: u32, mask: u32) -> Result<(), Error> {
        let value = self.read(register)?;
        self.write(register, value | mask)
    }
    fn set_checked(&mut self, register: u32, mask: u32) -> Result<(), Error> {
        self.set(register, mask)?;
        if self.read(register)? & mask != mask {
            return Err(Error::Rejected { register, mask });
        }
        Ok(())
    }
    fn poll(&mut self, register: u32, mask: u32, microseconds: u32) -> Result<(), Error> {
        // Same 10us interval/strict deadline as iwl_poll_bits_mask. A failed
        // register read is never a successful set-bit observation.
        for _ in 0..microseconds.div_ceil(10) {
            if self.read(register)? & mask == mask {
                return Ok(());
            }
            self.io.delay_us(10)?;
        }
        Err(Error::Timeout { register, mask })
    }
    fn ready(&mut self) -> Result<(), Error> {
        self.set(HW_IF, OWN)?;
        self.poll(HW_IF, OWN, 50)?;
        self.set(MAILBOX, 1 << 5)
    }
    fn ownership(&mut self, management: ManagementSession) -> Result<(), Error> {
        match self.ready() {
            Ok(()) => return Ok(()),
            Err(Error::Timeout { .. }) => {}
            Err(e) => return Err(e),
        }
        self.set_checked(LINK_PWR, 1 << 31)?;
        self.io.delay_us(1000)?;
        for _ in 0..10 {
            self.set(HW_IF, WAKE_ME)?;
            for _ in 0..750 {
                match self.ready() {
                    Ok(()) => return Ok(()),
                    Err(Error::Timeout { .. }) => {}
                    Err(e) => return Err(e),
                }
                match management {
                    ManagementSession::Connected => return Err(Error::ManagementConnected),
                    ManagementSession::Unknown => return Err(Error::ManagementUnknown),
                    ManagementSession::NotConnected => {}
                }
                self.io.delay_us(200)?;
            }
            self.io.delay_us(25000)?;
        }
        Err(Error::Timeout {
            register: HW_IF,
            mask: OWN,
        })
    }
    fn read_prph(&mut self, address: u32) -> Result<u32, Error> {
        let mask = if self.profile.family() == Family::Ax210 {
            0x00ffffff
        } else {
            0x000fffff
        };
        self.write(PRPH_RADDR, (address & mask) | (3 << 24))?;
        self.read(PRPH_RDATA)
    }
    fn write_prph(&mut self, address: u32, value: u32) -> Result<(), Error> {
        let mask = if self.profile.family() == Family::Ax210 {
            0x00ffffff
        } else {
            0x000fffff
        };
        self.write(PRPH_WADDR, (address & mask) | (3 << 24))?;
        self.write(PRPH_WDATA, value)
    }
    fn clear_persistence(&mut self) -> Result<(), Error> {
        if self.profile.family() != Family::Ax200 {
            return Ok(());
        }
        // AX200's actual pinned MAC cfg has umac_prph_offset=0. AX210 uses
        // +0x300000, but has no persistence-clear step in this donor routine.
        let hpm = self.read_prph(0xa03440)?;
        if hpm & (1 << 12) != 0 {
            if self.read_prph(0xa04d00)? & (1 << 12) != 0 {
                return Err(Error::PersistenceProtected);
            }
            self.write_prph(0xa03440, hpm & !(1 << 12))?;
            if self.read_prph(0xa03440)? & (1 << 12) != 0 {
                return Err(Error::PersistenceProtected);
            }
        }
        Ok(())
    }
    fn run(&mut self, management: ManagementSession) -> Result<Awake, Error> {
        let observed = self.profile.observed();
        if self.read(HW_REV)? != observed.hardware_revision
            || self.read(RF_ID)? != observed.radio_id
        {
            return Err(Error::IdentityChanged);
        }
        // Registration/routing remains inactive. This is not a DMA quiescence
        // proof; the exclusive NativeCsr constructor requires old DMA stopped.
        self.write(INT_MASK, 0)?;
        if self.read(INT_MASK)? != 0 {
            return Err(Error::Rejected {
                register: INT_MASK,
                mask: u32::MAX,
            });
        }
        self.write(INT, u32::MAX)?;
        self.write(FH_INT, u32::MAX)?;
        self.ownership(management)?;
        self.clear_persistence()?;
        self.set(RESET, 0x80)?;
        self.io.delay_us(5000)?;
        self.ownership(management)?;
        self.set_checked(CHICKEN, 0x00800000)?;
        self.set_checked(HPET, 0xffff0000)?;
        self.set_checked(HW_IF, 0x00080000)?;
        self.set_checked(GIO, 2)?;
        let bisr = self.profile.family() == Family::Ax200;
        if bisr {
            self.io.delay_us(2000)?;
        }
        self.set_checked(GP, 4)?;
        let wake = self.poll(GP, 1, 25000);
        if bisr {
            self.io.delay_us(200)?;
        }
        wake?;
        Ok(Awake {
            family: self.profile.family(),
            rf_killed: self.read(GP)? & 0x08000000 == 0,
        })
    }
    /// Consume only a successful MAC-clock epoch, transferring its exclusive
    /// CSR owner to the firmware/ring transport. This is not radio readiness.
    pub fn into_awake(self) -> Result<(C, Profile, Awake), Error> {
        if let State::Awake(status) = self.state {
            Ok((self.io, self.profile, status))
        } else {
            Err(Error::State)
        }
    }
    /// Wake the MAC clock with interrupts masked. Retrying an uncertain reset
    /// requires a new qualified ownership/reset epoch, never this used object.
    pub fn wake(&mut self, management: ManagementSession) -> Result<Awake, Error> {
        if self.state != State::Cold {
            return Err(Error::State);
        }
        self.state = State::Poisoned;
        let awake = self.run(management)?;
        self.state = State::Awake(awake);
        Ok(awake)
    }
}

#[cfg(test)]
mod tests {
    use super::super::identity::Observed;
    use super::*;
    use alloc::{collections::BTreeMap, vec::Vec};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        Read(u32),
        Write(u32, u32),
        Delay(u32),
    }
    struct Model {
        registers: BTreeMap<u32, u32>,
        peripheral: BTreeMap<u32, u32>,
        ops: Vec<Op>,
        fail: Option<usize>,
        sentinel: Option<usize>,
        sentinel_value: u32,
        own_attempts: usize,
        grant_after: usize,
        clock_after: Option<usize>,
        clock_reads: usize,
        mask_rejected: bool,
    }
    impl Model {
        fn new(family: Family) -> Self {
            let (hw, rf) = if family == Family::Ax200 {
                (0x340, 0x10a000)
            } else {
                (0x420, 0x10d000)
            };
            Self {
                registers: BTreeMap::from([
                    (HW_REV, hw),
                    (RF_ID, rf),
                    (HW_IF, 0x1000),
                    (INT_MASK, 0x1234),
                    (CHICKEN, 0x400),
                    (HPET, 0x1234),
                    (GIO, 0x100),
                    (GP, 0x08000000),
                ]),
                peripheral: BTreeMap::from([(0x3440, 0x01231000), (0x4d00, 0)]),
                ops: Vec::new(),
                fail: None,
                sentinel: None,
                sentinel_value: 0x5a5a5a5a,
                own_attempts: 0,
                grant_after: 1,
                clock_after: Some(0),
                clock_reads: 0,
                mask_rejected: false,
            }
        }
        fn op(&mut self, op: Op) -> Result<(), AccessError> {
            let at = self.ops.len();
            self.ops.push(op);
            if self.fail == Some(at) {
                return Err(AccessError::Unavailable);
            }
            Ok(())
        }
    }
    impl Csr for Model {
        fn read32(&mut self, register: u32) -> Result<u32, AccessError> {
            self.op(Op::Read(register))?;
            if self.sentinel == Some(self.ops.len() - 1) {
                return Ok(self.sentinel_value);
            }
            if register == PRPH_RDATA {
                let address = self.registers[&PRPH_RADDR] & 0x00ffffff;
                return Ok(*self.peripheral.get(&address).unwrap_or(&0));
            }
            if register == GP && self.registers[&GP] & 4 != 0 {
                self.clock_reads += 1;
                if self
                    .clock_after
                    .is_some_and(|count| self.clock_reads >= count)
                {
                    *self.registers.get_mut(&GP).unwrap() |= 1;
                }
            }
            // Mailbox SET is modeled write-only/W1S, not a readable receipt.
            if register == MAILBOX {
                return Ok(0);
            }
            Ok(*self.registers.get(&register).unwrap_or(&0))
        }
        fn write32(&mut self, register: u32, mut value: u32) -> Result<(), AccessError> {
            self.op(Op::Write(register, value))?;
            if register == HW_IF && value & OWN != 0 {
                self.own_attempts += 1;
                if self.own_attempts < self.grant_after {
                    value &= !OWN;
                }
            }
            if register == RESET && value & 0x80 != 0 {
                *self.registers.get_mut(&HW_IF).unwrap() &= !OWN;
                *self.registers.get_mut(&GP).unwrap() &= !5;
            }
            if register == INT || register == FH_INT {
                self.registers.insert(register, 0);
                return Ok(());
            }
            if register == INT_MASK && self.mask_rejected {
                return Ok(());
            }
            if register == PRPH_WDATA {
                let address = self.registers[&PRPH_WADDR] & 0x00ffffff;
                self.peripheral.insert(address, value);
            }
            self.registers.insert(register, value);
            Ok(())
        }
        fn delay_us(&mut self, us: u32) -> Result<(), AccessError> {
            self.op(Op::Delay(us))
        }
    }
    fn profile(family: Family) -> Profile {
        Profile::select(Observed {
            vendor: 0x8086,
            device: if family == Family::Ax200 {
                0x2723
            } else {
                0x2725
            },
            subsystem_vendor: 0x8086,
            subsystem_device: 0x84,
            pci_revision: 0x1a,
            class: [2, 0x80, 0],
            hardware_revision: if family == Family::Ax200 {
                0x340
            } else {
                0x420
            },
            radio_id: if family == Family::Ax200 {
                0x10a000
            } else {
                0x10d000
            },
        })
        .unwrap()
    }
    #[test]
    fn real_family_ownership_reset_persistence_bisr_and_stable_neighbor_effects() {
        for family in [Family::Ax200, Family::Ax210] {
            let mut power = Power::new(Model::new(family), profile(family));
            let awake = power.wake(ManagementSession::Unknown).unwrap();
            assert_eq!(
                awake,
                Awake {
                    family,
                    rf_killed: false
                }
            );
            assert_eq!(power.state, State::Awake(awake));
            assert_eq!(power.io.registers[&INT_MASK], 0);
            assert_eq!(power.io.registers[&CHICKEN], 0x00800400);
            assert_eq!(power.io.registers[&HPET], 0xffff1234);
            assert_eq!(power.io.registers[&GIO], 0x102);
            assert_eq!(power.io.registers[&HW_IF] & 0x1000, 0x1000);
            let delays: Vec<_> = power
                .io
                .ops
                .iter()
                .filter_map(|op| {
                    if let Op::Delay(us) = op {
                        Some(*us)
                    } else {
                        None
                    }
                })
                .collect();
            if family == Family::Ax200 {
                assert_eq!(delays, [5000, 2000, 200]);
                assert_eq!(power.io.peripheral[&0x3440], 0x01230000);
            } else {
                assert_eq!(delays, [5000]);
                assert!(
                    !power
                        .io
                        .ops
                        .iter()
                        .any(|op| matches!(op, Op::Write(PRPH_RADDR | PRPH_WADDR, _)))
                );
            }
            let before = power.io.ops.len();
            assert_eq!(
                power.wake(ManagementSession::NotConnected),
                Err(Error::State)
            );
            assert_eq!(before, power.io.ops.len());
            let (io, selected, status) = power.into_awake().unwrap();
            assert_eq!(selected.family(), family);
            assert_eq!(status, awake);
            assert_eq!(io.registers[&INT_MASK], 0);
        }
    }
    #[test]
    fn late_ownership_deadlines_management_unknown_and_connected_stay_explicit() {
        let family = Family::Ax200;
        let mut model = Model::new(family);
        model.grant_after = 3;
        let mut power = Power::new(model, profile(family));
        power.wake(ManagementSession::NotConnected).unwrap();
        assert!(power.io.ops.contains(&Op::Delay(1000)));
        assert!(power.io.ops.contains(&Op::Delay(200)));
        for (session, expected) in [
            (ManagementSession::Unknown, Error::ManagementUnknown),
            (ManagementSession::Connected, Error::ManagementConnected),
        ] {
            let mut model = Model::new(family);
            model.grant_after = usize::MAX;
            let mut power = Power::new(model, profile(family));
            assert_eq!(power.wake(session), Err(expected));
            assert_eq!(power.state, State::Poisoned);
            assert!(
                !power
                    .io
                    .ops
                    .iter()
                    .any(|op| matches!(op, Op::Write(RESET, _)))
            );
        }
        let mut model = Model::new(family);
        model.grant_after = usize::MAX;
        let mut power = Power::new(model, profile(family));
        assert_eq!(
            power.wake(ManagementSession::NotConnected),
            Err(Error::Timeout {
                register: HW_IF,
                mask: OWN
            })
        );
        assert_eq!(
            power
                .io
                .ops
                .iter()
                .filter(|op| **op == Op::Delay(25000))
                .count(),
            10
        );
    }
    #[test]
    fn persistence_protection_clock_timeout_rfkill_and_identity_never_invent_ready() {
        let family = Family::Ax200;
        let mut model = Model::new(family);
        model.peripheral.insert(0x4d00, 1 << 12);
        let mut power = Power::new(model, profile(family));
        assert_eq!(
            power.wake(ManagementSession::Unknown),
            Err(Error::PersistenceProtected)
        );
        assert!(
            !power
                .io
                .ops
                .iter()
                .any(|op| matches!(op, Op::Write(RESET, _)))
        );
        let mut model = Model::new(family);
        model.clock_after = None;
        let mut power = Power::new(model, profile(family));
        assert_eq!(
            power.wake(ManagementSession::Unknown),
            Err(Error::Timeout {
                register: GP,
                mask: 1
            })
        );
        assert_eq!(power.io.ops.last(), Some(&Op::Delay(200)));
        let mut model = Model::new(family);
        model.registers.insert(GP, 0);
        let mut power = Power::new(model, profile(family));
        assert!(power.wake(ManagementSession::Unknown).unwrap().rf_killed);
        let mut model = Model::new(family);
        model.registers.insert(RF_ID, 0x10d000);
        let mut power = Power::new(model, profile(family));
        assert_eq!(
            power.wake(ManagementSession::Unknown),
            Err(Error::IdentityChanged)
        );
        assert!(!power.io.ops.iter().any(|op| matches!(op, Op::Write(..))));
        let mut model = Model::new(family);
        model.mask_rejected = true;
        let mut power = Power::new(model, profile(family));
        assert!(matches!(
            power.wake(ManagementSession::Unknown),
            Err(Error::Rejected {
                register: INT_MASK,
                ..
            })
        ));
        assert!(
            !power
                .io
                .ops
                .iter()
                .any(|op| matches!(op, Op::Write(RESET, _)))
        );
    }
    #[test]
    fn every_source_operation_failure_and_failed_word_poison_the_epoch() {
        for family in [Family::Ax200, Family::Ax210] {
            let mut baseline = Power::new(Model::new(family), profile(family));
            baseline.wake(ManagementSession::Unknown).unwrap();
            for (index, op) in baseline.io.ops.iter().enumerate() {
                let mut model = Model::new(family);
                model.fail = Some(index);
                let mut power = Power::new(model, profile(family));
                assert!(
                    power.wake(ManagementSession::Unknown).is_err(),
                    "failure {family:?} {index} {op:?}"
                );
                assert_eq!(power.state, State::Poisoned);
                let before = power.io.ops.len();
                assert_eq!(
                    power.wake(ManagementSession::NotConnected),
                    Err(Error::State)
                );
                assert_eq!(before, power.io.ops.len());
                if matches!(op, Op::Read(_)) {
                    for sentinel_value in [u32::MAX, 0xa5a5a5a5, 0x5a5a5a5a] {
                        let mut model = Model::new(family);
                        model.sentinel = Some(index);
                        model.sentinel_value = sentinel_value;
                        let mut power = Power::new(model, profile(family));
                        assert!(
                            matches!(
                                power.wake(ManagementSession::Unknown),
                                Err(Error::FailedRead { .. })
                            ),
                            "sentinel {family:?} {index} {op:?} {sentinel_value:x}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    #[ignore = "requires unchanged pinned Linux power-helper trace; see THIRD_PARTY.md"]
    fn unchanged_linux_ownership_reset_and_clock_effects() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let path = std::env::var("STELA_IWLWIFI_POWER_ORACLE").expect("power trace");
        let trace = std::fs::read(path).unwrap();
        let digest: alloc::string::String = Sha256::digest(&trace)
            .iter()
            .map(|b| alloc::format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            "58c3468c51e9a8c5e34ae5f06e78e65cff867e717384230288a11d1866618d60"
        );
        let text = core::str::from_utf8(&trace).unwrap();
        let mut lines = text.lines();
        let mut cases = 0;
        let mut effects = 0;
        while let Some(line) = lines.next() {
            let scenario = line
                .strip_prefix("case ")
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let family = if scenario < 6 {
                Family::Ax200
            } else {
                Family::Ax210
            };
            let kind = scenario % 6;
            let mut expected = Vec::new();
            let expected_result;
            loop {
                let line = lines.next().unwrap();
                let fields: Vec<_> = line.split_whitespace().collect();
                match fields[0] {
                    "w" => expected.push(Op::Write(
                        u32::from_str_radix(fields[1], 16).unwrap(),
                        u32::from_str_radix(fields[2], 16).unwrap(),
                    )),
                    "d" => expected.push(Op::Delay(fields[1].parse().unwrap())),
                    "result" => {
                        expected_result = fields[1];
                        break;
                    }
                    other => panic!("unexpected source record {other}"),
                }
            }
            let mut model = Model::new(family);
            model
                .peripheral
                .insert(0x3440, if kind == 0 { 0x01230000 } else { 0x01231000 });
            model
                .peripheral
                .insert(0x4d00, if kind == 2 { 0x1000 } else { 0 });
            model.grant_after = if kind == 3 { 3 } else { 1 };
            model.clock_after = if kind == 4 { None } else { Some(0) };
            if kind == 5 {
                model.registers.insert(GP, 0);
            }
            let mut power = Power::new(model, profile(family));
            let result = power.wake(ManagementSession::NotConnected);
            let status = match result {
                Ok(_) => "ok",
                Err(Error::PersistenceProtected) => "protected",
                Err(Error::Timeout { .. }) => "timeout",
                Err(e) => panic!("unexpected power failure {e:?}"),
            };
            assert_eq!(status, expected_result, "case {scenario}");
            let actual: Vec<_> = power
                .io
                .ops
                .iter()
                .copied()
                .filter(|op| !matches!(op, Op::Read(_) | Op::Write(PRPH_RADDR, _)))
                .collect();
            assert_eq!(actual, expected, "source effects case {scenario}");
            cases += 1;
            effects += actual.len();
        }
        assert_eq!(cases, 12);
        assert!(effects > 5000);
    }
}
