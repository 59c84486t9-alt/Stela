// SPDX-License-Identifier: GPL-2.0-or-later
//! Inherited SFHv2 engines, not a private-root or old-MSI completion model.
extern crate std;
use super::*;
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Effect {
    Read(usize),
    Write(usize, u32),
    Master(bool),
    Authority,
}
struct ModelState {
    now: u64,
    acs: u32,
    response: u32,
    pending: Option<(Sensor, usize)>,
    active: u32,
    irq: u32,
    effects: Vec<Effect>,
    backing: Vec<u8>,
    fault: usize,
    accesses: usize,
    dead: bool,
    panic_command: bool,
    never_ack: bool,
}
struct Model(Rc<RefCell<ModelState>>);
#[derive(Clone)]
struct Clock(Rc<RefCell<ModelState>>);
impl Timer for Clock {
    fn now_us(&self) -> u64 {
        self.0.borrow().now
    }
    fn relax(&self) {
        self.0.borrow_mut().now += 100;
    }
}
impl Model {
    fn access(&self, e: Effect) -> Result<(), super::super::Error> {
        let mut s = self.0.borrow_mut();
        s.effects.push(e);
        s.accesses += 1;
        s.now += 7;
        if s.fault == s.accesses {
            s.dead = true;
        }
        if s.dead {
            Err(super::super::Error::PciAuthority)
        } else {
            Ok(())
        }
    }
}
impl Registers for Model {
    fn check_authority(&mut self) -> Result<(), super::super::Error> {
        self.access(Effect::Authority)
    }
    fn read32(&mut self, o: usize) -> Result<u32, super::super::Error> {
        self.access(Effect::Read(o))?;
        let mut s = self.0.borrow_mut();
        if o == P2C_ACS {
            return Ok(s.acs);
        }
        if o == P2C_INTERRUPT {
            return Ok(s.irq);
        }
        assert_eq!(o, P2C_RESPONSE);
        if !s.never_ack
            && let Some((sensor, reads)) = s.pending
        {
            if reads == 1 {
                s.response = 5 << 4 | u32::from(sensor as u8) << 16;
                s.active &= !(1 << (sensor as u8));
                s.pending = None;
            } else {
                s.pending = Some((sensor, reads + 1));
            }
        }
        Ok(s.response)
    }
    fn write32(&mut self, o: usize, v: u32) -> Result<(), super::super::Error> {
        self.access(Effect::Write(o, v))?;
        let mut s = self.0.borrow_mut();
        if o == C2P_COMMAND {
            if s.panic_command {
                drop(s);
                panic!("uncertain inherited disable publication");
            }
            assert_eq!(v & 0xffff, 0x1012);
            assert_eq!(v >> 24, 0);
            let id = ((v >> 16) & 255) as u8;
            let sensor = *SENSORS.iter().find(|sensor| **sensor as u8 == id).unwrap();
            s.pending = Some((sensor, 0));
        } else if o == P2C_INTERRUPT {
            s.irq = 0;
        } else if o == C2P_ADDRESS_LOW || o == C2P_ADDRESS_HIGH {
            assert_eq!(v, 0);
        } else {
            assert_eq!((o, v), (P2C_INTERRUPT_ACK, 15));
        }
        Ok(())
    }
    fn set_bus_master(&mut self, e: bool) -> Result<(), super::super::Error> {
        self.access(Effect::Master(e))
    }
    unsafe fn mark_quiescent(&mut self) {
        panic!("engine observation is not root/resource retirement");
    }
}
fn fixture(mask: u32) -> (Model, Clock, Rc<RefCell<ModelState>>) {
    let s = Rc::new(RefCell::new(ModelState {
        now: 0,
        acs: mask << 4 | 2,
        response: 4 << 4,
        pending: None,
        active: mask,
        irq: 1,
        effects: Vec::new(),
        backing: vec![0x9d; 8192],
        fault: usize::MAX,
        accesses: 0,
        dead: false,
        panic_command: false,
        never_ack: false,
    }));
    (Model(s.clone()), Clock(s.clone()), s)
}
fn full_mask() -> u32 {
    SENSORS.iter().fold(0, |m, s| m | 1 << (*s as u8))
}

#[test]
fn inherited_every_advertised_sensor_including_hpd_stops_before_any_root_or_new_dma_grant() {
    let (mut r, t, s) = fixture(full_mask());
    let mut attempt = StopAttempt::new();
    let stopped = attempt.stop(&mut r, &t).unwrap();
    assert_eq!(stopped.advertised_mask(), full_mask());
    let s = s.borrow();
    assert_eq!(s.active, 0);
    assert_eq!(s.backing, vec![0x9d; 8192]);
    assert_eq!(
        s.effects
            .iter()
            .filter(|e| matches!(e, Effect::Write(C2P_COMMAND, _)))
            .count(),
        7
    );
    assert_eq!(s.effects.last(), Some(&Effect::Master(false)));
    assert!(!s.effects.contains(&Effect::Master(true)));
}
#[test]
fn stale_disabled_mailbox_does_not_ack_a_new_stop_and_two_sensors_can_establish_fresh_order() {
    let (mut r, t, s) = fixture(1);
    s.borrow_mut().response = 5 << 4;
    let mut attempt = StopAttempt::new();
    assert!(matches!(
        attempt.stop(&mut r, &t),
        Err(Error::Controller(super::super::Error::StaleResponse { .. }))
    ));
    assert!(
        !s.borrow()
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Write(C2P_COMMAND, _)))
    );
    let (mut r, t, s) = fixture(3);
    s.borrow_mut().response = 5 << 4;
    let stopped = StopAttempt::new().stop(&mut r, &t).unwrap();
    assert_eq!(stopped.advertised_mask(), 3);
    let commands: Vec<_> = s
        .borrow()
        .effects
        .iter()
        .filter_map(|e| match e {
            Effect::Write(C2P_COMMAND, v) => Some((v >> 16) & 255),
            _ => None,
        })
        .collect();
    assert_eq!(commands, vec![1, 0]);
}
#[test]
fn unknown_engine_coverage_and_timeout_cannot_be_promoted_from_stop_all_or_disabled_default() {
    for mask in [0, 1 << 3] {
        let (mut r, t, s) = fixture(mask);
        assert!(StopAttempt::new().stop(&mut r, &t).is_err());
        assert!(
            !s.borrow()
                .effects
                .iter()
                .any(|e| matches!(e, Effect::Write(..)))
        );
    }
    let (mut r, t, s) = fixture(1);
    s.borrow_mut().never_ack = true;
    let mut attempt = StopAttempt::new();
    let e = attempt.stop(&mut r, &t).err().unwrap();
    assert!(matches!(
        e,
        Error::Controller(super::super::Error::Timeout { .. })
    ));
    let effects = s.borrow().effects.clone();
    assert_eq!(attempt.stop(&mut r, &t).err(), Some(e));

    assert_eq!(s.borrow().effects, effects);
    assert_eq!(s.borrow().active, 1);
}
#[test]
fn every_authority_register_command_and_bme_fault_is_terminal_and_preserves_backing() {
    let (mut r, t, s) = fixture(full_mask());
    StopAttempt::new().stop(&mut r, &t).unwrap();
    let accesses = s.borrow().accesses;
    for fault in 1..=accesses {
        let (mut r, t, s) = fixture(full_mask());
        s.borrow_mut().fault = fault;
        let mut attempt = StopAttempt::new();
        let e = attempt.stop(&mut r, &t).err().unwrap();
        let effects = s.borrow().effects.clone();
        assert_eq!(attempt.stop(&mut r, &t).err(), Some(e));

        assert_eq!(s.borrow().effects, effects);
        assert_eq!(s.borrow().backing, vec![0x9d; 8192]);
    }
}
#[test]
fn caught_inherited_command_unwind_never_reissues_stop_or_reopens_a_success_receipt() {
    let (mut r, t, s) = fixture(full_mask());
    s.borrow_mut().panic_command = true;
    let mut attempt = StopAttempt::new();
    assert!(catch_unwind(AssertUnwindSafe(|| attempt.stop(&mut r, &t))).is_err());
    let effects = s.borrow().effects.clone();
    assert_eq!(attempt.stop(&mut r, &t).err(), Some(Error::Interrupted));

    assert_eq!(s.borrow().effects, effects);
    assert_eq!(s.borrow().backing, vec![0x9d; 8192]);
}
#[test]
fn removed_interrupt_word_is_not_cleared_away_into_apparent_success() {
    let (mut r, t, s) = fixture(1);
    s.borrow_mut().irq = u32::MAX;
    assert_eq!(
        StopAttempt::new().stop(&mut r, &t).err(),
        Some(Error::Controller(super::super::Error::RegisterUnavailable(
            P2C_INTERRUPT
        )))
    );
    assert!(
        !s.borrow()
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Write(P2C_INTERRUPT, _) | Effect::Master(false)))
    );
}
