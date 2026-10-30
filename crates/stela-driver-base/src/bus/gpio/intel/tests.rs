// SPDX-License-Identifier: GPL-2.0
//! Independent peer implements immutable ownership, two lock classes, input
//! sampling, output latches and separate group status W1C semantics.
extern crate std;
mod oracle;
use super::*;
use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};

#[derive(Clone, Debug, Eq, PartialEq)]
enum Access {
    Read(u8, usize),
    Write(u8, usize, u32),
    Finish,
}
struct State {
    words: BTreeMap<(u8, usize), u32>,
    trace: Vec<Access>,
    status: Vec<(u8, usize)>,
    cfg0: Vec<(u8, usize)>,
    ignore: Option<(u8, usize)>,
    fail: Option<(u8, usize)>,
    post_write_failure: bool,
    finish_fail: bool,
    finish_count: usize,
}
struct Peer {
    state: Rc<RefCell<State>>,
    drops: Rc<Cell<usize>>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
impl super::registers::sealed::Sealed for Peer {}
impl RegisterIo for Peer {
    fn bytes(&self, _bar: u8) -> Result<usize, Error> {
        Ok(0x10000)
    }
    fn read32(&mut self, bar: u8, offset: usize) -> Result<u32, Error> {
        let mut state = self.state.borrow_mut();
        state.trace.push(Access::Read(bar, offset));
        assert_eq!(offset & 3, 0);
        assert!(offset < 0x10000);
        if state.fail == Some((bar, offset)) && !state.post_write_failure {
            return Err(Error::Access);
        }
        Ok(*state.words.get(&(bar, offset)).unwrap_or(&0))
    }
    fn write32(&mut self, bar: u8, offset: usize, value: u32) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        state.trace.push(Access::Write(bar, offset, value));
        assert_eq!(offset & 3, 0);
        let previous = *state.words.get(&(bar, offset)).unwrap_or(&0);
        if state.ignore != Some((bar, offset)) {
            let updated = if state.status.contains(&(bar, offset)) {
                previous & !value
            } else if state.cfg0.contains(&(bar, offset)) {
                (value & !2) | (previous & 2)
            } else {
                value
            };
            state.words.insert((bar, offset), updated);
        }
        if state.fail == Some((bar, offset)) && state.post_write_failure {
            return Err(Error::Access);
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        state.finish_count += 1;
        state.trace.push(Access::Finish);
        if state.finish_fail {
            Err(Error::Mapping)
        } else {
            Ok(())
        }
    }
}
fn peer(profile: &'static Profile, revision: u16) -> (Peer, Rc<RefCell<State>>, Rc<Cell<usize>>) {
    let mut state = State {
        words: BTreeMap::new(),
        trace: Vec::new(),
        status: Vec::new(),
        cfg0: Vec::new(),
        ignore: None,
        fail: None,
        post_write_failure: false,
        finish_fail: false,
        finish_count: 0,
    };
    for community in profile.communities {
        state
            .words
            .insert((community.bar, 0), u32::from(revision) << 16);
        state.words.insert((community.bar, 12), 0x1000);
        for group in community.groups {
            state.status.push((
                community.bar,
                community.status + usize::from(group.register) * 4,
            ));
            state.words.insert(
                (
                    community.bar,
                    community.host_own + usize::from(group.register) * 4,
                ),
                u32::MAX,
            );
        }
        for pin in community.first..community.first + community.count {
            let offset = cfg(profile, revision, pin).unwrap();
            state.cfg0.push((community.bar, offset));
            state.words.insert((community.bar, offset), 0x100);
            state.words.insert((community.bar, offset + 4), 0xa500_0000);
        }
    }
    let state = Rc::new(RefCell::new(state));
    let drops = Rc::new(Cell::new(0));
    (
        Peer {
            state: state.clone(),
            drops: drops.clone(),
        },
        state,
        drops,
    )
}
fn cfg(profile: &Profile, revision: u16, pin: u16) -> Option<usize> {
    profile.communities.iter().find_map(|community| {
        (pin >= community.first && pin - community.first < community.count).then(|| {
            0x1000 + usize::from(pin - community.first) * if revision >= 0x92 { 16 } else { 8 }
        })
    })
}
fn modern() -> &'static Profile {
    Profile::from_acpi("INT344B", None).unwrap()
}
fn setup(pins: &[u16], revision: u16) -> (Controller<Peer>, Rc<RefCell<State>>, Rc<Cell<usize>>) {
    let (peer, state, drops) = peer(modern(), revision);
    (Controller::new(peer, modern(), pins).unwrap(), state, drops)
}
fn writes(state: &Rc<RefCell<State>>) -> Vec<(u8, usize, u32)> {
    state
        .borrow()
        .trace
        .iter()
        .filter_map(|access| {
            if let Access::Write(bar, offset, value) = access {
                Some((*bar, *offset, *value))
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn all_original_modern_profiles_preserve_gpio_numbering_and_community_boundaries() {
    for (hid, profile) in tables::MATCHES {
        assert_eq!(
            Profile::from_acpi(hid, profile.uid).unwrap().name(),
            profile.name()
        );
        let mut pins = Vec::new();
        for community in profile.communities {
            for group in community.groups {
                if group.gpio < 0 {
                    continue;
                }
                for local in 0..group.count {
                    assert_eq!(
                        profile.gpio_to_pad(group.gpio as u16 + local),
                        Some(group.first + local)
                    );
                    pins.push(group.first + local);
                }
            }
        }
        for revision in [0x91, 0x94] {
            let (transport, state, drops) = peer(profile, revision);
            let mut controller = Controller::new(transport, profile, &pins).unwrap();
            assert!(writes(&state).is_empty());
            assert_eq!(controller.direction(pins[0]), Ok(Direction::Input));
            controller.direction_output(pins[0], true).unwrap();
            assert!(controller.value(pins[0]).unwrap());
            controller.retire().unwrap();
            drop(controller);
            assert_eq!(drops.get(), 1);
        }
    }
    assert!(Profile::from_acpi("INT3452", None).is_none());
    assert!(Profile::from_acpi("INT3452", Some("9")).is_none());
    assert!(Profile::from_acpi("INT33FC", None).is_none());
}

#[test]
fn gpio_direction_latch_input_and_preserved_firmware_gpio_request() {
    let (mut controller, state, drops) = setup(&[0, 1], 0x94);
    state.borrow_mut().trace.clear();
    controller.request_gpio(0).unwrap();
    assert!(writes(&state).is_empty());
    controller.direction_output(0, true).unwrap();
    let output = writes(&state);
    assert_eq!(output.len(), 2);
    assert_eq!(output[0].2 & 0x301, 0x101); // latch before TX enabled
    assert_eq!(output[1].2 & 0x301, 0x201);
    assert_eq!(controller.direction(0), Ok(Direction::Output));
    assert_eq!(controller.value(0), Ok(true));
    controller.set_output(0, false).unwrap();
    assert_eq!(controller.value(0), Ok(false));
    state
        .borrow_mut()
        .words
        .insert((0, cfg(modern(), 0x94, 1).unwrap()), 0x102);
    assert_eq!(controller.value(1), Ok(true));
    controller.high_impedance(0).unwrap();
    assert_eq!(controller.direction(0), Ok(Direction::HighImpedance));
    assert_eq!(controller.set_output(0, true), Err(Error::Direction));
    controller.retire().unwrap();
    drop(controller);
    assert_eq!(drops.get(), 1);
}

#[test]
fn firmware_and_separate_config_tx_locks_refuse_before_any_write() {
    for field in [0x20, 0xa0, 0xa4] {
        let (mut controller, state, _) = setup(&[0], 0x94);
        state.borrow_mut().words.insert((0, field), 1);
        state.borrow_mut().trace.clear();
        let expected = match field {
            0x20 => Error::FirmwareOwner,
            0xa0 => Error::Locked,
            _ => Error::TxLocked,
        };
        assert_eq!(controller.direction_output(0, true), Err(expected));
        assert!(writes(&state).is_empty());
    }
    let (mut controller, state, _) = setup(&[0], 0x94);
    controller.direction_output(0, false).unwrap();
    state.borrow_mut().words.insert((0, 0xa0), 1);
    controller.set_output(0, true).unwrap(); // config lock does not lock TX
    assert_eq!(controller.value(0), Ok(true));
}

#[test]
fn revision_selects_extended_pad_ownership_and_word_stride() {
    let (mut controller, state, _) = setup(&[8], 0x110);
    state.borrow_mut().words.insert((0, 0x20 + 8 * 4), 3);
    state.borrow_mut().trace.clear();
    assert_eq!(controller.direction_input(8), Err(Error::FirmwareOwner));
    assert!(state.borrow().trace.contains(&Access::Read(0, 0x40)));
    assert!(writes(&state).is_empty());
    let (mut controller, state, _) = setup(&[8], 0x91);
    controller.direction_output(8, true).unwrap();
    assert!(
        writes(&state)
            .iter()
            .any(|(_, offset, _)| *offset == 0x1040)
    );
}

#[test]
fn pull_encodes_source_values_and_rejects_invalid_before_effects() {
    let (mut controller, state, _) = setup(&[0], 0x94);
    for (pull, expected) in [
        (Pull::Disabled, 0),
        (Pull::Up(5_000), 0x2800),
        (Pull::Down(1_000), 0x400),
        (Pull::Up(833), 0x2c00),
        (Pull::Down(20_000), 0x1000),
    ] {
        controller.pull(0, pull).unwrap();
        assert_eq!(state.borrow().words[&(0, 0x1004)] & 0x3c00, expected);
    }
    state.borrow_mut().trace.clear();
    assert_eq!(controller.pull(0, Pull::Up(952)), Err(Error::InvalidPull));
    assert!(writes(&state).is_empty());
    let (mut old, state, _) = setup(&[0], 0x91);
    state.borrow_mut().trace.clear();
    assert_eq!(old.pull(0, Pull::Down(1000)), Err(Error::InvalidPull));
    assert!(writes(&state).is_empty());
}

#[test]
fn debounce_encodes_source_values_and_rejects_invalid_before_effects() {
    let (mut controller, state, _) = setup(&[0], 0x94);
    for micros in [0, 157, 250, 1000, 100_000, 1_000_000] {
        controller.debounce(0, micros).unwrap();
        let state = state.borrow();
        assert_eq!(state.words[&(0, 0x1000)] & (1 << 24) != 0, micros != 0);
        assert_eq!(state.words[&(0, 0x1008)] & 1 != 0, micros != 0);
    }
    state.borrow_mut().trace.clear();
    assert_eq!(controller.debounce(0, 1), Err(Error::InvalidDebounce));
    assert_eq!(
        controller.debounce(0, u32::MAX),
        Err(Error::InvalidDebounce)
    );
    assert!(writes(&state).is_empty());
    let (mut old, state, _) = setup(&[0], 0x91);
    state.borrow_mut().trace.clear();
    assert_eq!(old.debounce(0, 1000), Err(Error::Unsupported));
    assert!(writes(&state).is_empty());
}

#[test]
fn irq_hostown_mask_type_and_w1c_touch_only_selected_pad() {
    let (mut controller, state, _) = setup(&[0], 0x94);
    state.borrow_mut().words.insert((0, 0xd0), !1);
    state.borrow_mut().trace.clear();
    assert_eq!(
        controller.interrupt_type(0, Interrupt::Rising),
        Err(Error::AcpiInterrupt)
    );
    assert!(writes(&state).is_empty());
    state.borrow_mut().words.insert((0, 0xd0), u32::MAX);
    controller.interrupt_type(0, Interrupt::Falling).unwrap();
    assert_eq!(
        state.borrow().words[&(0, 0x1000)] & (3 << 25 | 1 << 23),
        1 << 25 | 1 << 23
    );
    state.borrow_mut().words.insert((0, 0x100), 0b11);
    controller.interrupt_mask(0, false).unwrap();
    assert_eq!(state.borrow().words[&(0, 0x100)], 0b10);
    assert_eq!(state.borrow().words[&(0, 0x120)], 1);
    state.borrow_mut().trace.clear();
    assert_eq!(
        controller.interrupt_type(0, Interrupt::High),
        Err(Error::InterruptActive)
    );
    assert!(writes(&state).is_empty());
    controller.interrupt_mask(0, true).unwrap();
    assert_eq!(state.borrow().words[&(0, 0x120)], 0);
}

#[test]
fn edge_is_acknowledged_before_its_consumer_runs() {
    let (mut controller, state, _) = setup(&[0], 0x94);
    controller.interrupt_type(0, Interrupt::Rising).unwrap();
    controller.interrupt_mask(0, false).unwrap();
    state.borrow_mut().words.insert((0, 0x100), 0b11);
    let report = controller.service(|pin| {
        assert_eq!(pin, 0);
        let mut state = state.borrow_mut();
        assert_eq!(state.words[&(0, 0x100)], 0b10);
        state.words.insert((0, 0x100), 0b11); // new edge during handler
        Ok(())
    });
    assert_eq!(report.error, None);
    assert_eq!(report.acknowledged[0], 1);
    assert_eq!(report.delivered[0], 1);
    assert_eq!(state.borrow().words[&(0, 0x100)], 0b11);
}

#[test]
fn level_is_masked_through_consumer_and_reassertion_remains_masked() {
    let (mut controller, state, _) = setup(&[0], 0x94);
    controller.interrupt_type(0, Interrupt::High).unwrap();
    controller.interrupt_mask(0, false).unwrap();
    state.borrow_mut().words.insert((0, 0x100), 1);
    let report = controller.service(|_| {
        let mut state = state.borrow_mut();
        assert_eq!(state.words[&(0, 0x120)] & 1, 0);
        state.words.insert((0, 0x100), 1);
        Ok(())
    });
    assert_eq!(report.error, None);
    assert_eq!(report.storm_masked[0], 1);
    assert_eq!(state.borrow().words[&(0, 0x120)] & 1, 0);
    assert_eq!(state.borrow().words[&(0, 0x100)], 1);
}

#[test]
fn consumed_irq_evidence_survives_failure_and_original_owner_is_kept() {
    let (mut controller, state, drops) = setup(&[0], 0x94);
    controller.interrupt_type(0, Interrupt::Rising).unwrap();
    controller.interrupt_mask(0, false).unwrap();
    state.borrow_mut().words.insert((0, 0x100), 1);
    let report = controller.service(|_| Err(Error::Consumer));
    assert_eq!(report.error, Some(Error::Consumer));
    assert_eq!(report.acknowledged[0], 1);
    assert_eq!(report.delivered[0], 0);
    assert_eq!(state.borrow().words[&(0, 0x120)] & 1, 0);
    assert_eq!(controller.value(0), Err(Error::Faulted));
    drop(controller);
    assert_eq!(drops.get(), 0);
}

#[test]
fn uncertain_posted_ack_is_recorded_even_without_confirmation_or_delivery() {
    let (mut controller, state, drops) = setup(&[0], 0x94);
    controller.interrupt_type(0, Interrupt::Rising).unwrap();
    controller.interrupt_mask(0, false).unwrap();
    {
        let mut state = state.borrow_mut();
        state.words.insert((0, 0x100), 1);
        state.fail = Some((0, 0x100));
        state.post_write_failure = true;
    }
    let report = controller.service(|_| panic!("unconfirmed acknowledgement cannot deliver"));
    assert_eq!(report.error, Some(Error::Access));
    assert_eq!(report.acknowledgement_attempted[0], 1);
    assert_eq!(report.acknowledged[0], 0);
    assert_eq!(report.delivered[0], 0);
    assert_eq!(state.borrow().words[&(0, 0x100)], 0);
    drop(controller);
    assert_eq!(drops.get(), 0);
}

#[test]
fn ignored_and_post_effect_writes_never_publish_success_or_free_transport() {
    for after_effect in [false, true] {
        let (mut controller, state, drops) = setup(&[0], 0x94);
        if after_effect {
            state.borrow_mut().fail = Some((0, 0x1000));
            state.borrow_mut().post_write_failure = true;
        } else {
            state.borrow_mut().ignore = Some((0, 0x1000));
        }
        let error = controller.direction_output(0, true).unwrap_err();
        assert!(matches!(error, Error::Access | Error::Readback));
        if after_effect {
            assert_eq!(state.borrow().words[&(0, 0x1000)] & 1, 1);
        }
        assert!(controller.faulted());
        drop(controller);
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn retirement_restores_owned_words_only_and_final_transport_retry_is_monotonic() {
    let (mut controller, state, drops) = setup(&[0], 0x94);
    state.borrow_mut().words.insert((0, 0x1010), 0xdead_0301);
    controller.direction_output(0, true).unwrap();
    controller.pull(0, Pull::Up(20_000)).unwrap();
    controller.debounce(0, 1000).unwrap();
    state.borrow_mut().finish_fail = true;
    assert_eq!(controller.retire(), Err(Error::Mapping));
    assert_eq!(state.borrow().words[&(0, 0x1000)], 0x100);
    assert_eq!(state.borrow().words[&(0, 0x1004)], 0xa500_0000);
    assert_eq!(state.borrow().words[&(0, 0x1010)], 0xdead_0301);
    state.borrow_mut().finish_fail = false;
    state.borrow_mut().trace.clear();
    controller.retire().unwrap();
    assert_eq!(state.borrow().trace, [Access::Finish]);
    assert_eq!(state.borrow().finish_count, 2);
    assert_eq!(controller.value(0), Err(Error::Retired));
    drop(controller);
    assert_eq!(drops.get(), 1);
}

#[test]
fn malformed_capability_cycle_and_padbar_refuse_without_any_write() {
    for cycle in [true, false] {
        let (transport, state, drops) = peer(modern(), 0x94);
        if cycle {
            state.borrow_mut().words.insert((0, 4), 4);
        } else {
            state.borrow_mut().words.insert((0, 12), 0x100);
        }
        let result = Controller::new(transport, modern(), &[0]);
        assert!(matches!(result, Err(Error::InvalidProfile)));
        assert!(writes(&state).is_empty());
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn native_supplier_dynamic_claim_preserves_direction_and_restores_before_reuse() {
    let (transport, state, drops) = peer(modern(), 0x94);
    let mut controller = Controller::new(transport, modern(), &[]).unwrap();
    assert!(!controller.has_claims());
    controller.capture(1).unwrap();
    assert!(controller.is_claimed(1));
    state.borrow_mut().trace.clear();
    controller.claim_debounce(1, 0).unwrap();
    assert!(writes(&state).is_empty());
    controller.write_latch(1, true).unwrap();
    assert_eq!(controller.direction(1), Ok(Direction::Input));
    assert_eq!(state.borrow().words[&(0, 0x1010)] & 0x301, 0x101);
    controller.release_pad(1).unwrap();
    assert!(!controller.is_claimed(1));
    assert!(!controller.has_claims());
    assert_eq!(state.borrow().words[&(0, 0x1010)] & !2, 0x100);
    controller.capture(1).unwrap();
    controller.direction_output(1, false).unwrap();
    controller.release_pad(1).unwrap();
    controller.retire().unwrap();
    drop(controller);
    assert_eq!(drops.get(), 1);
}

#[test]
fn native_supplier_failed_request_keeps_snapshot_and_failed_restore_keeps_claim() {
    let (transport, state, drops) = peer(modern(), 0x94);
    let mut controller = Controller::new(transport, modern(), &[]).unwrap();
    controller.capture(0).unwrap();
    state.borrow_mut().trace.clear();
    assert_eq!(controller.claim_debounce(0, 1), Err(Error::InvalidDebounce));
    assert!(writes(&state).is_empty());
    assert!(controller.is_claimed(0));
    controller.release_pad(0).unwrap();
    controller.capture(0).unwrap();
    controller.direction_output(0, true).unwrap();
    state.borrow_mut().ignore = Some((0, 0x1000));
    assert_eq!(controller.release_pad(0), Err(Error::Readback));
    assert!(controller.is_claimed(0));
    assert!(controller.has_claims());
    assert_eq!(drops.get(), 0);
    state.borrow_mut().ignore = None;
    controller.release_pad(0).unwrap();
    assert!(!controller.has_claims());
    controller.retire().unwrap();
    drop(controller);
    assert_eq!(drops.get(), 1);
}
