// SPDX-License-Identifier: GPL-2.0-only
//! Independent device peer: real 32-bit controls/W1C, byte mux, grouped status,
//! self-clearing EOI, GPIO levels, lock refusal and delayed debounce visibility.
mod oracle;

#[test]
fn native_supplier_dynamic_claim_preserves_input_latch_and_unowned_firmware() {
    for profile in profiles() {
        let (mut controller, state, drops) = setup(profile, &[]);
        state.borrow_mut().pads[3] = (1 << 13) | (1 << 11) | 0x1000_0000;
        assert!(!controller.has_claims());
        controller.capture(p(1)).unwrap();
        assert!(controller.is_claimed(p(1)));
        state.borrow_mut().trace.clear();
        controller.claim_debounce(p(1), 0).unwrap();
        assert!(
            state
                .borrow()
                .trace
                .iter()
                .all(|access| matches!(access, Access::Read32(_)))
        );
        controller.write_latch(p(1), true).unwrap();
        assert_eq!(state.borrow().pads[1] & (1 << 23), 0);
        assert_ne!(state.borrow().pads[1] & (1 << 22), 0);
        assert_eq!(
            controller.claim_debounce(p(1), 61),
            Err(Error::FirmwareWake)
        );
        assert!(controller.is_claimed(p(1)));
        controller.release_pad(p(1)).unwrap();
        assert!(!controller.has_claims());
        assert_eq!(state.borrow().pads[1], 0);
        assert_eq!(state.borrow().pads[3], (1 << 13) | (1 << 11) | 0x1000_0000);
        controller.retire().unwrap();
        drop(controller);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn native_supplier_precapture_refusal_has_no_claim_and_failed_release_keeps_owner() {
    for profile in profiles() {
        let (mut controller, state, drops) = setup(profile, &[]);
        state.borrow_mut().pads[1] = 1 << 13;
        assert_eq!(controller.capture(p(1)), Err(Error::FirmwareWake));
        assert!(!controller.is_claimed(p(1)));
        assert!(!controller.has_claims());
        state.borrow_mut().pads[1] = 0;
        controller.capture(p(1)).unwrap();
        controller.direction_output(p(1), true).unwrap();
        state.borrow_mut().lock = Some(1);
        assert_eq!(controller.release_pad(p(1)), Err(Error::Readback));
        assert!(controller.is_claimed(p(1)));
        assert_eq!(drops.get(), 0);
        state.borrow_mut().lock = None;
        controller.release_pad(p(1)).unwrap();
        assert!(!controller.has_claims());
        controller.retire().unwrap();
        drop(controller);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn controller_wide_settlement_preserves_each_unowned_firmware_wake_source() {
    for profile in profiles() {
        for wake in [1 << 13, 1 << 14, 1 << 15, 1 << 27] {
            for trigger in [None, Some(Interrupt::Rising)] {
                let (mut controller, state, drops) = setup(profile, &[1]);
                {
                    let mut state = state.borrow_mut();
                    // Firmware wake does not require either IRQ-enable bit.
                    // Both its already-latched cause and the target's cause
                    // must survive this refusal without any write or EOI.
                    state.pads[3] = wake | 0x1001_0000;
                    state.pads[1] = 0x2000_0000;
                    state.trace.clear();
                }
                let before = state.borrow().pads;
                let result = match trigger {
                    Some(kind) => controller.interrupt_type(p(1), kind),
                    None => controller.debounce(p(1), 61),
                };
                assert_eq!(result, Err(Error::FirmwareWake));
                assert_eq!(state.borrow().pads, before);
                assert!(
                    state
                        .borrow()
                        .trace
                        .iter()
                        .all(|access| { matches!(access, Access::Read32(_) | Access::Read8(_)) })
                );
                assert_eq!(drops.get(), 0);
                // A fresh real observation of firmware clearing that policy,
                // rather than a local boolean, permits the original request.
                state.borrow_mut().pads[3] &= !wake;
                match trigger {
                    Some(kind) => controller.interrupt_type(p(1), kind).unwrap(),
                    None => controller.debounce(p(1), 61).unwrap(),
                }
                assert_eq!(state.borrow().pads[3], 0x1001_0000);
                assert_eq!(state.borrow().pads[1] & 0x3000_0000, 0x2000_0000);
                controller.retire().unwrap();
            }
        }
    }
}

extern crate std;
use super::*;
use alloc::{rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Access {
    Read32(usize),
    Write32(usize, u32),
    Read8(u8),
    Write8(u8, u8),
}
struct State {
    pads: [u32; 184],
    master: u32,
    mux: [u8; 145],
    mux_present: bool,
    trace: Vec<Access>,
    delay: usize,
    hold_enable: bool,
    lock: Option<usize>,
    fail_read: Option<usize>,
    fail_write: Option<usize>,
    post_effect_failure: bool,
    reassert: Option<usize>,
    summary_high: u32,
    finish_fail: bool,
    finish_calls: usize,
}
impl State {
    // External line transitions, independently decoded from donor bit numbers.
    // Interrupt mask controls delivery, not input sampling or cause latching.
    fn drive(&mut self, pin: usize, high: bool) {
        let previous = self.pads[pin] & 0x10000 != 0;
        self.pads[pin] = (self.pads[pin] & !0x10000) | if high { 0x10000 } else { 0 };
        let control = self.pads[pin];
        let polarity = (control >> 9) & 3;
        let active = if control & 0x100 != 0 {
            match polarity {
                0 => high,
                1 => !high,
                _ => false,
            }
        } else {
            match polarity {
                0 => !previous && high,
                1 => previous && !high,
                2 => previous != high,
                _ => false,
            }
        };
        if active && control & 0x800 != 0 {
            self.pads[pin] |= 0x1000_0000;
        }
    }
}
impl Default for State {
    fn default() -> Self {
        Self {
            pads: [0; 184],
            master: 0,
            mux: [0; 145],
            mux_present: true,
            trace: Vec::new(),
            delay: 0,
            hold_enable: false,
            lock: None,
            fail_read: None,
            fail_write: None,
            post_effect_failure: false,
            reassert: None,
            summary_high: 0,
            finish_fail: false,
            finish_calls: 0,
        }
    }
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
    fn bytes(&self) -> usize {
        0x400
    }
    fn read32(&mut self, offset: usize) -> Result<u32, Error> {
        let mut s = self.state.borrow_mut();
        assert_eq!(offset & 3, 0, "GPIO access must be an aligned word");
        s.trace.push(Access::Read32(offset));
        if s.fail_read == Some(offset) {
            return Err(Error::Access);
        }
        match offset {
            0xfc => Ok(s.master),
            0x2f8 | 0x2fc => {
                let mut summary = 0u64;
                for n in 0..184 {
                    if n != 63 && s.pads[n] & 0x3000_0000 != 0 {
                        summary |= 1 << (n / 4);
                    }
                }
                if offset == 0x2f8 {
                    Ok(summary as u32)
                } else {
                    Ok((summary >> 32) as u32 | s.summary_high)
                }
            }
            _ if offset / 4 < 184 => {
                let value = s.pads[offset / 4];
                if s.hold_enable {
                    return Ok(value & !0x800);
                }
                if s.delay > 0 && value & 0x800 != 0 {
                    s.delay -= 1;
                    return Ok(value & !0x800);
                }
                Ok(value)
            }
            _ => panic!("register outside donor layout: {offset:#x}"),
        }
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        let mut s = self.state.borrow_mut();
        assert_eq!(offset & 3, 0);
        s.trace.push(Access::Write32(offset, value));
        let fail = s.fail_write == Some(offset);
        if fail && !s.post_effect_failure {
            return Err(Error::Access);
        }
        if offset == 0xfc {
            s.master = value & !(1 << 29); // EOI self clears.
        } else {
            assert!(offset / 4 < 184);
            let n = offset / 4;
            if s.lock != Some(n) {
                let pending = s.pads[n] & 0x3000_0000 & !value;
                let input = s.pads[n] & 0x10000;
                s.pads[n] = (value & !0x3001_0000) | pending | input;
                if s.reassert == Some(n) && value & 0x3000_0000 != 0 {
                    s.pads[n] |= 0x1000_0000;
                }
                if value & 0x3000_0000 != 0 && s.pads[n] & 0x900 == 0x900 {
                    let high = s.pads[n] & 0x10000 != 0;
                    let active = match (s.pads[n] >> 9) & 3 {
                        0 => high,
                        1 => !high,
                        _ => false,
                    };
                    if active {
                        s.pads[n] |= 0x1000_0000;
                    }
                }
            }
        }
        if fail { Err(Error::Access) } else { Ok(()) }
    }
    fn read_mux(&mut self, pad: u8) -> Result<u8, Error> {
        let mut s = self.state.borrow_mut();
        s.trace.push(Access::Read8(pad));
        if !s.mux_present {
            return Err(Error::MissingMux);
        }
        Ok(s.mux[usize::from(pad)])
    }
    fn write_mux(&mut self, pad: u8, value: u8) -> Result<(), Error> {
        let mut s = self.state.borrow_mut();
        s.trace.push(Access::Write8(pad, value));
        if !s.mux_present {
            return Err(Error::MissingMux);
        }
        if s.lock != Some(usize::from(pad)) {
            s.mux[usize::from(pad)] = value;
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Error> {
        let mut s = self.state.borrow_mut();
        s.finish_calls += 1;
        if s.finish_fail {
            Err(Error::Mapping)
        } else {
            Ok(())
        }
    }
}
fn setup(profile: Profile, pins: &[u8]) -> (Controller<Peer>, Rc<RefCell<State>>, Rc<Cell<usize>>) {
    setup_state(profile, pins, State::default())
}
fn setup_state(
    profile: Profile,
    pins: &[u8],
    state: State,
) -> (Controller<Peer>, Rc<RefCell<State>>, Rc<Cell<usize>>) {
    let state = Rc::new(RefCell::new(state));
    let drops = Rc::new(Cell::new(0));
    let peer = Peer {
        state: state.clone(),
        drops: drops.clone(),
    };
    let mut owned = [0u64; 3];
    for pin in pins {
        owned[usize::from(*pin) / 64] |= 1 << (pin % 64);
    }
    let c = Controller::new(peer, profile, owned).unwrap();
    (c, state, drops)
}
fn p(number: u8) -> Pad {
    Pad::new(number).unwrap()
}
fn profiles() -> [Profile; 4] {
    [
        Profile::Amd0030,
        Profile::Amdi0030,
        Profile::Amdi0031,
        Profile::Amdi0033,
    ]
}

#[test]
fn exact_acpi_profiles_sparse_inventory_and_no_probe_writes() {
    for (hid, profile) in ["AMD0030", "AMDI0030", "AMDI0031", "AMDI0033"]
        .into_iter()
        .zip(profiles())
    {
        assert_eq!(Profile::from_hid(hid), Some(profile));
        let (mut c, s, _) = setup(profile, &[0, 62, 64, 127, 128, 183]);
        assert_eq!(c.profile(), profile);
        assert!(
            s.borrow()
                .trace
                .iter()
                .all(|a| matches!(a, Access::Read32(_)))
        );
        c.retire().unwrap();
    }
    for hid in ["AMD0031", "AMDI0032", "AMDI00330", "amd0030", ""] {
        assert_eq!(Profile::from_hid(hid), None);
    }
    for n in 0..=255 {
        assert_eq!(Pad::new(n).is_ok(), n < 184 && n != 63);
    }
}

#[test]
fn input_output_pull_preserve_real_pending_and_neighbors_all_profiles() {
    for profile in profiles() {
        let mut initial = State::default();
        initial.pads[4] = 0x1427_0055; // pending, input and drive/unknown controls.
        initial.pads[5] = 0xdead_beef;
        let (mut c, s, drops) = setup_state(profile, &[4], initial);
        assert!(c.input(p(4)).unwrap());
        c.direction_output(p(4), true).unwrap();
        assert_eq!(s.borrow().pads[4] & 0x00c0_0000, 0x00c0_0000);
        c.set_output(p(4), false).unwrap();
        for (pull, bits) in [
            (Pull::Up, 0x10_0000),
            (Pull::Down, 0x20_0000),
            (Pull::Disabled, 0),
        ] {
            c.pull(p(4), pull).unwrap();
            assert_eq!(s.borrow().pads[4] & 0x30_0000, bits);
            assert_eq!(s.borrow().pads[4] & 0x3000_0000, 0x1000_0000);
        }
        c.direction_input(p(4)).unwrap();
        assert_eq!(c.set_output(p(4), true), Err(Error::Direction));
        assert_eq!(c.input(p(5)), Err(Error::UnownedPad));
        assert_eq!(s.borrow().pads[5], 0xdead_beef);
        c.retire().unwrap();
        assert_eq!(s.borrow().pads[4], 0x1427_0055);
        drop(c);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn mux_is_byte_only_bounded_preserves_upper_policy_and_restores_exactly() {
    let mut initial = State::default();
    initial.mux[144] = 0xa1;
    let (mut c, s, _) = setup_state(Profile::Amdi0033, &[144, 145], initial);
    c.mux(p(144), 3).unwrap();
    assert_eq!(s.borrow().mux[144], 0xa3);
    assert_eq!(c.mux(p(145), 0), Err(Error::InvalidMux));
    assert_eq!(c.mux(p(144), 4), Err(Error::InvalidMux));
    c.retire().unwrap();
    assert_eq!(s.borrow().mux[144], 0xa1);
    assert!(s.borrow().trace.contains(&Access::Write8(144, 0xa3)));
}

#[test]
fn mux_missing_invalid_locked_and_active_output_refuse() {
    for case in 0..4 {
        let mut state = State {
            mux_present: case != 0,
            ..State::default()
        };
        if case == 1 {
            state.mux[7] = 0xff;
        }
        if case == 2 {
            state.lock = Some(7);
        }
        let (mut c, s, _) = setup_state(Profile::Amd0030, &[7], state);
        if case == 3 {
            c.direction_output(p(7), false).unwrap();
        }
        let expected = [
            Error::MissingMux,
            Error::InvalidMux,
            Error::Readback,
            Error::InterruptActive,
        ][case];
        assert_eq!(c.mux(p(7), 2), Err(expected));
        assert_eq!(c.faulted(), case == 2);
        if case != 2 {
            c.retire().unwrap();
        } else {
            assert_eq!(s.borrow().mux[7], 0);
        }
    }
}

#[test]
fn firmware_wake_and_interrupt_policy_refuse_without_writes_or_owner_release() {
    for bits in [0x2000, 0x4000, 0x8000, 0x0800_0000, 0x800, 0x1000] {
        let mut state = State::default();
        state.pads[10] = bits;
        let s = Rc::new(RefCell::new(state));
        let drops = Rc::new(Cell::new(0));
        let result = Controller::new(
            Peer {
                state: s.clone(),
                drops: drops.clone(),
            },
            Profile::Amdi0031,
            [1 << 10, 0, 0],
        );
        assert!(matches!(
            result,
            Err(Error::FirmwareWake | Error::FirmwareInterrupt)
        ));
        assert!(
            s.borrow()
                .trace
                .iter()
                .all(|a| matches!(a, Access::Read32(_)))
        );
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn all_trigger_encodings_settle_while_masked_and_ordinary_writes_never_ack() {
    for profile in profiles() {
        for (trigger, bits) in [
            (Interrupt::Rising, 0),
            (Interrupt::Falling, 0x200),
            (Interrupt::BothEdges, 0x400),
            (Interrupt::High, 0x100),
            (Interrupt::Low, 0x300),
        ] {
            let (mut c, s, _) = setup(profile, &[8]);
            s.borrow_mut().pads[8] |= 0x3000_0000;
            s.borrow_mut().delay = 3;
            c.interrupt_type(p(8), trigger).unwrap();
            assert_eq!(s.borrow().pads[8] & 0x700, bits);
            assert_eq!(s.borrow().pads[8] & 0x1800, 0);
            assert_eq!(s.borrow().pads[8] & 0x3000_0000, 0x3000_0000);
            let writes: Vec<_> = s
                .borrow()
                .trace
                .iter()
                .filter_map(|a| {
                    if let Access::Write32(32, v) = a {
                        Some(*v)
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(writes, [bits | 0x800, bits]);
            c.interrupt_enable(p(8), true).unwrap();
            assert_eq!(s.borrow().pads[8] & 0x1800, 0x1800);
            assert_eq!(c.interrupt_type(p(8), trigger), Err(Error::InterruptActive));
            assert_eq!(c.direction_output(p(8), true), Err(Error::InterruptActive));
            c.interrupt_mask(p(8)).unwrap();
            assert_eq!(s.borrow().pads[8] & 0x1800, 0x800);
            c.interrupt_disable(p(8)).unwrap();
            c.retire().unwrap();
        }
    }
}

#[test]
fn debounce_exact_time_bins_internal_pin_zero_and_invalid_limit() {
    for (micros, bits) in [
        (0, 0),
        (1, 0x61),
        (60, 0x61),
        (61, 0x61),
        (975, 0x6f),
        (976, 0x74),
        (3899, 0x7f),
        (3900, 0xe0),
        (249_999, 0xef),
        (250_000, 0xf4),
        (999_999, 0xff),
    ] {
        let (mut c, s, _) = setup(Profile::Amd0030, &[0, 1]);
        c.debounce(p(1), micros).unwrap();
        assert_eq!(s.borrow().pads[1] & 255, bits, "{micros}");
        s.borrow_mut().master = 1 << 15;
        c.debounce(p(0), micros).unwrap();
        assert_eq!(s.borrow().pads[0] & 255, 0);
        let before = s.borrow().trace.len();
        assert_eq!(c.debounce(p(1), 1_000_000), Err(Error::InvalidDebounce));
        assert_eq!(s.borrow().trace.len(), before);
        c.retire().unwrap();
    }
}

#[test]
fn settle_timeout_is_bounded_sticky_and_keeps_owner() {
    let (mut c, s, drops) = setup(Profile::Amdi0030, &[3]);
    s.borrow_mut().hold_enable = true;
    assert_eq!(
        c.interrupt_type(p(3), Interrupt::BothEdges),
        Err(Error::DebounceTimeout)
    );
    assert!(s.borrow().trace.len() < 270);
    assert_eq!(c.input(p(3)), Err(Error::Faulted));
    drop(c);
    assert_eq!(drops.get(), 0);
}

#[test]
fn grouped_demux_edges_levels_fresh_rmw_and_unowned_cause_preserved() {
    let (mut c, s, _) = setup(Profile::Amdi0033, &[0, 62, 64, 127, 128, 183]);
    c.interrupt_type(p(64), Interrupt::High).unwrap();
    for pin in [0, 62, 64, 127, 128, 183] {
        c.interrupt_enable(p(pin), true).unwrap();
        s.borrow_mut().pads[usize::from(pin)] |= 0x1000_0000;
    }
    s.borrow_mut().pads[61] = 0x3000_1800;
    s.borrow_mut().summary_high = 0xffff_c000; // Must ignore summary bits46..63.
    let mut order = Vec::new();
    let report = c.service(|pad, pending| {
        assert!(pending.interrupt);
        assert!(!pending.wake);
        if pad.number() == 64 {
            assert_eq!(s.borrow().pads[64] & 0x1000, 0);
        }
        s.borrow_mut().pads[usize::from(pad.number())] |= 0x10_0000;
        order.push(pad.number());
        Ok(())
    });
    assert_eq!(report.error, None);
    assert_eq!(order, [0, 62, 64, 127, 128, 183]);
    for pin in order {
        assert_eq!(s.borrow().pads[usize::from(pin)] & 0x3010_1000, 0x10_1000);
    }
    assert_eq!(s.borrow().pads[61], 0x3000_1800);
    assert!(
        s.borrow()
            .trace
            .iter()
            .any(|a| matches!(a, Access::Write32(0xfc, 0x2000_0000)))
    );
    c.retire().unwrap();
}

#[test]
fn late_different_cause_and_reassertion_are_masked_not_silently_lost() {
    for reassert in [false, true] {
        let (mut c, s, _) = setup(Profile::Amdi0031, &[16]);
        c.interrupt_enable(p(16), true).unwrap();
        s.borrow_mut().pads[16] |= 0x1000_0000;
        if reassert {
            s.borrow_mut().reassert = Some(16);
        }
        let report = c.service(|_, _| {
            if !reassert {
                s.borrow_mut().pads[16] |= 0x2000_0000;
            }
            Ok(())
        });
        assert_eq!(report.error, None);
        assert_eq!(report.delivered, [1 << 16, 0, 0]);
        assert_eq!(report.storm_masked, [1 << 16, 0, 0]);
        assert_eq!(s.borrow().pads[16] & 0x1000, 0);
        assert_eq!(
            s.borrow().pads[16] & 0x3000_0000,
            if reassert { 0x1000_0000 } else { 0x2000_0000 }
        );
        c.retire().unwrap();
    }
}

#[test]
fn masked_pending_is_not_acknowledged_and_consumer_failure_masks_keeps() {
    let (mut c, s, drops) = setup(Profile::Amd0030, &[2, 3]);
    c.interrupt_enable(p(2), false).unwrap();
    c.interrupt_enable(p(3), true).unwrap();
    s.borrow_mut().pads[2] |= 0x1000_0000;
    s.borrow_mut().pads[3] |= 0x1000_0000;
    let report = c.service(|_, _| Err(Error::Consumer));
    assert_eq!(report.error, Some(Error::Consumer));
    assert_eq!(report.delivered, [0; 3]);
    assert_eq!(s.borrow().pads[2] & 0x1000_0000, 0x1000_0000);
    assert_eq!(s.borrow().pads[3] & 0x1000_1000, 0x1000_0000);
    assert!(c.faulted());
    drop(c);
    assert_eq!(drops.get(), 0);
}

#[test]
fn rejected_or_ambiguous_effects_fault_and_failed_retirement_is_retryable() {
    for post in [false, true] {
        let (mut c, s, drops) = setup(Profile::Amdi0033, &[9]);
        s.borrow_mut().fail_write = Some(36);
        s.borrow_mut().post_effect_failure = post;
        assert_eq!(c.direction_output(p(9), true), Err(Error::Access));
        assert_eq!(
            s.borrow().pads[9] & 0xc0_0000,
            if post { 0xc0_0000 } else { 0 }
        );
        assert_eq!(c.retire(), Err(Error::Access));
        assert!(!c.retired());
        assert_eq!(drops.get(), 0);
        s.borrow_mut().fail_write = None;
        c.retire().unwrap();
        assert!(c.retired());
        assert_eq!(c.input(p(9)), Err(Error::Retired));
        drop(c);
        assert_eq!(drops.get(), 1);
    }
    let (mut c, s, drops) = setup(Profile::Amd0030, &[6]);
    s.borrow_mut().lock = Some(6);
    assert_eq!(c.pull(p(6), Pull::Up), Err(Error::Readback));
    assert_eq!(c.input(p(6)), Err(Error::Faulted));
    drop(c);
    assert_eq!(drops.get(), 0);
}

#[test]
fn access_failures_keep_partial_deliveries_and_do_not_complete_eoi() {
    let (mut c, s, drops) = setup(Profile::Amdi0030, &[1, 2]);
    for pin in [1, 2] {
        c.interrupt_enable(p(pin), true).unwrap();
        s.borrow_mut().pads[usize::from(pin)] |= 0x1000_0000;
    }
    s.borrow_mut().trace.clear();
    let report = c.service(|pad, _| {
        if pad.number() == 1 {
            s.borrow_mut().fail_read = Some(8);
        }
        Ok(())
    });
    assert_eq!(report.delivered, [1 << 1, 0, 0]);
    assert_eq!(report.error, Some(Error::Access));
    assert_eq!(s.borrow().pads[1] & 0x1000_0000, 0);
    assert_eq!(s.borrow().pads[2] & 0x1000_0000, 0x1000_0000);
    assert!(
        !s.borrow()
            .trace
            .iter()
            .any(|a| matches!(a, Access::Write32(0xfc, _)))
    );
    drop(c);
    assert_eq!(drops.get(), 0);
}

#[test]
fn global_debounce_suppression_never_disturbs_firmware_or_live_sibling_irq() {
    let (mut c, s, _) = setup(Profile::Amdi0030, &[1, 2]);
    s.borrow_mut().pads[3] = 0x1800;
    for kind in [false, true] {
        s.borrow_mut().trace.clear();
        let result = if kind {
            c.interrupt_type(p(1), Interrupt::Low)
        } else {
            c.debounce(p(1), 1000)
        };
        assert_eq!(result, Err(Error::FirmwareInterrupt));
        assert!(
            s.borrow()
                .trace
                .iter()
                .all(|a| matches!(a, Access::Read32(_)))
        );
    }
    s.borrow_mut().pads[3] = 0;
    c.interrupt_enable(p(2), true).unwrap();
    assert_eq!(c.debounce(p(1), 1000), Err(Error::InterruptActive));
    c.interrupt_mask(p(2)).unwrap();
    c.debounce(p(1), 1000).unwrap();
    c.retire().unwrap();
}

#[test]
fn partial_transport_retirement_retry_never_reaccesses_retired_registers() {
    let (mut c, s, drops) = setup(Profile::Amdi0033, &[1]);
    c.direction_output(p(1), true).unwrap();
    s.borrow_mut().finish_fail = true;
    assert_eq!(c.retire(), Err(Error::Mapping));
    assert!(!c.retired());
    assert!(c.faulted());
    assert_eq!(drops.get(), 0);
    s.borrow_mut().trace.clear();
    s.borrow_mut().finish_fail = false;
    c.retire().unwrap();
    assert!(s.borrow().trace.is_empty());
    assert_eq!(s.borrow().finish_calls, 2);
    drop(c);
    assert_eq!(drops.get(), 1);
}

#[test]
fn reserved_pad_claim_and_out_of_table_tail_never_touch_registers() {
    for owned in [[1 << 63, 0, 0], [0, 0, 1 << 56]] {
        let s = Rc::new(RefCell::new(State::default()));
        let drops = Rc::new(Cell::new(0));
        assert!(matches!(
            Controller::new(
                Peer {
                    state: s.clone(),
                    drops: drops.clone()
                },
                Profile::Amd0030,
                owned
            ),
            Err(Error::InvalidPad)
        ));
        assert!(s.borrow().trace.is_empty());
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn failed_master_eoi_never_reports_a_completed_service_and_keeps_owner() {
    for post in [false, true] {
        let (mut c, s, drops) = setup(Profile::Amd0030, &[1]);
        c.interrupt_enable(p(1), true).unwrap();
        s.borrow_mut().pads[1] |= 0x1000_0000;
        s.borrow_mut().fail_write = Some(0xfc);
        s.borrow_mut().post_effect_failure = post;
        let report = c.service(|_, _| Ok(()));
        assert_eq!(report.delivered, [1 << 1, 0, 0]);
        assert_eq!(report.error, Some(Error::Access));
        assert!(c.faulted());
        drop(c);
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn real_line_transitions_cover_each_edge_level_and_masked_latching() {
    for (kind, initial, active) in [
        (Interrupt::Rising, false, true),
        (Interrupt::Falling, true, false),
        (Interrupt::BothEdges, false, true),
        (Interrupt::High, false, true),
        (Interrupt::Low, true, false),
    ] {
        let (mut c, s, _) = setup(Profile::Amdi0033, &[5]);
        s.borrow_mut().drive(5, initial);
        c.interrupt_type(p(5), kind).unwrap();
        c.interrupt_enable(p(5), false).unwrap();
        s.borrow_mut().drive(5, active);
        assert_eq!(s.borrow().pads[5] & 0x1000_0000, 0x1000_0000);
        let masked = c.service(|_, _| panic!("masked source delivered"));
        assert_eq!(masked.delivered, [0; 3]);
        assert_eq!(masked.error, None);
        c.interrupt_enable(p(5), true).unwrap();
        let report = c.service(|_, _| {
            s.borrow_mut().drive(5, initial);
            Ok(())
        });
        assert_eq!(report.delivered, [1 << 5, 0, 0]);
        assert_eq!(report.error, None);
        assert_eq!(s.borrow().pads[5] & 0x1000_0000, 0);
        c.retire().unwrap();
    }
}

#[test]
fn electrically_asserted_level_reasserts_w1c_and_is_actually_masked() {
    let (mut c, s, _) = setup(Profile::Amdi0030, &[5]);
    c.interrupt_type(p(5), Interrupt::High).unwrap();
    c.interrupt_enable(p(5), true).unwrap();
    s.borrow_mut().drive(5, true);
    let report = c.service(|_, _| Ok(()));
    assert_eq!(report.storm_masked, [1 << 5, 0, 0]);
    assert_eq!(report.error, None);
    assert_eq!(s.borrow().pads[5] & 0x1000_1000, 0x1000_0000);
    s.borrow_mut().drive(5, false);
    c.retire().unwrap();
}

#[test]
fn exact_drive_strength_encodings_preserve_pending_unknown_and_input_bits() {
    let (mut c, s, _) = setup(Profile::Amdi0031, &[4]);
    s.borrow_mut().pads[4] = 0x1401_0000;
    for encoding in 0..4 {
        c.drive_strength(p(4), encoding).unwrap();
        assert_eq!(
            s.borrow().pads[4],
            0x1401_0000 | (u32::from(encoding) << 17)
        );
    }
    let before = s.borrow().trace.len();
    assert_eq!(c.drive_strength(p(4), 4), Err(Error::InvalidDriveStrength));
    assert_eq!(s.borrow().trace.len(), before);
    c.retire().unwrap();
}
