use super::*;
use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};
use core::cell::RefCell;

#[derive(Default)]
struct Peripheral {
    words: BTreeMap<(u8, u8), u16>,
    log: Vec<(u8, u8, Option<u16>)>,
    accesses: usize,
    fail: Option<usize>,
    effect_then_error: bool,
    remove_after: Option<usize>,
    wrong_alarm: bool,
    empty_block: bool,
    pec: bool,
}
struct Model(Rc<RefCell<Peripheral>>);
impl Bus for Model {
    fn transaction(
        &mut self,
        address: Address,
        transaction: Transaction<'_>,
        pec: bool,
    ) -> Result<(), smbus::Error> {
        let mut m = self.0.borrow_mut();
        assert_eq!(pec, m.pec);
        m.accesses += 1;
        let fail = m.fail == Some(m.accesses);
        if fail && !m.effect_then_error {
            return Err(smbus::ErrorKind::Device.into());
        }
        let address = address.get();
        match transaction {
            Transaction::ReadWord { command, data } => {
                m.log.push((address, command, None));
                *data = m.words[&(address, command)];
            }
            Transaction::WriteWord { command, data } => {
                m.log.push((address, command, Some(data)));
                if address == MANAGER {
                    assert_eq!(command, SELECT);
                    // Physical presence is read-only, regardless of written ones.
                    let presence = m.words[&(MANAGER, SELECT)] & 15;
                    m.words
                        .insert((MANAGER, SELECT), (data & 0xf000) | presence);
                } else if !m.wrong_alarm {
                    assert_eq!((address, command), (BATTERY, SELECT));
                    m.words.insert((address, command), data);
                }
            }
            Transaction::ReadBlock { command, data } => {
                assert_eq!(address, BATTERY);
                m.log.push((address, command, None));
                if !m.empty_block {
                    *data = Block::from_slice(match command {
                        0x20 => b"maker\0raw",
                        0x21 => b"battery-model",
                        0x22 => b"LION",
                        _ => panic!("unexpected battery block"),
                    })
                    .unwrap();
                }
            }
            _ => panic!("unexpected SBS protocol"),
        }
        if m.remove_after == Some(m.accesses) {
            m.words.insert((MANAGER, SELECT), 0);
        }
        if fail {
            Err(smbus::ErrorKind::Device.into())
        } else {
            Ok(())
        }
    }
}
fn model(topology: Topology, pec: bool) -> (Sbs<Model>, Rc<RefCell<Peripheral>>) {
    let mut peripheral = Peripheral {
        pec,
        ..Peripheral::default()
    };
    for (command, value) in [
        (1, 500),
        (3, 0x8000),
        (0x10, 4500),
        (0x17, 42),
        (0x18, 5000),
        (0x19, 12000),
        (0x1a, 0x3211),
        (0x1c, 0x1234),
        (8, 2980),
        (9, 12000),
        (10, (-250i16) as u16),
        (11, (-200i16) as u16),
        (15, 3000),
        (14, 60),
        (0x16, 0x40),
    ] {
        peripheral.words.insert((BATTERY, command), value);
    }
    peripheral.words.insert((MANAGER, SELECT), 3);
    peripheral.words.insert((MANAGER, SYSTEM_INFO), 3);
    peripheral.words.insert((CHARGER, 0x13), 0x8010);
    let m = Rc::new(RefCell::new(peripheral));
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let sbs = unsafe { Sbs::claim(Model(m.clone()), topology, pec) }.unwrap();
    (sbs, m)
}

#[test]
fn native_information_state_signed_values_and_wire_blocks() {
    for topology in [Topology::Single, Topology::Managed] {
        for pec in [false, true] {
            let (mut sbs, m) = model(topology, pec);
            let snapshot = sbs.refresh(0).unwrap().unwrap();
            assert_eq!(
                snapshot.information.capacity_unit(),
                CapacityUnit::TenMilliwattHours
            );
            assert_eq!(snapshot.information.voltage_exponent(), 2);
            assert_eq!(snapshot.information.current_exponent(), 3);
            assert_eq!(snapshot.information.manufacturer.as_slice(), b"maker\0raw");
            assert_eq!(snapshot.information.design_capacity, 5000);
            assert_eq!(snapshot.state.current, -250);
            assert_eq!(snapshot.state.average_current, -200);
            assert_eq!(snapshot.state.remaining_capacity, 3000);
            assert_eq!(snapshot.state.temperature, 2980);
            let commands: Vec<_> = m
                .borrow()
                .log
                .iter()
                .filter(|(a, _, _)| *a == BATTERY)
                .map(|(_, c, _)| *c)
                .collect();
            assert_eq!(
                commands,
                [
                    1, 3, 0x10, 0x17, 0x18, 0x19, 0x1a, 0x1c, 0x20, 0x21, 0x22, 8, 9, 10, 11, 15,
                    14, 0x16, 3, 0x1c
                ]
            );
            assert_eq!(sbs.charger_online(), Ok(Some(true)));
        }
    }
}

#[test]
fn manager_selection_is_actual_and_absence_never_reads_battery() {
    let (mut sbs, m) = model(Topology::Managed, false);
    sbs.refresh(1).unwrap();
    assert!(m.borrow().log.contains(&(MANAGER, SELECT, Some(0x2fff))));
    assert_eq!(m.borrow().words[&(MANAGER, SELECT)], 0x2003);
    for slot in [2, 3, 4, 255] {
        let count = m.borrow().accesses;
        assert_eq!(sbs.refresh(slot), Err(Error::UnsupportedSlot(slot)));
        assert_eq!(m.borrow().accesses, count);
    }
    m.borrow_mut().words.insert((MANAGER, SELECT), 0x2001);
    let start = m.borrow().log.len();
    assert_eq!(sbs.refresh(1), Ok(None));
    assert!(sbs.snapshot().is_none());
    assert!(
        m.borrow().log[start..]
            .iter()
            .all(|(a, _, _)| *a == MANAGER)
    );
}

#[test]
fn alarm_needs_real_write_readback_and_retains_uncertain_owner() {
    let (mut sbs, m) = model(Topology::Managed, false);
    assert_eq!(sbs.set_alarm(100), Err(Error::NotPresent));
    sbs.refresh(0).unwrap();
    sbs.set_alarm(400).unwrap();
    assert_eq!(m.borrow().words[&(BATTERY, SELECT)], 400);
    assert_eq!(sbs.snapshot().unwrap().information.alarm_capacity, 400);
    m.borrow_mut().wrong_alarm = true;
    assert_eq!(sbs.set_alarm(350), Err(Error::Readback));
    assert!(sbs.needs_reset());
    assert!(sbs.snapshot().is_none());
    let count = m.borrow().accesses;
    assert_eq!(sbs.refresh(0), Err(Error::NeedsReset));
    assert_eq!(sbs.set_alarm(350), Err(Error::NeedsReset));
    assert_eq!(sbs.charger_online(), Err(Error::NeedsReset));
    assert_eq!(m.borrow().accesses, count);
}

#[test]
fn every_bus_error_prevents_partial_publication_and_failed_writes_never_replay() {
    let (mut baseline, m) = model(Topology::Managed, false);
    baseline.refresh(0).unwrap();
    let operations = m.borrow().accesses;
    for effect_then_error in [false, true] {
        for failure in 2..=operations {
            let (mut sbs, m) = model(Topology::Managed, false);
            m.borrow_mut().fail = Some(failure);
            m.borrow_mut().effect_then_error = effect_then_error;
            assert!(sbs.refresh(0).is_err());
            assert!(sbs.snapshot().is_none());
            if sbs.needs_reset() {
                let count = m.borrow().accesses;
                assert_eq!(sbs.refresh(0), Err(Error::NeedsReset));
                assert_eq!(m.borrow().accesses, count);
            }
        }
    }
    let (mut baseline, m) = model(Topology::Single, false);
    baseline.refresh(0).unwrap();
    let start = m.borrow().accesses;
    baseline.set_alarm(500).unwrap();
    let end = m.borrow().accesses;
    let mut failed_writes = 0;
    for failure in start + 1..=end {
        let (mut sbs, m) = model(Topology::Single, false);
        sbs.refresh(0).unwrap();
        m.borrow_mut().fail = Some(failure);
        m.borrow_mut().effect_then_error = true;
        assert!(sbs.set_alarm(450).is_err());
        assert!(sbs.snapshot().is_none());
        if sbs.needs_reset() {
            failed_writes += 1;
        }
    }
    // Write and every uncertain validation/readback after it.
    assert_eq!(failed_writes, 4);
}

#[test]
fn removal_or_identity_mode_change_refuses_mixed_snapshot_and_alarm() {
    let (mut sbs, m) = model(Topology::Managed, false);
    m.borrow_mut().remove_after = Some(12);
    assert_eq!(sbs.refresh(0), Err(Error::Changed));
    assert!(sbs.snapshot().is_none());
    let (mut sbs, m) = model(Topology::Single, false);
    sbs.refresh(0).unwrap();
    m.borrow_mut().words.insert((BATTERY, MODE), 0);
    let count = m.borrow().log.len();
    assert_eq!(sbs.set_alarm(100), Err(Error::Changed));
    assert!(!m.borrow().log[count..].iter().any(|(_, _, v)| v.is_some()));
    assert!(sbs.snapshot().is_none());
}

#[test]
fn unsupported_charger_and_empty_success_block_remain_explicit() {
    let (mut sbs, m) = model(Topology::Single, false);
    for (raw, online) in [
        (0xffff, None),
        (0, None),
        (0x8000, None),
        (0x10, Some(false)),
        (0x8010, Some(true)),
    ] {
        m.borrow_mut().words.insert((CHARGER, 0x13), raw);
        assert_eq!(sbs.charger_online(), Ok(online));
    }
    m.borrow_mut().empty_block = true;
    assert_eq!(sbs.refresh(0), Err(Error::EmptyBlock(0x20)));
}

#[test]
fn failed_manager_discovery_never_falls_back_to_a_direct_battery() {
    let peripheral = Rc::new(RefCell::new(Peripheral {
        fail: Some(1),
        ..Peripheral::default()
    }));
    // SAFETY: the model device, its pages and its domain belong to this test alone; no other
    // driver, worker or DMA touches them.
    let result = unsafe { Sbs::claim(Model(peripheral.clone()), Topology::Managed, false) };
    assert!(matches!(
        result,
        Err(Error::Bus {
            address: MANAGER,
            command: SYSTEM_INFO,
            ..
        })
    ));
    assert_eq!(peripheral.borrow().accesses, 1);
    assert!(peripheral.borrow().log.is_empty());
}
