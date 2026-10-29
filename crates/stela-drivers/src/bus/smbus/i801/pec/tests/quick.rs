// SPDX-License-Identifier: GPL-2.0-or-later
//! Empty-payload SMBus Quick through the configuration owner.
use super::*;

#[test]
fn quick_both_directions_all_unicast_addresses_never_touch_command_data_or_crc() {
    for device in [0x2413, 0x2483, 0x24c3, 0x7e22] {
        let mut f = fixture(device, true);
        f.state.borrow_mut().registers[3] = 0xf0;
        f.state.borrow_mut().registers[5] = 0x5a;
        f.state.borrow_mut().registers[6] = 0xa5;
        for address in 8..=0x77 {
            for read in [false, true] {
                f.host.quick(Address::new(address).unwrap(), read).unwrap();
                let h = f.state.borrow();
                assert_eq!(h.wire.last().unwrap(), &[address << 1 | u8::from(read)]);
                assert_eq!(h.starts.last().unwrap().0, START | PROTOCOL_QUICK);
                assert_eq!(h.starts.last().unwrap().1 & (AUX_CRC | AUX_BUFFER), 0);
                assert_eq!(
                    (h.registers[3], h.registers[5], h.registers[6]),
                    (0xf0, 0x5a, 0xa5)
                );
                assert!(!h.accesses.iter().any(|(_, r, _)| {
                    [HOST_COMMAND, HOST_DATA0, HOST_DATA1, BLOCK_DATA].contains(r)
                }));
                drop(h);
                check_clean(&f);
            }
        }
        drop(f.host.release().ok().unwrap());
        assert_eq!((f.register_drop.get(), f.configuration_drop.get()), (1, 1));
    }
}

#[test]
fn quick_errors_and_late_completion_never_succeed_or_replay() {
    for fault in 0..6 {
        let mut f = fixture(0x7e22, true);
        match fault {
            0 => f.state.borrow_mut().completion_status = DEV_ERR,
            1 => f.state.borrow_mut().completion_status = FAILED | DEV_ERR | BUS_ERR,
            2 => f.state.borrow_mut().jump_configuration = true,
            3 => f.state.borrow_mut().remove_on_completion = true,
            4 => f.state.borrow_mut().change_config_on_completion = true,
            5 => f.state.borrow_mut().hang = true,
            _ => unreachable!(),
        }
        let error = f.host.quick(address(), true).unwrap_err();
        assert_eq!(f.state.borrow().starts.len(), 1);
        assert!(match fault {
            0 => error.kind == ErrorKind::Device,
            1 => error.kind == ErrorKind::ArbitrationLost,
            2 | 5 => matches!(error.kind, ErrorKind::Timeout(_)),
            3 | 4 => error.recovery == Recovery::Failed,
            _ => false,
        });
        if fault == 3 || fault == 4 {
            let n = f.state.borrow().accesses.len();
            assert_eq!(
                f.host.quick(address(), false).unwrap_err().kind,
                ErrorKind::NeedsReset
            );
            assert_eq!(f.state.borrow().accesses.len(), n);
        } else {
            check_clean(&f);
        }
        drop(f.host);
        assert_eq!(
            (f.register_drop.get(), f.configuration_drop.get()),
            if fault == 3 || fault == 4 {
                (0, 0)
            } else {
                (1, 1)
            }
        );
    }
}

#[test]
fn quick_does_not_steal_a_busy_host_and_retains_failed_kill_or_mode_owners() {
    for status in [INUSE, HOST_BUSY, INUSE | HOST_BUSY] {
        let mut f = fixture(0x7e22, true);
        f.state.borrow_mut().status = status | ALERT;
        assert_eq!(
            f.host.quick(address(), false).unwrap_err().kind,
            ErrorKind::Busy
        );
        assert!(f.state.borrow().starts.is_empty());
        assert_eq!(f.state.borrow().kills, 0);
    }
    for mode in [false, true] {
        let mut f = fixture(0x7e22, true);
        if mode {
            f.state.borrow_mut().registers[13] |= AUX_CRC;
            f.state.borrow_mut().reject_crc_clear = true;
        } else {
            f.state.borrow_mut().hang = true;
            f.state.borrow_mut().kill_stuck = true;
        }
        let error = f.host.quick(address(), false).unwrap_err();
        assert_eq!(error.recovery, Recovery::Failed);
        assert_eq!(f.state.borrow().starts.len(), usize::from(!mode));
        assert_eq!(
            f.host.quick(address(), true).unwrap_err().kind,
            ErrorKind::NeedsReset
        );
        drop(f.host);
        assert_eq!((f.register_drop.get(), f.configuration_drop.get()), (0, 0));
    }
}

#[test]
#[ignore = "oracle: STELA_I801_QUICK_ORACLE"]
fn unchanged_linux_quick_target_error_policy_and_absence_of_data_or_pec_match_native() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var("STELA_I801_QUICK_ORACLE").expect("fresh Quick trace"),
    )
    .unwrap();
    let mut lines = trace.lines();
    assert_eq!(
        lines.next(),
        Some("I801_QUICK cc9de5d4b5ab6459f5774946aa3195ad51236fa8 96")
    );
    let mut count = 0;
    for (id, line) in lines.enumerate() {
        let v: Vec<usize> = line
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(v.len(), 18);
        assert_eq!(v[0], id);
        assert!(v[3] <= 1);
        let mut f = fixture(0x7e22, true);
        {
            let mut h = f.state.borrow_mut();
            h.registers[3] = 0xf0;
            h.registers[5] = 0x5a;
            h.registers[6] = 0xa5;
            h.registers[13] = AUX_OTHER | AUX_CRC;
            h.completion_status = v[4] as u8;
        }
        let result = f.host.quick(Address::new(v[1] as u8).unwrap(), v[2] != 0);
        let class = match result {
            Ok(()) => 0,
            Err(error) => match error.kind {
                ErrorKind::Failed => 1,
                ErrorKind::Device => 2,
                ErrorKind::ArbitrationLost => 4,
                other => panic!("unexpected Quick result: {other:?}"),
            },
        };
        assert_eq!(class, v[5]);
        let h = f.state.borrow();
        assert_eq!(h.starts.len(), 1);
        assert_eq!(usize::from(h.starts[0].0), v[6]);
        assert_eq!(usize::from(h.starts[0].2), v[7]);
        assert_eq!(usize::from(h.starts[0].1 & AUX_CRC), v[8]);
        assert_eq!(
            h.read_counts[usize::from(HOST_DATA0)] + h.read_counts[usize::from(HOST_DATA1)],
            v[9]
        );
        assert_eq!(
            h.accesses
                .iter()
                .filter(|(write, r, _)| *write && *r == HOST_COMMAND)
                .count(),
            v[10]
        );
        let data_stores = h
            .accesses
            .iter()
            .filter(|(write, offset, _)| *write && (*offset == HOST_DATA0 || *offset == HOST_DATA1))
            .count();
        assert_eq!(data_stores, v[11]);
        assert_eq!(usize::from(h.registers[3]), v[12]);
        assert_eq!(usize::from(h.registers[5]), v[13]);
        assert_eq!(usize::from(h.registers[6]), v[14]);
        assert_eq!(usize::from(h.registers[13]), v[15]);
        assert_eq!(usize::from(h.status & (INUSE | STATUS_FLAGS)), v[16]);
        assert_eq!(usize::from(h.registers[12]), v[17]);
        assert_eq!(h.wire, vec![vec![v[7] as u8]]);
        count += 1;
    }
    assert_eq!(count, 96);
}
