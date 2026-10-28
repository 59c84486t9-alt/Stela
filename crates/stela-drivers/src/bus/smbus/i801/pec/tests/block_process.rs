// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual retained controller and independent full-packet CRC/peripheral peers.
use super::*;

#[test]
fn every_request_reply_length_and_pec_mode_has_one_combined_wire_exchange() {
    for pec in [false, true] {
        for tx in 1..=MAX_BLOCK {
            for rx in 1..=MAX_BLOCK {
                let mut f = fixture(0x7e22, true);
                let request: Vec<u8> = (0..tx)
                    .map(|i| (i as u8).wrapping_mul(19).wrapping_add(tx as u8))
                    .collect();
                let reply: Vec<u8> = (0..rx)
                    .map(|i| (i as u8).wrapping_mul(31).wrapping_add(rx as u8))
                    .collect();
                f.state.borrow_mut().reply = reply.clone();
                let mut output = Block::default();
                f.host
                    .process_block(address(), 0xa7, &request, &mut output, pec)
                    .unwrap();
                assert_eq!(output.as_slice(), reply);
                let h = f.state.borrow();
                assert_eq!(h.starts.len(), 1);
                assert_eq!(
                    h.starts[0],
                    (
                        START | PROTOCOL_BLOCK_PROCESS_CALL,
                        AUX_OTHER | AUX_BUFFER | if pec { AUX_CRC } else { 0 },
                        0x58
                    )
                );
                let wire = &h.wire[0];
                assert_eq!(&wire[..3], &[0x58, 0xa7, tx as u8]);
                assert_eq!(&wire[3..3 + tx], request);
                assert_eq!(&wire[3 + tx..5 + tx], &[0x59, rx as u8]);
                assert_eq!(&wire[5 + tx..5 + tx + rx], reply);
                assert_eq!(wire.len(), 5 + tx + rx + usize::from(pec));
                if pec {
                    assert_eq!(host_crc(wire), 0);
                }
                drop(h);
                check_clean(&f);
                drop(f.host.release().ok().unwrap());
                assert_eq!((f.register_drop.get(), f.configuration_drop.get()), (1, 1));
            }
        }
    }
}

#[test]
fn source_capability_and_request_policy_refuse_before_any_configuration_or_host_io() {
    for device in [0x2413, 0x2483, 0x24c3] {
        let mut f = fixture(device, true);
        let mut output = Block::from_slice(&[0xa5]).unwrap();
        assert_eq!(
            f.host
                .process_block(address(), 0xa7, &[1], &mut output, true)
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedTransaction
        );
        let h = f.state.borrow();
        assert!(h.accesses.is_empty());
        assert_eq!((h.identity_reads, h.configuration_reads), (0, 0));
        assert_eq!(output.as_slice(), &[0xa5]);
    }
    let mut f = fixture(0x24d3, false);
    let mut output = Block::default();
    assert_eq!(
        f.host
            .process_block(address(), 1, &[1], &mut output, false)
            .unwrap_err()
            .kind,
        ErrorKind::UnsupportedTransaction
    );
    assert!(f.state.borrow().accesses.is_empty());
    for length in [0, 33] {
        let mut f = fixture(0x24d3, true);
        assert_eq!(
            f.host
                .process_block(address(), 1, &vec![1; length], &mut output, true)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidBlockLength(length)
        );
        assert!(f.state.borrow().accesses.is_empty());
        assert_eq!(f.state.borrow().identity_reads, 0);
    }
}

#[test]
fn invalid_reply_crc_late_data_or_lost_pci_never_publish_or_replay_the_request() {
    for fault in 0..6 {
        let mut f = fixture(0x24d3, true);
        match fault {
            0 | 1 => f.state.borrow_mut().reply = vec![7; if fault == 0 { 0 } else { 33 }],
            2 => f.state.borrow_mut().corrupt_packet = true,
            3 => f.state.borrow_mut().jump_read = Some((BLOCK_DATA, 3, 1000)),
            4 => f.state.borrow_mut().remove_on_completion = true,
            5 => f.state.borrow_mut().change_config_on_completion = true,
            _ => unreachable!(),
        }
        let mut output = Block::from_slice(&[0xa5, 0x5a]).unwrap();
        let error = f
            .host
            .process_block(address(), 0xa7, &[0x11, 0x22], &mut output, true)
            .unwrap_err();
        assert_eq!(output.as_slice(), &[0xa5, 0x5a]);
        assert_eq!(f.state.borrow().starts.len(), 1);
        if fault < 2 {
            assert!(matches!(error.kind, ErrorKind::InvalidBlockLength(_)));
            assert_eq!(f.state.borrow().read_counts[usize::from(BLOCK_DATA)], 0);
        }
        if fault >= 4 {
            assert_eq!(error.recovery, Recovery::Failed);
            let accesses = f.state.borrow().accesses.len();
            assert_eq!(
                f.host
                    .process_block(address(), 1, &[1], &mut output, false)
                    .unwrap_err()
                    .kind,
                ErrorKind::NeedsReset
            );
            assert_eq!(f.state.borrow().accesses.len(), accesses);
        } else {
            check_clean(&f);
        }
        drop(f.host);
        assert_eq!(
            (f.register_drop.get(), f.configuration_drop.get()),
            if fault >= 4 { (0, 0) } else { (1, 1) }
        );
    }
}

#[test]
fn failed_crc_cleanup_or_kill_retains_original_request_and_configuration_owners() {
    for fault in 0..3 {
        let mut f = fixture(0x7e22, true);
        match fault {
            0 => f.state.borrow_mut().reject_crc_clear = true,
            1 => {
                f.state.borrow_mut().corrupt_packet = true;
                f.state.borrow_mut().sticky_crc = true;
            }
            2 => {
                f.state.borrow_mut().hang = true;
                f.state.borrow_mut().kill_stuck = true;
            }
            _ => unreachable!(),
        }
        let mut output = Block::from_slice(&[0xa5]).unwrap();
        let error = f
            .host
            .process_block(address(), 0xa7, &[1, 2, 3], &mut output, true)
            .unwrap_err();
        assert_eq!(error.recovery, Recovery::Failed);
        assert_eq!(output.as_slice(), &[0xa5]);
        assert_eq!(f.state.borrow().starts.len(), 1);
        assert_eq!(
            f.host
                .transaction(address(), Transaction::SendByte(1), false)
                .unwrap_err()
                .kind,
            ErrorKind::NeedsReset
        );
        drop(f.host);
        assert_eq!((f.register_drop.get(), f.configuration_drop.get()), (0, 0));
    }
}

#[test]
#[ignore = "oracle: STELA_I801_BLOCK_PROCESS_ORACLE"]
fn unchanged_linux_combined_blocks_fifo_resets_and_optional_pec_policy() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var("STELA_I801_BLOCK_PROCESS_ORACLE").expect("fresh BPC source trace"),
    )
    .unwrap();
    let mut lines = trace.lines();
    assert_eq!(
        lines.next(),
        Some("I801_BLOCK_PROCESS cc9de5d4b5ab6459f5774946aa3195ad51236fa8 512")
    );
    let hash = |bytes: &[u8]| {
        bytes.iter().fold(2166136261u32, |h, b| {
            (h ^ u32::from(*b)).wrapping_mul(16777619)
        }) as usize
    };
    let mut count = 0;
    for (id, line) in lines.enumerate() {
        let v: Vec<usize> = line
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(v.len(), 17);
        assert_eq!(v[0], id);
        let request: Vec<u8> = (0..v[1])
            .map(|i| (i as u8).wrapping_mul(19).wrapping_add(v[1] as u8))
            .collect();
        let reply: Vec<u8> = (0..v[2])
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(v[2] as u8))
            .collect();
        let mut f = fixture(0x24d3, true);
        f.state.borrow_mut().reply = reply.clone();
        f.state.borrow_mut().completion_status = v[4] as u8;
        f.state.borrow_mut().corrupt_packet = v[5] != 0;
        let mut output = Block::from_slice(&[0xa5, 0x5a]).unwrap();
        let result = f
            .host
            .process_block(address(), 0xa7, &request, &mut output, v[3] != 0);
        let class = match result {
            Ok(()) => {
                assert_eq!(output.as_slice(), reply);
                assert_eq!(hash(output.as_slice()), v[11]);
                assert_eq!(v[12], v[2]);
                0
            }
            Err(error) => {
                assert_eq!(output.as_slice(), &[0xa5, 0x5a]);
                assert_eq!(v[11], v[10], "Linux input union retained on error");
                assert_eq!(v[12], v[1]);
                match error.kind {
                    ErrorKind::Failed => 1,
                    ErrorKind::Device => 2,
                    ErrorKind::PecMismatch {
                        auxiliary_status: AUX_CRC_ERROR,
                    } => 3,
                    ErrorKind::ArbitrationLost => 4,
                    other => panic!("unexpected BPC error: {other:?}"),
                }
            }
        };
        assert_eq!(class, v[6]);
        let h = f.state.borrow();
        assert_eq!(h.starts.len(), 1);
        assert_eq!(usize::from(h.starts[0].0), v[7]);
        assert_eq!(usize::from(h.starts[0].1), v[8]);
        assert_eq!(usize::from(h.starts[0].2), v[9]);
        let wire = &h.wire[0];
        assert_eq!(&wire[..3], &[0x58, 0xa7, v[1] as u8]);
        assert_eq!(hash(&wire[3..3 + v[1]]), v[10]);
        assert_eq!(&wire[3..3 + v[1]], request);
        assert_eq!(&wire[3 + v[1]..5 + v[1]], &[0x59, v[2] as u8]);
        assert_eq!(&wire[5 + v[1]..5 + v[1] + v[2]], reply);
        assert_eq!(usize::from(h.registers[13]), v[13]);
        assert_eq!(usize::from(h.status & (INUSE | STATUS_FLAGS)), v[14]);
        assert_eq!(usize::from(h.registers[12]), v[15]);
        assert_eq!(h.read_counts[usize::from(HOST_CONTROL)], v[16]);
        count += 1;
    }
    assert_eq!(count, 512);
}
