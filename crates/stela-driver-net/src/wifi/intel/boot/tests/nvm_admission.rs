// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn unified_missing_unknown_or_contradictory_nvm_abi_refuses_before_commands() {
    if crate::test_process::isolate_model() {
        return;
    }
    for failure in 0..3 {
        let mut bytes = if failure == 0 {
            firmware_bytes()
        } else {
            unified_bytes(false)
        };
        if failure == 1 {
            let at = bytes.windows(4).position(|w| w == [2, 12, 1, 4]).unwrap();
            bytes[at + 3] = 6;
        }
        if failure == 2 {
            let n = bytes.len();
            bytes[n - 4..].fill(0);
        }
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let boot = command_ready(boot, &empty, &source, &domain, &state);
        let mut init = boot.initialize_on_device_nvm();
        let ops = state.lock().unwrap().ops.len();
        let maps = domain.records.lock().unwrap().maps;
        assert!(matches!(
            // SAFETY: The model still owns the same requester/domain and exclusive Source;
            // unsupported ABI metadata is refused before allocating or publishing DMA.
            unsafe { init.advance(&source) },
            Err(Error::Nvm(_))
        ));
        assert_eq!(init.phase(), InitializationPhase::Failed);
        assert!(init.receipt().is_none());
        assert_eq!(state.lock().unwrap().ops.len(), ops);
        assert_eq!(domain.records.lock().unwrap().maps, maps);
        init.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
}

#[test]
fn unified_mac_data_words_allow_all_ff_fallback_and_valid_sentinel_patterns() {
    if crate::test_process::isolate_model() {
        return;
    }
    use crate::wifi::intel::nvm::{AddressSource, Request};
    for case in 0..8 {
        let bytes = unified_bytes(false);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let boot = command_ready(boot, &empty, &source, &domain, &state);
        let mut init = boot.initialize_on_device_nvm();
        // SAFETY: Source allocates exclusive RAM for this model initializer;
        // its requester/domain have no asynchronous device or IRQ user.
        unsafe { init.advance(&source) }.unwrap();
        complete(
            &init.boot,
            &domain,
            1,
            2,
            &command_packet(Request::ExtendedConfiguration.id(), 0, &[]),
        );
        // SAFETY: The extended-configuration ACK completed synchronously within that
        // same domain; its original Source/mappings remain live.
        unsafe { init.advance(&source) }.unwrap();
        let mut packet = command_packet(Request::AccessComplete.id(), 1, &[]);
        let notification = command_packet(
            crate::wifi::intel::command::Id {
                group: 0,
                opcode: 4,
                version: 0,
            },
            0x8000,
            &[],
        );
        packet[64..128].copy_from_slice(&notification[..64]);
        packet[128..132].copy_from_slice(&0x55550000u32.to_le_bytes());
        complete(&init.boot, &domain, 2, 3, &packet);
        // SAFETY: The combined access ACK/notification is published in owned model RAM;
        // the initializer keeps its source/domain through reclaim and staging.
        unsafe { init.advance(&source) }.unwrap();
        // SAFETY: The same model owner keeps the queued notification and pending DMA;
        // Source has no competing writer while initialization advances its phase.
        unsafe { init.advance(&source) }.unwrap();
        let strap = match case {
            0 => [u32::MAX; 2],
            1 => [0x02123456, u32::MAX],
            5 => [0xa5a5a5a0, 0x789a],
            6 => [0x5a5a5a50, 0x789a],
            _ => [0x02123456, 0x789a],
        };
        {
            let mut s = state.lock().unwrap();
            s.registers.extend([
                (0x388, strap[0]),
                (0x38c, strap[1]),
                (0x380, 0x02123456),
                (0x384, 0x789a),
            ]);
            if case == 2 {
                s.registers.insert(0x28, u32::MAX);
            }
            if case == 3 {
                s.fail_read = Some(0x388);
            }
            if case == 7 {
                s.all_ff = true;
            }
            // Three transport CSR operations precede the pre-read two
            // identity observations and the two MAC words.
            if case == 4 {
                s.sentinel = Some((s.ops.len() + 7, u32::MAX));
            }
        }
        complete(
            &init.boot,
            &domain,
            3,
            4,
            &command_packet(Request::GetInformation.id(), 2, &nvm_response()),
        );
        let live = domain.records.lock().unwrap().live.len();
        // SAFETY: Only the serialized model registers/failure injection changed; the
        // original source/domain still own all DMA while testing MAC-read outcomes.
        let result = unsafe { init.advance(&source) };
        match case {
            7 => {
                assert!(matches!(
                    result,
                    Err(Error::FailedRead {
                        register: 8,
                        value: u32::MAX
                    })
                ));
                assert!(init.receipt().is_none());
            }
            2 | 4 => {
                assert!(matches!(
                    result,
                    Err(Error::FailedRead {
                        register: 0x28,
                        value: u32::MAX
                    })
                ));
                assert!(init.receipt().is_none());
            }
            3 => {
                assert!(matches!(
                    result,
                    Err(Error::Access(power::AccessError::Unavailable))
                ));
                assert!(init.receipt().is_none());
            }
            _ => {
                assert_eq!(result.unwrap(), InitializationProgress::Observed);
                let address = init.receipt().unwrap().address;
                assert_eq!(
                    address.source,
                    if matches!(case, 0 | 5) {
                        AddressSource::Otp
                    } else {
                        AddressSource::Strap
                    }
                );
                assert_eq!(
                    address.bytes,
                    match case {
                        1 => [2, 0x12, 0x34, 0x56, 0xff, 0xff],
                        6 => [0x5a, 0x5a, 0x5a, 0x50, 0x78, 0x9a],
                        _ => [2, 0x12, 0x34, 0x56, 0x78, 0x9a],
                    }
                );
                if matches!(case, 1 | 6) {
                    let s = state.lock().unwrap();
                    assert!(!s.ops.contains(&Op::Read(0x380)));
                    assert!(!s.ops.contains(&Op::Read(0x384)));
                }
            }
        }
        state.lock().unwrap().fail_read = None;
        if case == 7 {
            assert!(init.stop().is_err());
            drop(init);
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
        } else {
            init.stop().unwrap();
            assert!(domain.records.lock().unwrap().live.is_empty());
        }
    }
}
