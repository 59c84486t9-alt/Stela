// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn cold_radio_real_prefix_retains_nvm_epoch_and_actual_command_completions() {
    exercise_cold_radio(false);
}

#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn cold_radio_actual_images_run_source_prefix_with_distinct_offload_and_latencies() {
    exercise_cold_radio(true);
}

#[test]
fn cold_radio_preflight_rfkill_wrong_response_and_uncertain_publication_fail_closed() {
    for case in 0..5 {
        let mut bytes = radio_bytes(false);
        if case == 0 {
            let mut at = 88;
            while at < bytes.len() {
                let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
                let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
                if kind == 48 {
                    for row in bytes[at + 8..at + 8 + len].as_chunks_mut::<4>().0 {
                        if row[..2] == [0xd1, 1] {
                            row[2] = 99;
                        }
                    }
                    break;
                }
                at += 8 + len.next_multiple_of(4);
            }
        }
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let boot = command_ready(boot, &empty, &source, &domain, &state);
        let init = drive_nvm(boot, &source, &domain, &state);
        let mut radio = init
            .begin_radio()
            .unwrap_or_else(|_| panic!("actual NVM rejected"));
        let before_ops = state.lock().unwrap().ops.len();
        let before_allocations = source.calls.load(Ordering::Relaxed);
        match case {
            1 => {
                *state.lock().unwrap().registers.get_mut(&0x24).unwrap() &= !0x08000000;
            }
            3 => {
                state.lock().unwrap().fail = Some(before_ops + 1);
            }
            4 => {
                let mut r = domain.records.lock().unwrap();
                r.map_fail = Some(r.maps);
            }
            _ => (),
        }
        // SAFETY: The original model owner keeps exclusive Source RAM in its Domain;
        // schema/RF-kill/publication failures are serialized without a competing device user.
        let result = unsafe { radio.advance(&source) };
        match case {
            0 => {
                assert_eq!(
                    result,
                    Err(Error::Radio(
                        crate::net::wifi::intel::radio::Error::Version {
                            stage: crate::net::wifi::intel::radio::Stage::SmartFifo,
                            declared: 99
                        }
                    ))
                );
                assert_eq!(state.lock().unwrap().ops.len(), before_ops);
                assert_eq!(source.calls.load(Ordering::Relaxed), before_allocations);
            }
            1 => assert_eq!(result, Err(Error::RfKilled)),
            2 => {
                assert!(result.is_ok());
                complete(
                    &radio.initialized.boot,
                    &domain,
                    5,
                    6,
                    &command_packet(
                        crate::net::wifi::intel::command::Id {
                            group: 2,
                            opcode: 0xfd,
                            version: 0,
                        },
                        3,
                        &[],
                    ),
                );
                assert_eq!(
                    // SAFETY: The wrong response completed synchronously in this model Domain;
                    // radio and the same Source keep all pending backing alive through its refusal.
                    unsafe { radio.advance(&source) },
                    Err(Error::InitializationResponse {
                        group: 2,
                        command: 0xfd
                    })
                );
                assert_eq!(state.lock().unwrap().registers[&0x460], 4);
            }
            3 => assert_eq!(result, Err(Error::Access(power::AccessError::Unavailable))),
            4 => assert!(matches!(result, Err(Error::Dma(_)))),
            _ => unreachable!(),
        }
        assert_eq!(radio.phase(), ColdRadioPhase::Failed);
        assert!(radio.prefix_responses().is_empty());
        let ops = state.lock().unwrap().ops.len();
        // SAFETY: The failed radio still owns its original Source/Domain and pending RAM;
        // this state-error reentry neither adds a publisher nor releases uncertain backing.
        assert_eq!(unsafe { radio.advance(&source) }, Err(Error::State));
        assert_eq!(state.lock().unwrap().ops.len(), ops);
        if case == 3 {
            {
                let mut s = state.lock().unwrap();
                s.fail = None;
                s.stop_ack = false;
            }
            assert!(radio.stop().is_err());
            let retained = domain.records.lock().unwrap().live.len();
            assert!(retained > 0);
            drop(radio);
            assert_eq!(domain.records.lock().unwrap().live.len(), retained);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
        } else {
            radio.stop().unwrap();
            drop(radio);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
}
