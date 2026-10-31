// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

pub(super) fn exercise_lari_bios(actual: bool) {
    for ax210 in [false, true] {
        let profile = if ax210 { ax210_profile() } else { profile() };
        let bytes = if actual {
            use sha2::{Digest, Sha256};
            let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
            let bytes =
                std::fs::read(std::path::Path::new(&root).join(profile.family().firmware_name()))
                    .unwrap();
            assert_eq!(
                std::format!("{:x}", Sha256::digest(&bytes)),
                if ax210 {
                    "792478ef7752595525379a5068e2d47e310a2c344636b7df866c54746ced1dc0"
                } else {
                    "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
                }
            );
            bytes
        } else {
            lari_bytes(ax210, if ax210 { 12 } else { 6 })
        };
        let expected_ids = if actual && !ax210 {
            vec![1]
        } else {
            vec![8, 1]
        };
        let catalog = catalog_for(&profile, profile.family().firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = if ax210 {
            ax210_state()
        } else {
            Arc::new(Mutex::new(ModelState::default()))
        };
        let drops = Arc::new(AtomicUsize::new(0));
        let bios_drops = Arc::new(AtomicUsize::new(0));
        let (observation, step_catalog) = step_fixture();
        let boot = if ax210 {
            start_ax210(
                &catalog,
                crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                &domain,
                &state,
                &drops,
            )
        } else {
            start(&catalog, &source, &domain, &state, &drops)
        };
        let boot = command_ready(boot, &empty, &source, &domain, &state);
        let init = drive_nvm(boot, &source, &domain, &state);
        let cold = init.begin_radio().unwrap_or_else(|_| panic!("actual NVM"));
        let before = state.lock().unwrap().ops.len();
        // SAFETY: RadioBios belongs to the same modeled function and moves into this call;
        // a prefix refusal returns that exact owned service without namespace reads.
        let rejected = unsafe {
            cold.begin_lari(RadioBios {
                drops: bios_drops.clone(),
                unavailable: false,
                absent: false,
            })
        }
        .err()
        .unwrap();
        assert_eq!(state.lock().unwrap().ops.len(), before);
        assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
        let (mut cold, bios) = *rejected;
        // Resume the original owner, without copying its initialization.
        let expected = crate::wifi::intel::radio::InitialPlan::prepare(
            &cold.initialized.boot.firmware,
            profile.platform(),
            &cold.initialized_nvm().information,
        )
        .unwrap();
        // SAFETY: The refused prefix returned the original boot owner and its Domain;
        // the same exclusive Source remains live while the cold plan is first published.
        unsafe { cold.advance(&source) }.unwrap();
        for (i, command) in expected.commands().iter().enumerate() {
            let mut id = command.id();
            if id.group == 0 {
                id.group = 1;
            }
            complete(
                &cold.initialized.boot,
                &domain,
                5 + i as u16,
                6 + i as u16,
                &command_packet(id, 3 + i as u16, &[]),
            );
            // SAFETY: Each prefix response completed synchronously in that domain;
            // cold and Source keep all mapped RAM through reclaim and next publication.
            unsafe { cold.advance(&source) }.unwrap();
        }
        // SAFETY: bios is the original modeled service returned by refusal, with no owner
        // substitution; it moves into LARI after this same boot prefix has completed.
        let mut lari = unsafe { cold.begin_lari(bios) }.unwrap_or_else(|_| panic!("real prefix"));
        assert_eq!(
            // SAFETY: The original boot/domain and BIOS service remain owned by LARI;
            // Source supplies exclusive model RAM for its schema-selected direct commands.
            unsafe { lari.advance(&source) }.unwrap(),
            LariPhase::Waiting {
                command: expected_ids[0]
            }
        );
        let commands: Vec<_> = lari
            .plan()
            .unwrap()
            .commands()
            .map(|(id, b)| (id, b.to_vec()))
            .collect();
        assert_eq!(
            commands.iter().map(|(id, _)| id.opcode).collect::<Vec<_>>(),
            expected_ids
        );
        assert_eq!(
            lari.plan().unwrap().schema(),
            if ax210 {
                if actual { 8 } else { 12 }
            } else {
                6
            }
        );
        assert_eq!(lari.platform_reads().len(), 3); // GLAI, GeneralCfg, WBEM
        let mut copied = lari.plan().unwrap().clone();
        let copied_inputs = *copied.inputs();
        copied = crate::wifi::intel::radio::lari::Plan::prepare(
            &lari.radio.initialized.boot.firmware,
            0,
            copied_inputs,
        )
        .unwrap();
        assert_eq!(copied.commands().count(), commands.len()); // no owner/advancement permission
        let base = expected.commands().len() as u16;
        for (i, (id, payload)) in commands.iter().enumerate() {
            let sequence = 3 + base + i as u16;
            let boot = &lari.radio.initialized.boot;
            let descriptor = device_read(
                &domain,
                boot.command.region().address,
                usize::from(sequence) * 256,
                256,
            );
            let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
            let encoded =
                crate::wifi::intel::command::Command::encode(*id, 0, sequence, payload).unwrap();
            let mut emitted = device_read(&domain, first, 0, encoded.bytes().len().min(20));
            if encoded.bytes().len() > 20 {
                let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
                emitted.extend(device_read(&domain, rest, 0, encoded.bytes().len() - 20));
            }
            assert_eq!(emitted, encoded.bytes());
            let bell = state.lock().unwrap().registers[&0x460];
            assert_eq!(
                // SAFETY: No completion has been injected since publication; the original LARI
                // owner/domain keep pending mappings and Source while polling without resend.
                unsafe { lari.advance(&source) }.unwrap(),
                LariPhase::Waiting { command: id.opcode }
            );
            assert_eq!(state.lock().unwrap().registers[&0x460], bell);
            complete(
                &lari.radio.initialized.boot,
                &domain,
                5 + base + i as u16,
                6 + base + i as u16,
                &command_packet(*id, sequence, &[0xa5 + i as u8]),
            );
            if i == 0 {
                let mut r = domain.records.lock().unwrap();
                r.cpu_sync_fail = Some(r.cpu_syncs + 1);
                drop(r);
                assert!(matches!(
                    // SAFETY: The response completed synchronously, and injected CPU-sync failure
                    // cannot release its backing: this same LARI owner/source keep the mapping.
                    unsafe { lari.advance(&source) },
                    Err(LariError::Boot(Error::CommandReclaim(_)))
                ));
                assert_eq!(lari.phase(), LariPhase::Waiting { command: id.opcode });
                assert_eq!(state.lock().unwrap().registers[&0x460], bell);
                domain.records.lock().unwrap().cpu_sync_fail = None;
            }
            assert_eq!(
                // SAFETY: The failed reclaim kept all original owner/domain mappings; clearing
                // the model injection permits retry with the same exclusive Source and response.
                unsafe { lari.advance(&source) }.unwrap(),
                commands
                    .get(i + 1)
                    .map_or(LariPhase::RxQueueConfigurationRequired, |(id, _)| {
                        LariPhase::Waiting { command: id.opcode }
                    })
            );
        }
        assert_eq!(lari.responses().len(), commands.len());
        for (i, response) in lari.responses().iter().enumerate() {
            assert_eq!(response.raw, [0xa5 + i as u8]);
        }
        let ops = state.lock().unwrap().ops.len();
        assert_eq!(
            // SAFETY: The completed LARI state still owns its original BIOS/source/domain;
            // this final observation has no new publication or competing model device user.
            unsafe { lari.advance(&source) }.unwrap(),
            LariPhase::RxQueueConfigurationRequired
        );
        assert_eq!(state.lock().unwrap().ops.len(), ops);
        assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
        lari.stop().unwrap();
        drop(lari);
        assert!(domain.records.lock().unwrap().live.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
    }
}
