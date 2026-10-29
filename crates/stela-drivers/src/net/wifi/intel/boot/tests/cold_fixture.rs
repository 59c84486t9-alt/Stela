// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

pub(super) fn exercise_cold_radio(actual: bool) {
    use crate::net::wifi::intel::radio::InitialPlan;
    for ax210 in [false, true] {
        let profile = if ax210 { ax210_profile() } else { profile() };
        let bytes = if actual {
            let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
            std::fs::read(std::path::Path::new(&root).join(profile.family().firmware_name()))
                .unwrap()
        } else {
            radio_bytes(ax210)
        };
        let catalog = catalog_for(&profile, profile.family().firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let (observation, step_catalog) = step_fixture();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = if ax210 {
            ax210_state()
        } else {
            Arc::new(Mutex::new(ModelState::default()))
        };
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = if ax210 {
            start_ax210(
                &catalog,
                crate::net::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
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
        let expected = InitialPlan::prepare(
            &init.boot.firmware,
            profile.family(),
            &init.receipt().unwrap().information,
        )
        .unwrap();
        let mut copied = init.receipt().unwrap().clone();
        copied.information.tx_chains = 0xff;
        copied.address.bytes = [0; 6];
        let mut radio = init
            .begin_radio()
            .unwrap_or_else(|_| panic!("genuine NVM refused"));
        let before = state.lock().unwrap().ops.len();
        assert!(matches!(radio.poll_mpdu_observation(), Err(Error::State)));
        assert_eq!(state.lock().unwrap().ops.len(), before);
        assert_eq!(radio.initialized_nvm().information.tx_chains, 3);
        assert_ne!(radio.initialized_nvm().address.bytes, copied.address.bytes);
        assert_eq!(
            // SAFETY: begin_radio moved the initialized model owner and its mappings;
            // the same exclusive Source/Domain publish the NVM-selected cold prefix.
            unsafe { radio.advance(&source) }.unwrap(),
            ColdRadioPhase::Waiting(expected.commands()[0].stage())
        );
        for (i, command) in expected.commands().iter().enumerate() {
            let sequence = 3 + i as u16;
            let boot = &radio.initialized.boot;
            let wire = device_read(
                &domain,
                boot.command.region().address,
                usize::from(sequence) * 256,
                256,
            );
            let first = u64::from_le_bytes(wire[4..12].try_into().unwrap());
            let encoded = crate::net::wifi::intel::command::Command::encode(
                command.id(),
                0,
                sequence,
                command.bytes(),
            )
            .unwrap();
            let mut emitted = device_read(&domain, first, 0, encoded.bytes().len().min(20));
            if encoded.bytes().len() > 20 {
                let rest = u64::from_le_bytes(wire[14..22].try_into().unwrap());
                emitted.extend(device_read(&domain, rest, 0, encoded.bytes().len() - 20));
            }
            assert_eq!(emitted, encoded.bytes());
            let doorbell = state.lock().unwrap().registers[&0x460];
            assert_eq!(
                // SAFETY: No completion has occurred since publication; radio keeps that same
                // pending mapping and exclusive Source while polling the serialized model.
                unsafe { radio.advance(&source) }.unwrap(),
                ColdRadioPhase::Waiting(command.stage())
            );
            assert_eq!(state.lock().unwrap().registers[&0x460], doorbell);
            let mut response_id = command.id();
            if response_id.group == 0 {
                response_id.group = 1;
            }
            complete(
                &radio.initialized.boot,
                &domain,
                5 + i as u16,
                6 + i as u16,
                &command_packet(response_id, sequence, &[0xa0 + i as u8]),
            );
            if i == 0 {
                let mut r = domain.records.lock().unwrap();
                r.cpu_sync_fail = Some(r.cpu_syncs + 1);
                drop(r);
                assert!(matches!(
                    // SAFETY: The response completed synchronously in kept model RAM; injected
                    // CPU-sync failure leaves ownership with radio for a retry using this Source.
                    unsafe { radio.advance(&source) },
                    Err(Error::CommandReclaim(_))
                ));
                assert_eq!(radio.phase(), ColdRadioPhase::Waiting(command.stage()));
                assert_eq!(state.lock().unwrap().registers[&0x460], doorbell);
                domain.records.lock().unwrap().cpu_sync_fail = None;
            }
            // SAFETY: The failed reclaim kept the original Domain and all pending buffers;
            // clearing its serialized injection retries with the same exclusive Source.
            let phase = unsafe { radio.advance(&source) }.unwrap();
            assert_eq!(
                phase,
                expected
                    .commands()
                    .get(i + 1)
                    .map_or(ColdRadioPhase::PlatformConfigurationRequired, |next| {
                        ColdRadioPhase::Waiting(next.stage())
                    })
            );
            assert_eq!(radio.prefix_responses().len(), i + 1);
            assert_eq!(radio.prefix_responses()[i].raw, [0xa0 + i as u8]);
        }
        let ops = state.lock().unwrap().ops.len();
        let allocations = source.calls.load(Ordering::Relaxed);
        assert_eq!(
            // SAFETY: The completed prefix still keeps the original model owner/domain;
            // the final observation uses the same Source without publishing another command.
            unsafe { radio.advance(&source) }.unwrap(),
            ColdRadioPhase::PlatformConfigurationRequired
        );
        assert_eq!(state.lock().unwrap().ops.len(), ops);
        assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
        exercise_mpdu_observations(&mut radio, &source, &domain, &state);
        radio.stop().unwrap();
        drop(radio);
        assert!(domain.records.lock().unwrap().live.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
