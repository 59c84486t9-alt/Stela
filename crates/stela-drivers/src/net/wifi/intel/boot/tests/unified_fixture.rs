// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

pub(super) fn exercise_unified_nvm(actual_image: bool) {
    use crate::net::wifi::intel::nvm::{AddressSource, Request};
    for ax210 in [false, true] {
        let p = if ax210 { ax210_profile() } else { profile() };
        let bytes = if actual_image {
            let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
            let b = std::fs::read(std::path::Path::new(&root).join(p.family().firmware_name()))
                .unwrap();
            use sha2::{Digest, Sha256};
            assert_eq!(
                std::format!("{:x}", Sha256::digest(&b)),
                if ax210 {
                    "792478ef7752595525379a5068e2d47e310a2c344636b7df866c54746ced1dc0"
                } else {
                    "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
                }
            );
            b
        } else {
            unified_bytes(ax210)
        };
        let catalog = catalog_for(&p, p.family().firmware_name(), &bytes);
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
        let mut boot = command_ready(boot, &empty, &source, &domain, &state);
        {
            let mut s = state.lock().unwrap();
            *s.registers.get_mut(&0x24).unwrap() &= !0x08000000;
            s.registers.extend(if ax210 {
                [(0x388, 0x02123456), (0x38c, 0x789a)]
            } else {
                [(0x380, 0x02123456), (0x384, 0x789a)]
            });
        }
        assert!(matches!(
            // SAFETY: Source provides fresh exclusive model RAM and boot retains its exact
            // requester/domain; the modeled RF-kill state is observed before publication.
            unsafe { boot.submit_command(command_id(), &[], &source) },
            Err(Error::RfKilled)
        ));
        let mut init = boot.initialize_on_device_nvm();
        assert_eq!(
            // SAFETY: The initializer owns that same model epoch/domain and Source stays
            // exclusive while staging the first extended-configuration command.
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::ExtendedConfiguration)
        );
        let tfd = device_read(&domain, init.boot.command.region().address, 0, 256);
        let first = u64::from_le_bytes(tfd[4..12].try_into().unwrap());
        assert_eq!(
            device_read(&domain, first, 0, 12),
            [3, 2, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0]
        );
        assert_eq!(
            // SAFETY: No model completion has been published yet; its same retained DMA
            // allocations/source remain live while polling the pending command.
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::ExtendedConfiguration)
        );
        complete(
            &init.boot,
            &domain,
            1,
            2,
            &command_packet(Request::ExtendedConfiguration.id(), 0, &[]),
        );
        // Retry actual completed-range CPU visibility without replaying the
        // command or losing its exact initialization stage.
        {
            let mut r = domain.records.lock().unwrap();
            r.cpu_sync_fail = Some(r.cpu_syncs + 1);
        }
        assert!(matches!(
            // SAFETY: The ACK was completed synchronously and injected CPU-sync failure
            // keeps its mapped buffers retained by this initializer for retry.
            unsafe { init.advance(&source) },
            Err(Error::CommandReclaim(_))
        ));
        assert_eq!(init.phase(), InitializationPhase::ExtendedConfiguration);
        domain.records.lock().unwrap().cpu_sync_fail = None;
        assert_eq!(
            // SAFETY: The failed reclaim retained the same domain/source and mappings;
            // clearing the CPU-sync injection adds no device or concurrent writer.
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::AccessComplete)
        );
        complete(
            &init.boot,
            &domain,
            2,
            3,
            &command_packet(Request::AccessComplete.id(), 1, &[]),
        );
        assert_eq!(
            // SAFETY: The access-complete ACK was written synchronously to the retained
            // receive mapping; this owner/source remain live through reclamation.
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::InitNotification)
        );
        assert_eq!(
            // SAFETY: Waiting for notification preserves the same owned model mappings
            // and exclusive Source, with no asynchronous device or IRQ worker.
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::InitNotification)
        );
        assert_eq!(state.lock().unwrap().registers.get(&0x460), Some(&2));
        let wrong = crate::net::wifi::intel::command::Id {
            group: 1,
            opcode: 4,
            version: 0,
        };
        complete(
            &init.boot,
            &domain,
            3,
            4,
            &command_packet(wrong, 0x8000, &[0x55]),
        );
        assert_eq!(
            // SAFETY: The unrelated notification was published by the synchronous model;
            // the original initializer/domain retain every pending buffer and Source.
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::InitNotification)
        );
        let actual = crate::net::wifi::intel::command::Id {
            group: 0,
            opcode: 4,
            version: 0,
        };
        complete(
            &init.boot,
            &domain,
            4,
            5,
            &command_packet(actual, 0x8000, &[0x66]),
        );
        assert_eq!(
            // SAFETY: The matching notification was completed within that same model
            // domain; its ownership and exclusive Source remain unchanged.
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::NvmInformation)
        );
        let raw = nvm_response();
        complete(
            &init.boot,
            &domain,
            5,
            6,
            &command_packet(Request::GetInformation.id(), 2, &raw),
        );
        assert_eq!(
            // SAFETY: The NVM response now occupies a synchronously completed live buffer;
            // the initializer/domain keep it retained through parsing and reclaim.
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Observed
        );
        let r = init.receipt().unwrap();
        assert_eq!(r.information.raw, raw);
        assert_eq!(r.information.channel_count, 2);
        assert_eq!(r.information.channel_profiles[1], 0xabcdef);
        assert_eq!(r.address.bytes, [2, 0x12, 0x34, 0x56, 0x78, 0x9a]);
        assert_eq!(
            r.address.source,
            if ax210 {
                AddressSource::Strap
            } else {
                AddressSource::Otp
            }
        );
        assert_eq!(r.init_complete.raw, [0x66]);
        assert_eq!(
            r.product_reset,
            ax210.then_some(ProductResetObservation {
                sb_configuration: 0,
                coordination: ProductResetCoordination::NotPerformedNoIwlmei
            })
        );
        assert_eq!(
            // SAFETY: Observation retains the same original model owner and source;
            // reentering this finished state introduces no new mapping or device user.
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Observed
        );
        let (mut boot, _) = match init.into_parts() {
            Ok(parts) => parts,
            Err(_) => panic!("missing observation"),
        };
        assert_eq!(boot.take_firmware_notification().unwrap().raw, [0x55]);
        let ops = state.lock().unwrap().ops.clone();
        if ax210 {
            assert!(!ops.contains(&Op::Read(0x380)));
            assert!(!ops.contains(&Op::Read(0x384)));
        }
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
}
