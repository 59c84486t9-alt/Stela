use super::*;

#[test]
fn mld_peer_requires_both_cfg_and_tlc_ack_reclaim_before_identity_and_flush_remove_before_parent() {
    exercise(&mld_image(1));
}

#[test]
fn unsupported_mld_station_body_and_missing_rate_refuse_before_first_station_effect() {
    for version in [1, 3] {
        let bytes = mld_image(version);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let link = mld_bound(&catalog, &empty, &source, &native, &policy, false);
        if version == 1 {
            policy
                .deny_rate
                .store(LegacyRate::Ofdm54 as usize + 1, Ordering::SeqCst);
        }
        // SAFETY: private same-provider model; missing envelope is denied.
        let mut peer =
            unsafe { link.begin_mld_peer(parameters()) }.unwrap_or_else(|_| panic!("MLD peer"));
        let calls = source.calls.load(Ordering::Relaxed);
        let ops = native.state.lock().unwrap().ops.len();
        let causes = native
            .state
            .lock()
            .unwrap()
            .registers
            .get(&8)
            .copied()
            .unwrap_or(0);
        let syncs = native.domain.records.lock().unwrap().syncs;
        let result = unsafe { peer.advance(&source) };
        if version == 3 {
            assert_eq!(
                result,
                Err(Ax200LegacyPeerError::Version {
                    group: 3,
                    command: 0x0a,
                    version: 3
                })
            );
        } else {
            assert_eq!(
                result,
                Err(Ax200LegacyPeerError::Binding(
                    Ax200BindingError::Regulatory(regulatory::Error::OsDenied)
                ))
            );
        }
        assert!(peer.ticket().is_none());
        assert_eq!(source.calls.load(Ordering::Relaxed), calls);
        let state = native.state.lock().unwrap();
        let expected_rx = [
            Op::Read(8),
            Op::Write(8, causes | !(1 | (1 << 31))),
            Op::Read(0x24),
        ];
        assert_eq!(
            &state.ops[ops..],
            if version == 3 {
                &[][..]
            } else {
                &expected_rx[..]
            }
        );
        drop(state);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        peer.stop().unwrap();
    }
}

#[test]
fn mld_partial_cfg_tlc_flush_or_remove_missing_ack_retains_original_link_and_failed_stop_dma() {
    for target in [1, 2, 3, 4] {
        let bytes = mld_image(2);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let link = mld_bound(&catalog, &empty, &source, &native, &policy, true);
        // SAFETY: retained genuine provider and explicit bounded-rate model.
        let mut peer =
            unsafe { link.begin_mld_peer(parameters()) }.unwrap_or_else(|_| panic!("MLD peer"));
        unsafe { peer.advance(&source) }.unwrap();
        for index in 0..target {
            let command = peer.commands()[index].clone();
            complete_mld_peer(&peer, &native, &command);
            unsafe { peer.advance(&source) }.unwrap();
            peer.replenish_completed_receive().unwrap();
            if index == 2 {
                peer.begin_remove().unwrap();
                unsafe { peer.advance(&source) }.unwrap();
            }
        }
        let kind = peer.commands()[target].kind();
        Clock {
            ticks_per_microsecond: 1,
        }
        .delay(20);
        let error = Ax200LegacyPeerError::Deadline(kind);
        assert_eq!(unsafe { peer.advance(&source) }, Err(error.clone()));
        assert_eq!(peer.first_error(), Some(&error));
        peer = match peer.into_binding() {
            Err(owner) => *owner,
            Ok(_) => panic!("partial station released link"),
        };
        let ops = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        assert_eq!(unsafe { peer.advance(&source) }, Err(error.clone()));
        assert_eq!(peer.replenish_completed_receive(), Err(error));
        assert_eq!(native.state.lock().unwrap().ops.len(), ops);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        if target == 4 {
            native.state.lock().unwrap().fail = Some(ops + 1);
            assert!(peer.stop().is_err());
            let live = native.domain.records.lock().unwrap().live.len();
            drop(peer);
            assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
        } else {
            peer.stop().unwrap();
        }
    }
}

#[test]
#[ignore = "requires unchanged pinned AX200 firmware"]
fn actual_ax200_mld_station_default_v1_and_tlc4_require_selected_owner_ack_lifetime() {
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
    );
    let firmware = crate::net::wifi::intel::firmware::Firmware::parse(&bytes).unwrap();
    assert!(firmware.supports_capability(110));
    assert!(firmware.command_version(3, 0x0a).is_none());
    assert_eq!(
        firmware.command_version(5, 0x0f).unwrap().command_version,
        4
    );
    exercise(&bytes);
}
