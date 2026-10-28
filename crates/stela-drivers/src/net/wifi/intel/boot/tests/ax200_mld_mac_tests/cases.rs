use super::*;

#[test]
fn mld_mac_preserves_command_order_identity_and_remove_lifetimes() {
    for (mac, link) in [(1, None), (2, Some(1)), (3, Some(8))] {
        exercise(&image(mac, link));
    }
}

#[test]
#[ignore = "requires unchanged pinned AX200 firmware"]
fn pinned_ax200_firmware_selects_mld_mac_and_inactive_link_commands() {
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
    );
    let fw = crate::net::wifi::intel::firmware::Firmware::parse(&bytes).unwrap();
    assert!(fw.supports_capability(110));
    assert_eq!(fw.command_version(3, 8).unwrap().command_version, 1);
    assert!(fw.command_version(3, 9).is_none());
    exercise(&bytes);
}

#[test]
fn unsupported_mld_versions_and_partial_publication_retain_owner() {
    for case in 0..3 {
        let bytes = image(
            if case == 0 { 4 } else { 1 },
            Some(if case == 1 { 9 } else { 1 }),
        );
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let (country, _, _) = country_ready(
            &catalog,
            &empty,
            &source,
            &native,
            Ax200SetupOptions::new(Clock {
                ticks_per_microsecond: 1_000_000,
            }),
        );
        let mut mac = country
            .begin_mld_mac_context()
            .unwrap_or_else(|_| panic!("MLD MAC"));
        let calls = source.calls.load(Ordering::Relaxed);
        let ops = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        if case < 2 {
            assert!(matches!(
                unsafe { mac.advance(&source) },
                Err(Ax200MacError::Version { .. })
            ));
            assert_eq!(source.calls.load(Ordering::Relaxed), calls);
            assert_eq!(native.state.lock().unwrap().ops.len(), ops);
            assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        } else {
            mac.replenish_completed_receive().unwrap();
            unsafe { mac.advance(&source) }.unwrap();
            for index in 0..2 {
                let command = mac.commands()[index].clone();
                complete_mld(&mac, &native, &command);
                if index == 1 {
                    let mut r = native.domain.records.lock().unwrap();
                    r.sync_fail = Some(r.syncs + 2);
                }
                let result = unsafe { mac.advance(&source) };
                if index == 0 {
                    result.unwrap();
                } else {
                    assert!(result.is_err());
                }
            }
            assert_eq!(mac.mac_id_and_color(), Some(0));
            assert!(mac.inactive_link_id().is_none());
        }
        let error = mac.first_error().unwrap().clone();
        let ops = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        assert_eq!(unsafe { mac.advance(&source) }, Err(error.clone()));
        assert_eq!(
            mac.replenish_completed_receive(),
            Err(match error {
                Ax200MacError::Boot(error) => error,
                _ => Error::State,
            })
        );
        assert_eq!(native.state.lock().unwrap().ops.len(), ops);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        if case == 2 {
            native.state.lock().unwrap().fail = Some(ops + 1);
            assert!(mac.stop().is_err());
            let live = native.domain.records.lock().unwrap().live.len();
            drop(mac);
            assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
        } else {
            mac.stop().unwrap();
        }
    }
}

#[test]
fn receive_rearm_failure_latches_error_and_quarantines_uncertain_dma() {
    let bytes = image(1, None);
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let (country, _, _) = country_ready(
        &catalog,
        &empty,
        &source,
        &native,
        Ax200SetupOptions::new(Clock {
            ticks_per_microsecond: 1_000_000,
        }),
    );
    let mut mac = country
        .begin_mld_mac_context()
        .unwrap_or_else(|_| panic!("MLD MAC"));
    let mut records = native.domain.records.lock().unwrap();
    records.sync_fail = Some(records.syncs + 1);
    drop(records);
    let error = mac.replenish_completed_receive().unwrap_err();
    assert_eq!(mac.first_error(), Some(&Ax200MacError::Boot(error.clone())));
    assert_eq!(mac.phase(), Ax200MacPhase::Failed);
    let operations = native.state.lock().unwrap().ops.len();
    let syncs = native.domain.records.lock().unwrap().syncs;
    assert_eq!(
        unsafe { mac.advance(&source) },
        Err(Ax200MacError::Boot(error.clone()))
    );
    assert_eq!(mac.replenish_completed_receive(), Err(error));
    assert_eq!(native.state.lock().unwrap().ops.len(), operations);
    assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
    native.state.lock().unwrap().fail = Some(operations + 1);
    assert!(mac.stop().is_err());
    let live = native.domain.records.lock().unwrap().live.len();
    drop(mac);
    assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
    assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
}
