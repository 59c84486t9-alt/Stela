use super::*;

#[test]
fn mld_unassign_reclaims_every_ack_before_releasing_phy_parent() {
    exercise(&image());
}

#[test]
fn mld_activation_refuses_unapproved_rate_or_power_before_publication() {
    for deny_rate in [false, true] {
        let bytes = image();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (power, _, _) = powered(&catalog, &empty, &source, &native, &policy, false);
        authorize(&policy);
        if deny_rate {
            policy
                .deny_rate
                .store(LegacyRate::Ofdm24 as usize + 1, Ordering::SeqCst);
        } else {
            policy.transmit_ceiling_mbm.store(1999, Ordering::SeqCst);
        }
        // SAFETY: authored same-device service explicitly denies this envelope.
        let mut link = unsafe { power.begin_mld_link() }.unwrap_or_else(|_| panic!("MLD link"));
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
        assert_eq!(
            // SAFETY: same-epoch model owners keep exclusive source RAM and
            // policy state while the explicit denial is tested before publication.
            unsafe { link.advance(&source) },
            Err(Ax200BindingError::Regulatory(regulatory::Error::OsDenied))
        );
        assert!(link.ticket().is_none());
        assert_eq!(source.calls.load(Ordering::Relaxed), calls);
        // The original idle RX check precedes admission: reading/acknowledging
        // interrupt causes is required, while no HCMD publication is allowed.
        assert_eq!(
            &native.state.lock().unwrap().ops[ops..],
            &[
                Op::Read(8),
                Op::Write(8, causes | !(1 | (1 << 31))),
                Op::Read(0x24)
            ]
        );
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        link.stop().unwrap();
    }
}

#[test]
fn missing_ack_keeps_phy_parent_and_latches_mld_failure() {
    for target in [0, 1, 3, 5, 6] {
        let bytes = image();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (power, _, _) = powered(&catalog, &empty, &source, &native, &policy, true);
        authorize(&policy);
        // SAFETY: same finite source response/revocation model.
        let mut link = unsafe { power.begin_mld_link() }.unwrap_or_else(|_| panic!("MLD link"));
        // SAFETY: Source supplies exclusive model RAM; Native keeps this
        // requester/domain and policy, with no asynchronous device access.
        unsafe { link.advance(&source) }.unwrap();
        for index in 0..target {
            let command = link.commands()[index].clone();
            complete_link(&link, &native, &command);
            // SAFETY: the synchronous model completed this exact command;
            // all pending mappings remain owned by the same link and domain.
            unsafe { link.advance(&source) }.unwrap();
            link.replenish_completed_receive().unwrap();
            if index == 2 {
                assert_eq!(link.phase(), Ax200BindingPhase::AuthenticationRequired);
                native.revoked.store(true, Ordering::SeqCst);
                link.begin_remove().unwrap();
                // SAFETY: revocation changes only the model policy;
                // ordered removal still owns the same source and DMA mappings.
                unsafe { link.advance(&source) }.unwrap();
            }
        }
        let kind = link.commands()[target].kind();
        Clock {
            ticks_per_microsecond: 1,
        }
        .delay(20);
        let error = Ax200BindingError::Deadline(kind);
        // SAFETY: only the model clock advanced; the timed-out link keeps
        // its original source/domain and unreclaimed DMA buffers.
        assert_eq!(unsafe { link.advance(&source) }, Err(error.clone()));
        assert_eq!(link.phase(), Ax200BindingPhase::Failed);
        assert_eq!(link.first_error(), Some(&error));
        link = match link.into_transmit_power() {
            Err(owner) => *owner,
            Ok(_) => panic!("incomplete source unassign released PHY parent"),
        };
        let ops = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        // SAFETY: the latched failure still owns those same live mappings;
        // no device or worker can access them during this repeated entry.
        assert_eq!(unsafe { link.advance(&source) }, Err(error.clone()));
        assert_eq!(link.replenish_completed_receive(), Err(error));
        assert_eq!(native.state.lock().unwrap().ops.len(), ops);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        if target == 6 {
            native.state.lock().unwrap().fail = Some(ops + 1);
            assert!(link.stop().is_err());
            let live = native.domain.records.lock().unwrap().live.len();
            drop(link);
            assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
        } else {
            link.stop().unwrap();
            drop(link);
            assert!(native.domain.records.lock().unwrap().live.is_empty());
        }
    }
}

#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn pinned_ax200_firmware_selects_mld_activation_and_unassign_commands() {
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
    );
    let fw = crate::wifi::intel::firmware::Firmware::parse(&bytes).unwrap();
    assert!(fw.supports_capability(110));
    assert!(fw.command_version(3, 9).is_none());
    exercise(&bytes);
}
