// SPDX-License-Identifier: GPL-2.0-only
//! Media changes cases.
use super::*;

#[test]
fn late_target_change_discards_earlier_probe_and_revalidates_before_publication() {
    use crate::block::BlockDevice;
    use crate::usb::storage::media::{Owner, scan_uas};
    let mut memory = vec![0u64; 32 * 1024];
    let mut initial = Media::disk(Lun::default(), 1);
    initial.blocks = 1024;
    let (raw, state) = target_owner(
        &mut memory,
        Target::new(vec![initial]),
        quirks::Flags::default(),
    );
    let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
    let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
    let mut failures = Vec::new();
    let mut old = scan_uas(owner.clone(), &mut failures).unwrap();
    {
        let mut state = state.borrow_mut();
        let target = state.target.as_mut().unwrap();
        target.report_attention = 1;
        target.report_change_blocks = Some(4096);
    }
    let mut fresh = scan_uas(owner.clone(), &mut failures).unwrap();
    assert_eq!(
        fresh[0].identity().blocks,
        4096,
        "earlier capacity survived late target change"
    );
    fresh[0].read(3000, &mut [0; 512]).unwrap();
    let before = state.borrow().events.len();
    assert!(old[0].flush().is_err());
    assert_eq!(state.borrow().events.len(), before);
    // Every REPORT now changes the target: no provisional view is usable.
    state.borrow_mut().target.as_mut().unwrap().report_attention = usize::MAX;
    assert_eq!(
        scan_uas(owner, &mut failures).err(),
        Some(BlockError::Unsupported(
            "USB media changed repeatedly during rescan"
        ))
    );
    let before = state.borrow().events.len();
    assert!(fresh[0].flush().is_err());
    assert_eq!(state.borrow().events.len(), before);
}

#[test]
fn block_zero_target_change_restarts_earlier_lun_metadata_before_publication() {
    use crate::block::BlockDevice;
    use crate::usb::storage::media::{Owner, scan_uas};
    for streams in [None, Some(2)] {
        let mut memory = vec![0u64; 32 * 1024];
        let later = Lun::sequential(4);
        let (raw, state) = target_owner(
            &mut memory,
            Target::new(vec![Media::disk(Lun::default(), 1), Media::disk(later, 4)]),
            quirks::Flags::default(),
        );
        state.borrow_mut().streams = streams;
        let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
        let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
        let mut old = scan_uas(owner.clone(), &mut Vec::new()).unwrap();
        assert_eq!(old.len(), 2);
        state
            .borrow_mut()
            .target
            .as_mut()
            .unwrap()
            .block_zero_change = Some((later, 8192));
        let mut failures = Vec::new();
        let fresh = scan_uas(owner, &mut failures).unwrap();
        assert_eq!(fresh.len(), 2);
        assert_eq!(
            fresh[0].identity().blocks,
            8192,
            "earlier provisional geometry survived a later block-zero target-change UA"
        );
        assert!(failures.iter().any(|(_, error)| *error
            == BlockError::Sense(Sense {
                key: 6,
                asc: 0x3f,
                ascq: 0x0e,
            })));
        let before = state.borrow().events.len();
        assert!(old[0].read(0, &mut [0; 512]).is_err());
        assert!(old[1].flush().is_err());
        assert_eq!(state.borrow().events.len(), before);
    }
}

#[test]
fn first_lun_cache_change_restarts_geometry_and_protection_before_publication() {
    use crate::block::BlockDevice;
    use crate::usb::storage::media::{Owner, scan_uas};
    for streams in [None, Some(2)] {
        for sense in [0x062800, 0x063f0e] {
            let mut memory = vec![0u64; 32 * 1024];
            let mut initial = Media::disk(Lun::default(), 0x51);
            initial.blocks = 1024;
            initial.read_only = true;
            let mut target = Target::new(vec![initial]);
            target.cache_reply = Some(CacheReply::Replace {
                sense,
                blocks: 8192,
                read_only: false,
            });
            let (raw, state) = target_owner(&mut memory, target, quirks::Flags::default());
            state.borrow_mut().streams = streams;
            let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
            let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
            let mut failures = Vec::new();
            let mut fresh = scan_uas(owner, &mut failures).unwrap();
            assert_eq!(fresh.len(), 1);
            assert_eq!(
                fresh[0].identity().blocks,
                8192,
                "final cache query published earlier geometry"
            );
            assert!(
                !fresh[0].identity().read_only,
                "final cache query published earlier protection"
            );
            assert!(failures.iter().any(|(_, error)| *error
                == BlockError::Sense(Sense {
                    key: (sense >> 16) as u8,
                    asc: (sense >> 8) as u8,
                    ascq: sense as u8
                })));
            assert_eq!(
                state
                    .borrow()
                    .history
                    .iter()
                    .filter(|iu| iu[16] == 0x25)
                    .count(),
                2
            );
            fresh[0].write(7000, &[0x62; 512]).unwrap();
            fresh[0].flush().unwrap();
            assert_eq!(
                state.borrow().target.as_ref().unwrap().flushes,
                vec![Lun::default()],
                "write-back flush suppressed after cache change"
            );
        }
    }
}

#[test]
fn first_lun_final_cache_no_media_never_publishes_previous_metadata() {
    use crate::usb::storage::media::{Owner, scan_uas};
    for streams in [None, Some(2)] {
        for sense in [0x023a00, 0x063a00] {
            let mut memory = vec![0u64; 32 * 1024];
            let mut target = Target::new(vec![Media::disk(Lun::default(), 0x31)]);
            target.cache_reply = Some(CacheReply::Replace {
                sense,
                blocks: 8192,
                read_only: false,
            });
            let (raw, state) = target_owner(&mut memory, target, quirks::Flags::default());
            state.borrow_mut().streams = streams;
            let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
            let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
            let mut failures = Vec::new();
            assert!(scan_uas(owner.clone(), &mut failures).unwrap().is_empty());
            assert!(failures.iter().any(|(_, error)| *error
                == BlockError::Sense(Sense {
                    key: (sense >> 16) as u8,
                    asc: (sense >> 8) as u8,
                    ascq: sense as u8
                })));
            // The reader remains retained. A later actual insertion is
            // freshly probed and keeps the target's real cache policy.
            state.borrow_mut().target.as_mut().unwrap().media[0].empty = false;
            let mut fresh = scan_uas(owner, &mut failures).unwrap();
            assert_eq!(fresh.len(), 1);
            assert_eq!(fresh[0].identity.blocks, 8192);
            use crate::block::BlockDevice;
            fresh[0].flush().unwrap();
            assert_eq!(
                state.borrow().target.as_ref().unwrap().flushes,
                vec![Lun::default()]
            );
        }
    }
}
