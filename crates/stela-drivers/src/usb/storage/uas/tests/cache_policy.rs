// SPDX-License-Identifier: GPL-2.0-only
//! Cache policy cases.
use super::*;

#[test]
fn stable_cache_policy_and_explicit_unsupported_page_preserve_flush_semantics() {
    use crate::block::BlockDevice;
    use crate::usb::storage::media::{Owner, scan_uas};
    for (reply, write_back) in [
        (CacheReply::Data(vec![7, 0, 0, 0, 8, 0x12, 4, 0]), true),
        (CacheReply::Data(vec![7, 0, 0, 0, 8, 0x12, 0, 0]), false),
        (CacheReply::Data(vec![3, 0, 0, 0]), false),
        (CacheReply::Sense(0x052400), false),
    ] {
        let mut memory = vec![0u64; 32 * 1024];
        let mut target = Target::new(vec![Media::disk(Lun::default(), 0x11)]);
        target.cache_reply = Some(reply);
        let (raw, state) = target_owner(&mut memory, target, quirks::Flags::default());
        let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
        let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
        let mut failures = Vec::new();
        let mut disks = scan_uas(owner, &mut failures).unwrap();
        assert_eq!(disks.len(), 1);
        assert!(failures.is_empty());
        assert_eq!(disks[0].identity().features.write_cache, write_back);
        disks[0].write(1, &[0x91; 512]).unwrap();
        disks[0].flush().unwrap();
        assert_eq!(
            state.borrow().target.as_ref().unwrap().flushes.len(),
            usize::from(write_back)
        );
        assert_eq!(
            state
                .borrow()
                .history
                .iter()
                .filter(|iu| iu[16] == 0x25)
                .count(),
            1
        );
    }
    for (reply, error) in [
        (
            CacheReply::Sense(0x052000),
            BlockError::Sense(Sense {
                key: 5,
                asc: 0x20,
                ascq: 0,
            }),
        ),
        (
            CacheReply::Data(vec![0; 4]),
            BlockError::Protocol("malformed USB mode parameter header"),
        ),
    ] {
        let mut memory = vec![0u64; 32 * 1024];
        let mut target = Target::new(vec![Media::disk(Lun::default(), 0x11)]);
        target.cache_reply = Some(reply);
        let (raw, _) = target_owner(&mut memory, target, quirks::Flags::default());
        let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
        let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
        let mut failures = Vec::new();
        assert!(scan_uas(owner, &mut failures).unwrap().is_empty());
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].1, error);
    }
}

#[test]
fn report_lun_removal_and_rescan_poison_permanently_invalidate_real_uas_aliases() {
    use crate::block::BlockDevice;
    use crate::usb::storage::media::{Owner, scan_uas};
    let mut memory = vec![0u64; 32 * 1024];
    let sparse = Lun::from_bytes([0x40, 7, 0, 2, 0, 0, 0, 0]);
    let (raw, state) = target_owner(
        &mut memory,
        Target::new(vec![Media::disk(Lun::default(), 1), Media::disk(sparse, 7)]),
        quirks::Flags::default(),
    );
    let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
    let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
    let mut failures = Vec::new();
    let mut old = scan_uas(owner.clone(), &mut failures).unwrap();
    state
        .borrow_mut()
        .target
        .as_mut()
        .unwrap()
        .reported
        .retain(|lun| *lun != sparse);
    let mut current = scan_uas(owner.clone(), &mut failures).unwrap();
    assert_eq!(current.len(), 1);
    let before = state.borrow().events.len();
    assert!(old[1].read(0, &mut [0; 512]).is_err());
    assert_eq!(state.borrow().events.len(), before);
    old[0].read(0, &mut [0; 512]).unwrap();
    state
        .borrow_mut()
        .target
        .as_mut()
        .unwrap()
        .reported
        .push(sparse);
    let mut inserted = scan_uas(owner.clone(), &mut failures).unwrap();
    inserted[1].read(0, &mut [0; 512]).unwrap();
    assert!(old[1].flush().is_err());
    state.borrow_mut().target.as_mut().unwrap().unit_attention = Some(0x063f0e);
    assert_eq!(
        inserted[0].command(&[0; 6], Data::None),
        Err(BlockError::Sense(Sense {
            key: 0x06,
            asc: 0x3f,
            ascq: 0x0e
        }))
    );
    let before = state.borrow().events.len();
    assert!(inserted[1].read(0, &mut [0; 512]).is_err());
    assert_eq!(
        state.borrow().events.len(),
        before,
        "target LUN remapping allowed old disk I/O"
    );
    let mut restored = scan_uas(owner.clone(), &mut failures).unwrap();
    state.borrow_mut().target.as_mut().unwrap().poison_lun = Some(sparse);
    assert!(scan_uas(owner, &mut failures).is_err());
    let before = state.borrow().events.len();
    assert!(current[0].flush().is_err());
    assert!(restored[0].flush().is_err());
    assert!(restored[1].write(0, &[0; 512]).is_err());
    assert_eq!(state.borrow().events.len(), before);
}
