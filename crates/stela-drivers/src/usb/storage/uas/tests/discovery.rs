// SPDX-License-Identifier: GPL-2.0-only
//! Discovery cases.
use super::*;

#[test]
fn reported_sparse_hierarchical_units_publish_real_blocks_and_keep_identity() {
    use crate::block::BlockDevice;
    let sparse = Lun::from_bytes([0x40, 7, 0, 2, 0, 0, 0, 0]);
    let mut empty = Media::disk(Lun::default(), 0);
    empty.empty = true;
    let mut protected = Media::disk(Lun::sequential(3), 0x33);
    protected.read_only = true;
    let mut big = Media::disk(sparse, 0x77);
    big.blocks = u64::from(u32::MAX) + 4096;
    let mut target = Target::new(vec![empty, protected, big]);
    target.report_attention = 2;
    let mut memory = vec![0u64; 32 * 1024];
    let (owner, state) = target_owner(&mut memory, target, quirks::Flags::default());
    let mut failures = Vec::new();
    let mut disks =
        crate::usb::storage::discover_uas_units(owner, "native", "serial", &mut failures).unwrap();
    assert_eq!(disks.len(), 2);
    assert_eq!(failures.len(), 1);
    assert_eq!(
        failures[0].1,
        BlockError::Sense(Sense {
            key: 0x02,
            asc: 0x3a,
            ascq: 0x00
        })
    );
    assert!(disks[0].identity().read_only);
    assert!(disks[0].write(0, &[0; 512]).is_err());
    assert_eq!(disks[1].identity().blocks, u64::from(u32::MAX) + 4096);
    assert!(disks[1].identity().location.ends_with("4007000200000000"));
    assert!(disks[1].identity().serial.ends_with(":lun4007000200000000"));
    let lba = u64::from(u32::MAX) + 1;
    let bytes = vec![0xab; MAX_TD + 512];
    disks[1].write(lba, &bytes).unwrap();
    disks[1].flush().unwrap();
    let mut actual = vec![0; bytes.len()];
    disks[1].read(lba, &mut actual).unwrap();
    assert_eq!(actual, bytes);
    let state = state.borrow();
    assert!(state.active.is_empty());
    let target = state.target.as_ref().unwrap();
    assert_eq!(target.writes.len(), 2);
    assert_eq!(target.flushes, vec![sparse]);
    assert!(target.writes.iter().all(|(lun, _, _)| *lun == sparse));
    assert_eq!(state.history.iter().filter(|iu| iu[16] == 0xa0).count(), 3);
}

#[test]
fn spc6_version_keeps_sparse_reported_units_beyond_first_absent_sequential_unit() {
    let mut zero = Media::disk(Lun::default(), 0x10);
    zero.version = 8;
    let sparse = Lun::sequential(7);
    let target = Target::new(vec![zero, Media::disk(sparse, 0x70)]);
    let mut memory = vec![0u64; 32 * 1024];
    let (owner, state) = target_owner(&mut memory, target, quirks::Flags::default());
    let mut failures = Vec::new();
    let disks =
        crate::usb::storage::discover_uas_units(owner, "native", "id", &mut failures).unwrap();
    assert_eq!(disks.len(), 2);
    assert_eq!(disks[1].lun, sparse);
    assert!(failures.is_empty());
    let state = state.borrow();
    assert!(state.history.iter().any(|iu| iu[16] == 0xa0));
    assert!(
        state
            .history
            .iter()
            .filter(|iu| iu[16] == 0x12)
            .all(|iu| iu[8..16] != Lun::sequential(1).bytes())
    );
    assert!(state.active.is_empty());
}

#[test]
fn actual_initial_zero_survives_omission_but_absent_zero_is_never_invented() {
    use crate::block::BlockDevice;
    for case in 0..5 {
        let zero = Lun::default();
        let sparse = Lun::sequential(7);
        let mut media = if case == 2 {
            Vec::new()
        } else {
            vec![Media::disk(zero, 0x10)]
        };
        if case != 0 {
            media.push(Media::disk(sparse, 0x70));
        }
        let mut target = Target::new(media);
        target.reported = if case == 0 {
            Vec::new()
        } else if case == 4 {
            vec![zero, sparse]
        } else {
            vec![sparse]
        };
        if case == 3 {
            target.poison_lun = Some(sparse);
        }
        let mut memory = vec![0u64; 32 * 1024];
        let (owner, state) = target_owner(&mut memory, target, quirks::Flags::default());
        let mut failures = Vec::new();
        let result =
            crate::usb::storage::discover_uas_units(owner.clone(), "native", "id", &mut failures);
        if case == 3 {
            assert!(result.is_err());
            assert!(owner.borrow().engine.poisoned);
        } else {
            let mut disks = result.unwrap();
            assert!(failures.is_empty());
            let expected = if matches!(case, 0 | 2) { 1 } else { 2 };
            assert_eq!(disks.len(), expected);
            assert_eq!(disks[0].lun, if case == 2 { sparse } else { zero });
            let mut bytes = [0; 512];
            disks[0].read(0, &mut bytes).unwrap();
            assert_eq!(bytes, [if case == 2 { 0x70 } else { 0x10 }; 512]);
        }
        let state = state.borrow();
        assert!(state.active.is_empty());
        assert_eq!(
            state
                .history
                .iter()
                .filter(|iu| iu[16] == 0x12 && iu[8..16] == zero.bytes())
                .count(),
            1
        );
        assert_eq!(
            state
                .history
                .iter()
                .filter(|iu| iu[16] == 0x25 && iu[8..16] == zero.bytes())
                .count(),
            usize::from(case != 2)
        );
    }
}

#[test]
fn source_no_report_fallback_scans_past_empty_slot_and_stops_at_actual_absence() {
    let mut empty = Media::disk(Lun::default(), 0);
    empty.empty = true;
    let target = Target::new(vec![empty, Media::disk(Lun::sequential(1), 0x11)]);
    let mut memory = vec![0u64; 32 * 1024];
    let flags = quirks::Flags::from_id(0x0bc2, 0x331a, 0);
    let (owner, state) = target_owner(&mut memory, target, flags);
    let mut failures = Vec::new();
    let disks =
        crate::usb::storage::discover_uas_units(owner, "card reader", "id", &mut failures).unwrap();
    assert_eq!(disks.len(), 1);
    assert_eq!(disks[0].lun, Lun::sequential(1));
    assert_eq!(failures.len(), 1);
    let state = state.borrow();
    assert!(state.history.iter().all(|iu| iu[16] != 0xa0));
    let inquiries: Vec<_> = state
        .history
        .iter()
        .filter(|iu| iu[16] == 0x12)
        .map(|iu| Lun::from_bytes(iu[8..16].try_into().unwrap()))
        .collect();
    assert_eq!(
        inquiries,
        vec![Lun::default(), Lun::sequential(1), Lun::sequential(2)]
    );
}

#[test]
fn reported_transfer_uncertainty_discards_previously_initialized_units() {
    let mut target = Target::new(vec![
        Media::disk(Lun::default(), 1),
        Media::disk(Lun::sequential(7), 7),
    ]);
    target.poison_lun = Some(Lun::sequential(7));
    let mut memory = vec![0u64; 32 * 1024];
    let (owner, state) = target_owner(&mut memory, target, quirks::Flags::default());
    let mut failures = Vec::new();
    assert!(
        crate::usb::storage::discover_uas_units(owner.clone(), "native", "id", &mut failures)
            .is_err()
    );
    assert!(owner.borrow().engine.poisoned);
    assert_eq!(failures.len(), 1);
    assert!(state.borrow().active.is_empty());
}

#[test]
fn report_list_grows_from_real_header_and_never_accepts_partial_or_duplicate_lists() {
    for case in 0..5 {
        let mut target = Target::new(vec![Media::disk(Lun::default(), 1)]);
        target.reported = (0..600).map(Lun::sequential).collect();
        match case {
            1 => target.report_override = Some(vec![0, 0, 0, 9, 0, 0, 0, 0]),
            2 => target.report_override = Some(vec![0, 1, 0, 0, 0, 0, 0, 0]),
            3 => target.report_override = Some(vec![0, 0, 0, 8, 0, 0, 0, 0]),
            4 => target.reported = vec![Lun::default(), Lun::default()],
            _ => {}
        }
        let mut memory = vec![0u64; 32 * 1024];
        let (owner, state) = target_owner(&mut memory, target, quirks::Flags::default());
        let result = crate::usb::storage::report_luns(&mut *owner.borrow_mut());
        if case == 0 {
            assert_eq!(result.unwrap().unwrap().len(), 600);
            assert_eq!(state.borrow().history.len(), 2);
        } else {
            assert!(result.is_err(), "case{case}");
        }
        assert!(state.borrow().active.is_empty());
        assert!(!owner.borrow().engine.poisoned);
    }
}

#[test]
fn illegal_report_falls_back_and_always_sync_uses_only_safe_mode_page() {
    use crate::block::BlockDevice;
    let mut target = Target::new(vec![Media::disk(Lun::default(), 0x11)]);
    target.report_illegal = true;
    let mut memory = vec![0u64; 32 * 1024];
    let flags = quirks::Flags::from_id(0x4971, 0x8024, 0);
    let (owner, state) = target_owner(&mut memory, target, flags);
    let mut failures = Vec::new();
    let mut disks =
        crate::usb::storage::discover_uas_units(owner, "native", "id", &mut failures).unwrap();
    assert_eq!(disks.len(), 1);
    assert!(failures.is_empty());
    disks[0].write(1, &[0x88; 512]).unwrap();
    assert!(state.borrow().target.as_ref().unwrap().flushes.is_empty());
    // ALWAYS_SYNC reads no mode page and flushes its assumed write cache.
    disks[0].flush().unwrap();
    let state = state.borrow();
    assert!(!state.history.iter().any(|iu| iu[16] == 0x1a));
    assert_eq!(state.target.as_ref().unwrap().flushes, vec![Lun::default()]);
    assert!(state.active.is_empty());
}
