use super::*;
use alloc::vec;

fn inputs() -> Inputs {
    Inputs {
        budget: 64,
        reference: 64,
        hardware_scale: 0,
        hardware_multiplier: 0,
        feature_word: 0,
        slot_flags: [0; GROUPS],
        quota_words: [64; GROUPS],
    }
}
fn row(group: u32, tier: u32, class: u32) -> [u32; WORDS] {
    [77, 9, tier, group, 7, 13, class, 8192, 0, 0xfeed, 0]
}
fn encoded(rows: &[[u32; WORDS]]) -> Vec<u8> {
    rows.iter()
        .flat_map(|row| row.iter().flat_map(|word| word.to_le_bytes()))
        .collect()
}
fn policy(rows: &[[u32; WORDS]]) -> Policy {
    Policy::new(&encoded(rows), inputs()).unwrap()
}
// These tests consume pure dirty work only to exercise bookkeeping; no
// hardware/PTD implementation or real completion is inferred from this.
fn clear_work(policy: &mut Policy) {
    for group in 0..GROUPS as u8 {
        if let Some(update) = policy.hardware_update(group).unwrap() {
            policy.complete_hardware(update).unwrap();
        }
    }
    for block in 0..RESPONSE_BLOCKS as u8 {
        if let Some(response) = policy.response_block(block).unwrap() {
            policy.complete_response(response).unwrap();
        }
    }
}

#[test]
fn startup_clears_requests_without_fabricating_new_input_lanes() {
    let mut p = policy(&[row(0, 1, 3), row(1, 2, 1)]);
    p.set_request(0, 0x2014).unwrap();
    p.allocate().unwrap();
    clear_work(&mut p);
    assert_eq!(p.group(0).unwrap().assigned, 20);
    p.start_defaults().unwrap();
    assert_eq!(p.group(0).unwrap().requested, 0);
    assert_eq!(p.group(0).unwrap().hardware_target, 64);
    assert_eq!(p.request_lane(0).unwrap(), Some(0x2014));
    assert_eq!(p.group(1).unwrap().assigned, 64);
    assert_eq!(
        p.dirty_masks(),
        DirtyMasks {
            hardware: 3,
            responses: 3
        }
    );
    p.allocate().unwrap();
    assert_eq!(p.group(0).unwrap().assigned, 0);
    assert_eq!(p.group(1).unwrap().assigned, 64);
    p.set_request(0, 20).unwrap();
    p.revision = u64::MAX;
    assert!(p.start_defaults().is_err());
    assert_eq!(p.group(0).unwrap().requested, 20);
}
#[test]
fn raw_rows_duplicates_sentinel_and_opaque_words_remain_exact() {
    let first = row(3, 7, 2);
    let mut duplicate = row(3, 99, 1);
    duplicate[8] = 123;
    duplicate[10] = 0xabcd;
    let sentinel = row(NO_GROUP, u32::MAX, 3);
    let rows = [first, duplicate, sentinel];
    let p = policy(&rows);
    assert_eq!(p.rows().len(), rows.len());
    for (retained, original) in p.rows().iter().zip(rows) {
        assert_eq!(retained.source_words(), &original);
    }
    assert_eq!(p.rows()[1].seeded_limit(), 64);
    assert_eq!(p.rows()[1].seeded_assigned(), 64);
    assert_eq!(p.rows()[2].group(), None);
    assert_eq!(p.rows()[2].seeded_limit(), 8192);
    assert_eq!(p.active_groups(), 1 << 3);
    assert_eq!(p.group(3).unwrap().row, 0);
    assert_eq!(p.group(3).unwrap().assigned, 0);
    assert_eq!(p.dirty_masks().hardware, 1 << 3);
    assert_eq!(p.dirty_masks().responses, 1 << 3);
}

#[test]
fn actual_full_word_seeds_replace_raw_limits_and_only_class1_assigned() {
    let mut rows = [row(0, 1, 1), row(1, 1, 2), row(2, 1, 3)];
    rows[0][8] = 1024;
    rows[1][8] = 12345;
    rows[2][8] = 23;
    let mut source = inputs();
    source.quota_words = [0xc0ab_0180; GROUPS];
    let p = Policy::new(&encoded(&rows), source).unwrap();
    assert_eq!(p.inputs().quota_words[0], 0xc0ab_0180);
    for retained in p.rows() {
        assert_eq!(retained.seeded_limit(), 384);
        assert_eq!(retained.source_words()[7], 8192);
    }
    assert_eq!(p.group(0).unwrap().assigned, 384);
    assert_eq!(p.group(1).unwrap().assigned, 12345);
    assert_eq!(p.group(2).unwrap().assigned, 23);
    assert_eq!(p.group(0).unwrap().hardware_target, 384);
    assert_eq!(p.hardware_update(0).unwrap().unwrap().scaled_units(), 384);
    // Publication masks12 bits independently of either hardware width.
    assert_eq!(
        p.response_block(0).unwrap().unwrap().packed(),
        384 | ((12345u64 & 0xfff) << 16) | (23 << 32)
    );
}

#[test]
fn full_allocator_overlaps_same_tier_and_reduces_only_lower_tiers() {
    let rows = [row(3, 3, 1), row(0, 1, 2), row(1, 1, 3), row(2, 2, 3)];
    let mut p = policy(&rows);
    clear_work(&mut p);
    assert!(p.set_request(0, 40).unwrap());
    assert!(p.set_request(1, 40).unwrap());
    assert!(p.set_request(2, 32).unwrap());
    assert!(!p.set_request(3, 0x2001).unwrap());
    p.allocate().unwrap();
    assert_eq!(p.group(0).unwrap().assigned, 40);
    assert_eq!(p.group(1).unwrap().assigned, 40);
    assert_eq!(p.group(2).unwrap().assigned, 0);
    assert_eq!(p.group(3).unwrap().assigned, 64);
    assert_eq!(p.group(0).unwrap().hardware_target, 64);
    assert_eq!(p.group(1).unwrap().hardware_target, 40);
    assert_eq!(p.group(2).unwrap().hardware_target, 0);
    assert_eq!(p.group(3).unwrap().hardware_target, 64);
    assert_eq!(
        p.dirty_masks(),
        DirtyMasks {
            hardware: 6,
            responses: 15
        }
    );
}

#[test]
fn dynamic_minimum_uses_remaining_ceiling_and_requested_independently() {
    let mut source = inputs();
    source.quota_words[1] = 9;
    let mut p = Policy::new(
        &encoded(&[row(0, 1, 2), row(1, 2, 3), row(2, 3, 3)]),
        source,
    )
    .unwrap();
    p.set_request(0, 50).unwrap();
    p.set_request(1, 20).unwrap();
    p.set_request(2, 20).unwrap();
    p.allocate().unwrap();
    assert_eq!(p.group(0).unwrap().assigned, 50);
    assert_eq!(p.group(1).unwrap().assigned, 9);
    assert_eq!(p.group(2).unwrap().assigned, 5);
}

#[test]
fn class1_nonzero_policy_is_retained_when_dynamic_budget_is_zero() {
    let mut p = policy(&[row(0, 1, 2), row(1, 3, 1)]);
    p.set_request(0, 64).unwrap();
    p.set_budget_payload(0);
    p.defaults().unwrap();
    p.allocate().unwrap();
    assert_eq!(p.group(0).unwrap().assigned, 0);
    assert_eq!(p.group(0).unwrap().hardware_target, 64);
    assert_eq!(p.group(1).unwrap().assigned, 64);
    assert_eq!(p.group(1).unwrap().hardware_target, 64);
}

#[test]
fn lane_flags_zero_two_and_upper_bits_do_not_select_policy_class() {
    let mut p = policy(&[row(0, 1, 2), row(1, 1, 1)]);
    assert!(p.set_request(0, 17).unwrap());
    p.allocate().unwrap();
    let first = *p.group(0).unwrap();
    clear_work(&mut p);
    assert!(p.set_request(0, 0x2011).unwrap());
    assert_eq!(p.request_lane(0).unwrap(), Some(0x2011));
    p.allocate().unwrap();
    assert_eq!(p.group(0).unwrap(), &first);
    assert_ne!(p.dirty_masks().responses, 0);
    // Even identical eligible input requires source allocation/publication.
    clear_work(&mut p);
    assert!(p.set_request(0, 0x2011).unwrap());
    p.allocate().unwrap();
    assert_ne!(p.dirty_masks().responses, 0);
    assert!(p.set_request(0, 0xffff).unwrap());
    assert_eq!(p.group(0).unwrap().requested, 4095);
    assert_eq!(p.request_lane(0).unwrap(), Some(0xffff));
    assert!(!p.set_request(1, 0x2007).unwrap());
    assert_eq!(p.request_lane(1).unwrap(), Some(0x2007));
    assert_eq!(p.group(1).unwrap().requested, 0);
    assert!(!p.set_request(31, 0x2009).unwrap());
    assert_eq!(p.request_lane(31).unwrap(), Some(0x2009));
    assert!(p.group(31).is_none());
}

#[test]
fn source_feature_guard_retains_only_when_word_and_slot_bit1_are_set() {
    for (feature, flags, retained) in [
        (0, 2, false),
        (1, 0, false),
        (1, 1, false),
        (7, 0x102, true),
    ] {
        let mut source = inputs();
        source.feature_word = feature;
        source.slot_flags[0] = flags;
        let mut r = row(0, 1, 2);
        r[8] = 41;
        let mut p = Policy::new(&encoded(&[r, row(1, 2, 3)]), source).unwrap();
        clear_work(&mut p);
        p.set_request(0, 17).unwrap();
        p.set_request(1, 64).unwrap();
        p.allocate().unwrap();
        assert_eq!(p.group(0).unwrap().assigned, if retained { 41 } else { 17 });
        assert_eq!(p.group(0).unwrap().hardware_target, 64);
        // Groups never consume the lower tier's budget.
        assert_eq!(p.group(1).unwrap().assigned, if retained { 64 } else { 47 });
        assert_eq!(p.group(0).unwrap().slot_flags, flags);
    }
}

#[test]
fn op1_floor_low32_and_defaults_intermediate_are_separate_phases() {
    let mut r = row(0, 1, 3);
    r[8] = 11;
    r[10] = 1;
    let mut p = policy(&[r]);
    p.set_request(0, 9).unwrap();
    p.allocate().unwrap();
    assert_eq!(p.group(0).unwrap().assigned, 9);
    clear_work(&mut p);
    p.set_budget_payload(0xfeed_beef_0041_ffff);
    assert_eq!(p.inputs().budget, 32);
    assert_eq!(p.inputs().reference, 64);
    assert_eq!(p.group(0).unwrap().assigned, 9);
    assert_eq!(
        p.dirty_masks(),
        DirtyMasks {
            hardware: 0,
            responses: 0
        }
    );
    p.defaults().unwrap();
    assert_eq!(p.group(0).unwrap().ceiling, 32);
    assert_eq!(p.group(0).unwrap().requested, 9);
    assert_eq!(p.group(0).unwrap().assigned, 11);
    assert_eq!(p.group(0).unwrap().hardware_target, 32);
    let response = p.response_block(0).unwrap().unwrap();
    assert_eq!(response.packed(), 11);
    p.complete_response(response).unwrap();
    p.allocate().unwrap();
    assert_eq!(p.group(0).unwrap().assigned, 9);
    assert_eq!(p.group(0).unwrap().hardware_target, 9);
    assert_eq!(p.response_block(0).unwrap().unwrap().packed(), 9);
    p.set_budget_payload(0x1234_5678_0001_ffff);
    assert_eq!(p.inputs().budget, 0);
}

#[test]
fn defaults_and_hardware_scaling_preserve_w32_wrap_and_udiv_zero() {
    let mut r = row(0, 1, 3);
    r[10] = 1;
    let mut source = inputs();
    source.quota_words[0] = u32::MAX;
    source.hardware_scale = 1;
    source.hardware_multiplier = u32::MAX;
    source.budget = 2;
    source.reference = 3;
    let p = Policy::new(&encoded(&[r]), source).unwrap();
    assert_eq!(p.rows()[0].seeded_limit(), u32::MAX - 510);
    assert_eq!(p.group(0).unwrap().ceiling, 1_431_655_424);
    assert_eq!(p.hardware_update(0).unwrap().unwrap().scaled_units(), 0);
    // ceil arithmetic wraps before UDIV, rather than using a wider host add.
    assert_eq!(source.hardware_units(u32::MAX), 0);
    source.reference = 0;
    let p = Policy::new(&encoded(&[r]), source).unwrap();
    assert_eq!(p.group(0).unwrap().ceiling, 0);
    source.hardware_multiplier = 0;
    assert_eq!(source.hardware_units(17), 0);
    assert_eq!(udiv(123, 0), 0);
}

#[test]
fn raw_scaling_byte_uses_nonzero_seed_but_exactly_one_write_condition() {
    let mut source = inputs();
    source.hardware_scale = 2;
    source.hardware_multiplier = 1000;
    source.quota_words[0] = 511;
    let p = Policy::new(&encoded(&[row(0, 1, 2)]), source).unwrap();
    let update = p.hardware_update(0).unwrap().unwrap();
    assert_eq!(p.rows()[0].seeded_limit(), 511_000);
    assert_eq!(update.target(), 511_000);
    assert_eq!(update.scaled_units(), 511_000);
    assert_ne!(update.scaled_units(), update.scaled_units() & QUOTA_MASK);
}

#[test]
fn completed_hardware_and_response_clear_only_their_own_pending_work() {
    let mut p = policy(&[row(0, 1, 3), row(1, 1, 3), row(31, 2, 1)]);
    let response = p.response_block(0).unwrap().unwrap();
    assert_eq!(response.block(), 0);
    assert_eq!(response.dirty_mask(), 3);
    let other = p.response_block(7).unwrap().unwrap();
    assert_eq!(other.packed(), 64 << 48);
    p.complete_response(response).unwrap();
    assert_eq!(
        p.dirty_masks(),
        DirtyMasks {
            hardware: 0x8000_0003,
            responses: 0x8000_0000
        }
    );
    let update = p.hardware_update(0).unwrap().unwrap();
    assert_eq!(update.group(), 0);
    p.complete_hardware(update).unwrap();
    assert_eq!(p.dirty_masks().hardware, 0x8000_0002);
    p.complete_response(other).unwrap();
    assert!(p.response_block(0).unwrap().is_none());
    assert!(p.response_block(7).unwrap().is_none());
    assert!(p.hardware_update(0).unwrap().is_none());
    assert!(p.hardware_update(1).unwrap().is_some());
    assert!(p.hardware_update(31).unwrap().is_some());
}

#[test]
fn stale_foreign_and_replayed_clears_refuse_without_changing_masks() {
    let mut a = policy(&[row(0, 1, 3)]);
    let mut b = policy(&[row(0, 1, 3)]);
    let before = b.dirty_masks();
    assert!(
        b.complete_hardware(a.hardware_update(0).unwrap().unwrap())
            .is_err()
    );
    assert!(
        b.complete_response(a.response_block(0).unwrap().unwrap())
            .is_err()
    );
    assert_eq!(b.dirty_masks(), before);
    let stale_hw = a.hardware_update(0).unwrap().unwrap();
    let stale_rsp = a.response_block(0).unwrap().unwrap();
    a.defaults().unwrap(); // Same values and dirty mask; new phase/revision.
    let before = a.dirty_masks();
    assert!(a.complete_hardware(stale_hw).is_err());
    assert!(a.complete_response(stale_rsp).is_err());
    assert_eq!(a.dirty_masks(), before);
    let hw1 = a.hardware_update(0).unwrap().unwrap();
    let hw2 = a.hardware_update(0).unwrap().unwrap();
    let rsp1 = a.response_block(0).unwrap().unwrap();
    let rsp2 = a.response_block(0).unwrap().unwrap();
    a.complete_hardware(hw1).unwrap();
    a.complete_response(rsp1).unwrap();
    assert!(a.complete_hardware(hw2).is_err());
    assert!(a.complete_response(rsp2).is_err());
    assert_eq!(
        a.dirty_masks(),
        DirtyMasks {
            hardware: 0,
            responses: 0
        }
    );
}

#[test]
fn same_block_reallocation_invalidates_response_but_not_unchanged_hardware() {
    let mut p = policy(&[row(0, 1, 2), row(3, 1, 3)]);
    let hw = p.hardware_update(0).unwrap().unwrap();
    let response = p.response_block(0).unwrap().unwrap();
    p.set_request(3, 17).unwrap();
    p.allocate().unwrap();
    let before = p.dirty_masks();
    assert!(p.complete_response(response).is_err());
    assert_eq!(p.dirty_masks(), before);
    p.complete_hardware(hw).unwrap();
    assert_eq!(p.dirty_masks().hardware, 1 << 3);
}

#[test]
fn malformed_tables_and_invalid_operations_are_atomic() {
    for group in [32, 0x10000, u32::MAX] {
        assert!(Policy::new(&encoded(&[row(group, 1, 2)]), inputs()).is_err());
    }
    for class in [0, 4, u32::MAX] {
        assert!(Policy::new(&encoded(&[row(0, 1, class)]), inputs()).is_err());
        assert!(Policy::new(&encoded(&[row(NO_GROUP, 1, class)]), inputs()).is_err());
    }
    for bytes in [vec![0; 1], vec![0; ROW_BYTES - 1], vec![0; ROW_BYTES + 1]] {
        assert!(Policy::new(&bytes, inputs()).is_err());
    }
    let mut p = policy(&[row(0, 1, 2)]);
    let before = (*p.group(0).unwrap(), p.dirty_masks(), p.inputs);
    assert!(p.set_request(32, 17).is_err());
    assert!(p.request_lane(32).is_err());
    assert!(p.hardware_update(32).is_err());
    assert!(p.response_block(8).is_err());
    assert_eq!((*p.group(0).unwrap(), p.dirty_masks(), p.inputs), before);
    p.revision = u64::MAX;
    assert!(p.defaults().is_err());
    assert!(p.allocate().is_err());
    assert_eq!((*p.group(0).unwrap(), p.dirty_masks(), p.inputs), before);
}

#[test]
fn empty_source_table_has_no_synthesized_active_group_or_dirty_work() {
    let mut p = Policy::new(&[], inputs()).unwrap();
    p.allocate().unwrap();
    p.set_budget_payload(u64::MAX);
    p.defaults().unwrap();
    assert_eq!(p.active_groups(), 0);
    assert_eq!(
        p.dirty_masks(),
        DirtyMasks {
            hardware: 0,
            responses: 0
        }
    );
    assert!(p.rows().is_empty());
    for group in 0..GROUPS as u8 {
        assert!(p.group(group).is_none());
        assert!(p.hardware_update(group).unwrap().is_none());
    }
}

#[test]
#[cfg(feature = "std")]
#[ignore = "oracle: STELA_TEST_MCC_J473_DT, STELA_TEST_PMP_T8112"]
fn original_t8112_cache_rows_seeds_defaults_and_allocator_match_source_windows() {
    use sha2::{Digest, Sha256};
    use stela_contracts::adt::Node;
    let pmp = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&pmp)),
        "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
    );
    for (start, end, expected) in [
        (
            0x426c,
            0x472c,
            "e4971d2db1643fd5fa9412d278d2dbb1ea177f902bba9ec22d4dc41c0fd62a7b",
        ),
        (
            0x47a4,
            0x4cbc,
            "c65d5dc752b1592321cc44d79ed14fe0eb386cedb02d33772cfaa98bb0dd0966",
        ),
        (
            0x4cbc,
            0x4ee8,
            "9d7f54726ce6b42b4f802022a6f3fb0902a2a53cb1f57bdfb028513d67d99ad7",
        ),
        (
            0x4ee8,
            0x50b0,
            "d4a3edc6cb531a9edfc4f9882e79b380cf99198abc49634bce3019240d6ea873",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&pmp[start..end])), expected);
    }
    let dt = std::fs::read(std::env::var("STELA_TEST_MCC_J473_DT").unwrap()).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&dt)),
        "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
    );
    let root = Node::root(&dt).unwrap();
    let raw = root
        .child("arm-io")
        .unwrap()
        .child("pmp")
        .unwrap()
        .child("iop-pmp-nub")
        .unwrap()
        .property("mcache-stream")
        .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(raw)),
        "1daa6222994ef3c8b22c87d2f4a3c3b2f224ec486093c42f8953a1544f1b8cab"
    );
    let word = |offset| u32::from_le_bytes(pmp[offset..offset + 4].try_into().unwrap());
    let mut source = inputs();
    source.budget = word(0x46f88);
    source.reference = word(0x46f88);
    source.hardware_scale = pmp[0x46f90];
    source.hardware_multiplier = word(0x46f94);
    source.feature_word = word(0x352b0);
    assert_eq!(
        (
            source.budget,
            source.reference,
            source.hardware_scale,
            source.hardware_multiplier,
            source.feature_word
        ),
        (64, 64, 0, 0, 0)
    );
    // Authored owner input, not an original reset claim.
    source.quota_words = core::array::from_fn(|group| 0x400a_0100 + group as u32);
    let mut p = Policy::new(raw, source).unwrap();
    assert_eq!(p.rows().len(), 22);
    assert_eq!(p.active_groups().count_ones(), 16);
    assert_eq!(p.rows()[0].source_words()[7], 8192);
    assert_eq!(p.rows()[0].seeded_limit(), 266);
    assert_eq!(p.group(13).unwrap().row, 7);
    assert_eq!(p.group(14).unwrap().row, 11);
    assert_eq!(p.group(8).unwrap().row, 16);
    assert_eq!(p.group(1).unwrap().row, 19);
    let reencoded: Vec<u8> = p
        .rows()
        .iter()
        .flat_map(|row| {
            row.source_words()
                .iter()
                .flat_map(|word| word.to_le_bytes())
        })
        .collect();
    assert_eq!(reencoded, raw);
    for group in 0..GROUPS as u8 {
        let eligible = p
            .group(group)
            .is_some_and(|slot| p.rows()[slot.row].class() != Class::Class1);
        assert_eq!(p.set_request(group, 0x2020).unwrap(), eligible);
    }
    clear_work(&mut p);
    p.allocate().unwrap();
    for group in [10, 4, 18, 2, 3, 11, 17, 13, 5, 7, 14] {
        assert_eq!(p.group(group).unwrap().assigned, 32);
        assert_eq!(
            p.group(group).unwrap().hardware_target,
            256 + u32::from(group)
        );
    }
    for group in [16, 15, 19] {
        assert_eq!(p.group(group).unwrap().assigned, 0);
        assert_eq!(p.group(group).unwrap().hardware_target, 0);
    }
    for group in [8, 1] {
        assert_eq!(p.group(group).unwrap().assigned, 256 + u32::from(group));
    }
}
