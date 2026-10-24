// SPDX-License-Identifier: GPL-2.0-or-later
//! Authored selector controls against the unchanged complete descriptor reader.
use super::*;
use crate::usb::hid::descriptor::{DecodeError, Descriptor, Value};
use alloc::vec;

const KEY: u32 = 0x0007_0000;
fn descriptor(usages: &[u32], minimum: i32, maximum: i64, size: u8, count: u16) -> Vec<u8> {
    let mut bytes = vec![5, 1, 9, 6, 0xa1, 1, 0x17];
    bytes.extend_from_slice(&minimum.to_le_bytes());
    bytes.push(0x27);
    bytes.extend_from_slice(&(maximum as u32).to_le_bytes());
    bytes.extend_from_slice(&[0x75, size, 0x96, count as u8, (count >> 8) as u8]);
    for usage in usages {
        bytes.push(0x0b);
        bytes.extend_from_slice(&usage.to_le_bytes());
    }
    bytes.extend_from_slice(&[0x81, 0, 0xc0]);
    bytes
}
fn agree(bytes: &[u8], body: &[u8]) -> Option<Vec<u32>> {
    let keys = parse(bytes).unwrap().keys.unwrap();
    let result = keys.pressed(body);
    let complete = Descriptor::parse(bytes).unwrap().decode(body);
    match complete {
        Err(DecodeError::KeyboardError(_)) => assert_eq!(result, None),
        Ok(frame) => {
            let mut expected = Vec::new();
            for sample in frame.samples {
                if let (Some(usage), Value::Scalar(_)) = (sample.usage, sample.value)
                    && usage >> 16 == KEYBOARD_PAGE
                    && usage & 0xffff != 0
                    && !expected.contains(&(usage & 0xffff))
                {
                    expected.push(usage & 0xffff);
                }
            }
            assert_eq!(result, Some(expected));
        }
        Err(error) => panic!("unexpected complete decode: {error:?}"),
    }
    result
}

#[test]
fn official_appendix_f_null_prefix_is_an_element_before_the_keypad_range() {
    // USB-IF HID1.11 Appendix F, printed76–77: [null, 0x53..0x63].
    let bytes = [
        5, 1, 9, 6, 0xa1, 1, 5, 7, 9, 0, 0x19, 0x53, 0x29, 0x63, 0x15, 0, 0x25, 17, 0x75, 8, 0x95,
        3, 0x81, 0, 0xc0,
    ];
    assert_eq!(agree(&bytes, &[0, 0, 0]), Some(vec![]));
    assert_eq!(agree(&bytes, &[11, 0, 0]), Some(vec![0x5d]));
    assert_eq!(agree(&bytes, &[1, 17, 18]), Some(vec![0x53, 0x63]));
    let keys = parse(&bytes).unwrap().keys.unwrap();
    assert_eq!(keys.arrays[0].1.usages[0], KEY);
    assert_eq!(keys.arrays[0].1.usages[1], KEY | 0x53);
}

#[test]
fn sparse_reordered_duplicate_and_mixed_page_slots_keep_their_exact_indices() {
    let usages = [
        KEY | 5,
        KEY | 4,
        KEY | 5,
        KEY,
        0x000c_0001,
        KEY | 2,
        KEY | 0xe1,
    ];
    let bytes = descriptor(&usages, 10, 16, 8, 3);
    assert_eq!(agree(&bytes, &[10, 11, 12]), Some(vec![5, 4]));
    assert_eq!(agree(&bytes, &[13, 14, 16]), Some(vec![0xe1]));
    assert_eq!(
        agree(&bytes, &[4, 14, 13]),
        Some(vec![]),
        "raw selector4 is not a mapped keyboard error"
    );
    assert_eq!(
        agree(&bytes, &[10, 15, 16]),
        None,
        "mapped keyboard POSTFail rejects the state"
    );
    let mixed = descriptor(&[0x000c_0001, KEY | 4, 0x000c_0003], 0, 2, 8, 1);
    assert!(
        parse(&mixed).unwrap().keys.is_some(),
        "keyboard membership is not endpoint-only"
    );
    assert_eq!(agree(&mixed, &[0]), Some(vec![]));
    assert_eq!(agree(&mixed, &[1]), Some(vec![4]));
    assert_eq!(agree(&mixed, &[2]), Some(vec![]));
}

#[test]
fn short_tables_never_repeat_last_usage_and_null_or_out_of_range_selects_nothing() {
    let mut bytes = descriptor(&[KEY | 4, KEY | 7], 0, 7, 8, 4);
    assert_eq!(agree(&bytes, &[0, 1, 2, 7]), Some(vec![4, 7]));
    assert_eq!(agree(&bytes, &[8, 255, 2, 7]), Some(vec![]));
    let input = bytes.windows(2).position(|w| w == [0x81, 0]).unwrap();
    bytes[input + 1] = 0x40;
    assert_eq!(agree(&bytes, &[8, 255, 2, 7]), Some(vec![]));
    let decoded = Descriptor::parse(&bytes)
        .unwrap()
        .decode(&[8, 255, 2, 7])
        .unwrap();
    assert!(decoded.samples[0].null && decoded.samples[1].null);
    assert!(!decoded.samples[2].null && decoded.samples[2].usage.is_none());
    assert_eq!(
        parse(&bytes).unwrap().keys.unwrap().pressed(&[0]),
        None,
        "short body never publishes a prefix"
    );
}

#[test]
fn signed_minima_and_full_unsigned32_selectors_use_private_wide_bounds() {
    let bytes = descriptor(&[KEY | 4, KEY | 5, KEY], -2, 0, 8, 3);
    assert_eq!(agree(&bytes, &[0xfe, 0xff, 0]), Some(vec![4, 5]));
    let signed = descriptor(
        &[KEY | 4, KEY | 5],
        i32::MIN,
        i64::from(i32::MIN) + 1,
        32,
        2,
    );
    let mut body = i32::MIN.to_le_bytes().to_vec();
    body.extend_from_slice(&(i32::MIN + 1).to_le_bytes());
    assert_eq!(agree(&signed, &body), Some(vec![4, 5]));
    let wide = descriptor(
        &[KEY | 4, KEY | 5, KEY | 6],
        i32::MAX - 1,
        i64::from(u32::MAX),
        32,
        2,
    );
    let mut body = 0x8000_0000u32.to_le_bytes().to_vec();
    body.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(agree(&wide, &body), Some(vec![6]));
    let keys = parse(&wide).unwrap().keys.unwrap();
    assert_eq!(keys.arrays[0].1.maximum, i64::from(u32::MAX));
    assert_eq!(keys.arrays[0].1.minimum, i64::from(i32::MAX) - 1);
}

#[test]
fn push_pop_restores_private_wide_bounds_and_each_main_owns_a_distinct_table() {
    let mut bytes = descriptor(
        &[KEY | 4, KEY | 5, KEY | 6],
        i32::MAX - 1,
        i64::from(u32::MAX),
        32,
        1,
    );
    bytes.pop();
    bytes.extend_from_slice(&[
        0xa4, 0x15, 0xfe, 0x25, 0, 0x75, 8, 0x0b, 8, 0, 7, 0, 0x0b, 9, 0, 7, 0, 0x0b, 0, 0, 7, 0,
        0x81, 0, 0xb4,
    ]);
    for usage in [KEY | 8, KEY | 9] {
        bytes.push(0x0b);
        bytes.extend_from_slice(&usage.to_le_bytes());
    }
    bytes.extend_from_slice(&[0x81, 0, 0xc0]);
    let mut body = 0x8000_0000u32.to_le_bytes().to_vec();
    body.push(0xfe);
    body.extend_from_slice(&(i32::MAX as u32).to_le_bytes());
    assert_eq!(agree(&bytes, &body), Some(vec![6, 8, 9]));
    let keys = parse(&bytes).unwrap().keys.unwrap();
    assert_eq!(keys.arrays.len(), 3);
    assert_eq!(keys.arrays[2].1.maximum, i64::from(u32::MAX));
    assert!(!Arc::ptr_eq(
        &keys.arrays[0].1.usages,
        &keys.arrays[2].1.usages
    ));
}

#[test]
fn one_shared_array_table_preserves_send_sync_and_variable_repeat_behavior() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Keys>();
    send_sync::<Reports>();
    send_sync::<Field>();
    send_sync::<Pointer>();
    let usages: Vec<_> = (4..516).rev().map(|usage| KEY | usage).collect();
    let bytes = descriptor(&usages, 0, 511, 16, 1024);
    let keys = parse(&bytes).unwrap().keys.unwrap();
    assert_eq!(keys.arrays.len(), 1024);
    assert_eq!(keys.arrays[0].1.usages.len(), 512);
    assert!(Arc::ptr_eq(
        &keys.arrays[0].1.usages,
        &keys.arrays[1023].1.usages
    ));
    let cloned = keys.clone();
    assert!(Arc::ptr_eq(
        &keys.arrays[0].1.usages,
        &cloned.arrays[0].1.usages
    ));
    let mut variable = descriptor(&[KEY | 4, KEY | 5], 0, 1, 1, 4);
    let input = variable.windows(2).position(|w| w == [0x81, 0]).unwrap();
    variable[input + 1] = 2;
    let (items, _) = items(&variable).unwrap();
    assert_eq!(
        items
            .iter()
            .map(|item| match &item.usage {
                Usage::Variable(u) => *u,
                _ => panic!("variable"),
            })
            .collect::<Vec<_>>(),
        [KEY | 4, KEY | 5, KEY | 5, KEY | 5]
    );
    let boot = Keys::boot();
    assert!(Arc::ptr_eq(
        &boot.arrays[0].1.usages,
        &boot.arrays[5].1.usages
    ));
    assert_eq!(boot.pressed(&[2, 0, 4, 0, 0, 0, 0, 0]), Some(vec![0xe1, 4]));
}

#[test]
fn mapped_error_codes_are_checked_after_lookup_and_malformed_ranges_stay_explicit() {
    for error in 1..=3 {
        let bytes = descriptor(&[KEY | 4, KEY | error], 0, 1, 8, 1);
        assert_eq!(agree(&bytes, &[0]), Some(vec![4]));
        assert_eq!(agree(&bytes, &[1]), None);
    }
    let malformed = descriptor(&[KEY | 4], 5, 4, 8, 1);
    assert!(parse(&malformed).is_err());
    assert!(Descriptor::parse(&malformed).is_err());
    for bytes in [
        &[5, 7, 0x19, 9, 0x29, 4, 0x75, 8, 0x95, 1, 0x81, 0][..],
        &[5, 7, 0x19, 4, 0x75, 8, 0x95, 1, 0x81, 0][..],
    ] {
        assert!(parse(bytes).is_err());
        assert!(Descriptor::parse(bytes).is_err());
    }
    let too_wide = descriptor(&[KEY | 4], 0, 0, 33, 1);
    assert_eq!(
        parse(&too_wide).unwrap().keys.unwrap().pressed(&[0; 5]),
        None,
        "legacy numeric reader remains bounded to32bits"
    );
}
