// SPDX-License-Identifier: GPL-2.0-only
//! Command forms cases.
use super::*;

#[test]
fn zero_empty_and_oversized_cdb_or_data_never_submit_work() {
    let mut memory = vec![0u64; 32 * 1024];
    let (io, mut dma) = model(&mut memory, 0, false, Fault::None);
    let state = io.state.clone();
    let mut engine = Engine::new(io, &mut dma).unwrap();
    for (cdb, n) in [(vec![], 0), (vec![0; 261], 0), (vec![0; 6], MAX_TD + 1)] {
        assert!(engine.command([0; 8], &cdb, Data::In(n)).is_err());
    }
    assert!(state.borrow().events.is_empty());
}

#[test]
fn command_extension_padding_and_status_lengths_are_bounded() {
    for length in [1, 6, 10, 16, 17, 31, 32, 255, 260] {
        let bytes = command_iu(0x1234, [0xa5; 8], &vec![0x6d; length]);
        let extra = length.saturating_sub(16).next_multiple_of(4);
        assert_eq!(bytes.len(), 32 + extra);
        assert_eq!(usize::from(bytes[6]), extra);
        assert!(bytes[16 + length..].iter().all(|b| *b == 0));
    }
    for bytes in [
        vec![],
        vec![STATUS_IU, 0, 0],
        vec![STATUS_IU, 0, 0, 1],
        vec![READ_READY_IU, 0, 0, 2],
        vec![STATUS_IU; 16],
    ] {
        assert!(status_iu(&bytes, 1).is_none());
    }
    let response = [RESPONSE_IU, 0, 0, 1, 0, 0, 0, 8];
    let Frame::Done(status) = status_iu(&response, 1).unwrap() else {
        panic!()
    };
    assert_eq!(status.code, 0);
    assert_eq!(status.response, Some(8));
    // Disagreeing sense lengths clamp to the transfer, as Linux uas_sense does.
    let mut sense = vec![STATUS_IU, 0, 0, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 40];
    sense.extend([0x70, 0, 6]);
    let Frame::Done(status) = status_iu(&sense, 1).unwrap() else {
        panic!()
    };
    assert_eq!(
        (status.code, status.sense.as_slice()),
        (2, &[0x70, 0, 6][..])
    );
    sense[15] = 1;
    let Frame::Done(status) = status_iu(&sense, 1).unwrap() else {
        panic!()
    };
    assert_eq!(status.sense, [0x70]);
}

#[test]
fn always_sync_writes_are_not_followed_by_a_cache_flush_like_linux() {
    for (op, action) in [(0x2a, None), (0x8a, None), (0x7f, Some(0x0b))] {
        let mut memory = vec![0u64; 32 * 1024];
        let (io, mut dma) = model(&mut memory, 512, false, Fault::None);
        let state = io.state.clone();
        let mut engine = Engine::new(io, &mut dma).unwrap();
        execute(
            &mut engine,
            quirks::Flags::from_id(0x4971, 0x8024, 0),
            [0; 8],
            &write_form(op, action, false),
            Data::Out(&[0xa5; 512]),
        )
        .unwrap();
        let state = state.borrow();
        assert_eq!(state.history.len(), 1);
        assert_eq!(state.written, vec![0xa5; 512]);
    }
}

#[test]
fn enclosure_restrictions_fail_before_dma_or_native_submission() {
    let mut memory = vec![0u64; 32 * 1024];
    let (io, mut dma) = model(&mut memory, 0, false, Fault::None);
    let state = io.state.clone();
    let mut engine = Engine::new(io, &mut dma).unwrap();
    assert!(
        execute(
            &mut engine,
            quirks::Flags::from_id(0x0bc2, 0, 0),
            [0; 8],
            &[0x85; 16],
            Data::None
        )
        .is_err()
    );
    assert!(state.borrow().events.is_empty());
    assert_eq!(engine.tag, 0);
}

#[test]
fn mode_page_and_standard_alias_policies_reject_before_native_submission() {
    let mut memory = vec![0u64; 32 * 1024];
    let (io, mut dma) = model(&mut memory, 0, false, Fault::None);
    let state = io.state.clone();
    let mut engine = Engine::new(io, &mut dma).unwrap();
    let always = quirks::Flags::from_id(0x4971, 0x8024, 0);
    let broken = quirks::Flags::from_id(0x152d, 0x0578, 0);
    for op in [0x1a, 0x5a] {
        for page in [8, 0x3f] {
            for pc in [0, 0x40, 0x80, 0xc0] {
                for dbd in [0, 8] {
                    let mut cdb = vec![0; if op == 0x1a { 6 } else { 10 }];
                    cdb[0] = op;
                    cdb[1] = dbd;
                    cdb[2] = page | pc;
                    assert!(execute(&mut engine, always, [0; 8], &cdb, Data::In(4)).is_err());
                }
            }
        }
    }
    for op in [0x2a, 0x2e, 0xaa, 0xae, 0x8a, 0x8e, 0x9c] {
        assert!(
            execute(
                &mut engine,
                broken,
                [0; 8],
                &write_form(op, None, true),
                Data::Out(&[0; 512])
            )
            .is_err()
        );
    }
    for action in [0x0b, 0x0c] {
        assert!(
            execute(
                &mut engine,
                broken,
                [0; 8],
                &write_form(0x7f, Some(action), true),
                Data::Out(&[0; 512])
            )
            .is_err()
        );
    }
    assert!(
        execute(
            &mut engine,
            quirks::Flags::from_id(0x059f, 0x105f, 0),
            [0; 8],
            &write_form(0x7f, Some(0x0d), false),
            Data::Out(&[0; 512])
        )
        .is_err()
    );
    assert!(
        execute(
            &mut engine,
            quirks::Flags::from_id(0x0bc2, 0, 0),
            [0; 8],
            &write_form(0x7f, Some(0x1ff0), false),
            Data::None
        )
        .is_err()
    );
    assert!(state.borrow().events.is_empty());
    assert_eq!(engine.tag, 0);
    assert!(always.permits(&[0x1a, 0, 0, 0, 4, 0]));
}
