// SPDX-License-Identifier: GPL-2.0-only
//! Linux oracle cases.
use super::*;

#[test]
#[ignore = "oracle: STELA_USB_UAS_RECOVERY_ORACLE"]
fn unchanged_linux_uas_reset_order_and_block_zero_cdb_match() {
    extern crate std;
    let trace = std::fs::read(
        std::env::var("STELA_USB_UAS_RECOVERY_ORACLE").expect("UAS recovery oracle trace"),
    )
    .unwrap();
    assert_eq!(&trace[..8], b"UASRCV01");
    let mut at = 8;
    for lock_failure in [0, 1] {
        for reset_failure in [0, 1] {
            let header = &trace[at..at + 4];
            at += 4;
            assert_eq!(&header[..2], &[lock_failure, reset_failure]);
            assert_eq!(header[2], u8::from(lock_failure != 0 || reset_failure != 0));
            let events = &trace[at..at + usize::from(header[3])];
            at += events.len();
            assert_eq!(
                events,
                if lock_failure != 0 {
                    &b"L"[..]
                } else {
                    &b"LCSDZRU"[..]
                }
            );
        }
    }
    for block_size in [512usize, 4096, MAX_TD] {
        for long_cdb in [false, true] {
            let bytes = u32::from_le_bytes(trace[at..at + 4].try_into().unwrap()) as usize;
            assert_eq!(bytes, block_size);
            assert_eq!(trace[at + 4], u8::from(long_cdb));
            let cdb = &trace[at + 5..at + 21];
            at += 21;
            if long_cdb {
                // The ordinary Stela block-zero path selects READ(10).
                // Keep the donor's alternative bytes without claiming a
                // production use_16_for_rw quirk that is not selected.
                assert_eq!(cdb[0], 0x88);
                assert_eq!(&cdb[10..14], &1u32.to_be_bytes());
                continue;
            }
            let mut medium = Media::disk(Lun::default(), 0x7a);
            medium.block_size = block_size as u32;
            let mut memory = vec![0u64; 32 * 1024];
            let (owner, state) = target_owner(
                &mut memory,
                Target::new(vec![medium]),
                quirks::Flags::default(),
            );
            let mut owner = owner.borrow_mut();
            read_block_zero(
                &mut owner.engine,
                quirks::Flags::default(),
                [0; 8],
                block_size,
            )
            .unwrap();
            assert_eq!(&state.borrow().history[0][16..32], cdb);
        }
    }
    assert_eq!(at, trace.len());
}

#[test]
#[ignore = "oracle: STELA_USB_UAS_ORACLE"]
fn unchanged_linux_uas_builders_and_enclosure_rows_match() {
    extern crate std;
    fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> &'a [u8] {
        let result = &bytes[*at..*at + n];
        *at += n;
        result
    }
    fn u16le(bytes: &[u8], at: &mut usize) -> u16 {
        u16::from_le_bytes(take(bytes, at, 2).try_into().unwrap())
    }
    let bytes =
        std::fs::read(std::env::var("STELA_USB_UAS_ORACLE").expect("UAS oracle trace path"))
            .unwrap();
    let mut at = 0;
    assert_eq!(take(&bytes, &mut at, 8), b"UASRAW01");
    for _ in 0..288 {
        let tag = u16le(&bytes, &mut at);
        let length = usize::from(u16le(&bytes, &mut at));
        let lun = take(&bytes, &mut at, 8).try_into().unwrap();
        let wire = usize::from(u16le(&bytes, &mut at));
        let cdb = take(&bytes, &mut at, length);
        let expected = take(&bytes, &mut at, wire);
        assert_eq!(command_iu(tag, lun, cdb), expected);
    }
    assert_eq!(take(&bytes, &mut at, 8), b"POLICY24");
    for _ in 0..24 {
        let vendor = u16le(&bytes, &mut at);
        let product = u16le(&bytes, &mut at);
        let lo = u16le(&bytes, &mut at);
        let hi = u16le(&bytes, &mut at);
        let bits = take(&bytes, &mut at, 1)[0];
        for revision in [lo, hi] {
            assert_eq!(
                quirks::Flags::from_id(vendor, product, revision).bits(),
                bits | if vendor == 0x0bc2 { 16 } else { 0 }
            );
        }
    }
    assert_eq!(at, bytes.len());
}
