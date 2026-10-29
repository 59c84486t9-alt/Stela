use super::super::{AddressFormat, FinishError, PacketKind};
use super::*;
use crate::platform::apple::pmgr::sequencer::control::{test_fields, test_initial};
use alloc::vec;
const SOURCE: u64 = 0x292f60000;
const DESTINATION: u64 = 0x1301000000;
fn words(source: u64, destination: u64, bytes: u32) -> Vec<u32> {
    vec![
        ((bytes - 1) << 6) | TAG,
        ((source >> 36) & 63) as u32 | (((destination >> 36) & 63) as u32) << 16,
        ((source >> 4) & u64::from(ADDRESS_FIELDS)) as u32,
        ((destination >> 4) & u64::from(ADDRESS_FIELDS)) as u32,
        (COMPLETE_JOIN << 6) | JOIN_TAG,
        0,
    ]
}
fn cursor(words: &[u32], format: AddressFormat) -> PacketCursor {
    let mut cursor = PacketCursor::unknown();
    cursor.bind_initial_control(test_initial()).unwrap();
    cursor
        .install_sram(
            0x292f01a00,
            &words
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>(),
            format,
        )
        .unwrap();
    cursor
}
fn payload(bytes: u32) -> Vec<u8> {
    (0..bytes)
        .map(|index| (index ^ (index >> 8)) as u8)
        .collect()
}

#[test]
fn actual_read_bytes_survive_destination_refusal_and_only_real_write_can_join() {
    let mut cursor = cursor(&words(SOURCE, DESTINATION, 256), AddressFormat::HighWord);
    let start = cursor.packet_pc();
    assert_eq!(cursor.packet_kind(), Ok(PacketKind::Copy));
    let read = cursor.begin_copy_read().unwrap();
    assert_eq!(
        read.read(),
        PhysicalRead {
            address: SOURCE,
            bytes: 256
        }
    );
    assert_eq!(cursor.begin_copy_read().unwrap_err(), Error::InFlight);
    cursor
        .dispatch_copy_read(&read, &read.qualify_context(test_fields()).unwrap())
        .unwrap();
    assert_eq!(
        cursor.cancel_copy_read(&read),
        Err(Error::AlreadyDispatched)
    );
    let source_ram = payload(256);
    cursor
        .finish_copy_read::<()>(&read, ReadOutcome::Read(source_ram.clone()))
        .unwrap();
    assert_eq!(cursor.packet_pc(), start);
    assert_eq!(
        cursor.begin_copy_read().unwrap_err(),
        Error::ExpectedCopyWrite
    );
    assert_eq!(cursor.pending_copy().unwrap().phase, Phase::Write);
    let claim = cursor.begin_copy_write().unwrap();
    let write = cursor
        .dispatch_copy_write(&claim, &claim.qualify_context(test_fields()).unwrap())
        .unwrap();
    assert_eq!(write.address, DESTINATION);
    assert_eq!(write.bytes(), source_ram);
    assert_eq!(
        cursor.finish_copy_write(&claim, RouteOutcome::NoEffect("target preflight")),
        Err(FinishError::NoEffect("target preflight"))
    );
    assert_eq!(
        cursor.dispatch_copy_write(&claim, &claim.qualify_context(test_fields()).unwrap()),
        Err(Error::StaleClaim)
    );
    assert_eq!(cursor.committed_reads(), 1);
    let retry = cursor.begin_copy_write().unwrap();
    let write = cursor
        .dispatch_copy_write(&retry, &retry.qualify_context(test_fields()).unwrap())
        .unwrap();
    let mut destination_ram = vec![0; 256];
    destination_ram.copy_from_slice(write.bytes());
    cursor
        .finish_copy_write::<()>(&retry, RouteOutcome::Committed)
        .unwrap();
    assert_eq!(destination_ram, source_ram);
    assert_eq!(cursor.pending_copy().unwrap().phase, Phase::Join);
    assert_eq!(cursor.packet_kind(), Ok(PacketKind::CopyJoin));
    assert_eq!(
        cursor.begin_copy_read().unwrap_err(),
        Error::ExpectedCopyJoin
    );
    let done = cursor.advance_copy_join().unwrap();
    assert_eq!(
        done.transfer,
        Transfer {
            source: SOURCE,
            destination: DESTINATION,
            bytes: 256
        }
    );
    assert_eq!(done.join_operand, COMPLETE_JOIN);
    assert_eq!(cursor.last_copy(), Some(done));
    assert_eq!(
        (cursor.committed_reads(), cursor.committed_writes()),
        (1, 1)
    );
    assert!(cursor.pending_copy().is_none());
    assert_eq!(cursor.packet_kind(), Err(Error::UnqualifiedRetirement));
}

#[test]
fn partial_reads_and_writes_quarantine_the_exact_transfer_without_retry_or_join() {
    for read_failure in [true, false] {
        let mut cursor = cursor(&words(SOURCE, DESTINATION, 128), AddressFormat::HighWord);
        let start = cursor.packet_pc();
        let read = cursor.begin_copy_read().unwrap();
        cursor
            .dispatch_copy_read(&read, &read.qualify_context(test_fields()).unwrap())
            .unwrap();
        if read_failure {
            assert_eq!(
                cursor.finish_copy_read(
                    &read,
                    ReadOutcome::Uncertain("read changed target before failure")
                ),
                Err(ReadFinishError::Uncertain(
                    "read changed target before failure"
                ))
            );
            assert_eq!(cursor.uncertain_copy_read(), Some(read.read()));
        } else {
            cursor
                .finish_copy_read::<()>(&read, ReadOutcome::Read(payload(128)))
                .unwrap();
            let claim = cursor.begin_copy_write().unwrap();
            let write = cursor
                .dispatch_copy_write(&claim, &claim.qualify_context(test_fields()).unwrap())
                .unwrap();
            let mut destination_ram = [0; 128];
            destination_ram[..64].copy_from_slice(&write.bytes()[..64]);
            assert_eq!(
                cursor.finish_copy_write(&claim, RouteOutcome::Uncertain("partial destination")),
                Err(FinishError::Uncertain("partial destination"))
            );
            assert_eq!(destination_ram[..64], payload(128)[..64]);
            assert_eq!(
                cursor.uncertain_copy_write(),
                Some(Transfer {
                    source: SOURCE,
                    destination: DESTINATION,
                    bytes: 128
                })
            );
        }
        assert_eq!(cursor.packet_pc(), start);
        assert_eq!(
            cursor.begin_copy_read().unwrap_err(),
            Error::UncertainEffects
        );
        assert_eq!(
            cursor.begin_copy_write().unwrap_err(),
            Error::UncertainEffects
        );
        assert_eq!(cursor.advance_copy_join(), Err(Error::UncertainEffects));
    }
    let mut short = cursor(&words(SOURCE, DESTINATION, 128), AddressFormat::HighWord);
    let read = short.begin_copy_read().unwrap();
    short
        .dispatch_copy_read(&read, &read.qualify_context(test_fields()).unwrap())
        .unwrap();
    assert_eq!(
        short.finish_copy_read::<()>(&read, ReadOutcome::Read(vec![0xaa; 64])),
        Err(ReadFinishError::InvalidLength {
            expected: 128,
            actual: 64
        })
    );
    assert_eq!(short.pending_copy().unwrap().retained_bytes, Some(64));
    assert_eq!(
        short.begin_copy_write().unwrap_err(),
        Error::UncertainEffects
    );
}

#[test]
fn suspension_tokens_join_forms_and_encoding_bounds_preserve_effect_ownership() {
    let mut cursor = cursor(&words(SOURCE, DESTINATION, 128), AddressFormat::HighWord);
    let canceled = cursor.begin_copy_read().unwrap();
    cursor.cancel_copy_read(&canceled).unwrap();
    let read = cursor.begin_copy_read().unwrap();
    assert_eq!(
        cursor.dispatch_copy_read(&canceled, &canceled.qualify_context(test_fields()).unwrap()),
        Err(Error::StaleClaim)
    );
    cursor.set_suspended(true);
    assert_eq!(
        cursor.dispatch_copy_read(&read, &read.qualify_context(test_fields()).unwrap()),
        Err(Error::Suspended)
    );
    cursor.set_suspended(false);
    cursor
        .dispatch_copy_read(&read, &read.qualify_context(test_fields()).unwrap())
        .unwrap();
    cursor.set_suspended(true);
    cursor
        .finish_copy_read::<()>(&read, ReadOutcome::Read(payload(128)))
        .unwrap();
    assert_eq!(cursor.begin_copy_write().unwrap_err(), Error::Suspended);
    cursor.set_suspended(false);
    let write = cursor.begin_copy_write().unwrap();
    cursor
        .dispatch_copy_write(&write, &write.qualify_context(test_fields()).unwrap())
        .unwrap();
    cursor.set_suspended(true);
    cursor
        .finish_copy_write::<()>(&write, RouteOutcome::Committed)
        .unwrap();
    assert_eq!(cursor.advance_copy_join(), Err(Error::Suspended));
    cursor.set_suspended(false);
    cursor.advance_copy_join().unwrap();
    let mut finite = words(SOURCE, DESTINATION, 128);
    finite[4] = (7 << 6) | JOIN_TAG;
    let mut finite = self::cursor(&finite, AddressFormat::HighWord);
    let read = finite.begin_copy_read().unwrap();
    finite
        .dispatch_copy_read(&read, &read.qualify_context(test_fields()).unwrap())
        .unwrap();
    finite
        .finish_copy_read::<()>(&read, ReadOutcome::Read(payload(128)))
        .unwrap();
    let write = finite.begin_copy_write().unwrap();
    finite
        .dispatch_copy_write(&write, &write.qualify_context(test_fields()).unwrap())
        .unwrap();
    finite
        .finish_copy_write::<()>(&write, RouteOutcome::Committed)
        .unwrap();
    assert_eq!(
        finite.advance_copy_join(),
        Err(Error::UnqualifiedCopyJoin(7))
    );
    assert_eq!(finite.pending_copy().unwrap().phase, Phase::Join);
    let mut empty_join = self::cursor(
        &[(COMPLETE_JOIN << 6) | JOIN_TAG, 0],
        AddressFormat::HighWord,
    );
    assert_eq!(empty_join.advance_copy_join(), Err(Error::ExpectedCopyJoin));
    for (mut words, expected) in [
        (words(SOURCE, SOURCE + 128, 256), Error::CopyOverlap),
        (words(SOURCE, DESTINATION, 127), Error::CopyAlignment),
        (words(SOURCE, DESTINATION, 128), Error::HighAddress),
    ] {
        if expected == Error::HighAddress {
            words[1] |= 1 << 8;
        }
        assert_eq!(
            self::cursor(&words, AddressFormat::HighWord)
                .begin_copy_read()
                .unwrap_err(),
            expected
        );
    }
    let mut compact = words(SOURCE, 0x701000000, 128);
    compact.remove(1);
    let mut compact = self::cursor(&compact, AddressFormat::Compact);
    assert_eq!(compact.begin_copy_read().unwrap().read().address, SOURCE);
}

#[cfg(feature = "std")]
#[test]
#[ignore = "oracle: STELA_TEST_PMGR_M1_IBOOTDATA, STELA_TEST_PMGR_M1_LLB"]
fn original_copy_emitter_segment_resolution_and_single_pending_join_are_pinned() {
    use sha2::{Digest, Sha256};
    let llb = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_LLB").unwrap()).unwrap();
    let data = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_IBOOTDATA").unwrap()).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&llb)),
        "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
    );
    assert_eq!(
        hex::encode(Sha256::digest(&data)),
        "6d38d4b30deedb1be526e36179205004957f10e23254392fc3645c63dfd2b095"
    );
    for (lo, hi, digest) in [
        (
            0x11008,
            0x113e8,
            "a31d850998a8858fa7888ac8165f800503246c2c03bf8135a69db3eed155312f",
        ),
        (
            0x12104,
            0x12840,
            "43395858db77a2ecc76cdbdc17fe7ad776c58ad450cf314f9806685b186d7b39",
        ),
        (
            0x4a5c8,
            0x4a660,
            "4cabac3bf3ee41320356244fe7fb58269d6ac85b01464747faaf2e2048586d43",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&llb[lo..hi])), digest);
    }
    assert_eq!(&llb[0x200056..0x20005d], b"__TEXT\0");
    assert_eq!(&llb[0x20005d..0x200064], b"__DATA\0");
    // Preserve the complete original record, including continuations. A
    // raw opcode census alone does not mark each row executable top-level.
    assert_eq!(
        hex::encode(Sha256::digest(&data[0x4000..0x6bf08])),
        "20975d766b7d5bc14ee81c764073359d80fdae6e276523b3f7055e1957ca8e76"
    );
    let mut joins = [0; 2];
    for row in data[0x4000..0x6bf08].as_chunks::<24>().0 {
        let opcode = u16::from_le_bytes(row[2..4].try_into().unwrap());
        if matches!(opcode, 0x33 | 0x34) {
            let operand = u64::from_le_bytes(row[16..24].try_into().unwrap());
            assert!(matches!(operand, 0x3ffffff | 0x7ffffff));
            assert_eq!(((operand as u32) << 6) | JOIN_TAG, 0xfffffff8);
            joins[usize::from(opcode == 0x34)] += 1;
        }
    }
    assert_eq!(joins, [3, 34]);
}
