//! AHCI sense tables cases.
use super::*;
#[test]
fn taskfile_errors_map_to_sense_data() {
    // Reference: libata ata_to_sense_error.
    let sense = |key, asc, ascq| Sense { key, asc, ascq };
    for (status, error, expected) in [
        (0x51, 0x40, sense(Sense::MEDIUM_ERROR, 0x11, 0x04)),
        (0x51, 0x84, sense(Sense::ABORTED_COMMAND, 0x47, 0x00)),
        (0x51, 0x10, sense(Sense::ILLEGAL_REQUEST, 0x21, 0x00)),
        (0x51, 0x20, sense(Sense::UNIT_ATTENTION, 0x28, 0x00)),
        (0x51, 0x37, sense(Sense::NOT_READY, 0x04, 0x00)),
        (0x51, 0x61, sense(Sense::HARDWARE_ERROR, 0x00, 0x00)),
        (0x51, 0xd1, sense(Sense::ABORTED_COMMAND, 0x00, 0x00)),
        // ABRT alone falls back to the status.
        (0x55, 0x04, sense(Sense::RECOVERED_ERROR, 0x00, 0x00)),
        (0x71, 0x04, sense(Sense::HARDWARE_ERROR, 0x44, 0x00)),
        (0x51, 0x04, sense(Sense::ABORTED_COMMAND, 0x00, 0x00)),
        // Busy invalidates the error register.
        (0xd0, 0x40, sense(Sense::ABORTED_COMMAND, 0x00, 0x00)),
    ] {
        assert_eq!(
            translate_error(status, error),
            expected,
            "{status:x} {error:x}"
        );
    }

    // The D2H FIS a failed flush completes with decides it.
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    let mut complete_with = |status: u8, error: u8, locked| {
        fixture.disk.locked = locked;
        let d2h = &mut fixture.disk.commands.bytes_mut()[RECEIVED_D2H..];
        (d2h[2], d2h[3]) = (status, error);
        let link = Link::new(&[Fault::TaskFile(u32::from(error) << 8 | 0x51)]);
        let result = fixture
            .disk
            .issue_on(&link, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false);
        (result, link.issued.get())
    };
    // A media change is requeued, a corrected error completes.
    assert_eq!(complete_with(0x51, 0x20, false), (Ok(()), 2));
    assert_eq!(complete_with(0x55, 0x04, false), (Ok(()), 1));
    assert_eq!(
        complete_with(0x51, 0x04, false),
        (
            Err(BlockError::Sense(sense(Sense::ABORTED_COMMAND, 0, 0))),
            1
        )
    );
    assert_eq!(
        complete_with(0x51, 0x04, true),
        (
            Err(BlockError::Sense(sense(Sense::DATA_PROTECT, 0x74, 0x71))),
            1
        )
    );
    // A FIS without a device error keeps the transport's error.
    assert_eq!(
        complete_with(0x50, 0x00, false),
        (Err(BlockError::Device { status: 0x51 }), 1)
    );
}

#[test]
fn identify_words_control_sense_reporting() {
    // Reference: libata ata_id_sense_reporting_enabled.
    fn words(pairs: &[(usize, u16)]) -> impl Fn(usize) -> u16 + '_ {
        move |index| {
            pairs
                .iter()
                .find(|(at, _)| *at == index)
                .map_or(0, |(_, value)| *value)
        }
    }
    let supported = [(86, 1 << 15), (119, 0x4040)];
    assert_eq!(sense_reporting(words(&supported)), (true, false));
    let enabled = [(86, 1 << 15), (119, 0x4040), (120, 0x4040)];
    assert_eq!(sense_reporting(words(&enabled)), (true, true));
    // Words 119 and 120 need word 86 bit 15 and their own 01b signature.
    assert_eq!(
        sense_reporting(words(&[(119, 0x4040), (120, 0x4040)])),
        (false, false)
    );
    assert_eq!(
        sense_reporting(words(&[(86, 1 << 15), (119, 0xc040), (120, 0x4040)])),
        (false, false)
    );
    assert_eq!(
        sense_reporting(words(&[(86, 1 << 15), (119, 0x4040), (120, 0x0040)])),
        (true, false)
    );
}

#[test]
fn sense_keys_select_completion_dispositions() {
    // Reference: scsi_check_sense and sd_completion.
    let sense = |key, asc, ascq| Sense { key, asc, ascq };
    for (key, asc, ascq, retry, done) in [
        (
            Sense::ABORTED_COMMAND,
            0x00,
            0x00,
            true,
            SenseCompletion::Fail,
        ),
        (
            Sense::ABORTED_COMMAND,
            0x10,
            0x01,
            false,
            SenseCompletion::Fail,
        ),
        (
            Sense::ABORTED_COMMAND,
            0x2e,
            0x02,
            false,
            SenseCompletion::Fail,
        ),
        (
            Sense::ABORTED_COMMAND,
            0x2e,
            0x04,
            true,
            SenseCompletion::Fail,
        ),
        (
            Sense::NOT_READY,
            0x04,
            0x01,
            true,
            SenseCompletion::Retry(9_000),
        ),
        (
            Sense::NOT_READY,
            0x04,
            0x0a,
            true,
            SenseCompletion::Retry(1_000_000),
        ),
        (
            Sense::NOT_READY,
            0x04,
            0x1b,
            false,
            SenseCompletion::Retry(9_000),
        ),
        (Sense::NOT_READY, 0x04, 0x02, false, SenseCompletion::Fail),
        (Sense::NOT_READY, 0x04, 0x24, false, SenseCompletion::Fail),
        (Sense::NOT_READY, 0x3a, 0x00, false, SenseCompletion::Fail),
        (
            Sense::UNIT_ATTENTION,
            0x29,
            0x00,
            false,
            SenseCompletion::Retry(0),
        ),
        (
            Sense::UNIT_ATTENTION,
            0x3f,
            0x0e,
            true,
            SenseCompletion::Retry(0),
        ),
        (
            Sense::MEDIUM_ERROR,
            0x11,
            0x04,
            false,
            SenseCompletion::Fail,
        ),
        (Sense::MEDIUM_ERROR, 0x0c, 0x00, true, SenseCompletion::Fail),
        (
            Sense::RECOVERED_ERROR,
            0x17,
            0x01,
            false,
            SenseCompletion::Done,
        ),
        (
            Sense::ILLEGAL_REQUEST,
            0x21,
            0x00,
            false,
            SenseCompletion::Fail,
        ),
        (0x04, 0x44, 0x00, false, SenseCompletion::Fail),
    ] {
        let sense = sense(key, asc, ascq);
        assert_eq!(sense.needs_retry(), retry, "{sense:?}");
        assert_eq!(sense.completion(false), done, "{sense:?}");
        // On a removable unit, UNIT ATTENTION reports a media change.
        if sense.key == Sense::UNIT_ATTENTION {
            assert_eq!(sense.completion(true), SenseCompletion::MediaChanged);
        }
    }
}
