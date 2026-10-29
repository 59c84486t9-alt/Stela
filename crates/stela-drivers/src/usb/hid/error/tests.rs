use super::*;
use crate::usb::hid::{Descriptor, Translator, report};

#[test]
fn descriptor_failures_keep_their_item_offset_and_wire_values() {
    for (bytes, offset, kind) in [
        // A report size past 256 bits keeps the wire value.
        (
            &[0x05, 1, 0x77, 1, 1, 0, 0][..],
            2,
            ParseErrorKind::ReportSize { bits: 257 },
        ),
        // A cut-off payload keeps the missing extent.
        (
            &[0x05, 1, 0x77, 0xaa],
            2,
            ParseErrorKind::TruncatedItem {
                needed: 4,
                available: 1,
            },
        ),
        // A usage range keeps both pages and encoding widths.
        (
            &[0x06, 7, 0, 0x19, 4, 0x2b, 5, 0, 8, 0],
            5,
            ParseErrorKind::Usage(UsageError::Range {
                first: 0x0007_0004,
                last: 0x0008_0005,
                first_extended: false,
                last_extended: true,
            }),
        ),
        // An unfinished usage range refuses before collection processing.
        (
            &[0x19, 4, 0xa1, 1],
            2,
            ParseErrorKind::Usage(UsageError::UnfinishedRange { minimum: 4 }),
        ),
        // An unclosed collection points to the end of the descriptor.
        (
            &[0xa1, 1],
            2,
            ParseErrorKind::UnfinishedCollections { depth: 1 },
        ),
        // A report past its extent keeps the report geometry.
        (
            &[0x76, 0, 1, 0x96, 0, 0x30, 0x81, 1],
            6,
            ParseErrorKind::ReportBits {
                existing: 0,
                size: 256,
                count: 12_288,
                limit: (16_384 - 1) * 8,
            },
        ),
    ] {
        let error = Descriptor::parse(bytes).unwrap_err();
        assert_eq!(error.reader, Reader::Descriptor);
        assert_eq!(
            (error.offset, error.kind),
            (Some(offset), kind),
            "{bytes:02x?}"
        );
        if matches!(kind, ParseErrorKind::Usage(_)) {
            assert!(core::error::Error::source(&error).is_some());
        }
    }
}

#[test]
fn parser_views_keep_their_existing_diagnostic_vocabulary() {
    let complete = Descriptor::parse(&[0xfe]).unwrap_err();
    let input = report::parse(&[0xfe]).unwrap_err();
    assert_eq!(complete.kind, ParseErrorKind::LongItem);
    assert_eq!(input.kind, complete.kind);
    assert_eq!(complete.message(), "HID long items are unsupported");
    assert_eq!(input.message(), "long items in a report descriptor");
    assert_eq!(input.reader, Reader::InputReports);
}

#[test]
fn incompatible_pointer_axes_report_both_modes_without_a_false_item_offset() {
    let bytes = [
        0x05, 1, 0x09, 2, 0xa1, 1, 0x09, 0x30, 0x15, 0, 0x25, 0x7f, 0x75, 8, 0x95, 1, 0x81, 6,
        0x09, 0x31, 0x81, 2, 0xc0,
    ];
    let error = Translator::describe(&bytes).err().unwrap();
    assert_eq!(error.offset, None);
    assert_eq!(
        error.kind,
        ParseErrorKind::MixedPointerAxes {
            x_relative: Some(true),
            y_relative: Some(false),
        }
    );
}
