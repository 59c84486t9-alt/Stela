use super::*;
use crate::usb::hid::{Descriptor, Translator, report};

#[test]
fn report_size_failure_keeps_the_item_offset_and_wire_value() {
    let error = Descriptor::parse(&[0x05, 1, 0x77, 1, 1, 0, 0]).unwrap_err();
    assert_eq!(error.reader, Reader::Descriptor);
    assert_eq!(error.offset, Some(2));
    assert_eq!(error.kind, ParseErrorKind::ReportSize { bits: 257 });
}

#[test]
fn truncated_item_keeps_the_missing_payload_extent() {
    let error = Descriptor::parse(&[0x05, 1, 0x77, 0xaa]).unwrap_err();
    assert_eq!(error.offset, Some(2));
    assert_eq!(
        error.kind,
        ParseErrorKind::TruncatedItem {
            needed: 4,
            available: 1
        }
    );
}

#[test]
fn usage_range_keeps_both_pages_and_encoding_widths() {
    let error = Descriptor::parse(&[0x06, 7, 0, 0x19, 4, 0x2b, 5, 0, 8, 0]).unwrap_err();
    assert_eq!(error.offset, Some(5));
    assert_eq!(
        error.kind,
        ParseErrorKind::Usage(UsageError::Range {
            first: 0x0007_0004,
            last: 0x0008_0005,
            first_extended: false,
            last_extended: true,
        })
    );
    assert!(core::error::Error::source(&error).is_some());
}

#[test]
fn unfinished_usage_range_precedes_collection_processing() {
    let error = Descriptor::parse(&[0x19, 4, 0xa1, 1]).unwrap_err();
    assert_eq!(error.offset, Some(2));
    assert_eq!(
        error.kind,
        ParseErrorKind::Usage(UsageError::UnfinishedRange { minimum: 4 })
    );
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
fn unclosed_collection_points_to_the_end_of_the_descriptor() {
    let error = Descriptor::parse(&[0xa1, 1]).unwrap_err();
    assert_eq!(error.offset, Some(2));
    assert_eq!(
        error.kind,
        ParseErrorKind::UnfinishedCollections { depth: 1 }
    );
}

#[test]
fn report_extent_failure_keeps_the_report_geometry() {
    let error = Descriptor::parse(&[0x76, 0, 1, 0x96, 0, 0x30, 0x81, 1]).unwrap_err();
    assert_eq!(error.offset, Some(6));
    assert_eq!(
        error.kind,
        ParseErrorKind::ReportBits {
            existing: 0,
            size: 256,
            count: 12_288,
            limit: (16_384 - 1) * 8,
        }
    );
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
