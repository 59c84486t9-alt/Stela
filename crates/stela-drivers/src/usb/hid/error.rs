// SPDX-License-Identifier: GPL-2.0-or-later
//! HID descriptor parsing failures with their input location and wire values.
use core::fmt;

/// The descriptor view that detected a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reader {
    /// Complete input, output and feature report layouts.
    Descriptor,
    /// Keyboard and pointer input projection.
    InputReports,
}

/// A local Usage or Delimiter state violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsageError {
    Limit {
        existing: usize,
        added: usize,
        limit: usize,
    },
    NestedMinimum {
        value: u32,
        size: usize,
        page: u32,
    },
    MaximumWithoutMinimum {
        value: u32,
        size: usize,
        page: u32,
    },
    Range {
        first: u32,
        last: u32,
        first_extended: bool,
        last_extended: bool,
    },
    UnfinishedRange {
        minimum: u32,
    },
    DelimiterLimit {
        existing: usize,
        limit: usize,
    },
    NestedDelimiter,
    CloseWithoutOpen,
    DelimiterValue {
        value: u32,
        size: usize,
    },
    UnclosedDelimiter,
    ForbiddenDelimiter {
        tag: u8,
        value: u32,
    },
}

impl UsageError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Limit { .. } => "too many HID usages",
            Self::NestedMinimum { .. } => "HID nested usage minimum",
            Self::MaximumWithoutMinimum { .. } => "HID usage maximum without minimum",
            Self::Range { .. } => "invalid HID usage range",
            Self::UnfinishedRange { .. } => "unfinished HID usage range",
            Self::DelimiterLimit { .. } => "too many HID delimiter sets",
            Self::NestedDelimiter => "nested HID delimiter",
            Self::CloseWithoutOpen => "HID delimiter close without open",
            Self::DelimiterValue { .. } => "invalid HID delimiter value",
            Self::UnclosedDelimiter => "unclosed HID delimiter",
            Self::ForbiddenDelimiter { .. } => "HID delimiter on Application Collection or Array",
        }
    }
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}
impl core::error::Error for UsageError {}

/// The failed descriptor constraint. Limits and supplied values remain
/// available to callers independently of diagnostic wording.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseErrorKind {
    LongItem,
    TruncatedItem {
        needed: usize,
        available: usize,
    },
    UsagePage {
        value: u32,
    },
    ReportSize {
        bits: u32,
    },
    ReportId {
        value: u32,
    },
    ReportCount {
        count: u32,
    },
    GlobalStackOverflow {
        limit: usize,
    },
    GlobalStackUnderflow,
    CollectionLimit {
        limit: usize,
    },
    CollectionType {
        value: u32,
    },
    CollectionUnderflow,
    ZeroSizeField {
        count: usize,
    },
    LogicalRange {
        minimum: i64,
        maximum: i64,
    },
    ReportBits {
        existing: usize,
        size: usize,
        count: usize,
        limit: usize,
    },
    FieldCount {
        existing: usize,
        added: usize,
        limit: usize,
    },
    ReservedItem {
        prefix: u8,
    },
    UnfinishedCollections {
        depth: usize,
    },
    MixedReportIds,
    Usage(UsageError),
    MixedPointerAxes {
        x_relative: Option<bool>,
        y_relative: Option<bool>,
    },
}

/// A parser failure. Item offsets identify the original prefix byte; an
/// end-of-input failure uses the descriptor length. Aggregate pointer
/// compatibility has no unique item location and reports None.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub reader: Reader,
    pub offset: Option<usize>,
    pub kind: ParseErrorKind,
}

impl ParseError {
    pub(super) const fn at(reader: Reader, offset: usize, kind: ParseErrorKind) -> Self {
        Self {
            reader,
            offset: Some(offset),
            kind,
        }
    }

    pub(super) const fn pointer(x_relative: Option<bool>, y_relative: Option<bool>) -> Self {
        Self {
            reader: Reader::InputReports,
            offset: None,
            kind: ParseErrorKind::MixedPointerAxes {
                x_relative,
                y_relative,
            },
        }
    }

    /// Stable transport diagnostic text. Structured callers inspect kind and
    /// offset; USB block/probe presentation adapters use this explicit mapping.
    pub const fn message(self) -> &'static str {
        let projection = matches!(self.reader, Reader::InputReports);
        match self.kind {
            ParseErrorKind::LongItem if projection => "long items in a report descriptor",
            ParseErrorKind::LongItem => "HID long items are unsupported",
            ParseErrorKind::TruncatedItem { .. } if projection => "truncated report descriptor",
            ParseErrorKind::TruncatedItem { .. } => "truncated HID item",
            ParseErrorKind::UsagePage { .. } => "HID usage page exceeds 16 bits",
            ParseErrorKind::ReportSize { .. } if projection => "Report Size over 256 bits",
            ParseErrorKind::ReportSize { .. } => "HID Report Size exceeds 256 bits",
            ParseErrorKind::ReportId { .. } if projection => "Report ID outside 1-255",
            ParseErrorKind::ReportId { .. } => "invalid HID report ID",
            ParseErrorKind::ReportCount { .. } if projection => "Report Count over 12288",
            ParseErrorKind::ReportCount { .. } => "HID Report Count exceeds 12288",
            ParseErrorKind::GlobalStackOverflow { .. } if projection => {
                "global item stack overflow"
            }
            ParseErrorKind::GlobalStackOverflow { .. } => "HID global stack overflow",
            ParseErrorKind::GlobalStackUnderflow if projection => "Pop without Push",
            ParseErrorKind::GlobalStackUnderflow => "HID Pop without Push",
            ParseErrorKind::CollectionLimit { .. } => "too many HID collections",
            ParseErrorKind::CollectionType { .. } => "invalid HID collection type",
            ParseErrorKind::CollectionUnderflow => "HID End Collection without Collection",
            ParseErrorKind::ZeroSizeField { .. } => "zero-size HID field",
            ParseErrorKind::LogicalRange { .. } if projection => {
                "HID array logical minimum exceeds maximum"
            }
            ParseErrorKind::LogicalRange { .. } => "invalid HID logical range",
            ParseErrorKind::ReportBits { .. } if projection => {
                "input report longer than 16384 bytes"
            }
            ParseErrorKind::ReportBits { .. } => "HID report exceeds 16384 bytes",
            ParseErrorKind::FieldCount { .. } => "too many HID fields",
            ParseErrorKind::ReservedItem { .. } if projection => {
                "unknown or reserved HID Main item"
            }
            ParseErrorKind::ReservedItem { .. } => "unknown or reserved HID item",
            ParseErrorKind::UnfinishedCollections { .. } => "unfinished HID descriptor",
            ParseErrorKind::MixedReportIds => {
                "HID descriptor mixes numbered and unnumbered reports"
            }
            ParseErrorKind::Usage(error) => error.message(),
            ParseErrorKind::MixedPointerAxes { .. } => {
                "HID pointer with one absolute and one relative axis"
            }
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}
impl core::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match &self.kind {
            ParseErrorKind::Usage(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
