// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! Bounded MT79xx Bluetooth firmware parsing and WMT download framing adapted
//! from pinned Linux btmtk.c. This module alone admits no devices, sends no
//! commands and establishes no firmware acceptance or authentication.
mod firmware;
pub use firmware::{FirmwareMetadata, Fragment, Patch, Section, SectionMetadata};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError {
    Size,
    Header,
    SectionTable,
    SectionBounds,
    DownloadBounds,
    OverlappingSections,
    NoDownload,
}
impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek firmware format {self:?}")
    }
}
impl core::error::Error for FormatError {}
