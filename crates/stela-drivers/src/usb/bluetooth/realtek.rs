// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Endless Mobile, Inc.
//! Realtek USB firmware staging adapted from pinned Linux `btrtl.c`/`btrtl.h`.
//! See THIRD_PARTY.md for exact provenance and limits. This pure parser does not
//! admit a USB device, initialize a controller or establish firmware authenticity.
//! Native ROM/security observation, exact Provider requirements, real upload
//! acknowledgements and controller lifecycle remain separate prerequisites.
mod firmware;
pub use firmware::{Configuration, Fragment, Patch, Project, Staged};

/// Malformed or explicitly unsupported Realtek input. Parsing never emits a
/// partially selected download or silently substitutes another ROM/project.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError {
    Size,
    Signature,
    Extension,
    Project,
    PatchTable,
    PatchBounds,
    OverlappingPatches,
    DuplicateChip,
    MissingRom,
    ConfigHeader,
    ConfigEntry,
    OverlappingConfig,
}
impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Realtek firmware format {self:?}")
    }
}
impl core::error::Error for FormatError {}
