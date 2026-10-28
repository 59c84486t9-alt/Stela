//! The macOS builds Stela supports. The device models speak each build's
//! AP-to-coprocessor firmware protocols (Stela models the coprocessors
//! rather than running their firmware), and the hosted kernel's call tables
//! follow each build's system-call census, so a build is supported only
//! once both are written for it. Setup, bundle preparation and the hosted
//! guest-system install refuse every other build with [`Unsupported`].
use alloc::{string::String, vec::Vec};
use core::fmt;

/// One supported build and the protocol values its firmware fixes.
#[derive(Debug, PartialEq, Eq)]
pub struct Build {
    /// The build, such as `26A434`.
    pub build: &'static str,
    /// Its product version, such as `27.0.1`.
    pub version: &'static str,
    /// The interface version of the DCP link library, which the
    /// coprocessor announces and the AP hashes into the interface CRC
    /// (`platform::apple::dcp::link`).
    pub dcp_link_version: u32,
    /// The RTKit management protocol version every RTKit coprocessor offers
    /// in its HELLO and the AP's RTBuddy accepts
    /// (`platform::apple::rtkit`).
    pub rtkit_version: u64,
}

/// Every supported build, newest first.
pub const SUPPORTED: &[Build] = &[Build {
    build: "26A434",
    version: "27.0.1",
    // The AP's global at 26A434 kernel file offset 0x5bd9bd8.
    dcp_link_version: 211,
    rtkit_version: 12,
}];

/// The build setup and `stela install-system` download when none is named:
/// the newest supported one.
pub const DEFAULT: &Build = &SUPPORTED[0];

/// `build`'s entry of `table`.
pub fn find_in<'t>(table: &'t [Build], build: &str) -> Result<&'t Build, Unsupported> {
    table
        .iter()
        .find(|entry| entry.build == build)
        .ok_or_else(|| Unsupported {
            build: build.into(),
            supported: table.iter().map(|entry| entry.build).collect(),
        })
}

/// `build`'s entry of [`SUPPORTED`].
pub fn find(build: &str) -> Result<&'static Build, Unsupported> {
    find_in(SUPPORTED, build)
}

/// A build outside the supported table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported {
    pub build: String,
    pub supported: Vec<&'static str>,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "macOS build {} is not supported; this Stela supports {}",
            self.build,
            self.supported.join(", ")
        )
    }
}

impl core::error::Error for Unsupported {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unlisted_build_is_refused_naming_the_supported_ones() {
        assert_eq!(find("26A434").unwrap().dcp_link_version, 211);
        assert_eq!(find("26A434").unwrap().rtkit_version, 12);
        assert_eq!(DEFAULT.build, "26A434");
        let error = find("26B5040").unwrap_err();
        assert_eq!(
            error.to_string(),
            "macOS build 26B5040 is not supported; this Stela supports 26A434"
        );
    }
}
