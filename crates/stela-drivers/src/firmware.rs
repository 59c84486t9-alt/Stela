// SPDX-License-Identifier: MIT
//! Exact host-device firmware resources, independent of a filesystem or OS loader.
//!
//! A setup/boot loader supplies owned [`Resource`] buffers and their manifests to
//! [`Catalog::from_handoff`], then retains the catalog while drivers borrow images.
//! The host-only manifest and reserved-page boot handoff supply it separately
//! from guest Apple boot bundles.
//! No vendor firmware is embedded here. Length and SHA-256 checks establish
//! integrity against the supplied manifest, **not** vendor authentication. A
//! caller that changes both the manifest and the bytes can pass those checks.
//! Device drivers must still validate vendor signatures, headers, firmware APIs,
//! calibration and upload/reset protocols before accepting a device as ready.
//!
//! Consumer requirements were checked against Linux commit
//! `a804c5742bff224d4cb4d25dd383554d598be32b`: `iwl-drv.c` builds a hardware
//! prefix plus API filename (`cfg/ax210.c` selects API 89); `btintel.c` selects
//! separate `.sfi`/`.ddc` names using silicon revision tuples; SOF's `loader.c`
//! and `sof-pci-dev.c` select platform firmware/topology paths. This native
//! facility incorporates no Linux code and never guesses a compatible variant.
//! Reference paths at that pin:
//! - `drivers/net/wireless/intel/iwlwifi/{iwl-drv.c,cfg/ax210.c}`
//! - `drivers/bluetooth/btintel.c`
//! - `sound/soc/sof/{loader.c,sof-pci-dev.c}`
//!
//! An image cannot outlive its provider:
//! ```compile_fail
//! use stela_drivers::firmware::{Catalog, Provider, Requirement, Target};
//! let image = {
//!     let catalog = Catalog::from_handoff(vec![]).unwrap();
//!     catalog.load(Requirement {
//!         name: "vendor/fw.bin",
//!         target: Target { driver: "wifi", hardware: "1234:5678",
//!                          revision: "a0", board: None },
//!         minimum_bytes: 1,
//!     }).unwrap()
//! };
//! let _ = image.bytes();
//! ```

pub mod smbios;

use alloc::{string::String, vec::Vec};
use core::fmt;
use sha2::{Digest, Sha256};

/// An owned diagnostic name. Copying borrowed bytes uses a fallible reserve;
/// OOM keeps the original byte count and SHA-256 instead of aborting. This
/// fallback is explicitly unavailable diagnostic data, never a resource identity.
/// Resource selection and valid-name acceptance are unchanged.
#[derive(PartialEq, Eq)]
pub enum ErrorName {
    Available(String),
    AllocationFailed {
        original_bytes: usize,
        sha256: [u8; 32],
    },
}

impl ErrorName {
    /// Exact complete bytes when available; OOM never substitutes a prefix.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Available(name) => Some(name),
            Self::AllocationFailed { .. } => None,
        }
    }
    /// Only a complete diagnostic name can match a suffix.
    pub fn ends_with(&self, suffix: &str) -> bool {
        self.as_str().is_some_and(|name| name.ends_with(suffix))
    }
}
impl From<&str> for ErrorName {
    fn from(name: &str) -> Self {
        let mut owned = String::new();
        if owned.try_reserve_exact(name.len()).is_err() {
            return Self::AllocationFailed {
                original_bytes: name.len(),
                sha256: Sha256::digest(name.as_bytes()).into(),
            };
        }
        owned.push_str(name);
        Self::Available(owned)
    }
}
impl From<String> for ErrorName {
    fn from(name: String) -> Self {
        Self::Available(name)
    }
}
impl Clone for ErrorName {
    fn clone(&self) -> Self {
        match self {
            Self::Available(name) => Self::from(name.as_str()),
            Self::AllocationFailed {
                original_bytes,
                sha256,
            } => Self::AllocationFailed {
                original_bytes: *original_bytes,
                sha256: *sha256,
            },
        }
    }
}
impl PartialEq<str> for ErrorName {
    fn eq(&self, name: &str) -> bool {
        self.as_str() == Some(name)
    }
}
impl PartialEq<&str> for ErrorName {
    fn eq(&self, name: &&str) -> bool {
        self == *name
    }
}
impl PartialEq<String> for ErrorName {
    fn eq(&self, name: &String) -> bool {
        self == name.as_str()
    }
}
impl fmt::Display for ErrorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Available(name) => fmt::Debug::fmt(name, f),
            Self::AllocationFailed {
                original_bytes,
                sha256,
            } => {
                write!(
                    f,
                    "<name unavailable: allocation failed; original bytes={original_bytes}; sha256="
                )?;
                for byte in sha256 {
                    write!(f, "{byte:02x}")?;
                }
                write!(f, ">")
            }
        }
    }
}
impl fmt::Debug for ErrorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Driver-defined, canonical identity labels, compared byte for byte.
/// `board: None` is an exact board-independent binding, never a wildcard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target<'a> {
    pub driver: &'a str,
    pub hardware: &'a str,
    /// Includes every silicon/ABI revision component the driver requires.
    pub revision: &'a str,
    pub board: Option<&'a str>,
}

/// An exact filename and target selected by the device driver.
#[derive(Clone, Copy, Debug)]
pub struct Requirement<'a> {
    pub name: &'a str,
    pub target: Target<'a>,
    /// Nonzero lower bound, before device-specific header parsing.
    pub minimum_bytes: usize,
}

/// Source identity retained with every accepted image; not an authentication proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Provenance<'a> {
    /// Package name or source URL.
    pub source: &'a str,
    /// Immutable source revision or vendor release identifier.
    pub revision: &'a str,
    /// Exact relative member path in the source package.
    pub member: &'a str,
    pub license: &'a str,
}

/// Loader-to-driver handoff. Construction consumes `bytes` without copying them;
/// descriptor strings need only live through [`Catalog::from_handoff`].
/// Expected length and digest must come from the loader's selected manifest.
pub struct Resource<'a, B = Vec<u8>> {
    pub name: &'a str,
    pub target: Target<'a>,
    pub provenance: Provenance<'a>,
    pub expected_length: usize,
    pub expected_sha256: [u8; 32],
    pub bytes: B,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub name: ErrorName,
    pub kind: ErrorKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidName,
    InvalidTarget(&'static str),
    InvalidProvenance(&'static str),
    InvalidRequirement,
    Missing,
    WrongTarget,
    Truncated {
        expected: usize,
        actual: usize,
    },
    LengthMismatch {
        expected: usize,
        actual: usize,
    },
    DigestMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    Duplicate,
    Conflict,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "firmware {}: {:?}", self.name, self.kind)
    }
}

impl core::error::Error for Error {}

#[derive(Debug, PartialEq, Eq)]
struct OwnedTarget {
    driver: String,
    hardware: String,
    revision: String,
    board: Option<String>,
}

impl OwnedTarget {
    fn view(&self) -> Target<'_> {
        Target {
            driver: &self.driver,
            hardware: &self.hardware,
            revision: &self.revision,
            board: self.board.as_deref(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct OwnedProvenance {
    source: String,
    revision: String,
    member: String,
    license: String,
}

impl OwnedProvenance {
    fn view(&self) -> Provenance<'_> {
        Provenance {
            source: &self.source,
            revision: &self.revision,
            member: &self.member,
            license: &self.license,
        }
    }
}

#[derive(Debug)]
enum Bytes {
    Owned(Vec<u8>),
    Persistent(&'static [u8]),
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Persistent(bytes) => bytes,
        }
    }
}

#[derive(Debug)]
struct Entry {
    name: String,
    target: OwnedTarget,
    provenance: OwnedProvenance,
    sha256: [u8; 32],
    bytes: Bytes,
}

/// Immutable verified resource catalog. Failed construction publishes no entries.
/// Loading never performs filesystem IO, allocates image copies or tries fallback
/// resource names. Drivers retain responsibility for choosing compatible APIs.
pub struct Catalog {
    entries: Vec<Entry>,
}

impl fmt::Debug for Catalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (images, bytes) = self.inventory();
        f.debug_struct("Catalog")
            .field("images", &images)
            .field("bytes", &bytes)
            .finish()
    }
}

/// Lifetime-checked, immutable image lookup. Implementations must preserve exact
/// name/target matching and integrity checks before publishing an [`Image`].
/// Other providers can select/delegate to validated catalogs; images cannot be
/// constructed from unchecked bytes through this interface.
pub trait Provider {
    fn load(&self, requirement: Requirement<'_>) -> Result<Image<'_>, Error>;
}

/// Borrow the boot handoff's optional catalog through the same exact provider
/// contract. Absence behaves like an empty catalog, including validation of
/// malformed requirements before reporting a missing resource.
pub struct HandoffProvider<'a> {
    catalog: Option<&'a Catalog>,
}

impl<'a> HandoffProvider<'a> {
    pub const fn new(catalog: Option<&'a Catalog>) -> Self {
        Self { catalog }
    }
}

impl Provider for HandoffProvider<'_> {
    fn load(&self, requirement: Requirement<'_>) -> Result<Image<'_>, Error> {
        static EMPTY: Catalog = Catalog {
            entries: Vec::new(),
        };
        self.catalog.unwrap_or(&EMPTY).load(requirement)
    }
}

/// An immutable image borrowed from a catalog; no device upload has occurred.
#[derive(Clone, Copy)]
pub struct Image<'a> {
    entry: &'a Entry,
}

impl<'a> Image<'a> {
    pub fn name(self) -> &'a str {
        &self.entry.name
    }
    pub fn target(self) -> Target<'a> {
        self.entry.target.view()
    }
    pub fn provenance(self) -> Provenance<'a> {
        self.entry.provenance.view()
    }
    pub fn sha256(self) -> [u8; 32] {
        self.entry.sha256
    }
    pub fn bytes(self) -> &'a [u8] {
        self.entry.bytes.as_ref()
    }
}

impl fmt::Debug for Image<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Image")
            .field("name", &self.name())
            .field("target", &self.target())
            .field("provenance", &self.provenance())
            .field("sha256", &self.sha256())
            .field("length", &self.bytes().len())
            .finish()
    }
}

impl Catalog {
    pub fn from_handoff(resources: Vec<Resource<'_>>) -> Result<Self, Error> {
        Self::from_resources(resources, Bytes::Owned)
    }

    /// Permanent immutable loader pages or static data, without an image copy.
    /// The caller must obtain actual static references; constructing references
    /// from physical addresses remains the platform's unsafe mapping boundary.
    pub fn from_persistent_handoff(
        resources: Vec<Resource<'_, &'static [u8]>>,
    ) -> Result<Self, Error> {
        Self::from_resources(resources, Bytes::Persistent)
    }

    /// Number and total bytes of immutable resources, for boot diagnostics.
    pub fn inventory(&self) -> (usize, usize) {
        (
            self.entries.len(),
            self.entries
                .iter()
                .map(|entry| entry.bytes.as_ref().len())
                .sum(),
        )
    }

    fn from_resources<B>(
        resources: Vec<Resource<'_, B>>,
        wrap: impl Fn(B) -> Bytes,
    ) -> Result<Self, Error> {
        let mut entries: Vec<Entry> = Vec::with_capacity(resources.len());
        for resource in resources {
            let fail = |kind| error(resource.name, kind);
            validate(resource.name, resource.target)?;
            let provenance = resource.provenance;
            for (field, value) in [
                ("source", provenance.source),
                ("revision", provenance.revision),
                ("license", provenance.license),
            ] {
                if !label(value) {
                    return Err(fail(ErrorKind::InvalidProvenance(field)));
                }
            }
            if !path(provenance.member) {
                return Err(fail(ErrorKind::InvalidProvenance("member")));
            }
            let bytes = wrap(resource.bytes);
            let actual = bytes.as_ref().len();
            if actual < resource.expected_length {
                return Err(fail(ErrorKind::Truncated {
                    expected: resource.expected_length,
                    actual,
                }));
            }
            if actual != resource.expected_length {
                return Err(fail(ErrorKind::LengthMismatch {
                    expected: resource.expected_length,
                    actual,
                }));
            }
            let sha256: [u8; 32] = Sha256::digest(bytes.as_ref()).into();
            if sha256 != resource.expected_sha256 {
                return Err(fail(ErrorKind::DigestMismatch {
                    expected: resource.expected_sha256,
                    actual: sha256,
                }));
            }
            if let Some(previous) = entries
                .iter()
                .find(|entry| entry.name == resource.name && entry.target.view() == resource.target)
            {
                return Err(fail(
                    if previous.sha256 == sha256
                        && previous.bytes.as_ref() == bytes.as_ref()
                        && previous.provenance.view() == provenance
                    {
                        ErrorKind::Duplicate
                    } else {
                        ErrorKind::Conflict
                    },
                ));
            }
            entries.push(Entry {
                name: resource.name.into(),
                target: OwnedTarget {
                    driver: resource.target.driver.into(),
                    hardware: resource.target.hardware.into(),
                    revision: resource.target.revision.into(),
                    board: resource.target.board.map(String::from),
                },
                provenance: OwnedProvenance {
                    source: provenance.source.into(),
                    revision: provenance.revision.into(),
                    member: provenance.member.into(),
                    license: provenance.license.into(),
                },
                sha256,
                bytes,
            });
        }
        Ok(Self { entries })
    }
}

impl Provider for Catalog {
    fn load(&self, requirement: Requirement<'_>) -> Result<Image<'_>, Error> {
        validate(requirement.name, requirement.target)?;
        let fail = |kind| error(requirement.name, kind);
        if requirement.minimum_bytes == 0 {
            return Err(fail(ErrorKind::InvalidRequirement));
        }
        let mut named = false;
        for entry in &self.entries {
            if entry.name != requirement.name {
                continue;
            }
            named = true;
            if entry.target.view() != requirement.target {
                continue;
            }
            if entry.bytes.as_ref().len() < requirement.minimum_bytes {
                return Err(fail(ErrorKind::Truncated {
                    expected: requirement.minimum_bytes,
                    actual: entry.bytes.as_ref().len(),
                }));
            }
            return Ok(Image { entry });
        }
        Err(fail(if named {
            ErrorKind::WrongTarget
        } else {
            ErrorKind::Missing
        }))
    }
}

fn error(name: &str, kind: ErrorKind) -> Error {
    Error {
        name: name.into(),
        kind,
    }
}

fn validate(name: &str, target: Target<'_>) -> Result<(), Error> {
    if !path(name) {
        return Err(error(name, ErrorKind::InvalidName));
    }
    for (field, value) in [
        ("driver", target.driver),
        ("hardware", target.hardware),
        ("revision", target.revision),
    ] {
        if !label(value) {
            return Err(error(name, ErrorKind::InvalidTarget(field)));
        }
    }
    if target.board.is_some_and(|board| !label(board)) {
        return Err(error(name, ErrorKind::InvalidTarget("board")));
    }
    Ok(())
}

fn label(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

fn path(value: &str) -> bool {
    label(value)
        && !value.contains('\\')
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST SHA-256 vector; all firmware contents here are synthetic fixtures.
    const ABC_SHA: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    fn target() -> Target<'static> {
        Target {
            driver: "iwlwifi",
            hardware: "8086:2725",
            revision: "ty-a0-gf-a0",
            board: None,
        }
    }
    fn requirement() -> Requirement<'static> {
        Requirement {
            name: "iwlwifi-ty-a0-gf-a0-89.ucode",
            target: target(),
            minimum_bytes: 3,
        }
    }
    fn resource() -> Resource<'static> {
        Resource {
            name: requirement().name,
            target: target(),
            provenance: Provenance {
                source: "synthetic-fixtures",
                revision: "v1",
                member: "fixtures/abc.bin",
                license: "CC0-1.0",
            },
            expected_length: 3,
            expected_sha256: ABC_SHA,
            bytes: b"abc".to_vec(),
        }
    }
    fn rejected(resources: Vec<Resource<'_>>) -> ErrorKind {
        match Catalog::from_handoff(resources) {
            Err(error) => error.kind,
            Ok(_) => panic!("invalid catalog published"),
        }
    }

    #[test]
    fn immutable_handoff_moves_buffer_and_owns_metadata() {
        let source = String::from("temporary-source");
        let revision = String::from("temporary-revision");
        let mut input = resource();
        input.provenance.source = &source;
        input.target.revision = &revision;
        let original_buffer = input.bytes.as_ptr();
        let catalog = Catalog::from_handoff(vec![input]).unwrap();
        drop(source);
        drop(revision);
        let provider: &dyn Provider = &catalog;
        let image = provider
            .load(Requirement {
                target: Target {
                    revision: "temporary-revision",
                    ..target()
                },
                ..requirement()
            })
            .unwrap();
        assert_eq!(image.bytes().as_ptr(), original_buffer);
        assert_eq!(image.bytes(), b"abc");
        assert_eq!(image.sha256(), ABC_SHA);
        assert_eq!(image.provenance().source, "temporary-source");
        assert_eq!(image.name(), requirement().name);
        assert_eq!(catalog.entries.len(), 1);
    }

    #[test]
    fn optional_handoff_provider_preserves_validation_and_missing_resource_details() {
        let provider = HandoffProvider::new(None);
        let empty = Catalog::from_handoff(vec![]).unwrap();
        for request in [
            requirement(),
            Requirement {
                name: "../invalid",
                ..requirement()
            },
            Requirement {
                minimum_bytes: 0,
                ..requirement()
            },
            Requirement {
                target: Target {
                    hardware: "",
                    ..target()
                },
                ..requirement()
            },
        ] {
            assert_eq!(
                provider.load(request).unwrap_err(),
                empty.load(request).unwrap_err()
            );
        }
        let missing = provider.load(requirement()).unwrap_err();
        assert_eq!(missing.name, requirement().name);
        assert_eq!(missing.kind, ErrorKind::Missing);
    }

    #[test]
    fn optional_handoff_provider_borrows_exact_catalog_images_without_fallback_or_copy() {
        let resource = resource();
        let original = resource.bytes.as_ptr();
        let catalog = Catalog::from_handoff(vec![resource]).unwrap();
        let provider = HandoffProvider::new(Some(&catalog));
        let image = provider.load(requirement()).unwrap();
        assert_eq!(image.bytes().as_ptr(), original);
        assert_eq!(image.sha256(), ABC_SHA);
        assert_eq!(image.provenance().member, "fixtures/abc.bin");
        for request in [
            Requirement {
                target: Target {
                    revision: "different-api",
                    ..target()
                },
                ..requirement()
            },
            Requirement {
                target: Target {
                    board: Some("different-board"),
                    ..target()
                },
                ..requirement()
            },
            Requirement {
                name: "another.bin",
                ..requirement()
            },
            Requirement {
                minimum_bytes: 4,
                ..requirement()
            },
        ] {
            assert_eq!(
                provider.load(request).unwrap_err(),
                catalog.load(request).unwrap_err()
            );
        }
        assert_eq!(
            provider
                .load(Requirement {
                    target: Target {
                        revision: "different-api",
                        ..target()
                    },
                    ..requirement()
                })
                .unwrap_err()
                .kind,
            ErrorKind::WrongTarget
        );
    }

    #[test]
    fn every_identity_component_and_name_is_exact() {
        let catalog = Catalog::from_handoff(vec![resource()]).unwrap();
        for target in [
            Target {
                driver: "btintel",
                ..target()
            },
            Target {
                hardware: "8086:2723",
                ..target()
            },
            Target {
                revision: "ty-a1-gf-a0",
                ..target()
            },
            Target {
                board: Some("oem-board"),
                ..target()
            },
        ] {
            assert_eq!(
                catalog
                    .load(Requirement {
                        target,
                        ..requirement()
                    })
                    .unwrap_err()
                    .kind,
                ErrorKind::WrongTarget
            );
        }
        assert_eq!(
            catalog
                .load(Requirement {
                    name: "iwlwifi-ty-a0-gf-a0-88.ucode",
                    ..requirement()
                })
                .unwrap_err()
                .kind,
            ErrorKind::Missing
        );
        let empty = Catalog::from_handoff(vec![]).unwrap();
        assert_eq!(
            empty.load(requirement()).unwrap_err().kind,
            ErrorKind::Missing
        );
    }

    #[test]
    fn same_filename_can_bind_distinct_boards_and_revisions() {
        let mut board = resource();
        board.target.board = Some("board-one");
        board.bytes = b"abd".to_vec();
        board.expected_sha256 = Sha256::digest(&board.bytes).into();
        let mut revision = resource();
        revision.target.revision = "b0";
        let catalog = Catalog::from_handoff(vec![resource(), board, revision]).unwrap();
        assert_eq!(catalog.load(requirement()).unwrap().bytes(), b"abc");
        assert_eq!(
            catalog
                .load(Requirement {
                    target: Target {
                        board: Some("board-one"),
                        ..target()
                    },
                    ..requirement()
                })
                .unwrap()
                .bytes(),
            b"abd"
        );
        assert_eq!(
            catalog
                .load(Requirement {
                    target: Target {
                        revision: "b0",
                        ..target()
                    },
                    ..requirement()
                })
                .unwrap()
                .target()
                .revision,
            "b0"
        );
        assert_eq!(
            catalog
                .load(Requirement {
                    target: Target {
                        board: Some("board-two"),
                        ..target()
                    },
                    ..requirement()
                })
                .unwrap_err()
                .kind,
            ErrorKind::WrongTarget
        );
        let mut board_only = resource();
        board_only.target.board = Some("board-one");
        let catalog = Catalog::from_handoff(vec![board_only]).unwrap();
        assert_eq!(
            catalog.load(requirement()).unwrap_err().kind,
            ErrorKind::WrongTarget
        );
    }

    #[test]
    fn manifest_detects_truncation_extra_bytes_and_corruption() {
        for (bytes, expected_kind) in [
            (
                b"ab".to_vec(),
                ErrorKind::Truncated {
                    expected: 3,
                    actual: 2,
                },
            ),
            (
                b"abcd".to_vec(),
                ErrorKind::LengthMismatch {
                    expected: 3,
                    actual: 4,
                },
            ),
        ] {
            let mut input = resource();
            input.bytes = bytes;
            assert_eq!(rejected(vec![resource(), input]), expected_kind);
        }
        let mut input = resource();
        input.bytes[2] = b'd';
        let ErrorKind::DigestMismatch { expected, actual } = rejected(vec![input]) else {
            panic!("corruption accepted");
        };
        assert_eq!(expected, ABC_SHA);
        assert_ne!(actual, expected);
    }

    #[test]
    fn duplicate_and_conflicting_bindings_are_rejected() {
        assert_eq!(rejected(vec![resource(), resource()]), ErrorKind::Duplicate);
        let mut different = resource();
        different.bytes = b"abd".to_vec();
        different.expected_sha256 = Sha256::digest(&different.bytes).into();
        assert_eq!(rejected(vec![resource(), different]), ErrorKind::Conflict);
        let mut provenance = resource();
        provenance.provenance.revision = "v2";
        assert_eq!(rejected(vec![resource(), provenance]), ErrorKind::Conflict);
    }

    #[test]
    fn canonical_paths_and_nonempty_identities_are_required() {
        for name in [
            "", "/abc", "abc/", "a//b", "a/./b", "a/../b", "a\\b", "a\0b", "a\nb",
        ] {
            let mut input = resource();
            input.name = name;
            assert_eq!(rejected(vec![input]), ErrorKind::InvalidName);
        }
        for (field, target) in [
            (
                "driver",
                Target {
                    driver: "",
                    ..target()
                },
            ),
            (
                "hardware",
                Target {
                    hardware: "bad\0id",
                    ..target()
                },
            ),
            (
                "revision",
                Target {
                    revision: "",
                    ..target()
                },
            ),
            (
                "board",
                Target {
                    board: Some(""),
                    ..target()
                },
            ),
        ] {
            let mut input = resource();
            input.target = target;
            assert_eq!(rejected(vec![input]), ErrorKind::InvalidTarget(field));
        }
        let mut input = resource();
        input.provenance.member = "../firmware";
        assert_eq!(
            rejected(vec![input]),
            ErrorKind::InvalidProvenance("member")
        );
        let mut input = resource();
        input.provenance.source = "";
        assert_eq!(
            rejected(vec![input]),
            ErrorKind::InvalidProvenance("source")
        );
        let mut input = resource();
        input.provenance.revision = "";
        assert_eq!(
            rejected(vec![input]),
            ErrorKind::InvalidProvenance("revision")
        );
        let mut input = resource();
        input.provenance.license = "";
        assert_eq!(
            rejected(vec![input]),
            ErrorKind::InvalidProvenance("license")
        );
    }

    #[test]
    fn invalid_name_diagnostics_escape_control_characters() {
        let mut input = resource();
        input.name = "bad\n\0\x1b[31m";
        let error = Catalog::from_handoff(vec![input]).err().unwrap();
        let rendered = alloc::format!("{error}");
        assert_eq!(rendered, "firmware \"bad\\n\\0\\u{1b}[31m\": InvalidName");
        assert!(!rendered.chars().any(char::is_control));
    }

    #[test]
    fn valid_manifest_does_not_override_driver_minimum_length() {
        let catalog = Catalog::from_handoff(vec![resource()]).unwrap();
        assert_eq!(
            catalog
                .load(Requirement {
                    minimum_bytes: 4,
                    ..requirement()
                })
                .unwrap_err()
                .kind,
            ErrorKind::Truncated {
                expected: 4,
                actual: 3
            }
        );
        assert_eq!(
            catalog
                .load(Requirement {
                    minimum_bytes: 0,
                    ..requirement()
                })
                .unwrap_err()
                .kind,
            ErrorKind::InvalidRequirement
        );
        let mut input = resource();
        input.bytes.clear();
        input.expected_length = 0;
        input.expected_sha256 = Sha256::digest([]).into();
        let catalog = Catalog::from_handoff(vec![input]).unwrap();
        assert_eq!(
            catalog.load(requirement()).unwrap_err().kind,
            ErrorKind::Truncated {
                expected: 3,
                actual: 0
            }
        );
    }
}
