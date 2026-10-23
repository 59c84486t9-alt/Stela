//! Bounded host-device firmware manifest. This is independent of Apple boot
//! bundles: names select exact driver requirements, paths select files beneath
//! `EFI/stela/firmware` on the same boot volume. Hashes establish integrity
//! against this manifest, not vendor authentication or permission to distribute.
use alloc::{format, string::String, vec::Vec};
use core::fmt;
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use stela_drivers::firmware::{Catalog, Provenance, Resource, Target};

/// Native host capability, independent of the guest bundle/options schema.
/// Revision 1 permits 16 MiB per image, revision 2 permits 64 MiB. Both keep
/// schema 1, 64 images and 64 MiB aggregate; changing these requires a revision.
pub const MOUNT_CAPABILITY: [u8; 21] = *b"STELA-HOST-FIRMWARE\0\x02";
pub fn supports_mount(image: &[u8]) -> bool {
    MountLimits::from_image(image).is_some()
}

/// Bounds advertised by an EFI image, independent of manifest schema 1.
#[derive(Clone, Copy, Debug)]
pub struct MountLimits {
    max_image_bytes: usize,
}

impl MountLimits {
    pub fn from_image(image: &[u8]) -> Option<Self> {
        let mut revision = 0;
        for marker in image.windows(MOUNT_CAPABILITY.len()) {
            if marker[..20] != MOUNT_CAPABILITY[..20] {
                continue;
            }
            match marker[20] {
                1 | 2 => revision = revision.max(marker[20]),
                // Never interpret an unknown mount contract as an older one.
                _ => return None,
            }
        }
        match revision {
            1 => Some(Self {
                max_image_bytes: 16 * 1024 * 1024,
            }),
            2 => Some(Self {
                max_image_bytes: MAX_IMAGE_BYTES,
            }),
            _ => None,
        }
    }

    /// Check metadata before payload allocation, download or publication.
    pub fn check_lengths(&self, lengths: impl IntoIterator<Item = usize>) -> Result<(), Error> {
        let mut count = 0usize;
        let mut total = 0usize;
        for length in lengths {
            if length == 0 || length > self.max_image_bytes {
                return Err(Error(format!(
                    "stela.efi host firmware image limit is {} bytes; update Stela before installing this package",
                    self.max_image_bytes
                )));
            }
            count += 1;
            total = total
                .checked_add(length)
                .ok_or_else(|| fail("host firmware total overflows its budget"))?;
            if count > MAX_IMAGES || total > MAX_TOTAL_BYTES {
                return Err(fail("host firmware resources exceed the mount budget"));
            }
        }
        Ok(())
    }
}

pub const MANIFEST_PATH: &str = "EFI/stela/firmware/manifest.json";
pub const DIRECTORY: &str = "EFI/stela/firmware";
pub const MAX_MANIFEST_BYTES: usize = 128 * 1024;
pub const MAX_IMAGES: usize = 64;
pub const MAX_IMAGE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_LABEL_BYTES: usize = 256;
pub const MAX_PATH_BYTES: usize = 240;

pub mod recipes;
pub mod requirements;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest<'a> {
    pub schema: u32,
    #[serde(borrow, deserialize_with = "bounded_images")]
    pub images: Vec<Image<'a>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image<'a> {
    /// Logical Linux/vendor name, case-exact and independent of the FAT path.
    pub name: &'a str,
    /// Canonical lower-case FAT-safe path relative to DIRECTORY.
    pub path: &'a str,
    #[serde(borrow)]
    pub target: Identity<'a>,
    #[serde(borrow)]
    pub provenance: Source<'a>,
    pub length: usize,
    pub sha256: &'a str,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity<'a> {
    pub driver: &'a str,
    pub hardware: &'a str,
    pub revision: &'a str,
    pub board: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source<'a> {
    pub source: &'a str,
    pub revision: &'a str,
    pub member: &'a str,
    pub license: &'a str,
}

fn bounded_images<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Image<'de>>, D::Error> {
    struct Images;
    impl<'de> Visitor<'de> for Images {
        type Value = Vec<Image<'de>>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {MAX_IMAGES} firmware resources")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut images = Vec::new();
            while let Some(image) = seq.next_element()? {
                if images.len() == MAX_IMAGES {
                    return Err(de::Error::custom("too many firmware resources"));
                }
                images.push(image);
            }
            Ok(images)
        }
    }
    deserializer.deserialize_seq(Images)
}

/// Plain, bounded diagnostic suitable for a setup error or pre-boot refusal.
#[derive(Debug)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl core::error::Error for Error {}
fn fail(message: &str) -> Error {
    Error(message.into())
}

impl<'a> Manifest<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(fail("host firmware manifest exceeds 128 KiB"));
        }
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|e| Error(format!("host firmware manifest: {e}")))?;
        if manifest.schema != 1 {
            return Err(fail("unsupported host firmware manifest schema"));
        }
        let mut total = 0usize;
        for (index, image) in manifest.images.iter().enumerate() {
            if !logical_path(image.name)
                || !storage_path(image.path)
                || image.path == "manifest.json"
            {
                return Err(fail("invalid host firmware name or storage path"));
            }
            for label in [
                image.target.driver,
                image.target.hardware,
                image.target.revision,
                image.provenance.source,
                image.provenance.revision,
                image.provenance.license,
            ] {
                if !valid_label(label) {
                    return Err(fail("invalid host firmware identity/provenance label"));
                }
            }
            if image.target.board.is_some_and(|board| !valid_label(board))
                || !logical_path(image.provenance.member)
            {
                return Err(fail("invalid host firmware board or source member"));
            }
            if image.length == 0 || image.length > MAX_IMAGE_BYTES {
                return Err(fail("host firmware image exceeds the nonzero 64 MiB limit"));
            }
            total = total
                .checked_add(image.length)
                .filter(|n| *n <= MAX_TOTAL_BYTES)
                .ok_or_else(|| fail("host firmware total exceeds 64 MiB"))?;
            image.digest()?;
            for previous in &manifest.images[..index] {
                if previous.path == image.path {
                    return Err(fail("duplicate host firmware storage path"));
                }
                if previous.name == image.name && previous.target == image.target {
                    return Err(fail("duplicate host firmware identity"));
                }
            }
        }
        Ok(manifest)
    }

    pub fn total_bytes(&self) -> usize {
        self.images.iter().map(|image| image.length).sum()
    }

    pub fn check_mount(&self, image: &[u8]) -> Result<(), Error> {
        MountLimits::from_image(image)
            .ok_or_else(|| fail("stela.efi has no supported host firmware mount capability"))?
            .check_lengths(self.images.iter().map(|image| image.length))
    }

    /// Build metadata in the active allocator; permanent pages are never copied.
    /// Each slice must actually remain immutable and mapped for this catalog's
    /// lifetime. Physical-to-reference construction belongs to the platform.
    pub fn catalog(&self, bytes: &[&'static [u8]]) -> Result<Catalog, Error> {
        self.catalog_with(bytes, Vec::new())
    }

    /// Add platform-observed permanent resources in the same validation pass.
    /// Descriptor borrows are copied into catalog metadata; image bytes remain
    /// in the caller's immutable permanent mappings.
    pub fn catalog_with<'b>(
        &'b self,
        bytes: &[&'static [u8]],
        additional: Vec<Resource<'b, &'static [u8]>>,
    ) -> Result<Catalog, Error> {
        if bytes.len() != self.images.len() {
            return Err(fail("host firmware handoff count mismatch"));
        }
        if self
            .images
            .len()
            .checked_add(additional.len())
            .is_none_or(|count| count > MAX_IMAGES)
            || additional
                .iter()
                .any(|resource| resource.bytes.len() > MAX_IMAGE_BYTES)
            || self
                .images
                .iter()
                .map(|image| image.length)
                .chain(additional.iter().map(|resource| resource.bytes.len()))
                .try_fold(0usize, |total, bytes| total.checked_add(bytes))
                .is_none_or(|total| total > MAX_TOTAL_BYTES)
        {
            return Err(fail("combined host firmware resources exceed their budget"));
        }
        let mut resources = self
            .images
            .iter()
            .zip(bytes)
            .map(|(image, bytes)| {
                Ok(Resource {
                    name: image.name,
                    target: Target {
                        driver: image.target.driver,
                        hardware: image.target.hardware,
                        revision: image.target.revision,
                        board: image.target.board,
                    },
                    provenance: Provenance {
                        source: image.provenance.source,
                        revision: image.provenance.revision,
                        member: image.provenance.member,
                        license: image.provenance.license,
                    },
                    expected_length: image.length,
                    expected_sha256: image.digest()?,
                    bytes: *bytes,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        resources.extend(additional);
        Catalog::from_persistent_handoff(resources).map_err(|e| Error(format!("host {e}")))
    }
}

impl Image<'_> {
    pub fn digest(&self) -> Result<[u8; 32], Error> {
        if self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(fail(
                "host firmware SHA-256 must be 64 lower-case hex digits",
            ));
        }
        let mut out = [0; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&self.sha256[index * 2..index * 2 + 2], 16)
                .map_err(|_| fail("invalid host firmware digest"))?;
        }
        Ok(out)
    }
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_BYTES
        && label.bytes().all(|b| (0x20..=0x7e).contains(&b))
}
fn logical_path(path: &str) -> bool {
    valid_label(path)
        && !path.contains('\\')
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}
/// Storage paths have one representation: no drive names, UEFI separators,
/// traversal, trailing-dot/space aliases, DOS device names or 8.3 tilde aliases.
pub fn storage_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return false;
    }
    path.split('/').all(|part| {
        if part.is_empty() || part.len() > 64 || part.starts_with('.') || part.ends_with('.') {
            return false;
        }
        if !part.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        }) {
            return false;
        }
        let stem = part.split('.').next().unwrap_or("");
        !matches!(stem, "con" | "prn" | "aux" | "nul")
            && !["com", "lpt"].iter().any(|prefix| {
                stem.strip_prefix(prefix).is_some_and(|suffix| {
                    suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
                })
            })
    })
}

#[cfg(feature = "std")]
mod package;
#[cfg(feature = "std")]
pub use package::{Package, check_installed_mount};

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec};
    use serde_json::{Value, json};
    use stela_drivers::firmware::{Provider, Requirement};

    fn image() -> Value {
        json!({"name":"Vendor/FW.bin", "path":"vendor/fw.bin",
            "target":{"driver":"realtek","hardware":"10ec:8168","revision":"xid-509","board":null},
            "provenance":{"source":"synthetic-fixture","revision":"v1","member":"fixtures/abc.bin","license":"CC0-1.0"},
            "length":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"})
    }
    fn manifest(images: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({"schema":1,"images":images})).unwrap()
    }

    #[test]
    fn mount_revision_checks_each_image_without_downgrading_unknown_contracts() {
        let mut legacy = MOUNT_CAPABILITY;
        legacy[20] = 1;
        let mut unknown = MOUNT_CAPABILITY;
        unknown[20] = 3;
        let current = MountLimits::from_image(&MOUNT_CAPABILITY).unwrap();
        let old = MountLimits::from_image(&legacy).unwrap();
        assert!(old.check_lengths([16 * 1024 * 1024]).is_ok());
        assert!(old.check_lengths([16 * 1024 * 1024 + 1]).is_err());
        assert!(current.check_lengths([MAX_IMAGE_BYTES]).is_ok());
        assert!(current.check_lengths([MAX_IMAGE_BYTES, 1]).is_err());
        assert!(current.check_lengths([0]).is_err());
        assert!(current.check_lengths([1; MAX_IMAGES + 1]).is_err());
        // Exact measured GB203 lengths, metadata only; no firmware is embedded.
        let lengths = [63_571_696, 200_812, 199_820];
        assert!(current.check_lengths(lengths).is_ok());
        assert!(old.check_lengths(lengths).is_err());
        assert!(current.check_lengths([63_571_696, 200_812, 199_820, 3_136_536]).is_ok());
        assert!(current.check_lengths([63_571_696, 200_812, 199_820, 3_136_537]).is_err());
        for length in [16 * 1024 * 1024, 16 * 1024 * 1024 + 1, MAX_IMAGE_BYTES] {
            let mut item = image();
            item["length"] = json!(length);
            let bytes = manifest(vec![item]);
            let parsed = Manifest::parse(&bytes).unwrap();
            assert!(parsed.check_mount(&MOUNT_CAPABILITY).is_ok());
            assert_eq!(parsed.check_mount(&legacy).is_ok(), length <= 16 * 1024 * 1024);
        }
        assert!(!supports_mount(b""));
        assert!(!supports_mount(&MOUNT_CAPABILITY[..20]));
        assert!(!supports_mount(&unknown));
        let mut mixed = legacy.to_vec();
        mixed.extend_from_slice(&MOUNT_CAPABILITY);
        assert!(MountLimits::from_image(&mixed).unwrap().check_lengths(lengths).is_ok());
        mixed.extend_from_slice(&unknown);
        assert!(!supports_mount(&mixed));
    }

    #[cfg(feature = "std")]
    #[test]
    fn installed_mount_checks_bounded_metadata_before_efi_replacement() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("firmware");
        assert!(check_installed_mount(&directory, b"legacy-no-mount").is_ok());
        std::fs::create_dir(&directory).unwrap();
        assert!(check_installed_mount(&directory, b"legacy-no-mount").is_ok());
        let mut item = image();
        item["length"] = json!(63_571_696);
        std::fs::write(directory.join("manifest.json"), manifest(vec![item])).unwrap();
        let mut legacy = MOUNT_CAPABILITY;
        legacy[20] = 1;
        assert!(check_installed_mount(&directory, &legacy).is_err());
        let error = Package::read_for_mount(&directory, &legacy).err().unwrap();
        assert!(error.to_string().contains("image limit"));
        // A compatible mount proceeds to the absent payload and refuses it.
        let error = Package::read_for_mount(&directory, &MOUNT_CAPABILITY).err().unwrap();
        assert!(error.to_string().contains("missing host firmware package file"));
        assert!(check_installed_mount(&directory, &MOUNT_CAPABILITY).is_ok());
        assert!(check_installed_mount(&directory, b"legacy-no-mount").is_err());
        for bytes in [b"{}".to_vec(), vec![b' '; MAX_MANIFEST_BYTES + 1]] {
            std::fs::write(directory.join("manifest.json"), bytes).unwrap();
            assert!(check_installed_mount(&directory, &MOUNT_CAPABILITY).is_err());
        }
        #[cfg(unix)]
        {
            let path = directory.join("manifest.json");
            std::fs::remove_file(&path).unwrap();
            let external = root.path().join("external.json");
            std::fs::write(&external, manifest(vec![image()])).unwrap();
            std::os::unix::fs::symlink(&external, &path).unwrap();
            assert!(check_installed_mount(&directory, &MOUNT_CAPABILITY).is_err());
        }
    }

    #[test]
    fn additional_permanent_resources_share_one_validation_pass_without_copying() {
        static RAW: [u8; 3] = *b"abc";
        let input = manifest(vec![image()]);
        let parsed = Manifest::parse(&input).unwrap();
        let extra = || Resource {
            name: "platform/raw.bin",
            target: Target {
                driver: "platform",
                hardware: "uefi:test",
                revision: "observed",
                board: None,
            },
            provenance: Provenance {
                source: "synthetic",
                revision: "v1",
                member: "raw.bin",
                license: "CC0-1.0",
            },
            expected_length: 3,
            expected_sha256: parsed.images[0].digest().unwrap(),
            bytes: &RAW[..],
        };
        let catalog = parsed.catalog_with(&[&RAW], vec![extra()]).unwrap();
        let loaded = catalog
            .load(Requirement {
                name: "platform/raw.bin",
                target: extra().target,
                minimum_bytes: 3,
            })
            .unwrap();
        assert_eq!(catalog.inventory(), (2, 6));
        assert_eq!(loaded.bytes().as_ptr(), RAW.as_ptr());
        assert!(
            parsed
                .catalog_with(&[&RAW], vec![extra(), extra()])
                .is_err()
        );
        assert!(
            parsed
                .catalog_with(&[&RAW], (0..MAX_IMAGES).map(|_| extra()).collect())
                .is_err()
        );
        let mut corrupt = extra();
        corrupt.expected_sha256 = [0; 32];
        assert!(parsed.catalog_with(&[&RAW], vec![corrupt]).is_err());
        let mut collision = extra();
        collision.name = parsed.images[0].name;
        collision.target = Target {
            driver: "realtek",
            hardware: "10ec:8168",
            revision: "xid-509",
            board: None,
        };
        assert!(parsed.catalog_with(&[&RAW], vec![collision]).is_err());
    }

    #[test]
    fn permanent_bytes_keep_pointer_identity_across_metadata_reconstruction_and_arc_clones() {
        let bytes = manifest(vec![image()]);
        let parsed = Manifest::parse(&bytes).unwrap();
        let persistent: &'static [u8] = Box::leak(b"abc".to_vec().into_boxed_slice());
        let before = parsed.catalog(&[persistent]).unwrap();
        assert_eq!(before.inventory(), (1, 3));
        drop(before);
        let catalog = alloc::sync::Arc::new(parsed.catalog(&[persistent]).unwrap());
        let copy = catalog.clone();
        assert!(alloc::sync::Arc::ptr_eq(&catalog, &copy));
        let requirement = Requirement {
            name: "Vendor/FW.bin",
            target: Target {
                driver: "realtek",
                hardware: "10ec:8168",
                revision: "xid-509",
                board: None,
            },
            minimum_bytes: 3,
        };
        let loaded = copy.load(requirement).unwrap();
        assert_eq!(loaded.bytes().as_ptr(), persistent.as_ptr());
        assert_eq!(loaded.provenance().license, "CC0-1.0");
        assert!(
            copy.load(Requirement {
                name: "vendor/fw.bin",
                ..requirement
            })
            .is_err()
        );
    }

    #[test]
    fn malformed_unknown_and_duplicate_fields_never_publish_a_manifest() {
        for bytes in [
            b"".as_slice(),
            b"{}",
            b"[]",
            b"{\"schema\":1,\"schema\":1,\"images\":[]}",
            b"{\"schema\":1,\"images\":[],\"fallback\":true}",
            b"{\"schema\":2,\"images\":[]}",
        ] {
            assert!(Manifest::parse(bytes).is_err(), "{bytes:?}");
        }
        let mut input = image();
        input["target"]["fallback"] = json!(true);
        assert!(Manifest::parse(&manifest(vec![input])).is_err());
        let good = String::from_utf8(manifest(vec![image()])).unwrap();
        let duplicate = good.replace("\"length\":3", "\"length\":3,\"length\":3");
        assert!(Manifest::parse(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn all_budgets_and_duplicate_bindings_are_checked_without_image_reads() {
        assert!(Manifest::parse(&vec![b' '; MAX_MANIFEST_BYTES + 1]).is_err());
        let mut input = image();
        input["name"] = json!("x".repeat(MAX_LABEL_BYTES + 1));
        assert!(Manifest::parse(&manifest(vec![input])).is_err());
        let mut input = image();
        input["target"]["revision"] = json!("x".repeat(MAX_LABEL_BYTES + 1));
        assert!(Manifest::parse(&manifest(vec![input])).is_err());
        for length in [0, MAX_IMAGE_BYTES + 1] {
            let mut input = image();
            input["length"] = json!(length);
            assert!(Manifest::parse(&manifest(vec![input])).is_err());
        }
        let mut images = Vec::new();
        for n in 0..=MAX_IMAGES {
            let mut input = image();
            input["path"] = json!(format!("file{n}.bin"));
            input["target"]["revision"] = json!(format!("rev{n}"));
            images.push(input);
        }
        assert!(Manifest::parse(&manifest(images)).is_err());
        let mut images = Vec::new();
        for n in 0..5 {
            let mut input = image();
            input["length"] = json!(MAX_IMAGE_BYTES);
            input["path"] = json!(format!("file{n}.bin"));
            input["target"]["revision"] = json!(format!("rev{n}"));
            images.push(input);
        }
        assert!(Manifest::parse(&manifest(images)).is_err());
        assert!(Manifest::parse(&manifest(vec![image(), image()])).is_err());
        let mut duplicate = image();
        duplicate["path"] = json!("other.bin");
        assert!(Manifest::parse(&manifest(vec![image(), duplicate])).is_err());
        let mut duplicate = image();
        duplicate["target"]["revision"] = json!("other");
        assert!(Manifest::parse(&manifest(vec![image(), duplicate])).is_err());
    }

    #[test]
    fn fat_aliases_and_uefi_path_escapes_are_rejected() {
        for path in [
            "",
            "/x",
            "x/",
            "x//y",
            ".",
            "..",
            "a/../b",
            "./x",
            "a\\b",
            "c:x",
            "a:b",
            "a b",
            "x.",
            "x ",
            "Vendor/fw.bin",
            "vendor/FW.bin",
            "x~1.bin",
            "con",
            "con.bin",
            "aux.bin",
            "lpt1.bin",
            "com9",
            "a\0b",
            "a\nb",
            "é.bin",
            "manifest.json",
        ] {
            let mut input = image();
            input["path"] = json!(path);
            assert!(
                Manifest::parse(&manifest(vec![input])).is_err(),
                "accepted {path:?}"
            );
        }
        assert!(storage_path("vendor/fw-1.2_test.bin"));
    }

    #[test]
    fn corruption_truncation_wrong_counts_and_bad_digests_fail() {
        let bytes = manifest(vec![image()]);
        let parsed = Manifest::parse(&bytes).unwrap();
        assert!(parsed.catalog(&[]).is_err());
        assert!(parsed.catalog(&[b"ab"]).is_err());
        assert!(parsed.catalog(&[b"abcd"]).is_err());
        assert!(parsed.catalog(&[b"abd"]).is_err());
        for hash in [
            "f",
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            "zz7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ] {
            let mut input = image();
            input["sha256"] = json!(hash);
            assert!(Manifest::parse(&manifest(vec![input])).is_err());
        }
    }

    #[cfg(feature = "std")]
    fn package(root: &std::path::Path) -> std::path::PathBuf {
        let source = root.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(source.join("vendor")).unwrap();
        std::fs::write(source.join("vendor/fw.bin"), b"abc").unwrap();
        std::fs::write(source.join("manifest.json"), manifest(vec![image()])).unwrap();
        source
    }

    #[cfg(feature = "std")]
    #[test]
    fn local_package_is_bounded_and_published_with_immutable_objects_before_manifest() {
        let root = tempfile::tempdir().unwrap();
        let source = package(root.path());
        let loaded = Package::read(&source).unwrap();
        assert_eq!(loaded.inventory(), (1, 3));
        let destination = root.path().join("firmware");
        loaded.publish(&destination).unwrap();
        let active = std::fs::read(destination.join("manifest.json")).unwrap();
        let parsed = Manifest::parse(&active).unwrap();
        assert!(parsed.images[0].path.starts_with("objects/"));
        assert_eq!(
            std::fs::read(destination.join(parsed.images[0].path)).unwrap(),
            b"abc"
        );
        assert_eq!(parsed.images[0].name, "Vendor/FW.bin");
        loaded.publish(&destination).unwrap();
        assert_eq!(
            std::fs::read(destination.join("manifest.json")).unwrap(),
            active
        );
        std::fs::write(destination.join(parsed.images[0].path), b"abd").unwrap();
        assert!(loaded.publish(&destination).is_err());
        assert_eq!(
            std::fs::read(destination.join("manifest.json")).unwrap(),
            active
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn local_loader_rejects_file_length_corruption_and_aliases_without_publication() {
        let root = tempfile::tempdir().unwrap();
        let source = package(root.path());
        for contents in [b"ab".as_slice(), b"abcd", b"abd"] {
            std::fs::write(source.join("vendor/fw.bin"), contents).unwrap();
            assert!(Package::read(&source).is_err());
        }
        std::fs::write(source.join("vendor/fw.bin"), b"abc").unwrap();
        std::fs::write(source.join("vendor/FW.BIN"), b"abc").unwrap();
        // A case-insensitive source filesystem has one entry; a case-sensitive
        // source with both spellings is ambiguous and must be rejected.
        if std::fs::read_dir(source.join("vendor")).unwrap().count() > 1 {
            assert!(Package::read(&source).is_err());
        }
        std::fs::write(
            source.join("manifest.json"),
            vec![b' '; MAX_MANIFEST_BYTES + 1],
        )
        .unwrap();
        assert!(Package::read(&source).is_err());
    }

    #[cfg(all(feature = "std", unix))]
    #[test]
    fn local_loader_and_publisher_refuse_symlink_escapes() {
        let root = tempfile::tempdir().unwrap();
        let source = package(root.path());
        let external = root.path().join("outside.bin");
        std::fs::write(&external, b"abc").unwrap();
        std::fs::remove_file(source.join("vendor/fw.bin")).unwrap();
        std::os::unix::fs::symlink(&external, source.join("vendor/fw.bin")).unwrap();
        assert!(Package::read(&source).is_err());
        std::fs::remove_file(source.join("vendor/fw.bin")).unwrap();
        std::fs::write(source.join("vendor/fw.bin"), b"abc").unwrap();
        let loaded = Package::read(&source).unwrap();
        let destination = root.path().join("firmware");
        std::fs::create_dir(&destination).unwrap();
        std::os::unix::fs::symlink(root.path(), destination.join("objects")).unwrap();
        assert!(loaded.publish(&destination).is_err());
        assert!(!destination.join("manifest.json").exists());
    }

    #[cfg(all(feature = "std", unix))]
    #[test]
    fn interruptions_before_manifest_commit_preserve_old_resources_and_allow_retry() {
        for stop in 0..5 {
            let root = tempfile::tempdir().unwrap();
            let source = package(root.path());
            let old = Package::read(&source).unwrap();
            let destination = root.path().join("firmware");
            old.publish(&destination).unwrap();
            let before = std::fs::read(destination.join("manifest.json")).unwrap();
            let parsed = Manifest::parse(&before).unwrap();
            let previous_object = destination.join(parsed.images[0].path);
            let mut changed = image();
            changed["target"]["revision"] = json!("v2");
            std::fs::write(source.join("manifest.json"), manifest(vec![changed])).unwrap();
            let next = Package::read(&source).unwrap();
            let mut checkpoints = 0;
            assert!(
                next.publish_checkpointed(&destination, |_| {
                    let at = checkpoints;
                    checkpoints += 1;
                    if at == stop {
                        Err(fail("injected interruption"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
            );
            assert_eq!(checkpoints, stop + 1);
            assert_eq!(
                std::fs::read(destination.join("manifest.json")).unwrap(),
                before
            );
            assert_eq!(std::fs::read(&previous_object).unwrap(), b"abc");
            assert_eq!(Package::read(&destination).unwrap().inventory(), (1, 3));
            next.publish(&destination).unwrap();
            let after = std::fs::read(destination.join("manifest.json")).unwrap();
            assert_eq!(
                Manifest::parse(&after).unwrap().images[0].target.revision,
                "v2"
            );
            assert_eq!(std::fs::read(&previous_object).unwrap(), b"abc");
        }
    }
}
