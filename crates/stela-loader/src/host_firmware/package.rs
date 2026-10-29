//! Setup's bounded local package reader and manifest-last publication. Immutable
//! objects live below a content-addressed package directory, so replacing the
//! active manifest never overwrites bytes the previous manifest still names.
use super::*;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use stela_crypto::{Sha256, digest::Digest};

pub struct Package {
    manifest: Vec<u8>,
    files: Vec<Vec<u8>>,
    notices: Vec<(String, Vec<u8>)>,
}
fn io(error: impl fmt::Display) -> Error {
    Error(format!("host firmware IO: {error}"))
}

fn read_bounded(path: &Path, expected: Option<usize>, limit: usize) -> Result<Vec<u8>, Error> {
    let mut file = File::open(path).map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    let length = usize::try_from(metadata.len()).map_err(io)?;
    if !metadata.is_file() || length == 0 || length > limit || expected.is_some_and(|n| n != length)
    {
        return Err(fail(
            "host firmware file exceeds its declared length or budget",
        ));
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes).map_err(io)?;
    if file.read(&mut [0]).map_err(io)? != 0 {
        return Err(fail("host firmware file grew during read"));
    }
    Ok(bytes)
}

/// Resolve a stable local source directory without following symlinks or case
/// aliases. The package is fully read and verified before destination writes.
fn resolve(root: &Path, relative: &str) -> Result<PathBuf, Error> {
    resolve_optional(root, relative)?.ok_or_else(|| fail("missing host firmware package file"))
}

fn resolve_optional(root: &Path, relative: &str) -> Result<Option<PathBuf>, Error> {
    let mut directory = root.to_path_buf();
    for component in relative.split('/') {
        let mut found = None;
        for (index, entry) in fs::read_dir(&directory).map_err(io)?.enumerate() {
            if index == 4096 {
                return Err(fail("host firmware directory has too many entries"));
            }
            let entry = entry.map_err(io)?;
            let name = entry.file_name();
            if name
                .to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(component))
            {
                if found.is_some() {
                    return Err(fail("ambiguous host firmware path case aliases"));
                }
                if entry.file_type().map_err(io)?.is_symlink() {
                    return Err(fail("host firmware source path is a symlink"));
                }
                found = Some(entry.path());
            }
        }
        let Some(found) = found else {
            return Ok(None);
        };
        directory = found;
    }
    Ok(Some(directory))
}

/// Validate an installed manifest against a candidate EFI before activation.
/// Absence is optional; malformed or unreadable present metadata is an error.
/// Payload integrity remains the package reader and boot mount's responsibility.
pub fn check_installed_mount(directory: &Path, image: &[u8]) -> Result<(), Error> {
    match fs::symlink_metadata(directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io(error)),
        Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => {}
        Ok(_) => return Err(fail("host firmware package must be a real directory")),
    }
    let Some(path) = resolve_optional(directory, "manifest.json")? else {
        return Ok(());
    };
    let bytes = read_bounded(&path, None, MAX_MANIFEST_BYTES)?;
    Manifest::parse(&bytes)?.check_mount(image)
}

pub(super) const NOTICE_MARKER: &str = "stela-notice-v1:";
const NOTICE_INDEX: &str = "provenance.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoticeIndex {
    schema: u32,
    #[serde(deserialize_with = "bounded_notices")]
    notices: Vec<NoticeEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoticeEntry {
    path: String,
    source: String,
    revision: String,
    member: String,
    length: usize,
    sha256: String,
}

fn bounded_notices<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<NoticeEntry>, D::Error> {
    struct Notices;
    impl<'de> Visitor<'de> for Notices {
        type Value = Vec<NoticeEntry>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most 63 notice artifacts")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut notices = Vec::new();
            while let Some(notice) = seq.next_element()? {
                if notices.len() == MAX_IMAGES - 1 {
                    return Err(de::Error::custom("too many firmware notices"));
                }
                notices.push(notice);
            }
            Ok(notices)
        }
    }
    deserializer.deserialize_seq(Notices)
}

fn read_notices(source: &Path, manifest: &Manifest<'_>) -> Result<Vec<(String, Vec<u8>)>, Error> {
    let mut parents = Vec::new();
    let mut selected = None;
    for image in &manifest.images {
        let parent = image.path.rsplit_once('/').map_or("", |(parent, _)| parent);
        if parents.contains(&parent) {
            continue;
        }
        parents.push(parent);
        let required = manifest.images.iter().any(|image| {
            image.path.rsplit_once('/').map_or("", |(parent, _)| parent) == parent
                && image.provenance.license.starts_with(NOTICE_MARKER)
        });
        // Legacy generated packages predate the marker and have one fixed
        // content-addressed parent. Do not interpret arbitrary extra files in
        // an ordinary local package as generated notice metadata.
        let generated = parent.strip_prefix("objects/").is_some_and(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
        if !required && !generated {
            continue;
        }
        let relative = if parent.is_empty() {
            NOTICE_INDEX.into()
        } else {
            format!("{parent}/{NOTICE_INDEX}")
        };
        if !storage_path(&relative) {
            return Err(fail("firmware notice index path exceeds its budget"));
        }
        if manifest.images.iter().any(|image| image.path == relative) {
            if required {
                return Err(fail(
                    "required firmware notice index conflicts with an image",
                ));
            }
            // The legacy directory shape is not reserved. An explicitly
            // declared firmware image keeps its meaning in unmarked packages.
            continue;
        }
        let found = resolve_optional(source, &relative)?;
        if let Some(found) = found {
            if selected.is_some() {
                return Err(fail(
                    "multiple firmware notice indexes cannot be imported losslessly",
                ));
            }
            selected = Some((parent, found, generated));
        } else if required {
            return Err(fail(
                "generated firmware package is missing required notices",
            ));
        }
    }
    let Some((parent, path, generated)) = selected else {
        return Ok(Vec::new());
    };
    let bytes = read_bounded(&path, None, MAX_MANIFEST_BYTES)?;
    let index: NoticeIndex = serde_json::from_slice(&bytes).map_err(io)?;
    if index.schema != 1 {
        return Err(fail("unsupported firmware notice index"));
    }
    let mut total = bytes.len();
    for (at, notice) in index.notices.iter().enumerate() {
        if !storage_path(&notice.path)
            || notice.path.contains('/')
            || !notice.path.ends_with(".txt")
            || !valid_label(&notice.source)
            || !valid_label(&notice.revision)
            || !logical_path(&notice.member)
            || notice.length == 0
            || notice.length > MAX_MANIFEST_BYTES
            || notice.sha256.len() != 64
            || !notice
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || index.notices[..at]
                .iter()
                .any(|other| other.path == notice.path)
        {
            return Err(fail("invalid or duplicate firmware notice entry"));
        }
        total = total
            .checked_add(notice.length)
            .filter(|n| *n <= 1024 * 1024)
            .ok_or_else(|| fail("firmware notices exceed 1 MiB"))?;
    }
    for image in &manifest.images {
        let member = image
            .provenance
            .license
            .strip_prefix(NOTICE_MARKER)
            .or_else(|| {
                (generated
                    && image.path.rsplit_once('/').map_or("", |(parent, _)| parent) == parent)
                    .then_some(image.provenance.license)
            });
        if let Some(member) = member
            && !index.notices.iter().any(|notice| {
                notice.member == member
                    && notice.source == image.provenance.source
                    && notice.revision == image.provenance.revision
            })
        {
            return Err(fail("required firmware notice provenance is missing"));
        }
    }
    let mut notices = Vec::with_capacity(index.notices.len() + 1);
    for notice in index.notices {
        let relative = if parent.is_empty() {
            notice.path.clone()
        } else {
            format!("{parent}/{}", notice.path)
        };
        if !storage_path(&relative) {
            return Err(fail("firmware notice path exceeds its budget"));
        }
        let bytes = read_bounded(
            &resolve(source, &relative)?,
            Some(notice.length),
            MAX_MANIFEST_BYTES,
        )?;
        if hex::encode(Sha256::digest(&bytes)) != notice.sha256 {
            return Err(fail("firmware notice digest mismatch"));
        }
        notices.push((notice.path, bytes));
    }
    notices.push((NOTICE_INDEX.into(), bytes));
    Ok(notices)
}

impl Package {
    /// `source` contains manifest.json and its relative members. No download or
    /// license inference is performed. The caller supplies an authorized package.
    pub fn read(source: &Path) -> Result<Self, Error> {
        Self::read_inner(source, None)
    }

    /// Check the target mount's bounds before reading any image payload.
    pub fn read_for_mount(source: &Path, image: &[u8]) -> Result<Self, Error> {
        Self::read_inner(source, Some(image))
    }

    fn read_inner(source: &Path, mount_image: Option<&[u8]>) -> Result<Self, Error> {
        let metadata = fs::symlink_metadata(source).map_err(io)?;
        if !metadata.is_dir() || metadata.is_symlink() {
            return Err(fail("host firmware package must be a real directory"));
        }
        let source = source.canonicalize().map_err(io)?;
        let manifest = read_bounded(
            &resolve(&source, "manifest.json")?,
            None,
            MAX_MANIFEST_BYTES,
        )?;
        let parsed = Manifest::parse(&manifest)?;
        if let Some(image) = mount_image {
            parsed.check_mount(image)?;
        }
        let mut files = Vec::with_capacity(parsed.images.len());
        for image in &parsed.images {
            let bytes = read_bounded(
                &resolve(&source, image.path)?,
                Some(image.length),
                MAX_IMAGE_BYTES,
            )?;
            let actual: [u8; 32] = Sha256::digest(&bytes).into();
            if actual != image.digest()? {
                return Err(fail("host firmware package digest mismatch"));
            }
            files.push(bytes);
        }
        let notices = read_notices(&source, &parsed)?;
        Self::assembled(manifest, files, notices)
    }

    /// Construct a generated package only after every image and accompanying
    /// notice has been fetched and checked by its pinned recipe.
    pub(super) fn assembled(
        manifest: Vec<u8>,
        files: Vec<Vec<u8>>,
        notices: Vec<(String, Vec<u8>)>,
    ) -> Result<Self, Error> {
        let parsed = Manifest::parse(&manifest)?;
        if parsed.images.len() != files.len() {
            return Err(fail("assembled firmware image count mismatch"));
        }
        for (image, bytes) in parsed.images.iter().zip(&files) {
            let actual: [u8; 32] = Sha256::digest(bytes).into();
            if bytes.len() != image.length || actual != image.digest()? {
                return Err(fail("assembled firmware image differs from manifest"));
            }
        }
        if notices.len() > MAX_IMAGES {
            return Err(fail("too many host firmware notices"));
        }
        let mut total = 0usize;
        for (index, (name, bytes)) in notices.iter().enumerate() {
            if !storage_path(name)
                || name.contains('/')
                || !(name.ends_with(".txt") || name == "provenance.json")
                || bytes.is_empty()
                || bytes.len() > MAX_MANIFEST_BYTES
                || notices[..index].iter().any(|(other, _)| other == name)
            {
                return Err(fail("invalid or oversized host firmware notice"));
            }
            total = total
                .checked_add(bytes.len())
                .filter(|n| *n <= 1024 * 1024)
                .ok_or_else(|| fail("host firmware notices exceed 1 MiB"))?;
        }
        Ok(Self {
            manifest,
            files,
            notices,
        })
    }

    pub fn inventory(&self) -> (usize, usize) {
        (self.files.len(), self.files.iter().map(Vec::len).sum())
    }

    pub fn check_mount(&self, image: &[u8]) -> Result<(), Error> {
        Manifest::parse(&self.manifest)?.check_mount(image)
    }

    /// Prepare immutable object names and publish only after all files are
    /// durable. An interrupted publication leaves the previous manifest valid;
    /// unreferenced package objects are held for recovery, never guessed away.
    pub fn publish(&self, directory: &Path) -> Result<(), Error> {
        self.publish_checkpointed(directory, |_| Ok(()))
    }

    /// Checkpoints occur only after durable parent/object publication and just
    /// before the final manifest replacement. Tests inject interruption here.
    pub(super) fn publish_checkpointed(
        &self,
        directory: &Path,
        mut checkpoint: impl FnMut(&Path) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if directory.exists() && fs::symlink_metadata(directory).map_err(io)?.is_symlink() {
            return Err(fail("host firmware destination is a symlink"));
        }
        let digest = hex::encode(Sha256::digest(&self.manifest));
        let object_path = format!("objects/{digest}");
        let object_directory = directory.join(&object_path);
        // All storage path components are generated, and existing directories
        // must be genuine. Do not follow a stale symlink from an old package.
        for path in [
            directory.to_path_buf(),
            directory.join("objects"),
            object_directory.clone(),
        ] {
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => {}
                Ok(_) => {
                    return Err(fail(
                        "host firmware destination component is not a real directory",
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&path).map_err(io)?
                }
                Err(error) => return Err(io(error)),
            }
            // Persist every hierarchy entry, including entries created by an
            // earlier interrupted attempt, before making a manifest depend on it.
            sync_directory(
                path.parent()
                    .ok_or_else(|| fail("firmware directory has no parent"))?,
            )?;
            checkpoint(&path)?;
        }
        let mut manifest: serde_json::Value = serde_json::from_slice(&self.manifest).map_err(io)?;
        for (index, bytes) in self.files.iter().enumerate() {
            let path = format!("{object_path}/{index}.bin");
            let destination = directory.join(&path);
            if destination.exists() {
                if fs::symlink_metadata(&destination).map_err(io)?.is_symlink()
                    || read_bounded(&destination, Some(bytes.len()), MAX_IMAGE_BYTES)? != *bytes
                {
                    return Err(fail("existing immutable firmware object differs"));
                }
            } else {
                atomic_write(&destination, bytes)?;
            }
            File::open(&destination)
                .and_then(|file| file.sync_all())
                .map_err(io)?;
            sync_directory(&object_directory)?;
            checkpoint(&destination)?;
            manifest["images"][index]["path"] = serde_json::Value::String(path);
        }
        for (name, bytes) in &self.notices {
            let destination = object_directory.join(name);
            if destination.exists() {
                if fs::symlink_metadata(&destination).map_err(io)?.is_symlink()
                    || read_bounded(&destination, Some(bytes.len()), MAX_MANIFEST_BYTES)? != *bytes
                {
                    return Err(fail("existing immutable firmware notice differs"));
                }
            } else {
                atomic_write(&destination, bytes)?;
            }
            File::open(&destination)
                .and_then(|file| file.sync_all())
                .map_err(io)?;
            sync_directory(&object_directory)?;
            checkpoint(&destination)?;
        }
        let manifest = serde_json::to_vec_pretty(&manifest).map_err(io)?;
        Manifest::parse(&manifest)?;
        let destination = directory.join("manifest.json");
        checkpoint(&destination)?;
        atomic_write(&destination, &manifest)
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = path
        .parent()
        .ok_or_else(|| fail("host firmware destination has no parent"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io)?
        .as_nanos();
    let temp = parent.join(format!(".firmware-{}-{nonce}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(io)?;
    let result = (|| {
        file.write_all(bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        drop(file);
        fs::rename(&temp, path).map_err(io)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn sync_directory(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(io)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(fail(
            "durable firmware package publication requires directory sync support",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ordinary_package(path: &str, license: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join(path);
        std::fs::create_dir_all(image.parent().unwrap()).unwrap();
        std::fs::write(image, b"abc").unwrap();
        let manifest = serde_json::json!({"schema":1,"images":[{"name":"vendor/config.json","path":path,"length":3,
            "sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "target":{"driver":"fixture","hardware":"synthetic","revision":"v1","board":null},
            "provenance":{"source":"synthetic","revision":"v1","member":"fixtures/abc.bin","license":license}}]});
        std::fs::write(
            dir.path().join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        dir
    }

    fn assert_ordinary_roundtrip(dir: &Path) {
        let package = Package::read(dir).unwrap();
        assert_eq!(package.inventory(), (1, 3));
        let output = dir.join("output");
        package.publish(&output).unwrap();
        let imported = Package::read(&output).unwrap();
        assert_eq!(imported.inventory(), (1, 3));
        assert_eq!(imported.files, vec![b"abc".to_vec()]);
        assert!(imported.notices.is_empty());
    }

    #[test]
    fn ordinary_firmware_named_like_a_notice_index_keeps_its_original_meaning() {
        let dir = ordinary_package("provenance.json", "CC0-1.0");
        assert_ordinary_roundtrip(dir.path());
    }

    #[test]
    fn ordinary_firmware_in_a_legacy_notice_directory_keeps_its_original_meaning() {
        let path = format!("objects/{}/provenance.json", "a".repeat(64));
        let dir = ordinary_package(&path, "CC0-1.0");
        assert_ordinary_roundtrip(dir.path());
    }

    #[test]
    fn required_notice_index_cannot_also_be_a_firmware_image() {
        let path = format!("objects/{}/provenance.json", "a".repeat(64));
        let dir = ordinary_package(&path, "stela-notice-v1:LICENSE.fixture");
        let error = Package::read(dir.path()).err().unwrap();
        assert_eq!(
            error.to_string(),
            "required firmware notice index conflicts with an image"
        );
    }

    #[test]
    fn legacy_generated_index_preserves_notices_and_requires_exact_associations() {
        let parent = format!("objects/{}", "a".repeat(64));
        let dir = ordinary_package(&format!("{parent}/0.bin"), "LICENSE.fixture");
        let notice = b"original notice";
        let index = serde_json::json!({"schema":1,"notices":[{
            "path":"license-0.txt","source":"synthetic","revision":"v1",
            "member":"LICENSE.fixture","length":notice.len(),
            "sha256":hex::encode(Sha256::digest(notice))}]});
        let index_bytes = serde_json::to_vec(&index).unwrap();
        let objects = dir.path().join(parent);
        std::fs::write(objects.join("license-0.txt"), notice).unwrap();
        std::fs::write(objects.join(NOTICE_INDEX), &index_bytes).unwrap();
        let package = Package::read(dir.path()).unwrap();
        let output = dir.path().join("output");
        package.publish(&output).unwrap();
        let imported = Package::read(&output).unwrap();
        assert_eq!(imported.files, vec![b"abc".to_vec()]);
        assert_eq!(imported.notices, package.notices);
        assert_eq!(imported.notices[0].1, notice);
        assert_eq!(imported.notices[1].1, index_bytes);
        let imported_manifest = Manifest::parse(&imported.manifest).unwrap();
        assert_eq!(
            imported_manifest.images[0].provenance.license,
            "LICENSE.fixture"
        );

        let mut mutations = vec![
            serde_json::json!({"schema":1,"notices":[]}),
            serde_json::json!({"schema":1}),
        ];
        for key in ["source", "revision", "member"] {
            let mut changed = index.clone();
            changed["notices"][0][key] = serde_json::json!("wrong");
            mutations.push(changed);
        }
        for changed in mutations {
            std::fs::write(
                objects.join(NOTICE_INDEX),
                serde_json::to_vec(&changed).unwrap(),
            )
            .unwrap();
            assert!(Package::read(dir.path()).is_err(), "{changed}");
        }
        std::fs::write(objects.join(NOTICE_INDEX), &index_bytes).unwrap();
        std::fs::remove_file(objects.join("license-0.txt")).unwrap();
        assert!(Package::read(dir.path()).is_err());
    }
}
