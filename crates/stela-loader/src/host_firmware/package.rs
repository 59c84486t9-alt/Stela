//! Setup's bounded local package reader and manifest-last publication. Immutable
//! objects live below a content-addressed package directory, so replacing the
//! active manifest never overwrites bytes the previous manifest still names.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

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
        directory = found.ok_or_else(|| fail("missing host firmware package file"))?;
    }
    Ok(directory)
}

impl Package {
    /// `source` contains manifest.json and its relative members. No download or
    /// license inference is performed. The caller supplies an authorized package.
    pub fn read(source: &Path) -> Result<Self, Error> {
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
        Self::assembled(manifest, files, Vec::new())
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

    /// Prepare immutable object names and publish only after all files are
    /// durable. An interrupted publication leaves the previous manifest valid;
    /// unreferenced package objects are retained for recovery, never guessed away.
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
