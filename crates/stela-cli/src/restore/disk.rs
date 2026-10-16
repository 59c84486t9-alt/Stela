//! Copy selected guest files out of a decrypted Apple disk image.
//!
//! The image is attached read-only through `hdiutil` under a private mount root
//! and always detached afterwards. Guest paths resolve inside the selected
//! volume without following symbolic links out of it.
use anyhow::{Context, Result, bail, ensure};
use plist::Value;
use serde_json::json;
use std::{
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};
use stela_core::sha256;

const HDIUTIL: &str = "/usr/bin/hdiutil";
/// Directory of the dyld shared cache inside an OS volume.
const SHARED_CACHE_DIRECTORY: &str = "System/Library/dyld";
const SHARED_CACHE_PREFIX: &str = "dyld_shared_cache_arm64e";
const MAX_SYMLINKS: usize = 32;

/// Guest files to copy; optional paths may be missing from the image.
pub struct Selection {
    pub required: Vec<String>,
    pub optional: Vec<String>,
    pub shared_cache: bool,
    pub volume: Option<String>,
}

/// One attached image; detaches on drop.
struct Attachment {
    device: String,
    mounts: Vec<PathBuf>,
}

impl Attachment {
    fn new(image: &Path, mount_root: &Path) -> Result<Self> {
        let output = Command::new(HDIUTIL)
            .arg("attach")
            .arg(image)
            .args(["-readonly", "-nobrowse", "-noautoopen", "-noautofsck"])
            .args(["-mount", "required", "-plist", "-mountroot"])
            .arg(mount_root)
            .output()
            .with_context(|| format!("cannot run {HDIUTIL}"))?;
        ensure!(
            output.status.success(),
            "hdiutil attach failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let plist = Value::from_reader(std::io::Cursor::new(output.stdout))?;
        let entities = plist
            .as_dictionary()
            .and_then(|root| root.get("system-entities"))
            .and_then(Value::as_array)
            .context("hdiutil reported no system entities")?;
        let field = |entity: &Value, key: &str| {
            entity
                .as_dictionary()
                .and_then(|entity| entity.get(key))
                .and_then(Value::as_string)
                .map(str::to_owned)
        };
        // The whole-disk entity is the shortest device node.
        let device = entities
            .iter()
            .filter_map(|entity| field(entity, "dev-entry"))
            .min_by_key(String::len)
            .context("hdiutil reported no device")?;
        let mounts = entities
            .iter()
            .filter_map(|entity| field(entity, "mount-point"))
            .map(PathBuf::from)
            .collect();
        Ok(Self { device, mounts })
    }
}

impl Drop for Attachment {
    fn drop(&mut self) {
        let detached = Command::new(HDIUTIL)
            .args(["detach", &self.device])
            .status()
            .is_ok_and(|status| status.success());
        if !detached {
            eprintln!("warning: could not detach {}", self.device);
        }
    }
}

/// Resolve `guest` (absolute) inside `volume`, following symbolic links only
/// while they stay inside it.
fn resolve(volume: &Path, guest: &str) -> Result<PathBuf> {
    ensure!(
        guest.starts_with('/'),
        "guest path {guest} must be absolute"
    );
    let mut pending: Vec<String> = guest
        .split('/')
        .filter(|part| !part.is_empty())
        .rev()
        .map(str::to_owned)
        .collect();
    let mut resolved = PathBuf::new();
    let mut links = 0;
    while let Some(part) = pending.pop() {
        match part.as_str() {
            "." => continue,
            ".." => {
                resolved.pop();
                continue;
            }
            _ => {}
        }
        let candidate = resolved.join(&part);
        let host = volume.join(&candidate);
        let metadata = fs::symlink_metadata(&host)
            .with_context(|| format!("{guest} is missing from the image"))?;
        if !metadata.file_type().is_symlink() {
            resolved = candidate;
            continue;
        }
        links += 1;
        ensure!(links <= MAX_SYMLINKS, "{guest} has too many symbolic links");
        let target = fs::read_link(&host)?;
        if target.is_absolute() {
            resolved = PathBuf::new();
        }
        for component in target.components().rev() {
            match component {
                Component::Normal(name) => pending.push(name.to_string_lossy().into_owned()),
                Component::ParentDir => pending.push("..".into()),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            }
        }
    }
    let host = volume.join(&resolved);
    ensure!(
        fs::metadata(&host)?.is_file(),
        "{guest} is not a regular file"
    );
    Ok(host)
}

/// Copy the selection from `image` into the new directory `output`, keeping
/// guest paths, and return a receipt of every copied file.
pub fn extract(image: &Path, output: &Path, selection: &Selection) -> Result<serde_json::Value> {
    ensure!(!output.exists(), "{} exists", output.display());
    let mount_root = tempfile::tempdir()?;
    let attachment = Attachment::new(image, mount_root.path())?;
    let volume = match &selection.volume {
        Some(name) => attachment
            .mounts
            .iter()
            .find(|mount| mount.file_name().is_some_and(|file| file == name.as_str()))
            .with_context(|| format!("no mounted volume named {name}"))?,
        None => match attachment.mounts.as_slice() {
            [volume] => volume,
            mounts => bail!(
                "image mounts {} volumes; select one with --volume",
                mounts.len()
            ),
        },
    }
    .clone();
    let volume = volume.as_path();
    let mut paths: Vec<(String, bool)> = selection
        .required
        .iter()
        .map(|path| (path.clone(), true))
        .chain(selection.optional.iter().map(|path| (path.clone(), false)))
        .collect();
    if selection.shared_cache {
        let directory = volume.join(SHARED_CACHE_DIRECTORY);
        for entry in fs::read_dir(&directory).context("image has no dyld shared cache directory")? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if name.starts_with(SHARED_CACHE_PREFIX) {
                paths.push((format!("/{SHARED_CACHE_DIRECTORY}/{name}"), true));
            }
        }
    }
    let mut files = vec![];
    let mut missing = vec![];
    for (guest, required) in paths {
        let source = match resolve(volume, &guest) {
            Ok(source) => source,
            Err(_) if !required => {
                missing.push(guest);
                continue;
            }
            Err(error) => return Err(error),
        };
        let destination = output.join(guest.trim_start_matches('/'));
        fs::create_dir_all(destination.parent().context("guest path has no parent")?)?;
        fs::copy(&source, &destination)?;
        let bytes = fs::read(&destination)?;
        files.push(json!({ "path": guest, "bytes": bytes.len(), "sha256": sha256(&bytes) }));
    }
    drop(attachment);
    let receipt = json!({
        "kind": "guest_file_extraction",
        "image": image.canonicalize()?,
        "volume": volume.file_name().map(|name| name.to_string_lossy().into_owned()),
        "files": files,
        "missing_optional": missing,
    });
    fs::write(output.join("receipt.json"), format!("{receipt:#}\n"))?;
    Ok(receipt)
}

#[cfg(test)]
mod tests;
