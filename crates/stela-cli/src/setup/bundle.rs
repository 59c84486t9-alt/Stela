//! The recoveryOS bundles on the USB: one for each macOS build setup keeps,
//! each Stela machine (its ECID is in the bundle's `/chosen`) and boot-bundle
//! schema (`stela_runtime::boot_bundle::SCHEMA_VERSION` of the `stela.efi`
//! that reads it), in `EFI/stela/boot/<build>/<leaf>` of the bundle volume:
//!
//! - `recovery`: a bundle from before machines had ECIDs, schema 1;
//! - `recovery-<ECID>`: a machine's bundle, schema 1;
//! - either with `-s<schema>` for another schema, so a Stela update that
//!   reads a new schema adds its bundles beside the old ones and its
//!   rollback finds them.
//!
//! A bundle is copied to a `.partial` sibling and renamed into place, so an
//! interrupted copy is never taken for a bundle; the setup record keeps the
//! SHA-256 of its `bundle.json`, whose file list carries every file's
//! SHA-256, so [`verify`] checks the whole bundle.
use super::ecid::Ecid;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(super) const MANIFEST: &str = "bundle.json";
const LEGACY_LEAF: &str = "recovery";
/// The schema bundles without a suffix have.
const FIRST_SCHEMA: u32 = 1;

/// One recoveryOS bundle setup wrote.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Bundle {
    pub(super) build: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ecid: Option<Ecid>,
    pub(super) schema: u32,
    /// SHA-256 of its `bundle.json`; empty for a bundle an older setup
    /// wrote without recording it.
    #[serde(default)]
    pub(super) manifest_sha256: String,
}

impl Bundle {
    pub(super) fn same(&self, build: &str, ecid: Option<Ecid>, schema: u32) -> bool {
        self.build == build && self.ecid == ecid && self.schema == schema
    }
}

pub(super) fn leaf(ecid: Option<Ecid>, schema: u32) -> String {
    let mut leaf = match ecid {
        Some(ecid) => format!("{LEGACY_LEAF}-{}", ecid.digits()),
        None => LEGACY_LEAF.into(),
    };
    if schema != FIRST_SCHEMA {
        leaf.push_str(&format!("-s{schema}"));
    }
    leaf
}

/// `EFI/stela/boot/<build>` on `volume`.
pub(super) fn build_directory(volume: &Path, build: &str) -> PathBuf {
    volume.join(format!("EFI/stela/boot/{build}"))
}

/// The bundle's directory on `volume`.
pub(super) fn directory(volume: &Path, build: &str, ecid: Option<Ecid>, schema: u32) -> PathBuf {
    build_directory(volume, build).join(leaf(ecid, schema))
}

/// The bundle's directory as `stela.cfg` names it on the firmware's volume.
pub(super) fn firmware_path(build: &str, ecid: Option<Ecid>, schema: u32) -> String {
    format!("\\EFI\\stela\\boot\\{build}\\{}", leaf(ecid, schema))
}

/// What `bundle.json` says of itself and its files.
#[derive(Deserialize)]
struct Listing {
    schema_version: u32,
    #[serde(default)]
    files: Vec<Listed>,
}

#[derive(Deserialize)]
struct Listed {
    name: String,
    bytes: u64,
    sha256: String,
}

/// The schema a bundle directory's `bundle.json` declares.
pub(super) fn schema(directory: &Path) -> Result<u32> {
    let listing: Listing = stela_runtime::read_json(&directory.join(MANIFEST))?;
    Ok(listing.schema_version)
}

/// Bytes of the files in a prepared bundle directory.
pub(super) fn bytes(directory: &Path) -> Result<u64> {
    let mut total = 0;
    for file in fs::read_dir(directory)? {
        total += file?.metadata()?.len();
    }
    Ok(total)
}

fn sha256_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file =
        fs::File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash)?;
    Ok(hex::encode(hash.finalize()))
}

/// Copy the prepared bundle in `prepared` to `destination`, replacing what
/// is there only once the copy is complete; returns its `bundle.json`'s
/// SHA-256.
pub(super) fn install(prepared: &Path, destination: &Path) -> Result<String> {
    let name = destination
        .file_name()
        .context("a bundle directory without a name")?
        .to_string_lossy()
        .into_owned();
    let partial = destination.with_file_name(format!("{name}.partial"));
    let previous = destination.with_file_name(format!("{name}.previous"));
    for stale in [&partial, &previous] {
        if stale.exists() {
            fs::remove_dir_all(stale)?;
        }
    }
    fs::create_dir_all(&partial)?;
    for file in fs::read_dir(prepared)? {
        let file = file?;
        let target = partial.join(file.file_name());
        fs::copy(file.path(), &target)?;
        fs::File::open(&target)?.sync_all()?;
    }
    if destination.exists() {
        fs::rename(destination, &previous)?;
    }
    fs::rename(&partial, destination)?;
    if previous.exists() {
        fs::remove_dir_all(&previous)?;
    }
    sha256_file(&destination.join(MANIFEST))
}

/// What is wrong with the bundle in `directory`, checked against its
/// `bundle.json` and, when known, that file's recorded SHA-256; empty when
/// it is intact.
pub(super) fn verify(directory: &Path, manifest_sha256: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let manifest = directory.join(MANIFEST);
    if !manifest.is_file() {
        problems.push(format!("{} is missing", manifest.display()));
        return problems;
    }
    match sha256_file(&manifest) {
        Ok(digest) if !manifest_sha256.is_empty() && digest != manifest_sha256 => problems.push(
            format!("{} differs from the one setup wrote", manifest.display()),
        ),
        Ok(_) => {}
        Err(error) => problems.push(format!("{error:#}")),
    }
    let listing: Listing = match stela_runtime::read_json(&manifest) {
        Ok(listing) => listing,
        Err(error) => {
            problems.push(format!("{} cannot be read: {error:#}", manifest.display()));
            return problems;
        }
    };
    if listing.files.is_empty() {
        problems.push(format!("{} lists no files", manifest.display()));
    }
    for file in &listing.files {
        let path = directory.join(&file.name);
        let check = || -> Result<()> {
            ensure!(
                !file.name.contains(['/', '\\']) && file.name != MANIFEST,
                "lists an unexpected file name {:?}",
                file.name
            );
            let bytes = fs::metadata(&path)
                .with_context(|| format!("{} is missing", path.display()))?
                .len();
            ensure!(
                bytes == file.bytes,
                "{} holds {bytes} bytes, not {}",
                path.display(),
                file.bytes
            );
            ensure!(
                sha256_file(&path)? == file.sha256,
                "{} differs from its SHA-256 in {MANIFEST}",
                path.display()
            );
            Ok(())
        };
        if let Err(error) = check() {
            problems.push(format!("{error:#}"));
        }
    }
    problems
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A bundle directory of one file, listed in a schema `schema`
    /// `bundle.json`.
    pub(in super::super) fn write(directory: &Path, schema: u32, contents: &[u8]) -> Result<()> {
        use sha2::{Digest, Sha256};
        fs::create_dir_all(directory)?;
        fs::write(directory.join("ramdisk.img"), contents)?;
        let listing = serde_json::json!({
            "schema_version": schema,
            "files": [{
                "name": "ramdisk.img",
                "bytes": contents.len(),
                "sha256": hex::encode(Sha256::digest(contents)),
            }],
        });
        stela_runtime::write_json(&directory.join(MANIFEST), &listing)
    }

    #[test]
    fn bundles_are_named_by_machine_and_schema() {
        assert_eq!(leaf(None, 1), "recovery");
        assert_eq!(leaf(Some(Ecid(0xab)), 1), "recovery-00000000000000AB");
        assert_eq!(leaf(Some(Ecid(0xab)), 2), "recovery-00000000000000AB-s2");
        assert_eq!(leaf(None, 3), "recovery-s3");
        assert_eq!(
            firmware_path("26A434", Some(Ecid(1)), 1),
            "\\EFI\\stela\\boot\\26A434\\recovery-0000000000000001"
        );
    }

    #[test]
    fn installed_bundles_verify_and_damage_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let prepared = dir.path().join("prepared");
        write(&prepared, 1, &[0x5a; 4096]).unwrap();
        let destination = dir.path().join("boot/B/recovery");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        let digest = install(&prepared, &destination).unwrap();
        assert!(verify(&destination, &digest).is_empty());
        assert_eq!(schema(&destination).unwrap(), 1);
        // A second install replaces it whole.
        write(&prepared, 2, &[0x33; 100]).unwrap();
        let second = install(&prepared, &destination).unwrap();
        assert_ne!(second, digest);
        assert_eq!(schema(&destination).unwrap(), 2);
        assert!(!dir.path().join("boot/B/recovery.partial").exists());
        assert!(!verify(&destination, &digest).is_empty());
        fs::write(destination.join("ramdisk.img"), [0x34; 100]).unwrap();
        let problems = verify(&destination, &second);
        assert!(
            problems[0].contains("differs from its SHA-256"),
            "{problems:?}"
        );
        fs::remove_file(destination.join("ramdisk.img")).unwrap();
        assert!(verify(&destination, "")[0].contains("missing"));
    }
}
