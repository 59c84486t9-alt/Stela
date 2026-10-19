//! Updates of an existing setup, each one a transaction in the setup
//! record: Stela updates replace `stela.efi`, macOS updates add the new
//! build's recoveryOS bundle and point `stela.cfg` at it. Both keep what
//! they replace, so `--rollback` undoes the last one; an update that was
//! interrupted is finished by running it again or undone by `--rollback`.
//!
//! - Stela: every `stela.efi` setup has run is kept under
//!   `EFI/stela/versions/<id>/stela.efi` on the ESP (`id`: the first 16
//!   hexadecimal digits of its SHA-256); the OpenCore tool is replaced
//!   atomically by the new one. Stela keeps no translation cache on disk
//!   (translations live in memory for one boot, and the Cache partition is
//!   unused), so an update invalidates none.
//! - macOS: an installed macOS updates itself from the Preboot volume
//!   `stela.efi` reads at every boot; setup refreshes the System Recovery
//!   bundle to the new build, so recoveryOS's Reinstall macOS installs it
//!   over the installed system, keeping its data, as on a Mac. A macOS
//!   Software Update that boots its update ramdisk (`boot-command upgrade`)
//!   is refused by `stela.efi`: what LLB boots for it is not modeled.
//!
//! Neither touches the installed disk's partitions.
use super::{Environment, MARGIN, RECOVERY, Record, write_record};
use crate::{efi, restore};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

/// The OpenCore tool `stela setup` installs.
const TOOL_PATH: &str = efi::INSTALLED[0];
pub(super) const VERSIONS: &str = "EFI/stela/versions";
const VERSION_FILE: &str = "stela.efi";
const VERSION_ID_DIGITS: usize = 16;
/// Stela versions and recoveryOS builds kept for rollback, the active one
/// included.
const KEEP: usize = 3;

/// One update, as the record keeps it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Change {
    /// `stela.efi` versions.
    Stela { from: String, to: String },
    /// recoveryOS builds.
    Os { from: String, to: String },
}

pub(super) fn version_id(image: &[u8]) -> String {
    let digest = hex::encode(Sha256::digest(image));
    digest[..VERSION_ID_DIGITS].into()
}

fn version_path(esp: &Path, id: &str) -> PathBuf {
    esp.join(VERSIONS).join(id).join(VERSION_FILE)
}

/// Keep `image` as a version; returns its id.
pub(super) fn store_version(esp: &Path, image: &[u8]) -> Result<String> {
    let id = version_id(image);
    let path = version_path(esp, &id);
    if fs::read(&path).is_ok_and(|kept| kept == image) {
        return Ok(id);
    }
    fs::create_dir_all(path.parent().expect("a version directory"))?;
    efi::write_atomic(&path, image, false)?;
    ensure!(
        version_id(&fs::read(&path)?) == id,
        "{} did not read back as written",
        path.display()
    );
    Ok(id)
}

fn activate_stela(esp: &Path, id: &str) -> Result<()> {
    let path = version_path(esp, id);
    ensure!(
        path.is_file(),
        "Stela version {id} is not kept at {}",
        path.display()
    );
    efi::add_mount(esp, &path, None, None)?;
    Ok(())
}

/// The recoveryOS bundle directory of `build` on the record's volume.
pub(super) fn bundle_directory(record: &Record, build: &str) -> PathBuf {
    record.volume.join(format!("EFI/stela/boot/{build}"))
}

/// Point `stela.cfg` at `build`'s recoveryOS.
fn activate_build(record: &mut Record, build: &str) -> Result<()> {
    record.build = build.into();
    record.bundle_directory = bundle_directory(record, build);
    record.options = super::options(record);
    let tool = record.esp.join(TOOL_PATH);
    efi::add_mount(&record.esp, &tool, None, Some(&record.options))?;
    Ok(())
}

fn prune(record: &mut Record) -> Result<()> {
    while record.stela_versions.len() > KEEP {
        let id = record.stela_versions.remove(0);
        if record.stela_version.as_deref() != Some(id.as_str()) {
            let directory = record.esp.join(VERSIONS).join(&id);
            if directory.is_dir() {
                fs::remove_dir_all(directory)?;
            }
        }
    }
    while record.recovery_builds.len() > KEEP {
        let build = record.recovery_builds.remove(0);
        if build != record.build {
            let directory = bundle_directory(record, &build);
            if directory.is_dir() {
                fs::remove_dir_all(directory)?;
            }
        }
    }
    let kept = |change: &Change| match change {
        Change::Stela { from, .. } => record.stela_versions.contains(from),
        Change::Os { from, .. } => record.recovery_builds.contains(from),
    };
    let history: Vec<Change> = record.history.iter().filter(|c| kept(c)).cloned().collect();
    record.history = history;
    Ok(())
}

/// The record of a completed setup, refusing another update while one is
/// pending unless it is `allowed`.
fn ready(record: &Record, allowed: impl Fn(&Change) -> bool) -> Result<()> {
    ensure!(
        record.complete,
        "the setup on {} was interrupted; run `stela setup --uninstall` and set up again",
        record.esp.display()
    );
    if let Some(pending) = &record.pending {
        ensure!(
            allowed(pending),
            "an update was interrupted ({pending:?}); run it again to finish it, or \
             `stela setup --rollback` to undo it"
        );
    }
    Ok(())
}

/// Replace `stela.efi` with `image_path`.
pub(super) fn update_stela(mut record: Record, image_path: &Path, dry_run: bool) -> Result<String> {
    let image =
        fs::read(image_path).with_context(|| format!("cannot read {}", image_path.display()))?;
    ensure!(
        image.starts_with(b"MZ"),
        "{} is not a UEFI application",
        image_path.display()
    );
    let to = version_id(&image);
    ready(
        &record,
        |pending| matches!(pending, Change::Stela { to: t, .. } if *t == to),
    )?;
    let esp = record.esp.clone();
    let current = fs::read(esp.join(TOOL_PATH))
        .with_context(|| format!("{} has no {TOOL_PATH}", esp.display()))?;
    let from = match &record.pending {
        Some(Change::Stela { from, .. }) => from.clone(),
        _ => version_id(&current),
    };
    let mut text = String::new();
    writeln!(text, "Stela update on {}:", esp.display())?;
    if from == to && record.pending.is_none() {
        writeln!(text, "  stela.efi      version {to} is already installed")?;
        return Ok(text);
    }
    writeln!(text, "  stela.efi      version {from} -> {to}")?;
    writeln!(
        text,
        "  keeps          {} and {}",
        version_path(&esp, &from).display(),
        version_path(&esp, &to).display()
    )?;
    writeln!(
        text,
        "  caches         none: Stela keeps no translation cache on disk"
    )?;
    writeln!(text, "  disks          the installed disk is not changed")?;
    if dry_run {
        text.push_str("Dry run: nothing was changed.\n");
        return Ok(text);
    }
    // The running version is kept before anything changes.
    if record.pending.is_none() {
        let kept = store_version(&esp, &current)?;
        if !record.stela_versions.contains(&kept) {
            record.stela_versions.push(kept);
        }
        record.pending = Some(Change::Stela {
            from: from.clone(),
            to: to.clone(),
        });
        write_record(&esp, &record)?;
    }
    store_version(&esp, &image)?;
    activate_stela(&esp, &to)?;
    record.stela_version = Some(to.clone());
    record.stela_versions.retain(|id| *id != to);
    record.stela_versions.push(to.clone());
    record.history.push(Change::Stela { from, to });
    record.pending = None;
    prune(&mut record)?;
    write_record(&esp, &record)?;
    text.push_str("Done. Undo with: stela setup --rollback\n");
    Ok(text)
}

/// Add `ipsw`'s recoveryOS and boot it for System Recovery.
pub(super) fn update_os(
    environment: &Environment<'_>,
    mut record: Record,
    ipsw: &Path,
    dry_run: bool,
) -> Result<String> {
    let (product_version, build) = restore::payload::identity(ipsw, &record.model)?;
    ready(
        &record,
        |pending| matches!(pending, Change::Os { to, .. } if *to == build),
    )?;
    let from = match &record.pending {
        Some(Change::Os { from, .. }) => from.clone(),
        _ => record.build.clone(),
    };
    ensure!(
        build != from,
        "recoveryOS {build} is already the System Recovery of this setup"
    );
    let bundle = tempfile::tempdir()?;
    (environment.prepare)(ipsw, &record.model, &bundle.path().join(RECOVERY))
        .context("preparing the recoveryOS boot bundle")?;
    let mut bytes = 0;
    for file in fs::read_dir(bundle.path().join(RECOVERY))? {
        bytes += file?.metadata()?.len();
    }
    let free = environment.host.volume(&record.volume)?.free_bytes;
    ensure!(
        free >= bytes + MARGIN,
        "{} has {:.1} GB free; the macOS {product_version} recoveryOS bundle needs {:.1} GB",
        record.volume.display(),
        free as f64 / 1e9,
        (bytes + MARGIN) as f64 / 1e9
    );
    let destination = bundle_directory(&record, &build).join(RECOVERY);
    let mut text = String::new();
    writeln!(text, "macOS update to {product_version} ({build}):")?;
    writeln!(
        text,
        "  recoveryOS     {} ({:.1} GB); {from}'s stays for rollback",
        destination.display(),
        bytes as f64 / 1e9
    )?;
    writeln!(
        text,
        "  stela.cfg      boots recoveryOS {build} for System Recovery"
    )?;
    writeln!(
        text,
        "  next           boot System Recovery (`stela setup --next-boot recovery`) and \
         choose Reinstall macOS: it installs {product_version} over the installed system and \
         keeps its data"
    )?;
    writeln!(
        text,
        "  note           a macOS Software Update that boots its update ramdisk is refused \
         by stela.efi: that boot is not modeled"
    )?;
    if dry_run {
        text.push_str("Dry run: nothing was changed.\n");
        return Ok(text);
    }
    if record.pending.is_none() {
        record.pending = Some(Change::Os {
            from: from.clone(),
            to: build.clone(),
        });
        write_record(&record.esp.clone(), &record)?;
    }
    if destination.exists() {
        fs::remove_dir_all(&destination)?;
    }
    fs::create_dir_all(&destination)?;
    for file in fs::read_dir(bundle.path().join(RECOVERY))? {
        let file = file?;
        fs::copy(file.path(), destination.join(file.file_name()))?;
    }
    activate_build(&mut record, &build)?;
    if !record.recovery_builds.contains(&from) {
        record.recovery_builds.insert(0, from.clone());
    }
    record.recovery_builds.retain(|b| *b != build);
    record.recovery_builds.push(build.clone());
    record.history.push(Change::Os { from, to: build });
    record.pending = None;
    prune(&mut record)?;
    write_record(&record.esp.clone(), &record)?;
    text.push_str("Done. Undo with: stela setup --rollback\n");
    Ok(text)
}

/// Undo the pending update, or else the last one.
pub(super) fn rollback(mut record: Record, dry_run: bool) -> Result<String> {
    ensure!(
        record.complete,
        "the setup on {} was interrupted; run `stela setup --uninstall` and set up again",
        record.esp.display()
    );
    let (change, pending) = match record.pending.clone() {
        Some(change) => (change, true),
        None => match record.history.last() {
            Some(change) => (change.clone(), false),
            None => bail!("{} has no update to roll back", record.esp.display()),
        },
    };
    let mut text = String::new();
    let what = if pending { "interrupted" } else { "last" };
    match &change {
        Change::Stela { from, to } => writeln!(
            text,
            "Roll back the {what} Stela update: stela.efi {to} -> {from}"
        )?,
        Change::Os { from, to } => writeln!(
            text,
            "Roll back the {what} macOS update: System Recovery {to} -> {from}"
        )?,
    }
    if dry_run {
        text.push_str("Dry run: nothing was changed.\n");
        return Ok(text);
    }
    let esp = record.esp.clone();
    match &change {
        Change::Stela { from, to } => {
            activate_stela(&esp, from)?;
            record.stela_version = Some(from.clone());
            record.stela_versions.retain(|id| id != to);
            let directory = esp.join(VERSIONS).join(to);
            if *to != *from && directory.is_dir() {
                fs::remove_dir_all(directory)?;
            }
        }
        Change::Os { from, to } => {
            let previous = bundle_directory(&record, from);
            ensure!(
                previous.join(RECOVERY).is_dir(),
                "recoveryOS {from} is no longer kept at {}",
                previous.display()
            );
            activate_build(&mut record, from)?;
            record.recovery_builds.retain(|b| b != to);
            let directory = bundle_directory(&record, to);
            if *to != *from && directory.is_dir() {
                fs::remove_dir_all(directory)?;
            }
        }
    }
    if pending {
        record.pending = None;
    } else {
        record.history.pop();
    }
    write_record(&esp, &record)?;
    text.push_str("Done.\n");
    Ok(text)
}
