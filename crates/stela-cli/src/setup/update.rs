//! Updates of an existing setup, each one a transaction in the setup
//! record: Stela updates replace `stela.efi`, macOS updates add the new
//! build's recoveryOS bundles and point `stela.cfg` at them. Both keep what
//! they replace, so `--rollback` undoes the last one; an update that was
//! interrupted is finished by running it again or undone by `--rollback`.
//!
//! - Stela: every `stela.efi` setup has run is kept under
//!   `EFI/stela/versions/<id>/stela.efi` on the ESP (`id`: the first 16
//!   hexadecimal digits of its SHA-256); the OpenCore tool is replaced
//!   atomically by the new one. A new `stela.efi` must carry this `stela`'s
//!   mount interface. When it reads another boot-bundle schema than the
//!   setup's bundles have, the update prepares every machine's bundle of
//!   the active build at the new schema (from `--ipsw` or `--fetch`) beside
//!   the old ones, which its rollback boots again. Stela keeps no
//!   translation cache on disk (translations live in memory for one boot,
//!   and the Cache partition is unused), so an update invalidates none.
//! - macOS: an installed macOS updates itself: Software Update stages the
//!   new system on the container's Update volume and sets `boot-command
//!   upgrade`, which `stela.efi` boots from that volume as iBEC would
//!   (`stela_loader::upgrade`), and every later boot builds from the
//!   Preboot volume's new objects. Setup refreshes the System Recovery
//!   bundles to the new build, so recoveryOS's Reinstall macOS installs it
//!   over the installed system, keeping its data, as on a Mac.
//!
//! Neither touches the installed disks' partitions.
use super::{
    Environment, Record, TOOL_PATH, bundle, check_space, copy_bundles, first_schema,
    prepare_bundles, publish, read_efi, write_record,
};
use crate::efi;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

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
    /// `stela.efi` versions, and the bundle schemas they read.
    Stela {
        from: String,
        to: String,
        #[serde(default = "first_schema")]
        from_schema: u32,
        #[serde(default = "first_schema")]
        to_schema: u32,
    },
    /// recoveryOS builds.
    Os { from: String, to: String },
}

pub(super) fn version_id(image: &[u8]) -> String {
    let digest = hex::encode(Sha256::digest(image));
    digest[..VERSION_ID_DIGITS].into()
}

pub(super) fn version_path(esp: &Path, id: &str) -> PathBuf {
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
        path.is_file() && fs::read(&path).is_ok_and(|image| version_id(&image) == id),
        "Stela version {id} is not kept intact at {}",
        path.display()
    );
    efi::add_mount(esp, &path, None, None)?;
    Ok(())
}

/// Point `stela.cfg` at `build`'s recoveryOS, which must have a bundle for
/// every machine at the active schema.
fn activate_build(record: &mut Record, build: &str) -> Result<()> {
    let missing = record.missing_bundles(build);
    ensure!(
        missing.is_empty(),
        "recoveryOS {build} has no schema {} bundle for {}; prepare them with `stela setup \
         --repair --ipsw` of that build after activating it, or keep the current build",
        record.bundle_schema,
        missing
            .iter()
            .map(|ecid| ecid.map_or_else(|| "the setup".into(), |e| format!("ECID {e}")))
            .collect::<Vec<_>>()
            .join(", ")
    );
    record.build = build.into();
    record.bundle_directory = bundle::build_directory(&record.volume, build);
    publish(record)
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
            let directory = bundle::build_directory(&record.volume, &build);
            if directory.is_dir() {
                fs::remove_dir_all(directory)?;
            }
            record.bundles.retain(|b| b.build != build);
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

/// Refuse a change to an interrupted setup, or while an update is pending
/// unless the pending one is `allowed`.
pub(super) fn ready(record: &Record, allowed: impl Fn(&Change) -> bool) -> Result<()> {
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

/// Replace `stela.efi` with `image_path`, preparing bundles of its schema
/// from `ipsw` when it reads another one.
pub(super) fn update_stela(
    environment: &Environment<'_>,
    mut record: Record,
    image_path: &Path,
    ipsw: Option<&Path>,
    dry_run: bool,
) -> Result<String> {
    let image = read_efi(environment, image_path)?;
    let to = version_id(&image);
    let to_schema = environment.interface.bundle_schema;
    ready(
        &record,
        |pending| matches!(pending, Change::Stela { to: t, .. } if *t == to),
    )?;
    let esp = record.esp.clone();
    let current = fs::read(esp.join(TOOL_PATH))
        .with_context(|| format!("{} has no {TOOL_PATH}", esp.display()))?;
    let (from, from_schema) = match &record.pending {
        Some(Change::Stela {
            from, from_schema, ..
        }) => (from.clone(), *from_schema),
        _ => (version_id(&current), record.bundle_schema),
    };
    let mut text = String::new();
    writeln!(text, "Stela update on {}:", esp.display())?;
    if from == to && record.pending.is_none() && from_schema == to_schema {
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
    // Bundles of the new schema for every machine of the active build.
    let mut next = record.clone();
    next.bundle_schema = to_schema;
    let missing = next.missing_bundles(&record.build);
    let prepared = if missing.is_empty() {
        Vec::new()
    } else {
        let Some(ipsw) = ipsw else {
            bail!(
                "stela.efi {to} reads boot-bundle schema {to_schema}, and this setup's recoveryOS \
                 bundles have schema {from_schema}: pass the macOS {} restore image with --ipsw \
                 or --fetch so the update prepares new ones",
                record.build
            );
        };
        let (_, _, prepared) = prepare_bundles(
            environment,
            ipsw,
            &record.model,
            Some(&record.build),
            &missing,
        )?;
        check_space(environment.host, &record.volume, &prepared)?;
        prepared
    };
    for bundle in &prepared {
        writeln!(
            text,
            "  recoveryOS     {} (schema {to_schema}, {:.1} GB); the schema {from_schema} \
             bundles stay for rollback",
            bundle::directory(&record.volume, &bundle.build, bundle.ecid, to_schema).display(),
            bundle.bytes as f64 / 1e9
        )?;
    }
    writeln!(
        text,
        "  caches         none: Stela keeps no translation cache on disk"
    )?;
    writeln!(text, "  disks          the installed disks are not changed")?;
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
            from_schema,
            to_schema,
        });
        write_record(&esp, &record)?;
    }
    record.bundle_schema = to_schema;
    copy_bundles(&mut record, &prepared)?;
    write_record(&esp, &record)?;
    store_version(&esp, &image)?;
    activate_stela(&esp, &to)?;
    publish(&mut record)?;
    record.stela_version = Some(to.clone());
    record.stela_versions.retain(|id| *id != to);
    record.stela_versions.push(to.clone());
    record.history.push(Change::Stela {
        from,
        to,
        from_schema,
        to_schema,
    });
    record.pending = None;
    prune(&mut record)?;
    write_record(&esp, &record)?;
    text.push_str("Done. Undo with: stela setup --rollback\n");
    Ok(text)
}

/// Add `ipsw`'s recoveryOS for every machine and boot it for System
/// Recovery.
pub(super) fn update_os(
    environment: &Environment<'_>,
    mut record: Record,
    ipsw: &Path,
    dry_run: bool,
) -> Result<String> {
    let (product_version, build) = crate::restore::payload::identity(ipsw, &record.model)?;
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
    let machines = record.machines();
    let (_, _, prepared) =
        prepare_bundles(environment, ipsw, &record.model, Some(&build), &machines)?;
    check_space(environment.host, &record.volume, &prepared)?;
    let mut text = String::new();
    writeln!(text, "macOS update to {product_version} ({build}):")?;
    for bundle in &prepared {
        writeln!(
            text,
            "  recoveryOS     {} ({:.1} GB); {from}'s stays for rollback",
            bundle::directory(&record.volume, &build, bundle.ecid, record.bundle_schema).display(),
            bundle.bytes as f64 / 1e9
        )?;
    }
    writeln!(
        text,
        "  stela.cfg      boots recoveryOS {build} for System Recovery"
    )?;
    writeln!(
        text,
        "  next           boot System Recovery (`stela setup --next-boot recovery`, or its \
         startup choice) and choose Reinstall macOS: it installs {product_version} over the \
         installed system and keeps its data"
    )?;
    writeln!(
        text,
        "  note           macOS's own Software Update stages the update on the Update volume; \
         stela.efi boots it from there (boot-command upgrade) and then the new Preboot \
         objects, without this command"
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
    copy_bundles(&mut record, &prepared)?;
    write_record(&record.esp.clone(), &record)?;
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
        Change::Stela { from, to, .. } => writeln!(
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
        Change::Stela {
            from,
            to,
            from_schema,
            to_schema,
        } => {
            activate_stela(&esp, from)?;
            record.stela_version = Some(from.clone());
            record.stela_versions.retain(|id| id != to);
            record.bundle_schema = *from_schema;
            publish(&mut record)?;
            let directory = esp.join(VERSIONS).join(to);
            if *to != *from && directory.is_dir() {
                fs::remove_dir_all(directory)?;
            }
            if from_schema != to_schema {
                let stale: Vec<bundle::Bundle> = record
                    .bundles
                    .iter()
                    .filter(|b| b.schema == *to_schema)
                    .cloned()
                    .collect();
                record.bundles.retain(|b| b.schema != *to_schema);
                super::remove_bundles(&record, &stale)?;
            }
        }
        Change::Os { from, to } => {
            ensure!(
                bundle::build_directory(&record.volume, from).is_dir(),
                "recoveryOS {from} is no longer kept at {}",
                bundle::build_directory(&record.volume, from).display()
            );
            activate_build(&mut record, from)?;
            record.recovery_builds.retain(|b| b != to);
            let directory = bundle::build_directory(&record.volume, to);
            if *to != *from && directory.is_dir() {
                fs::remove_dir_all(directory)?;
            }
            record.bundles.retain(|b| b.build != *to);
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
