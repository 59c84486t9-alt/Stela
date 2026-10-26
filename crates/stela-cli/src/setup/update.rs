//! Updates of an existing setup, each one a transaction in the setup
//! record: Stela updates replace `stela.efi`, macOS updates add the new
//! build's recoveryOS bundles and point `stela.cfg` at them. Both keep what
//! they replace, so `--rollback` undoes the last one; an update that was
//! interrupted is finished by running it again or undone by `--rollback`.
//!
//! - Stela: every `stela.efi` setup has run is kept under
//!   `EFI/stela/versions/<id>/stela.efi` on the ESP (`id`: the first 16
//!   hexadecimal digits of its SHA-256); the USB's boot loader is replaced
//!   atomically by the new one. A new `stela.efi` must carry this `stela`'s
//!   mount interface. When it reads another boot-bundle schema than the
//!   setup's bundles have, or this `stela` prepares another bundle revision
//!   (`stela_loader::boot_bundle::REVISION`) than theirs, the update
//!   prepares the active build's bundles for every machine again (the
//!   recoveryOS ones, and the restore ones while the setup has the build's
//!   install medium) at the new schema and revision, from `--ipsw` or
//!   `--fetch`, beside the old ones, which its rollback boots again; this
//!   makes it an update even with the same `stela.efi`.
//!   Bundles of a generation that no kept version boots are removed. The
//!   cache store's spare is prepared before activating an EFI version:
//!   its new translator takes that spare, while previous translators'
//!   packs remain bound to their own identities for rollback. Repeating
//!   an already-installed update replenishes a consumed spare without
//!   replacing EFI, boot configuration or update history.
//! - macOS: an installed macOS updates itself: Software Update stages the
//!   new system on the container's Update volume and sets `boot-command
//!   upgrade`, which `stela.efi` boots from that volume as iBEC would
//!   (`stela_loader::upgrade`), and every later boot builds from the
//!   Preboot volume's new objects. `--update-os` brings the setup to a new
//!   build offline: its System Recovery bundles and, for a setup with
//!   installs, the build's install medium and each machine's erase and
//!   update restore bundles. The Update macOS choice then restores
//!   the build's Update identity over the installed system, keeping its
//!   data, as Apple Configurator's update restore does. The previous
//!   build's medium is kept for rollback ([`MEDIA_KEPT`] media in all), so
//!   the USB needs room for both.
//!
//! Neither touches the installed disks' partitions.
use super::{
    Environment, LOADER_PATH, MEDIA_KEPT, Prepared, Record, apply_install, bundle,
    check_bundle_revision, check_space, copy_bundles, describe_install, first_schema, plan_install,
    prepare_bundles, prepare_kind, publish, read_efi, restore_bundles, write_record,
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
pub(super) const KEEP: usize = 3;

/// One update, as the record keeps it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Change {
    /// `stela.efi` versions, and the generations of the bundles they boot:
    /// the schemas they read and the revisions of the bundles, 0 for an
    /// update recorded before revisions.
    Stela {
        from: String,
        to: String,
        #[serde(default = "first_schema")]
        from_schema: u32,
        #[serde(default = "first_schema")]
        to_schema: u32,
        #[serde(default)]
        from_revision: u32,
        #[serde(default)]
        to_revision: u32,
    },
    /// recoveryOS builds.
    Os { from: String, to: String },
}

impl Change {
    /// The bundle generations a Stela update goes from and to.
    fn generations(&self) -> Option<(bundle::Generation, bundle::Generation)> {
        match *self {
            Self::Stela {
                from_schema,
                to_schema,
                from_revision,
                to_revision,
                ..
            } => Some((
                bundle::Generation {
                    schema: from_schema,
                    revision: from_revision,
                },
                bundle::Generation {
                    schema: to_schema,
                    revision: to_revision,
                },
            )),
            Self::Os { .. } => None,
        }
    }
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

pub(super) fn check_firmware_support(esp: &Path, image: &[u8]) -> Result<()> {
    stela_loader::host_firmware::check_installed_mount(
        &esp.join(stela_loader::host_firmware::DIRECTORY),
        image,
    )
    .context("stela.efi cannot load installed host firmware; keep a compatible Stela version")?;
    Ok(())
}

fn activate_stela(esp: &Path, id: &str) -> Result<()> {
    let path = version_path(esp, id);
    ensure!(
        path.is_file() && fs::read(&path).is_ok_and(|image| version_id(&image) == id),
        "Stela version {id} is not kept intact at {}",
        path.display()
    );
    check_firmware_support(esp, &fs::read(&path)?)?;
    efi::add_mount(esp, &path, None, None)?;
    Ok(())
}

/// Point `stela.cfg` at `build`'s recoveryOS, which must have a bundle for
/// every machine of the active generation.
fn activate_build(record: &mut Record, build: &str) -> Result<()> {
    let missing = record.missing_bundles(build);
    ensure!(
        missing.is_empty(),
        "recoveryOS {build} has no {} bundle for {}; prepare them with `stela setup \
         --repair --ipsw` of that build after activating it, or keep the current build",
        record.generation(),
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
    remove_unbooted_bundles(record)?;
    // The media of the newest kept builds, the active one's first.
    let newest: Vec<String> = record
        .recovery_builds
        .iter()
        .rev()
        .filter(|build| **build != record.build)
        .take(MEDIA_KEPT - 1)
        .cloned()
        .chain([record.build.clone()])
        .collect();
    let (kept, stale): (Vec<_>, Vec<_>) = record
        .media
        .drain(..)
        .partition(|m| newest.contains(&m.build));
    record.media = kept;
    for medium in stale {
        remove_medium(&medium)?;
    }
    Ok(())
}

/// Remove the bundles of generations that neither the active `stela.efi`
/// nor one a kept update rolls back to boots.
fn remove_unbooted_bundles(record: &mut Record) -> Result<()> {
    let booted: Vec<bundle::Generation> = record
        .history
        .iter()
        .filter_map(|change| change.generations().map(|(from, _)| from))
        .chain([record.generation()])
        .collect();
    let (kept, stale): (Vec<_>, Vec<_>) = record
        .bundles
        .drain(..)
        .partition(|b| booted.contains(&b.generation()));
    record.bundles = kept;
    super::remove_bundles(record, &stale)
}

/// Delete a medium the record no longer names.
fn remove_medium(medium: &super::medium::Medium) -> Result<()> {
    let directory = medium.removable_directory()?;
    if directory.is_dir() {
        fs::remove_dir_all(&directory)
            .with_context(|| format!("cannot remove {}", directory.display()))?;
    }
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
/// and this `stela`'s revision from `ipsw` when the setup's are of another.
pub(super) fn update_stela(
    environment: &Environment<'_>,
    mut record: Record,
    image_path: &Path,
    ipsw: Option<&Path>,
    dry_run: bool,
) -> Result<String> {
    let image = read_efi(environment, image_path)?;
    check_firmware_support(&record.esp, &image)?;
    let to = version_id(&image);
    let to_generation = environment.generation();
    ready(
        &record,
        |pending| matches!(pending, Change::Stela { to: t, .. } if *t == to),
    )?;
    let esp = record.esp.clone();
    let current = fs::read(esp.join(LOADER_PATH))
        .with_context(|| format!("{} has no {LOADER_PATH}", esp.display()))?;
    let (from, from_generation) = match &record.pending {
        Some(pending @ Change::Stela { from, .. }) => (
            from.clone(),
            pending.generations().expect("a Stela update").0,
        ),
        _ => (version_id(&current), record.generation()),
    };
    let mut text = String::new();
    writeln!(text, "Stela update on {}:", esp.display())?;
    text.push_str(&super::fdr::prepare(&record, true)?);
    if from == to && record.pending.is_none() && from_generation == to_generation {
        if !dry_run {
            super::fdr::prepare(&record, false)?;
        }
        writeln!(text, "  stela.efi      version {to} is already installed")?;
        if let Some(store) = &record.translations
            && (!store.config_intact() || !store.spare_ready())
        {
            writeln!(
                text,
                "  translations   prepare the cache configuration and spare"
            )?;
            if dry_run {
                text.push_str("Dry run: nothing was changed.\n");
            } else {
                store.publish()?;
            }
        }
        return Ok(text);
    }
    if from == to {
        writeln!(text, "  stela.efi      version {to} stays")?;
    } else {
        writeln!(text, "  stela.efi      version {from} -> {to}")?;
        writeln!(
            text,
            "  keeps          {} and {}",
            version_path(&esp, &from).display(),
            version_path(&esp, &to).display()
        )?;
    }
    // Bundles of the new generation for every machine of the active build,
    // restore ones too while it has an install medium.
    let mut next = record.clone();
    next.bundle_schema = to_generation.schema;
    next.bundle_revision = to_generation.revision;
    let missing = next.missing_bundles(&record.build);
    let missing_restore = match from_generation == to_generation {
        true => Vec::new(),
        false => next.missing_restore_bundles(),
    };
    let prepared = if missing.is_empty() && missing_restore.is_empty() {
        Vec::new()
    } else {
        let Some(ipsw) = ipsw else {
            bail!(
                "this stela and stela.efi {to} boot bundles of {to_generation}, and this \
                 setup's are {from_generation}: pass the macOS {} restore image with --ipsw or \
                 --fetch so the update prepares new ones",
                record.build
            );
        };
        let mut prepared: Vec<Prepared> = Vec::new();
        if !missing.is_empty() {
            prepared.extend(
                prepare_bundles(
                    environment,
                    ipsw,
                    &record.model,
                    Some(&record.build),
                    &missing,
                )?
                .2,
            );
        }
        for kind in bundle::RESTORE_KINDS {
            let ecids: Vec<_> = missing_restore
                .iter()
                .filter(|(k, _)| *k == kind)
                .map(|&(_, ecid)| ecid)
                .collect();
            if !ecids.is_empty() {
                let (_, _, restore) = prepare_kind(
                    environment,
                    kind,
                    record.tss,
                    ipsw,
                    &record.model,
                    Some(&record.build),
                    &ecids,
                )?;
                prepared.extend(restore);
            }
        }
        check_space(environment.host, &record.volume, &prepared)?;
        prepared
    };
    for bundle in &prepared {
        writeln!(
            text,
            "  {:<14} {} ({to_generation}, {:.1} GB); the {from_generation} bundles stay for \
             rollback",
            bundle.kind.label(),
            bundle::directory_of(
                bundle.kind,
                &record.volume,
                &bundle.build,
                bundle.ecid,
                to_generation
            )
            .display(),
            bundle.bytes as f64 / 1e9
        )?;
    }
    match &record.translations {
        Some(store) => {
            if from == to {
                writeln!(text, "  translations   {}", store.describe())?;
            } else {
                writeln!(
                    text,
                    "  translations   {}; the new stela.efi translates anew into its own pack",
                    store.describe()
                )?;
            }
            for pack in store.stale() {
                writeln!(text, "  remove         {}", pack.path.display())?;
            }
        }
        None => writeln!(text, "  translations   no store on this USB")?,
    }
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
        record.pending = Some(stela_change(&from, &to, from_generation, to_generation));
        write_record(&esp, &record)?;
    }
    record.bundle_schema = to_generation.schema;
    record.bundle_revision = to_generation.revision;
    copy_bundles(&mut record, &prepared)?;
    write_record(&esp, &record)?;
    store_version(&esp, &image)?;
    // A new translator must have its bounded spare before its EFI becomes
    // active. Failure leaves the old loader active and the update pending.
    if let Some(store) = &record.translations {
        store.publish()?;
    }
    super::fdr::prepare(&record, false)?;
    activate_stela(&esp, &to)?;
    publish(&mut record)?;
    record.stela_version = Some(to.clone());
    record.stela_versions.retain(|id| *id != to);
    record.stela_versions.push(to.clone());
    record
        .history
        .push(stela_change(&from, &to, from_generation, to_generation));
    record.pending = None;
    prune(&mut record)?;
    if let Some(store) = &record.translations {
        store.prune()?;
    }
    write_record(&esp, &record)?;
    text.push_str("Done. Undo with: stela setup --rollback\n");
    Ok(text)
}

fn stela_change(
    from: &str,
    to: &str,
    from_generation: bundle::Generation,
    to_generation: bundle::Generation,
) -> Change {
    Change::Stela {
        from: from.into(),
        to: to.into(),
        from_schema: from_generation.schema,
        to_schema: to_generation.schema,
        from_revision: from_generation.revision,
        to_revision: to_generation.revision,
    }
}

/// Add `ipsw`'s recoveryOS for every machine and boot it for System
/// Recovery.
pub(super) fn update_os(
    environment: &Environment<'_>,
    mut record: Record,
    ipsw: &Path,
    dry_run: bool,
) -> Result<String> {
    check_bundle_revision(environment, &record)?;
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
    let recovery_bytes: u64 = prepared.iter().map(|p| p.bytes).sum();
    // With installs, the build's install medium and restore bundles, so
    // Install and Update macOS restore the new build offline.
    let install = match record.installs.is_empty() {
        true => {
            check_space(environment.host, &record.volume, &prepared)?;
            None
        }
        false => Some(plan_install(
            environment,
            &record,
            &build,
            record
                .active_medium()
                .or(record.media.last())
                .map(|medium| medium.volume.as_path()),
            ipsw,
            &restore_bundles(&record.install_machines()),
            recovery_bytes,
        )?),
    };
    let mut text = String::new();
    writeln!(text, "macOS update to {product_version} ({build}):")?;
    for bundle in &prepared {
        writeln!(
            text,
            "  recoveryOS     {} ({:.1} GB); {from}'s stays for rollback",
            bundle::directory(&record.volume, &build, bundle.ecid, record.generation()).display(),
            bundle.bytes as f64 / 1e9
        )?;
    }
    if let Some(plan) = &install {
        describe_install(&record, plan, &mut text)?;
        if let Some(medium) = record.active_medium() {
            writeln!(
                text,
                "  keeps          {} for rollback",
                medium.directory().display()
            )?;
        }
    }
    writeln!(
        text,
        "  stela.cfg      boots recoveryOS {build} for System Recovery"
    )?;
    match &install {
        Some(_) => writeln!(
            text,
            "  next           choose Update macOS in the startup choices: it restores \
             {product_version} over the installed system offline and keeps its data (Install \
             macOS erases the disk instead)"
        )?,
        None => writeln!(
            text,
            "  next           boot System Recovery and choose Reinstall macOS, which downloads \
             {product_version} from Apple; an install added with --target restores it offline"
        )?,
    }
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
    if let Some(plan) = install {
        apply_install(environment, &mut record, ipsw, plan)?;
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
    if let Change::Stela { from, .. } = &change {
        check_firmware_support(&record.esp, &fs::read(version_path(&record.esp, from))?)?;
    }
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
        Change::Stela { from, to, .. } => {
            let (from_generation, _) = change.generations().expect("a Stela update");
            // The older translator may need a cold pack too. Preserve its
            // existing pack, and prepare only the spare/configuration.
            if let Some(store) = &record.translations {
                store.publish()?;
            }
            activate_stela(&esp, from)?;
            record.stela_version = Some(from.clone());
            record.bundle_schema = from_generation.schema;
            record.bundle_revision = from_generation.revision;
            publish(&mut record)?;
            let directory = esp.join(VERSIONS).join(to);
            if *to != *from {
                record.stela_versions.retain(|id| id != to);
                if directory.is_dir() {
                    fs::remove_dir_all(directory)?;
                }
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
            let (stale, kept): (Vec<_>, Vec<_>) =
                record.media.drain(..).partition(|m| m.build == *to);
            record.media = kept;
            for medium in &stale {
                remove_medium(medium)?;
            }
            if record.installs_media() && record.active_medium().is_none() {
                writeln!(
                    text,
                    "  note           the macOS {from} install medium is no longer kept; \
                     `stela setup --repair --ipsw` with its restore image writes it again"
                )?;
            }
        }
    }
    if pending {
        record.pending = None;
    } else {
        record.history.pop();
    }
    // The bundles the undone update prepared, unless an earlier one boots
    // them.
    remove_unbooted_bundles(&mut record)?;
    write_record(&esp, &record)?;
    text.push_str("Done.\n");
    Ok(text)
}
