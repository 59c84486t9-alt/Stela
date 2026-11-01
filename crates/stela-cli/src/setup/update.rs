//! Updates of an existing setup: a Stela update replaces `stela.efi`, a
//! macOS update replaces the install medium and restore bundles. Each one
//! writes the new files first and removes the old ones last, so one that was
//! interrupted is finished by running it again.
//!
//! - Stela: the USB's boot loader is replaced atomically by the new one. A
//!   new `stela.efi` must carry this `stela`'s mount interface. When it reads
//!   another boot-bundle schema than the setup's bundles have, or this
//!   `stela` prepares another bundle revision
//!   (`stela_loader::boot_bundle::REVISION`) than theirs, the update prepares
//!   the active build's restore bundles for every machine again (while the
//!   setup has the build's install medium) at the new schema and revision,
//!   from `--ipsw` or `--fetch`; this makes it an update even with the same
//!   `stela.efi`. The cache store's spare is prepared before activating it:
//!   its new translator takes that spare. Repeating an already-installed
//!   update replenishes a consumed spare without replacing EFI or boot
//!   configuration.
//! - macOS: an installed macOS updates itself: Software Update stages the
//!   new system on the container's Update volume and sets `boot-command
//!   upgrade`, which `stela.efi` boots from that volume as iBEC would
//!   (`stela_loader::upgrade`), and every later boot builds from the
//!   Preboot volume's new objects. `update os` brings the setup's Install
//!   macOS to a new build offline: the build's install medium and each
//!   machine's restore bundles, so the USB needs room for both while it runs.
//!
//! Neither touches the installed disks' partitions.
use super::{
    Environment, LOADER_PATH, Prepared, Record, apply_install, bundle, check_bundle_revision,
    check_space, copy_bundles, describe_install, plan_install, prepare_kind, publish, read_efi,
    restore_bundles, write_record,
};
use crate::efi;
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{fmt::Write as _, fs, path::Path};

pub(super) fn version_id(image: &[u8]) -> String {
    let digest = hex::encode(Sha256::digest(image));
    digest[..16].into()
}

pub(super) fn check_firmware_support(esp: &Path, image: &[u8]) -> Result<()> {
    stela_loader::host_firmware::check_installed_mount(
        &esp.join(stela_loader::host_firmware::DIRECTORY),
        image,
    )
    .context("stela.efi cannot load installed host firmware")?;
    Ok(())
}

/// Make `build` the active build, which Install macOS restores; its
/// restore bundles and medium are the startup choices' from now on.
fn activate_build(record: &mut Record, build: &str) -> Result<()> {
    record.build = build.into();
    record.bundle_directory = bundle::build_directory(&record.volume, build);
    publish(record)
}

/// Remove the bundles and media of everything but the active build and
/// generation.
fn prune(record: &mut Record) -> Result<()> {
    let (build, generation) = (record.build.clone(), record.generation());
    let (active, stale): (Vec<_>, Vec<_>) = record
        .bundles
        .drain(..)
        .partition(|b| b.build == build && b.generation() == generation);
    record.bundles = active;
    super::remove_bundles(record, &stale)?;
    for build in stale.iter().map(|b| &b.build) {
        let directory = bundle::build_directory(&record.volume, build);
        if *build != record.build && directory.is_dir() {
            fs::remove_dir_all(directory)?;
        }
    }
    let (active, stale): (Vec<_>, Vec<_>) = record.media.drain(..).partition(|m| m.build == build);
    record.media = active;
    for medium in stale {
        remove_medium(&medium)?;
    }
    Ok(())
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

/// Refuse a change to an interrupted setup.
pub(super) fn ready(record: &Record) -> Result<()> {
    ensure!(
        record.complete,
        "the setup on {} was interrupted; run `stela setup uninstall` and set up again",
        record.esp.display()
    );
    Ok(())
}

/// Image sources and write policy for a Stela update.
pub(super) struct UpdateOptions<'a> {
    pub(super) image_path: &'a Path,
    pub(super) ipsw: Option<&'a Path>,
    pub(super) dry_run: bool,
}

/// Replace `stela.efi` with `image_path`, preparing bundles of its schema
/// and this `stela`'s revision from `ipsw` when the setup's are of another.
pub(super) fn update_stela(
    environment: &Environment<'_>,
    mut record: Record,
    options: UpdateOptions<'_>,
) -> Result<String> {
    let UpdateOptions {
        image_path,
        ipsw,
        dry_run,
    } = options;
    let image = read_efi(environment, image_path)?;
    check_firmware_support(&record.esp, &image)?;
    let to = version_id(&image);
    let to_generation = environment.generation();
    ready(&record)?;
    let esp = record.esp.clone();
    // A missing or damaged loader is what an update also puts right.
    let from = fs::read(esp.join(LOADER_PATH)).map_or("none".into(), |image| version_id(&image));
    let from_generation = record.generation();
    let mut text = String::new();
    writeln!(text, "Stela update on {}:", esp.display())?;
    text.push_str(&super::fdr::prepare(&record, true)?);
    if from == to && from_generation == to_generation {
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
    }
    // Restore bundles of the new generation for every machine of the active
    // build while it has an install medium.
    let mut next = record.clone();
    next.bundle_schema = to_generation.schema;
    next.bundle_revision = to_generation.revision;
    let missing_restore = match from_generation == to_generation {
        true => Vec::new(),
        false => next.missing_restore_bundles(),
    };
    let prepared = if missing_restore.is_empty() {
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
        for kind in bundle::RESTORE_KINDS {
            let ecids: Vec<_> = missing_restore
                .iter()
                .filter(|(k, _)| *k == kind)
                .map(|&(_, ecid)| ecid)
                .collect();
            if !ecids.is_empty() {
                let (_, _, restore) = prepare_kind(
                    environment,
                    super::prepare::BundleOptions {
                        kind,
                        tss: record.tss,
                        ipsw,
                        model: &record.model,
                        build: Some(&record.build),
                        ecids: &ecids,
                    },
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
            "  {:<14} {} ({to_generation}, {:.1} GB); the {from_generation} bundles go",
            bundle.kind.label(),
            bundle::directory_of(
                &record.volume,
                bundle::Identity {
                    kind: bundle.kind,
                    build: &bundle.build,
                    ecid: bundle.ecid,
                    generation: to_generation
                }
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
    record.bundle_schema = to_generation.schema;
    record.bundle_revision = to_generation.revision;
    copy_bundles(&mut record, &prepared)?;
    write_record(&esp, &record)?;
    // A new translator must have its bounded spare before its EFI becomes
    // active. Failure leaves the old loader active.
    if let Some(store) = &record.translations {
        store.publish()?;
    }
    super::fdr::prepare(&record, false)?;
    efi::add_mount(&esp, &image, None, None)?;
    publish(&mut record)?;
    record.stela_version = Some(to);
    prune(&mut record)?;
    if let Some(store) = &record.translations {
        store.prune()?;
    }
    write_record(&esp, &record)?;
    text.push_str("Done.\n");
    Ok(text)
}

/// Add `ipsw`'s install medium and every machine's restore bundles, and
/// make its build the one Install macOS restores.
pub(super) fn update_os(
    environment: &Environment<'_>,
    mut record: Record,
    ipsw: &Path,
    dry_run: bool,
) -> Result<String> {
    check_bundle_revision(environment, &record)?;
    let (product_version, build) = crate::restore::payload::identity(ipsw, &record.model)?;
    super::supported(environment, ipsw, &build)?;
    ready(&record)?;
    let from = record.build.clone();
    ensure!(
        build != from,
        "macOS {build} is already the build this setup installs"
    );
    // The build's install medium and restore bundles, so Install macOS
    // restores the new build offline.
    let install = plan_install(
        environment,
        &record,
        super::create::InstallOptions {
            build: &build,
            ipsw,
            bundles: &restore_bundles(&record.install_machines()),
            additional_bytes: 0,
        },
    )?;
    let mut text = String::new();
    writeln!(text, "macOS update to {product_version} ({build}):")?;
    describe_install(&record, &install, &mut text)?;
    if let Some(medium) = record.active_medium() {
        writeln!(
            text,
            "  remove         {} and {from}'s restore bundles",
            medium.directory().display()
        )?;
    }
    writeln!(
        text,
        "  next           choose Install macOS in the startup choices: it erases the disk and \
         restores {product_version}"
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
    apply_install(environment, &mut record, ipsw, install)?;
    activate_build(&mut record, &build)?;
    prune(&mut record)?;
    write_record(&record.esp.clone(), &record)?;
    text.push_str("Done.\n");
    Ok(text)
}
