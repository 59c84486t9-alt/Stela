//! `--status` (also `--doctor`) and `--repair`.
//!
//! Status reads everything a setup consists of and changes nothing: the
//! record and any pending update, the installed `stela.efi` against its
//! kept version and this `stela`'s mount interface, the USB's boot loader,
//! `stela.cfg` and the startup choices against the record, every restore
//! bundle file against its `bundle.json` and the active ones'
//! revision against the one this `stela` prepares, the install medium's
//! manifest and pieces, and for each install its
//! partitions (still the recorded ones), the systems on its Apple region,
//! its NVRAM (what the next boot will be, and a failed update's
//! `ota-result`) and whether its SEP state is provisioned. Each problem
//! names the command that fixes it, and any problem fails the command.
//!
//! Repair puts back what the record says: the active `stela.efi` from its
//! kept copy, the entry, `stela.cfg` and the startup choices, and, from the
//! active build's restore image (`--ipsw` or `--fetch`), every damaged or
//! missing restore bundle and a damaged install medium; with an image it
//! prepares every restore bundle of the active build again, with each
//! machine's own ECID, and gives an install without one its ECID
//! (`machines::machine_ecid`).
use super::{
    CHOICES_PATH, Environment, LOADER_PATH, RECORD, Record, Setup, apply_install, bundle,
    check_bundle_revision, describe_install, ecid::Ecid, host::Host, installed, machines,
    plan_install, publish, read_record, revision_mismatch, state, update, write_record,
};
use crate::efi;
use anyhow::{Result, bail};
use std::{fmt::Write as _, fs, path::Path};
use stela_loader::{boot_selection, mount_interface, recovery};
use stela_runtime::{
    apfs::{self, Container, volume::APFS_VOL_ROLE_UPDATE},
    machine::apple::{nor::CAPACITY, sep_state},
    payload::ReadAt,
    preboot,
};

/// A host partition as an APFS source.
struct Partition<'a> {
    host: &'a dyn Host,
    identifier: String,
    bytes: u64,
}

impl ReadAt for Partition<'_> {
    type Error = String;

    fn len(&self) -> u64 {
        self.bytes
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), String> {
        let bytes = self
            .host
            .read(&self.identifier, offset, buffer.len())
            .map_err(|error| format!("{error:#}"))?;
        buffer.copy_from_slice(&bytes);
        Ok(())
    }
}

/// The installed systems on an Apple region: each container's boot
/// directories, whether it has a staged update, and the boot directories
/// of its paired recoveryOS and System Recovery (`stela_loader::recovery`).
fn systems(host: &dyn Host, identifier: &str, bytes: u64) -> Vec<String> {
    let mut disk = Partition {
        host,
        identifier: identifier.into(),
        bytes,
    };
    let partitions = match apfs::container_partitions(&mut disk) {
        Ok(partitions) => partitions,
        Err(_) => return Vec::new(),
    };
    let mut found = Vec::new();
    for (offset, _) in partitions {
        let Ok(mut container) = Container::open(&mut disk, offset) else {
            continue;
        };
        let update = container.volume_with_role(APFS_VOL_ROLE_UPDATE).is_ok();
        match preboot::candidates(&mut container) {
            Ok((_, sets)) => {
                for set in sets {
                    found.push(format!(
                        "container at {offset:#x}: {}{}",
                        set.directory(),
                        if update {
                            "; an update is staged on its Update volume"
                        } else {
                            ""
                        }
                    ));
                }
            }
            Err(error) => found.push(format!(
                "container at {offset:#x}: no boot objects ({error})"
            )),
        }
    }
    // The recoveryOS copies stela.efi boots when NVRAM asks for one.
    for kind in [recovery::Kind::Paired, recovery::Kind::System] {
        match recovery::find(&mut disk, kind, None) {
            Ok(copies) => {
                for copy in copies {
                    for set in &copy.sets {
                        found.push(format!(
                            "{} at {:#x}: {}",
                            kind.label(),
                            copy.offset,
                            set.directory()
                        ));
                    }
                }
            }
            Err(error) => found.push(format!("{}: unreadable ({error:#})", kind.label())),
        }
    }
    found
}

/// The report and its problems.
struct Report {
    text: String,
    problems: Vec<String>,
}

impl Report {
    fn line(&mut self, label: &str, value: impl std::fmt::Display) {
        let _ = writeln!(self.text, "  {label:<14} {value}");
    }

    fn problem(&mut self, problem: String) {
        self.problems.push(problem);
    }
}

/// The translation store's packs, and what `--repair` would fix.
fn translations_status(record: &Record, report: &mut Report) {
    let Some(store) = &record.translations else {
        report.line(
            "translations",
            "no store: every boot translates anew (the USB had no room for one)",
        );
        return;
    };
    report.line("translations", store.describe());
    for pack in store.packs() {
        report.line(
            "  pack",
            format!(
                "{} ({:.1} MB)",
                pack.path.display(),
                pack.bytes as f64 / 1e6
            ),
        );
    }
    for repair in store.repairs() {
        report.problem(format!(
            "translation store: {repair}: `stela setup --repair`"
        ));
    }
}

fn efi_status(environment: &Environment<'_>, record: &Record, report: &mut Report) {
    let tool = record.esp.join(LOADER_PATH);
    match fs::read(&tool) {
        Ok(image) => {
            let id = update::version_id(&image);
            let interface = mount_interface::find(&image);
            report.line(
                "stela.efi",
                format!(
                    "version {id}{}",
                    interface
                        .map(|i| format!(", reads boot-bundle schema {}", i.bundle_schema))
                        .unwrap_or_default()
                ),
            );
            if record.stela_version.as_deref() != Some(id.as_str()) {
                report.problem(format!(
                    "{} is not the version setup installed ({}): `stela setup --repair`",
                    tool.display(),
                    record.stela_version.as_deref().unwrap_or("unknown")
                ));
            }
            if let Some(reason) = mount_interface::mismatch(environment.interface, interface) {
                report.problem(format!(
                    "the installed stela.efi does not read what this stela writes ({reason}): \
                     `stela setup --update-stela`"
                ));
            }
        }
        Err(_) => report.problem(format!(
            "{} is missing: `stela setup --repair`",
            tool.display()
        )),
    }
    for id in &record.stela_versions {
        let kept = update::version_path(&record.esp, id);
        let intact = fs::read(&kept).is_ok_and(|image| update::version_id(&image) == *id);
        if !intact {
            report.problem(format!(
                "kept stela.efi {id} at {} is missing or damaged; rollback to it is not possible",
                kept.display()
            ));
        }
    }
    report.line("kept versions", record.stela_versions.join(", "));
    let options = fs::read_to_string(record.esp.join("EFI/stela/stela.cfg")).unwrap_or_default();
    match record.options_text() {
        Ok(expected) if options != expected => {
            report.problem("stela.cfg differs from the setup record: `stela setup --repair`".into())
        }
        Ok(_) => {}
        Err(error) => report.problem(format!(
            "stela.cfg cannot be written from the setup record: {error:#}"
        )),
    }
    let choices = fs::read_to_string(record.esp.join(CHOICES_PATH)).ok();
    match record.choices_text() {
        Ok(expected) if choices != expected => report.problem(
            "the startup choices (choices.cfg) differ from the setup record: `stela setup \
             --repair`"
                .into(),
        ),
        Ok(_) => {}
        Err(error) => report.problem(format!("the startup choices: {error:#}")),
    }
}

fn bundle_status(environment: &Environment<'_>, record: &Record, report: &mut Report) {
    for kept in &record.bundles {
        let directory = kept.directory(&record.volume);
        let role = if kept.build == record.build && kept.generation() == record.generation() {
            "active"
        } else {
            "kept for rollback"
        };
        let problems = bundle::verify(&directory, &kept.manifest_sha256);
        report.line(
            kept.kind.label(),
            format!(
                "{} ({role}, {}{}): {}",
                directory.display(),
                kept.generation(),
                kept.ecid
                    .map(|ecid| format!(", ECID {ecid}"))
                    .unwrap_or_default(),
                if problems.is_empty() {
                    "intact"
                } else {
                    "DAMAGED"
                }
            ),
        );
        for problem in problems {
            report.problem(format!(
                "{problem}: `stela setup --repair --ipsw` with the macOS {} restore image",
                kept.build
            ));
        }
    }
    for directory in record.build_directories() {
        for (_, what) in bundle::leftovers(&directory) {
            report.problem(format!("{what}: `stela setup --repair` puts it right"));
        }
    }
    if let Some(reason) = revision_mismatch(environment, record) {
        report.problem(reason);
    }
    for (kind, ecid) in record.missing_restore_bundles() {
        report.problem(format!(
            "the active build {} has no {} bundle for {}, so its {} choice is missing: `stela \
             setup --repair --ipsw`",
            record.build,
            kind.label(),
            ecid.map_or_else(|| "the setup".into(), |e| format!("ECID {e}")),
            super::restore_choice_name(kind)
        ));
    }
    if record.installs_media() && record.active_medium().is_none() {
        report.problem(format!(
            "the active build {} has no install medium, so its Install macOS choice is \
             missing: `stela setup --repair --ipsw` with its restore image",
            record.build
        ));
    }
    for medium in &record.media {
        let problems = medium.problems();
        report.line(
            if medium.build == record.build {
                "install medium"
            } else {
                "kept medium"
            },
            format!(
                "{} (macOS {}, partition {}): {}",
                medium.directory().display(),
                medium.build,
                medium.partition_guid,
                if problems.is_empty() {
                    "intact"
                } else {
                    "DAMAGED"
                }
            ),
        );
        for problem in problems {
            report.problem(format!(
                "{problem}: `stela setup --repair --ipsw` with the macOS {} restore image",
                medium.build
            ));
        }
        if medium.build == record.build && !record.tss {
            report.problem(
                "the Install macOS choice is off because the restore needs Apple's \
                 signing server: `stela setup --tss`"
                    .into(),
            );
        }
    }
}

fn install_status(
    environment: &Environment<'_>,
    record: &Record,
    install: &machines::Install,
    report: &mut Report,
) {
    let host = environment.host;
    let default = record.default().is_some_and(|d| d.name == install.name);
    let _ = writeln!(
        report.text,
        "Install \"{}\"{}:",
        install.name,
        if default { " (default)" } else { "" }
    );
    match install.ecid {
        Some(ecid) => report.line("ECID", ecid),
        None => report.problem(format!(
            "install \"{}\" has no ECID (an older setup made it): `stela setup --repair --ipsw`, \
             with --ecid or --new-ecid when its SEP state is provisioned",
            install.name
        )),
    }
    let disk = &install.disk;
    // A portable installer's disk is chosen in stela.efi, out of this
    // computer's reach.
    if disk.is_chosen() {
        report.line(
            "Apple region",
            "chosen in stela.efi on the PC when Install macOS starts",
        );
        return;
    }
    match installed::confirm(host, disk, installed::Role::AppleRegion, None) {
        Ok(region) => {
            let bytes = host.partition(&region).map(|p| p.bytes).unwrap_or(0);
            // The guest's SSD ends where a machine state in its tail starts.
            let bytes = disk.machine_state_offset.unwrap_or(bytes).min(bytes);
            let systems = systems(host, &region, bytes);
            report.line(
                "Apple region",
                format!(
                    "{region} (serial {}, partition {}): {}",
                    disk.apple_region_serial,
                    disk.apple_region_guid,
                    if systems.is_empty() {
                        "no installed macOS yet; choose Install macOS"
                    } else {
                        "macOS installed"
                    }
                ),
            );
            for system in systems {
                report.line("", system);
            }
        }
        Err(error) => report.problem(format!(
            "install \"{}\"'s Apple region: {error:#}",
            install.name
        )),
    }
    if let Ok(Some(region)) = installed::foreign(host, disk) {
        report.problem(foreign_problem(&install.name, &region.identifier));
    }
    let area = match installed::state_area(host, disk, None) {
        Ok(area) => area,
        Err(error) => {
            report.problem(format!(
                "install \"{}\"'s machine state: {error:#}",
                install.name
            ));
            return;
        }
    };
    let nor = area.identifier.clone();
    match disk.machine_state_offset {
        Some(_) => report.line(
            "machine state",
            format!("{}: {:#x} bytes", disk.state_description(), area.bytes),
        ),
        None => report.line("NOR", disk.state_description()),
    }
    let bytes = match area.read(host, 0, CAPACITY + sep_state::BYTES as usize) {
        Ok(bytes) => bytes,
        Err(error) => {
            report.problem(format!("{} cannot be read: {error:#}", area.describe()));
            return;
        }
    };
    let (nor_bytes, sep_area) = bytes.split_at(CAPACITY);
    match state::nvram(nor_bytes) {
        state::Nvram::Blank => report.line("NVRAM", "blank: stela.efi writes it at first boot"),
        state::Nvram::Valid(variables) => {
            report.line("next boot", state::next_boot(&variables));
            for name in [
                boot_selection::OTA_RESULT,
                boot_selection::OTA_FAILURE_REASON,
            ] {
                if let Some(value) = boot_selection::lookup(&variables, name) {
                    report.line(
                        "update",
                        format!(
                            "{}: {}",
                            String::from_utf8_lossy(name),
                            String::from_utf8_lossy(value)
                        ),
                    );
                }
            }
        }
        state::Nvram::Invalid(error) => report.problem(format!(
            "{nor}'s NVRAM is unreadable ({error}): `stela setup --reset-nvram --nor {nor}`"
        )),
    }
    match state::sep(sep_area) {
        Ok(true) => report.line(
            "SEP state",
            "provisioned; back it up with `stela setup --backup-state FILE`",
        ),
        Ok(false) => report.line("SEP state", "blank: the SEP provisions it at first boot"),
        Err(error) => report.problem(format!(
            "{nor}'s SEP area: {error}; restore it with `stela setup --restore-state FILE --nor \
             {nor}`"
        )),
    }
}

/// `--status`.
/// An install's Apple region holds another file system.
fn foreign_problem(install: &str, region: &str) -> String {
    format!(
        "install \"{install}\"'s Apple region {region} holds another file system, which the PC's \
         own OS mounts, clearing the free space it sees, Stela's machine state included"
    )
}

pub(super) fn status(environment: &Environment<'_>, usb: &Path) -> Result<String> {
    let record = read_record(environment, usb)?;
    let mut report = Report {
        text: String::new(),
        problems: Vec::new(),
    };
    let _ = writeln!(
        report.text,
        "Stela setup on {} ({}):",
        record.esp.display(),
        record.esp.join(RECORD).display()
    );
    if !record.complete {
        report.problem(
            "the setup was interrupted: `stela setup --uninstall`, then set up again".into(),
        );
    }
    if let Some(pending) = &record.pending {
        report.problem(format!(
            "an update was interrupted ({pending:?}): run it again, or `stela setup --rollback`"
        ));
    }
    report.line("model", &record.model);
    report.line(
        "macOS build",
        format!("{} (Install macOS restores it)", record.build),
    );
    report.line("kept builds", record.builds.join(", "));
    report.line(
        "TSS",
        if record.tss {
            "on: the restore host may send the ECID and component hashes to gs.apple.com"
        } else {
            "off"
        },
    );
    efi_status(environment, &record, &mut report);
    bundle_status(environment, &record, &mut report);
    translations_status(&record, &mut report);
    for install in &record.installs {
        install_status(environment, &record, install, &mut report);
    }
    let mut text = report.text;
    if report.problems.is_empty() {
        text.push_str("No problems found.\n");
        return Ok(text);
    }
    let _ = writeln!(text, "{} problems:", report.problems.len());
    for problem in &report.problems {
        let _ = writeln!(text, "  - {problem}");
    }
    bail!("{text}")
}

/// `--repair`.
pub(super) fn repair(environment: &Environment<'_>, command: &Setup) -> Result<String> {
    let mut record = read_record(environment, &command.usb)?;
    update::ready(&record, |_| false)?;
    let esp = record.esp.clone();
    let mut text = format!("Stela repair on {}:\n", esp.display());
    // The active stela.efi from its kept copy.
    let id = record
        .stela_version
        .clone()
        .ok_or_else(|| anyhow::anyhow!("the setup record names no stela.efi version"))?;
    let kept = update::version_path(&esp, &id);
    let kept_image = fs::read(&kept)
        .ok()
        .filter(|image| update::version_id(image) == id);
    let tool = fs::read(esp.join(LOADER_PATH)).ok();
    let restore_tool = tool
        .as_ref()
        .is_none_or(|image| update::version_id(image) != id);
    let Some(kept_image) = kept_image else {
        bail!(
            "the kept stela.efi {id} at {} is missing or damaged; install one with `stela setup \
             --update-stela`",
            kept.display()
        );
    };
    if let Some(reason) =
        mount_interface::mismatch(environment.interface, mount_interface::find(&kept_image))
    {
        bail!(
            "the setup's stela.efi does not read what this stela writes ({reason}); `stela \
             setup --update-stela` first"
        );
    }
    update::check_firmware_support(&esp, &kept_image)?;
    if restore_tool {
        writeln!(text, "  stela.efi      put back version {id}")?;
    }
    // Machines without an ECID get one; their bundles are prepared again.
    let ipsw = command.optional_image()?;
    if ipsw.is_some() {
        check_bundle_revision(environment, &record)?;
    }
    record.install_image = command.install_image.or(record.install_image);
    let mut notes = Vec::new();
    let mut assigned: Vec<(String, Ecid)> = Vec::new();
    if ipsw.is_some() {
        for index in 0..record.installs.len() {
            if record.installs[index].ecid.is_some() {
                continue;
            }
            let install = record.installs[index].clone();
            let area = installed::state_area(environment.host, &install.disk, None)?.read(
                environment.host,
                CAPACITY as u64,
                sep_state::ROOTS_BYTES,
            )?;
            let provisioned = state::sep(&area).unwrap_or(false);
            let ecid = machines::machine_ecid(
                command.ecid,
                None,
                provisioned,
                command.new_ecid,
                &mut notes,
            )?;
            record.installs[index].ecid = Some(ecid);
            assigned.push((install.name.clone(), ecid));
        }
    }
    for (name, ecid) in &assigned {
        writeln!(text, "  ECID           install \"{name}\" is now {ecid}")?;
    }
    // What interrupted copies left, before any bundle is judged; a dry run
    // judges a set-aside bundle where it would be put back.
    for directory in record.build_directories() {
        for (destination, what) in bundle::leftovers(&directory) {
            if command.dry_run {
                writeln!(text, "  bundle         would put right: {what}")?;
                continue;
            }
            for done in bundle::recover(&destination)? {
                writeln!(text, "  bundle         {done}")?;
            }
        }
    }
    let stale = record.drop_stale_bundles();
    for old in &stale {
        writeln!(
            text,
            "  remove         {}",
            old.directory(&record.volume).display()
        )?;
    }
    // The install's restore bundles and medium: all again with an image.
    // A setup that has written media needs the active build's: it is put
    // back when damaged or missing.
    let has_media = record.installs_media();
    let damaged_medium = has_media
        && record
            .active_medium()
            .is_none_or(|medium| !medium.problems().is_empty());
    let mut restore: Vec<(bundle::Kind, Option<Ecid>)> = Vec::new();
    if has_media {
        for (kind, ecid) in super::restore_bundles(&record.install_machines()) {
            let intact = record.restore_bundle(kind, ecid).is_some_and(|b| {
                bundle::verify(
                    &bundle::in_place(&b.directory(&record.volume)),
                    &b.manifest_sha256,
                )
                .is_empty()
            });
            if ipsw.is_some() || !intact {
                restore.push((kind, ecid));
            }
        }
    }
    let install = match (&ipsw, restore.is_empty() && !damaged_medium) {
        (_, true) => None,
        (Some(ipsw), false) => {
            let plan = plan_install(environment, &record, &record.build, ipsw, &restore, 0)?;
            describe_install(&record, &plan, &mut text)?;
            Some(plan)
        }
        (None, false) => bail!(
            "{text}  install        {} restore bundles of macOS {} are damaged or missing{}: \
             pass its restore image with --ipsw or --fetch",
            restore.len(),
            record.build,
            if damaged_medium {
                ", and so is the install medium"
            } else {
                ""
            }
        ),
    };
    writeln!(
        text,
        "  boot loader    stela.efi, stela.cfg and the startup choices as recorded"
    )?;
    // An Apple region holding another file system: erased with
    // --erase-target, else named.
    let mut foreign = Vec::new();
    for install in &record.installs {
        if let Some(region) = installed::foreign(environment.host, &install.disk)? {
            if command.erase_target {
                writeln!(
                    text,
                    "  disks          erase the file system on {}, install \"{}\"'s Apple region",
                    region.identifier, install.name
                )?;
                foreign.push(region);
            } else {
                notes.push(format!(
                    "{}; pass --erase-target to erase it",
                    foreign_problem(&install.name, &region.identifier)
                ));
            }
        }
    }
    for note in &notes {
        writeln!(text, "  note           {note}")?;
    }
    let store_repairs = record
        .translations
        .as_ref()
        .map(super::translations::Store::repairs)
        .unwrap_or_default();
    for repair in &store_repairs {
        writeln!(text, "  translations   {repair}")?;
    }
    if command.dry_run {
        text.push_str("Dry run: nothing was changed.\n");
        return Ok(text);
    }
    if let Some(store) = &record.translations
        && !store_repairs.is_empty()
    {
        store.repair()?;
    }
    for region in &foreign {
        installed::erase_foreign(environment.host, region)?;
    }
    if let (Some(plan), Some(ipsw)) = (install, &ipsw) {
        apply_install(environment, &mut record, ipsw, plan)?;
    }
    if restore_tool {
        efi::add_mount(&esp, &kept, None, None)?;
    }
    publish(&mut record)?;
    write_record(&esp, &record)?;
    super::remove_bundles(&record, &stale)?;
    text.push_str("Done. Check it with: stela setup --status\n");
    Ok(text)
}
