//! Creating a setup: the plan of what it writes, its description, and
//! writing it.
use super::{
    CHOICES_PATH, CHOOSER_SECONDS, Environment, INSTALL_CHOICE, InstallImage, LOADER_PATH, MARGIN,
    RECORD, Request, assets,
    bundle::{self, Kind},
    ecid::Ecid,
    format,
    host::{self, Host},
    image_is_remote, installed, locate_esp, machines, medium,
    prepare::{
        Prepared, PreparedSetup, copy_bundles, prepare_kind, prepare_restore_bundles, supported,
    },
    read_efi,
    record::{RECORD_KIND, RECORD_SCHEMA, Record, publish, write_record},
    translations, update, wifi, wizard,
};
use crate::{efi, restore};
use anyhow::{Context, Result, bail, ensure};
use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};
use stela_formats::builds;

/// The setup USB's one unmounted partition besides its EFI partition: a
/// raw partition, which becomes the Mac's internal SSD. `None` when the USB
/// has none; several are refused, since setup cannot tell them apart.
pub(super) fn stick_ssd(host: &dyn Host, usb_disk: Option<&str>) -> Result<Option<String>> {
    let Some(usb_disk) = usb_disk else {
        return Ok(None);
    };
    let disks = host.disks()?;
    let Some(disk) = disks.iter().find(|disk| disk.identifier == usb_disk) else {
        return Ok(None);
    };
    let raw: Vec<&str> = disk
        .partitions
        .iter()
        .filter(|p| p.content != "EFI" && p.mount.is_none())
        .map(|p| p.identifier.as_str())
        .collect();
    match raw[..] {
        [] => Ok(None),
        [partition] => Ok(Some(partition.into())),
        _ => bail!(
            "{usb_disk} has several unmounted partitions ({}); name the Mac's internal SSD with \
             --target",
            raw.join(", ")
        ),
    }
}

/// The install medium setup writes.
pub(super) struct MediumPlan {
    pub(super) volume: PathBuf,
    pub(super) guid: String,
    /// It names the IPSW on Apple's servers (`medium::write_remote`).
    pub(super) remote: bool,
    pub(super) ipsw_bytes: u64,
    /// Bytes still to write, with the hash files and a margin.
    pub(super) need: u64,
    pub(super) expected: medium::Expected,
    /// Directories it creates, deepest first.
    pub(super) created: Vec<PathBuf>,
}

/// What installing macOS needs: each machine's restore bundles and, unless
/// the USB holds the build's intact medium, the install medium.
pub(super) struct InstallPlan {
    /// The macOS build it installs.
    pub(super) build: String,
    pub(super) restore: Vec<Prepared>,
    pub(super) medium: Option<MediumPlan>,
}

/// The restore bundles of both kinds for each of `ecids`.
pub(super) fn restore_bundles(ecids: &[Option<Ecid>]) -> Vec<(Kind, Option<Ecid>)> {
    bundle::RESTORE_KINDS
        .into_iter()
        .flat_map(|kind| ecids.iter().map(move |&ecid| (kind, ecid)))
        .collect()
}

/// Restore image, selected machine bundles and additional volume bytes.
pub(super) struct InstallOptions<'a> {
    pub(super) build: &'a str,
    pub(super) ipsw: &'a Path,
    pub(super) bundles: &'a [(Kind, Option<Ecid>)],
    pub(super) additional_bytes: u64,
}

/// Plan the install of `build` from `ipsw` for `record`: the restore
/// bundles `bundles` names and the build's install medium; and check the
/// data partition's space: `also` is what else setup writes to it.
pub(super) fn plan_install(
    environment: &Environment<'_>,
    record: &Record,
    options: InstallOptions<'_>,
) -> Result<InstallPlan> {
    let InstallOptions {
        build,
        ipsw,
        bundles,
        additional_bytes: also,
    } = options;
    let host = environment.host;
    let mut restore = Vec::new();
    for kind in bundle::RESTORE_KINDS {
        let ecids: Vec<Option<Ecid>> = bundles
            .iter()
            .filter(|(k, _)| *k == kind)
            .map(|&(_, ecid)| ecid)
            .collect();
        if !ecids.is_empty() {
            let (_, _, prepared) = prepare_kind(
                environment,
                super::prepare::BundleOptions {
                    kind,
                    tss: record.tss,
                    ipsw,
                    model: &record.model,
                    build: Some(build),
                    ecids: &ecids,
                },
            )?;
            restore.extend(prepared);
        }
    }
    let remote = environment.download.is_none() && record.remote_install(ipsw)?;
    let intact = record
        .medium_of(build)
        .is_some_and(|m| m.remote == remote && m.problems().is_empty());
    let medium = match intact {
        true => None,
        false if remote => Some(MediumPlan {
            volume: record.volume.clone(),
            guid: String::new(),
            remote,
            ipsw_bytes: 0,
            need: MARGIN,
            expected: medium::Expected::default(),
            created: missing_directories(&record.volume, &medium::directory(&record.volume, build)),
        }),
        false => {
            let receipt = restore::receipt(ipsw)?;
            let (volume, guid) = medium::locate(host, &record.esp, Some(&record.volume))?;
            let ipsw_bytes = match environment.download {
                Some(download) => download.bytes,
                None => fs::metadata(ipsw)?.len(),
            };
            let need = medium::needed_bytes(&volume, build, ipsw_bytes, environment.piece_bytes);
            let created = missing_directories(&volume, &medium::directory(&volume, build));
            Some(MediumPlan {
                volume,
                guid,
                remote,
                ipsw_bytes,
                need,
                expected: match environment.download {
                    Some(download) => medium::Expected {
                        sha256: None,
                        sha1: download.image.sha1.clone(),
                    },
                    None => medium::Expected::of(receipt.as_ref()),
                },
                created,
            })
        }
    };
    // The medium and the bundles share the data partition.
    let restore_bytes: u64 = restore.iter().map(|p| p.bytes).sum();
    let need = medium.as_ref().map_or(MARGIN, |plan| plan.need) + restore_bytes + also;
    let free = host.volume(&record.volume)?.free_bytes;
    ensure!(
        free >= need,
        "{} has {:.1} GB free; the install medium and boot bundles need {:.1} GB{}. Free space \
         on it, or use a larger USB.",
        record.volume.display(),
        free as f64 / 1e9,
        need as f64 / 1e9,
        match &medium {
            Some(plan) if !plan.remote => {
                format!(
                    " (the macOS {build} IPSW is {:.1} GB)",
                    plan.ipsw_bytes as f64 / 1e9
                )
            }
            _ => String::new(),
        }
    );
    Ok(InstallPlan {
        build: build.into(),
        restore,
        medium,
    })
}

/// The plan's lines, after their two spaces.
pub(super) fn describe_install(
    record: &Record,
    plan: &InstallPlan,
    text: &mut String,
) -> Result<()> {
    for bundle in &plan.restore {
        writeln!(
            text,
            "  {:<14} {} ({:.1} GB)",
            bundle.kind.label(),
            bundle::directory_of(
                &record.volume,
                bundle::Identity {
                    kind: bundle.kind,
                    build: &bundle.build,
                    ecid: bundle.ecid,
                    generation: record.generation()
                }
            )
            .display(),
            bundle.bytes as f64 / 1e9
        )?;
    }
    if let Some(medium) = plan.medium.as_ref().filter(|m| m.remote) {
        writeln!(
            text,
            "  install image  {}: the macOS {} restore image's inventory (online); the install \
             streams the image from Apple's servers over the PC's wired network",
            medium::directory(&medium.volume, &plan.build).display(),
            plan.build,
        )?;
    } else if let Some(medium) = &plan.medium {
        writeln!(
            text,
            "  install medium {}: the macOS {} IPSW in pieces of at most 4 GiB on the USB's FAT32 \
             partition {} (offline; {:.1} GB still to write)",
            medium::directory(&medium.volume, &plan.build).display(),
            plan.build,
            medium.guid,
            medium.need as f64 / 1e9
        )?;
        if medium.expected.sha1.is_none() {
            writeln!(
                text,
                "  note           the IPSW has no download receipt, so it is checked against its \
                 BuildManifest but not Apple's catalog digest"
            )?;
        }
    }
    Ok(())
}

/// Copy the restore bundles and write the install medium.
pub(super) fn apply_install(
    environment: &Environment<'_>,
    record: &mut Record,
    ipsw: &Path,
    plan: InstallPlan,
) -> Result<()> {
    copy_bundles(record, &plan.restore)?;
    write_record(&record.esp.clone(), record)?;
    let build = plan.build;
    let Some(plan) = plan.medium else {
        return Ok(());
    };
    // A medium of the other kind or volume this one replaces, removed once
    // this one is written.
    let previous = record.medium_of(&build).cloned();
    // Recorded before the first piece, so an interrupted copy is undone.
    record.media.retain(|m| m.build != build);
    record.media.push(medium::Medium {
        build: build.clone(),
        volume: plan.volume.clone(),
        partition_guid: plan.guid.clone(),
        manifest_sha256: String::new(),
        remote: plan.remote,
    });
    let mut created = record.created_directories.clone();
    for directory in plan.created {
        if !created.contains(&directory) {
            created.push(directory);
        }
    }
    created.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    record.created_directories = created;
    write_record(&record.esp.clone(), record)?;
    if plan.remote {
        let progress = crate::progress::Phase::spinner("Preparing the online install inventory");
        let inventory = (environment.remote_inventory)(ipsw, &record.model)?;
        progress.finish();
        ensure!(
            inventory.manifest.product_build == build,
            "Apple's servers hold macOS build {}, not {build}",
            inventory.manifest.product_build,
        );
        let sha256 = medium::write_remote(&plan.volume, inventory)?;
        if let Some(medium) = record.media.iter_mut().find(|m| m.build == build) {
            medium.manifest_sha256 = sha256;
        }
        write_record(&record.esp.clone(), record)?;
        return remove_replaced(record, &build, previous.as_ref());
    }
    if let Some(download) = environment.download {
        let written = download.write(&plan.volume, &record.model, environment.piece_bytes)?;
        if let Some(medium) = record.media.iter_mut().find(|m| m.build == build) {
            medium.manifest_sha256 = written.manifest_sha256;
        }
        write_record(&record.esp.clone(), record)?;
        return remove_replaced(record, &build, previous.as_ref());
    }
    let progress = crate::progress::Phase::spinner("Checking installation files");
    let inventory = (environment.inventory)(ipsw, &record.model)?;
    progress.finish();
    ensure!(
        inventory.manifest.product_build == build,
        "{} holds macOS build {}, not {build}",
        ipsw.display(),
        inventory.manifest.product_build,
    );
    let written = medium::write(medium::WriteOptions {
        volume: &plan.volume,
        ipsw,
        inventory,
        expected: &plan.expected,
        piece_bytes: environment.piece_bytes,
    })?;
    if let Some(medium) = record.media.iter_mut().find(|m| m.build == build) {
        medium.manifest_sha256 = written.manifest_sha256;
    }
    write_record(&record.esp.clone(), record)?;
    remove_replaced(record, &build, previous.as_ref())
}

/// Remove what the medium of `build` that the one just written replaced
/// left (`medium::remove_replaced`).
pub(super) fn remove_replaced(
    record: &Record,
    build: &str,
    previous: Option<&medium::Medium>,
) -> Result<()> {
    match (previous, record.medium_of(build)) {
        (Some(previous), Some(current)) => medium::remove_replaced(previous, current),
        _ => Ok(()),
    }
}

/// Why a setup, which installs macOS, needs the explicit signing-service
/// choice.
pub(super) const TSS_REQUIRED: &str = "Stela setup installs macOS onto the Mac's internal SSD, which \
    needs --tss: required boot firmware needs personalized tickets from Apple's signing \
    server (gs.apple.com), which receives this machine's ECID, the restore's nonces and its \
    boot components' hashes. Add --tss to opt in.";

/// The checks' result: everything setup will write, and where.
pub(super) struct Plan {
    pub(super) record: Record,
    pub(super) ipsw: PathBuf,
    pub(super) product_version: String,
    /// The prepared restore bundles, in a host directory until setup
    /// copies them.
    pub(super) prepared: Vec<Prepared>,
    pub(super) efi_image: Vec<u8>,
    /// The install's disk, and the NOR image setup writes to it.
    pub(super) installed: installed::Checked,
    /// The install medium.
    pub(super) install: InstallPlan,
    pub(super) notes: Vec<String>,
    /// The key file's passphrase, for `--wifi`.
    pub(super) wifi_passphrase: Option<String>,
}

pub(super) fn plan(
    environment: &Environment<'_>,
    command: &Request,
    ipsw: PathBuf,
    early: Option<PreparedSetup>,
) -> Result<Plan> {
    let host = environment.host;
    let esp = locate_esp(host, &command.usb)?;
    if esp.join(RECORD).exists() {
        let interrupted = stela_runtime::read_json::<Record>(&esp.join(RECORD))
            .is_ok_and(|record| !record.complete);
        bail!(
            "{} was already set up{} ({}); run `stela setup uninstall --usb {}` first, or \
             update it with `stela setup update stela` or `update os`",
            esp.display(),
            if interrupted {
                ", and that setup was interrupted"
            } else {
                ""
            },
            esp.join(RECORD).display(),
            command.usb.display()
        );
    }
    let usb_disk = host.volume(&esp)?.disk;
    // Without --target, a raw partition of the USB is the Mac's internal
    // SSD, and the PC's disks its external drives.
    let stick = match &command.target {
        Some(_) => None,
        None => stick_ssd(host, usb_disk.as_deref())?,
    };
    let target = command.target.clone().or(stick.clone());
    ensure!(command.tss, TSS_REQUIRED);
    // With no disk named here, Install macOS chooses the PC's disk in
    // stela.efi.
    let installed = match &target {
        None => installed::Checked {
            disk: installed::InstalledDisk::chosen(),
            nor_image: None,
            sep_provisioned: false,
            foreign: None,
            notes: Vec::new(),
        },
        Some(target) => installed::check(
            host,
            &installed::Request {
                apple_region: target,
                nor: command.nor.as_deref(),
                serial: command.disk_serial.as_deref(),
                erase_target: command.erase_target,
                initialize_nor: command.initialize_nor,
                usb_disk: usb_disk.as_deref(),
                external_disks: stick.is_some(),
            },
        )?,
    };
    let mut notes = Vec::new();
    let ecid = machines::machine_ecid(
        machines::EcidOptions {
            given: command.ecid,
            recorded: None,
            sep_provisioned: installed.sep_provisioned,
            new_ecid: command.new_ecid,
        },
        &mut notes,
    )?;
    let efi_path = match &command.efi {
        Some(path) => path.clone(),
        None => assets::resolve()?,
    };
    let efi_image = read_efi(environment, &efi_path)?;
    update::check_firmware_support(&esp, &efi_image)?;
    // The restore bundles are prepared on this computer before the USB
    // changes, which also measures them for the space check.
    let (product_version, build, prepared) = match early {
        Some(prepared) => prepared,
        None => prepare_restore_bundles(environment, &ipsw, command.model(), ecid)?,
    };
    let bundles: u64 = prepared.iter().map(|bundle| bundle.bytes).sum();
    // The bundles, the install medium and the translation store go on the
    // USB's FAT32 data partition, which the firmware reads.
    let (volume, _) = medium::locate(host, &esp, command.install_volume.as_deref())?;
    let install = machines::Install {
        name: command
            .install
            .clone()
            .unwrap_or_else(|| machines::FIRST_NAME.into()),
        ecid: Some(ecid),
        disk: installed.disk.clone(),
    };
    machines::check_name(&install.name)?;
    let mut record = Record {
        schema_version: RECORD_SCHEMA,
        kind: RECORD_KIND.into(),
        build: build.clone(),
        model: command.model().into(),
        esp: esp.clone(),
        bundle_directory: bundle::build_directory(&volume, &build),
        created_directories: missing_directories(
            &volume,
            &bundle::build_directory(&volume, &build),
        ),
        volume,
        payload_directory: None,
        options: String::new(),
        complete: false,
        installed: None,
        stela_version: Some(update::version_id(&efi_image)),
        stela_versions: vec![update::version_id(&efi_image)],
        builds: vec![build],
        pending: None,
        history: Vec::new(),
        installs: vec![install],
        default_install: None,
        bundle_schema: environment.interface.bundle_schema,
        bundle_revision: environment.bundle_revision,
        bundles: Vec::new(),
        tss: command.tss,
        chooser_timeout: command.chooser_timeout,
        medium: None,
        media: Vec::new(),
        verify_on_read: command.verify_on_read,
        profile: command.profile,
        install_image: command.install_image,
        translations: None,
        wifi: command.wifi.clone().map(|ssid| wifi::Network {
            ssid,
            country: command.wifi_country.clone(),
        }),
    };
    // The restore bundles are prepared above: the install plan adds the
    // install medium.
    let install = plan_install(
        environment,
        &record,
        InstallOptions {
            build: &record.build,
            ipsw: &ipsw,
            bundles: &[],
            additional_bytes: bundles,
        },
    )?;
    // The translation store takes what the data partition has left after
    // everything above.
    let medium_bytes = install.medium.as_ref().map_or(0, |m| m.need);
    let (store, note) = translations::choose(
        host,
        &[record.volume.as_path()],
        |_| medium_bytes + bundles,
        command.translation_store_bytes,
    )?;
    notes.extend(note);
    record.translations = store;
    record.options = record.options_text()?;
    record.choices_text()?;
    let source = match install.medium.as_ref().is_some_and(|medium| medium.remote) {
        true => {
            "streaming the restore image from Apple's servers (about 27 GB) over the PC's \
                 wired network"
        }
        false => "from the install medium on this USB (TSS still needs network)",
    };
    notes.push(match installed.disk.is_chosen() {
        true => format!(
            "The Install macOS startup choice asks for a disk of the PC and the space macOS gets \
             there, then Apple's restore installs macOS onto it as the Mac's internal SSD \
             (ANS2), {source}. An install may not finish yet."
        ),
        false => format!(
            "The Install macOS startup choice restores macOS onto {} as the Mac's internal SSD \
             (ANS2), {source}. An install may not finish yet.",
            installed.disk.apple_region
        ),
    });
    notes.push(tss_note());
    notes.push("Erase installs retain the original development-board FDR failure policy: FDR connectivity is disabled and factory data remains unprovisioned.".into());
    notes.extend(installed.notes.iter().cloned());
    Ok(Plan {
        record,
        ipsw,
        product_version,
        prepared,
        efi_image,
        installed,
        install,
        notes,
        wifi_passphrase: command.wifi_passphrase.clone(),
    })
}

/// What the Apple signing server opt-in sends.
pub(super) fn tss_note() -> String {
    "TSS opt-in (--tss): the restore host sends this machine's ECID, the restore's nonces \
     and its boot components' hashes to Apple's signing server (gs.apple.com) for the \
     restore's root tickets and the recoveryOS LocalPolicy; `stela setup configure --no-tss` turns it \
     off."
        .into()
}

pub(super) fn describe(plan: &Plan) -> Result<String> {
    let record = &plan.record;
    let mut text = String::new();
    writeln!(
        text,
        "Stela setup for macOS {} ({}) on {}:",
        plan.product_version, record.build, record.model
    )?;
    writeln!(text, "  restore image  {}", plan.ipsw.display())?;
    writeln!(text, "  EFI partition  {}", record.esp.display())?;
    let install = &record.installs[0];
    writeln!(
        text,
        "  ECID           {}",
        install.ecid.expect("a new setup's install has an ECID")
    )?;
    for prepared in &plan.prepared {
        writeln!(
            text,
            "  {:<14} {} ({:.1} GB)",
            prepared.kind.label(),
            bundle::directory_of(
                &record.volume,
                bundle::Identity {
                    kind: prepared.kind,
                    build: &prepared.build,
                    ecid: prepared.ecid,
                    generation: record.generation()
                }
            )
            .display(),
            prepared.bytes as f64 / 1e9
        )?;
    }
    if let Some(store) = &record.translations {
        writeln!(text, "  translations   {}", store.describe())?;
    }
    writeln!(
        text,
        "  boot loader    {}: stela.efi",
        record.esp.join(LOADER_PATH).display()
    )?;
    let checked = &plan.installed;
    let disk = &checked.disk;
    writeln!(
        text,
        "  stela.cfg      {}: boots macOS from {}, or the disk's own recoveryOS when NVRAM \
         asks or the disk holds no system",
        record.esp.join("EFI/stela/stela.cfg").display(),
        disk.apple_region
    )?;
    writeln!(
        text,
        "  choices.cfg    {}: \"{}\" and \"{INSTALL_CHOICE}\", listed for {CHOOSER_SECONDS} \
         seconds at startup",
        record.esp.join(CHOICES_PATH).display(),
        install.name
    )?;
    describe_install(record, &plan.install, &mut text)?;
    if let Some(network) = &record.wifi {
        writeln!(text, "  {}", wifi::describe(network, &record.esp))?;
    }
    match disk.is_chosen() {
        true => writeln!(
            text,
            "  Apple region   a partition stela.efi's {INSTALL_CHOICE} makes on the PC disk you \
             choose"
        )?,
        false => writeln!(
            text,
            "  Apple region   {} (serial {}, partition {})",
            disk.apple_region, disk.apple_region_serial, disk.apple_region_guid
        )?,
    }
    writeln!(text, "  {}", state_line(disk))?;
    match checked.nor_image {
        Some(_) => writeln!(
            text,
            "  disks          this USB, and fresh machine state (NOR image or SEP area) on {}",
            disk.state_description()
        )?,
        None => writeln!(text, "  disks          none are written but this USB")?,
    }
    for note in &plan.notes {
        writeln!(text, "  note           {note}")?;
    }
    Ok(text)
}

/// The plan's line for an install's machine state, after its two spaces.
pub(super) fn state_line(disk: &installed::InstalledDisk) -> String {
    let label = if disk.machine_state_offset.is_some() || disk.is_chosen() {
        "machine state"
    } else {
        "NOR"
    };
    format!("{label:<14} {}", disk.state_description())
}

pub(super) fn setup(environment: &Environment<'_>, mut command: Request) -> Result<String> {
    let host = environment.host;
    ensure!(command.tss, TSS_REQUIRED);
    // Before anything is erased.
    command.read_wifi_passphrase()?;
    if command.fetch {
        builds::find_in(environment.builds, &command.build)?;
    }
    let mut erase = None;
    if let Some(disk) = host.whole_disk(&command.usb)? {
        let found = host.disks()?.into_iter().find(|d| d.identifier == disk);
        let found = found.with_context(|| format!("this computer lists no disk {disk}"))?;
        ensure!(
            found.erasable(),
            "{disk} ({}) is an internal disk; setup erases only a removable USB",
            found.name
        );
        ensure!(
            found.removal == host::Removal::Usb
                || command
                    .confirm_disk
                    .as_deref()
                    .is_some_and(|typed| found.confirmed_by(typed)),
            "{disk} ({}, {}) is not a USB disk; pass --confirm-disk with its model or size to \
             erase it",
            found.name,
            host::size_text(found.bytes)
        );
        if command.dry_run {
            return Ok(format!(
                "Setup would erase {disk} ({}) into an EFI partition and a FAT32 volume named \
                 {USB_VOLUME}, then set it up.\nDry run: nothing was changed.\n",
                found.name
            ));
        }
        host.check_erase_access(&disk)?;
        let identity = wizard::Usb::from_disk(&found, host);
        erase = Some((disk, found.name, found.bytes, identity));
    }
    // Downloaded boot archives are temporary. A full image goes directly to
    // USB after preparation and signing; an explicit cache directory keeps the
    // scripted cache behavior for developer workflows.
    let temporary = (command.fetch && command.download_dir.is_none() && !command.dry_run)
        .then(tempfile::tempdir)
        .transpose()?;
    let mut download = None;
    let ipsw = if let Some(temporary) = &temporary
        && command.install_image == Some(InstallImage::Offline)
    {
        let image = restore::select(
            &restore::catalog()?,
            Some(&command.build),
            Some(command.model()),
        )?;
        let boot = temporary.path().join("boot.ipsw");
        download = Some(medium::download::Download::prepare(
            image,
            command.model(),
            &boot,
        )?);
        boot
    } else {
        if let Some(temporary) = &temporary {
            command.download_dir = Some(temporary.path().to_owned());
        }
        command.image()?
    };
    if ipsw.is_file() {
        let (_, build) = restore::payload::identity(&ipsw, command.model())?;
        supported(environment, &ipsw, &build)?;
    }
    let environment = &Environment {
        download: download.as_ref(),
        ..*environment
    };
    if !command.dry_run {
        if command.efi.is_none() {
            command.efi = Some(assets::resolve()?);
        }
        read_efi(environment, command.efi.as_ref().unwrap())?;
    }
    let mut early = None;
    if let Some((disk, _, capacity, _)) = &erase {
        for path in std::iter::once(&ipsw).chain(command.efi.iter()) {
            ensure!(
                host.volume(path)?.disk.as_deref() != Some(disk),
                "{} is on the USB being erased; move installer inputs to another disk first",
                path.display()
            );
        }
        if let Some(path) = &command.efi {
            read_efi(environment, path)?;
        }
        let remote = download.is_none() && image_is_remote(&ipsw, command.install_image)?;
        // The portable installer knows its identity before the target PC is
        // connected. Prepare and sign once, and measure it before erasing USB.
        if command.target.is_none() {
            let ecid = command.ecid.map_or_else(Ecid::generate, Ok)?;
            command.ecid = Some(ecid);
            let (version, build, prepared) =
                prepare_restore_bundles(environment, &ipsw, command.model(), ecid)?;
            let image_bytes = if remote {
                0
            } else {
                match &download {
                    Some(download) => download.bytes,
                    None => fs::metadata(&ipsw)?.len(),
                }
            };
            let required = prepared.iter().map(|p| p.bytes).sum::<u64>()
                + image_bytes
                + format::ESP_BYTES
                + 4 * MARGIN;
            ensure!(
                *capacity == 0 || *capacity >= required,
                "the USB needs at least {:.1} GB for this installer (it has {:.1} GB); use a larger USB or online mode",
                required as f64 / 1e9,
                *capacity as f64 / 1e9
            );
            early = Some((version, build, prepared));
        }
    }
    if let Some((disk, name, _, identity)) = erase {
        identity.verify(host)?;
        eprintln!("Erasing {disk} ({name})");
        host.erase(&disk, USB_VOLUME)?;
        let volume = host
            .disks()?
            .into_iter()
            .find(|d| d.identifier == disk)
            .and_then(|d| d.partitions.into_iter().find_map(|p| p.mount))
            .with_context(|| format!("{disk} has no mounted volume after it was erased"))?;
        command.usb = volume;
    }
    let plan = plan(environment, &command, ipsw, early)?;
    let mut report = describe(&plan)?;
    if command.dry_run {
        report.push_str("Dry run: nothing was changed.\n");
        return Ok(report);
    }
    let disk = plan.installed.disk.clone();
    apply(environment, plan)?;
    let start = match disk {
        disk if disk.is_chosen() => format!(
            "choose \"{INSTALL_CHOICE}\" in Stela's startup choices, pick the PC disk and the \
             space macOS gets, and the install restores macOS onto it; Stela then starts the \
             installed macOS from that disk"
        ),
        disk if disk.external_disks => format!(
            "boot the PC from the USB: its internal SSD ({}) is blank, so Stela offers \
             \"{INSTALL_CHOICE}\", which restores it. Then recoveryOS's Disk Utility \
             partitions and formats the PC's disks, which macOS sees as external drives, and \
             Reinstall macOS installs onto one, as on a Mac",
            disk.apple_region
        ),
        disk => format!(
            "choose \"{INSTALL_CHOICE}\" in Stela's startup choices to install macOS onto \
             {target}, then boot from the USB again, which boots the installed macOS (or its \
             recoveryOS when NVRAM asks)",
            target = disk.apple_region
        ),
    };
    writeln!(
        report,
        "Done. Boot the PC from this USB (the firmware's boot menu lists it as a UEFI USB \
         device): {start}. Stela does not run recoveryOS to its window yet.\nCheck it with: \
         stela setup status --usb {}\nUndo with: stela setup uninstall --usb {}",
        command.usb.display(),
        command.usb.display()
    )?;
    Ok(report)
}

/// The FAT32 volume setup erases a USB into.
pub(super) const USB_VOLUME: &str = "STELA";

/// Directories from `root` down to `path` that do not exist yet, deepest
/// first.
pub(super) fn missing_directories(root: &Path, path: &Path) -> Vec<PathBuf> {
    let mut missing: Vec<PathBuf> = path
        .ancestors()
        .take_while(|p| p.starts_with(root) && *p != root)
        .filter(|p| !p.exists())
        .map(Path::to_path_buf)
        .collect();
    missing.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    missing
}

pub(super) fn apply(environment: &Environment<'_>, plan: Plan) -> Result<()> {
    let mut record = plan.record;
    let esp = record.esp.clone();
    // Recorded before the first write, so an interrupted setup can be undone.
    write_record(&esp, &record)?;
    copy_bundles(&mut record, &plan.prepared)?;
    write_record(&esp, &record)?;
    if let Some(store) = &record.translations {
        store.publish()?;
    }
    apply_install(environment, &mut record, &plan.ipsw, plan.install)?;
    let checked = &plan.installed;
    if let Some(region) = &checked.foreign {
        installed::erase_foreign(environment.host, region)?;
    }
    if let Some(nor) = &checked.nor_image {
        installed::initialize_nor(environment.host, &checked.disk, nor)?;
    }
    // The version is kept first, so `rollback` of a later update finds it.
    let version = update::store_version(&esp, &plan.efi_image)?;
    debug_assert_eq!(Some(&version), record.stela_version.as_ref());
    let kept = update::version_path(&esp, &version);
    if let Some(passphrase) = &plan.wifi_passphrase {
        wifi::write_key(&esp, passphrase)?;
    }
    efi::add_mount(&esp, &kept, None, Some(&record.options))?;
    publish(&mut record)?;
    record.complete = true;
    write_record(&esp, &record)
}
