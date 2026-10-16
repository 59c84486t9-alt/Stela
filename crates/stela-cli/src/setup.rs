//! `stela setup`: prepare a user's own OpenCore USB to install macOS 27.
//!
//! One command checks the USB, the restore image and the target disk
//! without writing anything, then writes the restore payload and boot
//! bundles to the USB, adds `stela.efi` to OpenCore's boot picker with an
//! install-mode `stela.cfg`, and records what it wrote in
//! `EFI/stela/setup.json`. `--dry-run` stops after the checks; `--uninstall`
//! removes everything the record names. Setup never writes the target disk:
//! `stela.efi` does, at boot, and only the disk `--target` names.
mod host;
mod usb;

use crate::{
    boot,
    efi::{self, PayloadLayout},
    restore,
};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use host::{FileSystem, Host};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};
use stela_runtime::payload::{MAX_SLICE_BYTES, gpt::Guid, images_directory};

/// The pinned system target.
const PINNED_BUILD: &str = "26A434";
const PINNED_MODEL: &str = "Mac14,3";
const RECORD: &str = "EFI/stela/setup.json";
const GIB: u64 = 1024 * 1024 * 1024;
/// Room for the boot bundles until they are prepared and measured, and a
/// margin so no volume is filled to its last byte.
const BUNDLE_ESTIMATE: u64 = GIB / 2;
const MARGIN: u64 = 64 * 1024 * 1024;

/// The boot bundles setup prepares, each a `boot prepare` run. The restore
/// bundle joins this list as `("restore", &["--restore"])` once `boot
/// prepare` accepts that option.
const BUNDLES: &[(&str, &[&str])] = &[("installed", &["--variant", "macOS Customer"])];

#[derive(Args)]
pub(crate) struct Setup {
    /// The USB's EFI partition, or another mounted volume of the same USB.
    #[arg(long)]
    usb: PathBuf,
    /// The macOS 27 restore image (IPSW).
    #[arg(long, conflicts_with = "fetch")]
    ipsw: Option<PathBuf>,
    /// Download the pinned restore image from Apple instead.
    #[arg(long)]
    fetch: bool,
    /// Where `--fetch` keeps the image.
    #[arg(long)]
    download_dir: Option<PathBuf>,
    /// The disk to install on: its serial number, or `guid:` and its GPT
    /// disk GUID. Run without it to list this computer's disks.
    #[arg(long)]
    target: Option<String>,
    /// A volume of the USB for the payload, when the EFI partition is small.
    #[arg(long)]
    payload_volume: Option<PathBuf>,
    /// Translation cache partition size, such as 16G.
    #[arg(long, value_parser = parse_bytes, default_value = "16G")]
    cache_size: u64,
    /// Smallest Apple region (the macOS disk) Stela accepts, such as 64G.
    #[arg(long, value_parser = parse_bytes, default_value = "64G")]
    min_macos_size: u64,
    /// Only verify the payload at boot; never write the target.
    #[arg(long)]
    verify_only: bool,
    /// The `stela.efi` to install; found beside `stela` or in the build tree
    /// by default.
    #[arg(long)]
    efi: Option<PathBuf>,
    /// The Mac model to install.
    #[arg(long, default_value = PINNED_MODEL, hide = true)]
    model: String,
    /// The build `--fetch` downloads.
    #[arg(long, default_value = PINNED_BUILD, hide = true)]
    build: String,
    /// Show what would change, and change nothing.
    #[arg(long)]
    dry_run: bool,
    /// Remove everything a previous setup wrote to this USB.
    #[arg(long, conflicts_with_all = ["ipsw", "fetch", "target", "payload_volume"])]
    uninstall: bool,
}

/// Parse a size: bytes, or a number with K, M, G or T (binary units).
fn parse_bytes(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let (digits, unit) = match text.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((at, _)) => text.split_at(at),
        None => (text, ""),
    };
    let shift = match unit
        .trim()
        .to_ascii_uppercase()
        .trim_end_matches(['B', 'I'])
    {
        "" => 0,
        "K" => 10,
        "M" => 20,
        "G" => 30,
        "T" => 40,
        _ => return Err(format!("unknown size unit {unit:?}; use K, M, G or T")),
    };
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(1 << shift))
        .ok_or_else(|| format!("invalid size {text:?}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetId {
    Serial(String),
    Guid(Guid),
}

fn parse_target(text: &str) -> Result<TargetId> {
    if let Some(guid) = text.strip_prefix("guid:") {
        return Guid::parse(guid)
            .map(TargetId::Guid)
            .with_context(|| format!("{guid} is not a GUID"));
    }
    if let Some(guid) = Guid::parse(text) {
        return Ok(TargetId::Guid(guid));
    }
    let serial = text.strip_prefix("serial:").unwrap_or(text);
    ensure!(
        !serial.is_empty() && serial.len() <= 40 && serial.bytes().all(|b| b.is_ascii_graphic()),
        "--target {text:?} is neither a disk serial number (printable, no spaces, at most 40 \
         characters) nor a GPT disk GUID"
    );
    Ok(TargetId::Serial(serial.into()))
}

impl TargetId {
    fn option(&self) -> String {
        match self {
            Self::Serial(serial) => format!("--install-target-serial {serial}"),
            Self::Guid(guid) => format!("--install-target-guid {guid}"),
        }
    }
}

impl std::fmt::Display for TargetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serial(serial) => write!(f, "the disk with serial number {serial}"),
            Self::Guid(guid) => write!(f, "the disk with GPT disk GUID {guid}"),
        }
    }
}

/// What setup writes, recorded on the ESP so `--uninstall` can remove it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Record {
    schema_version: u32,
    kind: String,
    build: String,
    model: String,
    target: String,
    esp: PathBuf,
    payload_volume: PathBuf,
    payload_directory: PathBuf,
    bundle_directory: PathBuf,
    /// Directories setup created on the payload volume, deepest first.
    created_directories: Vec<PathBuf>,
    options: String,
    complete: bool,
}

const RECORD_KIND: &str = "stela_setup";

/// The checks' result: everything setup will write, and where.
#[derive(Debug)]
struct Plan {
    esp: PathBuf,
    ipsw: PathBuf,
    product_version: String,
    build: String,
    model: String,
    target: TargetId,
    payload_volume: PathBuf,
    layout: PayloadLayout,
    payload_bytes: u64,
    options: String,
    efi_image: PathBuf,
    notes: Vec<String>,
}

impl Plan {
    fn payload_directory(&self) -> PathBuf {
        self.payload_volume.join(images_directory(&self.build))
    }

    fn bundle_directory(&self) -> PathBuf {
        self.payload_volume
            .join(format!("EFI/stela/boot/{}", self.build))
    }
}

/// Inputs that the command line fixes and tests replace.
struct Environment<'a> {
    host: &'a dyn Host,
    /// Whether to prepare boot bundles; tests use synthetic IPSWs, which
    /// have no kernel to prepare.
    bundles: bool,
}

impl Setup {
    pub(crate) fn run(self) -> Result<()> {
        let environment = Environment {
            host: &host::System,
            bundles: true,
        };
        let report = if self.uninstall {
            uninstall(&environment, &self.usb, self.dry_run)?
        } else {
            setup(&environment, self)?
        };
        print!("{report}");
        Ok(())
    }
}

/// The ESP to change: `usb` itself, or the EFI partition of its disk. It
/// must hold OpenCore and sit on a removable disk.
fn locate_esp(host: &dyn Host, usb: &Path) -> Result<PathBuf> {
    ensure!(usb.is_dir(), "{} is not a mounted volume", usb.display());
    let volume = host.volume(usb)?;
    let disks = host.disks()?;
    let disk = volume
        .disk
        .as_ref()
        .and_then(|id| disks.iter().find(|d| &d.identifier == id));
    let esp = match usb::detect(usb) {
        usb::BootManager::OpenCore => usb.to_path_buf(),
        manager => {
            let partition = disk.and_then(|d| d.partitions.iter().find(|p| p.content == "EFI"));
            match partition {
                Some(partition) => match &partition.mount {
                    Some(mount) if usb::detect(mount) == usb::BootManager::OpenCore => {
                        mount.clone()
                    }
                    Some(mount) => bail!(usb::refusal(&usb::detect(mount), mount)),
                    None => bail!(
                        "{} is on the same disk as EFI partition {}, which is not mounted. \
                         Mount it with `sudo diskutil mount {}` and run setup again.",
                        usb.display(),
                        partition.identifier,
                        partition.identifier
                    ),
                },
                None => bail!(usb::refusal(&manager, usb)),
            }
        }
    };
    if let Some(disk) = host
        .volume(&esp)?
        .disk
        .and_then(|id| disks.into_iter().find(|d| d.identifier == id))
    {
        ensure!(
            !disk.system && !disk.internal,
            "{} is on {} ({}), an internal disk{}. Setup changes only a removable USB; use \
             `stela efi install` to add Stela to another EFI partition by hand.",
            esp.display(),
            disk.identifier,
            disk.name,
            if disk.system {
                " that runs this computer"
            } else {
                ""
            }
        );
    }
    Ok(esp)
}

fn candidates(host: &dyn Host, usb_disk: Option<&str>) -> Result<String> {
    let disks = host.disks()?;
    let mut text = String::new();
    if disks.is_empty() {
        text.push_str(
            "This computer cannot list its disks for setup. Name the target by its serial \
             number (on the label, or in the firmware setup) or by `guid:` and its GPT disk \
             GUID.\n",
        );
        return Ok(text);
    }
    writeln!(text, "Disks on this computer:")?;
    for disk in &disks {
        let mut notes = Vec::new();
        if Some(disk.identifier.as_str()) == usb_disk {
            notes.push("this USB".to_owned());
        }
        if disk.system {
            notes.push("runs this computer".into());
        }
        let foreign = disk.foreign_partitions();
        if !foreign.is_empty() {
            let kinds: Vec<_> = foreign.iter().map(|p| p.content.as_str()).collect();
            notes.push(format!("has data: {}", kinds.join(", ")));
        }
        writeln!(
            text,
            "  {:<8} {:>7.1} GB  {:<12} serial {:<22} {}{}",
            disk.identifier,
            disk.bytes as f64 / 1e9,
            disk.protocol,
            disk.serial.as_deref().unwrap_or("(none)"),
            disk.name,
            if notes.is_empty() {
                String::new()
            } else {
                format!("  [{}]", notes.join("; "))
            }
        )?;
    }
    writeln!(
        text,
        "Pass --target with the serial number of an empty disk, or one with only an EFI \
         partition. stela.efi refuses any other disk when it boots. A disk in another \
         computer can be named the same way."
    )?;
    Ok(text)
}

/// Check the target against this computer's disks, where it can see them.
fn check_target(host: &dyn Host, target: &TargetId, usb_disk: Option<&str>) -> Result<String> {
    let TargetId::Serial(serial) = target else {
        return Ok(format!(
            "Setup cannot read GPT disk GUIDs here; stela.efi finds {target} at boot and \
             refuses it if it holds the USB or another system's partitions."
        ));
    };
    let disks = host.disks()?;
    let Some(disk) = disks.iter().find(|d| d.serial.as_deref() == Some(serial)) else {
        return Ok(format!(
            "{target} is not attached to this computer; stela.efi looks for it at boot."
        ));
    };
    ensure!(
        Some(disk.identifier.as_str()) != usb_disk,
        "{target} is this USB ({}); the target must be another disk",
        disk.identifier
    );
    ensure!(
        !disk.system,
        "{target} ({}, {}) runs this computer; choose an empty disk",
        disk.identifier,
        disk.name
    );
    let foreign = disk.foreign_partitions();
    ensure!(
        foreign.is_empty(),
        "{target} ({}, {}) holds {}. stela.efi installs only onto an empty disk or one with \
         just an EFI partition, and never touches another system's data; erase the disk \
         first, or choose another.",
        disk.identifier,
        disk.name,
        foreign
            .iter()
            .map(|p| format!("{} ({})", p.identifier, p.content))
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(format!(
        "{target} is {} ({}, {:.1} GB) on this computer.",
        disk.identifier,
        disk.name,
        disk.bytes as f64 / 1e9
    ))
}

/// Whether `stela.efi` can read a payload on this file system through
/// OpenCore, and in which layout.
fn layout_for(filesystem: &FileSystem, drivers: &[String]) -> Result<PayloadLayout, String> {
    let has = |name: &str| drivers.iter().any(|d| d.contains(name));
    match filesystem {
        FileSystem::Fat => Ok(PayloadLayout::Split),
        FileSystem::Hfs if has("hfsplus") => Ok(PayloadLayout::Archive),
        FileSystem::Hfs => Err(
            "is HFS+, but OpenCore loads no OpenHfsPlus.efi or HfsPlus.efi \
             driver to read it"
                .into(),
        ),
        FileSystem::Ntfs if has("openntfsdxe") => Ok(PayloadLayout::Archive),
        FileSystem::Ntfs => Err("is NTFS, but OpenCore loads no OpenNtfsDxe.efi driver".into()),
        FileSystem::ExFat => Err("is exFAT, which OpenCore cannot read; use FAT32 or HFS+".into()),
        FileSystem::Apfs => Err("is APFS, which stela.efi cannot read; use FAT32 or HFS+".into()),
        FileSystem::Other(name) => Err(format!(
            "has file system {name}, which stela.efi cannot read"
        )),
    }
}

/// The first volume of the USB the payload fits on.
fn choose_payload_volume(
    host: &dyn Host,
    esp: &Path,
    usb: &Path,
    explicit: Option<&Path>,
    size: &restore::payload::Size,
) -> Result<(PathBuf, PayloadLayout, u64)> {
    let drivers = usb::opencore_drivers(esp);
    let esp_disk = host.volume(esp)?.disk;
    let mut volumes: Vec<PathBuf> = match explicit {
        Some(path) => vec![path.to_path_buf()],
        None => {
            let mut volumes = vec![esp.to_path_buf()];
            if usb != esp {
                volumes.push(usb.to_path_buf());
            }
            if let Some(id) = &esp_disk {
                for disk in host.disks()?.iter().filter(|d| &d.identifier == id) {
                    volumes.extend(disk.partitions.iter().filter_map(|p| p.mount.clone()));
                }
            }
            volumes
        }
    };
    let mut seen = std::collections::BTreeSet::new();
    volumes.retain(|volume| seen.insert(volume.clone()));
    let mut reasons = String::new();
    for volume in volumes {
        let info = host.volume(&volume)?;
        if explicit.is_some() && esp_disk.is_some() && info.disk != esp_disk {
            bail!(
                "{} is not on the USB that holds {}",
                volume.display(),
                esp.display()
            );
        }
        let layout = match layout_for(&info.filesystem, &drivers) {
            Ok(layout) => layout,
            Err(reason) => {
                writeln!(reasons, "  {} {reason}", volume.display())?;
                continue;
            }
        };
        let need = match layout {
            PayloadLayout::Split => size.member_bytes,
            PayloadLayout::Archive => size.ipsw_bytes,
        } + BUNDLE_ESTIMATE
            + MARGIN;
        if info.free_bytes < need {
            writeln!(
                reasons,
                "  {} ({}) has {:.1} GB free; the payload needs {:.1} GB",
                volume.display(),
                info.filesystem,
                info.free_bytes as f64 / 1e9,
                need as f64 / 1e9
            )?;
            continue;
        }
        return Ok((volume, layout, need));
    }
    bail!(
        "No volume of the USB can hold the payload:\n{reasons}Use a USB of at least 64 GB \
         with a FAT32 or HFS+ data partition beside the EFI partition (HFS+ needs OpenCore's \
         OpenHfsPlus.efi driver), then pass it with --payload-volume."
    )
}

fn default_efi_image() -> Option<PathBuf> {
    let beside = std::env::current_exe().ok()?.parent()?.join("stela.efi");
    let built = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/boot/x86_64-unknown-uefi/release/stela.efi");
    [beside, built].into_iter().find(|path| path.is_file())
}

fn download_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    if cfg!(target_os = "macos") {
        home.join("Library/Caches/Stela/images")
    } else {
        std::env::var_os("XDG_CACHE_HOME")
            .map_or_else(|| home.join(".cache"), PathBuf::from)
            .join("stela/images")
    }
}

/// Download the pinned image, or reuse a complete earlier download.
fn fetch(command: &Setup) -> Result<PathBuf> {
    let directory = command.download_dir.clone().unwrap_or_else(download_dir);
    let images = restore::catalog()?;
    let image = restore::select(&images, Some(&command.build), Some(&command.model))?;
    ensure!(
        image.build.bytes().all(|c| c.is_ascii_alphanumeric())
            && image
                .version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'.'),
        "unexpected catalog identifiers"
    );
    let path = directory.join(format!(
        "UniversalMac_{}_{}_Restore.ipsw",
        image.version, image.build
    ));
    let mut receipt = path.as_os_str().to_owned();
    receipt.push(".json");
    if path.is_file() && Path::new(&receipt).is_file() {
        eprintln!("Using the earlier download {}", path.display());
    } else {
        eprintln!("Downloading {} to {}", image.url, path.display());
        restore::download(&image, &path)?;
    }
    Ok(path)
}

fn plan(environment: &Environment<'_>, command: &Setup, ipsw: PathBuf) -> Result<Plan> {
    let host = environment.host;
    let esp = locate_esp(host, &command.usb)?;
    efi::check_config(&esp)?;
    ensure!(
        !esp.join(RECORD).exists(),
        "{} was already set up ({}); run `stela setup --uninstall --usb {}` first",
        esp.display(),
        esp.join(RECORD).display(),
        command.usb.display()
    );
    let usb_disk = host.volume(&esp)?.disk;
    let Some(target) = &command.target else {
        bail!(
            "Choose the disk to install on with --target.\n{}",
            candidates(host, usb_disk.as_deref())?
        );
    };
    let target = parse_target(target)?;
    let mut notes = vec![check_target(host, &target, usb_disk.as_deref())?];
    let size = restore::payload::size(&ipsw, &command.model)?;
    if size.aea_members > 0 {
        notes.push(format!(
            "The {} encrypted members' public keys are fetched from Apple now, so the \
             installation itself needs no network.",
            size.aea_members
        ));
    }
    let (payload_volume, layout, payload_bytes) = choose_payload_volume(
        host,
        &esp,
        &command.usb,
        command.payload_volume.as_deref(),
        &size,
    )?;
    let efi_image = match &command.efi {
        Some(path) => path.clone(),
        None => default_efi_image().context(
            "no stela.efi found beside stela or in the build tree; build it with \
             `cargo xtask boot build --release`, or pass --efi",
        )?,
    };
    ensure!(
        fs::read(&efi_image)
            .with_context(|| format!("cannot read {}", efi_image.display()))?
            .starts_with(b"MZ"),
        "{} is not a UEFI application",
        efi_image.display()
    );
    let mode = if command.verify_only {
        "verify"
    } else {
        "stage"
    };
    let options = format!(
        "--install-mode {mode} --install-build {} {} --install-cache-bytes {} \
         --install-min-apple-bytes {}\n",
        size.product_build,
        target.option(),
        command.cache_size,
        command.min_macos_size
    );
    Ok(Plan {
        esp,
        ipsw,
        product_version: size.product_version,
        build: size.product_build,
        model: command.model.clone(),
        target,
        payload_volume,
        layout,
        payload_bytes,
        options,
        efi_image,
        notes,
    })
}

fn describe(plan: &Plan, verify_only: bool) -> Result<String> {
    let mut text = String::new();
    writeln!(
        text,
        "Stela setup for macOS {} ({}) on {}:",
        plan.product_version, plan.build, plan.model
    )?;
    writeln!(text, "  restore image  {}", plan.ipsw.display())?;
    writeln!(text, "  OpenCore ESP   {}", plan.esp.display())?;
    writeln!(
        text,
        "  payload        {} ({}, about {:.1} GB)",
        plan.payload_directory().display(),
        match plan.layout {
            PayloadLayout::Split => "FAT32 slices",
            PayloadLayout::Archive => "the whole IPSW",
        },
        plan.payload_bytes as f64 / 1e9
    )?;
    writeln!(
        text,
        "  boot bundles   {}",
        plan.bundle_directory().display()
    )?;
    writeln!(
        text,
        "  OpenCore       adds the \"{}\" tool entry; keeps the old config.plist as {}",
        efi::NAME,
        plan.esp.join("EFI/stela/config.plist.backup").display()
    )?;
    writeln!(
        text,
        "  stela.cfg      {}",
        plan.esp.join("EFI/stela/stela.cfg").display()
    )?;
    writeln!(
        text,
        "  target         {}{}",
        plan.target,
        if verify_only {
            " (verify only: nothing is written to it)"
        } else {
            ""
        }
    )?;
    for note in &plan.notes {
        writeln!(text, "  note           {note}")?;
    }
    Ok(text)
}

fn setup(environment: &Environment<'_>, command: Setup) -> Result<String> {
    let ipsw = match (&command.ipsw, command.fetch) {
        (Some(path), false) => path.clone(),
        (None, true) if command.dry_run => {
            bail!(
                "--dry-run with --fetch needs the image first; download it without --dry-run, \
                   or pass --ipsw"
            )
        }
        (None, true) => fetch(&command)?,
        _ => bail!("pass --ipsw IPSW, or --fetch to download macOS 27 from Apple"),
    };
    let plan = plan(environment, &command, ipsw)?;
    let mut report = describe(&plan, command.verify_only)?;
    if command.dry_run {
        report.push_str("Dry run: nothing was changed.\n");
        return Ok(report);
    }
    apply(environment, &plan)?;
    writeln!(
        report,
        "Done. Boot the PC from this USB, choose \"{}\" in OpenCore's picker, and stela.efi \
         {}. macOS 27 does not boot under Stela yet; this stages the installation.\nUndo with: \
         stela setup --uninstall --usb {}",
        efi::NAME,
        if command.verify_only {
            "verifies the payload and stops"
        } else {
            "verifies the payload and copies it to the target disk"
        },
        command.usb.display()
    )?;
    Ok(report)
}

/// Directories from `root` down to `path` that do not exist yet, deepest
/// first.
fn missing_directories(root: &Path, path: &Path) -> Vec<PathBuf> {
    let mut missing: Vec<PathBuf> = path
        .ancestors()
        .take_while(|p| p.starts_with(root) && *p != root)
        .filter(|p| !p.exists())
        .map(Path::to_path_buf)
        .collect();
    missing.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    missing
}

fn write_record(esp: &Path, record: &Record) -> Result<()> {
    let path = esp.join(RECORD);
    fs::create_dir_all(path.parent().unwrap())?;
    stela_runtime::write_json(&path, record)
}

fn apply(environment: &Environment<'_>, plan: &Plan) -> Result<()> {
    // The bundles go to a host directory first, so a failure leaves the USB
    // unchanged.
    let staged = tempfile::tempdir()?;
    if environment.bundles {
        for (name, arguments) in BUNDLES {
            let output = staged.path().join(name);
            let mut line: Vec<String> = [
                "--ipsw",
                plan.ipsw.to_str().context("IPSW path is not UTF-8")?,
                "--model",
                &plan.model,
                "--output",
                output.to_str().context("temporary path is not UTF-8")?,
            ]
            .map(str::to_owned)
            .into();
            line.extend(arguments.iter().map(|a| (*a).to_owned()));
            boot::prepare(&line).with_context(|| format!("preparing the {name} boot bundle"))?;
        }
    }
    let mut created = missing_directories(&plan.payload_volume, &plan.payload_directory());
    created.extend(missing_directories(
        &plan.payload_volume,
        &plan.bundle_directory(),
    ));
    created.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    created.dedup();
    let mut record = Record {
        schema_version: 1,
        kind: RECORD_KIND.into(),
        build: plan.build.clone(),
        model: plan.model.clone(),
        target: plan.target.to_string(),
        esp: plan.esp.clone(),
        payload_volume: plan.payload_volume.clone(),
        payload_directory: plan.payload_directory(),
        bundle_directory: plan.bundle_directory(),
        created_directories: created,
        options: plan.options.clone(),
        complete: false,
    };
    // Recorded before the first write, so an interrupted setup can be undone.
    write_record(&plan.esp, &record)?;
    restore::payload::write(&restore::payload::WriteOptions {
        image: &plan.ipsw,
        model: &plan.model,
        root: &plan.payload_volume,
        layout: plan.layout,
        slice_bytes: MAX_SLICE_BYTES,
        fetch_keys: true,
    })?;
    for entry in fs::read_dir(staged.path())? {
        let entry = entry?;
        let destination = plan.bundle_directory().join(entry.file_name());
        fs::create_dir_all(&destination)?;
        for file in fs::read_dir(entry.path())? {
            let file = file?;
            fs::copy(file.path(), destination.join(file.file_name()))?;
        }
    }
    efi::add_mount(&plan.esp, &plan.efi_image, None, Some(&plan.options))?;
    record.complete = true;
    write_record(&plan.esp, &record)
}

fn uninstall(environment: &Environment<'_>, usb: &Path, dry_run: bool) -> Result<String> {
    let esp = locate_esp(environment.host, usb)?;
    efi::check_config(&esp)?;
    let record: Option<Record> = esp
        .join(RECORD)
        .is_file()
        .then(|| stela_runtime::read_json(&esp.join(RECORD)))
        .transpose()?;
    let mut text = String::new();
    let mut removals: Vec<PathBuf> = Vec::new();
    if let Some(record) = &record {
        ensure!(
            record.kind == RECORD_KIND && record.schema_version == 1,
            "{} is not a setup record this version understands",
            esp.join(RECORD).display()
        );
        for directory in [&record.payload_directory, &record.bundle_directory] {
            ensure!(
                directory.starts_with(&record.payload_volume) && directory.ends_with(&record.build),
                "the setup record names an unexpected directory {}",
                directory.display()
            );
            if directory.exists() {
                removals.push(directory.clone());
            }
        }
    } else {
        writeln!(
            text,
            "No setup record on {}; removing only the OpenCore entry and Stela's files.",
            esp.display()
        )?;
    }
    writeln!(text, "Stela uninstall from {}:", esp.display())?;
    for directory in &removals {
        writeln!(text, "  remove   {}", directory.display())?;
    }
    for file in efi::INSTALLED {
        if esp.join(file).is_file() {
            writeln!(text, "  remove   {}", esp.join(file).display())?;
        }
    }
    writeln!(
        text,
        "  OpenCore remove the \"{}\" entry from {}",
        efi::NAME,
        esp.join("EFI/OC/config.plist").display()
    )?;
    writeln!(
        text,
        "  note     the target disk is not changed; delete its Stela partitions with a disk \
         utility if setup already staged to it"
    )?;
    if dry_run {
        text.push_str("Dry run: nothing was changed.\n");
        return Ok(text);
    }
    for directory in &removals {
        fs::remove_dir_all(directory)
            .with_context(|| format!("cannot remove {}", directory.display()))?;
    }
    if let Some(record) = &record {
        for directory in &record.created_directories {
            if fs::read_dir(directory).is_ok_and(|mut entries| entries.next().is_none()) {
                fs::remove_dir(directory)?;
            }
        }
        fs::remove_file(esp.join(RECORD))?;
    }
    efi::uninstall(&esp)?;
    text.push_str("Done.\n");
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use host::{Disk, Partition, Volume};
    use std::collections::BTreeMap;
    use stela_runtime::payload::gpt::{DEFAULT_CACHE_BYTES, DEFAULT_MIN_APPLE_BYTES};

    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/opencore-config.plist"
    );

    /// A computer whose volumes and disks the test declares.
    struct FakeHost {
        volumes: BTreeMap<PathBuf, (FileSystem, u64, Option<&'static str>)>,
        disks: Vec<Disk>,
    }

    impl Host for FakeHost {
        fn volume(&self, path: &Path) -> Result<Volume> {
            let (filesystem, free_bytes, disk) = self
                .volumes
                .iter()
                .filter(|(root, _)| path.starts_with(root))
                .max_by_key(|(root, _)| root.components().count())
                .map(|(_, v)| v.clone())
                .context("no such volume")?;
            Ok(Volume {
                filesystem,
                free_bytes,
                disk: disk.map(str::to_owned),
            })
        }
        fn disks(&self) -> Result<Vec<Disk>> {
            Ok(self.disks.clone())
        }
    }

    fn disk(id: &str, serial: &str, contents: &[(&str, Option<&Path>)]) -> Disk {
        Disk {
            identifier: id.into(),
            name: format!("Disk {id}"),
            bytes: 500 * GIB,
            serial: Some(serial.into()),
            internal: id != "disk5",
            protocol: "PCI-Express".into(),
            system: id == "disk0",
            partitions: contents
                .iter()
                .enumerate()
                .map(|(i, (content, mount))| Partition {
                    identifier: format!("{id}s{}", i + 1),
                    content: (*content).into(),
                    mount: mount.map(Path::to_path_buf),
                })
                .collect(),
        }
    }

    /// A USB (disk5) with an OpenCore ESP and an HFS+ data volume, this
    /// computer's system disk (disk0), an empty target (disk2) and a disk
    /// with another system (disk3).
    struct Fixture {
        _dir: tempfile::TempDir,
        esp: PathBuf,
        data: PathBuf,
        ipsw: PathBuf,
        efi: PathBuf,
        host: FakeHost,
    }

    fn fixture(esp_free: u64, hfs_driver: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let esp = dir.path().join("ESP");
        let data = dir.path().join("Data");
        fs::create_dir_all(esp.join("EFI/OC/Tools")).unwrap();
        fs::create_dir_all(&data).unwrap();
        let mut config = fs::read_to_string(FIXTURE).unwrap();
        if hfs_driver {
            config = config.replace("OpenRuntime.efi", "OpenHfsPlus.efi");
        }
        fs::write(esp.join("EFI/OC/config.plist"), config).unwrap();
        fs::write(esp.join("EFI/OC/OpenCore.efi"), b"MZoc").unwrap();
        let ipsw = dir.path().join("Synthetic.ipsw");
        efi::synthetic_ipsw(&ipsw).unwrap();
        let efi = dir.path().join("stela.efi");
        fs::write(&efi, b"MZstela").unwrap();
        let host = FakeHost {
            volumes: [
                (esp.clone(), (FileSystem::Fat, esp_free, Some("disk5"))),
                (data.clone(), (FileSystem::Hfs, 100 * GIB, Some("disk5"))),
                (
                    dir.path().to_path_buf(),
                    (FileSystem::Apfs, 100 * GIB, Some("disk0")),
                ),
            ]
            .into(),
            disks: vec![
                disk("disk0", "SYSTEM0", &[("EFI", None), ("Apple_APFS", None)]),
                disk("disk2", "EMPTY2", &[]),
                disk(
                    "disk3",
                    "WINDOWS3",
                    &[("EFI", None), ("Microsoft Basic Data", None)],
                ),
                disk(
                    "disk5",
                    "USB5",
                    &[("EFI", Some(&esp)), ("Apple_HFS", Some(&data))],
                ),
            ],
        };
        Fixture {
            _dir: dir,
            esp,
            data,
            ipsw,
            efi,
            host,
        }
    }

    fn command(f: &Fixture, usb: &Path, target: Option<&str>) -> Setup {
        Setup {
            usb: usb.to_path_buf(),
            ipsw: Some(f.ipsw.clone()),
            fetch: false,
            download_dir: None,
            target: target.map(str::to_owned),
            payload_volume: None,
            cache_size: DEFAULT_CACHE_BYTES,
            min_macos_size: DEFAULT_MIN_APPLE_BYTES,
            verify_only: false,
            efi: Some(f.efi.clone()),
            model: restore::payload::SYNTHETIC_MODEL.into(),
            build: PINNED_BUILD.into(),
            dry_run: false,
            uninstall: false,
        }
    }

    fn environment(host: &FakeHost) -> Environment<'_> {
        Environment {
            host,
            bundles: false,
        }
    }

    /// Every file under `root`, with its bytes.
    fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut files = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            for entry in fs::read_dir(&path).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    stack.push(entry.path());
                } else {
                    files.insert(entry.path(), fs::read(entry.path()).unwrap());
                }
            }
        }
        files
    }

    #[test]
    fn setup_writes_the_payload_entry_and_options_and_uninstall_restores_the_usb() {
        let f = fixture(64 * GIB, false);
        let before = (snapshot(&f.esp), snapshot(&f.data));
        let host = &f.host;

        let mut dry = command(&f, &f.esp, Some("EMPTY2"));
        dry.dry_run = true;
        let plan = setup(&environment(host), dry).unwrap();
        assert!(plan.contains("Dry run: nothing was changed."), "{plan}");
        assert!(plan.contains("serial number EMPTY2"));
        assert_eq!((snapshot(&f.esp), snapshot(&f.data)), before);

        let report = setup(&environment(host), command(&f, &f.esp, Some("EMPTY2"))).unwrap();
        assert!(report.contains("stela setup --uninstall"), "{report}");
        let options = fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap();
        assert!(options.contains("--install-mode stage"));
        assert!(options.contains(&format!(
            "--install-build {}",
            restore::payload::SYNTHETIC_BUILD
        )));
        assert!(options.contains("--install-target-serial EMPTY2"));
        assert!(options.contains(&format!("--install-cache-bytes {DEFAULT_CACHE_BYTES}")));
        assert!(!f.esp.join("EFI/stela/source.bin").exists());
        assert_eq!(
            fs::read(f.esp.join("EFI/OC/Tools/Stela.efi")).unwrap(),
            b"MZstela"
        );
        let config = fs::read_to_string(f.esp.join("EFI/OC/config.plist")).unwrap();
        assert!(config.contains("Stela.efi"));
        // The small FAT ESP holds the split payload.
        let payload = f
            .esp
            .join(images_directory(restore::payload::SYNTHETIC_BUILD))
            .join("payload.json");
        assert!(payload.is_file());
        let record: Record = stela_runtime::read_json(&f.esp.join(RECORD)).unwrap();
        assert!(record.complete);
        // A second setup is refused until the first is undone.
        let again = setup(&environment(host), command(&f, &f.esp, Some("EMPTY2")));
        assert!(again.unwrap_err().to_string().contains("--uninstall"));

        let mut dry = uninstall(&environment(host), &f.esp, true).unwrap();
        assert!(dry.contains("Dry run"));
        assert!(payload.is_file());
        dry = uninstall(&environment(host), &f.esp, false).unwrap();
        assert!(dry.contains("Done."));
        assert_eq!((snapshot(&f.esp), snapshot(&f.data)), before);
    }

    #[test]
    fn a_small_esp_sends_the_payload_to_a_readable_data_volume_of_the_same_usb() {
        // No HFS+ driver: the data volume is unreadable and nothing fits.
        let f = fixture(GIB / 4, false);
        let error = setup(&environment(&f.host), command(&f, &f.data, Some("EMPTY2")))
            .unwrap_err()
            .to_string();
        assert!(error.contains("OpenHfsPlus"), "{error}");
        assert!(error.contains("payload needs"), "{error}");
        // With the driver, the HFS+ volume takes the whole IPSW.
        let f = fixture(GIB / 4, true);
        setup(&environment(&f.host), command(&f, &f.data, Some("EMPTY2"))).unwrap();
        let directory = f
            .data
            .join(images_directory(restore::payload::SYNTHETIC_BUILD));
        assert!(directory.join("Synthetic.ipsw").is_file());
        assert!(
            !f.esp
                .join(images_directory(restore::payload::SYNTHETIC_BUILD))
                .exists()
        );
        assert!(f.esp.join("EFI/OC/Tools/Stela.efi").is_file());
        uninstall(&environment(&f.host), &f.data, false).unwrap();
        assert!(!f.data.join("EFI").exists());
    }

    #[test]
    fn targets_are_explicit_and_never_the_usb_the_system_or_another_systems_disk() {
        let f = fixture(64 * GIB, false);
        let host = &f.host;
        let run = |target: Option<&str>| {
            setup(&environment(host), command(&f, &f.esp, target)).map_err(|e| e.to_string())
        };
        let listed = run(None).unwrap_err();
        assert!(listed.contains("--target"), "{listed}");
        assert!(
            listed.contains("EMPTY2") && listed.contains("this USB"),
            "{listed}"
        );
        assert!(listed.contains("runs this computer"), "{listed}");
        assert!(run(Some("USB5")).unwrap_err().contains("is this USB"));
        assert!(
            run(Some("SYSTEM0"))
                .unwrap_err()
                .contains("runs this computer")
        );
        assert!(
            run(Some("WINDOWS3"))
                .unwrap_err()
                .contains("Microsoft Basic Data")
        );
        assert!(run(Some("has space")).unwrap_err().contains("serial"));
        assert!(
            snapshot(&f.esp)
                .keys()
                .all(|p| !p.starts_with(f.esp.join("EFI/stela")))
        );
        // A disk elsewhere, or a GPT GUID, is checked by stela.efi at boot.
        let mut dry = command(
            &f,
            &f.esp,
            Some("guid:C12A7328-F81F-11D2-BA4B-00A0C93EC93B"),
        );
        dry.dry_run = true;
        assert!(setup(&environment(host), dry).unwrap().contains("at boot"));
        let mut dry = command(&f, &f.esp, Some("ELSEWHERE9"));
        dry.dry_run = true;
        assert!(
            setup(&environment(host), dry)
                .unwrap()
                .contains("not attached")
        );
    }

    #[test]
    fn usbs_without_opencore_are_explained_and_left_unchanged() {
        let f = fixture(64 * GIB, false);
        for (layout, expected) in [
            ("EFI/CLOVER", "Clover"),
            ("Install macOS Tahoe.app", "Apple installer"),
            ("EFI/BOOT", "does not know"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            fs::create_dir_all(dir.path().join(layout)).unwrap();
            let mut host = FakeHost {
                volumes: f.host.volumes.clone(),
                disks: Vec::new(),
            };
            host.volumes
                .insert(dir.path().to_path_buf(), (FileSystem::Fat, GIB, None));
            let before = snapshot(dir.path());
            let error = setup(&environment(&host), command(&f, dir.path(), Some("EMPTY2")))
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
            assert!(error.contains("OpenCore"), "{error}");
            assert_eq!(snapshot(dir.path()), before);
        }
        // An internal OpenCore ESP is another system's boot partition.
        let mut host = FakeHost {
            volumes: f.host.volumes.clone(),
            disks: f.host.disks.clone(),
        };
        host.volumes
            .insert(f.esp.clone(), (FileSystem::Fat, 64 * GIB, Some("disk0")));
        let error = setup(&environment(&host), command(&f, &f.esp, Some("EMPTY2")))
            .unwrap_err()
            .to_string();
        assert!(error.contains("internal disk"), "{error}");
    }

    #[test]
    fn sizes_and_targets_parse_in_the_forms_users_write() {
        // The command line's defaults are the staging planner's.
        assert_eq!(parse_bytes("16G"), Ok(DEFAULT_CACHE_BYTES));
        assert_eq!(parse_bytes("64G"), Ok(DEFAULT_MIN_APPLE_BYTES));
        assert_eq!(parse_bytes("64GiB"), Ok(64 * GIB));
        assert_eq!(parse_bytes("512M"), Ok(512 << 20));
        assert_eq!(parse_bytes("4096"), Ok(4096));
        assert!(parse_bytes("12Q").is_err());
        assert_eq!(
            parse_target("S765NJ0X316978M").unwrap(),
            TargetId::Serial("S765NJ0X316978M".into())
        );
        assert_eq!(
            parse_target("serial:ABC").unwrap(),
            TargetId::Serial("ABC".into())
        );
        assert!(matches!(
            parse_target("C12A7328-F81F-11D2-BA4B-00A0C93EC93B").unwrap(),
            TargetId::Guid(_)
        ));
        assert!(parse_target("guid:nope").is_err());
        assert!(parse_target("").is_err());
    }
}
