//! `stela setup`: prepare a user's own OpenCore USB to boot macOS 27's
//! recoveryOS, from which macOS is installed as on a Mac (Disk Utility, then
//! Reinstall macOS).
//!
//! One command checks the USB and the restore image without writing
//! anything, prepares the recoveryOS boot bundle (`stela boot prepare
//! --recovery`) on this computer, then copies it to a volume of the USB that
//! OpenCore can read, adds `stela.efi` to OpenCore's boot picker with a
//! `stela.cfg` that boots that bundle, and records what it wrote in
//! `EFI/stela/setup.json`. `--dry-run` stops after the checks; `--uninstall`
//! removes everything the record names.
//!
//! With `--target` and `--nor`, setup runs on the PC itself and also names
//! the PC's own disk (`setup::installed`): the entry then boots the
//! installed macOS from that disk, or recoveryOS when NVRAM asks for it or
//! the disk holds no system yet, as a Mac does. Setup writes no disk but
//! the USB, except a fresh NOR image with `--initialize-nor` and NVRAM with
//! `--next-boot`.
//!
//! An existing setup is updated in place (`setup::update`): `--update-stela`
//! installs a new `stela.efi`, `--update-os` a new macOS build's recoveryOS,
//! and `--rollback` undoes the last update or finishes undoing an
//! interrupted one. Every path takes `--dry-run`.
mod host;
mod installed;
mod update;
mod usb;

pub(crate) use installed::NextBoot;

use crate::{boot, efi, restore};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use host::{FileSystem, Host};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};
use stela_loader::boot_bundle::Options as BundleOptions;

/// The pinned system target.
const PINNED_BUILD: &str = "26A434";
const PINNED_MODEL: &str = "Mac14,3";
const RECORD: &str = "EFI/stela/setup.json";
/// A margin so no volume is filled to its last byte.
pub(super) const MARGIN: u64 = 64 * 1024 * 1024;

/// The bundle setup prepares: recoveryOS, the installed system's kernel with
/// BaseSystem as its ramdisk.
pub(super) const RECOVERY: &str = "recovery";

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
    /// A volume of the USB for the recoveryOS bundle, when the EFI partition
    /// is too small.
    #[arg(long)]
    volume: Option<PathBuf>,
    /// The `stela.efi` to install; found beside `stela` or in the build tree
    /// by default.
    #[arg(long)]
    efi: Option<PathBuf>,
    /// The Mac model Stela presents, such as Mac14,2 (MacBook Air M2) or
    /// Mac14,9 (MacBook Pro M2 Pro); setup refuses one whose SoC the engine
    /// does not model yet (the M2, M2 Pro and M2 Max Macs are modeled).
    #[arg(long, default_value = PINNED_MODEL)]
    model: String,
    /// The build `--fetch` downloads.
    #[arg(long, default_value = PINNED_BUILD, hide = true)]
    build: String,
    /// Show what would change, and change nothing.
    #[arg(long)]
    dry_run: bool,
    /// Remove everything a previous setup wrote to this USB.
    #[arg(long, conflicts_with_all = ["ipsw", "fetch", "volume", "target", "update_stela",
        "update_os", "rollback", "next_boot"])]
    uninstall: bool,
    /// The PC's partition that becomes the Mac's internal SSD, such as
    /// disk1s2: macOS is installed onto it from recoveryOS and booted from it.
    #[arg(long, requires = "nor")]
    target: Option<String>,
    /// The PC's partition (at least 1 MiB) that holds the Mac's NOR flash,
    /// where NVRAM persists.
    #[arg(long, requires = "target")]
    nor: Option<String>,
    /// The serial number of the disk holding `--target` and `--nor`, when
    /// this computer cannot read it.
    #[arg(long, requires = "target")]
    disk_serial: Option<String>,
    /// Use a `--target` that holds other data, which installing macOS onto
    /// it erases.
    #[arg(long, requires = "target")]
    erase_target: bool,
    /// Write a fresh NOR image over a `--nor` that is neither blank nor one.
    #[arg(long, requires = "nor")]
    initialize_nor: bool,
    /// Replace `stela.efi` (`--efi`, or the one beside `stela`) on an
    /// existing setup, keeping the old one for `--rollback`.
    #[arg(long, conflicts_with_all = ["ipsw", "fetch", "target", "update_os", "rollback",
        "next_boot"])]
    update_stela: bool,
    /// Add a new macOS build's recoveryOS (`--ipsw` or `--fetch`) to an
    /// existing setup for System Recovery and Reinstall macOS.
    #[arg(long, conflicts_with_all = ["target", "rollback", "next_boot"])]
    update_os: bool,
    /// Undo the last update, or an interrupted one.
    #[arg(long, conflicts_with_all = ["ipsw", "fetch", "target", "next_boot"])]
    rollback: bool,
    /// Choose the next boot of the installed disk in its NVRAM.
    #[arg(long, value_enum, conflicts_with_all = ["ipsw", "fetch", "target"])]
    next_boot: Option<NextBoot>,
}

/// What setup writes, recorded on the ESP so `--uninstall` can remove it.
/// Schema 1 setups also wrote a restore payload and named a target disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Record {
    schema_version: u32,
    kind: String,
    build: String,
    model: String,
    esp: PathBuf,
    #[serde(alias = "payload_volume")]
    volume: PathBuf,
    /// A schema 1 setup's restore payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload_directory: Option<PathBuf>,
    bundle_directory: PathBuf,
    /// Directories setup created on the payload volume, deepest first.
    created_directories: Vec<PathBuf>,
    options: String,
    complete: bool,
    /// Schema 3: the PC's own disk, when setup named one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    installed: Option<installed::InstalledDisk>,
    /// Schema 3: the active `stela.efi` version and those kept, oldest
    /// first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stela_version: Option<String>,
    #[serde(default)]
    stela_versions: Vec<String>,
    /// Schema 3: the recoveryOS builds kept, oldest first; `build` is the
    /// active one.
    #[serde(default)]
    recovery_builds: Vec<String>,
    /// Schema 3: an update that started and has not finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<update::Change>,
    /// Schema 3: finished updates, for `--rollback`.
    #[serde(default)]
    history: Vec<update::Change>,
}

const RECORD_KIND: &str = "stela_setup";
const RECORD_SCHEMA: u32 = 3;

/// `stela.cfg` for the record: recoveryOS alone, or the installed disk with
/// recoveryOS for System Recovery.
fn options(record: &Record) -> String {
    options_for(&record.build, record.installed.as_ref())
}

fn options_for(build: &str, installed: Option<&installed::InstalledDisk>) -> String {
    let dram_bytes = BundleOptions::default().dram_size;
    let recovery = format!("\\EFI\\stela\\boot\\{build}\\{RECOVERY}");
    match installed {
        Some(disk) => disk.options(&recovery, dram_bytes),
        None => format!("--system --bundle {recovery} --ram-bytes {dram_bytes:#x}\n"),
    }
}

/// The record on the ESP of `usb`, which must be a complete setup's.
fn read_record(environment: &Environment<'_>, usb: &Path) -> Result<Record> {
    let esp = locate_esp(environment.host, usb)?;
    let path = esp.join(RECORD);
    ensure!(
        path.is_file(),
        "{} has no setup; run `stela setup` first",
        esp.display()
    );
    let record: Record = stela_runtime::read_json(&path)?;
    ensure!(
        record.kind == RECORD_KIND && (1..=RECORD_SCHEMA).contains(&record.schema_version),
        "{} is not a setup record this version understands",
        path.display()
    );
    ensure!(
        record.payload_directory.is_none(),
        "{} is a schema 1 setup, which installs from a restore payload; run `stela setup \
         --uninstall` and set up again",
        esp.display()
    );
    Ok(record)
}

/// The checks' result: everything setup will write, and where.
#[derive(Debug)]
struct Plan {
    esp: PathBuf,
    ipsw: PathBuf,
    product_version: String,
    build: String,
    model: String,
    volume: PathBuf,
    /// The prepared bundle, in a host directory until setup copies it.
    bundle: tempfile::TempDir,
    bundle_bytes: u64,
    options: String,
    efi_image: PathBuf,
    /// The PC's own disk, and the NOR image setup writes to it.
    installed: Option<installed::Checked>,
    notes: Vec<String>,
}

impl Plan {
    /// `EFI/stela/boot/<build>` on the chosen volume.
    fn bundle_directory(&self) -> PathBuf {
        self.volume.join(format!("EFI/stela/boot/{}", self.build))
    }
}

/// Writes the recoveryOS bundle for an IPSW and model into a directory.
type Prepare = dyn Fn(&Path, &str, &Path) -> Result<()>;

/// Inputs that the command line fixes and tests replace.
struct Environment<'a> {
    host: &'a dyn Host,
    /// `stela boot prepare --recovery`; tests use synthetic IPSWs, which
    /// have no kernel, and write a stand-in.
    prepare: &'a Prepare,
}

impl Setup {
    pub(crate) fn run(self) -> Result<()> {
        let environment = Environment {
            host: &host::System,
            prepare: &prepare_recovery,
        };
        print!("{}", self.dispatch(&environment)?);
        Ok(())
    }

    fn dispatch(self, environment: &Environment<'_>) -> Result<String> {
        if self.uninstall {
            return uninstall(environment, &self.usb, self.dry_run);
        }
        if self.update_stela {
            let record = read_record(environment, &self.usb)?;
            let image = match &self.efi {
                Some(path) => path.clone(),
                None => default_efi_image()
                    .context("no stela.efi found beside stela or in the build tree; pass --efi")?,
            };
            return update::update_stela(record, &image, self.dry_run);
        }
        if self.update_os {
            let record = read_record(environment, &self.usb)?;
            let ipsw = self.image()?;
            return update::update_os(environment, record, &ipsw, self.dry_run);
        }
        if self.rollback {
            return update::rollback(read_record(environment, &self.usb)?, self.dry_run);
        }
        if let Some(next) = self.next_boot {
            let record = read_record(environment, &self.usb)?;
            let disk = record.installed.as_ref().with_context(|| {
                format!(
                    "the setup on {} names no installed disk (--target and --nor)",
                    record.esp.display()
                )
            })?;
            let changes = installed::next_boot(environment.host, disk, next, self.dry_run)?;
            let mut text = format!("NVRAM of {} (the NOR partition):\n", disk.nor);
            if changes.is_empty() {
                text.push_str("  nothing to change\n");
            }
            for change in changes {
                writeln!(text, "  {change}")?;
            }
            text.push_str(if self.dry_run {
                "Dry run: nothing was changed.\n"
            } else {
                "Done.\n"
            });
            return Ok(text);
        }
        setup(environment, self)
    }

    /// The restore image: `--ipsw`, or the pinned build `--fetch` downloads.
    fn image(&self) -> Result<PathBuf> {
        match (&self.ipsw, self.fetch) {
            (Some(path), false) => Ok(path.clone()),
            (None, true) if self.dry_run => {
                bail!(
                    "--dry-run with --fetch needs the image first; download it without \
                     --dry-run, or pass --ipsw"
                )
            }
            (None, true) => fetch(self),
            _ => bail!("pass --ipsw IPSW, or --fetch to download macOS 27 from Apple"),
        }
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

/// Whether `stela.efi` can read files on this file system through OpenCore.
fn readable(filesystem: &FileSystem, drivers: &[String]) -> Result<(), String> {
    let has = |name: &str| drivers.iter().any(|d| d.contains(name));
    match filesystem {
        FileSystem::Fat => Ok(()),
        FileSystem::Hfs if has("hfsplus") => Ok(()),
        FileSystem::Hfs => Err(
            "is HFS+, but OpenCore loads no OpenHfsPlus.efi or HfsPlus.efi \
             driver to read it"
                .into(),
        ),
        FileSystem::Ntfs if has("openntfsdxe") => Ok(()),
        FileSystem::Ntfs => Err("is NTFS, but OpenCore loads no OpenNtfsDxe.efi driver".into()),
        FileSystem::ExFat => Err("is exFAT, which OpenCore cannot read; use FAT32 or HFS+".into()),
        FileSystem::Apfs => Err("is APFS, which stela.efi cannot read; use FAT32 or HFS+".into()),
        FileSystem::Other(name) => Err(format!(
            "has file system {name}, which stela.efi cannot read"
        )),
    }
}

/// The first volume of the USB that OpenCore can read and the bundle fits
/// on.
fn choose_volume(
    host: &dyn Host,
    esp: &Path,
    usb: &Path,
    explicit: Option<&Path>,
    bundle_bytes: u64,
) -> Result<PathBuf> {
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
    let need = bundle_bytes + MARGIN;
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
        if let Err(reason) = readable(&info.filesystem, &drivers) {
            writeln!(reasons, "  {} {reason}", volume.display())?;
            continue;
        }
        if info.free_bytes < need {
            writeln!(
                reasons,
                "  {} ({}) has {:.1} GB free; the recoveryOS bundle needs {:.1} GB",
                volume.display(),
                info.filesystem,
                info.free_bytes as f64 / 1e9,
                need as f64 / 1e9
            )?;
            continue;
        }
        return Ok(volume);
    }
    bail!(
        "No volume of the USB can hold the recoveryOS bundle:\n{reasons}Add a FAT32 or HFS+ \
         data partition of at least 4 GB beside the EFI partition (HFS+ needs OpenCore's \
         OpenHfsPlus.efi driver), then pass it with --volume."
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
    if esp.join(RECORD).exists() {
        let interrupted = stela_runtime::read_json::<Record>(&esp.join(RECORD))
            .is_ok_and(|record| !record.complete);
        bail!(
            "{} was already set up{} ({}); run `stela setup --uninstall --usb {}` first, or \
             update it with --update-stela or --update-os",
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
    let dram_bytes = BundleOptions::default().dram_size;
    let installed = match (&command.target, &command.nor) {
        (Some(target), Some(nor)) => {
            let usb_disk = host.volume(&esp)?.disk;
            Some(installed::check(
                host,
                &installed::Request {
                    apple_region: target,
                    nor,
                    serial: command.disk_serial.as_deref(),
                    erase_target: command.erase_target,
                    initialize_nor: command.initialize_nor,
                    dram_bytes,
                    usb_disk: usb_disk.as_deref(),
                },
            )?)
        }
        _ => None,
    };
    let (product_version, build) = restore::payload::identity(&ipsw, &command.model)?;
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
    // The bundle is prepared on this computer before the USB changes, which
    // also measures it for the space check.
    let bundle = tempfile::tempdir()?;
    (environment.prepare)(&ipsw, &command.model, &bundle.path().join(RECOVERY))
        .context("preparing the recoveryOS boot bundle")?;
    let mut bundle_bytes = 0;
    for file in fs::read_dir(bundle.path().join(RECOVERY))? {
        bundle_bytes += file?.metadata()?.len();
    }
    let volume = choose_volume(
        host,
        &esp,
        &command.usb,
        command.volume.as_deref(),
        bundle_bytes,
    )?;
    let options = options_for(&build, installed.as_ref().map(|checked| &checked.disk));
    let mut notes = vec![
        format!(
            "recoveryOS runs in {} GiB of guest memory, so the PC needs more RAM than that \
             free when it boots the entry.",
            dram_bytes >> 30
        ),
        match &installed {
            Some(checked) => format!(
                "Paused: Disk Utility and Reinstall macOS see {} as the Mac's internal SSD \
                 (ANS2), but the installer's personalization and the Secure Enclave are not \
                 modeled, so an install does not finish yet.",
                checked.disk.apple_region
            ),
            None => "Paused: Disk Utility and Reinstall macOS reach the PC's disks and \
                     keyboard only through PCIe/DART passthrough; the installer's \
                     personalization and the Secure Enclave are not modeled."
                .into(),
        },
    ];
    if let Some(checked) = &installed {
        notes.extend(checked.notes.iter().cloned());
    }
    Ok(Plan {
        esp,
        ipsw,
        product_version,
        build,
        model: command.model.clone(),
        volume,
        bundle,
        bundle_bytes,
        options,
        efi_image,
        installed,
        notes,
    })
}

/// `stela boot prepare --recovery` for the IPSW and model into `output`,
/// then the engine's own board check of the prepared DeviceTree
/// (`machine::soc::board`), so a model the engine cannot run is refused
/// before the USB changes rather than when the PC boots it.
fn prepare_recovery(ipsw: &Path, model: &str, output: &Path) -> Result<()> {
    let line: Vec<String> = [
        "--ipsw",
        ipsw.to_str().context("IPSW path is not UTF-8")?,
        "--model",
        model,
        "--recovery",
        "--output",
        output.to_str().context("temporary path is not UTF-8")?,
    ]
    .map(str::to_owned)
    .into();
    boot::prepare(&line)?;
    let tree = fs::read(output.join("devicetree.adt"))?;
    stela_runtime::machine::soc::board(&tree)
        .map_err(|reason| anyhow::anyhow!("Stela cannot run {model} yet: {reason}"))?;
    Ok(())
}

fn describe(plan: &Plan) -> Result<String> {
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
        "  recoveryOS     {} ({:.1} GB)",
        plan.bundle_directory().join(RECOVERY).display(),
        plan.bundle_bytes as f64 / 1e9
    )?;
    writeln!(
        text,
        "  OpenCore       adds the \"{}\" tool entry; keeps the old config.plist as {}",
        efi::NAME,
        plan.esp.join("EFI/stela/config.plist.backup").display()
    )?;
    match &plan.installed {
        Some(checked) => {
            let disk = &checked.disk;
            writeln!(
                text,
                "  stela.cfg      {}: boots macOS from {}, or recoveryOS when NVRAM asks or \
                 the disk holds no system",
                plan.esp.join("EFI/stela/stela.cfg").display(),
                disk.apple_region
            )?;
            writeln!(
                text,
                "  Apple region   {} (serial {}, partition {})",
                disk.apple_region, disk.apple_region_serial, disk.apple_region_guid
            )?;
            writeln!(
                text,
                "  NOR            {} (serial {}, partition {})",
                disk.nor, disk.nor_serial, disk.nor_guid
            )?;
            match checked.nor_image {
                Some(_) => writeln!(
                    text,
                    "  disks          this USB, and a fresh NOR image on {}",
                    disk.nor
                )?,
                None => writeln!(text, "  disks          none are written but this USB")?,
            }
        }
        None => {
            writeln!(
                text,
                "  stela.cfg      {}: boots recoveryOS",
                plan.esp.join("EFI/stela/stela.cfg").display()
            )?;
            writeln!(text, "  disks          none are written but this USB")?;
        }
    }
    for note in &plan.notes {
        writeln!(text, "  note           {note}")?;
    }
    Ok(text)
}

fn setup(environment: &Environment<'_>, command: Setup) -> Result<String> {
    let ipsw = command.image()?;
    let plan = plan(environment, &command, ipsw)?;
    let mut report = describe(&plan)?;
    if command.dry_run {
        report.push_str("Dry run: nothing was changed.\n");
        return Ok(report);
    }
    apply(environment, &plan)?;
    let start = match &plan.installed {
        Some(checked) => format!(
            "stela.efi boots the macOS installed on {}, or recoveryOS while it holds none or \
             when NVRAM asks (`stela setup --next-boot recovery`); from recoveryOS, Disk \
             Utility and Reinstall macOS install onto it, as on a Mac",
            checked.disk.apple_region
        ),
        None => "stela.efi starts recoveryOS, where Disk Utility prepares a disk and \
                 Reinstall macOS installs onto it, as on a Mac"
            .into(),
    };
    writeln!(
        report,
        "Done. Boot the PC from this USB and choose \"{}\" in OpenCore's picker: {start}. \
         Stela does not run recoveryOS to its window yet.\nUndo with: stela setup \
         --uninstall --usb {}",
        efi::NAME,
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
    let mut created = missing_directories(&plan.volume, &plan.bundle_directory());
    created.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    let image = fs::read(&plan.efi_image)?;
    let mut record = Record {
        schema_version: RECORD_SCHEMA,
        kind: RECORD_KIND.into(),
        build: plan.build.clone(),
        model: plan.model.clone(),
        esp: plan.esp.clone(),
        volume: plan.volume.clone(),
        payload_directory: None,
        bundle_directory: plan.bundle_directory(),
        created_directories: created,
        options: plan.options.clone(),
        complete: false,
        installed: plan.installed.as_ref().map(|checked| checked.disk.clone()),
        stela_version: Some(update::version_id(&image)),
        stela_versions: vec![update::version_id(&image)],
        recovery_builds: vec![plan.build.clone()],
        pending: None,
        history: Vec::new(),
    };
    // Recorded before the first write, so an interrupted setup can be undone.
    write_record(&plan.esp, &record)?;
    let destination = plan.bundle_directory().join(RECOVERY);
    fs::create_dir_all(&destination)?;
    for file in fs::read_dir(plan.bundle.path().join(RECOVERY))? {
        let file = file?;
        fs::copy(file.path(), destination.join(file.file_name()))?;
    }
    if let Some(checked) = &plan.installed
        && let Some(nor) = &checked.nor_image
    {
        installed::initialize_nor(environment.host, &checked.disk, nor)?;
    }
    // The version is kept first, so `--rollback` of a later update finds it.
    let version = update::store_version(&plan.esp, &image)?;
    efi::add_mount(&plan.esp, &plan.efi_image, None, Some(&plan.options))?;
    debug_assert_eq!(Some(version), record.stela_version);
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
            record.kind == RECORD_KIND && (1..=RECORD_SCHEMA).contains(&record.schema_version),
            "{} is not a setup record this version understands",
            esp.join(RECORD).display()
        );
        let builds = record
            .recovery_builds
            .iter()
            .map(|build| (update::bundle_directory(record, build), build));
        let directories: Vec<(PathBuf, &String)> = record
            .payload_directory
            .iter()
            .chain([&record.bundle_directory])
            .map(|d| (d.clone(), &record.build))
            .chain(builds)
            .collect();
        for (directory, build) in directories {
            ensure!(
                directory.starts_with(&record.volume) && directory.ends_with(build),
                "the setup record names an unexpected directory {}",
                directory.display()
            );
            if directory.exists() && !removals.contains(&directory) {
                removals.push(directory);
            }
        }
        let versions = esp.join(update::VERSIONS);
        if versions.is_dir() {
            removals.push(versions);
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
    let report = efi::uninstall(&esp)?;
    if let Some(backup) = report["kept_backup"].as_str() {
        writeln!(
            text,
            "  kept     {backup}: config.plist changed since install, so only the entry was \
             removed; the backup holds the configuration from before Stela"
        )?;
    }
    text.push_str("Done.\n");
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use host::{Cpu, Disk, Partition, PartitionInfo, Volume};
    use std::collections::BTreeMap;
    use stela_runtime::machine::apple::nor::nvram::Variables;

    const GIB: u64 = 1024 * 1024 * 1024;

    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/opencore-config.plist"
    );

    /// A computer whose volumes and disks the test declares.
    struct FakeHost {
        volumes: BTreeMap<PathBuf, (FileSystem, u64, Option<&'static str>)>,
        disks: Vec<Disk>,
        /// Partitions of the PC's disk, each backed by an image file.
        partitions: BTreeMap<String, (PartitionInfo, PathBuf)>,
        serials: BTreeMap<String, String>,
        memory: u64,
        cpu: Cpu,
    }

    impl FakeHost {
        fn new(
            volumes: BTreeMap<PathBuf, (FileSystem, u64, Option<&'static str>)>,
            disks: Vec<Disk>,
        ) -> Self {
            Self {
                volumes,
                disks,
                partitions: BTreeMap::new(),
                serials: BTreeMap::new(),
                memory: 32 * GIB,
                cpu: Cpu {
                    la57: true,
                    entropy: true,
                },
            }
        }

        fn image(&self, identifier: &str) -> Result<&Path> {
            self.partitions
                .get(identifier)
                .map(|(_, path)| path.as_path())
                .context("no such partition")
        }
    }

    impl Host for FakeHost {
        fn partition(&self, identifier: &str) -> Result<PartitionInfo> {
            self.partitions
                .get(identifier)
                .map(|(info, _)| info.clone())
                .context("no such partition")
        }
        fn serial(&self, disk: &str) -> Result<Option<String>> {
            Ok(self.serials.get(disk).cloned())
        }
        fn read(&self, identifier: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
            let bytes = fs::read(self.image(identifier)?)?;
            Ok(bytes[offset as usize..offset as usize + length].to_vec())
        }
        fn write(&self, identifier: &str, offset: u64, data: &[u8]) -> Result<()> {
            let path = self.image(identifier)?;
            let mut bytes = fs::read(path)?;
            ensure!(
                offset as usize + data.len() <= bytes.len(),
                "write past the partition"
            );
            bytes[offset as usize..offset as usize + data.len()].copy_from_slice(data);
            fs::write(path, bytes)?;
            Ok(())
        }
        fn memory_bytes(&self) -> Result<u64> {
            Ok(self.memory)
        }
        fn cpu(&self) -> Result<Cpu> {
            Ok(self.cpu)
        }
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

    fn disk(id: &str, contents: &[(&str, Option<&Path>)]) -> Disk {
        Disk {
            identifier: id.into(),
            name: format!("Disk {id}"),
            internal: id != "disk5",
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

    /// A USB (disk5) with an OpenCore ESP and an HFS+ data volume, and this
    /// computer's system disk (disk0).
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
        let host = FakeHost::new(
            [
                (esp.clone(), (FileSystem::Fat, esp_free, Some("disk5"))),
                (data.clone(), (FileSystem::Hfs, 100 * GIB, Some("disk5"))),
                (
                    dir.path().to_path_buf(),
                    (FileSystem::Apfs, 100 * GIB, Some("disk0")),
                ),
            ]
            .into(),
            vec![
                disk("disk0", &[("EFI", None), ("Apple_APFS", None)]),
                disk("disk5", &[("EFI", Some(&esp)), ("Apple_HFS", Some(&data))]),
            ],
        );
        Fixture {
            _dir: dir,
            esp,
            data,
            ipsw,
            efi,
            host,
        }
    }

    fn command(f: &Fixture, usb: &Path) -> Setup {
        Setup {
            usb: usb.to_path_buf(),
            ipsw: Some(f.ipsw.clone()),
            fetch: false,
            download_dir: None,
            volume: None,
            efi: Some(f.efi.clone()),
            model: restore::payload::SYNTHETIC_MODEL.into(),
            build: PINNED_BUILD.into(),
            dry_run: false,
            uninstall: false,
            target: None,
            nor: None,
            disk_serial: None,
            erase_target: false,
            initialize_nor: false,
            update_stela: false,
            update_os: false,
            rollback: false,
            next_boot: None,
        }
    }

    /// A stand-in for `boot prepare --recovery`: the synthetic IPSW has no
    /// kernel to prepare.
    fn fake_prepare(_: &Path, _: &str, output: &Path) -> Result<()> {
        fs::create_dir_all(output)?;
        fs::write(output.join("bundle.json"), b"{}")?;
        fs::write(output.join("ramdisk.img"), vec![0x5a; 4096])?;
        Ok(())
    }

    fn environment(host: &FakeHost) -> Environment<'_> {
        Environment {
            host,
            prepare: &fake_prepare,
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

    fn bundle(volume: &Path) -> PathBuf {
        volume.join(format!(
            "EFI/stela/boot/{}/{RECOVERY}",
            restore::payload::SYNTHETIC_BUILD
        ))
    }

    #[test]
    fn setup_boots_recovery_from_the_entry_and_uninstall_restores_the_usb() {
        let f = fixture(64 * GIB, false);
        let before = (snapshot(&f.esp), snapshot(&f.data));
        let host = &f.host;

        let mut dry = command(&f, &f.esp);
        dry.dry_run = true;
        let plan = setup(&environment(host), dry).unwrap();
        assert!(plan.contains("Dry run: nothing was changed."), "{plan}");
        assert!(plan.contains("boots recoveryOS"), "{plan}");
        assert!(plan.contains("Paused"), "{plan}");
        assert_eq!((snapshot(&f.esp), snapshot(&f.data)), before);

        let report = setup(&environment(host), command(&f, &f.esp)).unwrap();
        assert!(report.contains("stela setup --uninstall"), "{report}");
        assert!(report.contains("Reinstall macOS"), "{report}");
        assert_eq!(
            fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap(),
            format!(
                "--system --bundle \\EFI\\stela\\boot\\{}\\recovery --ram-bytes 0x200000000\n",
                restore::payload::SYNTHETIC_BUILD
            )
        );
        assert_eq!(
            fs::read(bundle(&f.esp).join("ramdisk.img")).unwrap(),
            vec![0x5a; 4096]
        );
        assert!(bundle(&f.esp).join("bundle.json").is_file());
        assert!(!f.esp.join("EFI/stela/source.bin").exists());
        assert_eq!(
            fs::read(f.esp.join("EFI/OC/Tools/Stela.efi")).unwrap(),
            b"MZstela"
        );
        let config = fs::read_to_string(f.esp.join("EFI/OC/config.plist")).unwrap();
        assert!(config.contains("Stela.efi"));
        let record: Record = stela_runtime::read_json(&f.esp.join(RECORD)).unwrap();
        assert!(record.complete);
        assert_eq!(record.schema_version, RECORD_SCHEMA);
        // A second setup is refused until the first is undone.
        let again = setup(&environment(host), command(&f, &f.esp));
        assert!(again.unwrap_err().to_string().contains("--uninstall"));

        let dry = uninstall(&environment(host), &f.esp, true).unwrap();
        assert!(dry.contains("Dry run"));
        assert!(bundle(&f.esp).is_dir());
        let done = uninstall(&environment(host), &f.esp, false).unwrap();
        assert!(done.contains("Done."));
        assert_eq!((snapshot(&f.esp), snapshot(&f.data)), before);
    }

    #[test]
    fn a_small_esp_sends_the_bundle_to_a_readable_data_volume_of_the_same_usb() {
        // No HFS+ driver: the data volume is unreadable and nothing fits.
        let f = fixture(GIB / 32, false);
        let error = setup(&environment(&f.host), command(&f, &f.data))
            .unwrap_err()
            .to_string();
        assert!(error.contains("OpenHfsPlus"), "{error}");
        assert!(error.contains("recoveryOS bundle needs"), "{error}");
        // With the driver, the HFS+ volume holds the bundle; the ESP keeps
        // only the entry, the tool and stela.cfg.
        let f = fixture(GIB / 32, true);
        setup(&environment(&f.host), command(&f, &f.data)).unwrap();
        assert!(bundle(&f.data).join("ramdisk.img").is_file());
        assert!(!f.esp.join("EFI/stela/boot").exists());
        assert!(f.esp.join("EFI/OC/Tools/Stela.efi").is_file());
        uninstall(&environment(&f.host), &f.data, false).unwrap();
        assert!(!f.data.join("EFI").exists());
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
            let mut host = FakeHost::new(f.host.volumes.clone(), Vec::new());
            host.volumes
                .insert(dir.path().to_path_buf(), (FileSystem::Fat, GIB, None));
            let before = snapshot(dir.path());
            let error = setup(&environment(&host), command(&f, dir.path()))
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
            assert!(error.contains("OpenCore"), "{error}");
            assert_eq!(snapshot(dir.path()), before);
        }
        // An internal OpenCore ESP is another system's boot partition.
        let mut host = FakeHost::new(f.host.volumes.clone(), f.host.disks.clone());
        host.volumes
            .insert(f.esp.clone(), (FileSystem::Fat, 64 * GIB, Some("disk0")));
        let error = setup(&environment(&host), command(&f, &f.esp))
            .unwrap_err()
            .to_string();
        assert!(error.contains("internal disk"), "{error}");
    }

    #[test]
    fn a_schema_1_setup_with_a_payload_and_target_is_still_undone() {
        let f = fixture(64 * GIB, false);
        let before = snapshot(&f.esp);
        efi::add_mount(&f.esp, &f.efi, None, Some("--install-mode verify\n")).unwrap();
        let payload = f.esp.join("EFI/stela/images/26A434");
        let bundles = f.esp.join("EFI/stela/boot/26A434");
        for directory in [&payload, &bundles] {
            fs::create_dir_all(directory).unwrap();
            fs::write(directory.join("file"), b"x").unwrap();
        }
        let record = serde_json::json!({
            "schema_version": 1,
            "kind": RECORD_KIND,
            "build": "26A434",
            "model": "Mac14,3",
            "target": "the disk with serial number EMPTY2",
            "esp": f.esp,
            "payload_volume": f.esp,
            "payload_directory": payload,
            "bundle_directory": bundles,
            "created_directories": [
                f.esp.join("EFI/stela/images"),
                f.esp.join("EFI/stela/boot"),
            ],
            "options": "--install-mode verify\n",
            "complete": true,
        });
        stela_runtime::write_json(&f.esp.join(RECORD), &record).unwrap();
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert_eq!(snapshot(&f.esp), before);
    }

    const REGION: &str = "disk1s2";
    const NOR: &str = "disk1s3";
    const REGION_GUID: &str = "5E1A0000-0000-4000-8000-000000000001";
    const NOR_GUID: &str = "5E1A0000-0000-4000-8000-000000000002";
    const SERIAL: &str = "STELAPC01";
    /// Bytes of each synthetic partition image: the probe reads and a NOR.
    const IMAGE_BYTES: usize = 2 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;

    /// Give `f`'s PC a disk1 with an Apple region and a NOR partition,
    /// backed by synthetic images that start with `region` and `nor`.
    fn add_installed_disk(f: &mut Fixture, region: &[u8], nor: &[u8]) {
        for (identifier, guid, bytes, head) in [
            (REGION, REGION_GUID, 100 * GIB, region),
            (NOR, NOR_GUID, 256 * MIB, nor),
        ] {
            let path = f._dir.path().join(format!("{identifier}.img"));
            let mut image = vec![0u8; IMAGE_BYTES];
            image[..head.len()].copy_from_slice(head);
            fs::write(&path, image).unwrap();
            let info = PartitionInfo {
                identifier: identifier.into(),
                disk: "disk1".into(),
                guid: guid.to_ascii_lowercase(),
                bytes,
                content: "Apple_APFS".into(),
                mount: None,
                container: None,
            };
            f.host.partitions.insert(identifier.into(), (info, path));
        }
        f.host.serials.insert("disk1".into(), SERIAL.into());
    }

    fn installed_command(f: &Fixture) -> Setup {
        let mut command = command(f, &f.esp);
        command.target = Some(REGION.into());
        command.nor = Some(NOR.into());
        command
    }

    fn partition_bytes(f: &Fixture, identifier: &str) -> Vec<u8> {
        fs::read(f.host.image(identifier).unwrap()).unwrap()
    }

    fn nvram(f: &Fixture) -> Variables {
        let bytes =
            partition_bytes(f, NOR)[..stela_runtime::machine::apple::nor::CAPACITY].to_vec();
        let image = stela_runtime::machine::apple::nor::Image::from_bytes(bytes).unwrap();
        Variables::parse(image.bank(image.current_bank().unwrap()).unwrap()).unwrap()
    }

    fn rerun(f: &Fixture, configure: impl Fn(&mut Setup)) -> Result<String> {
        let mut command = command(f, &f.esp);
        command.ipsw = None;
        configure(&mut command);
        command.dispatch(&environment(&f.host))
    }

    #[test]
    fn an_installed_disk_boots_macos_or_recoveryos_and_keeps_its_partitions() {
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        let before = snapshot(&f.esp);
        let disks = (partition_bytes(&f, REGION), partition_bytes(&f, NOR));

        let mut dry = installed_command(&f);
        dry.dry_run = true;
        let plan = setup(&environment(&f.host), dry).unwrap();
        assert!(
            plan.contains("Apple region   disk1s2 (serial STELAPC01"),
            "{plan}"
        );
        assert!(plan.contains("is blank: install macOS onto it"), "{plan}");
        assert!(plan.contains("Dry run"), "{plan}");
        assert_eq!(snapshot(&f.esp), before);

        setup(&environment(&f.host), installed_command(&f)).unwrap();
        let region = format!("{SERIAL}:{REGION_GUID}");
        assert_eq!(
            fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap(),
            format!(
                "--system --storage {region} --nor {SERIAL}:{NOR_GUID} --preboot {region} \
                 --recovery-bundle \\EFI\\stela\\boot\\{}\\recovery --ram-bytes 0x200000000\n",
                restore::payload::SYNTHETIC_BUILD
            )
        );
        // Setup itself writes neither partition.
        assert_eq!(
            (partition_bytes(&f, REGION), partition_bytes(&f, NOR)),
            disks
        );

        // The next boot is chosen in NVRAM, which a dry run leaves alone.
        let dry = rerun(&f, |c| {
            c.next_boot = Some(NextBoot::Recovery);
            c.dry_run = true;
        })
        .unwrap();
        assert!(
            dry.contains("one-time-boot-command=recover-system"),
            "{dry}"
        );
        assert_eq!(partition_bytes(&f, NOR), disks.1);
        rerun(&f, |c| c.next_boot = Some(NextBoot::Recovery)).unwrap();
        let variables = nvram(&f);
        assert_eq!(
            stela_loader::boot_selection::select(&variables)
                .unwrap()
                .target,
            stela_loader::boot_selection::Target::SystemRecovery
        );
        rerun(&f, |c| c.next_boot = Some(NextBoot::Macos)).unwrap();
        assert_eq!(
            stela_loader::boot_selection::select(&nvram(&f))
                .unwrap()
                .target,
            stela_loader::boot_selection::Target::MacOs { safe: false }
        );

        // Uninstall restores the USB and keeps the installed disk and NVRAM.
        let nor = partition_bytes(&f, NOR);
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert_eq!(snapshot(&f.esp), before);
        assert_eq!(partition_bytes(&f, REGION), disks.0);
        assert_eq!(partition_bytes(&f, NOR), nor);
    }

    #[test]
    fn installed_disks_that_would_lose_data_or_cannot_boot_are_refused() {
        let refusal = |f: &Fixture, configure: &dyn Fn(&mut Setup)| {
            let mut command = installed_command(f);
            configure(&mut command);
            setup(&environment(&f.host), command)
                .unwrap_err()
                .to_string()
        };
        // An Apple region with another file system needs --erase-target.
        let mut apfs = vec![0u8; 64];
        apfs[32..36].copy_from_slice(b"NXSB");
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &apfs, &[]);
        assert!(refusal(&f, &|_| {}).contains("--erase-target"));
        let mut dry = installed_command(&f);
        dry.erase_target = true;
        dry.dry_run = true;
        let plan = setup(&environment(&f.host), dry).unwrap();
        assert!(plan.contains("erases (--erase-target)"), "{plan}");
        // A NOR partition with other bytes needs --initialize-nor.
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], b"not a NOR image");
        assert!(refusal(&f, &|_| {}).contains("--initialize-nor"));
        let mut initialize = installed_command(&f);
        initialize.initialize_nor = true;
        setup(&environment(&f.host), initialize).unwrap();
        assert_eq!(
            stela_loader::boot_selection::select(&nvram(&f))
                .unwrap()
                .target,
            stela_loader::boot_selection::Target::MacOs { safe: false }
        );
        // A guest disk is kept and booted.
        let mut gpt = vec![0u8; 520];
        gpt[512..520].copy_from_slice(b"EFI PART");
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &gpt, &[]);
        let mut dry = installed_command(&f);
        dry.dry_run = true;
        assert!(
            setup(&environment(&f.host), dry)
                .unwrap()
                .contains("already holds a guest disk")
        );
        // Mounted or in-use partitions, the PC's limits and serials.
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        f.host.partitions.get_mut(REGION).unwrap().0.container = Some("disk4".into());
        assert!(refusal(&f, &|_| {}).contains("unmountDisk disk4"));
        f.host.partitions.get_mut(REGION).unwrap().0.container = None;
        f.host.partitions.get_mut(NOR).unwrap().0.mount = Some("/Volumes/x".into());
        assert!(refusal(&f, &|_| {}).contains("is mounted"));
        f.host.partitions.get_mut(NOR).unwrap().0.mount = None;
        assert!(refusal(&f, &|c| c.nor = Some(REGION.into())).contains("two partitions"));
        f.host.memory = 8 * GIB;
        assert!(refusal(&f, &|_| {}).contains("GiB of memory"));
        f.host.memory = 32 * GIB;
        f.host.cpu.la57 = false;
        assert!(refusal(&f, &|_| {}).contains("LA57"));
        f.host.cpu.la57 = true;
        assert!(refusal(&f, &|c| c.disk_serial = Some("OTHER".into())).contains("reports serial"));
        f.host.serials.clear();
        assert!(refusal(&f, &|_| {}).contains("--disk-serial"));
        let mut given = installed_command(&f);
        given.disk_serial = Some(SERIAL.into());
        given.dry_run = true;
        setup(&environment(&f.host), given).unwrap();
        // Nothing was written by any refusal.
        assert!(!f.esp.join(RECORD).exists());
    }

    #[test]
    fn stela_updates_keep_the_old_version_and_roll_back() {
        let f = fixture(64 * GIB, false);
        let before = snapshot(&f.esp);
        setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
        let tool = f.esp.join("EFI/OC/Tools/Stela.efi");
        let config = fs::read(f.esp.join("EFI/OC/config.plist")).unwrap();
        let new = f._dir.path().join("new.efi");
        fs::write(&new, b"MZstela-2").unwrap();
        let update = |dry_run: bool| {
            rerun(&f, |c| {
                c.update_stela = true;
                c.efi = Some(new.clone());
                c.dry_run = dry_run;
            })
        };
        assert!(update(true).unwrap().contains("Dry run"));
        assert_eq!(fs::read(&tool).unwrap(), b"MZstela");
        let report = update(false).unwrap();
        assert!(report.contains("no translation cache"), "{report}");
        assert_eq!(fs::read(&tool).unwrap(), b"MZstela-2");
        // Only the tool changed: the entry and stela.cfg stay.
        assert_eq!(fs::read(f.esp.join("EFI/OC/config.plist")).unwrap(), config);
        assert!(update(false).unwrap().contains("already installed"));
        let record: Record = stela_runtime::read_json(&f.esp.join(RECORD)).unwrap();
        assert_eq!(record.stela_versions.len(), 2);
        assert_eq!(record.history.len(), 1);
        rerun(&f, |c| c.rollback = true).unwrap();
        assert_eq!(fs::read(&tool).unwrap(), b"MZstela");
        assert!(
            rerun(&f, |c| c.rollback = true)
                .unwrap_err()
                .to_string()
                .contains("no update")
        );
        update(false).unwrap();
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert_eq!(snapshot(&f.esp), before);
    }

    #[test]
    fn os_updates_add_recoveryos_and_interrupted_updates_finish_or_roll_back() {
        let f = fixture(64 * GIB, false);
        let before = snapshot(&f.esp);
        setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
        let newer = f._dir.path().join("Newer.ipsw");
        restore::payload::synthetic_ipsw_of(&newer, "STELA2").unwrap();
        let update = |dry_run: bool| {
            rerun(&f, |c| {
                c.update_os = true;
                c.ipsw = Some(newer.clone());
                c.dry_run = dry_run;
            })
        };
        let options = || fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap();
        let first = options();
        assert!(update(true).unwrap().contains("Dry run"));
        assert_eq!(options(), first);
        let report = update(false).unwrap();
        assert!(report.contains("Reinstall macOS"), "{report}");
        assert!(options().contains("\\boot\\STELA2\\recovery"));
        assert!(
            f.esp
                .join("EFI/stela/boot/STELA2/recovery/bundle.json")
                .is_file()
        );
        // The old build stays for rollback.
        assert!(bundle(&f.esp).join("bundle.json").is_file());
        rerun(&f, |c| c.rollback = true).unwrap();
        assert_eq!(options(), first);
        assert!(!f.esp.join("EFI/stela/boot/STELA2").exists());

        // An update interrupted after it was recorded refuses other updates,
        // finishes when run again, and rolls back otherwise.
        let mut record: Record = stela_runtime::read_json(&f.esp.join(RECORD)).unwrap();
        record.pending = Some(update::Change::Os {
            from: restore::payload::SYNTHETIC_BUILD.into(),
            to: "STELA2".into(),
        });
        write_record(&f.esp, &record).unwrap();
        fs::create_dir_all(f.esp.join("EFI/stela/boot/STELA2/recovery")).unwrap();
        fs::write(f.esp.join("EFI/stela/boot/STELA2/recovery/partial"), b"x").unwrap();
        let other = rerun(&f, |c| {
            c.update_stela = true;
            c.efi = Some(f.efi.clone());
        });
        assert!(other.unwrap_err().to_string().contains("interrupted"));
        update(false).unwrap();
        assert!(options().contains("STELA2"));
        assert!(
            !f.esp
                .join("EFI/stela/boot/STELA2/recovery/partial")
                .exists()
        );
        record = stela_runtime::read_json(&f.esp.join(RECORD)).unwrap();
        record.pending = record.history.last().cloned();
        write_record(&f.esp, &record).unwrap();
        let undo = rerun(&f, |c| c.rollback = true).unwrap();
        assert!(undo.contains("interrupted macOS update"), "{undo}");
        assert_eq!(options(), first);
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert_eq!(snapshot(&f.esp), before);
    }
}
