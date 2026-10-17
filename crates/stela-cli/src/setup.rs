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
//! removes everything the record names. Setup writes no disk but the USB.
mod host;
mod usb;

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
const MARGIN: u64 = 64 * 1024 * 1024;

/// The bundle setup prepares: recoveryOS, the installed system's kernel with
/// BaseSystem as its ramdisk.
const RECOVERY: &str = "recovery";

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
    #[arg(long, conflicts_with_all = ["ipsw", "fetch", "volume"])]
    uninstall: bool,
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
}

const RECORD_KIND: &str = "stela_setup";
const RECORD_SCHEMA: u32 = 2;

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
    ensure!(
        !esp.join(RECORD).exists(),
        "{} was already set up ({}); run `stela setup --uninstall --usb {}` first",
        esp.display(),
        esp.join(RECORD).display(),
        command.usb.display()
    );
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
    let dram_bytes = BundleOptions::default().dram_size;
    let options = format!(
        "--system --bundle \\EFI\\stela\\boot\\{}\\{RECOVERY} --ram-bytes {dram_bytes:#x}\n",
        build
    );
    let notes = vec![
        format!(
            "recoveryOS runs in {} GiB of guest memory, so the PC needs more RAM than that \
             free when it boots the entry.",
            dram_bytes >> 30
        ),
        "Paused: Disk Utility and Reinstall macOS reach the PC's disks and keyboard only \
         through PCIe/DART passthrough; the installer's personalization and the Secure Enclave \
         are not modeled."
            .into(),
    ];
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
    writeln!(
        text,
        "  stela.cfg      {}: boots recoveryOS",
        plan.esp.join("EFI/stela/stela.cfg").display()
    )?;
    writeln!(text, "  disks          none are written but this USB")?;
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
    let mut report = describe(&plan)?;
    if command.dry_run {
        report.push_str("Dry run: nothing was changed.\n");
        return Ok(report);
    }
    apply(&plan)?;
    writeln!(
        report,
        "Done. Boot the PC from this USB and choose \"{}\" in OpenCore's picker: stela.efi \
         starts recoveryOS, where Disk Utility prepares a disk and Reinstall macOS installs \
         onto it, as on a Mac. Stela does not run recoveryOS to its window yet.\nUndo with: \
         stela setup --uninstall --usb {}",
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

fn apply(plan: &Plan) -> Result<()> {
    let mut created = missing_directories(&plan.volume, &plan.bundle_directory());
    created.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
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
    };
    // Recorded before the first write, so an interrupted setup can be undone.
    write_record(&plan.esp, &record)?;
    let destination = plan.bundle_directory().join(RECOVERY);
    fs::create_dir_all(&destination)?;
    for file in fs::read_dir(plan.bundle.path().join(RECOVERY))? {
        let file = file?;
        fs::copy(file.path(), destination.join(file.file_name()))?;
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
            record.kind == RECORD_KIND && (1..=RECORD_SCHEMA).contains(&record.schema_version),
            "{} is not a setup record this version understands",
            esp.join(RECORD).display()
        );
        for directory in record
            .payload_directory
            .iter()
            .chain([&record.bundle_directory])
        {
            ensure!(
                directory.starts_with(&record.volume) && directory.ends_with(&record.build),
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
    use host::{Disk, Partition, Volume};
    use std::collections::BTreeMap;

    const GIB: u64 = 1024 * 1024 * 1024;

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
                disk("disk0", &[("EFI", None), ("Apple_APFS", None)]),
                disk("disk5", &[("EFI", Some(&esp)), ("Apple_HFS", Some(&data))]),
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
            let mut host = FakeHost {
                volumes: f.host.volumes.clone(),
                disks: Vec::new(),
            };
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
        let mut host = FakeHost {
            volumes: f.host.volumes.clone(),
            disks: f.host.disks.clone(),
        };
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
}
