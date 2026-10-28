//! `stela setup`: prepare a USB to install macOS 27 onto
//! a disk of the PC and boot it, and keep it working over the installed
//! system's life.
//!
//! Setup writes the install medium (`setup::medium`) as `--install-image`
//! says: offline, the whole IPSW on the USB's FAT32 data partition; online,
//! only its inventory, and `stela.efi` streams the IPSW from Apple's servers
//! during the install. It prepares each machine's restore bundle (`stela
//! boot prepare --restore`) and adds an Install macOS startup choice
//! (`stela.efi --install`), which restores macOS and its paired recoveryOS
//! and System Recovery onto the Mac's internal SSD, as a Mac's erase
//! restore does. An erase restore needs the macOS system image, so
//! `--fetch`'s recovery members (`restore::payload::trim`) only prepare the
//! boot bundles (`docs/research/small-installer-usb.md`). The macOS choice
//! boots the installed system afterwards. The restore personalizes its root
//! tickets and the recoveryOS LocalPolicy with Apple's signing server, so
//! setup needs `--tss`.
//!
//! One command checks the USB and the restore image without writing
//! anything, prepares the restore bundle on this computer, then copies it
//! to the USB's FAT32 data partition, which the PC's firmware can read and
//! which also holds the install medium and the translation store
//! (`stela/boot`, `stela/install` and `stela/store`), installs `stela.efi`
//! as the USB's boot loader (`efi`) with a `stela.cfg` that boots the
//! installed macOS, and records what it wrote in `EFI/stela/setup.json` on
//! the EFI partition. `--dry-run` stops after the checks; `--uninstall`
//! removes everything the record names.
//!
//! Each Stela machine has its own ECID (`setup::ecid`), drawn once, kept in
//! the record and given to every bundle prepared for it. Without `--target`,
//! Install macOS asks for a disk of the PC in `stela.efi`, or a raw
//! partition of the USB is the Mac's internal SSD. With `--target`, setup
//! runs on the PC itself and names the PC's own disk (`setup::installed`):
//! one empty partition becomes the Mac's internal SSD and keeps the machine
//! state (NVRAM, the SEP's state, the boot log) in its last bytes, outside
//! what the guest sees, or `--nor` names a partition of its own for that
//! state. The USB then boots the installed macOS from that disk, or the
//! disk's own recoveryOS when NVRAM asks for it or the disk holds no system,
//! as a Mac does. Further disks become further installs of the same setup
//! (`setup::machines`), each its own machine, chosen at boot from
//! `stela.efi`'s startup choices. Setup writes no disk but the USB, except
//! fresh machine state with `--initialize-nor` and NVRAM with
//! `--next-boot`.
//!
//! An existing setup is updated in place (`setup::update`): `--update-stela`
//! installs a new `stela.efi` and prepares the boot bundles again when it
//! reads another schema or this `stela` prepares another bundle revision
//! than theirs, `--update-os` a new macOS build's install medium and
//! restore bundles, and `--rollback` undoes the last update or finishes
//! undoing an interrupted one. Every path takes `--dry-run`. A `stela.efi`
//! whose mount interface (`stela_loader::mount_interface`) differs from this
//! `stela`'s is refused.
mod assets;
mod bundle;
mod doctor;
mod ecid;
mod elevation;
mod fdr;
mod firmware;
mod format;
pub(crate) mod host;
mod installed;
mod machines;
mod medium;
mod state;
mod translations;
mod update;
mod wizard;

pub(crate) use elevation::hold_window;
pub(crate) use installed::NextBoot;

use crate::{boot, efi, restore};
use anyhow::{Context, Result, bail, ensure};
use bundle::Kind;
use clap::{Args, builder::TypedValueParser};
use ecid::Ecid;
use host::{FileSystem, Host};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};
use stela_loader::mount_interface::{self, Choice, Choices, Interface};
use stela_runtime::builds;

/// The Mac model Stela presents by default.
pub(crate) const PINNED_MODEL: &str = "MacBookPro18,3";
const RECORD: &str = "EFI/stela/setup.json";
/// A margin so no volume is filled to its last byte.
pub(super) const MARGIN: u64 = 64 * 1024 * 1024;
/// The boot loader `stela setup` installs: `stela.efi` itself.
pub(super) const LOADER_PATH: &str = efi::LOADER;
/// The startup choices beside `stela.cfg`.
const CHOICES_PATH: &str = "EFI/stela/choices.cfg";
/// The startup choices' timeout with several installs; with one, the list
/// opens only when a key is held.
const CHOOSER_SECONDS: u32 = 5;
/// The startup choice that installs macOS onto a setup's one install.
const INSTALL_CHOICE: &str = "Install macOS";
/// The startup choice that updates a setup's one install in place.
const UPDATE_CHOICE: &str = "Update macOS";
/// The engine option that restores the medium's Update identity.
const UPDATE_RESTORE: &str = "--update-restore";
/// The commands `--install-image` goes with.
const INSTALL_IMAGE_ACTIONS: &str = "--install-image goes with a new setup, or with --target, \
    --update-os or --repair (with --ipsw or --fetch), which write the install medium";
/// Install media kept: the active build's and the one before it, for
/// rollback.
pub(super) const MEDIA_KEPT: usize = 2;

/// The startup choice that restores with a bundle of `kind` on a setup
/// with one install.
fn restore_choice_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Update => UPDATE_CHOICE,
        _ => INSTALL_CHOICE,
    }
}

/// Where an install reads the macOS restore image (`--install-image`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum InstallImage {
    /// The whole IPSW on the USB: no image download; TSS still needs network.
    Offline,
    /// The IPSW on Apple's servers, streamed during the install.
    Online,
}

fn image_is_remote(ipsw: &Path, choice: Option<InstallImage>) -> Result<bool> {
    let complete = restore::payload::holds_system_image(ipsw)?;
    match choice {
        Some(InstallImage::Online) => Ok(true),
        Some(InstallImage::Offline) => {
            ensure!(
                complete,
                "{} holds only the recovery members, without the macOS system image an \
                 install restores; pass the whole IPSW with --ipsw, use --fetch to download \
                 it, or --install-image online to stream it from Apple during the install",
                ipsw.display()
            );
            Ok(false)
        }
        None => Ok(!complete),
    }
}

#[derive(Args)]
pub(crate) struct Setup {
    /// The USB's EFI partition, another mounted volume of the same USB, or
    /// the whole USB disk (such as disk5 on macOS, /dev/sdb on Linux or
    /// PhysicalDrive2 on Windows), which setup erases first into an EFI
    /// partition and a FAT32 volume.
    #[arg(long, default_value = "", value_parser = clap::builder::OsStringValueParser::new().map(PathBuf::from))]
    usb: PathBuf,
    /// The macOS 27 restore image (IPSW).
    #[arg(long, conflicts_with = "fetch")]
    ipsw: Option<PathBuf>,
    /// Download the pinned restore image from Apple instead: its recovery
    /// members, or the whole IPSW with `--install-image offline`.
    #[arg(long)]
    fetch: bool,
    /// Where an install reads the macOS restore image: `offline` copies the
    /// whole IPSW (about 27 GB) onto the USB; TSS still needs network.
    /// `online` writes only its inventory, and `stela.efi` streams
    /// the IPSW from Apple's servers during the install over the PC's wired
    /// network. A complete local IPSW defaults to offline, including for
    /// a disk chosen later in stela.efi. An image without the macOS system
    /// image (`--fetch`) defaults to online.
    #[arg(long, value_enum)]
    install_image: Option<InstallImage>,
    /// Where `--fetch` keeps the image.
    #[arg(long)]
    download_dir: Option<PathBuf>,
    /// The `stela.efi` to install instead of the one built into `stela`.
    #[arg(long)]
    efi: Option<PathBuf>,
    /// The Mac model Stela presents (MacBookPro18,3, M1 Pro, by default).
    /// Preparation checks the selected board's platform requirements and
    /// refuses unsupported ones. Every install of a setup presents the same model.
    #[arg(long)]
    model: Option<String>,
    /// The build `--fetch` downloads: the newest supported one by default.
    #[arg(long, default_value = builds::DEFAULT.build, hide = true)]
    build: String,
    /// Show what would change, and change nothing.
    #[arg(long)]
    dry_run: bool,
    /// Remove everything a previous setup wrote to this USB.
    #[arg(long)]
    uninstall: bool,
    /// The PC's partition that becomes the Mac's internal SSD, such as
    /// disk1s2 on macOS, /dev/nvme0n1p2 on Linux or disk1p2 on Windows:
    /// Install macOS restores macOS onto it, and it is booted from it.
    /// Without --nor its last 16 MiB keep the machine state (NVRAM, the SEP's
    /// state and the boot log), which the guest never sees. On an existing
    /// setup, it adds another install.
    #[arg(long, value_parser = partition_name)]
    target: Option<String>,
    /// Optional: a separate PC partition (at least 1 MiB and 64 KiB) for the
    /// machine state instead of the target's tail: the Mac's NOR flash, where
    /// NVRAM persists, and the SEP's state; with at least 0x510000 bytes it
    /// also keeps stela.efi's boot log. Later commands name the install's
    /// machine-state partition again with it (the target itself when its
    /// tail holds the state).
    #[arg(long, value_parser = partition_name)]
    nor: Option<String>,
    /// The serial number of the disk holding `--target` and `--nor`, when
    /// this computer cannot read it.
    #[arg(long, requires = "target")]
    disk_serial: Option<String>,
    /// Erase the other file system a `--target` holds, unmounting it first,
    /// or with `--repair` the one an install's Apple region holds: the PC's
    /// own OS would mount it and clear Stela's machine state.
    #[arg(long)]
    erase_target: bool,
    /// Write a fresh NOR image over machine state that is neither blank nor
    /// one, and blank a foreign SEP area.
    #[arg(long, requires = "target")]
    initialize_nor: bool,
    /// The name of a new install, or the install another option acts on
    /// (the default install otherwise).
    #[arg(long)]
    install: Option<String>,
    /// The ECID of the machine being set up, in hexadecimal: reuse a known
    /// machine's (from `--status` of its old USB or a `--backup-state` file).
    #[arg(long, value_parser = |value: &str| Ecid::parse(value).map_err(|e| e.to_string()))]
    ecid: Option<Ecid>,
    /// Give the machine a new ECID although its machine state belongs to
    /// another one. Its LocalPolicy and SEP state are then orphaned.
    #[arg(long)]
    new_ecid: bool,
    /// Opt in to Apple's signing server: the restore host sends the
    /// machine's ECID, the restore's nonces and the build's component hashes
    /// to gs.apple.com for the restore's personalized root tickets and the
    /// recoveryOS LocalPolicy. Required for a new setup, which installs
    /// macOS: a local IPSW supplies the image files, but boot firmware still
    /// needs personalized tickets. On an existing setup it turns the opt-in
    /// on.
    #[arg(long, conflicts_with = "no_tss")]
    tss: bool,
    /// Turn the Apple signing server opt-in off on an existing setup.
    #[arg(long)]
    no_tss: bool,
    /// Have every startup choice time the engine (its `--profile`): each
    /// heartbeat of the boot log then reports where the engine's time goes
    /// between translated blocks, by phase and by exit kind.
    #[arg(long, conflicts_with = "no_profile")]
    profile: bool,
    /// Turn the engine profile off on an existing setup.
    #[arg(long)]
    no_profile: bool,
    /// Have the install refuse an IPSW without recorded block hashes, which
    /// it otherwise reads whole before the restore starts; with them it
    /// checks each block as the restore reads it either way. It adds the
    /// engine's `--verify-on-read` to the Install macOS choice.
    #[arg(long, requires = "target")]
    verify_on_read: bool,
    /// The USB's FAT32 data partition, when it has several, for the boot
    /// bundles, the install medium (the full IPSW in pieces or its
    /// inventory) and the translation store; the first one by default.
    #[arg(long)]
    install_volume: Option<PathBuf>,
    /// Boot this install by default.
    #[arg(long)]
    default_install: Option<String>,
    /// Remove this install from the setup; its partitions are kept.
    #[arg(long)]
    remove_install: Option<String>,
    /// Seconds `stela.efi`'s startup choices wait (0: only when a key is
    /// held).
    #[arg(long)]
    chooser_timeout: Option<u32>,
    /// Replace `stela.efi` (`--efi`, or the one beside `stela`) on an
    /// existing setup, keeping the old one for `--rollback`; `--ipsw` or
    /// `--fetch` lets it prepare the boot bundles again when it reads a new
    /// bundle schema or this `stela` prepares a new bundle revision.
    #[arg(long)]
    update_stela: bool,
    /// Add a new macOS build's install medium and restore bundles (`--ipsw`
    /// or `--fetch`) to an existing setup for Install macOS.
    #[arg(long)]
    update_os: bool,
    /// Undo the last update, or an interrupted one.
    #[arg(long)]
    rollback: bool,
    /// Choose the next boot of the installed disk in its NVRAM.
    #[arg(long, value_enum)]
    next_boot: Option<NextBoot>,
    /// Report everything about the setup and check it, changing nothing;
    /// fails when something needs fixing.
    #[arg(long, visible_alias = "doctor")]
    status: bool,
    /// Put back what the setup record says (stela.efi, the entry,
    /// stela.cfg, the startup choices); with `--ipsw` or `--fetch`, prepare
    /// the active build's restore bundles again.
    #[arg(long)]
    repair: bool,
    /// Write a fresh NVRAM to the install's NOR partition (named again with
    /// `--nor`); its SEP state is kept.
    #[arg(long)]
    reset_nvram: bool,
    /// Copy the install's machine state (NVRAM and SEP state, with its keys)
    /// to a new private file.
    #[arg(long, value_name = "FILE")]
    backup_state: Option<PathBuf>,
    /// Write a `--backup-state` file back to the install it came from (its
    /// NOR partition named again with `--nor`).
    #[arg(long, value_name = "FILE")]
    restore_state: Option<PathBuf>,
    /// Print the boot log stela.efi keeps on the install's machine-state
    /// partition (`--install`, or the default install).
    #[arg(long)]
    boot_log: bool,
    /// The bound of each translation pack `stela.efi` keeps on the USB, in
    /// bytes (64 MiB to 4 GiB; 0 for none). By default 2 GiB, or what the
    /// USB's FAT32 volumes have room for.
    #[arg(long, value_name = "BYTES")]
    translation_store_bytes: Option<u64>,
    /// Install an authorized local host-device firmware package (manifest.json
    /// and resources) onto an existing USB; independent of Apple boot bundles.
    #[arg(long, value_name = "DIRECTORY")]
    host_firmware: Option<PathBuf>,
    /// Download pinned vendor firmware for exact requirements captured by native
    /// drivers. The inventory must come from the target PC, not this setup host.
    #[arg(long, value_name = "FILE")]
    host_firmware_requirements: Option<PathBuf>,
    /// Cache for pinned host firmware images and redistribution notices.
    #[arg(
        long,
        value_name = "DIRECTORY",
        requires = "host_firmware_requirements"
    )]
    host_firmware_cache: Option<PathBuf>,
    /// The model or size, as setup shows it, of the whole disk `--usb`
    /// names, which erasing a removable disk other than a USB (an SD card,
    /// a FireWire or Thunderbolt disk) needs typed back.
    #[arg(long, value_name = "MODEL|SIZE")]
    confirm_disk: Option<String>,
}

/// A partition's name, given as is or by its device path (`/dev/disk1s2`,
/// `/dev/sdb1`), as `--usb` takes a whole disk.
fn partition_name(value: &str) -> Result<String, String> {
    Ok(value.strip_prefix("/dev/").unwrap_or(value).to_owned())
}

#[derive(Args)]
pub struct InstallMedium {
    /// The macOS 27 restore image (IPSW); a download receipt beside it is
    /// checked.
    #[arg(long)]
    ipsw: PathBuf,
    /// The Mac model whose identities the inventory lists.
    #[arg(long, default_value = PINNED_MODEL)]
    model: String,
    /// The mounted FAT32 volume to write `stela/install/<build>` to.
    #[arg(long)]
    volume: PathBuf,
}

impl InstallMedium {
    pub fn run(self) -> Result<()> {
        let host = host::System;
        let info = host.volume(&self.volume)?;
        ensure!(
            info.filesystem == FileSystem::Fat,
            "{} is {}, not FAT32",
            self.volume.display(),
            info.filesystem
        );
        let (_, build) = restore::payload::identity(&self.ipsw, &self.model)?;
        let bytes = fs::metadata(&self.ipsw)?.len();
        let piece_bytes = stela_runtime::payload::PIECE_BYTES;
        medium::check_space(&host, &self.volume, &build, bytes, piece_bytes)?;
        let expected = medium::Expected::of(restore::receipt(&self.ipsw)?.as_ref());
        let inventory = restore::payload::inventory(&self.ipsw, &self.model, true, None, None)?;
        let written = medium::write(&self.volume, &self.ipsw, inventory, &expected, piece_bytes)?;
        let directory = medium::directory(&self.volume, &build);
        println!(
            "Install medium {}: {} pieces kept, {} written; payload.json SHA-256 {}",
            directory.display(),
            written.kept,
            written.wrote,
            written.manifest_sha256
        );
        println!(
            "Engine options: --install \\{}\\{} --install-source <the partition's GPT unique \
             GUID>",
            stela_runtime::payload::install_directory(&build).replace('/', "\\"),
            stela_runtime::payload::MANIFEST_FILE
        );
        if expected.sha1.is_none() {
            println!(
                "The IPSW has no download receipt: it was checked against its BuildManifest, not \
                 Apple's catalog digest."
            );
        }
        Ok(())
    }
}

/// What setup writes, recorded on the ESP so `--uninstall` can remove it.
/// Records before schema 8 also named a recoveryOS bundle on the USB, and
/// records before schema 9 kept the data partition's files under `EFI/`;
/// this `stela` reads them only to uninstall them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Record {
    schema_version: u32,
    kind: String,
    /// The active macOS build, which Install macOS restores.
    build: String,
    model: String,
    esp: PathBuf,
    /// The USB's FAT32 data partition.
    #[serde(alias = "payload_volume")]
    volume: PathBuf,
    /// A schema 1 setup's restore payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload_directory: Option<PathBuf>,
    /// `stela/boot/<build>` of the active build.
    bundle_directory: PathBuf,
    /// Directories setup created on the payload volume, deepest first.
    created_directories: Vec<PathBuf>,
    /// `stela.cfg`.
    options: String,
    complete: bool,
    /// Schema 3: the PC's own disk; read into `installs`.
    #[serde(default, skip_serializing)]
    installed: Option<installed::InstalledDisk>,
    /// Schema 3: the active `stela.efi` version and those kept, oldest
    /// first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stela_version: Option<String>,
    #[serde(default)]
    stela_versions: Vec<String>,
    /// Schema 3: the macOS builds kept for rollback, oldest first; `build`
    /// is the active one.
    #[serde(default, alias = "recovery_builds")]
    builds: Vec<String>,
    /// Schema 3: an update that started and has not finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<update::Change>,
    /// Schema 3: finished updates, for `--rollback`.
    #[serde(default)]
    history: Vec<update::Change>,
    /// Schema 4: the PC disks macOS installs onto, each its own machine.
    #[serde(default)]
    installs: Vec<machines::Install>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_install: Option<String>,
    /// Schema 4: the boot-bundle schema the active `stela.efi` reads.
    #[serde(default = "first_schema")]
    bundle_schema: u32,
    /// Schema 7: the revision of the active bundles, those of the loader
    /// that prepared them (`stela_loader::boot_bundle::REVISION`); 0 before.
    #[serde(default)]
    bundle_revision: u32,
    /// Schema 4: every boot bundle setup wrote.
    #[serde(default)]
    bundles: Vec<bundle::Bundle>,
    /// Schema 4: the Apple signing server opt-in (`--tss`).
    #[serde(default)]
    tss: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chooser_timeout: Option<u32>,
    /// Schema 5: the install medium; read into `media`.
    #[serde(default, skip_serializing)]
    medium: Option<medium::Medium>,
    /// Schema 6: the install media, each a full IPSW on the USB's FAT32
    /// data partition: the active build's and, for rollback, the one
    /// before it.
    #[serde(default)]
    media: Vec<medium::Medium>,
    /// Schema 5: the Install choice checks the IPSW as it reads it
    /// (`--verify-on-read`).
    #[serde(default)]
    verify_on_read: bool,
    /// Every choice times the engine (`--profile`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    profile: bool,
    /// Where installs read the restore image (`--install-image`); the
    /// default when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    install_image: Option<InstallImage>,
    /// The translation store `stela.efi` keeps its packs in, if the USB
    /// has room for one (`setup::translations`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    translations: Option<translations::Store>,
}

fn first_schema() -> u32 {
    1
}

const RECORD_KIND: &str = "stela_setup";
/// Schema 8: no recoveryOS bundle; every setup has an install. Schema 9:
/// the data partition's files are under `stela/`, not `EFI/stela/`.
const RECORD_SCHEMA: u32 = 9;

impl Record {
    /// Whether installs stream `ipsw`'s build from Apple's servers
    /// (`--install-image online`) rather than read it from the USB. An erase
    /// restore needs the macOS system image, which a recovery archive
    /// (`restore::payload::trim`) leaves out
    /// (`docs/research/small-installer-usb.md`). A complete local image
    /// stays local by default, including when the target disk will be
    /// chosen later on another PC.
    fn remote_install(&self, ipsw: &Path) -> Result<bool> {
        image_is_remote(ipsw, self.install_image)
    }

    /// Bring an older schema's record to one `--uninstall` reads: its
    /// install medium is listed and its installed disk becomes the first
    /// install.
    fn migrate(&mut self) {
        if let Some(medium) = self.medium.take()
            && !self.media.iter().any(|m| m.build == medium.build)
        {
            self.media.push(medium);
        }
        if let Some(disk) = self.installed.take() {
            self.installs.push(machines::Install {
                name: machines::FIRST_NAME.into(),
                ecid: None,
                disk,
            });
        }
    }

    /// The install `stela.cfg` boots.
    fn default(&self) -> Option<&machines::Install> {
        self.default_install
            .as_ref()
            .and_then(|name| self.installs.iter().find(|i| &i.name == name))
            .or(self.installs.first())
    }

    /// The install `name` names, or the default one.
    fn install(&self, name: Option<&str>) -> Result<&machines::Install> {
        match name {
            Some(name) => self
                .installs
                .iter()
                .find(|i| i.name == name)
                .with_context(|| format!("this setup has no install named {name:?}")),
            None => self.default().with_context(|| {
                format!(
                    "the setup on {} names no installed disk (--target)",
                    self.esp.display()
                )
            }),
        }
    }

    /// The generation of the active bundles.
    fn generation(&self) -> bundle::Generation {
        bundle::Generation {
            schema: self.bundle_schema,
            revision: self.bundle_revision,
        }
    }

    fn line(&self, text: String) -> String {
        let tss = if self.tss { " --tss" } else { "" };
        let profile = if self.profile { " --profile" } else { "" };
        format!("{text}{tss}{profile}\n")
    }

    /// The option line that boots `install`.
    fn boot_line(&self, install: &machines::Install) -> String {
        self.line(install.disk.options(install.ecid))
    }

    /// `stela.cfg`: the default install. Every setup this `stela` reads
    /// has one ([`read_record`]).
    fn options_text(&self) -> String {
        self.default()
            .map(|install| self.boot_line(install))
            .unwrap_or_default()
    }

    /// The restore bundle of `kind` (erase or update) of `ecid`'s machine
    /// for the active build.
    /// The active build's restore bundle of `kind` for `ecid`, signed as the
    /// setup's TSS choice needs: under Apple's personalized ticket with the
    /// opt-in, under the global one without. A bundle signed the other way
    /// counts as missing, so the next setup run prepares it again.
    fn restore_bundle(&self, kind: Kind, ecid: Option<Ecid>) -> Option<&bundle::Bundle> {
        self.bundles.iter().find(|b| {
            b.same_kind(kind, &self.build, ecid, self.generation()) && b.personalized == self.tss
        })
    }

    /// The install medium of `build`.
    fn medium_of(&self, build: &str) -> Option<&medium::Medium> {
        self.media.iter().find(|m| m.build == build)
    }

    /// The active build's install medium.
    fn active_medium(&self) -> Option<&medium::Medium> {
        self.medium_of(&self.build)
    }

    /// Whether the installs restore from install media: the setup has
    /// written a medium or a restore bundle, as every setup does.
    fn installs_media(&self) -> bool {
        !self.installs.is_empty() && (!self.media.is_empty() || !self.bundles.is_empty())
    }

    /// The machines of the installs, each once.
    fn install_machines(&self) -> Vec<Option<Ecid>> {
        let mut machines = Vec::new();
        for install in &self.installs {
            if !machines.contains(&install.ecid) {
                machines.push(install.ecid);
            }
        }
        machines
    }

    /// The option line of `install`'s Install macOS choice
    /// ([`Kind::Restore`]) or Update macOS choice
    /// ([`Kind::Update`]): its restore bundle of that kind, the install
    /// medium and its partitions. None without the active build's medium or
    /// the machine's bundle, or without the signing server opt-in.
    fn restore_line(&self, kind: Kind, install: &machines::Install) -> Option<String> {
        let medium = self.active_medium()?;
        self.restore_bundle(kind, install.ecid)?;
        if !self.tss {
            return None;
        }
        let restore = bundle::firmware_path_of(kind, &self.build, install.ecid, self.generation());
        let base = install.disk.bundle_options(&restore, install.ecid);
        let update = if kind == Kind::Update {
            format!(" {UPDATE_RESTORE}")
        } else {
            String::new()
        };
        let verify = if self.verify_on_read {
            " --verify-on-read"
        } else {
            ""
        };
        let development = if kind == Kind::Restore {
            " --development-restore"
        } else {
            ""
        };
        Some(self.line(format!(
            "{base} {}{update}{verify}{development}",
            medium.options()
        )))
    }

    /// The Install macOS choice's option line.
    fn install_line(&self, install: &machines::Install) -> Option<String> {
        self.restore_line(Kind::Restore, install)
    }

    /// The name of `install`'s Install macOS or Update macOS
    /// (Stela) choice.
    fn restore_choice(&self, kind: Kind, install: &machines::Install) -> String {
        if self.installs.len() == 1 {
            return restore_choice_name(kind).into();
        }
        let several = match kind {
            Kind::Update => "Update macOS",
            _ => "Install macOS",
        };
        format!("{} - {several}", install.name)
    }

    /// The restore bundles the installs' machines need of the active build
    /// and lack: both kinds of every install's while the setup has the
    /// build's install medium.
    fn missing_restore_bundles(&self) -> Vec<(Kind, Option<Ecid>)> {
        if self.active_medium().is_none() {
            return Vec::new();
        }
        let mut missing = Vec::new();
        for kind in bundle::RESTORE_KINDS {
            for ecid in self.install_machines() {
                let present = self
                    .restore_bundle(kind, ecid)
                    .is_some_and(|b| b.directory(&self.volume).join(bundle::MANIFEST).is_file());
                if !present {
                    missing.push((kind, ecid));
                }
            }
        }
        missing
    }

    /// The startup choices: each install, default first, and its Install
    /// macOS. None without an installed disk.
    fn choices(&self) -> Option<Choices> {
        let default = self.default()?;
        let mut entries = Vec::new();
        let others = self.installs.iter().filter(|i| i.name != default.name);
        for install in std::iter::once(default).chain(others) {
            entries.push(Choice {
                name: install.name.clone(),
                options: self.boot_line(install).trim().into(),
            });
            for kind in bundle::RESTORE_KINDS {
                if let Some(line) = self.restore_line(kind, install) {
                    entries.push(Choice {
                        name: self.restore_choice(kind, install),
                        options: line.trim().into(),
                    });
                }
            }
        }
        // The list opens on its own with several installs, and while the
        // USB can install macOS.
        let installing = self.installs.iter().any(|i| self.install_line(i).is_some());
        let seconds = if self.installs.len() > 1 || installing {
            CHOOSER_SECONDS
        } else {
            0
        };
        Some(Choices {
            timeout_seconds: self.chooser_timeout.unwrap_or(seconds),
            entries,
        })
    }

    fn choices_text(&self) -> Result<Option<String>> {
        self.choices()
            .map(|choices| choices.encode().map_err(anyhow::Error::msg))
            .transpose()
    }

    /// Forget the bundles of machines the setup no longer has; returns
    /// them for [`remove_bundles`] once the record no longer names them.
    fn drop_stale_bundles(&mut self) -> Vec<bundle::Bundle> {
        let machines = self.install_machines();
        let (kept, stale) = self
            .bundles
            .drain(..)
            .partition(|b| machines.contains(&b.ecid));
        self.bundles = kept;
        stale
    }

    /// Every build directory a bundle or the history names.
    fn build_directories(&self) -> Vec<PathBuf> {
        let mut builds: Vec<&String> = self.builds.iter().collect();
        builds.push(&self.build);
        builds.extend(self.bundles.iter().map(|b| &b.build));
        let mut directories = Vec::new();
        for build in builds {
            let directory = bundle::build_directory(&self.volume, build);
            if !directories.contains(&directory) {
                directories.push(directory);
            }
        }
        directories
    }
}

/// Delete the directories of bundles the record no longer names.
fn remove_bundles(record: &Record, stale: &[bundle::Bundle]) -> Result<()> {
    for kept in stale {
        let directory = kept.directory(&record.volume);
        if directory.is_dir() {
            fs::remove_dir_all(directory)?;
        }
    }
    Ok(())
}

/// Write `stela.cfg`, the startup choices and the entry for the record.
fn publish(record: &mut Record) -> Result<()> {
    record.options = record.options_text();
    let choices = record.choices_text()?;
    let tool = record.esp.join(LOADER_PATH);
    efi::add_mount(&record.esp, &tool, None, Some(&record.options))?;
    let path = record.esp.join(CHOICES_PATH);
    match choices {
        Some(text) => efi::write_atomic(&path, text.as_bytes(), false)?,
        None if path.exists() => fs::remove_file(&path)?,
        None => {}
    }
    Ok(())
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
    let header: serde_json::Value = stela_runtime::read_json(&path)?;
    let schema = header["schema_version"].as_u64().unwrap_or(0);
    ensure!(
        header["kind"] == RECORD_KIND && schema <= u64::from(RECORD_SCHEMA),
        "{} is not a setup record this version understands; it may come from a newer stela",
        path.display()
    );
    ensure!(
        schema == u64::from(RECORD_SCHEMA),
        "{} is a schema {schema} setup, which this stela no longer reads: {}. Run `stela setup \
         --uninstall --usb {}` and set the USB up again",
        path.display(),
        match schema {
            8 => "it keeps its files under EFI/ on the data partition",
            _ => "it booted a recoveryOS bundle from the USB",
        },
        usb.display()
    );
    let record: Record = stela_runtime::read_json(&path)?;
    ensure!(
        !record.installs.is_empty(),
        "{} names no install; run `stela setup --uninstall --usb {}` and set the USB up again",
        path.display(),
        usb.display()
    );
    Ok(record)
}

/// Any schema's record, for `--uninstall`: the bundles of an older
/// schema's record that name no kind or `recovery` are recoveryOS bundles,
/// which this `stela` has no kind for; their build directories are removed
/// with the rest. Before schema 9 the data partition's files were under
/// `EFI/`, which the record's volumes then gain, so every directory derived
/// from them is where that setup wrote it.
fn read_any_record(path: &Path) -> Result<Record> {
    let mut value: serde_json::Value = stela_runtime::read_json(path)?;
    let schema = value["schema_version"].as_u64().unwrap_or(0);
    ensure!(
        value["kind"] == RECORD_KIND && (1..=u64::from(RECORD_SCHEMA)).contains(&schema),
        "{} is not a setup record this version understands",
        path.display()
    );
    if schema < 8
        && let Some(bundles) = value
            .get_mut("bundles")
            .and_then(serde_json::Value::as_array_mut)
    {
        bundles.retain(|bundle| {
            bundle
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| kind != "recovery")
        });
    }
    let mut record: Record = serde_json::from_value(value)
        .with_context(|| format!("{} cannot be read", path.display()))?;
    record.migrate();
    if schema < 9 {
        record.volume.push("EFI");
        for medium in record.media.iter_mut().chain(record.medium.as_mut()) {
            medium.volume.push("EFI");
        }
        if let Some(store) = &mut record.translations {
            store.volume.push("EFI");
        }
    }
    Ok(record)
}

/// Replace the record through a synced sibling file, so a stop at any point
/// leaves the previous record or this one whole: the record is the journal
/// every interrupted setup, update and rollback is resumed or undone from.
fn write_record(esp: &Path, record: &Record) -> Result<()> {
    let path = esp.join(RECORD);
    fs::create_dir_all(path.parent().unwrap())?;
    let mut record = record.clone();
    record.schema_version = RECORD_SCHEMA;
    let mut bytes = serde_json::to_vec_pretty(&record)?;
    bytes.push(b'\n');
    efi::write_atomic(&path, &bytes, false)
}

/// Writes a restore bundle for an IPSW, model and machine into a
/// directory, under Apple's personalized ticket when the `bool` says so.
type Prepare = dyn Fn(&Path, &str, Option<Ecid>, bool, &Path) -> Result<()>;

/// An IPSW's restore inventory for a model.
type InventoryOf = dyn Fn(&Path, &str) -> Result<restore::payload::Inventory>;

/// Inputs that the command line fixes and tests replace.
#[derive(Clone, Copy)]
struct Environment<'a> {
    host: &'a dyn Host,
    download: Option<&'a medium::download::Download>,
    /// `stela-dev boot prepare --restore`; tests use synthetic IPSWs, which
    /// have no kernel, and write a stand-in.
    prepare_restore: &'a Prepare,
    /// `stela-dev boot prepare --restore --update`, likewise.
    prepare_update: &'a Prepare,
    /// The install medium's inventory, with the public AEA keys fetched.
    inventory: &'a InventoryOf,
    /// The inventory of the IPSW's build on Apple's servers, which a remote
    /// medium names (`restore::remote_inventory`).
    remote_inventory: &'a InventoryOf,
    /// The install medium's piece size (`payload::PIECE_BYTES`).
    piece_bytes: u64,
    /// The mount interface this `stela` writes for.
    interface: Interface,
    /// The revision of the bundles this `stela` prepares
    /// (`stela_loader::boot_bundle::REVISION`).
    bundle_revision: u32,
    /// The macOS builds setup prepares (`stela_runtime::builds::SUPPORTED`);
    /// tests add their synthetic images' builds.
    builds: &'a [builds::Build],
}

impl Environment<'_> {
    /// The generation of the bundles this `stela` prepares.
    fn generation(&self) -> bundle::Generation {
        bundle::Generation {
            schema: self.interface.bundle_schema,
            revision: self.bundle_revision,
        }
    }
}

/// The `stela.efi` at `path`, which must be a UEFI application with this
/// `stela`'s mount interface.
fn read_efi(environment: &Environment<'_>, path: &Path) -> Result<Vec<u8>> {
    let image = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    ensure!(
        image.starts_with(b"MZ"),
        "{} is not a UEFI application",
        path.display()
    );
    if let Some(reason) =
        mount_interface::mismatch(environment.interface, mount_interface::find(&image))
    {
        bail!(
            "{} is not the stela.efi this stela installs: {reason}. Omit --efi to install the \
             stela.efi built into this stela.",
            path.display()
        );
    }
    Ok(image)
}

/// Refuse to change a setup whose installed `stela.efi` reads another
/// interface than this `stela` writes; `--update-stela` replaces it first.
fn check_installed_efi(environment: &Environment<'_>, record: &Record) -> Result<()> {
    let tool = record.esp.join(LOADER_PATH);
    let image = fs::read(&tool).with_context(|| format!("cannot read {}", tool.display()))?;
    if let Some(reason) =
        mount_interface::mismatch(environment.interface, mount_interface::find(&image))
    {
        bail!(
            "the stela.efi on {} does not read what this stela writes ({reason}); install this \
             stela's stela.efi first with `stela setup --update-stela`, or use the stela that \
             installed it",
            record.esp.display()
        );
    }
    Ok(())
}

/// Refuse to prepare bundles for `record` when its active ones are of
/// another revision than this `stela` prepares: `--update-stela` prepares
/// them all at this one, keeping the old ones for its rollback.
fn check_bundle_revision(environment: &Environment<'_>, record: &Record) -> Result<()> {
    match revision_mismatch(environment, record) {
        Some(reason) => bail!("{reason}"),
        None => Ok(()),
    }
}

/// Why `record`'s active bundles are not of the revision this `stela`
/// prepares, with the command that brings them to it.
fn revision_mismatch(environment: &Environment<'_>, record: &Record) -> Option<String> {
    let (theirs, ours) = (record.bundle_revision, environment.bundle_revision);
    if theirs == ours {
        return None;
    }
    Some(if theirs < ours {
        format!(
            "this setup's boot bundles are revision {theirs}, and this stela prepares revision \
             {ours}: prepare them again with `stela setup --update-stela` and the macOS {} \
             restore image (--ipsw or --fetch)",
            record.build
        )
    } else {
        format!(
            "this setup's boot bundles are revision {theirs}, newer than the revision {ours} \
             this stela prepares: use the stela that prepared them"
        )
    })
}

/// A boot bundle prepared on this computer, not yet copied.
struct Prepared {
    build: String,
    ecid: Option<Ecid>,
    kind: Kind,
    personalized: bool,
    generation: bundle::Generation,
    directory: tempfile::TempDir,
    bytes: u64,
}

type PreparedSetup = (String, String, Vec<Prepared>);

impl Prepared {
    fn path(&self) -> PathBuf {
        self.directory.path().join(BUNDLE_LEAF)
    }
}

/// The directory a bundle is prepared into, inside its temporary one.
const BUNDLE_LEAF: &str = "bundle";

/// Prepare `ipsw`'s restore bundles of every kind setup writes
/// ([`bundle::RESTORE_KINDS`]) for the machine `ecid`, under Apple's
/// personalized ticket. Returns the image's version and build too.
fn prepare_restore_bundles(
    environment: &Environment<'_>,
    ipsw: &Path,
    model: &str,
    ecid: Ecid,
) -> Result<PreparedSetup> {
    let (product_version, build) = restore::payload::identity(ipsw, model)?;
    let mut prepared = Vec::new();
    for kind in bundle::RESTORE_KINDS {
        let (_, _, bundles) = prepare_kind(
            environment,
            kind,
            true,
            ipsw,
            model,
            Some(&build),
            &[Some(ecid)],
        )?;
        prepared.extend(bundles);
    }
    Ok((product_version, build, prepared))
}

/// Prepare `ipsw`'s bundles of `kind` for each machine of `ecids`, under
/// Apple's personalized ticket with the TSS opt-in `tss`; the image must be
/// `build`, when given. Returns the image's version and build too.
/// Refuse `ipsw`, of macOS `build`, unless setup supports that build.
fn supported(environment: &Environment<'_>, ipsw: &Path, build: &str) -> Result<()> {
    builds::find_in(environment.builds, build)
        .map(drop)
        .map_err(|error| anyhow::anyhow!("{}: {error}", ipsw.display()))
}

fn prepare_kind(
    environment: &Environment<'_>,
    kind: Kind,
    tss: bool,
    ipsw: &Path,
    model: &str,
    build: Option<&str>,
    ecids: &[Option<Ecid>],
) -> Result<(String, String, Vec<Prepared>)> {
    let (product_version, found) = restore::payload::identity(ipsw, model)?;
    if let Some(build) = build {
        ensure!(
            found == build,
            "{} holds macOS build {found}, not {build}",
            ipsw.display()
        );
    }
    supported(environment, ipsw, &found)?;
    let mut prepared = Vec::new();
    for &ecid in ecids {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join(BUNDLE_LEAF);
        let prepare = match kind {
            Kind::Restore => environment.prepare_restore,
            Kind::Update => environment.prepare_update,
        };
        let personalized = tss;
        let progress =
            crate::progress::Phase::spinner(format!("Preparing {} boot files", kind.label()));
        prepare(ipsw, model, ecid, personalized, &output)
            .with_context(|| format!("preparing the {} boot bundle", kind.label()))?;
        progress.finish();
        let generation = bundle::generation(&output)?;
        ensure!(
            generation == environment.generation(),
            "the prepared bundle is {generation}, not the {} this stela and its stela.efi use",
            environment.generation()
        );
        let bytes = bundle::bytes(&output)?;
        prepared.push(Prepared {
            build: found.clone(),
            ecid,
            kind,
            personalized,
            generation,
            directory,
            bytes,
        });
    }
    Ok((product_version, found, prepared))
}

/// Copy prepared bundles to the record's volume and record them, as
/// bundles of its active generation.
fn copy_bundles(record: &mut Record, prepared: &[Prepared]) -> Result<()> {
    let generation = record.generation();
    for bundle in prepared {
        ensure!(
            bundle.generation == generation,
            "a {} bundle cannot be one of this setup's {generation} bundles",
            bundle.generation
        );
        let destination = bundle::directory_of(
            bundle.kind,
            &record.volume,
            &bundle.build,
            bundle.ecid,
            generation,
        );
        fs::create_dir_all(destination.parent().unwrap())?;
        let digest = bundle::install(&bundle.path(), &destination)?;
        // Read back, so a USB that loses writes is found now, not at boot.
        let problems = bundle::verify(&destination, &digest);
        ensure!(
            problems.is_empty(),
            "the copied bundle does not read back as written: {}",
            problems.join("; ")
        );
        record
            .bundles
            .retain(|b| !b.same_kind(bundle.kind, &bundle.build, bundle.ecid, generation));
        record.bundles.push(bundle::Bundle {
            build: bundle.build.clone(),
            ecid: bundle.ecid,
            schema: generation.schema,
            revision: generation.revision,
            manifest_sha256: digest,
            kind: bundle.kind,
            personalized: bundle.personalized,
        });
    }
    Ok(())
}

/// Whether `volume` has room for `prepared`.
fn check_space(host: &dyn Host, volume: &Path, prepared: &[Prepared]) -> Result<()> {
    let need: u64 = prepared.iter().map(|p| p.bytes).sum::<u64>() + MARGIN;
    let free = host.volume(volume)?.free_bytes;
    ensure!(
        free >= need,
        "{} has {:.1} GB free; the boot bundles need {:.1} GB",
        volume.display(),
        free as f64 / 1e9,
        need as f64 / 1e9
    );
    Ok(())
}

impl Setup {
    pub(crate) fn run(mut self) -> Result<()> {
        if self.usb.as_os_str().is_empty() {
            wizard::check_creation(&self)?;
            if !self.dry_run && elevation::relaunch()? {
                return Ok(());
            }
        }
        debug_assert_eq!(
            stela_loader::boot_bundle::SCHEMA_VERSION,
            mount_interface::CURRENT.bundle_schema
        );
        let environment = Environment {
            host: &host::System,
            download: None,
            prepare_restore: &prepare_restore,
            prepare_update: &prepare_update,
            inventory: &|ipsw, model| restore::payload::inventory(ipsw, model, true, None, None),
            remote_inventory: &|ipsw, model| {
                let (_, build) = restore::payload::identity(ipsw, model)?;
                let image = restore::select(&restore::catalog()?, Some(&build), Some(model))?;
                restore::remote_inventory(&image, model, None)
            },
            piece_bytes: stela_runtime::payload::PIECE_BYTES,
            interface: mount_interface::CURRENT,
            bundle_revision: stela_loader::boot_bundle::REVISION,
            builds: builds::SUPPORTED,
        };
        let interactive = self.usb.as_os_str().is_empty();
        if interactive && !wizard::configure(&mut self, environment.host)? {
            return Ok(());
        }
        let dry_run = self.dry_run;
        let profile = self.profile;
        let report = self.dispatch(&environment)?;
        if interactive && !dry_run {
            let profile = if profile {
                "\nProfiling is on. Keep EFI/stela/boot.log after your run."
            } else {
                ""
            };
            cliclack::note(
                "Next steps",
                format!(
                    "Boot the target PC from this USB and choose Install macOS.\nLater Apple policy signing may still need an internet connection.{profile}"
                ),
            )?;
            cliclack::outro("Your installer USB is ready")?;
        } else {
            print!("{report}");
        }
        Ok(())
    }

    fn model(&self) -> &str {
        self.model.as_deref().unwrap_or(PINNED_MODEL)
    }

    /// Settings of an existing setup this command changes.
    fn configures(&self) -> bool {
        self.default_install.is_some()
            || self.remove_install.is_some()
            || self.no_tss
            || self.no_profile
            || self.chooser_timeout.is_some()
    }

    /// At most one action per command.
    fn check_actions(&self) -> Result<()> {
        let actions = [
            ("--host-firmware", self.host_firmware.is_some()),
            (
                "--host-firmware-requirements",
                self.host_firmware_requirements.is_some(),
            ),
            ("--uninstall", self.uninstall),
            ("--update-stela", self.update_stela),
            ("--update-os", self.update_os),
            ("--rollback", self.rollback),
            ("--next-boot", self.next_boot.is_some()),
            ("--status", self.status),
            ("--repair", self.repair),
            ("--reset-nvram", self.reset_nvram),
            ("--backup-state", self.backup_state.is_some()),
            ("--restore-state", self.restore_state.is_some()),
            ("--boot-log", self.boot_log),
            ("--target", self.target.is_some()),
            ("--default-install, --remove-install", self.configures()),
        ];
        let chosen: Vec<&str> = actions
            .iter()
            .filter(|(_, on)| *on)
            .map(|(name, _)| *name)
            .collect();
        ensure!(
            chosen.len() <= 1,
            "{} are separate commands; run them one at a time",
            chosen.join(" and ")
        );
        ensure!(
            self.install_image.is_none()
                || chosen.is_empty()
                || self.target.is_some()
                || self.update_os
                || self.repair,
            "{INSTALL_IMAGE_ACTIONS}"
        );
        ensure!(
            self.nor.is_none()
                || self.target.is_some()
                || self.reset_nvram
                || self.backup_state.is_some()
                || self.restore_state.is_some()
                || self.boot_log,
            "--nor names a NOR partition for --target, --reset-nvram, --backup-state, \
             --restore-state or --boot-log"
        );
        ensure!(
            !self.erase_target || self.target.is_some() || self.repair,
            "--erase-target goes with --target or --repair"
        );
        Ok(())
    }

    fn dispatch(self, environment: &Environment<'_>) -> Result<String> {
        self.check_actions()?;
        if let Some(inventory) = &self.host_firmware_requirements {
            let record = read_record(environment, &self.usb)?;
            check_installed_efi(environment, &record)?;
            let mount_image = fs::read(record.esp.join(LOADER_PATH))?;
            ensure!(
                stela_loader::host_firmware::supports_mount(&mount_image),
                "installed stela.efi predates host firmware resources; run stela setup --update-stela first"
            );
            let cache = self
                .host_firmware_cache
                .clone()
                .unwrap_or_else(|| download_dir().with_file_name("firmware"));
            return firmware::provision(
                inventory,
                &record.esp.join(stela_loader::host_firmware::DIRECTORY),
                &cache,
                self.dry_run,
                &mount_image,
            );
        }
        if let Some(source) = &self.host_firmware {
            let record = read_record(environment, &self.usb)?;
            check_installed_efi(environment, &record)?;
            let mount_image = fs::read(record.esp.join(LOADER_PATH))?;
            ensure!(
                stela_loader::host_firmware::supports_mount(&mount_image),
                "installed stela.efi predates host firmware resources; run stela setup --update-stela first"
            );
            let package =
                stela_loader::host_firmware::Package::read_for_mount(source, &mount_image)?;
            let (images, bytes) = package.inventory();
            let destination = record.esp.join(stela_loader::host_firmware::DIRECTORY);
            let mut report = format!(
                "Host firmware: {images} verified resources, {bytes} bytes to {}\n",
                destination.display()
            );
            if self.dry_run {
                report.push_str("Dry run: nothing was changed.\n");
            } else {
                package.publish(&destination)?;
                report.push_str(
                    "Published host firmware manifest. Device initialization is checked at boot.\n",
                );
            }
            return Ok(report);
        }
        if self.uninstall {
            return uninstall(environment, &self.usb, self.dry_run);
        }
        if self.status {
            return doctor::status(environment, &self.usb);
        }
        if self.repair {
            return doctor::repair(environment, &self);
        }
        if self.reset_nvram {
            let record = read_record(environment, &self.usb)?;
            return state::reset_nvram(environment, &record, &self);
        }
        if let Some(path) = &self.backup_state {
            let record = read_record(environment, &self.usb)?;
            return state::backup(environment, &record, &self, path);
        }
        if let Some(path) = &self.restore_state {
            let record = read_record(environment, &self.usb)?;
            return state::restore(environment, &record, &self, path);
        }
        if self.boot_log {
            let record = read_record(environment, &self.usb)?;
            return state::boot_log(environment, &record, &self);
        }
        if self.update_stela {
            let record = read_record(environment, &self.usb)?;
            let image = match &self.efi {
                Some(path) => path.clone(),
                None => assets::resolve()?,
            };
            let ipsw = (self.ipsw.is_some() || self.fetch)
                .then(|| self.image())
                .transpose()?;
            return update::update_stela(
                environment,
                record,
                &image,
                ipsw.as_deref(),
                self.dry_run,
            );
        }
        if self.update_os {
            let mut record = read_record(environment, &self.usb)?;
            check_installed_efi(environment, &record)?;
            record.install_image = self.install_image.or(record.install_image);
            let ipsw = self.image()?;
            return update::update_os(environment, record, &ipsw, self.dry_run);
        }
        if self.rollback {
            return update::rollback(read_record(environment, &self.usb)?, self.dry_run);
        }
        if let Some(next) = self.next_boot {
            let record = read_record(environment, &self.usb)?;
            check_installed_efi(environment, &record)?;
            let install = record.install(self.install.as_deref())?;
            let disk = &install.disk;
            let changes = installed::next_boot(environment.host, disk, next, self.dry_run)?;
            let mut text = format!(
                "NVRAM of {} (install \"{}\"'s machine state):\n",
                match disk.machine_state_offset {
                    Some(offset) => format!("{} from byte {offset:#x}", disk.nor),
                    None => disk.nor.clone(),
                },
                install.name
            );
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
        let configured =
            locate_esp(environment.host, &self.usb).is_ok_and(|esp| esp.join(RECORD).is_file());
        ensure!(
            !configured || self.install_image.is_none() || self.target.is_some(),
            "{INSTALL_IMAGE_ACTIONS}"
        );
        if configured && self.target.is_some() {
            return machines::add(environment, &self);
        }
        if configured
            && (self.configures()
                || ((self.tss || self.profile) && self.ipsw.is_none() && !self.fetch))
        {
            return machines::configure(environment, &self);
        }
        ensure!(
            !self.configures() && !self.no_tss && !self.no_profile,
            "{} has no setup to change; run `stela setup` first",
            self.usb.display()
        );
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

    /// The restore image when the command names one.
    fn optional_image(&self) -> Result<Option<PathBuf>> {
        (self.ipsw.is_some() || self.fetch)
            .then(|| self.image())
            .transpose()
    }
}

/// The ESP to change: the EFI partition of `usb`'s disk, which must be
/// mounted, sit on a removable disk and boot no loader but Stela's.
/// The setup USB's one unmounted partition besides its EFI partition: a
/// raw partition, which becomes the Mac's internal SSD. `None` when the USB
/// has none; several are refused, since setup cannot tell them apart.
fn stick_ssd(host: &dyn Host, usb_disk: Option<&str>) -> Result<Option<String>> {
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

fn locate_esp(host: &dyn Host, usb: &Path) -> Result<PathBuf> {
    ensure!(usb.is_dir(), "{} is not a mounted volume", usb.display());
    let volume = host.volume(usb)?;
    let disks = host.disks()?;
    let disk = volume
        .disk
        .as_ref()
        .and_then(|id| disks.iter().find(|d| &d.identifier == id));
    let partition = disk.and_then(|d| d.partitions.iter().find(|p| p.content == "EFI"));
    let esp = match partition {
        Some(partition) => match &partition.mount {
            Some(mount) => mount.clone(),
            // Hosts leave a USB's EFI partition unmounted.
            None => host.mount(&partition.identifier).with_context(|| {
                format!(
                    "{} is on the same disk as EFI partition {}, which could not be mounted \
                     (setup needs {})",
                    usb.display(),
                    partition.identifier,
                    host::ADMIN
                )
            })?,
        },
        None => bail!(
            "{} is on a disk without an EFI partition. Setup erases a USB into one when --usb \
             names its whole disk (such as {}), which deletes everything on it.",
            usb.display(),
            host::DISK_EXAMPLE
        ),
    };
    // A USB setup prepared owns its loader, damaged or old as it may be.
    if !esp.join(RECORD).is_file() {
        efi::check_loader(&esp)?;
    }
    if let Some(disk) = host
        .volume(&esp)?
        .disk
        .and_then(|id| disks.into_iter().find(|d| d.identifier == id))
    {
        ensure!(
            disk.erasable(),
            "{} is on {} ({}), an internal disk{}. Setup changes only a removable USB; use \
             `stela-dev efi install` to install Stela on another EFI partition by hand.",
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

/// Where `--fetch` keeps downloaded restore images: the host's per-user cache.
pub(crate) fn download_dir() -> PathBuf {
    std::env::temp_dir().join("Stela/images")
}

/// Download `--build`'s image, or reuse a complete earlier download: the
/// whole IPSW for an offline install medium, else its recovery members,
/// which prepare the boot bundles.
fn fetch(command: &Setup) -> Result<PathBuf> {
    let directory = command.download_dir.clone().unwrap_or_else(download_dir);
    match command.install_image {
        Some(InstallImage::Offline) => fetch_image(&directory, &command.build, command.model()),
        _ => fetch_recovery(&directory, &command.build, command.model()),
    }
}

/// Copy `build`'s recovery members for `model` from Apple's servers into
/// `directory` (`restore::fetch_recovery`), or reuse an earlier complete
/// copy: setup's install medium needs no more of the image.
fn fetch_recovery(directory: &Path, build: &str, model: &str) -> Result<PathBuf> {
    ensure!(
        build.bytes().all(|c| c.is_ascii_alphanumeric())
            && model
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b','),
        "unexpected build or model identifier"
    );
    let path = directory.join(format!("Recovery_{build}_{}.ipsw", model.replace(',', "_")));
    if path.is_file() {
        let archive = zip::ZipArchive::new(fs::File::open(&path)?)
            .with_context(|| format!("{} is not a complete archive", path.display()))?;
        ensure!(
            archive.comment() == restore::payload::RECOVERY_COMMENT,
            "{} is not a recovery archive; move it away",
            path.display()
        );
        eprintln!("Using downloaded boot files");
        return Ok(path);
    }
    let images = restore::catalog()?;
    let image = restore::select(&images, Some(build), Some(model))?;
    fs::create_dir_all(directory)?;
    let bytes = restore::fetch_recovery(&image, model, &path)?;
    eprintln!("Downloaded {:.2} GB of boot files", bytes as f64 / 1e9);
    Ok(path)
}

/// Download `build`'s restore image for `model` from Apple's catalog into
/// `directory`, or reuse a complete earlier download from the same entry.
pub(crate) fn fetch_image(directory: &Path, build: &str, model: &str) -> Result<PathBuf> {
    let images = restore::catalog()?;
    let image = restore::select(&images, Some(build), Some(model))?;
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
    if path.is_file()
        && let Some(receipt) = restore::receipt(&path)?
    {
        // Reused only as the catalog entry it was downloaded from.
        ensure!(
            receipt.image == image && receipt.catalog_sha1_verified,
            "{} was downloaded from another catalog entry than Apple lists for macOS {} now; \
             move it away, or pass it with --ipsw",
            path.display(),
            image.build
        );
        eprintln!("Using the downloaded macOS image");
    } else {
        restore::download(&image, &path)?;
    }
    Ok(path)
}

/// The console boot-args of the bundles setup prepares: the kernel's text
/// on the screen (`-v`) and on the debug UART, which the engine records in
/// the boot log as `GUEST|` lines, so a run on a PC can be read afterwards.
const CONSOLE_BOOT_ARGS: &str = "--boot-args=-v serial=3 serial-device-name=uart0";

/// `stela-dev boot prepare --restore` for the IPSW, model and machine into
/// `output`: the restore bundle the Install macOS choice boots.
fn prepare_restore(
    ipsw: &Path,
    model: &str,
    ecid: Option<Ecid>,
    personalized: bool,
    output: &Path,
) -> Result<()> {
    prepare_ramdisk(ipsw, model, ecid, personalized, output, false)
}

/// `stela-dev boot prepare --restore --update`: the update restore bundle the
/// Update macOS choice boots.
fn prepare_update(
    ipsw: &Path,
    model: &str,
    ecid: Option<Ecid>,
    personalized: bool,
    output: &Path,
) -> Result<()> {
    prepare_ramdisk(ipsw, model, ecid, personalized, output, true)
}

/// A restore bundle of the model's erase or, with `update`, update restore
/// identity; `personalized`, under the AP ticket Apple's signing service
/// issues for the machine, which the restore's `--tss` choice needs. Then
/// the engine's own board check of the prepared DeviceTree
/// (`machine::soc::board`), so a model the engine cannot run is refused
/// before the USB changes rather than when the PC boots it.
fn prepare_ramdisk(
    ipsw: &Path,
    model: &str,
    ecid: Option<Ecid>,
    personalized: bool,
    output: &Path,
    update: bool,
) -> Result<()> {
    let mut line: Vec<String> = [
        "--ipsw",
        ipsw.to_str().context("IPSW path is not UTF-8")?,
        "--model",
        model,
        "--restore",
        "--output",
        output.to_str().context("temporary path is not UTF-8")?,
        CONSOLE_BOOT_ARGS,
    ]
    .map(str::to_owned)
    .into();
    if update {
        line.push("--update".into());
    }
    if let Some(ecid) = ecid {
        line.extend(["--ecid".into(), ecid.to_string()]);
    }
    if personalized {
        ensure!(
            ecid.is_some(),
            "a personalized restore bundle needs an ECID"
        );
        line.push("--tss".into());
    }
    boot::prepare(&line)?;
    let tree = fs::read(output.join("devicetree.adt"))?;
    stela_runtime::machine::soc::board(&tree)
        .map_err(|reason| anyhow::anyhow!("Stela cannot run {model} yet: {reason}"))?;
    Ok(())
}

/// The install medium setup writes.
struct MediumPlan {
    volume: PathBuf,
    guid: String,
    /// It names the IPSW on Apple's servers (`medium::write_remote`).
    remote: bool,
    ipsw_bytes: u64,
    /// Bytes still to write, with the hash files and a margin.
    need: u64,
    expected: medium::Expected,
    /// Directories it creates, deepest first.
    created: Vec<PathBuf>,
}

/// What installing macOS needs: each machine's restore bundles and, unless
/// the USB holds the build's intact medium, the install medium.
struct InstallPlan {
    /// The macOS build it installs.
    build: String,
    restore: Vec<Prepared>,
    medium: Option<MediumPlan>,
}

/// The restore bundles of both kinds for each of `ecids`.
fn restore_bundles(ecids: &[Option<Ecid>]) -> Vec<(Kind, Option<Ecid>)> {
    bundle::RESTORE_KINDS
        .into_iter()
        .flat_map(|kind| ecids.iter().map(move |&ecid| (kind, ecid)))
        .collect()
}

/// Plan the install of `build` from `ipsw` for `record`: the restore
/// bundles `bundles` names and the build's install medium; and check the
/// data partition's space: `also` is what else setup writes to it.
fn plan_install(
    environment: &Environment<'_>,
    record: &Record,
    build: &str,
    ipsw: &Path,
    bundles: &[(Kind, Option<Ecid>)],
    also: u64,
) -> Result<InstallPlan> {
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
                kind,
                record.tss,
                ipsw,
                &record.model,
                Some(build),
                &ecids,
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
fn describe_install(record: &Record, plan: &InstallPlan, text: &mut String) -> Result<()> {
    for bundle in &plan.restore {
        writeln!(
            text,
            "  {:<14} {} ({:.1} GB)",
            bundle.kind.label(),
            bundle::directory_of(
                bundle.kind,
                &record.volume,
                &bundle.build,
                bundle.ecid,
                record.generation()
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
fn apply_install(
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
    let written = medium::write(
        &plan.volume,
        ipsw,
        inventory,
        &plan.expected,
        environment.piece_bytes,
    )?;
    if let Some(medium) = record.media.iter_mut().find(|m| m.build == build) {
        medium.manifest_sha256 = written.manifest_sha256;
    }
    write_record(&record.esp.clone(), record)?;
    remove_replaced(record, &build, previous.as_ref())
}

/// Remove what the medium of `build` that the one just written replaced
/// left (`medium::remove_replaced`).
fn remove_replaced(record: &Record, build: &str, previous: Option<&medium::Medium>) -> Result<()> {
    match (previous, record.medium_of(build)) {
        (Some(previous), Some(current)) => medium::remove_replaced(previous, current),
        _ => Ok(()),
    }
}

/// Why a setup, which installs macOS, needs the explicit signing-service
/// choice.
const TSS_REQUIRED: &str = "Stela setup installs macOS onto the Mac's internal SSD, which \
    needs --tss: required boot firmware needs personalized tickets from Apple's signing \
    server (gs.apple.com), which receives this machine's ECID, the restore's nonces and its \
    boot components' hashes. Add --tss to opt in.";

/// The checks' result: everything setup will write, and where.
struct Plan {
    record: Record,
    ipsw: PathBuf,
    product_version: String,
    /// The prepared restore bundles, in a host directory until setup
    /// copies them.
    prepared: Vec<Prepared>,
    efi_image: Vec<u8>,
    /// The install's disk, and the NOR image setup writes to it.
    installed: installed::Checked,
    /// The install medium.
    install: InstallPlan,
    notes: Vec<String>,
}

fn plan(
    environment: &Environment<'_>,
    command: &Setup,
    ipsw: PathBuf,
    early: Option<PreparedSetup>,
) -> Result<Plan> {
    let host = environment.host;
    let esp = locate_esp(host, &command.usb)?;
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
        command.ecid,
        None,
        installed.sep_provisioned,
        command.new_ecid,
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
    };
    // The restore bundles are prepared above: the install plan adds the
    // install medium.
    let install = plan_install(environment, &record, &record.build, &ipsw, &[], bundles)?;
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
    record.options = record.options_text();
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
    })
}

/// What the Apple signing server opt-in sends.
fn tss_note() -> String {
    "TSS opt-in (--tss): the restore host sends this machine's ECID, the restore's nonces \
     and its boot components' hashes to Apple's signing server (gs.apple.com) for the \
     restore's root tickets and the recoveryOS LocalPolicy; `stela setup --no-tss` turns it \
     off."
        .into()
}

fn describe(plan: &Plan) -> Result<String> {
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
                prepared.kind,
                &record.volume,
                &prepared.build,
                prepared.ecid,
                record.generation()
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
fn state_line(disk: &installed::InstalledDisk) -> String {
    let label = if disk.machine_state_offset.is_some() || disk.is_chosen() {
        "machine state"
    } else {
        "NOR"
    };
    format!("{label:<14} {}", disk.state_description())
}

fn setup(environment: &Environment<'_>, mut command: Setup) -> Result<String> {
    let host = environment.host;
    ensure!(command.tss, TSS_REQUIRED);
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
         stela setup --status --usb {}\nUndo with: stela setup --uninstall --usb {}",
        command.usb.display(),
        command.usb.display()
    )?;
    Ok(report)
}

/// The FAT32 volume setup erases a USB into.
const USB_VOLUME: &str = "STELA";

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

fn apply(environment: &Environment<'_>, plan: Plan) -> Result<()> {
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
    // The version is kept first, so `--rollback` of a later update finds it.
    let version = update::store_version(&esp, &plan.efi_image)?;
    debug_assert_eq!(Some(&version), record.stela_version.as_ref());
    let kept = update::version_path(&esp, &version);
    efi::add_mount(&esp, &kept, None, Some(&record.options))?;
    publish(&mut record)?;
    record.complete = true;
    write_record(&esp, &record)
}

fn uninstall(environment: &Environment<'_>, usb: &Path, dry_run: bool) -> Result<String> {
    let esp = locate_esp(environment.host, usb)?;
    let record: Option<Record> = esp
        .join(RECORD)
        .is_file()
        .then(|| read_any_record(&esp.join(RECORD)))
        .transpose()?;
    let mut text = String::new();
    let mut removals: Vec<PathBuf> = Vec::new();
    if let Some(record) = &record {
        let directories: Vec<PathBuf> = record
            .payload_directory
            .iter()
            .cloned()
            .chain([record.bundle_directory.clone()])
            .chain(record.build_directories())
            .collect();
        for directory in directories {
            ensure!(
                directory.starts_with(&record.volume)
                    && directory.parent().is_some_and(|p| {
                        p.ends_with(bundle::BOOT_DIRECTORY) || p.ends_with("EFI/stela/images")
                    }),
                "the setup record names an unexpected directory {}",
                directory.display()
            );
            if directory.exists() && !removals.contains(&directory) {
                removals.push(directory);
            }
        }
        for medium in &record.media {
            let directory = medium.removable_directory()?;
            if directory.exists() {
                removals.push(directory);
            }
        }
        let versions = esp.join(update::VERSIONS);
        if versions.is_dir() {
            removals.push(versions);
        }
        if let Some(store) = &record.translations {
            let directory = translations::checked_directory(store)?;
            if directory.is_dir() {
                removals.push(directory);
            }
        }
    } else {
        writeln!(
            text,
            "No setup record on {}; removing only Stela's boot loader and files.",
            esp.display()
        )?;
    }
    writeln!(text, "Stela uninstall from {}:", esp.display())?;
    for directory in &removals {
        writeln!(text, "  remove   {}", directory.display())?;
    }
    for file in efi::INSTALLED.iter().chain([&CHOICES_PATH]) {
        if esp.join(file).is_file() {
            writeln!(text, "  remove   {}", esp.join(file).display())?;
        }
    }
    for install in record.iter().flat_map(|r| r.installs.iter()) {
        writeln!(
            text,
            "  keep     install \"{}\": {} keep macOS, its NVRAM and SEP state{}; delete them \
             with a disk utility when no longer wanted",
            install.name,
            install.disk.partitions(),
            install
                .ecid
                .map(|ecid| format!(" (ECID {ecid}, which a new setup reuses with --ecid)"))
                .unwrap_or_default()
        )?;
    }
    if dry_run {
        text.push_str("Dry run: nothing was changed.\n");
        return Ok(text);
    }
    for directory in &removals {
        fs::remove_dir_all(directory)
            .with_context(|| format!("cannot remove {}", directory.display()))?;
    }
    if esp.join(CHOICES_PATH).is_file() {
        fs::remove_file(esp.join(CHOICES_PATH))?;
    }
    if let Some(record) = &record {
        for directory in &record.created_directories {
            if fs::read_dir(directory).is_ok_and(|mut entries| entries.next().is_none()) {
                fs::remove_dir(directory)?;
            }
        }
        fs::remove_file(esp.join(RECORD))?;
    }
    efi::uninstall(&esp, record.is_some())?;
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

    #[test]
    fn partitions_are_named_alone_or_by_device_path() {
        use clap::Parser as _;
        let crate::Command::Setup(setup) = crate::Cli::try_parse_from([
            "stela",
            "setup",
            "--usb",
            "/dev/sdb",
            "--target",
            "/dev/nvme0n1p2",
            "--nor",
            "sdc3",
        ])
        .unwrap()
        .command
        else {
            panic!("not a setup");
        };
        assert_eq!(setup.target.as_deref(), Some("nvme0n1p2"));
        assert_eq!(setup.nor.as_deref(), Some("sdc3"));
    }

    /// A computer whose volumes and disks the test declares.
    pub(super) struct FakeHost {
        pub(super) volumes: BTreeMap<PathBuf, (FileSystem, u64, Option<&'static str>)>,
        pub(super) disks: Vec<Disk>,
        /// Partitions of the PC's disk, each backed by an image file.
        pub(super) partitions: BTreeMap<String, (PartitionInfo, PathBuf)>,
        pub(super) serials: BTreeMap<String, String>,
        pub(super) cpu: Cpu,
        /// The partitions `unmount` unmounted, in order.
        pub(super) unmounted: std::cell::RefCell<Vec<String>>,
        /// Where `mount` mounts a partition; others refuse.
        pub(super) mountable: BTreeMap<String, PathBuf>,
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
                cpu: Cpu { entropy: true },
                unmounted: Default::default(),
                mountable: BTreeMap::new(),
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
            let mut info = self
                .partitions
                .get(identifier)
                .map(|(info, _)| info.clone())
                .context("no such partition")?;
            if self
                .unmounted
                .borrow()
                .iter()
                .any(|done| done == identifier)
            {
                info.mount = None;
                info.container = None;
            }
            Ok(info)
        }
        fn unmount(&self, partition: &PartitionInfo) -> Result<()> {
            self.unmounted
                .borrow_mut()
                .push(partition.identifier.clone());
            Ok(())
        }
        fn mount(&self, identifier: &str) -> Result<PathBuf> {
            self.mountable
                .get(identifier)
                .cloned()
                .context("permission denied")
        }
        fn serial(&self, disk: &str) -> Result<Option<String>> {
            Ok(self.serials.get(disk).cloned())
        }
        // Images may be sparse files as large as the partition, so they
        // are read and written in place.
        fn read(&self, identifier: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
            use std::io::{Read, Seek, SeekFrom};
            let mut file = fs::File::open(self.image(identifier)?)?;
            ensure!(
                offset + length as u64 <= file.metadata()?.len(),
                "read past the partition"
            );
            file.seek(SeekFrom::Start(offset))?;
            let mut bytes = vec![0; length];
            file.read_exact(&mut bytes)?;
            Ok(bytes)
        }
        fn write(&self, identifier: &str, offset: u64, data: &[u8]) -> Result<()> {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = fs::OpenOptions::new()
                .write(true)
                .open(self.image(identifier)?)?;
            ensure!(
                offset + data.len() as u64 <= file.metadata()?.len(),
                "write past the partition"
            );
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(data)?;
            Ok(())
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
            bytes: 128 * GIB,
            removal: match id {
                "disk5" => host::Removal::Usb,
                "disk6" => host::Removal::Typed,
                _ => host::Removal::Fixed,
            },
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

    /// A `stela.efi` stand-in with this tree's mount interface.
    fn efi_image(tag: &[u8]) -> Vec<u8> {
        let mut image = b"MZ".to_vec();
        image.extend_from_slice(tag);
        image.extend_from_slice(&mount_interface::marker(mount_interface::CURRENT));
        image
    }

    /// A USB (disk5) with an empty EFI partition and a data volume, HFS+ or
    /// FAT, and this computer's system disk (disk0).
    struct Fixture {
        _dir: tempfile::TempDir,
        esp: PathBuf,
        data: PathBuf,
        ipsw: PathBuf,
        efi: PathBuf,
        host: FakeHost,
    }

    fn fixture(esp_free: u64, fat_data: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let esp = dir.path().join("ESP");
        let data = dir.path().join("Data");
        fs::create_dir_all(&esp).unwrap();
        fs::create_dir_all(&data).unwrap();
        let data_filesystem = if fat_data {
            FileSystem::Fat
        } else {
            FileSystem::Hfs
        };
        let ipsw = dir.path().join("Synthetic.ipsw");
        efi::synthetic_ipsw(&ipsw).unwrap();
        let efi = dir.path().join("stela.efi");
        fs::write(&efi, efi_image(b"stela")).unwrap();
        let host = FakeHost::new(
            [
                (esp.clone(), (FileSystem::Fat, esp_free, Some("disk5"))),
                (data.clone(), (data_filesystem, 100 * GIB, Some("disk5"))),
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
            install_image: None,
            download_dir: None,
            efi: Some(f.efi.clone()),
            model: Some(restore::payload::SYNTHETIC_MODEL.into()),
            build: restore::payload::SYNTHETIC_BUILD.into(),
            dry_run: false,
            uninstall: false,
            target: None,
            nor: None,
            disk_serial: None,
            erase_target: false,
            initialize_nor: false,
            install: None,
            ecid: None,
            new_ecid: false,
            // Every setup installs macOS, which needs the opt-in.
            tss: true,
            no_tss: false,
            profile: false,
            no_profile: false,
            verify_on_read: false,
            install_volume: None,
            default_install: None,
            remove_install: None,
            chooser_timeout: None,
            update_stela: false,
            update_os: false,
            rollback: false,
            next_boot: None,
            status: false,
            repair: false,
            reset_nvram: false,
            backup_state: None,
            restore_state: None,
            boot_log: false,
            // The smallest store: its spare is allocated at the bound, and
            // `snapshot` reads every file it compares. The default bound's
            // shrinking to fit is `translations::choose`'s to test.
            translation_store_bytes: Some(translations::MIN_PACK_BYTES),
            host_firmware: None,
            host_firmware_requirements: None,
            host_firmware_cache: None,
            confirm_disk: None,
        }
    }

    /// The generation of the bundles this tree prepares.
    fn current() -> bundle::Generation {
        bundle::Generation {
            schema: mount_interface::CURRENT.bundle_schema,
            revision: stela_loader::boot_bundle::REVISION,
        }
    }

    /// A stand-in for `boot prepare --restore`: the synthetic IPSW has no
    /// kernel to prepare. The bundle's byte names the machine.
    fn fake_prepare_restore(
        _: &Path,
        _: &str,
        ecid: Option<Ecid>,
        _: bool,
        output: &Path,
    ) -> Result<()> {
        let byte = ecid.map_or(0x5a, |e| e.0 as u8) ^ 0xa5;
        bundle::tests::write(output, current(), &[byte; 2048])
    }

    /// A stand-in for `boot prepare --restore --update`.
    fn fake_prepare_update(
        _: &Path,
        _: &str,
        ecid: Option<Ecid>,
        _: bool,
        output: &Path,
    ) -> Result<()> {
        let byte = ecid.map_or(0x5a, |e| e.0 as u8) ^ 0x3c;
        bundle::tests::write(output, current(), &[byte; 1024])
    }

    /// The synthetic IPSW's inventory: it names no AEA member to fetch a
    /// key for.
    fn fake_inventory(ipsw: &Path, model: &str) -> Result<restore::payload::Inventory> {
        restore::payload::inventory(ipsw, model, false, None, None)
    }

    /// The synthetic IPSW's inventory as if it were on Apple's servers.
    fn fake_remote_inventory(ipsw: &Path, model: &str) -> Result<restore::payload::Inventory> {
        let layout = stela_runtime::payload::Layout::Remote {
            url: "http://updates-http.example.test/Synthetic.ipsw".into(),
            etag: "\"synthetic\"".into(),
        };
        let bytes = fs::metadata(ipsw)?.len();
        restore::payload::remote_inventory(fs::File::open(ipsw)?, ipsw, bytes, layout, model, None)
    }

    fn environment(host: &FakeHost) -> Environment<'_> {
        Environment {
            host,
            download: None,
            prepare_restore: &fake_prepare_restore,
            prepare_update: &fake_prepare_update,
            inventory: &fake_inventory,
            remote_inventory: &fake_remote_inventory,
            piece_bytes: medium::tests::PIECE_BYTES,
            interface: mount_interface::CURRENT,
            bundle_revision: stela_loader::boot_bundle::REVISION,
            builds: SYNTHETIC_BUILDS,
        }
    }

    /// The synthetic images' builds, as supported ones.
    const SYNTHETIC_BUILDS: &[builds::Build] = &[
        synthetic_build(restore::payload::SYNTHETIC_BUILD),
        synthetic_build("STELA2"),
        synthetic_build("STELA3"),
    ];

    const fn synthetic_build(build: &'static str) -> builds::Build {
        builds::Build {
            build,
            version: "27.0",
            dcp_link_version: builds::DEFAULT.dcp_link_version,
        }
    }

    #[test]
    fn a_build_outside_the_table_is_not_prepared() {
        let f = fixture(64 * GIB, true);
        let environment = Environment {
            builds: builds::SUPPORTED,
            ..environment(&f.host)
        };
        let error = setup(&environment, command(&f, &f.esp))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!(
                "macOS build {} is not supported",
                restore::payload::SYNTHETIC_BUILD
            )),
            "{error}"
        );
        assert!(error.contains(builds::DEFAULT.build), "{error}");
    }

    /// Stand-ins for the restore and update restore `boot prepare` of a
    /// stela whose loader prepares `revision`; each bundle's byte names its
    /// machine, kind and revision.
    fn preparers(revision: u32) -> [Box<Prepare>; 2] {
        let of = |kind: u8, bytes: usize| -> Box<Prepare> {
            Box::new(
                move |_: &Path, _: &str, ecid: Option<Ecid>, _: bool, output: &Path| {
                    let byte = ecid.map_or(0x5a, |e| e.0 as u8) ^ kind ^ revision as u8;
                    let generation = bundle::Generation {
                        revision,
                        ..current()
                    };
                    bundle::tests::write(output, generation, &vec![byte; bytes])
                },
            )
        };
        [of(0xa5, 2048), of(0x3c, 1024)]
    }

    /// The environment of a stela whose loader prepares `revision`.
    fn environment_at<'a>(
        host: &'a FakeHost,
        preparers: &'a [Box<Prepare>; 2],
        revision: u32,
    ) -> Environment<'a> {
        Environment {
            prepare_restore: &*preparers[0],
            prepare_update: &*preparers[1],
            bundle_revision: revision,
            ..environment(host)
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

    fn record(f: &Fixture) -> Record {
        stela_runtime::read_json(&f.esp.join(RECORD)).unwrap()
    }

    /// The active build's restore bundle of `ecid`'s machine.
    fn bundle_of(f: &Fixture, ecid: Option<Ecid>) -> PathBuf {
        let record = record(f);
        bundle::directory_of(
            Kind::Restore,
            &record.volume,
            &record.build,
            ecid,
            record.generation(),
        )
    }

    #[test]
    fn setup_installs_from_the_usb_and_uninstall_restores_it() {
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        let volume = stela_volume(&f);
        let before = (snapshot(&f.esp), snapshot(&f.data), snapshot(&volume));
        let host = &f.host;

        // A setup installs macOS, which needs the signing opt-in.
        let mut no_tss = command(&f, &f.esp);
        no_tss.tss = false;
        let error = setup(&environment(host), no_tss).unwrap_err().to_string();
        assert!(error.contains("needs --tss"), "{error}");
        assert!(error.contains("gs.apple.com"), "{error}");
        assert_eq!(
            (snapshot(&f.esp), snapshot(&f.data), snapshot(&volume)),
            before
        );

        let mut dry = command(&f, &f.esp);
        dry.dry_run = true;
        let plan = setup(&environment(host), dry).unwrap();
        assert!(plan.contains("Dry run: nothing was changed."), "{plan}");
        assert!(plan.contains("the disk's own recoveryOS"), "{plan}");
        assert!(plan.contains("ECID           0x"), "{plan}");
        assert!(plan.contains("restore        "), "{plan}");
        assert!(!plan.contains("recoveryOS     "), "{plan}");
        assert_eq!(
            (snapshot(&f.esp), snapshot(&f.data), snapshot(&volume)),
            before
        );

        let report = setup(&environment(host), command(&f, &f.esp)).unwrap();
        assert!(report.contains("stela setup --uninstall"), "{report}");
        assert!(report.contains("pick the PC disk"), "{report}");
        let record = record(&f);
        let ecid = record.installs[0].ecid.unwrap();
        assert_ne!(ecid.0, 0);
        let options = fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap();
        assert_eq!(
            options,
            format!(
                "--system --storage @disk --nor @disk --preboot @disk --ecid {ecid} \
                 --external-disks --guest-network --tss\n"
            )
        );
        assert!(!options.contains("--bundle"), "{options}");
        // The only bundle is the machine's restore bundle.
        assert_eq!(record.bundles.len(), 1);
        assert_eq!(record.bundles[0].kind, Kind::Restore);
        let bundle = bundle_of(&f, Some(ecid));
        assert_eq!(
            fs::read(bundle.join("ramdisk.img")).unwrap(),
            vec![ecid.0 as u8 ^ 0xa5; 2048]
        );
        assert!(bundle::verify(&bundle, &record.bundles[0].manifest_sha256).is_empty());
        assert!(!f.esp.join("EFI/stela/source.bin").exists());
        let choices =
            Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
        let names: Vec<&str> = choices.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["macOS", INSTALL_CHOICE]);
        assert_eq!(
            fs::read(f.esp.join(efi::LOADER)).unwrap(),
            efi_image(b"stela")
        );
        assert!(record.complete);
        assert_eq!(record.schema_version, RECORD_SCHEMA);
        // A second setup is refused until the first is undone.
        let again = setup(&environment(host), command(&f, &f.esp));
        assert!(again.unwrap_err().to_string().contains("--uninstall"));
        // The only install is not removed alone.
        let error = rerun(&f, |c| c.remove_install = Some("macOS".into()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("only one"), "{error}");

        let dry = uninstall(&environment(host), &f.esp, true).unwrap();
        assert!(dry.contains("Dry run"));
        assert!(bundle.is_dir());
        let done = uninstall(&environment(host), &f.esp, false).unwrap();
        assert!(done.contains("Done."));
        assert_eq!(
            (snapshot(&f.esp), snapshot(&f.data), snapshot(&volume)),
            before
        );
    }

    #[test]
    fn a_stela_efi_of_another_interface_is_refused() {
        let f = fixture(64 * GIB, false);
        fs::write(&f.efi, b"MZ without a marker").unwrap();
        let error = setup(&environment(&f.host), command(&f, &f.esp))
            .unwrap_err()
            .to_string();
        assert!(error.contains("no Stela mount interface marker"), "{error}");
        let other = mount_interface::Interface {
            options_revision: mount_interface::OPTIONS_REVISION + 1,
            ..mount_interface::CURRENT
        };
        let mut image = b"MZ".to_vec();
        image.extend_from_slice(&mount_interface::marker(other));
        fs::write(&f.efi, image).unwrap();
        let error = setup(&environment(&f.host), command(&f, &f.esp))
            .unwrap_err()
            .to_string();
        assert!(error.contains("stela.cfg option revision"), "{error}");
        assert!(!f.esp.join(RECORD).exists());
    }

    #[test]
    fn the_bundles_go_to_the_usb_s_fat32_data_partition() {
        // The firmware cannot read HFS+, so the USB has no data partition.
        let f = fixture(GIB / 32, false);
        let error = setup(&environment(&f.host), command(&f, &f.data))
            .unwrap_err()
            .to_string();
        assert!(error.contains("not FAT32"), "{error}");
        assert!(
            error.contains("boot bundles and the install medium"),
            "{error}"
        );
        // A FAT data partition holds the bundle and the online install's
        // inventory under `stela/`; the EFI partition keeps only the boot
        // loader and its configuration.
        let mut f = fixture(GIB / 32, false);
        add_stela(&mut f);
        let volume = stela_volume(&f);
        let mut online = command(&f, &volume);
        online.install_image = Some(InstallImage::Online);
        setup(&environment(&f.host), online).unwrap();
        let ecid = record(&f).installs[0].ecid;
        assert!(bundle_of(&f, ecid).join("ramdisk.img").is_file());
        assert!(bundle_of(&f, ecid).starts_with(volume.join("stela/boot")));
        assert!(volume.join("stela/install").is_dir());
        assert!(!f.esp.join("stela").exists());
        assert!(f.esp.join(efi::LOADER).is_file());
        uninstall(&environment(&f.host), &volume, false).unwrap();
        assert!(!volume.join("stela").exists());
    }

    #[test]
    fn usbs_setup_cannot_boot_from_are_explained_and_left_unchanged() {
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        // A USB without an EFI partition, one whose partition is not
        // mounted, and one that already boots another loader.
        let dir = tempfile::tempdir().unwrap();
        let mut host = FakeHost::new(f.host.volumes.clone(), Vec::new());
        host.volumes
            .insert(dir.path().to_path_buf(), (FileSystem::Fat, GIB, None));
        let error = setup(&environment(&host), command(&f, dir.path()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("names its whole disk"), "{error}");
        let mut host = FakeHost::new(f.host.volumes.clone(), f.host.disks.clone());
        host.partitions = f.host.partitions.clone();
        // An unmounted EFI partition is mounted, or the error says why not.
        host.disks[1].partitions[0].mount = None;
        let error = setup(&environment(&host), command(&f, &f.data))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("disk5s1, which could not be mounted"),
            "{error}"
        );
        host.mountable.insert("disk5s1".into(), f.esp.clone());
        let mut dry = command(&f, &f.data);
        dry.dry_run = true;
        let plan = setup(&environment(&host), dry).unwrap();
        assert!(plan.contains(&f.esp.display().to_string()), "{plan}");
        let loader = f.esp.join(efi::LOADER);
        fs::create_dir_all(loader.parent().unwrap()).unwrap();
        fs::write(&loader, b"MZopencore").unwrap();
        let before = snapshot(&f.esp);
        let error = setup(&environment(&f.host), command(&f, &f.esp))
            .unwrap_err()
            .to_string();
        assert!(error.contains("another loader"), "{error}");
        assert_eq!(snapshot(&f.esp), before);
        // An internal EFI partition is another system's boot partition.
        let f = fixture(64 * GIB, false);
        let mut host = FakeHost::new(f.host.volumes.clone(), f.host.disks.clone());
        host.volumes
            .insert(f.esp.clone(), (FileSystem::Fat, 64 * GIB, Some("disk0")));
        host.disks[0].partitions[0].mount = Some(f.esp.clone());
        let error = setup(&environment(&host), command(&f, &f.esp))
            .unwrap_err()
            .to_string();
        assert!(error.contains("internal disk"), "{error}");
    }

    #[test]
    fn older_setups_are_still_read_and_undone() {
        // Schema 1, with a payload and a target.
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

        // Schema 7, with a recoveryOS bundle on the USB: this stela no longer
        // reads it, and uninstalls it.
        let f = fixture(64 * GIB, false);
        let before = snapshot(&f.esp);
        efi::add_mount(&f.esp, &f.efi, None, Some("--system\n")).unwrap();
        let build = f.esp.join("EFI/stela/boot/STELA1");
        let recovery = build.join("recovery-0000000000000001");
        let restore = build.join("restore-0000000000000001");
        bundle::tests::write(&recovery, bundle::Generation::FIRST, b"old").unwrap();
        bundle::tests::write(&restore, bundle::Generation::FIRST, b"old").unwrap();
        let disk = installed::InstalledDisk {
            apple_region: REGION.into(),
            apple_region_serial: SERIAL.into(),
            apple_region_guid: REGION_GUID.into(),
            nor: NOR.into(),
            nor_serial: SERIAL.into(),
            nor_guid: NOR_GUID.into(),
            machine_state_offset: None,
            external_disks: false,
        };
        let mut install = serde_json::to_value(&disk).unwrap();
        install["name"] = "macOS".into();
        install["ecid"] = "0x1".into();
        let record = serde_json::json!({
            "schema_version": 7,
            "kind": RECORD_KIND,
            "build": "STELA1",
            "model": "Mac14,3",
            "esp": f.esp,
            "volume": f.esp,
            "bundle_directory": build,
            "created_directories": [build, f.esp.join("EFI/stela/boot")],
            "options": "--system\n",
            "complete": true,
            "recovery_builds": ["STELA1"],
            "ecid": "0x1",
            "installs": [install],
            "bundles": [
                {"build": "STELA1", "ecid": "0x1", "schema": 1, "manifest_sha256": ""},
                {"build": "STELA1", "ecid": "0x1", "schema": 1, "manifest_sha256": "",
                 "kind": "restore", "personalized": true},
            ],
        });
        stela_runtime::write_json(&f.esp.join(RECORD), &record).unwrap();
        let error = read_record(&environment(&f.host), &f.esp)
            .unwrap_err()
            .to_string();
        assert!(error.contains("schema 7 setup"), "{error}");
        assert!(error.contains("recoveryOS bundle"), "{error}");
        assert!(error.contains("--uninstall"), "{error}");
        let error = rerun(&f, |c| c.status = true).unwrap_err().to_string();
        assert!(error.contains("no longer reads"), "{error}");
        let dry = uninstall(&environment(&f.host), &f.esp, true).unwrap();
        assert!(dry.contains("keep     install \"macOS\""), "{dry}");
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert_eq!(snapshot(&f.esp), before);

        // Schema 8, which kept the data partition's bundles, install medium
        // and translation store under `EFI/stela`: refused, and uninstalled
        // from where it wrote them.
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        let volume = stela_volume(&f);
        let before = (snapshot(&f.esp), snapshot(&volume));
        efi::add_mount(&f.esp, &f.efi, None, Some("--system\n")).unwrap();
        let old = volume.join("EFI/stela");
        let build = old.join("boot/STELA1");
        bundle::tests::write(
            &build.join("restore-0000000000000001"),
            bundle::Generation::FIRST,
            b"old",
        )
        .unwrap();
        for (directory, file) in [("install/STELA1", "payload.json"), ("store", "store.cfg")] {
            fs::create_dir_all(old.join(directory)).unwrap();
            fs::write(old.join(directory).join(file), b"x").unwrap();
        }
        let mut install = serde_json::to_value(&disk).unwrap();
        install["name"] = "macOS".into();
        install["ecid"] = "0x1".into();
        let record = serde_json::json!({
            "schema_version": 8,
            "kind": RECORD_KIND,
            "build": "STELA1",
            "model": "Mac14,3",
            "esp": f.esp,
            "volume": volume,
            "bundle_directory": build,
            "created_directories": [build, old.join("boot")],
            "options": "--system\n",
            "complete": true,
            "builds": ["STELA1"],
            "installs": [install],
            "bundles": [
                {"build": "STELA1", "ecid": "0x1", "schema": 1, "manifest_sha256": "",
                 "personalized": true},
            ],
            "media": [
                {"build": "STELA1", "volume": volume, "partition_guid": STELA_GUID,
                 "manifest_sha256": ""},
            ],
            "translations": {"volume": volume, "pack_bytes": translations::MIN_PACK_BYTES},
        });
        stela_runtime::write_json(&f.esp.join(RECORD), &record).unwrap();
        let error = read_record(&environment(&f.host), &f.esp)
            .unwrap_err()
            .to_string();
        assert!(error.contains("under EFI/"), "{error}");
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert_eq!((snapshot(&f.esp), snapshot(&volume)), before);
        assert!(!old.join("boot").exists());
    }

    const REGION: &str = "disk1s2";
    const NOR: &str = "disk1s3";
    const REGION_GUID: &str = "5E1A0000-0000-4000-8000-000000000001";
    const NOR_GUID: &str = "5E1A0000-0000-4000-8000-000000000002";
    const REGION2: &str = "disk2s2";
    const NOR2: &str = "disk2s3";
    const REGION2_GUID: &str = "5E1A0000-0000-4000-8000-000000000003";
    const NOR2_GUID: &str = "5E1A0000-0000-4000-8000-000000000004";
    const SERIAL: &str = "STELAPC01";
    const SERIAL2: &str = "STELAPC02";
    /// Bytes of each synthetic partition image: the probe reads and a NOR.
    const IMAGE_BYTES: usize = stela_runtime::pc::boot_log::PARTITION_BYTES as usize;
    const MIB: u64 = 1024 * 1024;

    /// Give `f`'s PC a disk (`disk1`, or `disk2` with `second`) with an
    /// Apple region and a NOR partition, backed by synthetic images that
    /// start with `region` and `nor`.
    fn add_disk(f: &mut Fixture, second: bool, region: &[u8], nor: &[u8]) {
        add_stela(f);
        let (disk, serial, partitions) = if second {
            (
                "disk2",
                SERIAL2,
                [(REGION2, REGION2_GUID, region), (NOR2, NOR2_GUID, nor)],
            )
        } else {
            (
                "disk1",
                SERIAL,
                [(REGION, REGION_GUID, region), (NOR, NOR_GUID, nor)],
            )
        };
        for ((identifier, guid, head), bytes) in partitions.into_iter().zip([100 * GIB, 256 * MIB])
        {
            let path = f._dir.path().join(format!("{identifier}.img"));
            let mut image = vec![0u8; IMAGE_BYTES];
            image[..head.len()].copy_from_slice(head);
            fs::write(&path, image).unwrap();
            let info = PartitionInfo {
                identifier: identifier.into(),
                disk: disk.into(),
                guid: guid.to_ascii_lowercase(),
                bytes,
                content: "Apple_APFS".into(),
                mount: None,
                container: None,
            };
            f.host.partitions.insert(identifier.into(), (info, path));
        }
        f.host.serials.insert(disk.into(), serial.into());
    }

    fn add_installed_disk(f: &mut Fixture, region: &[u8], nor: &[u8]) {
        add_disk(f, false, region, nor);
    }

    fn installed_command(f: &Fixture) -> Setup {
        let mut command = command(f, &f.esp);
        command.target = Some(REGION.into());
        command.nor = Some(NOR.into());
        command.tss = true;
        command
    }

    /// The USB's FAT32 data partition, which holds the install medium.
    const STELA_PARTITION: &str = "disk5s3";
    const STELA_GUID: &str = "5E1A0000-0000-4000-8000-0000000000aa";

    fn stela_volume(f: &Fixture) -> PathBuf {
        f._dir.path().join("STELA")
    }

    /// Give the USB its FAT32 data partition, once.
    fn add_stela(f: &mut Fixture) {
        let volume = stela_volume(f);
        if volume.exists() {
            return;
        }
        fs::create_dir_all(&volume).unwrap();
        f.host
            .volumes
            .insert(volume.clone(), (FileSystem::Fat, 100 * GIB, Some("disk5")));
        let usb = f
            .host
            .disks
            .iter_mut()
            .find(|d| d.identifier == "disk5")
            .unwrap();
        usb.partitions.push(Partition {
            identifier: STELA_PARTITION.into(),
            content: "Microsoft Basic Data".into(),
            mount: Some(volume.clone()),
        });
        let info = PartitionInfo {
            identifier: STELA_PARTITION.into(),
            disk: "disk5".into(),
            guid: STELA_GUID.into(),
            bytes: 100 * GIB,
            content: "Microsoft Basic Data".into(),
            mount: Some(volume.clone()),
            container: None,
        };
        let image = f._dir.path().join("stela-partition.img");
        f.host
            .partitions
            .insert(STELA_PARTITION.into(), (info, image));
    }

    fn partition_bytes(f: &Fixture, identifier: &str) -> Vec<u8> {
        fs::read(f.host.image(identifier).unwrap()).unwrap()
    }

    fn nvram_of(f: &Fixture, nor: &str) -> Variables {
        let bytes =
            partition_bytes(f, nor)[..stela_runtime::machine::apple::nor::CAPACITY].to_vec();
        let image = stela_runtime::machine::apple::nor::Image::from_bytes(bytes).unwrap();
        Variables::parse(image.bank(image.current_bank().unwrap()).unwrap()).unwrap()
    }

    fn nvram(f: &Fixture) -> Variables {
        nvram_of(f, NOR)
    }

    /// Give the USB an unmounted raw partition, as the Mac's internal SSD.
    fn add_stick_ssd(f: &mut Fixture, identifier: &str, guid: &str) {
        add_stela(f);
        let usb = f
            .host
            .disks
            .iter_mut()
            .find(|d| d.identifier == "disk5")
            .unwrap();
        usb.partitions.push(Partition {
            identifier: identifier.into(),
            content: "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF".into(),
            mount: None,
        });
        // Sparse, as large as the partition: the machine state is its tail.
        let path = f._dir.path().join(format!("{identifier}.img"));
        fs::File::create(&path).unwrap().set_len(100 * GIB).unwrap();
        let info = PartitionInfo {
            identifier: identifier.into(),
            disk: "disk5".into(),
            guid: guid.to_ascii_lowercase(),
            bytes: 100 * GIB,
            content: "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF".into(),
            mount: None,
            container: None,
        };
        f.host.partitions.insert(identifier.into(), (info, path));
        f.host.serials.insert("disk5".into(), "STICK01".into());
    }

    #[test]
    fn a_raw_partition_of_the_usb_is_the_macs_ssd_and_the_pc_disks_external() {
        let mut f = fixture(64 * GIB, false);
        add_stick_ssd(&mut f, "disk5s4", REGION_GUID);
        let mut no_tss = command(&f, &f.esp);
        no_tss.tss = false;
        let error = setup(&environment(&f.host), no_tss)
            .unwrap_err()
            .to_string();
        assert!(error.contains("needs --tss"), "{error}");
        let mut opted = command(&f, &f.esp);
        opted.tss = true;
        let report = setup(&environment(&f.host), opted).unwrap();
        assert!(report.contains("external drives"), "{report}");
        let record = record(&f);
        assert!(record.tss);
        let disk = &record.installs[0].disk;
        assert_eq!(disk.apple_region, "disk5s4");
        assert!(disk.external_disks);
        let options = fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap();
        assert!(
            options.contains(&format!("--storage STICK01:{REGION_GUID}")),
            "{options}"
        );
        assert!(options.contains("--external-disks"), "{options}");
        let choices = fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap();
        let install = choices
            .lines()
            .find(|line| line.starts_with(INSTALL_CHOICE))
            .unwrap();
        assert!(install.contains("--development-restore"), "{install}");
        assert!(install.contains("--tss"), "{install}");

        // Two raw partitions name no one internal SSD.
        let mut f = fixture(64 * GIB, false);
        add_stick_ssd(&mut f, "disk5s4", REGION_GUID);
        add_stick_ssd(&mut f, "disk5s5", REGION2_GUID);
        let mut opted = command(&f, &f.esp);
        opted.tss = true;
        let error = setup(&environment(&f.host), opted).unwrap_err().to_string();
        assert!(error.contains("several unmounted partitions"), "{error}");
    }

    #[test]
    fn a_whole_usb_disk_is_erased_first_and_an_internal_one_refused() {
        let f = fixture(64 * GIB, true);
        let whole = |usb: &str| f.host.whole_disk(Path::new(usb)).unwrap();
        assert_eq!(whole("/dev/disk5").as_deref(), Some("disk5"));
        assert_eq!(whole("disk0").as_deref(), Some("disk0"));
        let esp = f.esp.to_str().unwrap();
        for volume in [
            esp,
            "/Volumes/STELA",
            "disk5s1",
            "disk",
            "/dev/rdisk5",
            "disk12",
        ] {
            assert_eq!(whole(volume), None, "{volume}");
        }
        let mut dry = command(&f, Path::new("disk5"));
        dry.dry_run = true;
        let report = setup(&environment(&f.host), dry).unwrap();
        assert!(report.contains("would erase disk5"), "{report}");
        let mut internal = command(&f, Path::new("disk0"));
        internal.dry_run = true;
        let error = setup(&environment(&f.host), internal)
            .unwrap_err()
            .to_string();
        assert!(error.contains("internal disk"), "{error}");
        // An SD card is erased only with its model or size typed back.
        let mut host = FakeHost::new(f.host.volumes.clone(), f.host.disks.clone());
        host.disks.push(disk("disk6", &[]));
        let mut card = command(&f, Path::new("disk6"));
        card.dry_run = true;
        let error = setup(&environment(&host), card).unwrap_err().to_string();
        assert!(error.contains("--confirm-disk"), "{error}");
        for typed in ["Disk disk6", "137.4 GB"] {
            let mut card = command(&f, Path::new("disk6"));
            card.dry_run = true;
            card.confirm_disk = Some(typed.into());
            let report = setup(&environment(&host), card).unwrap();
            assert!(report.contains("would erase disk6"), "{report}");
        }
        // Without an image, the USB is left as it was: no erase is tried.
        let mut no_image = command(&f, Path::new("disk5"));
        no_image.ipsw = None;
        let error = setup(&environment(&f.host), no_image)
            .unwrap_err()
            .to_string();
        assert!(error.contains("pass --ipsw"), "{error}");
    }

    #[test]
    fn portable_usb_preparation_refuses_signing_failures_and_small_disks_before_erase() {
        let mut f = fixture(64 * GIB, true);
        let before = (snapshot(&f.esp), snapshot(&f.data));
        let mut opted = command(&f, Path::new("disk5"));
        opted.tss = true;
        let fail = |_: &Path, _: &str, _: Option<Ecid>, _: bool, _: &Path| {
            bail!("signing service unavailable")
        };
        let env = Environment {
            prepare_restore: &fail,
            ..environment(&f.host)
        };
        let error = setup(&env, opted).unwrap_err();
        assert!(format!("{error:#}").contains("signing service unavailable"));
        assert_eq!((snapshot(&f.esp), snapshot(&f.data)), before);

        f.host
            .disks
            .iter_mut()
            .find(|d| d.identifier == "disk5")
            .unwrap()
            .bytes = 1;
        let mut opted = command(&f, Path::new("disk5"));
        opted.tss = true;
        let error = setup(&environment(&f.host), opted).unwrap_err();
        assert!(
            error.to_string().contains("USB needs at least"),
            "{error:#}"
        );
        assert_eq!((snapshot(&f.esp), snapshot(&f.data)), before);
    }

    #[test]
    fn a_usb_replaced_while_preparing_is_refused_even_at_the_same_disk_number() {
        let mut f = fixture(64 * GIB, true);
        f.host.serials.insert("disk5".into(), "original".into());
        let selected = wizard::Usb::from_disk(&f.host.disks[1], &f.host);
        selected.verify(&f.host).unwrap();
        f.host.serials.insert("disk5".into(), "replacement".into());
        assert!(selected.verify(&f.host).is_err());
        f.host.serials.insert("disk5".into(), "original".into());
        f.host.disks[1].system = true;
        assert!(selected.verify(&f.host).is_err());
        f.host.disks.pop();
        assert!(selected.verify(&f.host).is_err());
    }

    #[test]
    fn a_signing_setup_without_a_target_installs_on_the_disk_chosen_in_stela_efi() {
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        // The authoring computer need not have the target's CPU features.
        f.host.cpu.entropy = false;
        let mut opted = command(&f, &f.esp);
        opted.tss = true;
        let report = setup(&environment(&f.host), opted).unwrap();
        assert!(report.contains("pick the PC disk"), "{report}");
        let record = record(&f);
        assert!(record.installs[0].disk.is_chosen());
        let medium = record.active_medium().unwrap();
        assert!(!medium.remote && medium.problems().is_empty(), "{medium:?}");
        let choices = fs::read_to_string(f.esp.join("EFI/stela/choices.cfg")).unwrap();
        let install = choices
            .lines()
            .find(|line| line.starts_with(INSTALL_CHOICE))
            .unwrap();
        assert!(install.contains("--storage @disk --nor @disk"), "{install}");
        assert!(install.contains(&medium.options()), "{install}");
        assert!(install.contains("--install-source"), "{install}");
        let mut joined = Vec::new();
        for index in 0.. {
            let piece = medium
                .directory()
                .join(stela_runtime::payload::piece_name(index));
            let Ok(bytes) = fs::read(piece) else { break };
            joined.extend(bytes);
        }
        assert_eq!(joined, fs::read(&f.ipsw).unwrap());
        let options = fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap();
        assert!(options.contains("--preboot @disk"), "{options}");
        // This computer never reaches the chosen disk's machine state.
        let error = rerun(&f, |c| c.reset_nvram = true).unwrap_err().to_string();
        assert!(error.contains("chosen in stela.efi"), "{error}");
    }

    fn rerun(f: &Fixture, configure: impl Fn(&mut Setup)) -> Result<String> {
        let mut command = command(f, &f.esp);
        command.ipsw = None;
        command.model = None;
        // Commands on an existing setup leave the opt-in as it is.
        command.tss = false;
        configure(&mut command);
        command.dispatch(&environment(&f.host))
    }

    #[test]
    fn another_file_system_on_a_target_is_unmounted_and_erased_now_and_on_repair() {
        let mut apfs = vec![0u8; 64];
        apfs[32..36].copy_from_slice(b"NXSB");
        let erased = |f: &Fixture| {
            fs::read(&f.host.partitions[REGION].1).unwrap()[..IMAGE_BYTES / 2]
                .iter()
                .all(|&byte| byte == 0)
        };
        // A mounted container is refused, and with --erase-target setup
        // unmounts and erases it, so the PC's OS stops mounting it.
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &apfs, &[]);
        f.host.partitions.get_mut(REGION).unwrap().0.container = Some("disk9".into());
        let error = setup(&environment(&f.host), installed_command(&f))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("--erase-target, which unmounts and erases"),
            "{error}"
        );
        let mut erase = installed_command(&f);
        erase.erase_target = true;
        setup(&environment(&f.host), erase).unwrap();
        assert_eq!(*f.host.unmounted.borrow(), [REGION]);
        assert!(erased(&f));
        // One an existing install's region gains is a problem --status
        // names and --repair erases with --erase-target.
        let path = f.host.partitions[REGION].1.clone();
        let mut image = fs::read(&path).unwrap();
        image[..apfs.len()].copy_from_slice(&apfs);
        fs::write(&path, image).unwrap();
        let error = rerun(&f, |c| c.status = true).unwrap_err().to_string();
        assert!(error.contains("holds another file system"), "{error}");
        let report = rerun(&f, |c| c.repair = true).unwrap();
        assert!(
            report.contains("pass --erase-target to erase it"),
            "{report}"
        );
        assert!(!erased(&f));
        rerun(&f, |c| {
            c.repair = true;
            c.erase_target = true;
        })
        .unwrap();
        assert!(erased(&f));
    }

    #[test]
    fn an_install_reads_the_image_from_the_usb_offline_or_streams_it_online() {
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        // Online: the USB holds the inventory alone, and the Install choice
        // names no partition to read the IPSW from.
        let mut online = installed_command(&f);
        online.install_image = Some(InstallImage::Online);
        let report = setup(&environment(&f.host), online).unwrap();
        assert!(report.contains("streaming the restore image"), "{report}");
        let written = record(&f);
        assert_eq!(written.install_image, Some(InstallImage::Online));
        let medium = written.active_medium().cloned().unwrap();
        assert!(medium.remote && medium.problems().is_empty(), "{medium:?}");
        let choices = fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap();
        let install = choices
            .lines()
            .find(|line| line.starts_with(INSTALL_CHOICE))
            .unwrap();
        assert!(install.contains(&medium.options()), "{install}");
        assert!(!install.contains("--install-source"), "{install}");
        // The choice is the setup's; other commands do not take it.
        let others: [fn(&mut Setup); 2] = [
            |c| c.install_image = Some(InstallImage::Offline),
            |c| {
                c.status = true;
                c.install_image = Some(InstallImage::Offline);
            },
        ];
        for configure in others {
            let error = rerun(&f, configure).unwrap_err().to_string();
            assert!(error.contains("--install-image goes with"), "{error}");
        }
        // Repair turns it offline: the IPSW in pieces on the USB.
        let switch = |image| {
            rerun(&f, |c| {
                c.repair = true;
                c.ipsw = Some(f.ipsw.clone());
                c.install_image = Some(image);
            })
            .unwrap();
            record(&f).active_medium().cloned().unwrap()
        };
        let offline = switch(InstallImage::Offline);
        assert!(
            !offline.remote && offline.problems().is_empty(),
            "{offline:?}"
        );
        let first_piece = offline
            .directory()
            .join(stela_runtime::payload::piece_name(0));
        assert!(first_piece.is_file());
        // Back online, the pieces go.
        let online = switch(InstallImage::Online);
        assert!(online.remote && online.problems().is_empty(), "{online:?}");
        assert!(!first_piece.exists());
    }

    #[test]
    fn an_offline_install_needs_the_system_image_a_recovery_archive_leaves_out() {
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        let recovery = f._dir.path().join("Recovery.ipsw");
        restore::payload::trim(
            fs::File::open(&f.ipsw).unwrap(),
            restore::payload::SYNTHETIC_MODEL,
            &recovery,
        )
        .unwrap();
        assert!(restore::payload::holds_system_image(&f.ipsw).unwrap());
        assert!(!restore::payload::holds_system_image(&recovery).unwrap());
        let mut offline = installed_command(&f);
        offline.ipsw = Some(recovery.clone());
        offline.install_image = Some(InstallImage::Offline);
        offline.dry_run = true;
        let error = format!("{:#}", setup(&environment(&f.host), offline).unwrap_err());
        assert!(error.contains("only the recovery members"), "{error}");
        // By default such an image streams the install instead.
        let mut default = installed_command(&f);
        default.ipsw = Some(recovery);
        setup(&environment(&f.host), default).unwrap();
        let record = record(&f);
        assert_eq!(record.install_image, None);
        assert!(record.active_medium().unwrap().remote);
    }

    #[test]
    fn an_installed_disk_boots_macos_or_recoveryos_and_keeps_its_partitions() {
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        let before = snapshot(&f.esp);
        let stela_before = snapshot(&stela_volume(&f));
        let disks = (partition_bytes(&f, REGION), partition_bytes(&f, NOR));

        // A local image does not remove the signing requirement. Refuse
        // before writing the USB or either target partition.
        let mut no_tss = installed_command(&f);
        no_tss.tss = false;
        let error = setup(&environment(&f.host), no_tss)
            .unwrap_err()
            .to_string();
        assert!(error.contains("needs --tss"), "{error}");
        assert!(error.contains("gs.apple.com"), "{error}");
        assert_eq!(snapshot(&f.esp), before);

        let mut dry = installed_command(&f);
        dry.dry_run = true;
        let plan = setup(&environment(&f.host), dry).unwrap();
        assert!(plan.contains("install medium "), "{plan}");
        assert!(plan.contains(STELA_GUID), "{plan}");
        assert!(plan.contains("restore        "), "{plan}");
        assert_eq!(snapshot(&stela_volume(&f)), stela_before);
        assert!(
            plan.contains("Apple region   disk1s2 (serial STELAPC01"),
            "{plan}"
        );
        assert!(plan.contains("is blank: install macOS onto it"), "{plan}");
        assert!(plan.contains("Dry run"), "{plan}");
        assert_eq!(snapshot(&f.esp), before);

        let mut tss = installed_command(&f);
        tss.tss = true;
        let report = setup(&environment(&f.host), tss).unwrap();
        assert!(report.contains("gs.apple.com"), "{report}");
        let record = record(&f);
        let ecid = record.installs[0].ecid.unwrap();
        // The restore boots under the ticket Apple personalized for it.
        assert!(
            record
                .restore_bundle(Kind::Restore, Some(ecid))
                .is_some_and(|b| b.personalized)
        );
        let region = format!("{SERIAL}:{REGION_GUID}");
        let line = format!(
            "--system --storage {region} --nor {SERIAL}:{NOR_GUID} --preboot {region} \
             --ecid {ecid} --tss"
        );
        assert_eq!(
            fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap(),
            format!("{line}\n")
        );
        // The startup choices hold the install and Install macOS, and open
        // on their own.
        let choices =
            Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
        assert_eq!(choices.timeout_seconds, CHOOSER_SECONDS);
        assert_eq!(choices.entries.len(), 2);
        assert_eq!(choices.entries[0].name, "macOS");
        assert_eq!(choices.entries[0].options, line);
        // stela.efi routes a disk without an installed system to the disk's
        // System Recovery, and refuses one that holds none.
        let mut selection = stela_loader::boot_selection::select(
            &Variables::parse(&stela_runtime::machine::apple::nor::nvram::empty_bank()).unwrap(),
        )
        .unwrap();
        selection.missing_boot_media();
        assert!(stela_loader::boot_selection::route(&line, Some(&selection)).is_err());
        selection.system_on_disk = true;
        let (routed, _) = stela_loader::boot_selection::route(&line, Some(&selection)).unwrap();
        assert!(routed.contains(&format!("--preboot {region}")), "{routed}");
        assert!(routed.ends_with("--system-recovery"), "{routed}");
        // Install macOS restores the install medium onto the disk
        // with the machine's restore bundle.
        let build = restore::payload::SYNTHETIC_BUILD;
        assert_eq!(choices.entries[1].name, INSTALL_CHOICE);
        assert_eq!(
            choices.entries[1].options,
            format!(
                "--system --storage {region} --nor {SERIAL}:{NOR_GUID} --bundle \
                 \\stela\\boot\\{build}\\{} --ecid {ecid} \
                 --install \\stela\\install\\{build}\\payload.json --install-source \
                 {STELA_GUID} --development-restore --tss",
                bundle::leaf_of(Kind::Restore, Some(ecid), current())
            )
        );
        let restore_bundle = record.restore_bundle(Kind::Restore, Some(ecid)).unwrap();
        assert!(
            bundle::verify(
                &restore_bundle.directory(&record.volume),
                &restore_bundle.manifest_sha256
            )
            .is_empty()
        );
        // The medium is the IPSW in pieces on the USB's FAT32 partition.
        let medium = record.active_medium().cloned().unwrap();
        assert_eq!(
            (medium.volume.as_path(), medium.partition_guid.as_str()),
            (stela_volume(&f).as_path(), STELA_GUID)
        );
        assert!(medium.problems().is_empty());
        let mut joined = Vec::new();
        for index in 0.. {
            let piece = medium
                .directory()
                .join(stela_runtime::payload::piece_name(index));
            let Ok(bytes) = fs::read(piece) else { break };
            joined.extend(bytes);
        }
        assert_eq!(joined, fs::read(&f.ipsw).unwrap());
        // Status finds a damaged piece by name.
        let first = medium
            .directory()
            .join(stela_runtime::payload::piece_name(0));
        let piece = fs::read(&first).unwrap();
        fs::write(&first, &piece[1..]).unwrap();
        let status = format!("{:#}", rerun(&f, |c| c.status = true).unwrap_err());
        assert!(status.contains("ipsw.000 holds"), "{status}");
        fs::write(&first, &piece).unwrap();
        // --verify-on-read is the engine's, on the Install choice alone.
        let mut verify = record.clone();
        verify.verify_on_read = true;
        let line = verify.install_line(&verify.installs[0]).unwrap();
        assert!(line.contains("--install-source"), "{line}");
        assert!(
            line.trim_end()
                .ends_with("--verify-on-read --development-restore --tss"),
            "{line}"
        );
        // Setup itself writes neither partition.
        assert_eq!(
            (partition_bytes(&f, REGION), partition_bytes(&f, NOR)),
            disks
        );
        // Turning the signing opt-in off removes the Install choice.
        let off = rerun(&f, |c| c.no_tss = true).unwrap();
        assert!(off.contains("TSS/FDR        off"), "{off}");
        assert!(
            !fs::read_to_string(f.esp.join("EFI/stela/stela.cfg"))
                .unwrap()
                .contains("--tss")
        );
        let choices =
            Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
        assert_eq!(choices.entries.len(), 1);
        // Its personalized restore bundle no longer serves the setup.
        let off = self::record(&f);
        assert_eq!(
            off.restore_bundle(Kind::Restore, off.installs[0].ecid),
            None
        );
        assert_eq!(off.missing_restore_bundles().len(), 1);

        // The engine profile turns on for every choice, and off again.
        let on = rerun(&f, |c| c.profile = true).unwrap();
        assert!(on.contains("profile        on"), "{on}");
        let config = || fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap();
        assert!(config().trim_end().ends_with("--profile"), "{}", config());
        let choices =
            Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
        assert!(
            choices
                .entries
                .iter()
                .all(|e| e.options.ends_with("--profile"))
        );
        rerun(&f, |c| c.no_profile = true).unwrap();
        assert!(!config().contains("--profile"));

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
        // A partition whose GUID is no longer the recorded one is not
        // written: its identifier now names another partition.
        let nor = partition_bytes(&f, NOR);
        f.host.partitions.get_mut(NOR).unwrap().0.guid = REGION2_GUID.into();
        let error = rerun(&f, |c| c.next_boot = Some(NextBoot::Recovery))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("not this install's NOR partition"),
            "{error}"
        );
        assert_eq!(partition_bytes(&f, NOR), nor);
        f.host.partitions.get_mut(NOR).unwrap().0.guid = NOR_GUID.to_ascii_lowercase();

        // Uninstall restores the USB and keeps the installed disk and NVRAM.
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert_eq!(snapshot(&f.esp), before);
        assert_eq!(snapshot(&stela_volume(&f)), stela_before);
        assert!(!stela_volume(&f).join("stela").exists());
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
        assert!(plan.contains("setup erases (--erase-target)"), "{plan}");
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
        // So does a SEP area after the NOR image that holds other bytes; the
        // flag blanks it and keeps the NOR image.
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        let capacity = stela_runtime::machine::apple::nor::CAPACITY;
        let path = f.host.partitions[NOR].1.clone();
        let mut image = fs::read(&path).unwrap();
        image[capacity..capacity + 8].copy_from_slice(b"not SEP!");
        fs::write(&path, image).unwrap();
        assert!(refusal(&f, &|_| {}).contains("--initialize-nor"));
        let mut initialize = installed_command(&f);
        initialize.initialize_nor = true;
        setup(&environment(&f.host), initialize).unwrap();
        let bytes = partition_bytes(&f, NOR);
        assert!(bytes[capacity..].iter().all(|&b| b == 0));
        assert!(bytes[..capacity].iter().all(|&b| b == 0));
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
        assert!(refusal(&f, &|_| {}).contains("APFS container disk4"));
        f.host.partitions.get_mut(REGION).unwrap().0.container = None;
        f.host.partitions.get_mut(NOR).unwrap().0.mount = Some("/Volumes/x".into());
        assert!(refusal(&f, &|_| {}).contains("is mounted"));
        f.host.partitions.get_mut(NOR).unwrap().0.mount = None;
        assert!(refusal(&f, &|c| c.nor = Some(REGION.into())).contains("two partitions"));
        f.host.cpu.entropy = false;
        assert!(refusal(&f, &|_| {}).contains("RDSEED"));
        f.host.cpu.entropy = true;
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

    /// A SEP roots record, as the SEP model provisions one.
    fn provision_sep(f: &Fixture, nor: &str) {
        let capacity = stela_runtime::machine::apple::nor::CAPACITY;
        let path = f.host.partitions[nor].1.clone();
        let mut image = fs::read(&path).unwrap();
        let mut record = vec![0u8; 8 + 2 * 32];
        record[..8].copy_from_slice(b"STSEPR01");
        record[8..].fill(0x42);
        use sha2::{Digest, Sha256};
        let sum = Sha256::digest(&record);
        record.extend_from_slice(&sum);
        image[capacity..capacity + record.len()].copy_from_slice(&record);
        fs::write(&path, image).unwrap();
        assert_eq!(
            stela_runtime::machine::apple::sep_state::blank(
                &partition_bytes(f, nor)
                    [capacity..capacity + stela_runtime::machine::apple::sep_state::ROOTS_BYTES]
            ),
            Ok(false)
        );
    }

    #[test]
    fn machine_state_of_an_earlier_machine_keeps_its_ecid() {
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        provision_sep(&f, NOR);
        let error = setup(&environment(&f.host), installed_command(&f))
            .unwrap_err()
            .to_string();
        assert!(error.contains("--ecid"), "{error}");
        let mut known = installed_command(&f);
        known.ecid = Some(Ecid(0x1234));
        setup(&environment(&f.host), known).unwrap();
        assert_eq!(record(&f).installs[0].ecid, Some(Ecid(0x1234)));
        assert!(bundle_of(&f, Some(Ecid(0x1234))).is_dir());
    }

    #[test]
    fn a_second_disk_is_a_second_machine_chosen_at_startup() {
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        add_disk(&mut f, true, &[], &[]);
        setup(&environment(&f.host), installed_command(&f)).unwrap();
        let record1 = record(&f);
        let first = record1.installs[0].ecid.unwrap();
        let kinds: Vec<Kind> = record1.bundles.iter().map(|b| b.kind).collect();
        assert_eq!(kinds, [Kind::Restore]);
        assert!(record1.active_medium().unwrap().problems().is_empty());
        let add = |target: &str, nor: &str, ipsw: bool, dry_run: bool| {
            rerun(&f, |c| {
                c.target = Some(target.into());
                c.nor = Some(nor.into());
                c.ipsw = ipsw.then(|| f.ipsw.clone());
                c.dry_run = dry_run;
                c.tss = true;
            })
        };
        // The second is a new machine and needs its own bundle, which it
        // restores with from the IPSW.
        let error = add(REGION2, NOR2, false, false).unwrap_err().to_string();
        assert!(error.contains("is installed from the macOS"), "{error}");
        let before = snapshot(&f.esp);
        assert!(add(REGION2, NOR2, true, true).unwrap().contains("Dry run"));
        assert_eq!(snapshot(&f.esp), before);
        add(REGION2, NOR2, true, false).unwrap();
        let record2 = record(&f);
        let second = record2.installs[1].ecid.unwrap();
        assert_ne!(second, first);
        assert_eq!(record2.installs[1].name, "macOS 2");
        assert_eq!(
            fs::read(bundle_of(&f, Some(second)).join("ramdisk.img")).unwrap(),
            vec![second.0 as u8 ^ 0xa5; 2048]
        );
        // The same partitions are not added twice.
        assert!(
            add(REGION2, NOR2, true, false)
                .unwrap_err()
                .to_string()
                .contains("already belongs")
        );
        let choices =
            || Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
        assert_eq!(choices().timeout_seconds, CHOOSER_SECONDS);
        let names: Vec<String> = choices().entries.into_iter().map(|e| e.name).collect();
        assert_eq!(
            names,
            [
                "macOS",
                "macOS - Install macOS",
                "macOS 2",
                "macOS 2 - Install macOS"
            ]
        );
        // Each install restores with its own machine's restore bundle.
        let restore2 = bundle::directory_of(
            Kind::Restore,
            &record2.volume,
            &record2.build,
            Some(second),
            record2.generation(),
        );
        assert!(choices().entries[3].options.contains(&format!(
            "--bundle \\stela\\boot\\{}\\restore-{}",
            record2.build,
            second.digits()
        )));
        // The default moves, and stela.cfg with it.
        rerun(&f, |c| c.default_install = Some("macOS 2".into())).unwrap();
        assert_eq!(choices().entries[0].name, "macOS 2");
        assert!(
            fs::read_to_string(f.esp.join("EFI/stela/stela.cfg"))
                .unwrap()
                .contains(&format!("{SERIAL2}:{NOR2_GUID}"))
        );
        // Each install's next boot is its own NVRAM.
        rerun(&f, |c| {
            c.next_boot = Some(NextBoot::Recovery);
            c.install = Some("macOS".into());
        })
        .unwrap();
        assert_eq!(
            stela_loader::boot_selection::select(&nvram_of(&f, NOR))
                .unwrap()
                .target,
            stela_loader::boot_selection::Target::SystemRecovery
        );
        assert!(partition_bytes(&f, NOR2).iter().all(|&b| b == 0));
        // A model other than the setup's is refused for an install.
        let mut f2 = rerun(&f, |c| {
            c.target = Some(REGION2.into());
            c.nor = Some(NOR2.into());
            c.model = Some("Mac14,2".into());
        })
        .unwrap_err()
        .to_string();
        assert!(f2.contains("same model"), "{f2}");
        // Removing an install keeps its partitions and drops its bundle.
        let nor2 = partition_bytes(&f, NOR2);
        f2 = rerun(&f, |c| c.remove_install = Some("macOS 2".into())).unwrap();
        assert!(f2.contains(&format!("--ecid {second}")), "{f2}");
        assert!(!bundle_of(&f, Some(second)).exists());
        assert!(!restore2.exists());
        assert_eq!(partition_bytes(&f, NOR2), nor2);
        // The list still opens on its own while the USB can install macOS.
        assert_eq!(choices().timeout_seconds, CHOOSER_SECONDS);
        assert_eq!(choices().entries[1].name, INSTALL_CHOICE);
        assert_eq!(record(&f).installs.len(), 1);
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert!(!f.esp.join("EFI/stela").exists());
    }

    #[test]
    fn same_stela_update_replenishes_only_the_cache_and_preserves_custom_options() {
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        let mut first = command(&f, &f.esp);
        first.translation_store_bytes = Some(translations::MIN_PACK_BYTES);
        setup(&environment(&f.host), first).unwrap();
        let store = record(&f).translations.unwrap();
        let spare = store.directory().join(translations::SPARE);
        fs::remove_file(&spare).unwrap();
        let pack = translations::tests::write_pack(&store.directory(), [4; 32], 100);
        let pack_bytes = fs::read(&pack).unwrap();
        let options = f.esp.join(efi::OPTIONS);
        let custom = b"--system --watch 0x1000,0x10\n";
        fs::write(&options, custom).unwrap();
        let before_record = fs::read(f.esp.join(RECORD)).unwrap();
        let before_efi = fs::read(f.esp.join(efi::LOADER)).unwrap();
        let update = |dry_run| {
            rerun(&f, |c| {
                c.update_stela = true;
                c.dry_run = dry_run;
            })
        };
        assert!(update(true).unwrap().contains("Dry run"));
        assert!(!spare.exists());
        assert_eq!(fs::read(&options).unwrap(), custom);
        assert!(update(false).unwrap().contains("prepare the cache"));
        assert_eq!(fs::metadata(&spare).unwrap().len(), store.pack_bytes);
        assert_eq!(fs::read(&pack).unwrap(), pack_bytes);
        assert_eq!(fs::read(&options).unwrap(), custom);
        assert_eq!(fs::read(f.esp.join(RECORD)).unwrap(), before_record);
        assert_eq!(fs::read(f.esp.join(efi::LOADER)).unwrap(), before_efi);
        // Retry after a partial allocation repairs the spare without an update.
        fs::write(&spare, [0; 64]).unwrap();
        fs::remove_file(store.directory().join(translations::CONFIG)).unwrap();
        update(false).unwrap();
        assert!(store.config_intact() && store.spare_ready());
        assert_eq!(fs::read(&pack).unwrap(), pack_bytes);
        assert_eq!(fs::read(&options).unwrap(), custom);
        assert_eq!(fs::read(f.esp.join(RECORD)).unwrap(), before_record);
        assert!(update(false).unwrap().contains("already installed"));
    }

    #[test]
    fn cache_spare_failure_blocks_efi_activation_and_update_or_rollback_can_retry() {
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        let mut first = command(&f, &f.esp);
        first.translation_store_bytes = Some(translations::MIN_PACK_BYTES);
        setup(&environment(&f.host), first).unwrap();
        let store = record(&f).translations.unwrap();
        let spare = store.directory().join(translations::SPARE);
        let pack = translations::tests::write_pack(&store.directory(), [4; 32], 100);
        let pack_bytes = fs::read(&pack).unwrap();
        let active = f.esp.join(efi::LOADER);
        let old_efi = fs::read(&active).unwrap();
        let config = fs::read(f.esp.join(efi::OPTIONS)).unwrap();
        let new = f._dir.path().join("new.efi");
        let new_efi = efi_image(b"stela-2");
        fs::write(&new, &new_efi).unwrap();
        let update = || {
            rerun(&f, |c| {
                c.update_stela = true;
                c.efi = Some(new.clone());
            })
        };
        fs::remove_file(&spare).unwrap();
        fs::create_dir(&spare).unwrap();
        assert!(update().unwrap_err().to_string().contains("cannot create"));
        assert_eq!(fs::read(&active).unwrap(), old_efi);
        assert_eq!(fs::read(f.esp.join(efi::OPTIONS)).unwrap(), config);
        assert!(record(&f).pending.is_some());
        assert_eq!(fs::read(&pack).unwrap(), pack_bytes);
        fs::remove_dir(&spare).unwrap();
        update().unwrap();
        assert_eq!(fs::read(&active).unwrap(), new_efi);
        assert!(record(&f).pending.is_none() && store.spare_ready());
        assert_eq!(fs::read(&pack).unwrap(), pack_bytes);
        // A rollback also prepares its cold-cache destination before activation.
        fs::remove_file(&spare).unwrap();
        fs::create_dir(&spare).unwrap();
        let before_rollback = fs::read(f.esp.join(RECORD)).unwrap();
        assert!(
            rerun(&f, |c| {
                c.rollback = true;
                c.dry_run = true;
            })
            .unwrap()
            .contains("Dry run")
        );
        assert_eq!(fs::read(f.esp.join(RECORD)).unwrap(), before_rollback);
        assert!(rerun(&f, |c| c.rollback = true).is_err());
        assert_eq!(fs::read(&active).unwrap(), new_efi);
        assert_eq!(fs::read(f.esp.join(RECORD)).unwrap(), before_rollback);
        fs::remove_dir(&spare).unwrap();
        rerun(&f, |c| c.rollback = true).unwrap();
        assert_eq!(fs::read(&active).unwrap(), old_efi);
        assert!(store.spare_ready());
        assert_eq!(fs::read(&pack).unwrap(), pack_bytes);
    }

    #[test]
    fn stela_update_and_rollback_with_disabled_cache_create_no_store() {
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        let mut first = command(&f, &f.esp);
        first.translation_store_bytes = Some(0);
        setup(&environment(&f.host), first).unwrap();
        assert!(record(&f).translations.is_none());
        let new = f._dir.path().join("new.efi");
        fs::write(&new, efi_image(b"stela-2")).unwrap();
        rerun(&f, |c| {
            c.update_stela = true;
            c.efi = Some(new.clone());
        })
        .unwrap();
        rerun(&f, |c| c.rollback = true).unwrap();
        assert!(!f.esp.join(translations::DIRECTORY).exists());
        assert!(record(&f).translations.is_none());
        assert_eq!(
            fs::read(f.esp.join(efi::LOADER)).unwrap(),
            fs::read(&f.efi).unwrap()
        );
    }

    #[test]
    fn stela_updates_keep_the_old_version_and_roll_back() {
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        let before = snapshot(&f.esp);
        setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
        let tool = f.esp.join(efi::LOADER);
        let config = fs::read(f.esp.join(efi::OPTIONS)).unwrap();
        let new = f._dir.path().join("new.efi");
        fs::write(&new, efi_image(b"stela-2")).unwrap();
        let update = |dry_run: bool| {
            rerun(&f, |c| {
                c.update_stela = true;
                c.efi = Some(new.clone());
                c.dry_run = dry_run;
            })
        };
        assert!(update(true).unwrap().contains("Dry run"));
        assert_eq!(fs::read(&tool).unwrap(), efi_image(b"stela"));
        // Packs of four translators and a damaged one: the update keeps the
        // three newest intact ones.
        let packs = record(&f).translations.unwrap().directory();
        assert!(packs.join(translations::CONFIG).is_file());
        let written: Vec<PathBuf> = (0..4u8)
            .map(|n| {
                let path = translations::tests::write_pack(&packs, [n; 32], 100);
                fs::File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_modified(
                        std::time::SystemTime::UNIX_EPOCH
                            + std::time::Duration::from_secs(1000 + u64::from(n)),
                    )
                    .unwrap();
                path
            })
            .collect();
        fs::write(packs.join(translations::pack_name(&[0xab; 32])), b"STLT").unwrap();
        let report = update(false).unwrap();
        assert!(
            report.contains("translates anew into its own pack"),
            "{report}"
        );
        assert!(
            report.contains(&written[0].display().to_string()),
            "{report}"
        );
        assert!(!written[0].exists() && written[1..].iter().all(|path| path.exists()));
        assert_eq!(
            fs::read_dir(&packs).unwrap().count(),
            5,
            "store.cfg, three packs and the spare"
        );
        assert!(packs.join(translations::SPARE).exists());
        assert_eq!(fs::read(&tool).unwrap(), efi_image(b"stela-2"));
        // Only the loader changed: stela.cfg stays.
        assert_eq!(fs::read(f.esp.join(efi::OPTIONS)).unwrap(), config);
        assert!(update(false).unwrap().contains("already installed"));
        let record1 = record(&f);
        assert_eq!(record1.stela_versions.len(), 2);
        assert_eq!(record1.history.len(), 1);
        rerun(&f, |c| c.rollback = true).unwrap();
        assert_eq!(fs::read(&tool).unwrap(), efi_image(b"stela"));
        assert!(
            rerun(&f, |c| c.rollback = true)
                .unwrap_err()
                .to_string()
                .contains("no update")
        );
        // A stela.efi of another interface is refused.
        fs::write(&new, b"MZ old build").unwrap();
        assert!(
            update(false)
                .unwrap_err()
                .to_string()
                .contains("not the stela.efi")
        );
        fs::write(&new, efi_image(b"stela-2")).unwrap();
        update(false).unwrap();
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert_eq!(snapshot(&f.esp), before);
    }

    #[test]
    fn a_stela_update_to_a_new_bundle_schema_prepares_new_bundles_and_rolls_back() {
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
        let old_schema = record(&f).bundle_schema;
        let next_schema = old_schema.checked_add(1).unwrap();
        let ecid = record(&f).installs[0].ecid;
        let old = bundle_of(&f, ecid);
        // The Install macOS choice names the restore bundle.
        let options = || fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap();
        let first = options();
        // A later stela and stela.efi read the next schema.
        let newer = mount_interface::Interface {
            bundle_schema: next_schema,
            ..mount_interface::CURRENT
        };
        let next_generation = bundle::Generation {
            schema: next_schema,
            ..current()
        };
        let prepare = move |_: &Path, _: &str, ecid: Option<Ecid>, _: bool, output: &Path| {
            bundle::tests::write(
                output,
                next_generation,
                &[ecid.map_or(0, |e| e.0 as u8) ^ 0xff; 64],
            )
        };
        let environment = Environment {
            prepare_restore: &prepare,
            interface: newer,
            ..environment(&f.host)
        };
        let new = f._dir.path().join("new.efi");
        let mut image = b"MZstela-3".to_vec();
        image.extend_from_slice(&mount_interface::marker(newer));
        fs::write(&new, image).unwrap();
        let update = |ipsw: bool| {
            let mut command = command(&f, &f.esp);
            command.ipsw = ipsw.then(|| f.ipsw.clone());
            command.model = None;
            command.update_stela = true;
            command.efi = Some(new.clone());
            command.dispatch(&environment)
        };
        let error = update(false).unwrap_err().to_string();
        assert!(error.contains(&format!("schema {next_schema}")), "{error}");
        assert!(error.contains("--ipsw"), "{error}");
        update(true).unwrap();
        let record2 = record(&f);
        assert_eq!(record2.bundle_schema, next_schema);
        let migrated = bundle_of(&f, ecid);
        let leaf = bundle::leaf_of(Kind::Restore, ecid, next_generation);
        assert!(
            migrated.ends_with(&leaf) && leaf.contains(&format!("-s{next_schema}")),
            "{leaf}"
        );
        assert!(
            options()
                .split_ascii_whitespace()
                .any(|word| word.ends_with(&leaf)),
            "{}",
            options()
        );
        // The old bundle stays for the rollback, which boots it again.
        assert!(old.join("bundle.json").is_file());
        rerun(&f, |c| c.rollback = true).unwrap();
        assert_eq!(options(), first);
        assert!(!migrated.exists());
        assert_eq!(record(&f).bundle_schema, old_schema);
    }

    #[test]
    fn a_stela_update_prepares_the_bundles_of_a_new_revision_and_rolls_back() {
        // A setup with an install, made before setups recorded revisions.
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        let (older, newer) = (preparers(0), preparers(1));
        let old = environment_at(&f.host, &older, 0);
        setup(&old, installed_command(&f)).unwrap();
        let path = f.esp.join(RECORD);
        let mut json: serde_json::Value = stela_runtime::read_json(&path).unwrap();
        json.as_object_mut().unwrap().remove("bundle_revision");
        for kept in json["bundles"].as_array_mut().unwrap() {
            kept.as_object_mut().unwrap().remove("revision");
        }
        stela_runtime::write_json(&path, &json).unwrap();
        let first = record(&f);
        assert_eq!(first.bundle_revision, 0);
        let ecid = first.installs[0].ecid;
        let options = || fs::read_to_string(f.esp.join(efi::OPTIONS)).unwrap();
        let choices = || fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap();
        let (first_options, first_choices) = (options(), choices());
        let directories = |revision: u32| -> Vec<PathBuf> {
            let generation = bundle::Generation {
                revision,
                ..current()
            };
            vec![bundle::directory_of(
                Kind::Restore,
                &first.volume,
                &first.build,
                ecid,
                generation,
            )]
        };
        // A later stela prepares revision 1, with the same stela.efi.
        let new = environment_at(&f.host, &newer, 1);
        let run = |configure: &dyn Fn(&mut Setup)| {
            let mut command = command(&f, &f.esp);
            command.ipsw = None;
            command.model = None;
            configure(&mut command);
            command.dispatch(&new)
        };
        let status = run(&|c| c.status = true).unwrap_err().to_string();
        assert!(
            status.contains("boot bundles are revision 0, and this stela prepares revision 1"),
            "{status}"
        );
        assert!(status.contains("--update-stela"), "{status}");
        // Other changes that prepare bundles wait for the update.
        let repair = run(&|c| {
            c.repair = true;
            c.ipsw = Some(f.ipsw.clone());
        });
        assert!(
            repair.unwrap_err().to_string().contains("--update-stela"),
            "the repair is refused"
        );
        let update = |ipsw: bool, dry_run: bool| {
            run(&|c| {
                c.update_stela = true;
                c.ipsw = ipsw.then(|| f.ipsw.clone());
                c.dry_run = dry_run;
            })
        };
        let refusal = update(false, false).unwrap_err().to_string();
        assert!(
            refusal.contains(&format!("schema {} revision 1", current().schema)),
            "{refusal}"
        );
        assert!(refusal.contains("--ipsw or --fetch"), "{refusal}");
        let before = (snapshot(&f.esp), snapshot(&stela_volume(&f)));
        let plan = update(true, true).unwrap();
        assert!(!plan.contains("is already installed"), "{plan}");
        for directory in directories(1) {
            assert!(plan.contains(&directory.display().to_string()), "{plan}");
        }
        assert_eq!((snapshot(&f.esp), snapshot(&stela_volume(&f))), before);
        update(true, false).unwrap();
        let updated = record(&f);
        assert_eq!(updated.bundle_revision, 1);
        assert_eq!(updated.stela_version, first.stela_version);
        for (old, new) in directories(0).iter().zip(directories(1)) {
            assert_eq!(bundle::generation(&new).unwrap().revision, 1);
            // The revision 0 bundles stay for the rollback.
            assert_eq!(bundle::generation(old).unwrap().revision, 0);
        }
        let [restore] = &directories(1)[..] else {
            unreachable!()
        };
        let leaf = restore.file_name().unwrap().to_string_lossy().into_owned();
        assert!(choices().contains(&leaf), "{}", choices());
        assert!(
            run(&|c| c.status = true)
                .unwrap()
                .contains("No problems found.")
        );
        // Bundles of the current revision are left alone: a new stela.efi
        // needs no restore image, and the same one is no update.
        assert!(update(false, false).unwrap().contains("already installed"));
        // Going back to the earlier stela boots its kept bundles, and undoing
        // that keeps them for the first update's rollback.
        let mut back = command(&f, &f.esp);
        (back.ipsw, back.model, back.update_stela) = (None, None, true);
        back.dispatch(&old).unwrap();
        assert_eq!(record(&f).bundle_revision, 0);
        run(&|c| c.rollback = true).unwrap();
        assert_eq!(record(&f).bundles, updated.bundles);
        let new_efi = f._dir.path().join("new.efi");
        fs::write(&new_efi, efi_image(b"stela-2")).unwrap();
        let report = run(&|c| {
            c.update_stela = true;
            c.efi = Some(new_efi.clone());
        })
        .unwrap();
        assert!(!report.contains("stay for rollback"), "{report}");
        assert_eq!(record(&f).bundles, updated.bundles);
        // Each rollback undoes one update: the second boots the revision 0
        // bundles again and removes the revision 1 ones.
        run(&|c| c.rollback = true).unwrap();
        assert_eq!(record(&f).bundles, updated.bundles);
        run(&|c| c.rollback = true).unwrap();
        let rolled = record(&f);
        assert_eq!(rolled.bundle_revision, 0);
        assert_eq!(rolled.stela_version, first.stela_version);
        assert!(
            rolled
                .stela_versions
                .contains(first.stela_version.as_ref().unwrap())
        );
        assert_eq!((options(), choices()), (first_options, first_choices));
        assert!(directories(1).iter().all(|d| !d.exists()));
        assert!(
            directories(0)
                .iter()
                .all(|d| d.join(bundle::MANIFEST).is_file())
        );
        let mut status = command(&f, &f.esp);
        (status.ipsw, status.model, status.status) = (None, None, true);
        assert!(
            status
                .dispatch(&old)
                .is_ok_and(|text| text.contains("No problems found.")),
            "the earlier stela finds its setup as it left it"
        );
    }

    #[test]
    fn stela_updates_remove_bundles_no_kept_version_boots() {
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        let preparers: Vec<_> = (0..4).map(preparers).collect();
        setup(
            &environment_at(&f.host, &preparers[0], 0),
            command(&f, &f.esp),
        )
        .unwrap();
        let ecid = record(&f).installs[0].ecid;
        let directory = |revision: u32| {
            let record = record(&f);
            let generation = bundle::Generation {
                revision,
                ..current()
            };
            bundle::directory_of(
                Kind::Restore,
                &record.volume,
                &record.build,
                ecid,
                generation,
            )
        };
        for revision in 1..4 {
            let image = f._dir.path().join(format!("stela-{revision}.efi"));
            fs::write(&image, efi_image(format!("stela-{revision}").as_bytes())).unwrap();
            let mut command = command(&f, &f.esp);
            command.model = None;
            command.update_stela = true;
            command.efi = Some(image);
            let environment = environment_at(&f.host, &preparers[revision as usize], revision);
            command.dispatch(&environment).unwrap();
        }
        // Four versions: the first is no longer kept, nor are its bundles.
        let record = record(&f);
        assert_eq!(record.stela_versions.len(), update::KEEP);
        assert_eq!(record.history.len(), update::KEEP - 1);
        assert!(!directory(0).exists());
        for revision in 1..4 {
            assert!(directory(revision).join(bundle::MANIFEST).is_file());
        }
        assert_eq!(record.bundles.len(), 3);
    }

    #[test]
    fn os_updates_add_restore_bundles_and_interrupted_updates_finish_or_roll_back() {
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        let before = snapshot(&f.esp);
        setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
        let ecid = record(&f).installs[0].ecid;
        let newer = f._dir.path().join("Newer.ipsw");
        restore::payload::synthetic_ipsw_of(&newer, "STELA2").unwrap();
        let update = |dry_run: bool| {
            rerun(&f, |c| {
                c.update_os = true;
                c.ipsw = Some(newer.clone());
                c.dry_run = dry_run;
            })
        };
        // The Install macOS choice names the build's restore bundle.
        let options = || fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap();
        let first = options();
        assert!(update(true).unwrap().contains("Dry run"));
        assert_eq!(options(), first);
        let report = update(false).unwrap();
        assert!(report.contains("choose Install macOS"), "{report}");
        assert!(report.contains("Update volume"), "{report}");
        assert!(options().contains("\\boot\\STELA2\\restore-"));
        let leaf = bundle::leaf_of(Kind::Restore, ecid, current());
        assert!(
            stela_volume(&f)
                .join(format!("stela/boot/STELA2/{leaf}/bundle.json"))
                .is_file()
        );
        // The old build stays for rollback.
        let old = bundle::directory_of(
            Kind::Restore,
            &stela_volume(&f),
            restore::payload::SYNTHETIC_BUILD,
            ecid,
            current(),
        );
        assert!(old.join("bundle.json").is_file());
        rerun(&f, |c| c.rollback = true).unwrap();
        assert_eq!(options(), first);
        assert!(!stela_volume(&f).join("stela/boot/STELA2").exists());

        // An update interrupted after it was recorded refuses other updates,
        // finishes when run again, and rolls back otherwise.
        let mut record1 = record(&f);
        record1.pending = Some(update::Change::Os {
            from: restore::payload::SYNTHETIC_BUILD.into(),
            to: "STELA2".into(),
        });
        write_record(&f.esp, &record1).unwrap();
        let partial = stela_volume(&f).join(format!("stela/boot/STELA2/{leaf}.partial"));
        fs::create_dir_all(&partial).unwrap();
        fs::write(partial.join("partial"), b"x").unwrap();
        let other = rerun(&f, |c| {
            c.update_stela = true;
            c.efi = Some(f.efi.clone());
        });
        assert!(other.unwrap_err().to_string().contains("interrupted"));
        update(false).unwrap();
        assert!(options().contains("STELA2"));
        assert!(!partial.exists());
        record1 = record(&f);
        record1.pending = record1.history.last().cloned();
        write_record(&f.esp, &record1).unwrap();
        let undo = rerun(&f, |c| c.rollback = true).unwrap();
        assert!(undo.contains("interrupted macOS update"), "{undo}");
        assert_eq!(options(), first);
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert_eq!(snapshot(&f.esp), before);
    }

    #[test]
    fn os_updates_of_an_install_write_the_new_medium_and_restore_it_keeping_the_data() {
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        setup(&environment(&f.host), installed_command(&f)).unwrap();
        let ecid = record(&f).installs[0].ecid.unwrap();
        assert_eq!(record(&f).media.len(), 1);
        assert!(
            rerun(&f, |c| c.status = true)
                .unwrap()
                .contains("No problems found.")
        );
        let disks = (partition_bytes(&f, REGION), partition_bytes(&f, NOR));
        let choices =
            || Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
        let names: Vec<String> = choices().entries.into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["macOS", INSTALL_CHOICE]);
        let first = restore::payload::SYNTHETIC_BUILD;
        let newer = f._dir.path().join("Newer.ipsw");
        restore::payload::synthetic_ipsw_of(&newer, "STELA2").unwrap();
        let update_to = |ipsw: &Path, dry_run: bool| {
            rerun(&f, |c| {
                c.update_os = true;
                c.ipsw = Some(ipsw.to_path_buf());
                c.dry_run = dry_run;
            })
        };
        let before = snapshot(&f.esp);
        let plan = update_to(&newer, true).unwrap();
        assert!(plan.contains("install medium"), "{plan}");
        assert!(plan.contains("keeps"), "{plan}");
        assert_eq!(snapshot(&f.esp), before);
        update_to(&newer, false).unwrap();
        let record1 = record(&f);
        assert_eq!(record1.build, "STELA2");
        let media: Vec<&str> = record1.media.iter().map(|m| m.build.as_str()).collect();
        assert_eq!(media, [first, "STELA2"], "the old medium is kept");
        assert!(record1.active_medium().unwrap().problems().is_empty());
        assert!(record1.restore_bundle(Kind::Restore, Some(ecid)).is_some());
        for entry in &choices().entries[1..2] {
            assert!(
                entry.options.contains("\\boot\\STELA2\\")
                    && entry.options.contains("\\install\\STELA2\\payload.json"),
                "{}",
                entry.options
            );
        }
        let status = rerun(&f, |c| c.status = true).unwrap();
        assert!(status.contains("kept medium"), "{status}");
        // The update writes no disk of the PC.
        assert_eq!(
            (partition_bytes(&f, REGION), partition_bytes(&f, NOR)),
            disks
        );
        // A rollback drops the new medium and restores the old choices.
        rerun(&f, |c| c.rollback = true).unwrap();
        let record2 = record(&f);
        assert_eq!(record2.build, first);
        let media: Vec<&str> = record2.media.iter().map(|m| m.build.as_str()).collect();
        assert_eq!(media, [first]);
        assert!(!medium::directory(&stela_volume(&f), "STELA2").exists());
        assert!(
            choices().entries[1]
                .options
                .contains(&format!("\\boot\\{first}\\"))
        );
        // Two updates on, only the newest two media are kept.
        update_to(&newer, false).unwrap();
        let newest = f._dir.path().join("Newest.ipsw");
        restore::payload::synthetic_ipsw_of(&newest, "STELA3").unwrap();
        update_to(&newest, false).unwrap();
        let media: Vec<String> = record(&f).media.into_iter().map(|m| m.build).collect();
        assert_eq!(media, ["STELA2", "STELA3"]);
        assert!(!medium::directory(&stela_volume(&f), first).exists());
        assert!(
            rerun(&f, |c| c.status = true)
                .unwrap()
                .contains("No problems found.")
        );
        // Rolling back past the pruned medium says how to write it again.
        rerun(&f, |c| c.rollback = true).unwrap();
        let undo = rerun(&f, |c| c.rollback = true).unwrap();
        assert!(undo.contains("no longer kept"), "{undo}");
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert!(!f.esp.join("EFI/stela").exists());
        assert!(!stela_volume(&f).join("stela/install").exists());
    }

    #[test]
    fn status_reports_everything_and_repair_puts_back_what_the_record_says() {
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        setup(&environment(&f.host), installed_command(&f)).unwrap();
        let status = || rerun(&f, |c| c.status = true);
        let report = status().unwrap();
        assert!(report.contains("No problems found."), "{report}");
        assert!(report.contains("Install \"macOS\" (default)"), "{report}");
        assert!(report.contains("ECID           0x"), "{report}");
        assert!(report.contains("no installed macOS yet"), "{report}");
        assert!(report.contains("NVRAM          blank"), "{report}");
        assert!(report.contains("SEP state      blank"), "{report}");
        assert!(report.contains("intact"), "{report}");
        // Status changes nothing.
        let before = snapshot(&f.esp);
        status().unwrap();
        assert_eq!(snapshot(&f.esp), before);

        // A damaged bundle, tool and stela.cfg are found ...
        let ecid = record(&f).installs[0].ecid;
        let ramdisk = bundle_of(&f, ecid).join("ramdisk.img");
        fs::write(&ramdisk, [0u8; 10]).unwrap();
        fs::write(f.esp.join(LOADER_PATH), b"MZ damaged").unwrap();
        fs::write(f.esp.join("EFI/stela/stela.cfg"), b"--system\n").unwrap();
        let error = status().unwrap_err().to_string();
        assert!(error.contains("problems:"), "{error}");
        assert!(error.contains("ramdisk.img"), "{error}");
        assert!(error.contains("not the version setup installed"), "{error}");
        assert!(error.contains("stela.cfg differs"), "{error}");
        // ... and the bundle needs the restore image to be repaired.
        let error = rerun(&f, |c| c.repair = true).unwrap_err().to_string();
        assert!(error.contains("--ipsw"), "{error}");
        let damaged = snapshot(&f.esp);
        rerun(&f, |c| {
            c.repair = true;
            c.ipsw = Some(f.ipsw.clone());
            c.dry_run = true;
        })
        .unwrap();
        assert_eq!(snapshot(&f.esp), damaged);
        rerun(&f, |c| {
            c.repair = true;
            c.ipsw = Some(f.ipsw.clone());
        })
        .unwrap();
        // The bundle is the machine's own again, with its ECID.
        assert_eq!(record(&f).installs[0].ecid, ecid);
        assert_eq!(
            fs::read(&ramdisk).unwrap(),
            vec![ecid.unwrap().0 as u8 ^ 0xa5; 2048]
        );
        assert_eq!(snapshot(&f.esp), before);
        status().unwrap();

        // A machine an older setup made without an ECID gets one.
        let mut old = record(&f);
        old.installs[0].ecid = None;
        write_record(&f.esp, &old).unwrap();
        let error = status().unwrap_err().to_string();
        assert!(error.contains("has no ECID"), "{error}");
        rerun(&f, |c| {
            c.repair = true;
            c.ipsw = Some(f.ipsw.clone());
        })
        .unwrap();
        let repaired = record(&f);
        let new = repaired.installs[0].ecid.unwrap();
        assert!(bundle_of(&f, Some(new)).join("bundle.json").is_file());
        status().unwrap();
    }

    #[test]
    fn no_maintenance_operation_writes_the_installed_disk_or_another_partition() {
        let mut f = fixture(64 * GIB, false);
        // An installed macOS: the Apple region holds the guest's own GPT,
        // and its containers' bytes after it stand for the user's data.
        let mut region = vec![0u8; 64 * 1024];
        region[512..520].copy_from_slice(b"EFI PART");
        for (n, byte) in region[1024..].iter_mut().enumerate() {
            *byte = (n % 251) as u8;
        }
        add_installed_disk(&mut f, &region, &[]);
        // A partition of another system on the same disk.
        let foreign = f._dir.path().join("disk1s4.img");
        fs::write(&foreign, vec![0xa5; IMAGE_BYTES]).unwrap();
        f.host.partitions.insert(
            "disk1s4".into(),
            (
                PartitionInfo {
                    identifier: "disk1s4".into(),
                    disk: "disk1".into(),
                    guid: "5e1a0000-0000-4000-8000-0000000000ff".into(),
                    bytes: 50 * GIB,
                    content: "Apple_HFS".into(),
                    mount: None,
                    container: None,
                },
                foreign.clone(),
            ),
        );
        let disks = || {
            (
                partition_bytes(&f, REGION),
                partition_bytes(&f, NOR),
                fs::read(&foreign).unwrap(),
                snapshot(&f.data),
            )
        };
        let before = disks();
        let report = setup(&environment(&f.host), installed_command(&f)).unwrap();
        assert!(report.contains("guest disk"), "{report}");
        assert_eq!(disks(), before, "setup");
        let new = f._dir.path().join("new.efi");
        fs::write(&new, efi_image(b"stela-2")).unwrap();
        let newer = f._dir.path().join("Newer.ipsw");
        restore::payload::synthetic_ipsw_of(&newer, "STELA2").unwrap();
        type Step<'a> = (&'a str, &'a dyn Fn(&mut Setup));
        let steps: [Step<'_>; 7] = [
            ("status", &|c| c.status = true),
            ("update-stela", &|c| {
                c.update_stela = true;
                c.efi = Some(new.clone());
            }),
            ("rollback", &|c| c.rollback = true),
            ("update-os", &|c| {
                c.update_os = true;
                c.ipsw = Some(newer.clone());
            }),
            ("rollback", &|c| c.rollback = true),
            ("repair", &|c| {
                c.repair = true;
                c.ipsw = Some(f.ipsw.clone());
            }),
            ("status", &|c| c.status = true),
        ];
        for (name, step) in steps {
            rerun(&f, step).unwrap_or_else(|error| panic!("{name}: {error:#}"));
            assert_eq!(disks(), before, "{name}");
        }
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert_eq!(disks(), before, "uninstall");
    }

    #[test]
    fn a_bundle_copy_stopped_between_its_renames_is_found_and_put_back() {
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        setup(&environment(&f.host), installed_command(&f)).unwrap();
        let before = snapshot(&f.esp);
        let directory = bundle_of(&f, record(&f).installs[0].ecid);
        // The stop came after the old bundle was set aside, before the new
        // copy was renamed into place.
        let (partial, previous) = bundle::siblings(&directory).unwrap();
        fs::rename(&directory, &previous).unwrap();
        fs::create_dir_all(&partial).unwrap();
        fs::write(partial.join("ramdisk.img"), b"half").unwrap();
        let error = rerun(&f, |c| c.status = true).unwrap_err().to_string();
        assert!(error.contains("set aside"), "{error}");
        assert!(error.contains("stopped part way"), "{error}");
        // A dry run says so and changes nothing, and needs no restore image.
        let interrupted = snapshot(&f.esp);
        let dry = rerun(&f, |c| {
            c.repair = true;
            c.dry_run = true;
        })
        .unwrap();
        assert!(dry.contains("would put right"), "{dry}");
        assert_eq!(snapshot(&f.esp), interrupted);
        let report = rerun(&f, |c| c.repair = true).unwrap();
        assert!(report.contains("put back"), "{report}");
        assert!(!partial.exists() && !previous.exists());
        assert_eq!(snapshot(&f.esp), before);
        rerun(&f, |c| c.status = true).unwrap();
    }

    #[test]
    fn nvram_resets_and_machine_state_backs_up_and_restores_to_its_own_machine() {
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        add_disk(&mut f, true, &[], &[]);
        setup(&environment(&f.host), installed_command(&f)).unwrap();
        provision_sep(&f, NOR);
        rerun(&f, |c| c.next_boot = Some(NextBoot::Recovery)).unwrap();
        let capacity = stela_runtime::machine::apple::nor::CAPACITY;
        let sep = |f: &Fixture| partition_bytes(f, NOR)[capacity..].to_vec();
        let sep_before = sep(&f);

        // A reset needs the partition named again, and keeps the SEP state.
        let error = rerun(&f, |c| c.reset_nvram = true).unwrap_err().to_string();
        assert!(error.contains("--nor"), "{error}");
        let error = rerun(&f, |c| {
            c.reset_nvram = true;
            c.nor = Some(NOR2.into());
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("not this install's NOR"), "{error}");
        let state = partition_bytes(&f, NOR);
        rerun(&f, |c| {
            c.reset_nvram = true;
            c.nor = Some(NOR.into());
            c.dry_run = true;
        })
        .unwrap();
        assert_eq!(partition_bytes(&f, NOR), state);
        // Back up before the reset.
        let file = f._dir.path().join("machine.state");
        rerun(&f, |c| c.backup_state = Some(file.clone())).unwrap();
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&file).unwrap().permissions())
                & 0o777,
            0o600
        );
        assert!(
            rerun(&f, |c| c.backup_state = Some(file.clone()))
                .unwrap_err()
                .to_string()
                .contains("exists")
        );
        rerun(&f, |c| {
            c.reset_nvram = true;
            c.nor = Some(NOR.into());
        })
        .unwrap();
        assert_eq!(
            stela_loader::boot_selection::select(&nvram(&f))
                .unwrap()
                .target,
            stela_loader::boot_selection::Target::MacOs { safe: false }
        );
        assert_eq!(sep(&f), sep_before);
        let status = rerun(&f, |c| c.status = true).unwrap();
        assert!(status.contains("SEP state      provisioned"), "{status}");
        assert!(status.contains("next boot      macOS"), "{status}");

        // The backup restores only to its own machine.
        let mut second = installed_command(&f);
        second.target = Some(REGION2.into());
        second.nor = Some(NOR2.into());
        second.install = Some("Other".into());
        second.model = None;
        second.dispatch(&environment(&f.host)).unwrap();
        let error = rerun(&f, |c| {
            c.restore_state = Some(file.clone());
            c.install = Some("Other".into());
            c.nor = Some(NOR2.into());
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("restored only to that machine"), "{error}");
        let damaged = f._dir.path().join("damaged.state");
        let mut bytes = fs::read(&file).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&damaged, bytes).unwrap();
        let error = rerun(&f, |c| {
            c.restore_state = Some(damaged.clone());
            c.nor = Some(NOR.into());
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("damaged"), "{error}");
        rerun(&f, |c| {
            c.restore_state = Some(file.clone());
            c.nor = Some(NOR.into());
        })
        .unwrap();
        assert_eq!(partition_bytes(&f, NOR), state);
        assert_eq!(
            stela_loader::boot_selection::select(&nvram(&f))
                .unwrap()
                .target,
            stela_loader::boot_selection::Target::SystemRecovery
        );
        // --nor alone names nothing to do.
        assert!(rerun(&f, |c| c.nor = Some(NOR.into())).is_err());
    }

    #[test]
    fn boot_log_prints_the_install_s_log_and_names_a_missing_one() {
        use stela_runtime::pc::boot_log::{LOG_BYTES, OFFSET, PARTITION_BYTES};
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        let plan = setup(&environment(&f.host), installed_command(&f)).unwrap();
        assert!(plan.contains("also keeps stela.efi's boot log"), "{plan}");
        let path = f.host.image(NOR).unwrap().to_path_buf();
        let mut bytes = fs::read(&path).unwrap();
        bytes.resize(PARTITION_BYTES as usize, 0);
        fs::write(&path, &bytes).unwrap();
        let error = format!("{:#}", rerun(&f, |c| c.boot_log = true).unwrap_err());
        assert!(error.contains("the log region is blank"), "{error}");

        let region = crate::boot_log::tests::region(&["NOR persistent fresh=true\n"]);
        bytes[OFFSET as usize..(OFFSET + LOG_BYTES) as usize].copy_from_slice(&region);
        fs::write(&path, &bytes).unwrap();
        let state = partition_bytes(&f, NOR);
        let text = rerun(&f, |c| c.boot_log = true).unwrap();
        assert!(
            text.contains("(disk1s3): Stela boot log: 1 boots, 47 bytes\n"),
            "{text}"
        );
        assert!(
            text.ends_with("=== STELA BOOT 1 ===\nNOR persistent fresh=true\n"),
            "{text}"
        );
        assert_eq!(partition_bytes(&f, NOR), state);
        // The USB's own log, which setup preallocates, comes first.
        let usb = crate::boot_log::tests::region(&["CHOICE 3 (Install macOS)\n"]);
        fs::write(f.esp.join(efi::BOOT_LOG), &usb).unwrap();
        let text = rerun(&f, |c| c.boot_log = true).unwrap();
        assert!(text.starts_with("Boot log on the USB ("), "{text}");
        assert!(text.contains("CHOICE 3 (Install macOS)\n"), "{text}");
        assert!(
            text.ends_with("=== STELA BOOT 1 ===\nNOR persistent fresh=true\n"),
            "{text}"
        );
        // The log is optional: a smaller partition is noted, not refused,
        // and the USB's log still prints.
        f.host.partitions.get_mut(NOR).unwrap().0.bytes = PARTITION_BYTES - 1;
        let text = rerun(&f, |c| c.boot_log = true).unwrap();
        assert!(text.starts_with("Boot log on the USB ("), "{text}");
        assert!(text.ends_with("without one\n"), "{text}");
        fs::write(f.esp.join(efi::BOOT_LOG), vec![0; LOG_BYTES as usize]).unwrap();
        let error = format!("{:#}", rerun(&f, |c| c.boot_log = true).unwrap_err());
        assert!(
            error.contains("has no boot log: the log region is blank\n"),
            "{error}"
        );
        assert!(error.ends_with("without one"), "{error}");
        let mut again = installed_command(&f);
        again.target = Some(REGION2.into());
        again.nor = Some(NOR2.into());
        add_disk(&mut f, true, &[], &[]);
        f.host.partitions.get_mut(NOR2).unwrap().0.bytes = PARTITION_BYTES - 1;
        again.install = Some("Other".into());
        again.model = None;
        again.dry_run = true;
        let plan = again.dispatch(&environment(&f.host)).unwrap();
        assert!(plan.contains("boots without a boot log"), "{plan}");
    }

    /// The Apple region of a one-partition install: 100 GiB, a sparse image.
    const SPLIT_BYTES: u64 = 100 * GIB;

    /// Give `f`'s PC a disk (`disk1`, or `disk2` with `second`) whose Apple
    /// region alone is set up, as a sparse image of the whole partition
    /// that starts with `head`.
    fn add_split_disk(f: &mut Fixture, second: bool, head: &[u8]) {
        add_stela(f);
        let (disk, serial, identifier, guid) = if second {
            ("disk2", SERIAL2, REGION2, REGION2_GUID)
        } else {
            ("disk1", SERIAL, REGION, REGION_GUID)
        };
        let path = f._dir.path().join(format!("{identifier}.img"));
        let file = fs::File::create(&path).unwrap();
        file.set_len(SPLIT_BYTES).unwrap();
        drop(file);
        let info = PartitionInfo {
            identifier: identifier.into(),
            disk: disk.into(),
            guid: guid.to_ascii_lowercase(),
            bytes: SPLIT_BYTES,
            content: "Apple_APFS".into(),
            mount: None,
            container: None,
        };
        f.host.partitions.insert(identifier.into(), (info, path));
        f.host.serials.insert(disk.into(), serial.into());
        f.host.write(identifier, 0, head).unwrap();
    }

    /// Where the region's machine state starts.
    fn tail() -> u64 {
        stela_runtime::pc::machine_state::split(SPLIT_BYTES)
            .unwrap()
            .state_offset()
    }

    fn split_command(f: &Fixture) -> Setup {
        let mut command = command(f, &f.esp);
        command.target = Some(REGION.into());
        command.tss = true;
        command
    }

    /// The region's machine state: its NOR image and SEP area.
    fn state_of(f: &Fixture, identifier: &str) -> Vec<u8> {
        let bytes = stela_runtime::machine::apple::nor::CAPACITY
            + stela_runtime::machine::apple::sep_state::BYTES as usize;
        f.host.read(identifier, tail(), bytes).unwrap()
    }

    fn tail_nvram(f: &Fixture) -> Variables {
        let capacity = stela_runtime::machine::apple::nor::CAPACITY;
        let image = stela_runtime::machine::apple::nor::Image::from_bytes(
            state_of(f, REGION)[..capacity].to_vec(),
        )
        .unwrap();
        Variables::parse(image.bank(image.current_bank().unwrap()).unwrap()).unwrap()
    }

    fn next_target(variables: &Variables) -> stela_loader::boot_selection::Target {
        stela_loader::boot_selection::select(variables)
            .unwrap()
            .target
    }

    /// A guest disk's primary GPT header at LBA 1 of 512-byte blocks, whose
    /// backup header is at `backup`.
    fn guest_gpt(backup: u64) -> Vec<u8> {
        let mut head = vec![0u8; 1024];
        head[512..520].copy_from_slice(b"EFI PART");
        head[512 + 32..512 + 40].copy_from_slice(&backup.to_le_bytes());
        head[512 + 48..512 + 56].copy_from_slice(&(backup - 33).to_le_bytes());
        head
    }

    #[test]
    fn one_partition_keeps_the_machine_state_in_its_tail_outside_the_guest() {
        use stela_runtime::machine::apple::nor::CAPACITY;
        let mut f = fixture(64 * GIB, false);
        add_split_disk(&mut f, false, &[]);
        let mut dry = split_command(&f);
        dry.dry_run = true;
        let plan = setup(&environment(&f.host), dry).unwrap();
        assert!(
            plan.contains(&format!(
                "machine state  the tail of disk1s2 from byte {:#x}",
                tail()
            )),
            "{plan}"
        );
        assert!(
            plan.contains(&format!(
                "recoveryOS sees the {:#x} bytes before it as the Mac's SSD",
                tail()
            )),
            "{plan}"
        );
        assert!(plan.contains("also keeps stela.efi's boot log"), "{plan}");
        assert!(!f.esp.join(RECORD).exists());

        setup(&environment(&f.host), split_command(&f)).unwrap();
        let record = record(&f);
        let disk = &record.installs[0].disk;
        assert_eq!(disk.machine_state_offset, Some(tail()));
        assert_eq!(
            (
                disk.nor.as_str(),
                disk.nor_serial.as_str(),
                disk.nor_guid.as_str()
            ),
            (REGION, SERIAL, REGION_GUID)
        );
        // The record keeps the choice, and the boot line names the region as
        // both the SSD and the machine state.
        let json = fs::read_to_string(f.esp.join(RECORD)).unwrap();
        assert!(
            json.contains(&format!("\"machine_state_offset\": {}", tail())),
            "{json}"
        );
        let ecid = record.installs[0].ecid.unwrap();
        let region = format!("{SERIAL}:{REGION_GUID}");
        let restore = format!(
            "\\stela\\boot\\{}\\{}",
            restore::payload::SYNTHETIC_BUILD,
            bundle::leaf_of(Kind::Restore, Some(ecid), current())
        );
        assert_eq!(
            fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap(),
            format!(
                "--system --storage {region} --nor {region} --preboot {region} --ecid {ecid} \
                 --tss\n"
            )
        );
        let choices =
            Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
        assert!(
            choices.entries[1].options.starts_with(&format!(
                "--system --storage {region} --nor {region} --bundle {restore} --ecid {ecid} "
            )),
            "{}",
            choices.entries[1].options
        );
        // Setup itself wrote neither the SSD nor the machine state.
        assert!(
            f.host
                .read(REGION, 0, 1 << 20)
                .unwrap()
                .iter()
                .all(|&b| b == 0)
        );
        assert!(state_of(&f, REGION).iter().all(|&b| b == 0));

        // NVRAM is the tail's: the next boot is chosen there.
        rerun(&f, |c| c.next_boot = Some(NextBoot::Recovery)).unwrap();
        assert_eq!(
            next_target(&tail_nvram(&f)),
            stela_loader::boot_selection::Target::SystemRecovery
        );
        assert!(
            f.host
                .read(REGION, 0, 1 << 20)
                .unwrap()
                .iter()
                .all(|&b| b == 0)
        );
        let status = rerun(&f, |c| c.status = true).unwrap();
        assert!(
            status.contains(&format!(
                "machine state  the tail of disk1s2 from byte {:#x}",
                tail()
            )),
            "{status}"
        );
        assert!(
            status.contains("next boot      System Recovery"),
            "{status}"
        );
        assert!(status.contains("SEP state      blank"), "{status}");
        assert!(status.contains("No problems found."), "{status}");

        // A provisioned SEP area in the tail backs up, survives a reset and
        // restores, each command addressing the tail.
        let mut roots = vec![0u8; 8 + 2 * 32];
        roots[..8].copy_from_slice(b"STSEPR01");
        roots[8..].fill(0x42);
        use sha2::{Digest, Sha256};
        let sum = Sha256::digest(&roots);
        roots.extend_from_slice(&sum);
        f.host
            .write(REGION, tail() + CAPACITY as u64, &roots)
            .unwrap();
        let state = state_of(&f, REGION);
        let file = f._dir.path().join("split.state");
        rerun(&f, |c| c.backup_state = Some(file.clone())).unwrap();
        let error = rerun(&f, |c| c.reset_nvram = true).unwrap_err().to_string();
        assert!(error.contains("Apple region, whose last bytes"), "{error}");
        let reset = rerun(&f, |c| {
            c.reset_nvram = true;
            c.nor = Some(REGION.into());
        })
        .unwrap();
        assert!(
            reset.contains(&format!("(disk1s2 from byte {:#x})", tail())),
            "{reset}"
        );
        assert_eq!(
            next_target(&tail_nvram(&f)),
            stela_loader::boot_selection::Target::MacOs { safe: false }
        );
        assert_eq!(state_of(&f, REGION)[CAPACITY..], state[CAPACITY..]);
        let status = rerun(&f, |c| c.status = true).unwrap();
        assert!(status.contains("SEP state      provisioned"), "{status}");
        rerun(&f, |c| {
            c.restore_state = Some(file.clone());
            c.nor = Some(REGION.into());
        })
        .unwrap();
        assert_eq!(state_of(&f, REGION), state);
        assert_eq!(
            next_target(&tail_nvram(&f)),
            stela_loader::boot_selection::Target::SystemRecovery
        );

        // The boot log is read from the tail too.
        let error = format!("{:#}", rerun(&f, |c| c.boot_log = true).unwrap_err());
        assert!(error.contains("the log region is blank"), "{error}");
        let log = crate::boot_log::tests::region(&["MACHINE STATE in the target's tail\n"]);
        f.host
            .write(REGION, tail() + stela_runtime::pc::boot_log::OFFSET, &log)
            .unwrap();
        let text = rerun(&f, |c| c.boot_log = true).unwrap();
        assert!(
            text.contains(&format!(
                "(disk1s2 from byte {:#x}): Stela boot log: 1 boots",
                tail()
            )),
            "{text}"
        );
        assert!(
            text.ends_with("=== STELA BOOT 1 ===\nMACHINE STATE in the target's tail\n"),
            "{text}"
        );
        assert!(
            f.host
                .read(REGION, 0, 1 << 20)
                .unwrap()
                .iter()
                .all(|&b| b == 0)
        );

        // A resized partition moves the tail: nothing is written there.
        f.host.partitions.get_mut(REGION).unwrap().0.bytes = SPLIT_BYTES - (1 << 20);
        let error = rerun(&f, |c| c.next_boot = Some(NextBoot::Macos))
            .unwrap_err()
            .to_string();
        assert!(error.contains("was resized"), "{error}");
        let error = rerun(&f, |c| c.status = true).unwrap_err().to_string();
        assert!(error.contains("was resized"), "{error}");
        f.host.partitions.get_mut(REGION).unwrap().0.bytes = SPLIT_BYTES;
        assert_eq!(state_of(&f, REGION), state);

        let removed = uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert!(
            removed.contains("install \"macOS\": disk1s2 keep macOS"),
            "{removed}"
        );
        assert_eq!(state_of(&f, REGION), state);
    }

    #[test]
    fn the_tail_is_checked_and_an_existing_guest_disk_is_never_converted() {
        let refusal = |f: &Fixture, configure: &dyn Fn(&mut Setup)| {
            let mut command = split_command(f);
            configure(&mut command);
            setup(&environment(&f.host), command)
                .unwrap_err()
                .to_string()
        };
        // A tail holding other bytes needs --initialize-nor, which writes a
        // fresh image there and leaves the SSD alone.
        let mut f = fixture(64 * GIB, false);
        add_split_disk(&mut f, false, &[]);
        f.host.write(REGION, tail(), b"not a NOR image").unwrap();
        let error = refusal(&f, &|_| {});
        assert!(error.contains("disk1s2's machine state"), "{error}");
        assert!(error.contains("--initialize-nor"), "{error}");
        let mut initialize = split_command(&f);
        initialize.initialize_nor = true;
        setup(&environment(&f.host), initialize).unwrap();
        assert_eq!(
            next_target(&tail_nvram(&f)),
            stela_loader::boot_selection::Target::MacOs { safe: false }
        );
        assert!(
            f.host
                .read(REGION, 0, 1 << 20)
                .unwrap()
                .iter()
                .all(|&b| b == 0)
        );

        // A guest disk that spans the whole partition is not converted; one
        // inside the SSD, laid out by an earlier one-partition install, is
        // kept.
        let blocks = SPLIT_BYTES / 512;
        let mut f = fixture(64 * GIB, false);
        add_split_disk(&mut f, false, &guest_gpt(blocks - 1));
        let error = refusal(&f, &|c| c.erase_target = true);
        assert!(error.contains("is not converted"), "{error}");
        assert!(error.contains("--nor"), "{error}");
        let mut f = fixture(64 * GIB, false);
        add_split_disk(&mut f, false, &guest_gpt(tail() / 512 - 1));
        let mut dry = split_command(&f);
        dry.dry_run = true;
        let plan = setup(&environment(&f.host), dry).unwrap();
        assert!(plan.contains("already holds a guest disk"), "{plan}");

        // The SSD before the tail must still hold 64 GB.
        let mut f = fixture(64 * GIB, false);
        add_split_disk(&mut f, false, &[]);
        f.host.partitions.get_mut(REGION).unwrap().0.bytes = 64_000_000_000;
        assert!(refusal(&f, &|_| {}).contains("before the machine state"));

        // An install with a machine-state partition of its own keeps it: its
        // Apple region is not added again as a one-partition install.
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        setup(&environment(&f.host), installed_command(&f)).unwrap();
        let before = snapshot(&f.esp);
        let error = rerun(&f, |c| {
            c.target = Some(REGION.into());
            c.install = Some("Again".into());
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("not converted"), "{error}");
        assert_eq!(snapshot(&f.esp), before);
        // Its separate partition still holds its machine state.
        let record = record(&f);
        assert_eq!(record.installs[0].disk.machine_state_offset, None);
        assert!(
            record
                .options
                .contains(&format!("--nor {SERIAL}:{NOR_GUID}")),
            "{}",
            record.options
        );

        // A further disk can be a one-partition install beside it.
        add_split_disk(&mut f, true, &[]);
        let added = rerun(&f, |c| {
            c.target = Some(REGION2.into());
            c.install = Some("Other".into());
            c.ipsw = Some(f.ipsw.clone());
        })
        .unwrap();
        assert!(
            added.contains("machine state  the tail of disk2s2"),
            "{added}"
        );
        let record = self::record(&f);
        assert_eq!(record.installs[1].disk.machine_state_offset, Some(tail()));
        let choices =
            Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
        let region2 = format!("{SERIAL2}:{REGION2_GUID}");
        assert!(
            choices.entries[2]
                .options
                .contains(&format!("--storage {region2} --nor {region2}")),
            "{}",
            choices.entries[2].options
        );
        // Its Install choice restores onto the region with the tail kept.
        assert_eq!(choices.entries[3].name, "Other - Install macOS");
        for entry in &choices.entries[3..4] {
            assert!(
                entry
                    .options
                    .contains(&format!("--storage {region2} --nor {region2} --bundle")),
                "{}",
                entry.options
            );
        }
    }
    #[test]
    fn observed_firmware_setup_action_requires_capability_and_preserves_dry_run() {
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
        let inventory = f._dir.path().join("observed-firmware.json");
        fs::write(&inventory, br#"{"schema":1,"complete":true,"requirements":[{"name":"rtl_nic/rtl8168e-3.fw","target":{"driver":"realtek","hardware":"10ec:8168","revision":"xid-2c8","board":null},"minimum_bytes":4}]}"#).unwrap();
        let before = snapshot(&f.esp);
        assert!(
            rerun(&f, |c| {
                c.host_firmware_requirements = Some(inventory.clone());
                c.dry_run = true;
            })
            .unwrap_err()
            .to_string()
            .contains("predates host firmware")
        );
        assert_eq!(snapshot(&f.esp), before);
        let capable = f._dir.path().join("firmware-capable.efi");
        let mut image = efi_image(b"observed-firmware-capable");
        let mut legacy_marker = stela_loader::host_firmware::MOUNT_CAPABILITY;
        legacy_marker[20] = 1;
        image.extend_from_slice(&legacy_marker);
        fs::write(&capable, image).unwrap();
        rerun(&f, |c| {
            c.update_stela = true;
            c.efi = Some(capable.clone());
        })
        .unwrap();
        let before = snapshot(&f.esp);
        let cache = f._dir.path().join("firmware-cache");
        let report = rerun(&f, |c| {
            c.host_firmware_requirements = Some(inventory.clone());
            c.host_firmware_cache = Some(cache.clone());
            c.dry_run = true;
        })
        .unwrap();
        assert!(report.contains("1 exact observed bindings"));
        assert!(report.contains("3872 bytes"));
        assert_eq!(snapshot(&f.esp), before);
        assert!(!cache.exists());
        assert!(
            rerun(&f, |c| {
                c.host_firmware_requirements = Some(inventory.clone());
                c.host_firmware = Some(f._dir.path().join("manual"));
            })
            .is_err()
        );
        assert_eq!(snapshot(&f.esp), before);
    }

    #[test]
    fn large_firmware_refuses_legacy_install_update_rollback_and_reinstall_before_writes() {
        use sha2::{Digest, Sha256};
        use stela_loader::host_firmware::{DIRECTORY, MOUNT_CAPABILITY, Package};
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
        let legacy = f._dir.path().join("firmware-v1.efi");
        let mut marker = MOUNT_CAPABILITY;
        marker[20] = 1;
        let mut image = efi_image(b"firmware-v1");
        image.extend_from_slice(&marker);
        fs::write(&legacy, image).unwrap();
        rerun(&f, |c| {
            c.update_stela = true;
            c.efi = Some(legacy.clone());
        })
        .unwrap();
        let source = f._dir.path().join("large-package");
        fs::create_dir(&source).unwrap();
        let bytes = vec![0x5a; 16 * 1024 * 1024 + 1];
        fs::write(source.join("data.bin"), &bytes).unwrap();
        fs::write(source.join("manifest.json"), serde_json::to_vec(&serde_json::json!({
            "schema":1,"images":[{"name":"fixture/large.bin","path":"data.bin",
            "length":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes)),
            "target":{"driver":"fixture","hardware":"synthetic","revision":"v1","board":null},
            "provenance":{"source":"synthetic","revision":"v1","member":"fixture/large.bin","license":"CC0-1.0"}}]
        })).unwrap()).unwrap();
        drop(bytes);
        let before = snapshot(&f.esp);
        for dry in [true, false] {
            let error = rerun(&f, |c| {
                c.host_firmware = Some(source.clone());
                c.dry_run = dry;
            })
            .unwrap_err();
            assert!(error.to_string().contains("image limit"), "{error:#}");
            assert_eq!(snapshot(&f.esp), before);
        }
        let current = f._dir.path().join("firmware-v2.efi");
        let mut image = efi_image(b"firmware-v2");
        image.extend_from_slice(&MOUNT_CAPABILITY);
        fs::write(&current, image).unwrap();
        rerun(&f, |c| {
            c.update_stela = true;
            c.efi = Some(current.clone());
        })
        .unwrap();
        rerun(&f, |c| c.host_firmware = Some(source.clone())).unwrap();
        let loaded = Package::read(&f.esp.join(DIRECTORY)).unwrap();
        assert_eq!(loaded.inventory(), (1, 16 * 1024 * 1024 + 1));
        assert!(loaded.check_mount(&fs::read(&current).unwrap()).is_ok());
        assert!(loaded.check_mount(&fs::read(&legacy).unwrap()).is_err());
        let before = snapshot(&f.esp);
        let error = rerun(&f, |c| c.rollback = true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot load installed host firmware"),
            "{error:#}"
        );
        assert_eq!(snapshot(&f.esp), before);
        let error = rerun(&f, |c| {
            c.update_stela = true;
            c.efi = Some(legacy.clone());
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot load installed host firmware"),
            "{error:#}"
        );
        assert_eq!(snapshot(&f.esp), before);

        // Uninstall retains independently managed host firmware. A new setup
        // must check it during planning, even when there is no setup record.
        let firmware_before = snapshot(&f.esp.join(DIRECTORY));
        rerun(&f, |c| c.uninstall = true).unwrap();
        assert!(!f.esp.join(RECORD).exists());
        assert_eq!(snapshot(&f.esp.join(DIRECTORY)), firmware_before);
        let before = snapshot(&f.esp);
        for candidate in [&legacy, &f.efi] {
            for dry in [true, false] {
                let mut reinstall = command(&f, &f.esp);
                reinstall.efi = Some(candidate.clone());
                reinstall.dry_run = dry;
                let error = setup(&environment(&f.host), reinstall).unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("cannot load installed host firmware"),
                    "{error:#}"
                );
                assert_eq!(snapshot(&f.esp), before);
            }
        }
        let mut reinstall = command(&f, &f.esp);
        reinstall.efi = Some(current.clone());
        reinstall.dry_run = true;
        setup(&environment(&f.host), reinstall).unwrap();
        assert_eq!(snapshot(&f.esp), before);
        let mut reinstall = command(&f, &f.esp);
        reinstall.efi = Some(current);
        setup(&environment(&f.host), reinstall).unwrap();
        assert!(record(&f).complete);
        assert_eq!(snapshot(&f.esp.join(DIRECTORY)), firmware_before);
    }

    #[test]
    fn host_firmware_action_validates_dry_run_and_publishes_separately_from_guest_bundles() {
        let mut f = fixture(64 * GIB, false);
        add_stela(&mut f);
        setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
        let source = f._dir.path().join("firmware-package");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("data.bin"), b"abc").unwrap();
        fs::write(source.join("manifest.json"), serde_json::to_vec(&serde_json::json!({
            "schema": 1, "images": [{"name":"Vendor/FW.bin", "path":"data.bin", "length":3,
            "sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "target":{"driver":"fixture","hardware":"synthetic","revision":"v1","board":null},
            "provenance":{"source":"synthetic","revision":"v1","member":"fixtures/abc.bin","license":"CC0-1.0"}}]
        })).unwrap()).unwrap();
        let old = snapshot(&f.esp);
        let mut unsupported = command(&f, &f.esp);
        unsupported.host_firmware = Some(source.clone());
        assert!(
            unsupported
                .dispatch(&environment(&f.host))
                .unwrap_err()
                .to_string()
                .contains("predates host firmware")
        );
        assert_eq!(snapshot(&f.esp), old);
        let aware = f._dir.path().join("firmware-aware.efi");
        let mut image = efi_image(b"firmware-aware");
        let mut legacy_marker = stela_loader::host_firmware::MOUNT_CAPABILITY;
        legacy_marker[20] = 1;
        image.extend_from_slice(&legacy_marker);
        fs::write(&aware, image).unwrap();
        rerun(&f, |c| {
            c.update_stela = true;
            c.efi = Some(aware.clone());
        })
        .unwrap();
        let before = snapshot(&f.esp);
        let mut dry = command(&f, &f.esp);
        dry.host_firmware = Some(source.clone());
        dry.dry_run = true;
        let report = dry.dispatch(&environment(&f.host)).unwrap();
        assert!(report.contains("1 verified resources, 3 bytes"));
        assert_eq!(snapshot(&f.esp), before);
        let mut write = command(&f, &f.esp);
        write.host_firmware = Some(source.clone());
        write.dispatch(&environment(&f.host)).unwrap();
        let published = f.esp.join(stela_loader::host_firmware::MANIFEST_PATH);
        assert!(published.is_file());
        for (path, bytes) in &before {
            assert_eq!(&fs::read(path).unwrap(), bytes);
        }
        let active = fs::read(&published).unwrap();
        let firmware_before = snapshot(&f.esp.join(stela_loader::host_firmware::DIRECTORY));
        let new_efi = f._dir.path().join("firmware-test-update.efi");
        let mut image = efi_image(b"firmware-test-update");
        image.extend_from_slice(&stela_loader::host_firmware::MOUNT_CAPABILITY);
        fs::write(&new_efi, image).unwrap();
        rerun(&f, |c| {
            c.update_stela = true;
            c.efi = Some(new_efi.clone());
        })
        .unwrap();
        assert_eq!(
            snapshot(&f.esp.join(stela_loader::host_firmware::DIRECTORY)),
            firmware_before
        );
        rerun(&f, |c| c.rollback = true).unwrap();
        let new_os = f._dir.path().join("firmware-test-update.ipsw");
        restore::payload::synthetic_ipsw_of(&new_os, "STELA2").unwrap();
        rerun(&f, |c| {
            c.update_os = true;
            c.ipsw = Some(new_os.clone());
        })
        .unwrap();
        assert_eq!(
            snapshot(&f.esp.join(stela_loader::host_firmware::DIRECTORY)),
            firmware_before
        );
        rerun(&f, |c| c.rollback = true).unwrap();
        rerun(&f, |c| c.repair = true).unwrap();
        assert_eq!(
            snapshot(&f.esp.join(stela_loader::host_firmware::DIRECTORY)),
            firmware_before
        );
        let before_downgrade = snapshot(&f.esp);
        assert!(
            rerun(&f, |c| {
                c.update_stela = true;
                c.efi = Some(f.efi.clone());
            })
            .unwrap_err()
            .to_string()
            .contains("cannot load installed host firmware")
        );
        assert_eq!(snapshot(&f.esp), before_downgrade);
        assert!(
            rerun(&f, |c| c.rollback = true)
                .unwrap_err()
                .to_string()
                .contains("cannot load installed host firmware")
        );
        assert_eq!(snapshot(&f.esp), before_downgrade);
        fs::write(source.join("data.bin"), b"abd").unwrap();
        let mut corrupt = command(&f, &f.esp);
        corrupt.host_firmware = Some(source);
        assert!(corrupt.dispatch(&environment(&f.host)).is_err());
        assert_eq!(fs::read(published).unwrap(), active);
    }
}
