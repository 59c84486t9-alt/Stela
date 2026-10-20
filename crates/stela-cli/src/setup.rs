//! `stela setup`: prepare a user's own OpenCore USB to install macOS 27 onto
//! a disk of the PC and boot it, and keep it working over the installed
//! system's life.
//!
//! With `--target`, macOS is installed offline from the full IPSW, in Apple
//! Configurator's DFU-restore role: setup writes the IPSW onto the USB's
//! FAT32 data partition as the install medium (`setup::medium`), prepares
//! each machine's restore bundle (`stela boot prepare --restore`), and adds
//! an Install macOS (Stela) startup choice that restores the medium onto
//! the target with Apple's stock restore options (`stela.efi --install`).
//! "macOS (Stela)" then boots the result. The restore personalizes the
//! recoveryOS LocalPolicy with Apple's signing server, so `--target` needs
//! `--tss`.
//!
//! One command checks the USB and the restore image without writing
//! anything, prepares the recoveryOS boot bundle (`stela boot prepare
//! --recovery`) on this computer, then copies it to a volume of the USB that
//! OpenCore can read, adds `stela.efi` to OpenCore's boot picker with a
//! `stela.cfg` that boots that bundle, and records what it wrote in
//! `EFI/stela/setup.json`. `--dry-run` stops after the checks; `--uninstall`
//! removes everything the record names.
//!
//! Each Stela machine has its own ECID (`setup::ecid`), drawn once, kept in
//! the record and given to every bundle prepared for it. With `--target`,
//! setup runs on the PC itself and also names the PC's own disk
//! (`setup::installed`): one empty partition becomes the Mac's internal SSD
//! and keeps the machine state (NVRAM, the SEP's state, the boot log) in its
//! last bytes, outside what the guest sees, or `--nor` names a partition of
//! its own for that state. The entry then boots the installed macOS from
//! that disk, or recoveryOS when NVRAM asks for it or the disk holds no
//! system yet, as a Mac does. Further disks become further installs of the same
//! setup (`setup::machines`), each its own machine, chosen at boot from
//! `stela.efi`'s startup choices. Setup writes no disk but the USB, except
//! fresh machine state with `--initialize-nor` and NVRAM with
//! `--next-boot`.
//!
//! An existing setup is updated in place (`setup::update`): `--update-stela`
//! installs a new `stela.efi`, `--update-os` a new macOS build's recoveryOS,
//! and `--rollback` undoes the last update or finishes undoing an
//! interrupted one. Every path takes `--dry-run`. A `stela.efi` whose mount
//! interface (`stela_loader::mount_interface`) differs from this `stela`'s is
//! refused.
mod bundle;
mod doctor;
mod ecid;
mod host;
mod installed;
mod machines;
mod medium;
mod state;
mod update;
mod usb;

pub(crate) use installed::NextBoot;

use crate::{boot, efi, restore};
use anyhow::{Context, Result, bail, ensure};
use bundle::Kind;
use clap::Args;
use ecid::Ecid;
use host::{FileSystem, Host};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};
use stela_loader::{
    boot_bundle::Options as BundleOptions,
    mount_interface::{self, Choice, Choices, Interface},
};

/// The pinned system target.
const PINNED_BUILD: &str = "26A434";
const PINNED_MODEL: &str = "Mac14,3";
const RECORD: &str = "EFI/stela/setup.json";
/// A margin so no volume is filled to its last byte.
pub(super) const MARGIN: u64 = 64 * 1024 * 1024;
/// The OpenCore tool `stela setup` installs.
pub(super) const TOOL_PATH: &str = efi::INSTALLED[0];
/// The startup choices beside `stela.cfg`.
const CHOICES_PATH: &str = "EFI/stela/choices.cfg";
/// The startup choices' timeout with several installs; with one, the list
/// opens only when a key is held.
const CHOOSER_SECONDS: u32 = 5;
/// The startup choice that installs macOS onto a setup's one install.
const INSTALL_CHOICE: &str = "Install macOS (Stela)";

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
    /// The Mac model Stela presents (Mac14,3 by default), such as Mac14,2
    /// (MacBook Air M2) or Mac14,9 (MacBook Pro M2 Pro); setup refuses one
    /// whose SoC the engine does not model yet (the M2, M2 Pro and M2 Max
    /// Macs are modeled). Every install of a setup presents the same model.
    #[arg(long)]
    model: Option<String>,
    /// The build `--fetch` downloads.
    #[arg(long, default_value = PINNED_BUILD, hide = true)]
    build: String,
    /// Show what would change, and change nothing.
    #[arg(long)]
    dry_run: bool,
    /// Remove everything a previous setup wrote to this USB.
    #[arg(long)]
    uninstall: bool,
    /// The PC's partition that becomes the Mac's internal SSD, such as
    /// disk1s2: macOS is installed onto it from recoveryOS and booted from it.
    /// Without --nor its last 8 MiB keep the machine state (NVRAM, the SEP's
    /// state and the boot log), which the guest never sees. On an existing
    /// setup, it adds another install.
    #[arg(long)]
    target: Option<String>,
    /// Optional: a separate PC partition (at least 1 MiB and 64 KiB) for the
    /// machine state instead of the target's tail: the Mac's NOR flash, where
    /// NVRAM persists, and the SEP's state; with at least 0x510000 bytes it
    /// also keeps stela.efi's boot log. Later commands name the install's
    /// machine-state partition again with it (the target itself when its
    /// tail holds the state).
    #[arg(long)]
    nor: Option<String>,
    /// The serial number of the disk holding `--target` and `--nor`, when
    /// this computer cannot read it.
    #[arg(long, requires = "target")]
    disk_serial: Option<String>,
    /// Use a `--target` that holds other data, which installing macOS onto
    /// it erases.
    #[arg(long, requires = "target")]
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
    /// Opt in to Apple's signing server: the restore host may send the
    /// machine's ECID and component hashes to gs.apple.com for the
    /// recoveryOS LocalPolicy. Off by default; on an existing setup it turns
    /// the opt-in on.
    #[arg(long, conflicts_with = "no_tss")]
    tss: bool,
    /// Turn the Apple signing server opt-in off on an existing setup.
    #[arg(long)]
    no_tss: bool,
    /// Have the install check the IPSW's recorded hashes only as the restore
    /// reads each block, instead of reading every member whole before the
    /// restore starts: faster, for QEMU test runs. It adds the engine's
    /// `--verify-on-read` to the Install macOS (Stela) choice.
    #[arg(long, requires = "target")]
    verify_on_read: bool,
    /// The USB's FAT32 data partition for the install medium (the full IPSW
    /// in pieces), when it has several; the first one by default.
    #[arg(long, requires = "target")]
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
    /// `--fetch` lets it prepare bundles of a new bundle schema.
    #[arg(long)]
    update_stela: bool,
    /// Add a new macOS build's recoveryOS (`--ipsw` or `--fetch`) to an
    /// existing setup for System Recovery and Reinstall macOS.
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
    /// the active build's recoveryOS bundles again.
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
}

#[derive(Args)]
pub(crate) struct InstallMedium {
    /// The macOS 27 restore image (IPSW); a download receipt beside it is
    /// checked.
    #[arg(long)]
    ipsw: PathBuf,
    /// The Mac model whose identities the inventory lists.
    #[arg(long, default_value = PINNED_MODEL)]
    model: String,
    /// The mounted FAT32 volume to write `EFI/stela/install/<build>` to.
    #[arg(long)]
    volume: PathBuf,
}

impl InstallMedium {
    pub(crate) fn run(self) -> Result<()> {
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
/// Schema 1 setups also wrote a restore payload and named a target disk;
/// schema 3 ones named at most one installed disk and no ECIDs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Record {
    schema_version: u32,
    kind: String,
    /// The active macOS build, whose recoveryOS boots.
    build: String,
    model: String,
    esp: PathBuf,
    #[serde(alias = "payload_volume")]
    volume: PathBuf,
    /// A schema 1 setup's restore payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload_directory: Option<PathBuf>,
    /// `EFI/stela/boot/<build>` of the active build.
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
    /// Schema 4: the ECID of the machine without an installed disk, which
    /// the first install takes over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ecid: Option<Ecid>,
    /// Schema 4: the PC disks macOS installs onto, each its own machine.
    #[serde(default)]
    installs: Vec<machines::Install>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_install: Option<String>,
    /// Schema 4: the boot-bundle schema the active `stela.efi` reads.
    #[serde(default = "first_schema")]
    bundle_schema: u32,
    /// Schema 4: every recoveryOS bundle setup wrote.
    #[serde(default)]
    bundles: Vec<bundle::Bundle>,
    /// Schema 4: the Apple signing server opt-in (`--tss`).
    #[serde(default)]
    tss: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chooser_timeout: Option<u32>,
    /// Schema 5: the install medium, the full IPSW on the USB's FAT32 data
    /// partition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    medium: Option<medium::Medium>,
    /// Schema 5: the Install choice checks the IPSW as it reads it
    /// (`--verify-on-read`).
    #[serde(default)]
    verify_on_read: bool,
}

fn first_schema() -> u32 {
    1
}

const RECORD_KIND: &str = "stela_setup";
const RECORD_SCHEMA: u32 = 5;

impl Record {
    /// Bring an older schema's record to this one: its installed disk
    /// becomes the first install, its bundles (one per build, without an
    /// ECID) are listed.
    fn migrate(&mut self) {
        if let Some(disk) = self.installed.take() {
            self.installs.push(machines::Install {
                name: machines::FIRST_NAME.into(),
                ecid: None,
                disk,
            });
        }
        if self.bundles.is_empty() {
            let mut builds = self.recovery_builds.clone();
            if !builds.contains(&self.build) {
                builds.push(self.build.clone());
            }
            for build in builds {
                if bundle::directory(&self.volume, &build, None, 1).is_dir() {
                    self.bundles.push(bundle::Bundle {
                        build,
                        ecid: None,
                        schema: 1,
                        manifest_sha256: String::new(),
                        kind: Kind::Recovery,
                    });
                }
            }
        }
    }

    /// The ECIDs of the machines whose bundles the active build needs: one
    /// per install, or the setup's own without one.
    fn machines(&self) -> Vec<Option<Ecid>> {
        if self.installs.is_empty() {
            return vec![self.ecid];
        }
        let mut machines: Vec<Option<Ecid>> = Vec::new();
        for install in &self.installs {
            if !machines.contains(&install.ecid) {
                machines.push(install.ecid);
            }
        }
        machines
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

    /// The recoveryOS bundle of `ecid`'s machine for the active build.
    fn recovery(&self, ecid: Option<Ecid>) -> String {
        bundle::firmware_path(&self.build, ecid, self.bundle_schema)
    }

    fn line(&self, text: String) -> String {
        let tss = if self.tss { " --tss" } else { "" };
        format!("{text}{tss}\n")
    }

    /// The option line that boots `install`, or the setup's own recoveryOS.
    fn boot_line(&self, install: Option<&machines::Install>) -> String {
        let dram_bytes = BundleOptions::default().dram_size;
        match install {
            Some(install) => self.line(install.disk.options(
                &self.recovery(install.ecid),
                dram_bytes,
                install.ecid,
            )),
            None => self.line(format!(
                "--system --bundle {} --ram-bytes {dram_bytes:#x}",
                self.recovery(self.ecid)
            )),
        }
    }

    /// `stela.cfg`: the default install, or recoveryOS alone.
    fn options_text(&self) -> String {
        self.boot_line(self.default())
    }

    /// The restore bundle of `ecid`'s machine for the active build.
    fn restore_bundle(&self, ecid: Option<Ecid>) -> Option<&bundle::Bundle> {
        self.bundles
            .iter()
            .find(|b| b.same_kind(Kind::Restore, &self.build, ecid, self.bundle_schema))
    }

    /// The active build's install medium.
    fn active_medium(&self) -> Option<&medium::Medium> {
        self.medium.as_ref().filter(|m| m.build == self.build)
    }

    /// The option line of `install`'s Install macOS (Stela) choice: its
    /// restore bundle, the install medium and its partitions. None without
    /// the active build's medium or the machine's restore bundle, or
    /// without the signing server opt-in the restore needs.
    fn install_line(&self, install: &machines::Install) -> Option<String> {
        let medium = self.active_medium()?;
        self.restore_bundle(install.ecid)?;
        if !self.tss {
            return None;
        }
        let restore =
            bundle::firmware_path_of(Kind::Restore, &self.build, install.ecid, self.bundle_schema);
        let base = install.disk.recovery_options(
            &restore,
            BundleOptions::default().dram_size,
            install.ecid,
        );
        let verify = if self.verify_on_read {
            " --verify-on-read"
        } else {
            ""
        };
        Some(self.line(format!("{base} {}{verify}", medium.options())))
    }

    /// The name of `install`'s Install macOS (Stela) choice.
    fn install_choice(&self, install: &machines::Install) -> String {
        if self.installs.len() == 1 {
            INSTALL_CHOICE.into()
        } else {
            format!("{} - Install macOS", install.name)
        }
    }

    /// The installs' machines that need a restore bundle of the active
    /// build: every install's while the setup has an install medium.
    fn missing_restore_bundles(&self) -> Vec<Option<Ecid>> {
        if self.active_medium().is_none() {
            return Vec::new();
        }
        let mut missing = Vec::new();
        for install in &self.installs {
            let present = self
                .restore_bundle(install.ecid)
                .is_some_and(|b| b.directory(&self.volume).join(bundle::MANIFEST).is_file());
            if !present && !missing.contains(&install.ecid) {
                missing.push(install.ecid);
            }
        }
        missing
    }

    /// The startup choices: each install, default first, its System
    /// Recovery and its Install macOS (Stela). None without an installed
    /// disk.
    fn choices(&self) -> Option<Choices> {
        let default = self.default()?;
        let dram_bytes = BundleOptions::default().dram_size;
        let mut entries = Vec::new();
        let others = self.installs.iter().filter(|i| i.name != default.name);
        for install in std::iter::once(default).chain(others) {
            entries.push(Choice {
                name: install.name.clone(),
                options: self.boot_line(Some(install)).trim().into(),
            });
            entries.push(Choice {
                name: format!("{} - System Recovery", install.name),
                options: self
                    .line(install.disk.recovery_options(
                        &self.recovery(install.ecid),
                        dram_bytes,
                        install.ecid,
                    ))
                    .trim()
                    .into(),
            });
            if let Some(line) = self.install_line(install) {
                entries.push(Choice {
                    name: self.install_choice(install),
                    options: line.trim().into(),
                });
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

    /// The bundle of `build` for `ecid`'s machine at the active schema.
    fn bundle(&self, build: &str, ecid: Option<Ecid>) -> Option<&bundle::Bundle> {
        self.bundles
            .iter()
            .find(|b| b.same(build, ecid, self.bundle_schema))
    }

    /// Bundle keys of `build` that the machines need and the record or the
    /// volume lacks.
    fn missing_bundles(&self, build: &str) -> Vec<Option<Ecid>> {
        self.machines()
            .into_iter()
            .filter(|&ecid| {
                self.bundle(build, ecid).is_none()
                    || !bundle::directory(&self.volume, build, ecid, self.bundle_schema)
                        .join(bundle::MANIFEST)
                        .is_file()
            })
            .collect()
    }

    /// Forget the bundles of machines the setup no longer has; returns
    /// them for [`remove_bundles`] once the record no longer names them.
    fn drop_stale_bundles(&mut self) -> Vec<bundle::Bundle> {
        let machines = self.machines();
        let (kept, stale) = self
            .bundles
            .drain(..)
            .partition(|b| machines.contains(&b.ecid));
        self.bundles = kept;
        stale
    }

    /// Every build directory a bundle or the history names.
    fn build_directories(&self) -> Vec<PathBuf> {
        let mut builds: Vec<&String> = self.recovery_builds.iter().collect();
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
    let tool = record.esp.join(TOOL_PATH);
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
    let mut record: Record = stela_runtime::read_json(&path)?;
    ensure!(
        record.kind == RECORD_KIND && (1..=RECORD_SCHEMA).contains(&record.schema_version),
        "{} is not a setup record this version understands; it may come from a newer stela",
        path.display()
    );
    ensure!(
        record.payload_directory.is_none(),
        "{} is a schema 1 setup, which installs from a restore payload; run `stela setup \
         --uninstall` and set up again",
        esp.display()
    );
    record.migrate();
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

/// Writes a boot bundle for an IPSW, model and machine into a directory.
type Prepare = dyn Fn(&Path, &str, Option<Ecid>, &Path) -> Result<()>;

/// An IPSW's restore inventory for a model.
type InventoryOf = dyn Fn(&Path, &str) -> Result<restore::payload::Inventory>;

/// Inputs that the command line fixes and tests replace.
struct Environment<'a> {
    host: &'a dyn Host,
    /// `stela boot prepare --recovery`; tests use synthetic IPSWs, which
    /// have no kernel, and write a stand-in.
    prepare: &'a Prepare,
    /// `stela boot prepare --restore`, likewise.
    prepare_restore: &'a Prepare,
    /// The install medium's inventory, with the public AEA keys fetched.
    inventory: &'a InventoryOf,
    /// The install medium's piece size (`payload::PIECE_BYTES`).
    piece_bytes: u64,
    /// The mount interface this `stela` writes for.
    interface: Interface,
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
            "{} is not the stela.efi this stela installs: {reason}. Use the stela and stela.efi \
             of one build (`cargo build --release` and `cargo xtask boot build --release`).",
            path.display()
        );
    }
    Ok(image)
}

/// Refuse to change a setup whose installed `stela.efi` reads another
/// interface than this `stela` writes; `--update-stela` replaces it first.
fn check_installed_efi(environment: &Environment<'_>, record: &Record) -> Result<()> {
    let tool = record.esp.join(TOOL_PATH);
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

/// A boot bundle prepared on this computer, not yet copied.
struct Prepared {
    build: String,
    ecid: Option<Ecid>,
    kind: Kind,
    directory: tempfile::TempDir,
    bytes: u64,
}

impl Prepared {
    fn path(&self) -> PathBuf {
        self.directory.path().join("recovery")
    }
}

/// Prepare `ipsw`'s recoveryOS for each machine of `ecids`; the image must
/// be `build`, when given. Returns the image's version and build too.
fn prepare_bundles(
    environment: &Environment<'_>,
    ipsw: &Path,
    model: &str,
    build: Option<&str>,
    ecids: &[Option<Ecid>],
) -> Result<(String, String, Vec<Prepared>)> {
    prepare_kind(environment, Kind::Recovery, ipsw, model, build, ecids)
}

/// [`prepare_bundles`] for bundles of `kind`.
fn prepare_kind(
    environment: &Environment<'_>,
    kind: Kind,
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
    let mut prepared = Vec::new();
    for &ecid in ecids {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("recovery");
        let prepare = match kind {
            Kind::Recovery => environment.prepare,
            Kind::Restore => environment.prepare_restore,
        };
        prepare(ipsw, model, ecid, &output)
            .with_context(|| format!("preparing the {} boot bundle", kind.label()))?;
        let schema = bundle::schema(&output)?;
        ensure!(
            schema == environment.interface.bundle_schema,
            "the prepared bundle has schema {schema}, not the {} this stela's stela.efi reads",
            environment.interface.bundle_schema
        );
        let bytes = bundle::bytes(&output)?;
        prepared.push(Prepared {
            build: found.clone(),
            ecid,
            kind,
            directory,
            bytes,
        });
    }
    Ok((product_version, found, prepared))
}

/// Copy prepared bundles to the record's volume and record them.
fn copy_bundles(record: &mut Record, prepared: &[Prepared]) -> Result<()> {
    for bundle in prepared {
        let schema = record.bundle_schema;
        let destination = bundle::directory_of(
            bundle.kind,
            &record.volume,
            &bundle.build,
            bundle.ecid,
            schema,
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
            .retain(|b| !b.same_kind(bundle.kind, &bundle.build, bundle.ecid, schema));
        record.bundles.push(bundle::Bundle {
            build: bundle.build.clone(),
            ecid: bundle.ecid,
            schema,
            manifest_sha256: digest,
            kind: bundle.kind,
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
    pub(crate) fn run(self) -> Result<()> {
        debug_assert_eq!(
            stela_loader::boot_bundle::SCHEMA_VERSION,
            mount_interface::CURRENT.bundle_schema
        );
        let environment = Environment {
            host: &host::System,
            prepare: &prepare_recovery,
            prepare_restore: &prepare_restore,
            inventory: &|ipsw, model| restore::payload::inventory(ipsw, model, true, None, None),
            piece_bytes: stela_runtime::payload::PIECE_BYTES,
            interface: mount_interface::CURRENT,
        };
        print!("{}", self.dispatch(&environment)?);
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
            || self.chooser_timeout.is_some()
    }

    /// At most one action per command.
    fn check_actions(&self) -> Result<()> {
        let actions = [
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
            self.nor.is_none()
                || self.target.is_some()
                || self.reset_nvram
                || self.backup_state.is_some()
                || self.restore_state.is_some()
                || self.boot_log,
            "--nor names a NOR partition for --target, --reset-nvram, --backup-state, \
             --restore-state or --boot-log"
        );
        Ok(())
    }

    fn dispatch(self, environment: &Environment<'_>) -> Result<String> {
        self.check_actions()?;
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
                None => default_efi_image()
                    .context("no stela.efi found beside stela or in the build tree; pass --efi")?,
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
            let record = read_record(environment, &self.usb)?;
            check_installed_efi(environment, &record)?;
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
        if configured && self.target.is_some() {
            return machines::add(environment, &self);
        }
        if configured && (self.configures() || (self.tss && self.ipsw.is_none() && !self.fetch)) {
            return machines::configure(environment, &self);
        }
        ensure!(
            !self.configures() && !self.no_tss,
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
    let image = restore::select(&images, Some(&command.build), Some(command.model()))?;
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
            "{} was downloaded from another catalog entry than Apple lists for macOS {} now;              move it away, or pass it with --ipsw",
            path.display(),
            image.build
        );
        eprintln!("Using the earlier download {}", path.display());
    } else {
        eprintln!("Downloading {} to {}", image.url, path.display());
        restore::download(&image, &path)?;
    }
    Ok(path)
}

/// `stela boot prepare --recovery` for the IPSW, model and machine into
/// `output`, then the engine's own board check of the prepared DeviceTree
/// (`machine::soc::board`), so a model the engine cannot run is refused
/// before the USB changes rather than when the PC boots it.
fn prepare_recovery(ipsw: &Path, model: &str, ecid: Option<Ecid>, output: &Path) -> Result<()> {
    let mut line: Vec<String> = [
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
    if let Some(ecid) = ecid {
        line.extend(["--ecid".into(), ecid.to_string()]);
    }
    boot::prepare(&line)?;
    let tree = fs::read(output.join("devicetree.adt"))?;
    stela_runtime::machine::soc::board(&tree)
        .map_err(|reason| anyhow::anyhow!("Stela cannot run {model} yet: {reason}"))?;
    Ok(())
}

/// `stela boot prepare --restore` for the IPSW, model and machine into
/// `output`: the restore bundle the Install macOS (Stela) choice boots.
fn prepare_restore(ipsw: &Path, model: &str, ecid: Option<Ecid>, output: &Path) -> Result<()> {
    let mut line: Vec<String> = [
        "--ipsw",
        ipsw.to_str().context("IPSW path is not UTF-8")?,
        "--model",
        model,
        "--restore",
        "--output",
        output.to_str().context("temporary path is not UTF-8")?,
    ]
    .map(str::to_owned)
    .into();
    if let Some(ecid) = ecid {
        line.extend(["--ecid".into(), ecid.to_string()]);
    }
    boot::prepare(&line)
}

/// The install medium setup writes.
struct MediumPlan {
    volume: PathBuf,
    guid: String,
    ipsw_bytes: u64,
    /// Bytes still to write, with the hash files and a margin.
    need: u64,
    expected: medium::Expected,
    /// Directories it creates, deepest first.
    created: Vec<PathBuf>,
}

/// What installing macOS needs besides the recoveryOS bundles: each
/// machine's restore bundle and, unless the USB holds the build's intact
/// medium, the install medium.
struct InstallPlan {
    restore: Vec<Prepared>,
    medium: Option<MediumPlan>,
}

/// Plan the install for `ecids`' machines of `record` from `ipsw`, and
/// check the space: `also` is what else setup writes to the bundle volume.
fn plan_install(
    environment: &Environment<'_>,
    record: &Record,
    install_volume: Option<&Path>,
    ipsw: &Path,
    ecids: &[Option<Ecid>],
    also: u64,
) -> Result<InstallPlan> {
    let host = environment.host;
    let restore = match ecids.is_empty() {
        true => Vec::new(),
        false => {
            prepare_kind(
                environment,
                Kind::Restore,
                ipsw,
                &record.model,
                Some(&record.build),
                ecids,
            )?
            .2
        }
    };
    let intact = record
        .active_medium()
        .is_some_and(|m| m.problems().is_empty());
    let medium = match intact {
        true => None,
        false => {
            let receipt = restore::receipt(ipsw)?;
            let (volume, guid) = medium::locate(host, &record.esp, install_volume)?;
            let ipsw_bytes = fs::metadata(ipsw)?.len();
            let need =
                medium::needed_bytes(&volume, &record.build, ipsw_bytes, environment.piece_bytes);
            let created = missing_directories(&volume, &medium::directory(&volume, &record.build));
            Some(MediumPlan {
                volume,
                guid,
                ipsw_bytes,
                need,
                expected: medium::Expected::of(receipt.as_ref()),
                created,
            })
        }
    };
    let restore_bytes: u64 = restore.iter().map(|p| p.bytes).sum();
    match &medium {
        Some(plan) if plan.volume == record.volume => {
            let need = plan.need + restore_bytes + also;
            let free = host.volume(&plan.volume)?.free_bytes;
            ensure!(
                free >= need,
                "{} has {:.1} GB free; the install medium and boot bundles need {:.1} GB (the \
                 macOS {} IPSW is {:.1} GB)",
                plan.volume.display(),
                free as f64 / 1e9,
                need as f64 / 1e9,
                record.build,
                plan.ipsw_bytes as f64 / 1e9
            );
        }
        Some(plan) => {
            medium::check_space(
                host,
                &plan.volume,
                &record.build,
                plan.ipsw_bytes,
                environment.piece_bytes,
            )?;
            check_space(host, &record.volume, &restore)?;
        }
        None => check_space(host, &record.volume, &restore)?,
    }
    Ok(InstallPlan { restore, medium })
}

/// The plan's lines, after their two spaces.
fn describe_install(record: &Record, plan: &InstallPlan, text: &mut String) -> Result<()> {
    for bundle in &plan.restore {
        writeln!(
            text,
            "  restore        {} ({:.1} GB)",
            bundle::directory_of(
                Kind::Restore,
                &record.volume,
                &bundle.build,
                bundle.ecid,
                record.bundle_schema
            )
            .display(),
            bundle.bytes as f64 / 1e9
        )?;
    }
    if let Some(medium) = &plan.medium {
        writeln!(
            text,
            "  install medium {}: the macOS {} IPSW in pieces of at most 4 GiB on the USB's FAT32 \
             partition {} ({:.1} GB still to write)",
            medium::directory(&medium.volume, &record.build).display(),
            record.build,
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
    let Some(plan) = plan.medium else {
        return Ok(());
    };
    // Recorded before the first piece, so an interrupted copy is undone.
    record.medium = Some(medium::Medium {
        build: record.build.clone(),
        volume: plan.volume.clone(),
        partition_guid: plan.guid.clone(),
        manifest_sha256: String::new(),
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
    eprintln!(
        "Writing the install medium to {}",
        medium::directory(&plan.volume, &record.build).display()
    );
    let inventory = (environment.inventory)(ipsw, &record.model)?;
    ensure!(
        inventory.manifest.product_build == record.build,
        "{} holds macOS build {}, not {}",
        ipsw.display(),
        inventory.manifest.product_build,
        record.build
    );
    let written = medium::write(
        &plan.volume,
        ipsw,
        inventory,
        &plan.expected,
        environment.piece_bytes,
    )?;
    if let Some(medium) = &mut record.medium {
        medium.manifest_sha256 = written.manifest_sha256;
    }
    write_record(&record.esp.clone(), record)
}

/// Why `--target` needs `--tss`.
const TSS_REQUIRED: &str = "installing macOS onto --target needs --tss: the restore \
    personalizes the recoveryOS LocalPolicy with Apple's signing server (gs.apple.com), which \
    receives this machine's ECID and its boot components' hashes. Add --tss to opt in.";

/// The checks' result: everything setup will write, and where.
struct Plan {
    record: Record,
    ipsw: PathBuf,
    product_version: String,
    /// The prepared bundle, in a host directory until setup copies it.
    prepared: Vec<Prepared>,
    efi_image: Vec<u8>,
    /// The PC's own disk, and the NOR image setup writes to it.
    installed: Option<installed::Checked>,
    /// With an installed disk: its restore bundle and the install medium.
    install: Option<InstallPlan>,
    notes: Vec<String>,
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
    ensure!(command.target.is_none() || command.tss, TSS_REQUIRED);
    let installed = match &command.target {
        Some(target) => {
            let usb_disk = host.volume(&esp)?.disk;
            Some(installed::check(
                host,
                &installed::Request {
                    apple_region: target,
                    nor: command.nor.as_deref(),
                    serial: command.disk_serial.as_deref(),
                    erase_target: command.erase_target,
                    initialize_nor: command.initialize_nor,
                    dram_bytes,
                    usb_disk: usb_disk.as_deref(),
                },
            )?)
        }
        None => None,
    };
    let mut notes = Vec::new();
    let ecid = match &installed {
        Some(checked) => machines::machine_ecid(
            command.ecid,
            None,
            checked.sep_provisioned,
            command.new_ecid,
            &mut notes,
        )?,
        None => command.ecid.map_or_else(Ecid::generate, Ok)?,
    };
    let efi_path = match &command.efi {
        Some(path) => path.clone(),
        None => default_efi_image().context(
            "no stela.efi found beside stela or in the build tree; build it with \
             `cargo xtask boot build --release`, or pass --efi",
        )?,
    };
    let efi_image = read_efi(environment, &efi_path)?;
    // The bundle is prepared on this computer before the USB changes, which
    // also measures it for the space check.
    let (product_version, build, prepared) =
        prepare_bundles(environment, &ipsw, command.model(), None, &[Some(ecid)])?;
    // With an installed disk, its restore bundle (about the size of the
    // recoveryOS one) goes on the same volume.
    let bundles = prepared[0].bytes * if command.target.is_some() { 2 } else { 1 };
    let volume = choose_volume(host, &esp, &command.usb, command.volume.as_deref(), bundles)?;
    let installs = installed
        .iter()
        .map(|checked| machines::Install {
            name: command
                .install
                .clone()
                .unwrap_or_else(|| machines::FIRST_NAME.into()),
            ecid: Some(ecid),
            disk: checked.disk.clone(),
        })
        .collect::<Vec<_>>();
    if let Some(install) = installs.first() {
        machines::check_name(&install.name)?;
    }
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
        recovery_builds: vec![build],
        pending: None,
        history: Vec::new(),
        ecid: Some(ecid),
        installs,
        default_install: None,
        bundle_schema: environment.interface.bundle_schema,
        bundles: Vec::new(),
        tss: command.tss,
        chooser_timeout: command.chooser_timeout,
        medium: None,
        verify_on_read: command.verify_on_read,
    };
    let install = match &installed {
        Some(_) => Some(plan_install(
            environment,
            &record,
            command.install_volume.as_deref(),
            &ipsw,
            &[Some(ecid)],
            prepared[0].bytes,
        )?),
        None => None,
    };
    record.options = record.options_text();
    record.choices_text()?;
    notes.push(format!(
        "recoveryOS runs in {} GiB of guest memory, so the PC needs more RAM than that free \
         when it boots the entry.",
        dram_bytes >> 30
    ));
    notes.push(match &installed {
        Some(checked) => format!(
            "The Install macOS (Stela) startup choice restores the install medium onto {} as \
             the Mac's internal SSD (ANS2); the restore host's live USB transport and the \
             complete SEP trust route are still being qualified, so an install does not finish \
             yet.",
            checked.disk.apple_region
        ),
        None => "Paused: Disk Utility and Reinstall macOS reach the PC's disks and keyboard \
                 only through PCIe/DART passthrough; the installer's personalization and the \
                 Secure Enclave are not modeled."
            .into(),
    });
    if command.tss {
        notes.push(tss_note());
    }
    if let Some(checked) = &installed {
        notes.extend(checked.notes.iter().cloned());
    }
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
    "TSS opt-in (--tss): the restore host may send this machine's ECID and its boot \
     components' hashes to Apple's signing server (gs.apple.com) for the recoveryOS \
     LocalPolicy; `stela setup --no-tss` turns it off."
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
    writeln!(text, "  OpenCore ESP   {}", record.esp.display())?;
    writeln!(
        text,
        "  ECID           {}",
        record.ecid.expect("a new setup has an ECID")
    )?;
    for prepared in &plan.prepared {
        writeln!(
            text,
            "  recoveryOS     {} ({:.1} GB)",
            bundle::directory(
                &record.volume,
                &prepared.build,
                prepared.ecid,
                record.bundle_schema
            )
            .display(),
            prepared.bytes as f64 / 1e9
        )?;
    }
    writeln!(
        text,
        "  OpenCore       adds the \"{}\" tool entry; keeps the old config.plist as {}",
        efi::NAME,
        record.esp.join("EFI/stela/config.plist.backup").display()
    )?;
    match (&plan.installed, record.installs.first()) {
        (Some(checked), Some(install)) => {
            let disk = &checked.disk;
            writeln!(
                text,
                "  stela.cfg      {}: boots macOS from {}, or recoveryOS when NVRAM asks or \
                 the disk holds no system",
                record.esp.join("EFI/stela/stela.cfg").display(),
                disk.apple_region
            )?;
            writeln!(
                text,
                "  choices.cfg    {}: \"{}\", its System Recovery and \"{INSTALL_CHOICE}\", \
                 listed for {CHOOSER_SECONDS} seconds at startup",
                record.esp.join(CHOICES_PATH).display(),
                install.name
            )?;
            if let Some(install) = &plan.install {
                describe_install(record, install, &mut text)?;
            }
            writeln!(
                text,
                "  Apple region   {} (serial {}, partition {})",
                disk.apple_region, disk.apple_region_serial, disk.apple_region_guid
            )?;
            writeln!(text, "  {}", state_line(disk))?;
            match checked.nor_image {
                Some(_) => writeln!(
                    text,
                    "  disks          this USB, and fresh machine state (NOR image or SEP area) \
                     on {}",
                    disk.state_description()
                )?,
                None => writeln!(text, "  disks          none are written but this USB")?,
            }
        }
        _ => {
            writeln!(
                text,
                "  stela.cfg      {}: boots recoveryOS",
                record.esp.join("EFI/stela/stela.cfg").display()
            )?;
            writeln!(text, "  disks          none are written but this USB")?;
        }
    }
    for note in &plan.notes {
        writeln!(text, "  note           {note}")?;
    }
    Ok(text)
}

/// The plan's line for an install's machine state, after its two spaces.
fn state_line(disk: &installed::InstalledDisk) -> String {
    let label = if disk.machine_state_offset.is_some() {
        "machine state"
    } else {
        "NOR"
    };
    format!("{label:<14} {}", disk.state_description())
}

fn setup(environment: &Environment<'_>, command: Setup) -> Result<String> {
    let ipsw = command.image()?;
    let plan = plan(environment, &command, ipsw)?;
    let mut report = describe(&plan)?;
    if command.dry_run {
        report.push_str("Dry run: nothing was changed.\n");
        return Ok(report);
    }
    apply(environment, plan)?;
    let start = match &command.target {
        Some(target) => format!(
            "choose \"{INSTALL_CHOICE}\" in Stela's startup choices to install macOS onto \
             {target}, then reboot and choose \"{}\" again, which boots the installed macOS \
             (or recoveryOS while {target} holds none, or when NVRAM asks)",
            efi::NAME
        ),
        _ => "stela.efi starts recoveryOS, where Disk Utility prepares a disk and Reinstall \
              macOS installs onto it, as on a Mac"
            .into(),
    };
    writeln!(
        report,
        "Done. Boot the PC from this USB and choose \"{}\" in OpenCore's picker: {start}. \
         Stela does not run recoveryOS to its window yet.\nCheck it with: stela setup --status \
         --usb {}\nUndo with: stela setup --uninstall --usb {}",
        efi::NAME,
        command.usb.display(),
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

fn apply(environment: &Environment<'_>, plan: Plan) -> Result<()> {
    let mut record = plan.record;
    let esp = record.esp.clone();
    // Recorded before the first write, so an interrupted setup can be undone.
    write_record(&esp, &record)?;
    copy_bundles(&mut record, &plan.prepared)?;
    write_record(&esp, &record)?;
    if let Some(install) = plan.install {
        apply_install(environment, &mut record, &plan.ipsw, install)?;
    }
    if let Some(checked) = &plan.installed
        && let Some(nor) = &checked.nor_image
    {
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
        let mut record = record.clone();
        record.migrate();
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
                    && directory.parent().is_some_and(
                        |p| p.ends_with("EFI/stela/boot") || p.ends_with("EFI/stela/images")
                    ),
                "the setup record names an unexpected directory {}",
                directory.display()
            );
            if directory.exists() && !removals.contains(&directory) {
                removals.push(directory);
            }
        }
        if let Some(medium) = &record.medium {
            let directory = medium.directory();
            ensure!(
                directory.starts_with(&medium.volume)
                    && directory
                        .parent()
                        .is_some_and(|p| p.ends_with("EFI/stela/install")),
                "the setup record names an unexpected install medium {}",
                directory.display()
            );
            if directory.exists() {
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
    for file in efi::INSTALLED.iter().chain([&CHOICES_PATH]) {
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
    for install in record.iter().flat_map(|r| {
        let mut r = r.clone();
        r.migrate();
        r.installs
    }) {
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
    pub(super) struct FakeHost {
        pub(super) volumes: BTreeMap<PathBuf, (FileSystem, u64, Option<&'static str>)>,
        pub(super) disks: Vec<Disk>,
        /// Partitions of the PC's disk, each backed by an image file.
        pub(super) partitions: BTreeMap<String, (PartitionInfo, PathBuf)>,
        pub(super) serials: BTreeMap<String, String>,
        pub(super) memory: u64,
        pub(super) cpu: Cpu,
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

    /// A `stela.efi` stand-in with this tree's mount interface.
    fn efi_image(tag: &[u8]) -> Vec<u8> {
        let mut image = b"MZ".to_vec();
        image.extend_from_slice(tag);
        image.extend_from_slice(&mount_interface::marker(mount_interface::CURRENT));
        image
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
        fs::write(&efi, efi_image(b"stela")).unwrap();
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
            model: Some(restore::payload::SYNTHETIC_MODEL.into()),
            build: PINNED_BUILD.into(),
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
            tss: false,
            no_tss: false,
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
        }
    }

    /// A stand-in for `boot prepare --recovery`: the synthetic IPSW has no
    /// kernel to prepare. The bundle's byte names the machine.
    fn fake_prepare(_: &Path, _: &str, ecid: Option<Ecid>, output: &Path) -> Result<()> {
        let byte = ecid.map_or(0x5a, |e| e.0 as u8);
        bundle::tests::write(output, 1, &[byte; 4096])
    }

    /// A stand-in for `boot prepare --restore`.
    fn fake_prepare_restore(_: &Path, _: &str, ecid: Option<Ecid>, output: &Path) -> Result<()> {
        let byte = ecid.map_or(0x5a, |e| e.0 as u8) ^ 0xa5;
        bundle::tests::write(output, 1, &[byte; 2048])
    }

    /// The synthetic IPSW's inventory: it names no AEA member to fetch a
    /// key for.
    fn fake_inventory(ipsw: &Path, model: &str) -> Result<restore::payload::Inventory> {
        restore::payload::inventory(ipsw, model, false, None, None)
    }

    fn environment(host: &FakeHost) -> Environment<'_> {
        Environment {
            host,
            prepare: &fake_prepare,
            prepare_restore: &fake_prepare_restore,
            inventory: &fake_inventory,
            piece_bytes: medium::tests::PIECE_BYTES,
            interface: mount_interface::CURRENT,
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
        let mut record: Record = stela_runtime::read_json(&f.esp.join(RECORD)).unwrap();
        record.migrate();
        record
    }

    /// The active build's bundle of `ecid`'s machine.
    fn bundle_of(f: &Fixture, ecid: Option<Ecid>) -> PathBuf {
        let record = record(f);
        bundle::directory(&record.volume, &record.build, ecid, record.bundle_schema)
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
        assert!(plan.contains("ECID           0x"), "{plan}");
        assert!(plan.contains("Paused"), "{plan}");
        assert_eq!((snapshot(&f.esp), snapshot(&f.data)), before);

        let report = setup(&environment(host), command(&f, &f.esp)).unwrap();
        assert!(report.contains("stela setup --uninstall"), "{report}");
        assert!(report.contains("Reinstall macOS"), "{report}");
        let record = record(&f);
        let ecid = record.ecid.unwrap();
        assert_ne!(ecid.0, 0);
        assert_eq!(
            fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap(),
            format!(
                "--system --bundle \\EFI\\stela\\boot\\{}\\recovery-{} --ram-bytes \
                 0x200000000\n",
                restore::payload::SYNTHETIC_BUILD,
                ecid.digits()
            )
        );
        let bundle = bundle_of(&f, Some(ecid));
        assert_eq!(
            fs::read(bundle.join("ramdisk.img")).unwrap(),
            vec![ecid.0 as u8; 4096]
        );
        assert!(bundle::verify(&bundle, &record.bundles[0].manifest_sha256).is_empty());
        assert!(!f.esp.join("EFI/stela/source.bin").exists());
        assert!(!f.esp.join(CHOICES_PATH).exists());
        assert_eq!(
            fs::read(f.esp.join("EFI/OC/Tools/Stela.efi")).unwrap(),
            efi_image(b"stela")
        );
        let config = fs::read_to_string(f.esp.join("EFI/OC/config.plist")).unwrap();
        assert!(config.contains("Stela.efi"));
        assert!(record.complete);
        assert_eq!(record.schema_version, RECORD_SCHEMA);
        // A second setup is refused until the first is undone.
        let again = setup(&environment(host), command(&f, &f.esp));
        assert!(again.unwrap_err().to_string().contains("--uninstall"));

        let dry = uninstall(&environment(host), &f.esp, true).unwrap();
        assert!(dry.contains("Dry run"));
        assert!(bundle.is_dir());
        let done = uninstall(&environment(host), &f.esp, false).unwrap();
        assert!(done.contains("Done."));
        assert_eq!((snapshot(&f.esp), snapshot(&f.data)), before);
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
        let ecid = record(&f).ecid;
        assert!(bundle_of(&f, ecid).join("ramdisk.img").is_file());
        assert!(bundle_of(&f, ecid).starts_with(&f.data));
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

        // Schema 3, with one installed disk and a bundle without an ECID:
        // the disk becomes the first install, the bundle is listed.
        let f = fixture(64 * GIB, false);
        let before = snapshot(&f.esp);
        // A schema 3 setup's stela.efi has no interface marker.
        let old = f._dir.path().join("old.efi");
        fs::write(&old, b"MZstela-old").unwrap();
        efi::add_mount(&f.esp, &old, None, Some("--system\n")).unwrap();
        let legacy = f.esp.join("EFI/stela/boot/STELA1/recovery");
        bundle::tests::write(&legacy, 1, b"old").unwrap();
        let disk = installed::InstalledDisk {
            apple_region: REGION.into(),
            apple_region_serial: SERIAL.into(),
            apple_region_guid: REGION_GUID.into(),
            nor: NOR.into(),
            nor_serial: SERIAL.into(),
            nor_guid: NOR_GUID.into(),
            machine_state_offset: None,
        };
        let record = serde_json::json!({
            "schema_version": 3,
            "kind": RECORD_KIND,
            "build": "STELA1",
            "model": "Mac14,3",
            "esp": f.esp,
            "volume": f.esp,
            "bundle_directory": f.esp.join("EFI/stela/boot/STELA1"),
            "created_directories": [f.esp.join("EFI/stela/boot/STELA1"), f.esp.join("EFI/stela/boot")],
            "options": "--system\n",
            "complete": true,
            "installed": disk,
            "recovery_builds": ["STELA1"],
        });
        stela_runtime::write_json(&f.esp.join(RECORD), &record).unwrap();
        let migrated = read_record(&environment(&f.host), &f.esp).unwrap();
        assert_eq!(migrated.installs.len(), 1);
        assert_eq!(migrated.installs[0].disk, disk);
        assert_eq!(migrated.installs[0].ecid, None);
        assert_eq!(migrated.bundles.len(), 1);
        assert_eq!(migrated.missing_bundles("STELA1"), Vec::new());
        assert!(
            migrated
                .options_text()
                .contains("\\boot\\STELA1\\recovery ")
        );
        // The markerless stela.efi it has must be updated before changes.
        let error = rerun(&f, |c| c.no_tss = true).unwrap_err().to_string();
        assert!(error.contains("--update-stela"), "{error}");
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert_eq!(snapshot(&f.esp), before);
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
    const IMAGE_BYTES: usize = 2 * 1024 * 1024;
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

    fn rerun(f: &Fixture, configure: impl Fn(&mut Setup)) -> Result<String> {
        let mut command = command(f, &f.esp);
        command.ipsw = None;
        command.model = None;
        configure(&mut command);
        command.dispatch(&environment(&f.host))
    }

    #[test]
    fn an_installed_disk_boots_macos_or_recoveryos_and_keeps_its_partitions() {
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        let before = snapshot(&f.esp);
        let stela_before = snapshot(&stela_volume(&f));
        let disks = (partition_bytes(&f, REGION), partition_bytes(&f, NOR));

        // An install needs the signing server opt-in, and says why.
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
        assert_eq!(record.ecid, Some(ecid));
        let region = format!("{SERIAL}:{REGION_GUID}");
        let recovery = format!(
            "\\EFI\\stela\\boot\\{}\\recovery-{}",
            restore::payload::SYNTHETIC_BUILD,
            ecid.digits()
        );
        let line = format!(
            "--system --storage {region} --nor {SERIAL}:{NOR_GUID} --preboot {region} \
             --recovery-bundle {recovery} --ram-bytes 0x200000000 --ecid {ecid} --tss"
        );
        assert_eq!(
            fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap(),
            format!("{line}\n")
        );
        // The startup choices hold the install, its System Recovery and
        // Install macOS (Stela), and open on their own.
        let choices =
            Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
        assert_eq!(choices.timeout_seconds, CHOOSER_SECONDS);
        assert_eq!(choices.entries[0].name, "macOS");
        assert_eq!(choices.entries[0].options, line);
        assert_eq!(choices.entries[1].name, "macOS - System Recovery");
        assert_eq!(
            choices.entries[1].options,
            format!(
                "--system --storage {region} --nor {SERIAL}:{NOR_GUID} --bundle {recovery} \
                 --ram-bytes 0x200000000 --ecid {ecid} --tss"
            )
        );
        // That line is what stela.efi routes a System Recovery choice to.
        let mut selection = stela_loader::boot_selection::select(
            &Variables::parse(&stela_runtime::machine::apple::nor::nvram::empty_bank()).unwrap(),
        )
        .unwrap();
        selection.missing_boot_media();
        let (routed, _) = stela_loader::boot_selection::route(&line, Some(&selection)).unwrap();
        let mut routed: Vec<&str> = routed.split_ascii_whitespace().collect();
        let mut expected: Vec<&str> = choices.entries[1]
            .options
            .split_ascii_whitespace()
            .collect();
        routed.sort_unstable();
        expected.sort_unstable();
        assert_eq!(routed, expected);
        // Install macOS (Stela) restores the install medium onto the disk
        // with the machine's restore bundle.
        let build = restore::payload::SYNTHETIC_BUILD;
        assert_eq!(choices.entries[2].name, INSTALL_CHOICE);
        assert_eq!(
            choices.entries[2].options,
            format!(
                "--system --storage {region} --nor {SERIAL}:{NOR_GUID} --bundle \
                 \\EFI\\stela\\boot\\{build}\\restore-{} --ram-bytes 0x200000000 --ecid {ecid} \
                 --install \\EFI\\stela\\install\\{build}\\payload.json --install-source \
                 {STELA_GUID} --tss",
                ecid.digits()
            )
        );
        let restore_bundle = record.restore_bundle(Some(ecid)).unwrap();
        assert!(
            bundle::verify(
                &restore_bundle.directory(&record.volume),
                &restore_bundle.manifest_sha256
            )
            .is_empty()
        );
        // The medium is the IPSW in pieces on the USB's FAT32 partition.
        let medium = record.medium.clone().unwrap();
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
            line.trim_end().ends_with("--verify-on-read --tss"),
            "{line}"
        );
        // Setup itself writes neither partition.
        assert_eq!(
            (partition_bytes(&f, REGION), partition_bytes(&f, NOR)),
            disks
        );
        // The opt-in turns off again, and the Install choice with it.
        let off = rerun(&f, |c| c.no_tss = true).unwrap();
        assert!(off.contains("drops the Install macOS (Stela)"), "{off}");
        assert!(
            !fs::read_to_string(f.esp.join("EFI/stela/stela.cfg"))
                .unwrap()
                .contains("--tss")
        );
        let choices =
            Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
        assert_eq!(choices.entries.len(), 2);

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
        assert!(!stela_volume(&f).join("EFI").exists());
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
        // Set up without a disk first; the first install takes over the
        // setup's machine and its bundle.
        setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
        let first = record(&f).ecid.unwrap();
        let add = |target: &str, nor: &str, ipsw: bool, dry_run: bool| {
            rerun(&f, |c| {
                c.target = Some(target.into());
                c.nor = Some(nor.into());
                c.ipsw = ipsw.then(|| f.ipsw.clone());
                c.dry_run = dry_run;
                c.tss = true;
            })
        };
        // An install restores from the IPSW, which it needs.
        let error = add(REGION, NOR, false, false).unwrap_err().to_string();
        assert!(error.contains("is installed from the macOS"), "{error}");
        // Without the signing server opt-in it is refused by name.
        let error = rerun(&f, |c| {
            c.target = Some(REGION.into());
            c.nor = Some(NOR.into());
            c.ipsw = Some(f.ipsw.clone());
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("needs --tss"), "{error}");
        add(REGION, NOR, true, false).unwrap();
        let record1 = record(&f);
        assert_eq!(record1.installs[0].ecid, Some(first));
        let kinds: Vec<Kind> = record1.bundles.iter().map(|b| b.kind).collect();
        assert_eq!(kinds, [Kind::Recovery, Kind::Restore]);
        assert!(record1.medium.as_ref().unwrap().problems().is_empty());
        // The second is a new machine and needs its own bundles.
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
            vec![second.0 as u8; 4096]
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
                "macOS - System Recovery",
                "macOS - Install macOS",
                "macOS 2",
                "macOS 2 - System Recovery",
                "macOS 2 - Install macOS"
            ]
        );
        // Each install restores with its own machine's restore bundle.
        let restore2 = bundle::directory_of(
            Kind::Restore,
            &record2.volume,
            &record2.build,
            Some(second),
            record2.bundle_schema,
        );
        assert!(choices().entries[5].options.contains(&format!(
            "--bundle \\EFI\\stela\\boot\\{}\\restore-{}",
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
        assert_eq!(choices().entries[2].name, INSTALL_CHOICE);
        assert_eq!(record(&f).installs.len(), 1);
        uninstall(&environment(&f.host), &f.esp, false).unwrap();
        assert!(!f.esp.join("EFI/stela").exists());
    }

    #[test]
    fn stela_updates_keep_the_old_version_and_roll_back() {
        let f = fixture(64 * GIB, false);
        let before = snapshot(&f.esp);
        setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
        let tool = f.esp.join("EFI/OC/Tools/Stela.efi");
        let config = fs::read(f.esp.join("EFI/OC/config.plist")).unwrap();
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
        let report = update(false).unwrap();
        assert!(report.contains("no translation cache"), "{report}");
        assert_eq!(fs::read(&tool).unwrap(), efi_image(b"stela-2"));
        // Only the tool changed: the entry and stela.cfg stay.
        assert_eq!(fs::read(f.esp.join("EFI/OC/config.plist")).unwrap(), config);
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
        let f = fixture(64 * GIB, false);
        setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
        let ecid = record(&f).ecid;
        let old = bundle_of(&f, ecid);
        let options = || fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap();
        let first = options();
        // A later stela and stela.efi read schema 2.
        let newer = mount_interface::Interface {
            bundle_schema: 2,
            ..mount_interface::CURRENT
        };
        let prepare = |_: &Path, _: &str, ecid: Option<Ecid>, output: &Path| {
            bundle::tests::write(output, 2, &[ecid.map_or(0, |e| e.0 as u8) ^ 0xff; 64])
        };
        let environment = Environment {
            host: &f.host,
            prepare: &prepare,
            prepare_restore: &fake_prepare_restore,
            inventory: &fake_inventory,
            piece_bytes: medium::tests::PIECE_BYTES,
            interface: newer,
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
        assert!(error.contains("schema 2"), "{error}");
        assert!(error.contains("--ipsw"), "{error}");
        update(true).unwrap();
        let record2 = record(&f);
        assert_eq!(record2.bundle_schema, 2);
        let migrated = bundle_of(&f, ecid);
        assert!(migrated.ends_with(format!("recovery-{}-s2", ecid.unwrap().digits())));
        assert!(options().contains("-s2 "), "{}", options());
        // The old bundle stays for the rollback, which boots it again.
        assert!(old.join("bundle.json").is_file());
        rerun(&f, |c| c.rollback = true).unwrap();
        assert_eq!(options(), first);
        assert!(!migrated.exists());
        assert_eq!(record(&f).bundle_schema, 1);
    }

    #[test]
    fn os_updates_add_recoveryos_and_interrupted_updates_finish_or_roll_back() {
        let f = fixture(64 * GIB, false);
        let before = snapshot(&f.esp);
        setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
        let ecid = record(&f).ecid;
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
        assert!(report.contains("Update volume"), "{report}");
        assert!(options().contains("\\boot\\STELA2\\recovery-"));
        let leaf = bundle::leaf(ecid, 1);
        assert!(
            f.esp
                .join(format!("EFI/stela/boot/STELA2/{leaf}/bundle.json"))
                .is_file()
        );
        // The old build stays for rollback.
        let old = bundle::directory(&f.esp, restore::payload::SYNTHETIC_BUILD, ecid, 1);
        assert!(old.join("bundle.json").is_file());
        rerun(&f, |c| c.rollback = true).unwrap();
        assert_eq!(options(), first);
        assert!(!f.esp.join("EFI/stela/boot/STELA2").exists());

        // An update interrupted after it was recorded refuses other updates,
        // finishes when run again, and rolls back otherwise.
        let mut record1 = record(&f);
        record1.pending = Some(update::Change::Os {
            from: restore::payload::SYNTHETIC_BUILD.into(),
            to: "STELA2".into(),
        });
        write_record(&f.esp, &record1).unwrap();
        let partial = f.esp.join(format!("EFI/stela/boot/STELA2/{leaf}.partial"));
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
        let ecid = record(&f).ecid;
        let ramdisk = bundle_of(&f, ecid).join("ramdisk.img");
        fs::write(&ramdisk, [0u8; 10]).unwrap();
        fs::write(f.esp.join(TOOL_PATH), b"MZ damaged").unwrap();
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
        assert_eq!(record(&f).ecid, ecid);
        assert_eq!(
            fs::read(&ramdisk).unwrap(),
            vec![ecid.unwrap().0 as u8; 4096]
        );
        assert_eq!(snapshot(&f.esp), before);
        status().unwrap();

        // A machine an older setup made without an ECID gets one.
        let mut old = record(&f);
        old.installs[0].ecid = None;
        old.ecid = None;
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
        assert_eq!(repaired.ecid, Some(new));
        assert!(bundle_of(&f, Some(new)).join("bundle.json").is_file());
        status().unwrap();
    }

    #[test]
    fn a_bundle_copy_stopped_between_its_renames_is_found_and_put_back() {
        let mut f = fixture(64 * GIB, false);
        add_installed_disk(&mut f, &[], &[]);
        setup(&environment(&f.host), installed_command(&f)).unwrap();
        let before = snapshot(&f.esp);
        let directory = bundle_of(&f, record(&f).ecid);
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
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
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
        // The log is optional: a smaller partition is noted, not refused.
        f.host.partitions.get_mut(NOR).unwrap().0.bytes = PARTITION_BYTES - 1;
        let error = format!("{:#}", rerun(&f, |c| c.boot_log = true).unwrap_err());
        assert!(error.contains("without one"), "{error}");
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
        let recovery = format!(
            "\\EFI\\stela\\boot\\{}\\recovery-{}",
            restore::payload::SYNTHETIC_BUILD,
            ecid.digits()
        );
        assert_eq!(
            fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap(),
            format!(
                "--system --storage {region} --nor {region} --preboot {region} \
                 --recovery-bundle {recovery} --ram-bytes 0x200000000 --ecid {ecid} --tss\n"
            )
        );
        let choices =
            Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
        assert_eq!(
            choices.entries[1].options,
            format!(
                "--system --storage {region} --nor {region} --bundle {recovery} \
                 --ram-bytes 0x200000000 --ecid {ecid} --tss"
            )
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
            choices.entries[3]
                .options
                .contains(&format!("--storage {region2} --nor {region2}")),
            "{}",
            choices.entries[3].options
        );
        // Its Install choice restores onto the region with the tail kept.
        assert_eq!(choices.entries[5].name, "Other - Install macOS");
        assert!(
            choices.entries[5]
                .options
                .contains(&format!("--storage {region2} --nor {region2} --bundle")),
            "{}",
            choices.entries[5].options
        );
    }
}
