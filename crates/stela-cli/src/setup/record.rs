//! The setup record, `EFI/stela/setup.json`: what setup wrote, read by every
//! later command and written before each change.
use super::{
    CHOICES_PATH, CHOOSER_SECONDS, Environment, InstallImage, LOADER_PATH, RECORD,
    bundle::{self, Kind},
    ecid::Ecid,
    image_is_remote, installed, locate_esp, machines, medium, restore_choice_name, translations,
    update, wifi,
};
use crate::efi;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use stela_boot_core::options::System;
use stela_loader::mount_interface::{Choice, Choices};

/// What setup writes, recorded on the ESP so `uninstall` can remove it.
/// Records before schema 8 also named a recoveryOS bundle on the USB, and
/// records before schema 9 kept the data partition's files under `EFI/`;
/// this `stela` reads them only to uninstall them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) schema_version: u32,
    pub(super) kind: String,
    /// The active macOS build, which Install macOS restores.
    pub(super) build: String,
    pub(super) model: String,
    pub(super) esp: PathBuf,
    /// The USB's FAT32 data partition.
    #[serde(alias = "payload_volume")]
    pub(super) volume: PathBuf,
    /// A schema 1 setup's restore payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) payload_directory: Option<PathBuf>,
    /// `stela/boot/<build>` of the active build.
    pub(super) bundle_directory: PathBuf,
    /// Directories setup created on the payload volume, deepest first.
    pub(super) created_directories: Vec<PathBuf>,
    /// `stela.cfg`.
    pub(super) options: String,
    pub(super) complete: bool,
    /// Schema 3: the PC's own disk; read into `installs`.
    #[serde(default, skip_serializing)]
    pub(super) installed: Option<installed::InstalledDisk>,
    /// Schema 3: the active `stela.efi` version and those kept, oldest
    /// first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) stela_version: Option<String>,
    #[serde(default)]
    pub(super) stela_versions: Vec<String>,
    /// Schema 3: the macOS builds kept for rollback, oldest first; `build`
    /// is the active one.
    #[serde(default, alias = "recovery_builds")]
    pub(super) builds: Vec<String>,
    /// Schema 3: an update that started and has not finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) pending: Option<update::Change>,
    /// Schema 3: finished updates, for `rollback`.
    #[serde(default)]
    pub(super) history: Vec<update::Change>,
    /// Schema 4: the PC disks macOS installs onto, each its own machine.
    #[serde(default)]
    pub(super) installs: Vec<machines::Install>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) default_install: Option<String>,
    /// Schema 4: the boot-bundle schema the active `stela.efi` reads.
    #[serde(default = "first_schema")]
    pub(super) bundle_schema: u32,
    /// Schema 7: the revision of the active bundles, those of the loader
    /// that prepared them (`stela_loader::boot_bundle::REVISION`); 0 before.
    #[serde(default)]
    pub(super) bundle_revision: u32,
    /// Schema 4: every boot bundle setup wrote.
    #[serde(default)]
    pub(super) bundles: Vec<bundle::Bundle>,
    /// Schema 4: the Apple signing server opt-in (`--tss`).
    #[serde(default)]
    pub(super) tss: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) chooser_timeout: Option<u32>,
    /// Schema 5: the install medium; read into `media`.
    #[serde(default, skip_serializing)]
    pub(super) medium: Option<medium::Medium>,
    /// Schema 6: the install media, each a full IPSW on the USB's FAT32
    /// data partition: the active build's and, for rollback, the one
    /// before it.
    #[serde(default)]
    pub(super) media: Vec<medium::Medium>,
    /// Schema 5: the Install choice checks the IPSW as it reads it
    /// (`--verify-on-read`).
    #[serde(default)]
    pub(super) verify_on_read: bool,
    /// Every choice times the engine (`--profile`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) profile: bool,
    /// Where installs read the restore image (`--install-image`); the
    /// default when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) install_image: Option<InstallImage>,
    /// The translation store `stela.efi` keeps its packs in, if the USB
    /// has room for one (`setup::translations`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) translations: Option<translations::Store>,
    /// The Wi-Fi network every choice joins (`--wifi`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) wifi: Option<wifi::Network>,
}

pub(super) fn first_schema() -> u32 {
    1
}

pub(super) const RECORD_KIND: &str = "stela_setup";

/// Schema 8: no recoveryOS bundle; every setup has an install. Schema 9:
/// the data partition's files are under `stela/`, not `EFI/stela/`.
pub(super) const RECORD_SCHEMA: u32 = 9;

impl Record {
    /// Whether installs stream `ipsw`'s build from Apple's servers
    /// (`--install-image online`) rather than read it from the USB. An erase
    /// restore needs the macOS system image, which a recovery archive
    /// (`restore::payload::trim`) leaves out
    /// (`docs/research/small-installer-usb.md`). A complete local image
    /// stays local by default, including when the target disk will be
    /// chosen later on another PC.
    pub(super) fn remote_install(&self, ipsw: &Path) -> Result<bool> {
        image_is_remote(ipsw, self.install_image)
    }

    /// Bring an older schema's record to one `uninstall` reads: its
    /// install medium is listed and its installed disk becomes the first
    /// install.
    pub(super) fn migrate(&mut self) {
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
    pub(super) fn default(&self) -> Option<&machines::Install> {
        self.default_install
            .as_ref()
            .and_then(|name| self.installs.iter().find(|i| &i.name == name))
            .or(self.installs.first())
    }

    /// The install `name` names, or the default one.
    pub(super) fn install(&self, name: Option<&str>) -> Result<&machines::Install> {
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
    pub(super) fn generation(&self) -> bundle::Generation {
        bundle::Generation {
            schema: self.bundle_schema,
            revision: self.bundle_revision,
        }
    }

    pub(super) fn line(&self, mut system: System) -> String {
        system.tss = self.tss;
        system.profile = self.profile;
        // The key file is `--wifi`'s default one.
        system.ssid = self.wifi.as_ref().map(|network| network.ssid.clone());
        system.wifi_country = self
            .wifi
            .as_ref()
            .and_then(|network| network.country.clone());
        format!("{system}\n")
    }

    /// The option line that boots `install`.
    pub(super) fn boot_line(&self, install: &machines::Install) -> Result<String> {
        Ok(self.line(install.disk.options(install.ecid)?))
    }

    /// `stela.cfg`: the default install. Every setup this `stela` reads
    /// has one ([`read_record`]).
    pub(super) fn options_text(&self) -> Result<String> {
        self.default()
            .map(|install| self.boot_line(install))
            .transpose()
            .map(Option::unwrap_or_default)
    }

    /// The restore bundle of `kind` (erase or update) of `ecid`'s machine
    /// for the active build.
    /// The active build's restore bundle of `kind` for `ecid`, signed as the
    /// setup's TSS choice needs: under Apple's personalized ticket with the
    /// opt-in, under the global one without. A bundle signed the other way
    /// counts as missing, so the next setup run prepares it again.
    pub(super) fn restore_bundle(&self, kind: Kind, ecid: Option<Ecid>) -> Option<&bundle::Bundle> {
        self.bundles.iter().find(|b| {
            b.same_kind(kind, &self.build, ecid, self.generation()) && b.personalized == self.tss
        })
    }

    /// The install medium of `build`.
    pub(super) fn medium_of(&self, build: &str) -> Option<&medium::Medium> {
        self.media.iter().find(|m| m.build == build)
    }

    /// The active build's install medium.
    pub(super) fn active_medium(&self) -> Option<&medium::Medium> {
        self.medium_of(&self.build)
    }

    /// Whether the installs restore from install media: the setup has
    /// written a medium or a restore bundle, as every setup does.
    pub(super) fn installs_media(&self) -> bool {
        !self.installs.is_empty() && (!self.media.is_empty() || !self.bundles.is_empty())
    }

    /// The machines of the installs, each once.
    pub(super) fn install_machines(&self) -> Vec<Option<Ecid>> {
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
    pub(super) fn restore_line(
        &self,
        kind: Kind,
        install: &machines::Install,
    ) -> Result<Option<String>> {
        let Some(medium) = self.active_medium() else {
            return Ok(None);
        };
        if self.restore_bundle(kind, install.ecid).is_none() || !self.tss {
            return Ok(None);
        }
        let restore = bundle::firmware_path_of(kind, &self.build, install.ecid, self.generation());
        let mut system = install.disk.bundle_options(&restore, install.ecid)?;
        medium.restore_from(&mut system)?;
        system.update_restore = kind == Kind::Update;
        system.verify_on_read = self.verify_on_read;
        system.development_restore = kind == Kind::Restore;
        Ok(Some(self.line(system)))
    }

    /// The Install macOS choice's option line.
    pub(super) fn install_line(&self, install: &machines::Install) -> Result<Option<String>> {
        self.restore_line(Kind::Restore, install)
    }

    /// The name of `install`'s Install macOS or Update macOS
    /// (Stela) choice.
    pub(super) fn restore_choice(&self, kind: Kind, install: &machines::Install) -> String {
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
    pub(super) fn missing_restore_bundles(&self) -> Vec<(Kind, Option<Ecid>)> {
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
    pub(super) fn choices(&self) -> Result<Option<Choices>> {
        let Some(default) = self.default() else {
            return Ok(None);
        };
        let mut entries = Vec::new();
        let others = self.installs.iter().filter(|i| i.name != default.name);
        for install in std::iter::once(default).chain(others) {
            entries.push(Choice {
                name: install.name.clone(),
                options: self.boot_line(install)?.trim().into(),
            });
            for kind in bundle::RESTORE_KINDS {
                if let Some(line) = self.restore_line(kind, install)? {
                    entries.push(Choice {
                        name: self.restore_choice(kind, install),
                        options: line.trim().into(),
                    });
                }
            }
        }
        // The list opens on its own with several installs, and while the
        // USB can install macOS.
        let mut installing = false;
        for install in &self.installs {
            installing |= self.install_line(install)?.is_some();
        }
        let seconds = if self.installs.len() > 1 || installing {
            CHOOSER_SECONDS
        } else {
            0
        };
        Ok(Some(Choices {
            timeout_seconds: self.chooser_timeout.unwrap_or(seconds),
            entries,
        }))
    }

    pub(super) fn choices_text(&self) -> Result<Option<String>> {
        self.choices()?
            .map(|choices| choices.encode().map_err(anyhow::Error::msg))
            .transpose()
    }

    /// Forget the bundles of machines the setup no longer has; returns
    /// them for [`remove_bundles`] once the record no longer names them.
    pub(super) fn drop_stale_bundles(&mut self) -> Vec<bundle::Bundle> {
        let machines = self.install_machines();
        let (kept, stale) = self
            .bundles
            .drain(..)
            .partition(|b| machines.contains(&b.ecid));
        self.bundles = kept;
        stale
    }

    /// Every build directory a bundle or the history names.
    pub(super) fn build_directories(&self) -> Vec<PathBuf> {
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
pub(super) fn remove_bundles(record: &Record, stale: &[bundle::Bundle]) -> Result<()> {
    for kept in stale {
        let directory = kept.directory(&record.volume);
        if directory.is_dir() {
            fs::remove_dir_all(directory)?;
        }
    }
    Ok(())
}

/// Write `stela.cfg`, the startup choices and the entry for the record.
pub(super) fn publish(record: &mut Record) -> Result<()> {
    record.options = record.options_text()?;
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
pub(super) fn read_record(environment: &Environment<'_>, usb: &Path) -> Result<Record> {
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
         uninstall --usb {}` and set the USB up again",
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
        "{} names no install; run `stela setup uninstall --usb {}` and set the USB up again",
        path.display(),
        usb.display()
    );
    Ok(record)
}

/// Any schema's record, for `uninstall`: the bundles of an older
/// schema's record that name no kind or `recovery` are recoveryOS bundles,
/// which this `stela` has no kind for; their build directories are removed
/// with the rest. Before schema 9 the data partition's files were under
/// `EFI/`, which the record's volumes then gain, so every directory derived
/// from them is where that setup wrote it.
pub(super) fn read_any_record(path: &Path) -> Result<Record> {
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
pub(super) fn write_record(esp: &Path, record: &Record) -> Result<()> {
    let path = esp.join(RECORD);
    fs::create_dir_all(path.parent().unwrap())?;
    let mut record = record.clone();
    record.schema_version = RECORD_SCHEMA;
    let mut bytes = serde_json::to_vec_pretty(&record)?;
    bytes.push(b'\n');
    efi::write_atomic(&path, &bytes, false)
}
