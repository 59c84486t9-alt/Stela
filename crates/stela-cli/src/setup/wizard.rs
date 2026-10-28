//! A small Clack-style front end to the same setup command used by scripts.
use super::{
    InstallImage, Setup,
    host::{self, Disk, Host, Removal},
};
use crate::{progress::Phase, restore};
use anyhow::{Context, Result, ensure};
use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
};

mod catalog;
mod choices;
mod menu;
mod theme;

// Advertised USB capacity classes; preparation also checks exact image sizes.
const NETWORK_MIN: u64 = 7 * 1024 * 1024 * 1024;
const OFFLINE_MIN: u64 = 28 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Usb {
    id: String,
    name: String,
    bytes: u64,
    removal: Removal,
    serial: Option<String>,
}

impl Usb {
    pub(super) fn from_disk(disk: &Disk, host: &dyn Host) -> Self {
        Self {
            id: disk.identifier.clone(),
            name: disk.name.clone(),
            bytes: disk.bytes,
            removal: disk.removal,
            serial: host.serial(&disk.identifier).ok().flatten(),
        }
    }

    pub(super) fn verify(&self, host: &dyn Host) -> Result<()> {
        let disk = host
            .disks()?
            .into_iter()
            .find(|d| d.identifier == self.id)
            .context("the selected USB was disconnected; run setup again")?;
        ensure!(
            disk.erasable() && *self == Self::from_disk(&disk, host),
            "the selected USB changed; run setup again and choose it again"
        );
        Ok(())
    }

    fn path(&self) -> PathBuf {
        PathBuf::from(&self.id)
    }

    fn size(&self) -> String {
        host::size_text(self.bytes)
    }

    fn description(&self) -> String {
        format!("{} · {} · {}", self.name, self.size(), self.id)
    }

    /// Its model or size, typed back to erase a disk other than a USB.
    fn typed_back(&self) -> Result<String> {
        cliclack::log::warning(format!(
            "{} ({}, {}) is not a USB disk.",
            self.name,
            self.size(),
            self.id
        ))?;
        let (name, bytes) = (self.name.clone(), self.bytes);
        let expected = format!("Type {} or {}", self.name, self.size());
        Ok(cliclack::input("Type its model or size to erase it")
            .placeholder(&format!("{} or {}", self.name, self.size()))
            .validate(move |typed: &String| {
                if host::names_disk(&name, bytes, typed) {
                    Ok(())
                } else {
                    Err(expected.clone())
                }
            })
            .interact()?)
    }

    /// The name and size people recognize, for the erase warning.
    fn short(&self) -> String {
        format!("{} ({})", self.name, self.size())
    }
}

#[derive(serde::Deserialize)]
struct LocalImage {
    #[serde(rename = "ProductVersion")]
    product_version: String,
    #[serde(rename = "ProductBuildVersion")]
    product_build: String,
    #[serde(rename = "SupportedProductTypes")]
    supported_models: Vec<String>,
}

fn local_image(path: &Path) -> Result<LocalImage> {
    // Read only metadata into the wizard, rather than retaining every board's
    // component map. Preparation validates the selected identity before erase.
    let bytes = restore::archive::read_member(path, "BuildManifest.plist", 64 * 1024 * 1024)?;
    Ok(plist::from_reader(std::io::Cursor::new(bytes))?)
}

pub(super) fn check_creation(command: &Setup) -> Result<()> {
    ensure!(
        !command.status
            && !command.repair
            && !command.uninstall
            && !command.update_stela
            && !command.update_os
            && !command.rollback
            && command.next_boot.is_none()
            && !command.reset_nvram
            && command.backup_state.is_none()
            && command.restore_state.is_none()
            && !command.boot_log
            && !command.configures()
            && command.host_firmware.is_none()
            && command.host_firmware_requirements.is_none(),
        "maintenance commands need --usb; run `stela setup` alone to create an installer"
    );
    Ok(())
}

/// `false` is cancellation. No disk is written by this function.
pub(super) fn configure(command: &mut Setup, host: &dyn Host) -> Result<bool> {
    check_creation(command)?;
    ensure!(
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
        "interactive setup needs a terminal; scripts should pass --usb and --ipsw or --fetch"
    );
    match configure_inner(command, host) {
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::Interrupted) =>
        {
            Ok(false)
        }
        result => result,
    }
}

fn configure_inner(command: &mut Setup, host: &dyn Host) -> Result<bool> {
    cliclack::set_theme(theme::Stela::default());
    crate::progress::follow(theme::rail());
    cliclack::intro(
        theme::accent()
            .bold()
            .apply_to("Stela · Create a macOS installer"),
    )?;
    let disks = host.disks()?;
    let choices: Vec<_> = disks
        .iter()
        .filter(|d| d.erasable())
        .map(|d| Usb::from_disk(d, host))
        .collect();
    ensure!(
        !choices.is_empty(),
        "no removable USB found. Connect one and run setup again ({}).",
        super::host::ADMIN
    );
    let mut images = None;
    let mut names = catalog::cached_names();
    let mut first = true;
    // `--build`, or the newest supported build.
    let mut preferred_build = Some(command.build.clone());
    loop {
        let rows: Vec<_> = choices
            .iter()
            .enumerate()
            .map(|(i, usb)| menu::Item {
                value: i,
                label: usb.description(),
                hint: if usb.bytes == 0 {
                    "Capacity unavailable; run setup as administrator".into()
                } else if usb.bytes < NETWORK_MIN {
                    "Too small · Requires an 8 GB or larger USB".into()
                } else if usb.bytes < OFFLINE_MIN {
                    "Network installer only · Offline needs a 32 GB USB".into()
                } else {
                    "Offline or network installer".into()
                },
                enabled: usb.bytes >= NETWORK_MIN,
            })
            .collect();
        let initial = choices
            .iter()
            .position(|usb| usb.path() == command.usb)
            .unwrap_or(0);
        let usb = &choices[menu::select("1 / 6  Choose a USB", &rows, initial)?];
        command.usb = usb.path();
        let offline = usb.bytes >= OFFLINE_MIN;
        let prefilled = first && command.ipsw.is_some() && offline;
        first = false;
        let source = if prefilled {
            2
        } else {
            let item = |value, label: &str, hint: &str, enabled| menu::Item {
                value,
                label: label.into(),
                hint: hint.into(),
                enabled,
            };
            let rows = [
                item(
                    0,
                    "Offline installer",
                    "Downloads the full macOS image onto the USB · Requires a 32 GB USB",
                    offline,
                ),
                item(
                    1,
                    "Network installer",
                    "Downloads boot files only · Requires an 8 GB USB; Ethernet needed during installation",
                    true,
                ),
                item(
                    2,
                    "Use an existing IPSW",
                    "Copies your downloaded image to the USB · Requires a 32 GB USB",
                    offline,
                ),
            ];
            let initial = if command.ipsw.is_some() {
                2
            } else {
                usize::from(command.install_image == Some(InstallImage::Online))
            };
            menu::select("2 / 6  Choose an installer", &rows, initial)?
        };
        let (version, models) = if source == 2 {
            let path = if prefilled {
                command.ipsw.clone().unwrap()
            } else {
                let initial = command
                    .ipsw
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                let text: String = cliclack::input("3 / 6  Choose an IPSW file")
                    .placeholder("Path to the .ipsw file")
                    .default_input(&initial)
                    .validate(|s: &String| {
                        if Path::new(s.trim().trim_matches('"')).is_file() {
                            Ok(())
                        } else {
                            Err("Choose an existing IPSW file")
                        }
                    })
                    .interact()?;
                PathBuf::from(text.trim().trim_matches('"'))
            };
            let progress = Phase::spinner("Reading IPSW metadata");
            let manifest =
                local_image(&path).with_context(|| format!("reading {}", path.display()))?;
            progress.finish();
            stela_runtime::builds::find(&manifest.product_build)
                .with_context(|| path.display().to_string())?;
            command.ipsw = Some(path);
            command.fetch = false;
            command.build = manifest.product_build.clone();
            preferred_build = Some(command.build.clone());
            command.install_image = Some(InstallImage::Offline);
            cliclack::log::info(format!(
                "macOS {} ({}) · local IPSW",
                manifest.product_version, manifest.product_build
            ))?;
            (manifest.product_version, manifest.supported_models)
        } else {
            if images.is_none() {
                let progress = Phase::spinner("Loading available macOS versions");
                images = Some(catalog::load()?);
                if let Ok(fresh) = catalog::model_names() {
                    names = fresh;
                }
                progress.finish();
            }
            let entries = images.as_ref().unwrap();
            let image =
                &entries[choices::release(entries, preferred_build.as_deref().unwrap_or(""))?];
            command.build = image.build.clone();
            preferred_build = Some(command.build.clone());
            command.ipsw = None;
            command.fetch = true;
            command.install_image = Some(if source == 0 {
                InstallImage::Offline
            } else {
                InstallImage::Online
            });
            (image.version.clone(), image.models.clone())
        };
        ensure!(
            !models.is_empty(),
            "this image lists no compatible Mac models"
        );
        let mut models = models;
        models.sort();
        models.dedup();
        command.model = Some(choices::model(&models, &names, command.model.as_deref())?);
        // Every setup installs macOS, which needs TSS personalization, so the
        // wizard does not offer it as a choice; `--no-tss` withdraws the
        // opt-in from an existing setup.
        cliclack::set_theme(theme::Stela { extras: true });
        let extras = cliclack::multiselect("5 / 6  Choose extras")
            .item(0, "Profiling", "Save translation timing in the boot log")
            .initial_values(if command.profile { vec![0] } else { vec![] })
            .required(false)
            .interact()?;
        cliclack::set_theme(theme::Stela::default());
        command.tss = true;
        command.no_tss = false;
        command.profile = extras.contains(&0);
        let installer = match (source, command.install_image) {
            (2, _) => format!(
                "Existing IPSW · {}",
                command
                    .ipsw
                    .as_deref()
                    .and_then(Path::file_name)
                    .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
            ),
            (_, Some(InstallImage::Online)) => {
                "Network · macOS downloads over Ethernet during installation".into()
            }
            _ => "Offline · the full macOS image goes on the USB".into(),
        };
        cliclack::note(
            "6 / 6  Review",
            format!(
                "USB        {}\nInstaller  {installer}\nmacOS      {version} ({})\nMac        {}\nProfiling  {}\nSigning    Apple personalizes the boot files during setup",
                usb.serial.as_ref().map_or_else(
                    || usb.description(),
                    |serial| format!("{} · serial {serial}", usb.description())
                ),
                command.build,
                names
                    .get(command.model())
                    .map_or(command.model(), String::as_str),
                if command.profile { "On" } else { "Off" },
            ),
        )?;
        cliclack::log::warning(format!("Everything on {} will be erased.", usb.short()))?;
        match cliclack::select("Create the installer?")
            .item(
                0,
                "Create installer",
                format!("Erase {} and write the installer", usb.short()),
            )
            .item(1, "Edit choices", "")
            .item(2, "Cancel", "")
            .initial_value(0)
            .interact()?
        {
            0 => {
                if usb.removal == Removal::Typed {
                    command.confirm_disk = Some(usb.typed_back()?);
                }
                usb.verify(host)?;
                return Ok(true);
            }
            1 => continue,
            _ => {
                cliclack::outro_cancel("Setup cancelled. Your USB was not changed.")?;
                return Ok(false);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_manifest_retains_version_and_model_compatibility_without_network() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("local.ipsw");
        crate::efi::synthetic_ipsw(&path)?;
        let manifest = local_image(&path)?;
        assert_eq!(manifest.product_build, restore::payload::SYNTHETIC_BUILD);
        assert!(
            manifest
                .supported_models
                .contains(&restore::payload::SYNTHETIC_MODEL.into())
        );
        assert!(local_image(&dir.path().join("missing.ipsw")).is_err());
        Ok(())
    }

    #[test]
    fn maintenance_without_a_usb_is_refused_before_opening_prompts() {
        use clap::Parser;
        for action in [
            "--status",
            "--repair",
            "--uninstall",
            "--update-stela",
            "--no-tss",
        ] {
            let crate::Command::Setup(command) =
                crate::Cli::try_parse_from(["stela", "setup", action])
                    .unwrap()
                    .command
            else {
                panic!("not setup");
            };
            assert!(check_creation(&command).is_err(), "{action}");
        }
    }
}
