//! The installs of a setup: each a disk of the PC (an Apple region and a
//! machine-state partition) that is its own Stela machine with its own ECID,
//! NVRAM and SEP state, as two Macs are. One is the default `stela.cfg`
//! boots; `stela.efi`'s startup choices (`choices.cfg`) list every install
//! and its System Recovery, opening on their own with several installs and
//! when a key is held with one.
//!
//! A machine's ECID is kept for its life: an install whose machine-state
//! partition already holds SEP state takes the ECID given with `--ecid`, and
//! a new one only with `--new-ecid`, since its LocalPolicy and SEP state are
//! bound to the old one. The first install takes over the setup's own
//! machine (recoveryOS without a disk keeps no state), so its recoveryOS
//! bundle serves it; every further install needs its own bundle, prepared
//! from the active build's restore image.
use super::{
    Environment, Prepared, Setup, bundle, check_installed_efi, check_space, copy_bundles,
    ecid::Ecid, installed, prepare_bundles, publish, read_record, tss_note, write_record,
};
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use stela_loader::{boot_bundle::Options as BundleOptions, mount_interface::MAX_CHOICES};

/// The first install's name unless `--install` gives one.
pub(super) const FIRST_NAME: &str = "macOS";
/// Each install takes two startup choices: itself and its System Recovery.
const MAX_INSTALLS: usize = MAX_CHOICES / 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Install {
    pub(super) name: String,
    /// None only for an install a schema 3 setup made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ecid: Option<Ecid>,
    #[serde(flatten)]
    pub(super) disk: installed::InstalledDisk,
}

/// A name the startup choices can show, with room for " - System Recovery".
pub(super) fn check_name(name: &str) -> Result<()> {
    const RECOVERY_SUFFIX: usize = " - System Recovery".len();
    ensure!(
        !name.is_empty()
            && name.len() + RECOVERY_SUFFIX <= stela_loader::mount_interface::MAX_NAME
            && name.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
            && name.trim() == name,
        "an install name is 1 to {} printable ASCII characters",
        stela_loader::mount_interface::MAX_NAME - RECOVERY_SUFFIX
    );
    Ok(())
}

/// The ECID of a machine being set up: the one `given`, else the one
/// `recorded`, else a fresh one, but never a new one for machine state that
/// belongs to an earlier machine unless `new_ecid` says so.
pub(super) fn machine_ecid(
    given: Option<Ecid>,
    recorded: Option<Ecid>,
    sep_provisioned: bool,
    new_ecid: bool,
    notes: &mut Vec<String>,
) -> Result<Ecid> {
    match (given, recorded) {
        (Some(given), Some(recorded)) if given != recorded && !new_ecid => bail!(
            "this machine's ECID is {recorded}, not {given}; changing it orphans its LocalPolicy \
             and SEP state. Pass --new-ecid to change it anyway."
        ),
        (Some(given), _) => Ok(given),
        (None, Some(recorded)) => Ok(recorded),
        (None, None) if sep_provisioned && !new_ecid => bail!(
            "the NOR partition holds an earlier Stela machine's SEP state, which is bound to that \
             machine's ECID. Pass that ECID with --ecid (`stela setup --status` on its old USB \
             or its --backup-state file shows it), or --new-ecid to start a new machine, which \
             orphans its LocalPolicy and SEP state."
        ),
        (None, None) => {
            if sep_provisioned {
                notes.push(
                    "--new-ecid: the NOR partition's SEP state and LocalPolicy belong to another \
                     ECID and are orphaned"
                        .into(),
                );
            }
            Ecid::generate()
        }
    }
}

/// `--target` and `--nor` on an existing setup: add an install.
pub(super) fn add(environment: &Environment<'_>, command: &Setup) -> Result<String> {
    let record = read_record(environment, &command.usb)?;
    check_installed_efi(environment, &record)?;
    super::update::ready(&record, |_| false)?;
    if let Some(model) = &command.model {
        ensure!(
            *model == record.model,
            "this setup presents {}; every install of a setup presents the same model, so set \
             up {model} on another USB",
            record.model
        );
    }
    ensure!(
        record.installs.len() < MAX_INSTALLS,
        "the startup choices list at most {MAX_INSTALLS} installs"
    );
    let host = environment.host;
    let (Some(target), Some(nor)) = (&command.target, &command.nor) else {
        bail!("an install needs --target and --nor");
    };
    let usb_disk = host.volume(&record.esp)?.disk;
    let checked = installed::check(
        host,
        &installed::Request {
            apple_region: target,
            nor,
            serial: command.disk_serial.as_deref(),
            erase_target: command.erase_target,
            initialize_nor: command.initialize_nor,
            dram_bytes: BundleOptions::default().dram_size,
            usb_disk: usb_disk.as_deref(),
        },
    )?;
    for install in &record.installs {
        let guids = [&install.disk.apple_region_guid, &install.disk.nor_guid];
        ensure!(
            !guids.contains(&&checked.disk.apple_region_guid)
                && !guids.contains(&&checked.disk.nor_guid),
            "{target} or {nor} already belongs to install \"{}\"",
            install.name
        );
    }
    let name = match &command.install {
        Some(name) => name.clone(),
        None if record.installs.is_empty() => FIRST_NAME.into(),
        None => (2..)
            .map(|n| format!("{FIRST_NAME} {n}"))
            .find(|name| record.installs.iter().all(|i| &i.name != name))
            .expect("a free name"),
    };
    check_name(&name)?;
    ensure!(
        record.installs.iter().all(|i| i.name != name),
        "this setup already has an install named {name:?}"
    );
    let mut notes = checked.notes.clone();
    // The first install takes over the setup's own machine, which kept no
    // state, unless the partition holds an earlier machine's.
    let takes_over = record
        .installs
        .is_empty()
        .then_some(record.ecid)
        .flatten()
        .filter(|_| command.ecid.is_none() && !checked.sep_provisioned);
    let ecid = machine_ecid(
        command.ecid,
        takes_over,
        checked.sep_provisioned,
        command.new_ecid,
        &mut notes,
    )?;
    ensure!(
        record.installs.iter().all(|i| i.ecid != Some(ecid)),
        "ECID {ecid} already belongs to another install of this setup"
    );
    let install = Install {
        name: name.clone(),
        ecid: Some(ecid),
        disk: checked.disk.clone(),
    };
    let mut next = record.clone();
    next.installs.push(install.clone());
    if next.installs.len() == 1 {
        next.ecid = Some(ecid);
    }
    let stale = next.drop_stale_bundles();
    let missing = next.missing_bundles(&record.build);
    let prepared: Vec<Prepared> = if missing.is_empty() {
        Vec::new()
    } else {
        let Some(ipsw) = command.optional_image()? else {
            bail!(
                "install \"{name}\" is a new machine (ECID {ecid}) and needs its own recoveryOS \
                 bundle: pass the macOS {} restore image with --ipsw or --fetch",
                record.build
            );
        };
        let (_, _, prepared) = prepare_bundles(
            environment,
            &ipsw,
            &record.model,
            Some(&record.build),
            &missing,
        )?;
        check_space(host, &record.volume, &prepared)?;
        prepared
    };
    let mut text = String::new();
    writeln!(text, "Add install \"{name}\" to {}:", record.esp.display())?;
    writeln!(text, "  ECID           {ecid}")?;
    let disk = &checked.disk;
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
    for bundle in &prepared {
        writeln!(
            text,
            "  recoveryOS     {} ({:.1} GB)",
            bundle::directory(
                &record.volume,
                &bundle.build,
                bundle.ecid,
                record.bundle_schema
            )
            .display(),
            bundle.bytes as f64 / 1e9
        )?;
    }
    writeln!(
        text,
        "  choices.cfg    lists \"{name}\" and its System Recovery{}",
        if next.installs.len() > 1 {
            "; the startup choices open at every boot"
        } else {
            ""
        }
    )?;
    if checked.nor_image.is_some() {
        writeln!(
            text,
            "  disks          fresh machine state (NOR image or SEP area) on {}",
            disk.nor
        )?;
    }
    for kept in &stale {
        writeln!(
            text,
            "  remove         {}",
            bundle::directory(&record.volume, &kept.build, kept.ecid, kept.schema).display()
        )?;
    }
    for note in &notes {
        writeln!(text, "  note           {note}")?;
    }
    if command.dry_run {
        text.push_str("Dry run: nothing was changed.\n");
        return Ok(text);
    }
    copy_bundles(&mut next, &prepared)?;
    write_record(&next.esp.clone(), &next)?;
    if let Some(image) = &checked.nor_image {
        installed::initialize_nor(host, &checked.disk, image)?;
    }
    publish(&mut next)?;
    write_record(&next.esp.clone(), &next)?;
    super::remove_bundles(&next, &stale)?;
    text.push_str("Done.\n");
    Ok(text)
}

/// Settings of an existing setup: the default install, removing one, the
/// TSS opt-in and the startup choices' timeout.
pub(super) fn configure(environment: &Environment<'_>, command: &Setup) -> Result<String> {
    let mut record = read_record(environment, &command.usb)?;
    check_installed_efi(environment, &record)?;
    super::update::ready(&record, |_| false)?;
    let mut text = format!("Stela setup on {}:\n", record.esp.display());
    let mut removed_bundles = Vec::new();
    if let Some(name) = &command.remove_install {
        let install = record.install(Some(name))?.clone();
        record.installs.retain(|i| i.name != *name);
        if record.default_install.as_deref() == Some(name.as_str()) {
            record.default_install = None;
        }
        if record.installs.is_empty() {
            record.ecid = install.ecid.or(record.ecid);
        }
        writeln!(
            text,
            "  remove         install \"{name}\"; {} and {} keep macOS, its NVRAM and SEP \
             state{}",
            install.disk.apple_region,
            install.disk.nor,
            install
                .ecid
                .map(|ecid| format!(" (ECID {ecid}: add it again with --ecid {ecid})"))
                .unwrap_or_default()
        )?;
        removed_bundles = record.drop_stale_bundles();
        for kept in &removed_bundles {
            writeln!(
                text,
                "  remove         {}",
                bundle::directory(&record.volume, &kept.build, kept.ecid, kept.schema).display()
            )?;
        }
    }
    if let Some(name) = &command.default_install {
        record.install(Some(name))?;
        record.default_install = Some(name.clone());
        writeln!(text, "  default        install \"{name}\" boots by default")?;
    }
    if command.tss || command.no_tss {
        record.tss = command.tss;
        if record.tss {
            writeln!(text, "  TSS            on. {}", tss_note())?;
        } else {
            writeln!(
                text,
                "  TSS            off: nothing is sent to Apple's signing server"
            )?;
        }
    }
    if let Some(seconds) = command.chooser_timeout {
        record.chooser_timeout = Some(seconds);
        writeln!(text, "  choices        wait {seconds} s")?;
    }
    record.choices_text()?;
    if command.dry_run {
        text.push_str("Dry run: nothing was changed.\n");
        return Ok(text);
    }
    publish(&mut record)?;
    write_record(&record.esp.clone(), &record)?;
    super::remove_bundles(&record, &removed_bundles)?;
    text.push_str("Done.\n");
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecids_are_kept_and_changed_only_when_asked() {
        let mut notes = Vec::new();
        let (a, b) = (Ecid(0xa), Ecid(0xb));
        assert_eq!(
            machine_ecid(None, Some(a), true, false, &mut notes).unwrap(),
            a
        );
        assert_eq!(
            machine_ecid(Some(a), Some(a), true, false, &mut notes).unwrap(),
            a
        );
        assert!(machine_ecid(Some(b), Some(a), false, false, &mut notes).is_err());
        assert_eq!(
            machine_ecid(Some(b), Some(a), false, true, &mut notes).unwrap(),
            b
        );
        let error = machine_ecid(None, None, true, false, &mut notes).unwrap_err();
        assert!(error.to_string().contains("--ecid"), "{error}");
        assert_eq!(
            machine_ecid(Some(b), None, true, false, &mut notes).unwrap(),
            b
        );
        assert!(notes.is_empty());
        machine_ecid(None, None, true, true, &mut notes).unwrap();
        assert!(notes[0].contains("orphaned"));
        assert!(check_name("macOS 2").is_ok());
        for bad in ["", " macOS", "a\tb", &"x".repeat(30)] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
    }
}
