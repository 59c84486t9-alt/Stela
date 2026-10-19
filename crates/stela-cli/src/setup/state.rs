//! A machine's state on its machine-state partition: the NOR image (NVRAM)
//! and, after it, the SEP's area (its UID/GID roots and anti-replay store,
//! `stela_runtime::machine::apple::sep_state`, which the SEP model owns;
//! setup only copies the area whole and never reads its keys).
//!
//! - `--reset-nvram` writes a fresh NOR image, as clearing a Mac's NVRAM
//!   does; the SEP's area is kept.
//! - `--backup-state FILE` copies the NOR image and the SEP's area to a new
//!   file only its owner can read: the area holds the machine's keys. The
//!   file also names the machine (ECID, partition and serial) and carries
//!   the SHA-256 of what it holds.
//! - `--restore-state FILE` writes such a file back to the machine it came
//!   from, and to no other.
//! - `--boot-log` prints the boot log `stela.efi` keeps after the SEP's area
//!   on a partition of at least `boot_log::PARTITION_BYTES`
//!   (`stela_runtime::pc::boot_log`), and writes nothing.
//!
//! Both writes need the NOR partition named again with `--nor`, and that
//! partition must still be the install's (`installed::confirm`).
use super::{Environment, Record, Setup, check_installed_efi, ecid::Ecid, installed, machines};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    fs,
    io::{BufRead, Read, Write},
    path::Path,
};
use stela_loader::boot_selection;
use stela_runtime::{
    machine::apple::{
        nor::{CAPACITY, Image, nvram::Variables},
        sep_state,
    },
    pc::boot_log,
};

const MAGIC: &str = "STELA MACHINE STATE 1";
const STATE_BYTES: usize = CAPACITY + sep_state::BYTES as usize;

/// What a backup file says of itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Header {
    install: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ecid: Option<Ecid>,
    model: String,
    nor_serial: String,
    nor_guid: String,
    nor_bytes: usize,
    sep_bytes: usize,
    sha256: String,
}

/// The NVRAM a NOR image holds.
pub(super) enum Nvram {
    Blank,
    Valid(Variables),
    Invalid(String),
}

pub(super) fn nvram(bytes: &[u8]) -> Nvram {
    if bytes.iter().all(|&b| b == 0) {
        return Nvram::Blank;
    }
    let parsed = Image::from_bytes(bytes.to_vec()).and_then(|image| {
        let bank = image.current_bank()?;
        Variables::parse(image.bank(bank)?)
    });
    match parsed {
        Ok(variables) => Nvram::Valid(variables),
        Err(error) => Nvram::Invalid(error.into()),
    }
}

/// What the SEP's area holds.
pub(super) fn sep(area: &[u8]) -> Result<bool, &'static str> {
    sep_state::blank(&area[..sep_state::ROOTS_BYTES]).map(|blank| !blank)
}

/// What the next boot of an NVRAM is, as `stela.efi` will choose it.
pub(super) fn next_boot(variables: &Variables) -> String {
    match boot_selection::select(variables) {
        Ok(selection) => {
            let target = match selection.target {
                boot_selection::Target::MacOs { safe: false } => "macOS".into(),
                boot_selection::Target::MacOs { safe: true } => "macOS in safe mode".into(),
                boot_selection::Target::PairedRecovery => {
                    "recoveryOS (Stela's System Recovery bundle)".into()
                }
                boot_selection::Target::SystemRecovery => "System Recovery".into(),
                boot_selection::Target::Upgrade => {
                    "the macOS update staged on the Update volume".to_string()
                }
            };
            if selection.reasons.is_empty() {
                target
            } else {
                format!("{target} ({})", selection.reasons.join(", "))
            }
        }
        Err(error) => format!("refused by stela.efi: {error:#}"),
    }
}

/// The install and confirmed NOR partition a state command acts on; the
/// partition must be named with `--nor` for a write.
fn target<'a>(
    environment: &Environment<'_>,
    record: &'a Record,
    command: &Setup,
    write: bool,
) -> Result<(&'a machines::Install, String)> {
    let install = record.install(command.install.as_deref())?;
    if write {
        ensure!(
            command.nor.is_some(),
            "name install \"{}\"'s NOR partition with --nor (it was {}), so no other partition \
             is written",
            install.name,
            install.disk.nor
        );
    }
    let nor = installed::confirm(
        environment.host,
        &install.disk,
        installed::Role::Nor,
        command.nor.as_deref(),
    )?;
    Ok((install, nor))
}

/// `--reset-nvram`.
pub(super) fn reset_nvram(
    environment: &Environment<'_>,
    record: &Record,
    command: &Setup,
) -> Result<String> {
    check_installed_efi(environment, record)?;
    let (install, nor) = target(environment, record, command, true)?;
    let current = environment.host.read(&nor, 0, CAPACITY)?;
    let mut text = format!("Reset the NVRAM of install \"{}\" ({nor}):\n", install.name);
    match nvram(&current) {
        Nvram::Blank => writeln!(text, "  NVRAM          blank; it is written fresh")?,
        Nvram::Valid(variables) => {
            let count = [
                stela_runtime::machine::apple::nor::nvram::Partition::System,
                stela_runtime::machine::apple::nor::nvram::Partition::Common,
            ]
            .iter()
            .map(|p| variables.list(*p).count())
            .sum::<usize>();
            writeln!(
                text,
                "  NVRAM          {count} variables are removed, boot-volume and boot-args \
                 among any set; macOS's startup disk choice is made again in macOS"
            )?;
        }
        Nvram::Invalid(error) => writeln!(
            text,
            "  NVRAM          unreadable ({error}); it is written fresh"
        )?,
    }
    writeln!(text, "  SEP state      kept")?;
    if command.dry_run {
        text.push_str("Dry run: nothing was changed.\n");
        return Ok(text);
    }
    let fresh = Image::fresh();
    environment.host.write(&nor, 0, fresh.bytes())?;
    ensure!(
        environment.host.read(&nor, 0, CAPACITY)? == fresh.bytes(),
        "{nor} did not read back as written"
    );
    text.push_str("Done.\n");
    Ok(text)
}

/// `--boot-log`: the boot log `stela.efi` keeps after the SEP's area, when
/// the partition holds one.
pub(super) fn boot_log(
    environment: &Environment<'_>,
    record: &Record,
    command: &Setup,
) -> Result<String> {
    let (install, nor) = target(environment, record, command, false)?;
    let bytes = environment.host.partition(&nor)?.bytes;
    ensure!(
        bytes >= boot_log::PARTITION_BYTES,
        "{nor} holds {bytes:#x} bytes; the boot log needs {:#x}, so stela.efi boots install \
         \"{}\" without one",
        boot_log::PARTITION_BYTES,
        install.name
    );
    let region = environment
        .host
        .read(&nor, boot_log::OFFSET, boot_log::LOG_BYTES as usize)?;
    let log = boot_log::read(&region)
        .with_context(|| format!("{nor} has no boot log of install \"{}\"", install.name))?;
    let mut text = format!(
        "Boot log of install \"{}\" ({nor}): {}",
        install.name,
        crate::boot_log::summary(&log)
    );
    text.push_str(&String::from_utf8_lossy(&log.stream));
    if !text.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}

/// `--backup-state FILE`.
pub(super) fn backup(
    environment: &Environment<'_>,
    record: &Record,
    command: &Setup,
    path: &Path,
) -> Result<String> {
    let (install, nor) = target(environment, record, command, false)?;
    ensure!(
        !path.exists(),
        "{} exists; choose a new file for the backup",
        path.display()
    );
    let bytes = environment.host.read(&nor, 0, STATE_BYTES)?;
    let header = Header {
        install: install.name.clone(),
        ecid: install.ecid,
        model: record.model.clone(),
        nor_serial: install.disk.nor_serial.clone(),
        nor_guid: install.disk.nor_guid.clone(),
        nor_bytes: CAPACITY,
        sep_bytes: sep_state::BYTES as usize,
        sha256: hex::encode(Sha256::digest(&bytes)),
    };
    let mut text = format!(
        "Back up the machine state of install \"{}\" ({nor}) to {}:\n",
        install.name,
        path.display()
    );
    if let Some(ecid) = install.ecid {
        writeln!(text, "  ECID           {ecid}")?;
    }
    writeln!(
        text,
        "  holds          the NOR image (NVRAM) and the SEP's area, with the machine's keys: \
         keep the file private; it is created readable by its owner only"
    )?;
    if command.dry_run {
        text.push_str("Dry run: nothing was changed.\n");
        return Ok(text);
    }
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    writeln!(file, "{MAGIC}")?;
    writeln!(file, "{}", serde_json::to_string(&header)?)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    text.push_str("Done.\n");
    Ok(text)
}

fn read_backup(path: &Path) -> Result<(Header, Vec<u8>)> {
    let file = fs::File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut magic = String::new();
    reader.read_line(&mut magic)?;
    ensure!(
        magic.trim_end() == MAGIC,
        "{} is not a Stela machine-state backup",
        path.display()
    );
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let header: Header = serde_json::from_str(line.trim_end())
        .with_context(|| format!("{} has a damaged header", path.display()))?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    ensure!(
        header.nor_bytes == CAPACITY
            && header.sep_bytes == sep_state::BYTES as usize
            && bytes.len() == STATE_BYTES,
        "{} holds a machine-state layout this stela does not write",
        path.display()
    );
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == header.sha256,
        "{} is damaged: its contents differ from their SHA-256",
        path.display()
    );
    Ok((header, bytes))
}

/// `--restore-state FILE`.
pub(super) fn restore(
    environment: &Environment<'_>,
    record: &Record,
    command: &Setup,
    path: &Path,
) -> Result<String> {
    check_installed_efi(environment, record)?;
    let (header, bytes) = read_backup(path)?;
    let (install, nor) = target(environment, record, command, true)?;
    ensure!(
        header.nor_guid.eq_ignore_ascii_case(&install.disk.nor_guid),
        "{} is the state of partition {}, not install \"{}\"'s {}; a machine's state is \
         restored only to that machine",
        path.display(),
        header.nor_guid,
        install.name,
        install.disk.nor_guid
    );
    match (header.ecid, install.ecid) {
        (Some(saved), Some(current)) if saved != current => bail!(
            "{} is the state of ECID {saved}, but install \"{}\" is ECID {current}",
            path.display(),
            install.name
        ),
        _ => {}
    }
    let current = environment.host.read(&nor, 0, STATE_BYTES)?;
    let mut text = format!(
        "Restore the machine state of install \"{}\" ({nor}) from {}:\n",
        install.name,
        path.display()
    );
    if current == bytes {
        writeln!(text, "  state          already as backed up")?;
        return Ok(text);
    }
    writeln!(
        text,
        "  writes         the NOR image (NVRAM) and the SEP's area as backed up"
    )?;
    writeln!(
        text,
        "  note           this returns the SEP's anti-replay store to the backup's: nonces \
         issued since then are forgotten, which the SEP cannot detect"
    )?;
    if command.dry_run {
        text.push_str("Dry run: nothing was changed.\n");
        return Ok(text);
    }
    environment.host.write(&nor, 0, &bytes)?;
    ensure!(
        environment.host.read(&nor, 0, STATE_BYTES)? == bytes,
        "{nor} did not read back as written"
    );
    text.push_str("Done.\n");
    Ok(text)
}
