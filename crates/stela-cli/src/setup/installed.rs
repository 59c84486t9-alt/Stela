//! The PC's own disk for an installed macOS: the partition whose bytes are
//! the Mac's internal SSD (ANS2 backing, `--storage`, and the disk the
//! installed system's Preboot volume is read from, `--preboot`) and the
//! partition that holds its NOR flash (`--nor`), where NVRAM persists.
//!
//! Setup checks them and writes neither, except that `--initialize-nor`
//! writes a fresh NOR image over a NOR partition that is neither blank nor
//! a NOR image. recoveryOS's Disk Utility and Reinstall macOS write the
//! Apple region, as on a Mac; a region that holds anything but a guest disk
//! or zeros is used only with `--erase-target`, so no host data is lost by
//! accident. Every later Stela or macOS update keeps both partitions.
use super::host::{Host, PartitionInfo};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use stela_loader::boot_selection::{
    BOOT_COMMAND, Command, ONE_TIME_BOOT_COMMAND, RECOVERY_BOOT_MODE, lookup,
};
use stela_runtime::{
    machine::apple::nor::{CAPACITY, Image, SECTOR_SIZE, nvram::Partition, nvram::Variables},
    payload::gpt::DEFAULT_MIN_APPLE_BYTES,
};

/// Memory the PC keeps for itself beyond the guest's DRAM: the engine's
/// heap, translations and the firmware's own.
const HOST_RESERVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
/// LBA 1 at 512-byte or 4096-byte blocks.
const GPT_HEADER_OFFSETS: [u64; 2] = [512, 4096];
const PROBE_BYTES: usize = 8192;

/// The installed disk, as `stela.cfg` names it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct InstalledDisk {
    pub(super) apple_region: String,
    pub(super) apple_region_serial: String,
    pub(super) apple_region_guid: String,
    pub(super) nor: String,
    pub(super) nor_serial: String,
    pub(super) nor_guid: String,
}

impl InstalledDisk {
    /// The engine options that boot it: macOS from its Preboot volume, or
    /// recoveryOS from `recovery` as NVRAM chooses.
    pub(super) fn options(&self, recovery: &str, dram_bytes: u64) -> String {
        let region = format!("{}:{}", self.apple_region_serial, self.apple_region_guid);
        format!(
            "--system --storage {region} --nor {}:{} --preboot {region} --recovery-bundle \
             {recovery} --ram-bytes {dram_bytes:#x}\n",
            self.nor_serial, self.nor_guid
        )
    }
}

/// What `stela.efi` will find in the Apple region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Contents {
    Blank,
    /// A guest disk with a partition table: an installed or installing
    /// system, kept.
    GuestDisk,
    /// Anything else, such as a host file system.
    Other,
}

/// The choices the command line makes for the installed disk.
pub(super) struct Request<'a> {
    pub(super) apple_region: &'a str,
    pub(super) nor: &'a str,
    pub(super) serial: Option<&'a str>,
    pub(super) erase_target: bool,
    pub(super) initialize_nor: bool,
    pub(super) dram_bytes: u64,
    /// The setup USB's whole disk, which holds neither partition.
    pub(super) usb_disk: Option<&'a str>,
}

/// The checked disk, what setup will write to its NOR partition, and notes.
#[derive(Debug)]
pub(super) struct Checked {
    pub(super) disk: InstalledDisk,
    pub(super) nor_image: Option<Vec<u8>>,
    pub(super) notes: Vec<String>,
}

fn contents(host: &dyn Host, partition: &str) -> Result<Contents> {
    let head = host.read(partition, 0, PROBE_BYTES)?;
    if head.iter().all(|&b| b == 0) {
        return Ok(Contents::Blank);
    }
    let gpt = GPT_HEADER_OFFSETS.iter().any(|&offset| {
        head.get(offset as usize..offset as usize + GPT_SIGNATURE.len()) == Some(GPT_SIGNATURE)
    });
    Ok(if gpt {
        Contents::GuestDisk
    } else {
        Contents::Other
    })
}

fn usable(
    host: &dyn Host,
    identifier: &str,
    role: &str,
    usb_disk: Option<&str>,
) -> Result<PartitionInfo> {
    let info = host.partition(identifier)?;
    ensure!(
        !info.guid.is_empty() && !info.disk.is_empty(),
        "{identifier} is not a GUID partition table partition"
    );
    ensure!(
        info.content != "EFI",
        "{identifier} is an EFI system partition; the {role} needs its own partition"
    );
    ensure!(
        usb_disk != Some(info.disk.as_str()),
        "{identifier} is on the setup USB; the {role} belongs on the PC's own disk"
    );
    if let Some(mount) = &info.mount {
        bail!(
            "{identifier} is mounted at {}: the {role} is a raw partition Stela owns. Unmount it \
             (`diskutil unmount {identifier}`) after moving anything you keep elsewhere.",
            mount.display()
        );
    }
    if let Some(container) = &info.container {
        bail!(
            "{identifier} backs APFS container {container}, whose volumes are mounted: the {role} \
             is a raw partition Stela owns. Unmount them (`diskutil unmountDisk {container}`) \
             after moving anything you keep elsewhere; the container of the running system \
             cannot be used."
        );
    }
    Ok(info)
}

fn serial(host: &dyn Host, disk: &str, explicit: Option<&str>) -> Result<String> {
    match (host.serial(disk)?, explicit) {
        (Some(found), Some(given)) if found != given => {
            bail!("{disk} reports serial {found:?}, not {given:?}")
        }
        (Some(found), _) => Ok(found),
        (None, Some(given)) => Ok(given.into()),
        (None, None) => bail!(
            "{disk} reports no serial number, which stela.efi finds it by; pass the serial its \
             NVMe or ATA controller reports with --disk-serial"
        ),
    }
}

/// Check the PC and its installed disk.
pub(super) fn check(host: &dyn Host, request: &Request) -> Result<Checked> {
    let mut notes = Vec::new();
    let cpu = host.cpu()?;
    ensure!(
        cpu.la57,
        "this PC's CPU lacks five-level paging (LA57), which stela.efi's system mode needs"
    );
    ensure!(
        cpu.entropy,
        "this PC's CPU has neither RDSEED nor RDRAND, which the kernel's seeds need"
    );
    let memory = host.memory_bytes()?;
    ensure!(
        memory >= request.dram_bytes + HOST_RESERVE_BYTES,
        "this PC has {:.1} GiB of memory; the guest's {} GiB and Stela need {:.1} GiB",
        memory as f64 / (1u64 << 30) as f64,
        request.dram_bytes >> 30,
        (request.dram_bytes + HOST_RESERVE_BYTES) as f64 / (1u64 << 30) as f64
    );
    ensure!(
        request.apple_region != request.nor,
        "the Apple region and the NOR are two partitions"
    );
    let region = usable(host, request.apple_region, "Apple region", request.usb_disk)?;
    ensure!(
        region.bytes >= DEFAULT_MIN_APPLE_BYTES,
        "{} holds {:.1} GB; macOS needs an Apple region of at least {} GB",
        region.identifier,
        region.bytes as f64 / 1e9,
        DEFAULT_MIN_APPLE_BYTES / 1_000_000_000
    );
    match contents(host, &region.identifier)? {
        Contents::GuestDisk => notes.push(format!(
            "{} already holds a guest disk; it is kept and booted",
            region.identifier
        )),
        Contents::Blank => notes.push(format!(
            "{} is blank: install macOS onto it from recoveryOS (Disk Utility, then Reinstall \
             macOS)",
            region.identifier
        )),
        Contents::Other if request.erase_target => notes.push(format!(
            "{} holds other data, which installing macOS onto it from recoveryOS erases \
             (--erase-target)",
            region.identifier
        )),
        Contents::Other => bail!(
            "{} holds data that is not a Stela guest disk; installing macOS onto it would erase \
             it. Pass --erase-target to use it anyway.",
            region.identifier
        ),
    }
    let nor = usable(host, request.nor, "NOR", request.usb_disk)?;
    ensure!(
        nor.bytes >= CAPACITY as u64,
        "{} is smaller than the 1 MiB NOR image",
        nor.identifier
    );
    let bytes = host.read(&nor.identifier, 0, CAPACITY)?;
    let blank = bytes.iter().all(|&b| b == 0);
    let image = (!blank).then(|| Image::from_bytes(bytes)).transpose();
    let nor_image = match image {
        _ if blank => {
            notes.push(format!(
                "{} is blank: stela.efi writes a fresh NOR image there at its first boot",
                nor.identifier
            ));
            None
        }
        Ok(Some(image)) if image.current_bank().is_ok() => {
            notes.push(format!(
                "{} holds a NOR image; its NVRAM is kept",
                nor.identifier
            ));
            None
        }
        _ if request.initialize_nor => {
            notes.push(format!(
                "{} is neither blank nor a NOR image: setup writes a fresh NOR image \
                 (--initialize-nor)",
                nor.identifier
            ));
            Some(Image::fresh().bytes().to_vec())
        }
        _ => bail!(
            "{} is neither blank nor a NOR image, so stela.efi would refuse it. Pass \
             --initialize-nor to write a fresh NOR image over it.",
            nor.identifier
        ),
    };
    let same_disk = region.disk == nor.disk;
    ensure!(
        request.serial.is_none() || same_disk,
        "--disk-serial names one disk, but the Apple region and the NOR are on {} and {}",
        region.disk,
        nor.disk
    );
    let disk = InstalledDisk {
        apple_region_serial: serial(host, &region.disk, request.serial)?,
        apple_region_guid: region.guid.to_ascii_uppercase(),
        apple_region: region.identifier,
        nor_serial: serial(host, &nor.disk, request.serial)?,
        nor_guid: nor.guid.to_ascii_uppercase(),
        nor: nor.identifier,
    };
    Ok(Checked {
        disk,
        nor_image,
        notes,
    })
}

/// Write the fresh NOR image `check` planned.
pub(super) fn initialize_nor(host: &dyn Host, disk: &InstalledDisk, image: &[u8]) -> Result<()> {
    host.write(&disk.nor, 0, image)
        .with_context(|| format!("writing a fresh NOR image to {}", disk.nor))
}

/// What the next boot is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum NextBoot {
    /// System Recovery: Stela's recoveryOS bundle.
    Recovery,
    /// macOS, clearing a pending recovery request.
    Macos,
}

/// Set the next boot in the NOR's NVRAM as macOS's `nvram` would: a
/// one-time `recover-system` command, or none (also clearing a persistent
/// recovery command and `recovery-boot-mode`). Returns what changed;
/// nothing is written with `dry_run`.
pub(super) fn next_boot(
    host: &dyn Host,
    disk: &InstalledDisk,
    next: NextBoot,
    dry_run: bool,
) -> Result<Vec<String>> {
    let bytes = host.read(&disk.nor, 0, CAPACITY)?;
    let blank = bytes.iter().all(|&b| b == 0);
    let mut image = if blank {
        Image::fresh()
    } else {
        Image::from_bytes(bytes).map_err(anyhow::Error::msg)?
    };
    let current = image.current_bank().map_err(anyhow::Error::msg)?;
    let mut variables = Variables::parse(image.bank(current).map_err(anyhow::Error::msg)?)
        .map_err(anyhow::Error::msg)?;
    let mut changes = Vec::new();
    match next {
        NextBoot::Recovery => {
            let value = Command::RecoverSystem.name().as_bytes();
            variables
                .set(Partition::System, ONE_TIME_BOOT_COMMAND, value)
                .map_err(anyhow::Error::msg)?;
            changes.push("set one-time-boot-command=recover-system".into());
        }
        NextBoot::Macos => {
            let recovery_command = lookup(&variables, BOOT_COMMAND)
                .and_then(|v| Command::parse(v).ok())
                .is_some_and(|c| c != Command::Fsboot && c != Command::FsbootSafe);
            let mut names = vec![ONE_TIME_BOOT_COMMAND, RECOVERY_BOOT_MODE];
            if recovery_command {
                names.push(BOOT_COMMAND);
            }
            for name in names {
                for partition in [Partition::System, Partition::Common] {
                    if variables.remove(partition, name).is_some() {
                        changes.push(format!("remove {}", String::from_utf8_lossy(name)));
                    }
                }
            }
        }
    }
    if changes.is_empty() || dry_run {
        return Ok(changes);
    }
    let bank = variables.encode().map_err(anyhow::Error::msg)?;
    let (_, sectors) = image.save_bank(&bank).map_err(anyhow::Error::msg)?;
    if blank {
        host.write(&disk.nor, 0, image.bytes())?;
    } else {
        for offset in sectors {
            host.write(
                &disk.nor,
                offset as u64,
                &image.bytes()[offset..offset + SECTOR_SIZE],
            )?;
        }
    }
    Ok(changes)
}
