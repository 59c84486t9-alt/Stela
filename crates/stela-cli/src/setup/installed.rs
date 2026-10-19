//! The PC's own disk for an installed macOS: the partition whose bytes are
//! the Mac's internal SSD (ANS2 backing, `--storage`, and the disk the
//! installed system's Preboot volume is read from, `--preboot`) and the
//! machine-state partition (`--nor`): its NOR flash, where NVRAM persists,
//! then the SEP's state.
//!
//! Setup checks them and writes neither, except that `--initialize-nor`
//! writes a fresh NOR image over a NOR area that is neither blank nor a NOR
//! image, and blanks a SEP area that is neither blank nor a SEP roots record. recoveryOS's Disk Utility and Reinstall macOS write the
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
    machine::apple::sep_state,
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
        let region = self.region_target();
        format!(
            "--system --storage {region} --nor {} --preboot {region} --recovery-bundle \
             {recovery} --ram-bytes {dram_bytes:#x}",
            self.nor_target()
        )
    }

    /// The options of its System Recovery, as `stela.efi` routes a
    /// recoveryOS choice of NVRAM (`boot_selection::route`): the disk and
    /// NVRAM stay, `--bundle` replaces `--preboot`.
    pub(super) fn recovery_options(&self, recovery: &str, dram_bytes: u64) -> String {
        format!(
            "--system --storage {} --nor {} --bundle {recovery} --ram-bytes {dram_bytes:#x}",
            self.region_target(),
            self.nor_target()
        )
    }

    fn region_target(&self) -> String {
        format!("{}:{}", self.apple_region_serial, self.apple_region_guid)
    }

    fn nor_target(&self) -> String {
        format!("{}:{}", self.nor_serial, self.nor_guid)
    }
}

/// Which of an installed disk's partitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Role {
    Nor,
}

/// The partition identifier that is still `disk`'s partition in `role`:
/// `explicit` when the user names one, else the recorded identifier, which
/// must carry the recorded GUID, sit on a disk with the recorded serial (when
/// this computer reports one) and be unmounted. Every write setup makes to a
/// partition goes through this, so a renumbered disk or another partition
/// is never written.
pub(super) fn confirm(
    host: &dyn Host,
    disk: &InstalledDisk,
    role: Role,
    explicit: Option<&str>,
) -> Result<String> {
    let (recorded, serial, guid, what) = match role {
        Role::Nor => (&disk.nor, &disk.nor_serial, &disk.nor_guid, "NOR partition"),
    };
    let identifier = explicit.unwrap_or(recorded);
    let info = host
        .partition(identifier)
        .with_context(|| format!("cannot inspect {identifier}"))?;
    ensure!(
        info.guid.eq_ignore_ascii_case(guid),
        "{identifier} is not this install's {what} (partition {guid}); its identifier may have \
         changed. Find the partition with that GUID (`diskutil info`) and pass it with {}",
        match role {
            Role::Nor => "--nor",
        }
    );
    if let Some(found) = host.serial(&info.disk)? {
        ensure!(
            found == *serial,
            "{identifier} is on a disk with serial {found:?}, not this install's {serial:?}"
        );
    }
    ensure!(
        info.mount.is_none(),
        "{identifier} is mounted; this install's {what} is a raw partition Stela owns"
    );
    Ok(identifier.to_owned())
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

/// The checked disk, what setup will write to its machine-state partition
/// from its start, and notes.
#[derive(Debug)]
pub(super) struct Checked {
    pub(super) disk: InstalledDisk,
    pub(super) nor_image: Option<Vec<u8>>,
    /// The SEP area holds an earlier machine's state, which is bound to
    /// that machine's ECID.
    pub(super) sep_provisioned: bool,
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
    let state_bytes = CAPACITY + sep_state::BYTES as usize;
    ensure!(
        nor.bytes >= state_bytes as u64,
        "{} is smaller than the {state_bytes:#x} bytes of the 1 MiB NOR image and the SEP's state",
        nor.identifier
    );
    let bytes = host.read(&nor.identifier, 0, state_bytes)?;
    let (nor_bytes, sep_area) = bytes.split_at(CAPACITY);
    let blank = nor_bytes.iter().all(|&b| b == 0);
    let image = (!blank)
        .then(|| Image::from_bytes(nor_bytes.to_vec()))
        .transpose();
    let nor_foreign = match image {
        _ if blank => {
            notes.push(format!(
                "{} is blank: stela.efi writes a fresh NOR image there at its first boot",
                nor.identifier
            ));
            false
        }
        Ok(Some(image)) if image.current_bank().is_ok() => {
            notes.push(format!(
                "{} holds a NOR image; its NVRAM is kept",
                nor.identifier
            ));
            false
        }
        _ if request.initialize_nor => {
            notes.push(format!(
                "{} is neither blank nor a NOR image: setup writes a fresh NOR image \
                 (--initialize-nor)",
                nor.identifier
            ));
            true
        }
        _ => bail!(
            "{} is neither blank nor a NOR image, so stela.efi would refuse it. Pass \
             --initialize-nor to write a fresh NOR image over it.",
            nor.identifier
        ),
    };
    let mut sep_provisioned = false;
    let sep_foreign = match sep_state::blank(&sep_area[..sep_state::ROOTS_BYTES]) {
        Ok(true) => false,
        Ok(false) => {
            sep_provisioned = true;
            notes.push(format!(
                "{} holds SEP state; its anti-replay store is kept",
                nor.identifier
            ));
            false
        }
        Err(_) if request.initialize_nor => {
            notes.push(format!(
                "{} holds other bytes after its NOR image: setup blanks the SEP's state \
                 (--initialize-nor)",
                nor.identifier
            ));
            true
        }
        Err(error) => bail!(
            "{}: {error}, so stela.efi would refuse it. Pass --initialize-nor to blank the \
             SEP's state.",
            nor.identifier
        ),
    };
    let nor_image = (nor_foreign || sep_foreign).then(|| {
        let mut plan = if nor_foreign {
            Image::fresh().bytes().to_vec()
        } else {
            nor_bytes.to_vec()
        };
        if sep_foreign {
            plan.resize(state_bytes, 0);
        } else {
            plan.extend_from_slice(sep_area);
        }
        plan
    });
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
        sep_provisioned,
        notes,
    })
}

/// Write the machine-state bytes `check` planned: a fresh NOR image, a
/// blank SEP area, or both.
pub(super) fn initialize_nor(host: &dyn Host, disk: &InstalledDisk, image: &[u8]) -> Result<()> {
    let nor = confirm(host, disk, Role::Nor, None)?;
    host.write(&nor, 0, image)
        .with_context(|| format!("writing a fresh NOR image to {nor}"))
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
    let nor = confirm(host, disk, Role::Nor, None)?;
    let bytes = host.read(&nor, 0, CAPACITY)?;
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
        host.write(&nor, 0, image.bytes())?;
    } else {
        for offset in sectors {
            host.write(
                &nor,
                offset as u64,
                &image.bytes()[offset..offset + SECTOR_SIZE],
            )?;
        }
    }
    Ok(changes)
}
