//! The PC's own disk for an installed macOS: the partition whose bytes are
//! the Mac's internal SSD (ANS2 backing, `--storage`, and the disk the
//! installed system's Preboot volume is read from, `--preboot`) and the
//! machine state (`--nor`): its NOR flash, where NVRAM persists, then the
//! SEP's state and the boot log. The machine state is either a partition of
//! its own or, when setup is given only `--target`, the Apple region's last
//! bytes (`stela_runtime::pc::machine_state`): the boot options then name
//! the Apple region as `--nor` too, and `stela.efi` gives the guest only the
//! bytes before them, as a Mac keeps NVRAM and the SEP's storage off its
//! internal SSD. An existing guest disk that spans the whole partition is
//! never converted, since the tail would truncate it.
//!
//! Setup checks them and writes neither, except that `--initialize-nor`
//! writes a fresh NOR image over a NOR area that is neither blank nor a NOR
//! image, and blanks a SEP area that is neither blank nor a SEP roots record. recoveryOS's Disk Utility and Reinstall macOS write the
//! Apple region, as on a Mac; a region that holds anything but a guest disk
//! or zeros is used only with `--erase-target`, so no host data is lost by
//! accident. Every later Stela or macOS update keeps both partitions.
use super::ecid::Ecid;
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
    pc::{boot_log, machine_state},
};

const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
/// LBA 1 at 512-byte or 4096-byte blocks.
const GPT_HEADER_OFFSETS: [u64; 2] = [512, 4096];
const PROBE_BYTES: usize = 8192;
/// The bytes at the start of an Apple region that `--erase-target` clears
/// of another file system: the signatures every host OS finds one by (APFS's
/// container superblock in block 0, HFS+'s and ext4's at 1 KiB, NTFS's and
/// FAT's boot sector) lie in its first MiB.
const FOREIGN_HEAD_BYTES: usize = 1 << 20;

/// The installed disk, as `stela.cfg` names it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct InstalledDisk {
    pub(super) apple_region: String,
    pub(super) apple_region_serial: String,
    pub(super) apple_region_guid: String,
    pub(super) nor: String,
    pub(super) nor_serial: String,
    pub(super) nor_guid: String,
    /// The machine state's byte offset in the Apple region, when it lives in
    /// the region's tail (`pc::machine_state`); the `nor` fields then name
    /// the Apple region. None for a machine-state partition of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) machine_state_offset: Option<u64>,
    /// The Apple region is a partition of the setup USB, and every PC disk
    /// is the Mac's external drive (`--external-disks`), which recoveryOS
    /// partitions, formats and installs macOS onto.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub(super) external_disks: bool,
}

impl InstalledDisk {
    /// The partitions the install keeps, for messages.
    pub(super) fn partitions(&self) -> String {
        match self.machine_state_offset {
            Some(_) => self.apple_region.clone(),
            None => format!("{} and {}", self.apple_region, self.nor),
        }
    }

    /// Where the machine state is, for messages.
    pub(super) fn state_description(&self) -> String {
        match self.machine_state_offset {
            Some(offset) => format!(
                "the tail of {} from byte {offset:#x}, outside the Mac's SSD (serial {}, \
                 partition {})",
                self.apple_region, self.apple_region_serial, self.apple_region_guid
            ),
            None => format!(
                "{} (serial {}, partition {})",
                self.nor, self.nor_serial, self.nor_guid
            ),
        }
    }

    /// The engine options that boot it: macOS from its Preboot volume, or
    /// recoveryOS from `recovery` as NVRAM chooses. The bundle `stela.efi`
    /// builds from Preboot carries the machine's `ecid`.
    pub(super) fn options(&self, recovery: &str, ecid: Option<Ecid>) -> String {
        let region = self.region_target();
        let ecid = ecid
            .map(|ecid| format!(" --ecid {ecid}"))
            .unwrap_or_default();
        format!(
            "--system --storage {region} --nor {} --preboot {region} --recovery-bundle \
             {recovery}{ecid}{}",
            self.nor_target(),
            self.external()
        )
    }

    /// The options of its System Recovery, as `stela.efi` routes a
    /// recoveryOS choice of NVRAM (`boot_selection::route`): the disk and
    /// NVRAM stay, `--bundle` replaces `--preboot`.
    pub(super) fn recovery_options(&self, recovery: &str, ecid: Option<Ecid>) -> String {
        let ecid = ecid
            .map(|ecid| format!(" --ecid {ecid}"))
            .unwrap_or_default();
        format!(
            "--system --storage {} --nor {} --bundle {recovery}{ecid}{}",
            self.region_target(),
            self.nor_target(),
            self.external()
        )
    }

    fn external(&self) -> &'static str {
        if self.external_disks {
            " --external-disks"
        } else {
            ""
        }
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
    AppleRegion,
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
        Role::AppleRegion => (
            &disk.apple_region,
            &disk.apple_region_serial,
            &disk.apple_region_guid,
            "Apple region",
        ),
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
            Role::AppleRegion => "--target",
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

/// Where a machine's state is: a partition, and the byte offset and length
/// of its layout (the NOR image, the SEP's area, the boot log) in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StateArea {
    pub(super) identifier: String,
    pub(super) offset: u64,
    pub(super) bytes: u64,
}

impl StateArea {
    pub(super) fn read(&self, host: &dyn Host, at: u64, length: usize) -> Result<Vec<u8>> {
        self.check(at, length)?;
        host.read(&self.identifier, self.offset + at, length)
    }

    pub(super) fn write(&self, host: &dyn Host, at: u64, data: &[u8]) -> Result<()> {
        self.check(at, data.len())?;
        host.write(&self.identifier, self.offset + at, data)
    }

    fn check(&self, at: u64, length: usize) -> Result<()> {
        ensure!(
            at.checked_add(length as u64)
                .is_some_and(|end| end <= self.bytes),
            "{} bytes at {at:#x} are outside {}'s {:#x}-byte machine state",
            length,
            self.identifier,
            self.bytes
        );
        Ok(())
    }

    /// The area, for messages: the partition, or where in it the tail is.
    pub(super) fn describe(&self) -> String {
        if self.offset == 0 {
            self.identifier.clone()
        } else {
            format!("{} from byte {:#x}", self.identifier, self.offset)
        }
    }
}

/// The confirmed machine state of `disk` (`confirm` with [`Role::Nor`]):
/// its partition, or the Apple region's tail, which must still start where
/// the record says, so a resized partition is never written.
pub(super) fn state_area(
    host: &dyn Host,
    disk: &InstalledDisk,
    explicit: Option<&str>,
) -> Result<StateArea> {
    let identifier = confirm(host, disk, Role::Nor, explicit)?;
    let bytes = host.partition(&identifier)?.bytes;
    let Some(recorded) = disk.machine_state_offset else {
        return Ok(StateArea {
            identifier,
            offset: 0,
            bytes,
        });
    };
    let layout = machine_state::split(bytes).map_err(|e| anyhow::anyhow!("{identifier}: {e}"))?;
    ensure!(
        layout.state_offset() == recorded,
        "{identifier} holds {bytes:#x} bytes, so its machine state would start at {:#x}, not \
         at the recorded {recorded:#x}: the partition was resized, and stela.efi would no \
         longer find its NVRAM and SEP state. Restore its size, or restore a --backup-state \
         file after setting the install up again.",
        layout.state_offset()
    );
    Ok(StateArea {
        identifier,
        offset: recorded,
        bytes: layout.state_bytes,
    })
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
    /// A machine-state partition of its own; without one the machine state
    /// lives in the Apple region's tail.
    pub(super) nor: Option<&'a str>,
    pub(super) serial: Option<&'a str>,
    pub(super) erase_target: bool,
    pub(super) initialize_nor: bool,
    /// The setup USB's whole disk, which holds neither partition, unless
    /// the Apple region is the USB's own (`external_disks`).
    pub(super) usb_disk: Option<&'a str>,
    /// The Apple region is a partition of the setup USB, and the PC's disks
    /// are the Mac's external drives.
    pub(super) external_disks: bool,
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
    /// The region holds another file system, which [`erase_foreign`]
    /// clears: the partition as found, mounted or not.
    pub(super) foreign: Option<PartitionInfo>,
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

/// The bytes a guest disk's GPT spans from the partition's start: past its
/// last usable block and its backup header. None when the probe holds no
/// GPT header.
fn guest_disk_bytes(head: &[u8]) -> Option<u64> {
    GPT_HEADER_OFFSETS.iter().find_map(|&block| {
        let header = head.get(block as usize..block as usize + 56)?;
        if &header[..GPT_SIGNATURE.len()] != GPT_SIGNATURE {
            return None;
        }
        let word = |at: usize| u64::from_le_bytes(header[at..at + 8].try_into().unwrap());
        let (backup, last_usable) = (word(32), word(48));
        backup
            .max(last_usable)
            .checked_add(1)
            .and_then(|blocks| blocks.checked_mul(block))
    })
}

/// `identifier` as a partition Stela may own. A mounted one is refused,
/// unless `erasing` says setup erases it anyway, after unmounting it.
fn usable(
    host: &dyn Host,
    identifier: &str,
    role: &str,
    usb_disk: Option<&str>,
    erasing: bool,
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
    if erasing {
        return Ok(info);
    }
    if let Some(mount) = &info.mount {
        bail!(
            "{identifier} is mounted at {}: the {role} is a raw partition Stela owns. Move \
             anything you keep elsewhere, then pass --erase-target, which unmounts and erases it.",
            mount.display()
        );
    }
    if let Some(container) = &info.container {
        bail!(
            "{identifier} backs APFS container {container}, whose volumes are mounted: the {role} \
             is a raw partition Stela owns. Move anything you keep elsewhere, then pass \
             --erase-target, which unmounts and erases it; the container of the running system \
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
        cpu.entropy,
        "this PC's CPU has neither RDSEED nor RDRAND, which the kernel's seeds need"
    );
    ensure!(
        request.nor != Some(request.apple_region),
        "the Apple region and a NOR partition of its own are two partitions; leave out --nor to \
         keep the machine state in the Apple region's last {} MiB",
        machine_state::MACHINE_STATE_BYTES >> 20
    );
    let region = usable(
        host,
        request.apple_region,
        "Apple region",
        request.usb_disk.filter(|_| !request.external_disks),
        request.erase_target,
    )?;
    // Without `--nor`, the guest's SSD is the region less its tail.
    let split = match request.nor {
        Some(_) => None,
        None => Some(
            machine_state::split(region.bytes)
                .map_err(|e| anyhow::anyhow!("{}: {e}", region.identifier))?,
        ),
    };
    let ssd_bytes = split.map_or(region.bytes, |split| split.namespace_bytes);
    ensure!(
        ssd_bytes >= DEFAULT_MIN_APPLE_BYTES,
        "{} holds {:.1} GB{}; macOS needs an Apple region of at least {} GB",
        region.identifier,
        ssd_bytes as f64 / 1e9,
        if split.is_some() {
            " before the machine state in its last bytes"
        } else {
            ""
        },
        DEFAULT_MIN_APPLE_BYTES / 1_000_000_000
    );
    let found = contents(host, &region.identifier)?;
    let foreign = matches!(found, Contents::Other).then(|| region.clone());
    match found {
        Contents::GuestDisk => {
            if let Some(split) = split {
                let head = host.read(&region.identifier, 0, PROBE_BYTES)?;
                let spans = guest_disk_bytes(&head);
                ensure!(
                    spans.is_some_and(|bytes| bytes <= split.namespace_bytes),
                    "{} holds a guest disk that spans {}, past the {:#x} bytes the Mac's SSD \
                     keeps when the machine state lives in the partition's last bytes. Its \
                     install is not converted: that would truncate the disk and overwrite its \
                     backup GPT. Keep its machine state on a partition of its own with --nor.",
                    region.identifier,
                    spans.map_or_else(
                        || "an unreadable size".into(),
                        |bytes| format!("{bytes:#x} bytes")
                    ),
                    split.namespace_bytes
                );
            }
            notes.push(format!(
                "{} already holds a guest disk; it is kept and booted",
                region.identifier
            ))
        }
        Contents::Blank => notes.push(format!(
            "{} is blank: install macOS onto it from recoveryOS (Disk Utility, then Reinstall \
             macOS)",
            region.identifier
        )),
        Contents::Other if request.erase_target => notes.push(format!(
            "{} holds other data, which setup erases (--erase-target): left in place, the PC's \
             own OS would mount its file system and clear the free space it sees, Stela's \
             machine state included",
            region.identifier
        )),
        Contents::Other => bail!(
            "{} holds data that is not a Stela guest disk; installing macOS onto it would erase \
             it. Pass --erase-target to use it anyway.",
            region.identifier
        ),
    }
    // The machine state: a partition of its own, or the region's tail.
    let (nor, area, label) = match (request.nor, split) {
        (Some(identifier), _) => {
            let nor = usable(host, identifier, "NOR", request.usb_disk, false)?;
            let area = StateArea {
                identifier: nor.identifier.clone(),
                offset: 0,
                bytes: nor.bytes,
            };
            let label = nor.identifier.clone();
            (nor, area, label)
        }
        (None, Some(split)) => {
            let area = StateArea {
                identifier: region.identifier.clone(),
                offset: split.state_offset(),
                bytes: split.state_bytes,
            };
            let label = format!(
                "{}'s machine state (its last {:#x} bytes)",
                region.identifier, split.state_bytes
            );
            notes.push(format!(
                "the machine state (NVRAM, the SEP's state and the boot log) lives in the last \
                 {:#x} bytes of {}, from byte {:#x}; recoveryOS sees the {:#x} bytes before it \
                 as the Mac's SSD",
                split.state_bytes,
                region.identifier,
                split.state_offset(),
                split.namespace_bytes
            ));
            (region.clone(), area, label)
        }
        (None, None) => unreachable!("a split without --nor"),
    };
    let state_bytes = CAPACITY + sep_state::BYTES as usize;
    ensure!(
        area.bytes >= state_bytes as u64,
        "{} is smaller than the {state_bytes:#x} bytes of the 1 MiB NOR image and the SEP's \
         state ({:#x} bytes also keep the optional boot log)",
        nor.identifier,
        boot_log::PARTITION_BYTES
    );
    notes.push(if area.bytes >= boot_log::PARTITION_BYTES {
        format!("{label} also keeps stela.efi's boot log (`stela setup --boot-log`)")
    } else {
        format!(
            "{label} holds {:#x} bytes: it boots without a boot log, which is optional and needs \
             a partition of at least {:#x} bytes",
            area.bytes,
            boot_log::PARTITION_BYTES
        )
    });
    let bytes = area.read(host, 0, state_bytes)?;
    let (nor_bytes, sep_area) = bytes.split_at(CAPACITY);
    let blank = nor_bytes.iter().all(|&b| b == 0);
    let image = (!blank)
        .then(|| Image::from_bytes(nor_bytes.to_vec()))
        .transpose();
    let nor_foreign = match image {
        _ if blank => {
            notes.push(format!(
                "{label} is blank: stela.efi writes a fresh NOR image there at its first boot"
            ));
            false
        }
        Ok(Some(image)) if image.current_bank().is_ok() => {
            notes.push(format!("{label} holds a NOR image; its NVRAM is kept"));
            false
        }
        _ if request.initialize_nor => {
            notes.push(format!(
                "{label} is neither blank nor a NOR image: setup writes a fresh NOR image \
                 (--initialize-nor)"
            ));
            true
        }
        _ => bail!(
            "{label} is neither blank nor a NOR image, so stela.efi would refuse it. Pass \
             --initialize-nor to write a fresh NOR image over it."
        ),
    };
    let mut sep_provisioned = false;
    let sep_foreign = match sep_state::blank(&sep_area[..sep_state::ROOTS_BYTES]) {
        Ok(true) => false,
        Ok(false) => {
            sep_provisioned = true;
            notes.push(format!(
                "{label} holds SEP state; its anti-replay store is kept"
            ));
            false
        }
        Err(_) if request.initialize_nor => {
            notes.push(format!(
                "{label} holds other bytes after its NOR image: setup blanks the SEP's state \
                 (--initialize-nor)"
            ));
            true
        }
        Err(error) => bail!(
            "{label}: {error}, so stela.efi would refuse it. Pass --initialize-nor to blank the \
             SEP's state."
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
        machine_state_offset: split.map(|split| split.state_offset()),
        external_disks: request.external_disks,
    };
    Ok(Checked {
        disk,
        nor_image,
        sep_provisioned,
        foreign,
        notes,
    })
}

/// The Apple region of `disk`, when it holds another file system than a
/// guest disk: the PC's own OS mounts it and clears its free space, Stela's
/// machine state included.
pub(super) fn foreign(host: &dyn Host, disk: &InstalledDisk) -> Result<Option<PartitionInfo>> {
    let identifier = confirm(host, disk, Role::AppleRegion, None)?;
    Ok(match contents(host, &identifier)? {
        Contents::Other => Some(host.partition(&identifier)?),
        Contents::Blank | Contents::GuestDisk => None,
    })
}

/// Clear the other file system at the start of `region`, unmounting it
/// first, which `--erase-target` gave up.
pub(super) fn erase_foreign(host: &dyn Host, region: &PartitionInfo) -> Result<()> {
    if region.mount.is_some() || region.container.is_some() {
        host.unmount(region)?;
    }
    host.write(&region.identifier, 0, &vec![0; FOREIGN_HEAD_BYTES])
        .with_context(|| format!("erasing the file system on {}", region.identifier))
}

/// Write the machine-state bytes `check` planned: a fresh NOR image, a
/// blank SEP area, or both, at the start of the machine state.
pub(super) fn initialize_nor(host: &dyn Host, disk: &InstalledDisk, image: &[u8]) -> Result<()> {
    let area = state_area(host, disk, None)?;
    area.write(host, 0, image)
        .with_context(|| format!("writing a fresh NOR image to {}", area.describe()))
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
    let area = state_area(host, disk, None)?;
    let bytes = area.read(host, 0, CAPACITY)?;
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
        area.write(host, 0, image.bytes())?;
    } else {
        for offset in sectors {
            area.write(
                host,
                offset as u64,
                &image.bytes()[offset..offset + SECTOR_SIZE],
            )?;
        }
    }
    Ok(changes)
}
