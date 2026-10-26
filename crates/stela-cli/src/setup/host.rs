//! What `stela setup` reads from the computer it runs on: each volume's file
//! system and free space, the disks with their partitions and serial
//! numbers, and, for a disk the PC boots itself, its memory and CPU. macOS
//! answers through `diskutil`, `system_profiler` and `sysctl`. The only
//! write is [`Host::write`], which setup uses for the NOR partition alone.
use anyhow::{Context, Result, bail, ensure};
use plist::Value;
use std::{
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FileSystem {
    Fat,
    ExFat,
    Hfs,
    #[cfg(any(test, target_os = "macos"))]
    Apfs,
    Ntfs,
    Other(String),
}

impl std::fmt::Display for FileSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fat => f.write_str("FAT"),
            Self::ExFat => f.write_str("exFAT"),
            Self::Hfs => f.write_str("HFS+"),
            #[cfg(any(test, target_os = "macos"))]
            Self::Apfs => f.write_str("APFS"),
            Self::Ntfs => f.write_str("NTFS"),
            Self::Other(name) => f.write_str(name),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Volume {
    pub(crate) filesystem: FileSystem,
    pub(crate) free_bytes: u64,
    /// The whole disk it is on, such as `disk5`, when the host can tell.
    pub(crate) disk: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Partition {
    pub(crate) identifier: String,
    pub(crate) content: String,
    pub(crate) mount: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub(crate) struct Disk {
    pub(crate) identifier: String,
    pub(crate) name: String,
    pub(crate) internal: bool,
    /// It holds the volume this computer runs from.
    pub(crate) system: bool,
    pub(crate) partitions: Vec<Partition>,
}

/// One partition, as `stela.cfg` names it and setup checks it.
#[derive(Debug, Clone)]
pub(crate) struct PartitionInfo {
    pub(crate) identifier: String,
    /// The whole disk, such as `disk1`.
    pub(crate) disk: String,
    /// The GPT unique partition GUID.
    pub(crate) guid: String,
    pub(crate) bytes: u64,
    /// The partition type, such as `Apple_APFS`, or empty.
    pub(crate) content: String,
    pub(crate) mount: Option<PathBuf>,
    /// The APFS container it backs, when any of that container's volumes is
    /// mounted.
    pub(crate) container: Option<String>,
}

/// What the PC's CPU offers the engine.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Cpu {
    /// RDSEED or RDRAND: the kernel's seeds.
    pub(crate) entropy: bool,
}

pub(crate) trait Host {
    fn volume(&self, path: &Path) -> Result<Volume>;
    /// Physical whole disks; empty where the host cannot list them.
    fn disks(&self) -> Result<Vec<Disk>>;
    /// A partition by its identifier, such as `disk1s2`.
    fn partition(&self, identifier: &str) -> Result<PartitionInfo>;
    /// A whole disk's serial number, as its NVMe or ATA controller reports
    /// it and `stela.efi` reads it; `None` when the host cannot tell.
    fn serial(&self, disk: &str) -> Result<Option<String>>;
    /// Read `length` bytes at `offset` of a partition.
    fn read(&self, identifier: &str, offset: u64, length: usize) -> Result<Vec<u8>>;
    /// Write `bytes` at `offset` of a partition, durably.
    fn write(&self, identifier: &str, offset: u64, bytes: &[u8]) -> Result<()>;
    /// Unmount `partition`'s volume, or every volume of the APFS container
    /// it backs.
    fn unmount(&self, partition: &PartitionInfo) -> Result<()>;
    /// Mount the volume on partition `identifier` and return where.
    fn mount(&self, identifier: &str) -> Result<PathBuf>;
    /// This computer's CPU, for a disk it boots itself.
    fn cpu(&self) -> Result<Cpu>;
    /// Erase whole disk `disk` into a GPT with an EFI partition and a FAT32
    /// volume named `name` on the rest, mounted.
    fn erase(&self, disk: &str, name: &str) -> Result<()> {
        bail!("this computer cannot erase {disk} into {name}")
    }
}

/// The computer `stela setup` runs on.
pub(crate) struct System;

impl Host for System {
    fn volume(&self, path: &Path) -> Result<Volume> {
        statfs(path)
    }

    fn disks(&self) -> Result<Vec<Disk>> {
        if cfg!(target_os = "macos") {
            mac_disks()
        } else {
            Ok(Vec::new())
        }
    }

    fn partition(&self, identifier: &str) -> Result<PartitionInfo> {
        ensure!(
            cfg!(target_os = "macos"),
            "naming an installed disk's partitions needs macOS's diskutil"
        );
        ensure!(
            identifier.starts_with("disk") && identifier.bytes().all(|b| b.is_ascii_alphanumeric()),
            "{identifier} is not a partition identifier such as disk1s2"
        );
        let info = plist(Command::new("diskutil").args(["info", "-plist", identifier]))?;
        let size = info
            .as_dictionary()
            .and_then(|d| d.get("Size").or_else(|| d.get("TotalSize")))
            .and_then(Value::as_unsigned_integer)
            .unwrap_or(0);
        let list = plist(Command::new("diskutil").args(["list", "-plist"]))?;
        let container = array(&list, "AllDisksAndPartitions")
            .iter()
            .find(|entry| {
                array(entry, "APFSPhysicalStores")
                    .iter()
                    .any(|store| text(store, "DeviceIdentifier") == identifier)
                    && array(entry, "APFSVolumes")
                        .iter()
                        .any(|volume| !text(volume, "MountPoint").is_empty())
            })
            .map(|entry| text(entry, "DeviceIdentifier"));
        Ok(PartitionInfo {
            identifier: identifier.into(),
            disk: text(&info, "ParentWholeDisk"),
            guid: text(&info, "DiskUUID"),
            bytes: size,
            content: text(&info, "Content"),
            mount: Some(text(&info, "MountPoint"))
                .filter(|m| !m.is_empty())
                .map(PathBuf::from),
            container,
        })
    }

    fn serial(&self, disk: &str) -> Result<Option<String>> {
        if !cfg!(target_os = "macos") {
            return Ok(None);
        }
        let output = Command::new("system_profiler")
            .args(["-json", "SPNVMeDataType", "SPSerialATADataType"])
            .output()
            .context("cannot run system_profiler")?;
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        if let Some(serial) = serial_of(&report, disk) {
            return Ok(Some(serial));
        }
        // A USB disk: its device's serial number string, which the
        // IORegistry links to the disk as the device's descendant.
        let devices =
            plist(Command::new("ioreg").args(["-a", "-r", "-c", "IOUSBHostDevice", "-l"]))?;
        Ok(usb_serial_of(&devices, disk))
    }

    fn read(&self, identifier: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
        use std::{io::Read, io::Seek, io::SeekFrom};
        let path = raw_device(identifier)?;
        let mut file = std::fs::File::open(&path).with_context(|| {
            format!(
                "cannot read {path}; setup reads the installed disk's partitions as root (sudo)"
            )
        })?;
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn write(&self, identifier: &str, offset: u64, bytes: &[u8]) -> Result<()> {
        use std::{io::Seek, io::SeekFrom, io::Write};
        let path = raw_device(identifier)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .with_context(|| format!("cannot open {path} for writing (sudo)"))?;
        file.seek(SeekFrom::Start(offset))?;
        // A raw device has no file cache to flush: its writes reach the
        // disk unbuffered, and `sync_all`'s F_FULLFSYNC fails on it (ENOTTY).
        file.write_all(bytes)?;
        Ok(())
    }

    fn unmount(&self, partition: &PartitionInfo) -> Result<()> {
        let mut command = Command::new("diskutil");
        match &partition.container {
            Some(container) => command.args(["unmountDisk", container]),
            None => command.args(["unmount", &partition.identifier]),
        };
        let status = command.status().context("cannot run diskutil")?;
        ensure!(
            status.success(),
            "diskutil could not unmount {}",
            partition
                .container
                .as_deref()
                .unwrap_or(&partition.identifier)
        );
        Ok(())
    }

    fn mount(&self, identifier: &str) -> Result<PathBuf> {
        let status = Command::new("diskutil")
            .args(["mount", identifier])
            .status()
            .context("cannot run diskutil")?;
        ensure!(status.success(), "diskutil could not mount {identifier}");
        let info = plist(Command::new("diskutil").args(["info", "-plist", identifier]))?;
        let mount = text(&info, "MountPoint");
        ensure!(!mount.is_empty(), "diskutil mounted {identifier} nowhere");
        Ok(PathBuf::from(mount))
    }

    fn erase(&self, disk: &str, name: &str) -> Result<()> {
        ensure!(
            cfg!(target_os = "macos"),
            "erasing a USB needs macOS's diskutil"
        );
        // diskutil's GPT always starts with a 200 MiB EFI partition.
        let status = Command::new("diskutil")
            .args(["eraseDisk", "FAT32", name, "GPT", disk])
            .status()
            .context("cannot run diskutil")?;
        ensure!(status.success(), "diskutil could not erase {disk}");
        Ok(())
    }

    fn cpu(&self) -> Result<Cpu> {
        #[cfg(target_arch = "x86_64")]
        {
            use core::arch::x86_64::{__cpuid, __cpuid_count};
            const RDSEED: u32 = 1 << 18;
            const RDRAND: u32 = 1 << 30;
            let (basic, extended) = (__cpuid(1), __cpuid_count(7, 0));
            Ok(Cpu {
                entropy: extended.ebx & RDSEED != 0 || basic.ecx & RDRAND != 0,
            })
        }
        #[cfg(not(target_arch = "x86_64"))]
        bail!("an installed disk is set up on the x86 PC that boots it")
    }
}

/// `/dev/rdiskNsM` for a partition identifier.
fn raw_device(identifier: &str) -> Result<String> {
    let partition = identifier.strip_prefix("disk").is_some_and(|rest| {
        rest.split_once('s').is_some_and(|(disk, slice)| {
            !disk.is_empty()
                && !slice.is_empty()
                && disk.bytes().all(|b| b.is_ascii_digit())
                && slice.bytes().all(|b| b.is_ascii_digit())
        })
    });
    ensure!(
        partition,
        "{identifier} is not a partition identifier such as disk1s2"
    );
    Ok(format!("/dev/r{identifier}"))
}

/// The serial `system_profiler -json` reports for the whole disk `disk`.
pub(crate) fn serial_of(report: &serde_json::Value, disk: &str) -> Option<String> {
    let groups = report.as_object()?;
    for controllers in groups.values().filter_map(serde_json::Value::as_array) {
        for controller in controllers {
            let devices = controller
                .get("_items")
                .and_then(serde_json::Value::as_array);
            for device in devices.into_iter().flatten() {
                if device.get("bsd_name").and_then(serde_json::Value::as_str) == Some(disk) {
                    return device
                        .get("device_serial")
                        .and_then(serde_json::Value::as_str)
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty());
                }
            }
        }
    }
    None
}

/// The `USB Serial Number` of the USB device in an `ioreg -a -r -c
/// IOUSBHostDevice -l` listing whose descendants include whole disk `disk`.
pub(crate) fn usb_serial_of(devices: &Value, disk: &str) -> Option<String> {
    fn holds(entry: &Value, disk: &str) -> bool {
        let Some(entry) = entry.as_dictionary() else {
            return false;
        };
        let whole = entry.get("Whole").and_then(Value::as_boolean) == Some(true);
        if whole && entry.get("BSD Name").and_then(Value::as_string) == Some(disk) {
            return true;
        }
        entry
            .get("IORegistryEntryChildren")
            .and_then(Value::as_array)
            .is_some_and(|children| children.iter().any(|child| holds(child, disk)))
    }
    let devices = match devices.as_array() {
        Some(devices) => devices.as_slice(),
        None => core::slice::from_ref(devices),
    };
    devices
        .iter()
        .find(|device| holds(device, disk))?
        .as_dictionary()?
        .get("USB Serial Number")?
        .as_string()
        .map(|serial| serial.trim().to_owned())
        .filter(|serial| !serial.is_empty())
}

#[cfg(target_os = "macos")]
fn statfs(path: &Path) -> Result<Volume> {
    use std::{ffi::CStr, os::unix::ffi::OsStrExt};
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a zeroed out-structure.
    if unsafe { libc::statfs(c_path.as_ptr(), &mut info) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("cannot inspect {}", path.display()));
    }
    // SAFETY: statfs NUL-terminates both names.
    let name = unsafe { CStr::from_ptr(info.f_fstypename.as_ptr()) }.to_string_lossy();
    let device = unsafe { CStr::from_ptr(info.f_mntfromname.as_ptr()) }.to_string_lossy();
    let filesystem = match name.as_ref() {
        "msdos" => FileSystem::Fat,
        "exfat" => FileSystem::ExFat,
        "hfs" => FileSystem::Hfs,
        "apfs" => FileSystem::Apfs,
        "ntfs" | "ufsd_NTFS" | "tuxera_ntfs" => FileSystem::Ntfs,
        other => FileSystem::Other(other.into()),
    };
    Ok(Volume {
        filesystem,
        free_bytes: info.f_bavail * info.f_bsize as u64,
        disk: device.strip_prefix("/dev/").map(whole_disk),
    })
}

#[cfg(not(target_os = "macos"))]
fn statfs(path: &Path) -> Result<Volume> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a zeroed out-structure.
    if unsafe { libc::statfs(c_path.as_ptr(), &mut info) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("cannot inspect {}", path.display()));
    }
    // Linux superblock magic numbers.
    let filesystem = match info.f_type as u64 {
        0x4d44 => FileSystem::Fat,
        0x2011_bab0 => FileSystem::ExFat,
        0x482b | 0x4858 => FileSystem::Hfs,
        0x5346_544e | 0x7366_746e => FileSystem::Ntfs,
        other => FileSystem::Other(format!("{other:#x}")),
    };
    Ok(Volume {
        filesystem,
        free_bytes: info.f_bavail as u64 * info.f_bsize as u64,
        disk: None,
    })
}

/// `disk5s1` → `disk5`; APFS volumes such as `disk3s1s1` → `disk3`.
fn whole_disk(device: &str) -> String {
    match device.strip_prefix("disk").and_then(|rest| rest.find('s')) {
        Some(at) => device[..4 + at].into(),
        None => device.into(),
    }
}

fn plist(command: &mut Command) -> Result<Value> {
    let output = command
        .output()
        .with_context(|| format!("cannot run {:?}", command.get_program()))?;
    if !output.status.success() {
        bail!(
            "{:?} failed: {}",
            command.get_program(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(Value::from_reader(std::io::Cursor::new(output.stdout))?)
}

fn text(value: &Value, key: &str) -> String {
    value
        .as_dictionary()
        .and_then(|d| d.get(key))
        .and_then(Value::as_string)
        .unwrap_or_default()
        .to_owned()
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .as_dictionary()
        .and_then(|d| d.get(key))
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn mac_disks() -> Result<Vec<Disk>> {
    let list = plist(Command::new("diskutil").args(["list", "-plist"]))?;
    // Physical disks that hold the running system's APFS container.
    let mut system_disks = Vec::new();
    for entry in array(&list, "AllDisksAndPartitions") {
        let mounted_root = array(entry, "APFSVolumes")
            .iter()
            .any(|v| matches!(text(v, "MountPoint").as_str(), "/" | "/System/Volumes/Data"));
        if mounted_root {
            for store in array(entry, "APFSPhysicalStores") {
                system_disks.push(whole_disk(&text(store, "DeviceIdentifier")));
            }
        }
    }
    let mut disks = Vec::new();
    for entry in array(&list, "AllDisksAndPartitions") {
        let identifier = text(entry, "DeviceIdentifier");
        if !array(entry, "APFSPhysicalStores").is_empty() {
            continue;
        }
        let info = plist(Command::new("diskutil").args(["info", "-plist", &identifier]))?;
        // A disk image stands in for a USB, as a stick's copy does in QEMU.
        if text(&info, "VirtualOrPhysical") == "Virtual"
            && text(&info, "BusProtocol") != "Disk Image"
        {
            continue;
        }
        let flag = |key| {
            info.as_dictionary()
                .and_then(|d| d.get(key))
                .and_then(Value::as_boolean)
                .unwrap_or(false)
        };
        let partitions = array(entry, "Partitions")
            .iter()
            .map(|p| Partition {
                identifier: text(p, "DeviceIdentifier"),
                content: text(p, "Content"),
                mount: Some(text(p, "MountPoint"))
                    .filter(|m| !m.is_empty())
                    .map(PathBuf::from),
            })
            .collect();
        disks.push(Disk {
            name: text(&info, "MediaName"),
            internal: flag("Internal"),
            system: system_disks.contains(&identifier),
            partitions,
            identifier,
        });
    }
    Ok(disks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_and_apfs_names_map_to_their_whole_disk() {
        assert_eq!(whole_disk("disk5s1"), "disk5");
        assert_eq!(whole_disk("disk3s1s1"), "disk3");
        assert_eq!(whole_disk("disk12"), "disk12");
        assert_eq!(whole_disk("disk12s3"), "disk12");
    }

    #[test]
    fn serials_come_from_the_controller_listing_by_bsd_name() {
        let report = serde_json::json!({
            "SPNVMeDataType": [{"_items": [
                {"bsd_name": "disk0", "device_serial": "  74EXN0LIWOG103  "},
                {"bsd_name": "disk1", "device_serial": ""},
            ]}],
            "SPSerialATADataType": [{"_items": [{"bsd_name": "disk2", "device_serial": "WD-1"}]}],
        });
        assert_eq!(
            serial_of(&report, "disk0").as_deref(),
            Some("74EXN0LIWOG103")
        );
        assert_eq!(serial_of(&report, "disk1"), None);
        assert_eq!(serial_of(&report, "disk2").as_deref(), Some("WD-1"));
        assert_eq!(serial_of(&report, "disk9"), None);
        let media = |name: &str, whole: bool| {
            Value::Dictionary(
                [
                    ("BSD Name".to_owned(), Value::from(name)),
                    ("Whole".to_owned(), Value::from(whole)),
                ]
                .into_iter()
                .collect(),
            )
        };
        let device = |serial: &str, children: Vec<Value>| {
            Value::Dictionary(
                [
                    ("USB Serial Number".to_owned(), Value::from(serial)),
                    (
                        "IORegistryEntryChildren".to_owned(),
                        Value::Array(vec![Value::Dictionary(
                            [("IORegistryEntryChildren".to_owned(), Value::Array(children))]
                                .into_iter()
                                .collect(),
                        )]),
                    ),
                ]
                .into_iter()
                .collect(),
            )
        };
        let devices = Value::Array(vec![
            device("KEYBOARD", Vec::new()),
            device(
                " D036F68A3B1E6921 ",
                vec![media("disk5", true), media("disk5s1", false)],
            ),
        ]);
        assert_eq!(
            usb_serial_of(&devices, "disk5").as_deref(),
            Some("D036F68A3B1E6921")
        );
        assert_eq!(usb_serial_of(&devices, "disk5s1"), None);
        assert_eq!(usb_serial_of(&devices, "disk6"), None);
        assert!(raw_device("disk1s2").is_ok());
        assert!(raw_device("disk1").is_err());
        assert!(raw_device("../disk1s2").is_err());
    }
}
