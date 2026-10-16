//! What `stela setup` reads from the computer it runs on: each volume's file
//! system and free space, and the disks with their serial numbers. Nothing
//! here writes; macOS answers through `diskutil` and `ioreg`.
use anyhow::{Context, Result, bail};
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
    pub(crate) bytes: u64,
    pub(crate) serial: Option<String>,
    pub(crate) internal: bool,
    pub(crate) protocol: String,
    /// It holds the volume this computer runs from.
    pub(crate) system: bool,
    pub(crate) partitions: Vec<Partition>,
}

impl Disk {
    /// Partitions that `stela.efi` would refuse to stage beside.
    pub(crate) fn foreign_partitions(&self) -> Vec<&Partition> {
        self.partitions
            .iter()
            .filter(|p| !matches!(p.content.as_str(), "EFI" | ""))
            .collect()
    }
}

pub(crate) trait Host {
    fn volume(&self, path: &Path) -> Result<Volume>;
    /// Physical whole disks; empty where the host cannot list them.
    fn disks(&self) -> Result<Vec<Disk>>;
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
    let serials = mac_serials().unwrap_or_default();
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
        if text(&info, "VirtualOrPhysical") == "Virtual" {
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
            bytes: info
                .as_dictionary()
                .and_then(|d| d.get("Size"))
                .and_then(Value::as_unsigned_integer)
                .unwrap_or(0),
            serial: serials
                .iter()
                .find(|(disk, _)| *disk == identifier)
                .map(|(_, serial)| serial.clone()),
            internal: flag("Internal"),
            protocol: text(&info, "BusProtocol"),
            system: system_disks.contains(&identifier),
            partitions,
            identifier,
        });
    }
    Ok(disks)
}

/// Whole-disk BSD names and serial numbers from the I/O Registry.
fn mac_serials() -> Result<Vec<(String, String)>> {
    let tree = plist(Command::new("ioreg").args(["-a", "-r", "-c", "IOBlockStorageDevice", "-l"]))?;
    fn bsd(node: &Value) -> Option<String> {
        let dict = node.as_dictionary()?;
        if dict.get("Whole").and_then(Value::as_boolean) == Some(true)
            && let Some(name) = dict.get("BSD Name").and_then(Value::as_string)
        {
            return Some(name.into());
        }
        dict.get("IORegistryEntryChildren")?
            .as_array()?
            .iter()
            .find_map(bsd)
    }
    Ok(tree
        .as_array()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter_map(|device| {
            let serial = device
                .as_dictionary()?
                .get("Device Characteristics")?
                .as_dictionary()?
                .get("Serial Number")?
                .as_string()?
                .trim()
                .to_owned();
            Some((bsd(device)?, serial)).filter(|(_, s)| !s.is_empty())
        })
        .collect())
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
    fn only_esps_and_empty_slots_count_as_free_of_another_system() {
        let disk = |contents: &[&str]| Disk {
            identifier: "disk9".into(),
            name: "Test".into(),
            bytes: 1,
            serial: None,
            internal: true,
            protocol: "PCI-Express".into(),
            system: false,
            partitions: contents
                .iter()
                .map(|c| Partition {
                    identifier: "disk9s1".into(),
                    content: (*c).into(),
                    mount: None,
                })
                .collect(),
        };
        assert!(disk(&[]).foreign_partitions().is_empty());
        assert!(disk(&["EFI"]).foreign_partitions().is_empty());
        assert_eq!(
            disk(&["EFI", "Microsoft Basic Data"])
                .foreign_partitions()
                .len(),
            1
        );
    }
}
