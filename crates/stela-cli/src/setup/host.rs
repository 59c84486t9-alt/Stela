//! What `stela setup` reads from the computer it runs on: each volume's file
//! system and free space, the disks with their partitions and serial
//! numbers, and, for a disk the PC boots itself, its memory and CPU. Each
//! operating system answers through its own backend: macOS through
//! `diskutil`, `system_profiler` and `ioreg`, Linux through sysfs and
//! `lsblk`, Windows through its storage and volume control codes. Setup
//! writes raw bytes only to erase a USB and to the NOR partition.
use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub(crate) use linux::{ADMIN, DISK_EXAMPLE, PARTITION_LISTING, System};
#[cfg(target_os = "macos")]
pub(crate) use macos::{ADMIN, DISK_EXAMPLE, PARTITION_LISTING, System};
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) use unsupported::{ADMIN, DISK_EXAMPLE, PARTITION_LISTING, System};
#[cfg(windows)]
pub(crate) use windows::{ADMIN, DISK_EXAMPLE, PARTITION_LISTING, System};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FileSystem {
    Fat,
    ExFat,
    // Windows mounts no HFS+ volumes, and only macOS mounts APFS ones.
    #[cfg_attr(
        windows,
        allow(
            dead_code,
            reason = "Windows reports no HFS+ mounts; the shared filesystem enum covers all host backends"
        )
    )]
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
    /// `EFI` for an EFI system partition; otherwise the host's name for the
    /// partition type.
    pub(crate) content: String,
    pub(crate) mount: Option<PathBuf>,
}

/// The bus a whole disk is attached by, as far as [`DiskFacts::removal`]
/// distinguishes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bus {
    Usb,
    /// IEEE 1394, which reaches only devices outside the computer.
    FireWire,
    /// A file standing in for a disk: a Linux loop device, a Windows virtual
    /// disk (VHD) or a macOS disk image, as a USB's copy does in QEMU.
    Image,
    /// Every other bus: NVMe, SATA, SAS, SD and MMC (an SD card reader as
    /// well as eMMC soldered to the board), PCIe tunnelled over Thunderbolt.
    Other,
}

/// What a host reports about a whole disk: the input of the one rule,
/// [`DiskFacts::removal`], that decides which disks setup may erase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DiskFacts {
    pub(crate) bus: Bus,
    /// The device reports removable media: Linux's `rm`, Windows's
    /// `RemovableMedia`, macOS's `RemovableMedia`.
    pub(crate) removable_media: bool,
    /// The host places the disk outside the computer: macOS's `Internal`
    /// false. Linux and Windows report no such fact. Linux's `hotplug` is
    /// set for every device on a hot-plug-capable bus, internal NVMe slots
    /// and backplane drives included, so setup does not read it.
    pub(crate) external: bool,
}

/// Which whole disks setup may erase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Removal {
    /// A USB disk, or a disk image standing in for one: erased after the
    /// usual confirmation.
    Usb,
    /// Removable by another bus: an SD card in a reader, a FireWire disk, an
    /// external Thunderbolt disk. Erased only once its model or size is
    /// typed back ([`Disk::confirmed_by`]).
    Typed,
    /// Part of the computer: never erased.
    Fixed,
}

impl DiskFacts {
    /// USB and disk images are removable; another bus is removable only
    /// with removable media or a host that places it outside the computer.
    /// SD and MMC report one bus for a card reader and for soldered eMMC,
    /// which differ in removable media alone.
    pub(crate) fn removal(self) -> Removal {
        match self.bus {
            Bus::Usb | Bus::Image => Removal::Usb,
            Bus::FireWire => Removal::Typed,
            Bus::Other if self.removable_media || self.external => Removal::Typed,
            Bus::Other => Removal::Fixed,
        }
    }
}

/// A capacity as setup shows it, in decimal gigabytes.
pub(crate) fn size_text(bytes: u64) -> String {
    if bytes == 0 {
        "size unavailable".into()
    } else {
        format!("{:.1} GB", bytes as f64 / 1e9)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Disk {
    pub(crate) identifier: String,
    pub(crate) name: String,
    pub(crate) bytes: u64,
    pub(crate) removal: Removal,
    /// It holds the volume this computer runs from.
    pub(crate) system: bool,
    pub(crate) partitions: Vec<Partition>,
}

impl Disk {
    /// Setup may erase it: it is removable and does not run this computer.
    pub(crate) fn erasable(&self) -> bool {
        !self.system && self.removal != Removal::Fixed
    }

    /// `typed` names this disk ([`names_disk`]).
    pub(crate) fn confirmed_by(&self, typed: &str) -> bool {
        names_disk(&self.name, self.bytes, typed)
    }
}

/// `typed` is a disk's model `name`, or its size as [`size_text`] shows
/// it, ignoring case and spaces.
pub(crate) fn names_disk(name: &str, bytes: u64, typed: &str) -> bool {
    let squeeze = |text: &str| {
        text.split_whitespace()
            .collect::<String>()
            .to_ascii_lowercase()
    };
    let typed = squeeze(typed);
    !typed.is_empty()
        && (typed == squeeze(name) || bytes != 0 && typed == squeeze(&size_text(bytes)))
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
    /// Check write access before downloading or signing for a whole USB.
    fn check_erase_access(&self, _disk: &str) -> Result<()> {
        Ok(())
    }
    /// Erase whole disk `disk` into a GPT with an EFI partition and a FAT32
    /// volume named `name` on the rest, mounted.
    fn erase(&self, disk: &str, name: &str) -> Result<()> {
        bail!("this computer cannot erase {disk} into {name}")
    }
    /// The whole disk `usb` names, such as `disk5` or `/dev/disk5`, when it
    /// names one of [`Host::disks`] rather than a mounted volume.
    fn whole_disk(&self, usb: &Path) -> Result<Option<String>> {
        if usb.is_dir() {
            return Ok(None);
        }
        let Some(name) = usb.to_str() else {
            return Ok(None);
        };
        let name = name.strip_prefix("/dev/").unwrap_or(name);
        Ok(self
            .disks()?
            .into_iter()
            .map(|disk| disk.identifier)
            .find(|identifier| identifier == name))
    }
}

/// This computer's CPU, which boots the disk setup installs on.
fn cpu() -> Result<Cpu> {
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

/// Write `layout` to the whole disk `file`, durably: the bytes setup's
/// erase lays out, written in their order, zeros in bounded runs.
#[cfg(not(target_os = "macos"))]
fn write_layout(file: &mut std::fs::File, layout: &super::format::Layout) -> Result<()> {
    use super::format::Write as Step;
    use std::io::{Seek, SeekFrom, Write};
    const RUN: u64 = 1 << 20;
    let zeros = vec![0u8; RUN as usize];
    for step in &layout.writes {
        match step {
            Step::Bytes(at, bytes) => {
                file.seek(SeekFrom::Start(*at))?;
                file.write_all(bytes)?;
            }
            Step::Zeros(at, length) => {
                file.seek(SeekFrom::Start(*at))?;
                let mut left = *length;
                while left > 0 {
                    let run = left.min(RUN);
                    file.write_all(&zeros[..run as usize])?;
                    left -= run;
                }
            }
        }
    }
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(bus: Bus, removable_media: bool, external: bool) -> DiskFacts {
        DiskFacts {
            bus,
            removable_media,
            external,
        }
    }

    #[test]
    fn only_usb_images_and_removable_media_are_erasable() {
        assert_eq!(facts(Bus::Usb, false, false).removal(), Removal::Usb);
        assert_eq!(facts(Bus::Image, false, false).removal(), Removal::Usb);
        assert_eq!(facts(Bus::FireWire, false, false).removal(), Removal::Typed);
        // An SD card in a reader; soldered eMMC on the same bus is fixed.
        assert_eq!(facts(Bus::Other, true, false).removal(), Removal::Typed);
        assert_eq!(facts(Bus::Other, false, false).removal(), Removal::Fixed);
        // A Thunderbolt SSD macOS places outside the Mac.
        assert_eq!(facts(Bus::Other, false, true).removal(), Removal::Typed);
    }

    #[test]
    fn a_disk_is_confirmed_by_its_model_or_shown_size() {
        let disk = Disk {
            identifier: "mmcblk0".into(),
            name: "SD Card Reader".into(),
            bytes: 63_864_569_856,
            removal: Removal::Typed,
            system: false,
            partitions: Vec::new(),
        };
        assert!(disk.erasable());
        for typed in ["SD Card Reader", " sd card reader ", "63.9 GB", "63.9gb"] {
            assert!(disk.confirmed_by(typed), "{typed}");
        }
        for typed in ["", "yes", "64 GB", "mmcblk0"] {
            assert!(!disk.confirmed_by(typed), "{typed}");
        }
        let no_size = Disk { bytes: 0, ..disk };
        assert!(!no_size.confirmed_by(&size_text(0)));
        let fixed = Disk {
            removal: Removal::Fixed,
            ..no_size
        };
        assert!(!fixed.erasable());
    }
}
