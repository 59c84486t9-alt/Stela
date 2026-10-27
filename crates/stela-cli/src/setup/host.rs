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
    #[cfg_attr(windows, allow(dead_code))]
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

#[derive(Debug, Clone)]
pub(crate) struct Disk {
    pub(crate) identifier: String,
    pub(crate) name: String,
    pub(crate) bytes: u64,
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
#[cfg_attr(target_os = "macos", allow(dead_code))]
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
