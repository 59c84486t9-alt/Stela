//! The kernel boot bundle: `bundle.json` and the files it lists, as prepared
//! on the host by `stela boot prepare` (the iBoot side of the hand-off).
//! `stela_runtime::boot_bundle` checks every region's SHA-256, writes the
//! regions and their zero tails into guest DRAM, and fills the patch slots
//! only the running machine knows; this supplies the machine's side: guest
//! RAM through the engine's host, RDSEED or RDRAND entropy and the timebase.
//! The format is `docs/design/runtime.md#kernel-boot-bundle`.
//!
//! [`read`] runs before boot services end and reads the files into their own
//! `LOADER_DATA` pages, so a restore ramdisk does not have to fit the heap.
//! [`from_disk`] runs after them instead: Stela's own storage drivers read
//! the installed system on a host disk's APFS container, and
//! `stela_loader::installed` builds the same bundle `stela boot prepare
//! --disk` writes, in the heap. [`upgrade_from_disk`] and
//! [`recovery_from_disk`] build a staged update's and a recoveryOS's the
//! same way (`stela_loader::upgrade`, `stela_loader::recovery`).
use crate::{
    firmware,
    handoff::{File, Region},
    layout, output,
    paging::PAGE,
};
use alloc::{format, string::String, vec, vec::Vec};
use core::arch::{
    asm,
    x86_64::{__cpuid, __cpuid_count},
};
use stela_drivers::{
    Handoff,
    block::{BlockDevice, BlockError},
    bus::dma::RegionAllocator,
    probe::probe,
};
use stela_loader::{
    boot_bundle::Options, boot_selection::BootVolume, installed, recovery, upgrade,
};
use stela_runtime::{
    boot_bundle::{Framebuffer, MANIFEST_FILE, Machine, Manifest, Nvram},
    machine::Host,
    payload::{self, PayloadManifest, ReadAt},
    pc::{
        self,
        storage::{self, Target},
    },
};
use uefi::{
    CString16, boot,
    proto::media::{
        file::{Directory, File as _, FileAttribute, FileInfo, FileMode, RegularFile},
        fs::SimpleFileSystem,
    },
};

/// The counter frequency the machine presents in CNTFRQ_EL0.
const TIMEBASE_HZ: u64 = 24_000_000;
/// Attempts per 64-bit word before an entropy instruction counts as failed.
const ENTROPY_RETRIES: usize = 128;
const CPUID_RDRAND: u32 = 1 << 30;
const CPUID_RDSEED: u32 = 1 << 18;

pub struct Entry {
    pub pc: u64,
    pub x0: u64,
    pub dram_base: u64,
    pub regions: usize,
    pub patches: usize,
    pub kept: Vec<String>,
    /// The AMCC CTRR-A region iBoot programs, `(base, bytes)`.
    pub read_only_region: Option<(u64, u64)>,
}

pub(super) fn contents(file: &File) -> &'static [u8] {
    // SAFETY: the loader left every bundle file allocated; the physmap maps it.
    unsafe {
        core::slice::from_raw_parts(
            layout::physical(file.contents.physical) as *const u8,
            file.contents.bytes as usize,
        )
    }
}

fn open(root: &mut Directory, path: &str) -> Result<RegularFile, &'static str> {
    let path = CString16::try_from(path).map_err(|_| "bundle path is not UCS-2")?;
    root.open(&path, FileMode::Read, FileAttribute::empty())
        .map_err(|_| "cannot open a bundle file")?
        .into_regular_file()
        .ok_or("a bundle path is a directory")
}

/// Read a whole file into fresh `LOADER_DATA` pages, which Stela keeps.
/// The part of a large file read between progress updates.
const PROGRESS_STEP: usize = 16 << 20;

fn read_file(root: &mut Directory, path: &str) -> Result<Region, &'static str> {
    read_bounded(root, path, u64::MAX)
}

fn read_bounded(root: &mut Directory, path: &str, limit: u64) -> Result<Region, &'static str> {
    let mut file = open(root, path)?;
    let bytes = file
        .get_boxed_info::<FileInfo>()
        .map_err(|_| "cannot read a bundle file's size")?
        .file_size();
    if bytes > limit {
        return Err("file size outside configured bound");
    }
    let length = usize::try_from(bytes).map_err(|_| "bundle file is too large")?;
    let physical = firmware::pages(length.div_ceil(PAGE).max(1))?;
    // SAFETY: fresh pages Stela owns for the whole boot, never freed.
    let buffer = unsafe { core::slice::from_raw_parts_mut(physical as *mut u8, length) };
    // Large files are read in parts, with their progress on the screen.
    let name = path.rsplit('\\').next().unwrap_or(path);
    let mut done = 0;
    while done < length {
        let end = length.min(done + PROGRESS_STEP);
        let count = file
            .read(&mut buffer[done..end])
            .map_err(|_| "cannot read a bundle file")?;
        if count == 0 {
            return Err("a bundle file ended early");
        }
        done += count;
        if length > PROGRESS_STEP {
            crate::status::progress(&format!("{name}  {} of {} MB", done >> 20, length >> 20));
        }
    }
    Ok(Region {
        physical: physical as u64,
        bytes,
    })
}

/// Read `bundle.json` from `directory` on the first volume that has it, then
/// every file it lists, unchanged; `bundle.json` comes first. Run before boot
/// services end, with no other exclusive opening of the volume.
pub fn read(directory: &str) -> Result<Vec<(String, Region)>, &'static str> {
    let directory = directory.trim_end_matches('\\');
    let manifest_path = format!("{directory}\\{MANIFEST_FILE}");
    let handles = boot::find_handles::<SimpleFileSystem>().map_err(|_| "no file systems")?;
    for handle in handles {
        let Ok(mut volume) = boot::open_protocol_exclusive::<SimpleFileSystem>(handle) else {
            continue;
        };
        let Ok(mut root) = volume.open_volume() else {
            continue;
        };
        let Ok(json) = read_file(&mut root, &manifest_path) else {
            continue;
        };
        // SAFETY: just read into Stela's own pages.
        let bytes =
            unsafe { core::slice::from_raw_parts(json.physical as *const u8, json.bytes as usize) };
        let manifest = Manifest::parse(bytes).map_err(|error| {
            output::arguments(format_args!("bundle refusal: {error}\n"));
            "bundle.json is not a boot bundle"
        })?;
        let mut files = alloc::vec![(String::from(MANIFEST_FILE), json)];
        crate::status::begin("Reading the boot files");
        for file in &manifest.files {
            output::arguments(format_args!("READ {directory}\\{}\n", file.name));
            let contents = read_file(&mut root, &format!("{directory}\\{}", file.name))
                .inspect_err(|error| crate::status::fail(error))?;
            files.push((file.name.clone(), contents));
        }
        let bytes: u64 = files.iter().map(|(_, region)| region.bytes).sum();
        crate::status::done(&format!("{} MB", bytes >> 20));
        return Ok(files);
    }
    Err("no volume has the bundle's bundle.json")
}

/// The restore inventory as it was read, and what it names beside itself.
pub struct Inventory {
    pub manifest: Region,
    /// Its members' precomputed block hashes (`payload::BlockHashes`), when
    /// it names them.
    pub blocks: Option<Region>,
    /// An install medium's piece block hashes (`Layout::Pieces`).
    pub pieces: Option<Region>,
}

/// The most bytes a hash file may hold: a million blocks' hashes.
const MAX_HASH_FILE_BYTES: u64 = payload::MAX_HASH_BLOCKS * 32;

/// Bounded restore inventory, read before ExitBootServices, with the hash
/// files it names from the same directory of the same volume. Reject
/// ambiguous paths across firmware volumes rather than choosing a different
/// inventory.
pub fn restore_inventory(path: &str) -> Result<Inventory, &'static str> {
    with_inventory(path, |_, _, _| Ok(()))
}

/// [`restore_inventory`], also running `check` on the inventory's volume
/// while it is open, with the inventory's directory.
pub fn with_inventory(
    path: &str,
    mut check: impl FnMut(&mut Directory, &str, &PayloadManifest) -> Result<(), &'static str>,
) -> Result<Inventory, &'static str> {
    const LIMIT: u64 = 16 * 1024 * 1024;
    let mut found = None;
    for handle in boot::find_handles::<SimpleFileSystem>().map_err(|_| "no file systems")? {
        let Ok(mut volume) = boot::open_protocol_exclusive::<SimpleFileSystem>(handle) else {
            continue;
        };
        let Ok(mut root) = volume.open_volume() else {
            continue;
        };
        if open(&mut root, path).is_err() {
            continue;
        }
        if found.is_some() {
            return Err("restore inventory path appears on multiple volumes");
        }
        let manifest = read_bounded(&mut root, path, LIMIT)?;
        // SAFETY: just read into Stela's own pages.
        let bytes = unsafe {
            core::slice::from_raw_parts(manifest.physical as *const u8, manifest.bytes as usize)
        };
        let parsed = PayloadManifest::parse(bytes).map_err(|error| {
            output::arguments(format_args!("restore inventory refusal: {error}\n"));
            "the restore inventory is not a payload manifest"
        })?;
        let directory = path
            .rsplit_once('\\')
            .map_or("", |(directory, _)| directory);
        let mut hash_file = |entry: Option<&payload::BlockHashes>| {
            entry
                .map(|entry| {
                    let path = format!("{directory}\\{}", entry.file);
                    output::arguments(format_args!("READ {path}\n"));
                    read_bounded(&mut root, &path, MAX_HASH_FILE_BYTES)
                        .map_err(|_| "a hash file the restore inventory names cannot be read")
                })
                .transpose()
        };
        let blocks = hash_file(parsed.block_hashes.as_ref())?;
        let pieces = hash_file(match &parsed.layout {
            payload::Layout::Pieces { block_hashes, .. } => Some(block_hashes),
            _ => None,
        })?;
        check(&mut root, directory, &parsed)?;
        found = Some(Inventory {
            manifest,
            blocks,
            pieces,
        });
    }
    found.ok_or("restore inventory file was not found")
}

/// The size of the file at `path` of `root`, when it is one.
pub fn file_size(root: &mut Directory, path: &str) -> Result<u64, &'static str> {
    let mut file = open(root, path)?;
    Ok(file
        .get_boxed_info::<FileInfo>()
        .map_err(|_| "cannot read a file's size")?
        .file_size())
}

/// One 64-bit word from RDSEED or RDRAND, retried while the source is busy.
fn random_word(seed: bool) -> Option<u64> {
    for _ in 0..ENTROPY_RETRIES {
        let (value, ok): (u64, u8);
        // SAFETY: the caller checked CPUID for the instruction; it writes
        // only its destination and the flags.
        unsafe {
            if seed {
                asm!("rdseed {}", "setc {}", out(reg) value, out(reg_byte) ok, options(nomem, nostack));
            } else {
                asm!("rdrand {}", "setc {}", out(reg) value, out(reg_byte) ok, options(nomem, nostack));
            }
        }
        if ok != 0 {
            return Some(value);
        }
        core::hint::spin_loop();
    }
    None
}

/// The largest transfer [`Bytes`] asks a device for.
const TRANSFER_BYTES: usize = 1 << 20;

/// Byte-addressed reads over a block device, for the APFS reader.
pub(crate) struct Bytes<D> {
    device: D,
    block: Vec<u8>,
}

impl<D: BlockDevice> Bytes<D> {
    pub(crate) fn new(device: D) -> Self {
        let block = vec![0; device.identity().block_size as usize];
        Self { device, block }
    }

    pub(crate) fn into_inner(self) -> D {
        self.device
    }
}

impl<D: BlockDevice> ReadAt for Bytes<D> {
    type Error = BlockError;

    fn len(&self) -> u64 {
        self.device.identity().bytes()
    }

    fn read_at(&mut self, mut offset: u64, mut buffer: &mut [u8]) -> Result<(), BlockError> {
        let size = self.block.len() as u64;
        while !buffer.is_empty() {
            let lba = offset / size;
            let within = (offset % size) as usize;
            let whole = buffer.len().min(TRANSFER_BYTES) / size as usize * size as usize;
            let done = if within == 0 && whole > 0 {
                self.device.read(lba, &mut buffer[..whole])?;
                whole
            } else {
                self.device.read(lba, &mut self.block)?;
                let count = buffer.len().min(self.block.len() - within);
                buffer[..count].copy_from_slice(&self.block[within..within + count]);
                count
            };
            offset += done as u64;
            buffer = &mut buffer[done..];
        }
        Ok(())
    }
}

/// Build the boot bundle of the installed system on `target`'s partition,
/// an APFS container or a disk image with a GUID partition table, as
/// `request` names it, with `options` (`stela boot prepare`'s defaults and
/// the boot's own boot-args); returns `bundle.json` first and then every
/// file it lists. Runs after boot services end, on the controllers
/// `storage` describes.
/// `target`'s partition, through Stela's own drivers for the controllers
/// `storage` describes. Runs after boot services end.
fn open_partition(
    storage: &Handoff,
    target: &Target,
) -> Result<pc::gpt::PartitionDevice<alloc::boxed::Box<dyn BlockDevice>>, String> {
    // SAFETY: the DMA pages were reserved for the storage drivers alone.
    let mut dma = unsafe { RegionAllocator::new(storage.dma.clone()) };
    // SAFETY: `storage` describes this machine after ExitBootServices, with
    // its ranges mapped uncached, and nothing else drives the controllers.
    let mut disks = unsafe { probe(storage, &mut dma) };
    for (address, error) in &disks.failures {
        output::arguments(format_args!("STORAGE FAILED pci={address} error={error}\n"));
    }
    storage::open(&mut disks.devices, target)
        .map_err(|e| format!("{}:{}: {e}", target.serial, target.partition))
}

pub fn from_disk(
    storage: &Handoff,
    target: &Target,
    request: &installed::Request,
    options: &Options,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let partition = open_partition(storage, target)?;
    let (offset, installed) = installed::prepare_disk(&mut Bytes::new(partition), request, options)
        .map_err(|e| format!("{e:#}"))?;
    output::arguments(format_args!(
        "PREBOOT {} volume={:?} container={offset:#x} objects={} named-by={}\n",
        installed.set.directory(),
        installed.preboot.name,
        installed.set.objects.len(),
        installed
            .evidence
            .named_by
            .as_deref()
            .unwrap_or("evidence alone")
    ));
    let manifest =
        serde_json::to_vec(&installed.bundle.manifest).map_err(|e| format!("bundle.json: {e}"))?;
    let mut files = vec![(String::from(MANIFEST_FILE), manifest)];
    files.extend(installed.bundle.files);
    Ok(files)
}

/// Build the boot bundle of the macOS update staged on `target`'s Update
/// volume (`stela_loader::upgrade`), with `options` plus the update's own
/// boot-args and OS environment; returns `bundle.json` first. Runs after
/// boot services end.
pub fn upgrade_from_disk(
    storage: &Handoff,
    target: &Target,
    volume: Option<BootVolume>,
    options: &Options,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let partition = open_partition(storage, target)?;
    let mut options = options.clone();
    options.boot_args = upgrade_boot_args(&options.boot_args);
    options.osenvironment = Some(upgrade::ENVIRONMENT);
    let (offset, staged) =
        upgrade::prepare_disk(&mut Bytes::new(partition), volume, None, &options)?;
    output::arguments(format_args!(
        "UPGRADE {} container={offset:#x} objects={} firmware-set-aside={}\n",
        staged.volume.name,
        staged.update.root.len(),
        staged.update.other_firmware.len()
    ));
    let manifest =
        serde_json::to_vec(&staged.bundle.manifest).map_err(|e| format!("bundle.json: {e}"))?;
    let mut files = vec![(String::from(MANIFEST_FILE), manifest)];
    files.extend(staged.bundle.files);
    Ok(files)
}

/// Build the boot bundle of the recoveryOS of `kind` on `target`'s disk
/// (`stela_loader::recovery`): the paired recoveryOS of the boot container's
/// Recovery volume, or System Recovery of the RecoveryOSContainer, as
/// NVRAM's boot `volume` names them; returns `bundle.json` first. Runs
/// after boot services end.
pub fn recovery_from_disk(
    storage: &Handoff,
    target: &Target,
    kind: recovery::Kind,
    volume: Option<BootVolume>,
    options: &Options,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let partition = open_partition(storage, target)?;
    let (offset, recovered) = recovery::prepare_disk(
        &mut Bytes::new(partition),
        kind,
        volume.as_ref(),
        None,
        options,
    )
    .map_err(|e| format!("{e:#}"))?;
    output::arguments(format_args!(
        "RECOVERY {} {} volume={:?} container={offset:#x} objects={} named-by={}\n",
        kind.label(),
        recovered.set.directory(),
        recovered.volume.name,
        recovered.set.objects.len(),
        recovered
            .evidence
            .named_by
            .as_deref()
            .unwrap_or("evidence alone")
    ));
    let manifest =
        serde_json::to_vec(&recovered.bundle.manifest).map_err(|e| format!("bundle.json: {e}"))?;
    let mut files = vec![(String::from(MANIFEST_FILE), manifest)];
    files.extend(recovered.bundle.files);
    Ok(files)
}

/// The update ramdisk's boot-args: the console args kept, plus iBoot's
/// `rd=md0`, `-progress` and `-restore` that the restore kexts read.
fn upgrade_boot_args(console: &str) -> String {
    let mut args: Vec<&str> = console.split_ascii_whitespace().collect();
    for extra in upgrade::BOOT_ARGS {
        let key = extra.split('=').next().unwrap_or(extra);
        if !args
            .iter()
            .any(|a| *a == key || a.split('=').next() == Some(key))
        {
            args.push(extra);
        }
    }
    args.join(" ")
}

/// Fill `buffer` from RDSEED, or from RDRAND on a CPU without RDSEED. A CPU
/// with neither is refused: the kernel's seeds must not be predictable.
pub(super) fn entropy(buffer: &mut [u8]) -> Result<(), &'static str> {
    let seed = __cpuid_count(7, 0).ebx & CPUID_RDSEED != 0;
    let rand = __cpuid(1).ecx & CPUID_RDRAND != 0;
    if !seed && !rand {
        return Err("this CPU has neither RDSEED nor RDRAND");
    }
    for chunk in buffer.chunks_mut(8) {
        let word = random_word(seed).ok_or(if seed {
            "RDSEED returned no entropy"
        } else {
            "RDRAND returned no entropy"
        })?;
        chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
    }
    Ok(())
}

/// The bundle's `bundle.json`, from the files the loader read or a bundle
/// built in the heap.
fn manifest(files: &[File], built: Option<&[(String, Vec<u8>)]>) -> Result<Manifest, String> {
    let json = match built {
        Some(built) => built
            .iter()
            .find(|(name, _)| name == MANIFEST_FILE)
            .map(|(_, bytes)| bytes.as_slice()),
        None => files
            .iter()
            .find(|file| file.name() == MANIFEST_FILE)
            .map(contents),
    }
    .ok_or("bundle.json was not read")?;
    Manifest::parse(json).map_err(|e| format!("{e}"))
}

/// The guest DRAM base the bundle was prepared for (`bundle.json`).
pub fn dram_base(files: &[File], built: Option<&[(String, Vec<u8>)]>) -> Result<u64, String> {
    Ok(manifest(files, built)?.options.dram_base)
}

/// Whether the bundle enters recoveryOS (`osenvironment` `recoveryos`).
pub fn enters_recovery_os(
    files: &[File],
    built: Option<&[(String, Vec<u8>)]>,
) -> Result<bool, String> {
    Ok(manifest(files, built)?.options.osenvironment.as_deref() == Some("recoveryos"))
}

/// Load the bundle the loader read into guest DRAM `[dram_base, dram_base +
/// ram_bytes)`, with the guest framebuffer when the machine shows one.
pub fn load(
    host: &mut impl Host,
    files: &[File],
    dram_base: u64,
    ram_bytes: u64,
    framebuffer: Option<Framebuffer>,
    nvram: Option<Nvram>,
) -> Result<Entry, String> {
    let named = |name: &str| files.iter().find(|file| file.name() == name).map(contents);
    load_named(host, &named, dram_base, ram_bytes, framebuffer, nvram)
}

/// Load a bundle built in the heap, as [`from_disk`] returns it.
pub fn load_built(
    host: &mut impl Host,
    files: &[(String, Vec<u8>)],
    dram_base: u64,
    ram_bytes: u64,
    framebuffer: Option<Framebuffer>,
    nvram: Option<Nvram>,
) -> Result<Entry, String> {
    let named = |name: &str| {
        files
            .iter()
            .find(|(file, _)| file == name)
            .map(|(_, bytes)| bytes.as_slice())
    };
    load_named(host, &named, dram_base, ram_bytes, framebuffer, nvram)
}

fn load_named<'a>(
    host: &mut impl Host,
    named: &impl Fn(&str) -> Option<&'a [u8]>,
    dram_base: u64,
    ram_bytes: u64,
    framebuffer: Option<Framebuffer>,
    nvram: Option<Nvram>,
) -> Result<Entry, String> {
    let json = named(MANIFEST_FILE).ok_or("bundle.json was not read")?;
    let manifest = Manifest::parse(json).map_err(|e| format!("{e}"))?;
    let verified = manifest
        .verify(&|name| named(name))
        .map_err(|e| format!("{e}"))?;
    let machine = Machine {
        dram_base,
        ram_bytes,
        timebase_hz: TIMEBASE_HZ,
        framebuffer,
        boot_args: None,
        nvram,
    };
    let image = verified
        .load(&machine, &mut entropy, &mut |pa, data| {
            host.write_ram(pa, data)
        })
        .map_err(|e| format!("{e}"))?;
    for region in &image.regions {
        output::arguments(format_args!(
            "REGION {} pa={:#x} bytes={:#x} memory={:#x}\n",
            region.name, region.guest_pa, region.bytes, region.memory_bytes
        ));
    }
    Ok(Entry {
        pc: image.entry_pa,
        x0: image.x0,
        dram_base,
        regions: image.regions.len(),
        patches: image.patches.len(),
        kept: image.kept,
        read_only_region: manifest
            .read_only_region
            .map(|region| (region.base, region.bytes)),
    })
}
