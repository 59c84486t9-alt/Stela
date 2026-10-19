//! LLB's boot choice, before boot services end: with `--preboot`,
//! `stela.efi` reads the persistent NOR's current NVRAM bank (`--nor
//! SERIAL:GUID`) through the firmware's block I/O, chooses macOS or
//! recoveryOS as `stela_loader::boot_selection` does, removes the one-shot
//! variables that boot consumes (saving the next bank, as LLB saves NVRAM
//! before it boots) and hands the engine the options for that boot. A macOS
//! boot whose Preboot disk holds no installed system boots System Recovery
//! instead (missing boot media), as a Mac with an erased disk does. A
//! recoveryOS boot reads the `--recovery-bundle` directory here, because the
//! ESP is readable only through the firmware.
//!
//! Each partition is found as the engine finds it: exactly one whole disk
//! reports the serial, and exactly one of its GPT partitions has the GUID;
//! an EFI system partition is refused. A blank NOR partition holds no
//! variables yet: the engine initializes it.
use crate::{
    output,
    payload::{Aligned, device_path, disk_serial},
};
use alloc::{format, string::String, vec, vec::Vec};
use stela_loader::boot_selection::{self, BootVolume, Selection};
use stela_runtime::{
    apfs::{self, ApfsError, Container},
    machine::apple::nor::{
        CAPACITY, Image, SECTOR_SIZE,
        nvram::{Variables, empty_bank},
    },
    payload::{
        ReadAt,
        gpt::{self, Disk, Role},
    },
    pc::storage::Target,
    preboot::{self, PrebootError},
};
use uefi::{
    Handle,
    boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol},
    proto::media::block::BlockIO,
};

/// One GPT partition, through its whole disk's block I/O.
struct Partition {
    io: ScopedProtocol<BlockIO>,
    media: u32,
    block_bytes: u64,
    first_lba: u64,
    bytes: u64,
}

impl Partition {
    fn read_blocks(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), &'static str> {
        let mut aligned = Aligned::new(buffer.len());
        self.io
            .read_blocks(self.media, self.first_lba + lba, aligned.bytes())
            .map_err(|_| "cannot read the partition")?;
        buffer.copy_from_slice(aligned.bytes());
        Ok(())
    }

    fn write_sector(&mut self, offset: usize, sector: &[u8]) -> Result<(), &'static str> {
        let mut buffer = Aligned::new(SECTOR_SIZE);
        buffer.bytes().copy_from_slice(sector);
        let lba = self.first_lba + offset as u64 / self.block_bytes;
        self.io
            .write_blocks(self.media, lba, buffer.bytes())
            .map_err(|_| "cannot write the NOR partition")
    }
}

/// The largest firmware read, so a large APFS read needs no huge buffer.
const TRANSFER_BYTES: u64 = 1 << 20;

impl ReadAt for Partition {
    type Error = &'static str;

    fn len(&self) -> u64 {
        self.bytes
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), &'static str> {
        let end = offset
            .checked_add(buffer.len() as u64)
            .filter(|&end| end <= self.bytes)
            .ok_or("read past the partition")?;
        let mut at = offset;
        while at < end {
            let first = at / self.block_bytes;
            let span = (end - at).min(TRANSFER_BYTES);
            let last = (at + span).div_ceil(self.block_bytes);
            let mut blocks = vec![0u8; ((last - first) * self.block_bytes) as usize];
            self.read_blocks(first, &mut blocks)?;
            let within = (at - first * self.block_bytes) as usize;
            let done = (at - offset) as usize;
            buffer[done..done + span as usize]
                .copy_from_slice(&blocks[within..within + span as usize]);
            at += span;
        }
        Ok(())
    }
}

/// Open `handle`'s block I/O for reading and, on the NOR partition only,
/// writing. Not exclusive: the disk's other partitions, such as the ESP
/// this image was loaded from, stay connected.
fn block_io(handle: Handle) -> Option<ScopedProtocol<BlockIO>> {
    // SAFETY: Stela reads the named partitions and writes only the NOR's.
    unsafe {
        boot::open_protocol::<BlockIO>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()
}

fn find(target: &Target) -> Result<Partition, &'static str> {
    let handles = boot::find_handles::<BlockIO>().map_err(|_| "no block devices")?;
    let mut disks = Vec::new();
    for handle in handles {
        let Some(io) = block_io(handle) else {
            continue;
        };
        let media = io.media();
        if media.is_logical_partition() || !media.is_media_present() {
            continue;
        }
        let path = device_path(handle).unwrap_or_default();
        if disk_serial(handle, &path).is_some_and(|serial| serial == target.serial) {
            disks.push(io);
        }
    }
    let [io] = <[_; 1]>::try_from(disks).map_err(|_| "not exactly one disk has the serial")?;
    let media = io.media();
    let disk = Disk {
        block_bytes: media.block_size() as u64,
        blocks: media.last_block() + 1,
    };
    let media = media.media_id();
    let mut whole = Partition {
        io,
        media,
        block_bytes: disk.block_bytes,
        first_lba: 0,
        bytes: disk.blocks * disk.block_bytes,
    };
    let mut header = vec![0u8; disk.block_bytes as usize];
    whole.read_blocks(1, &mut header)?;
    let info = gpt::parse_header(disk, 1, &header)
        .ok()
        .flatten()
        .ok_or("the disk has no valid GPT")?;
    let mut entries = vec![0u8; info.entry_array_bytes() as usize];
    whole.read_blocks(info.entries_lba, &mut entries)?;
    let table = gpt::parse_entries(&info, &entries).map_err(|_| "invalid GPT entries")?;
    let matching: Vec<_> = table
        .partitions
        .iter()
        .filter(|p| p.unique_guid.0 == target.partition.0)
        .collect();
    let [partition] = matching[..] else {
        return Err("not exactly one partition has the GUID");
    };
    if partition.role() == Some(Role::Esp) {
        return Err("the partition is an EFI system partition");
    }
    whole.first_lba = partition.first_lba;
    whole.bytes = partition.blocks() * disk.block_bytes;
    Ok(whole)
}

/// The boot NVRAM chooses, with its one-shot variables consumed and saved.
fn select(target: &Target) -> Result<Selection, String> {
    let mut nor = find(target).map_err(|e| format!("NOR partition: {e}"))?;
    if nor.io.media().is_read_only()
        || !SECTOR_SIZE.is_multiple_of(nor.block_bytes as usize)
        || nor.bytes < CAPACITY as u64
    {
        return Err(
            "the NOR partition is read-only, smaller than the image or has odd blocks".into(),
        );
    }
    let mut bytes = vec![0u8; CAPACITY];
    nor.read_blocks(0, &mut bytes)?;
    let select =
        |variables: &Variables| boot_selection::select(variables).map_err(|e| format!("{e:#}"));
    if bytes.iter().all(|&b| b == 0) {
        return select(&Variables::parse(&empty_bank()).map_err(String::from)?);
    }
    let mut image = Image::from_bytes(bytes).map_err(String::from)?;
    let current = image.current_bank().map_err(String::from)?;
    let mut variables =
        Variables::parse(image.bank(current).map_err(String::from)?).map_err(String::from)?;
    let selection = select(&variables)?;
    if boot_selection::consume(&mut variables, &selection).map_err(|e| format!("{e:#}"))? {
        let bank = variables.encode().map_err(String::from)?;
        let (written, sectors) = image.save_bank(&bank).map_err(String::from)?;
        for offset in sectors {
            let sector = image.bytes()[offset..offset + SECTOR_SIZE].to_vec();
            nor.write_sector(offset, &sector)?;
        }
        nor.io
            .flush_blocks()
            .map_err(|_| String::from("cannot flush the NOR partition"))?;
        output::arguments(format_args!(
            "NVRAM consumed {} into bank {written}\n",
            selection
                .consumed
                .iter()
                .map(|name| core::str::from_utf8(name).unwrap_or("?"))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    Ok(selection)
}

/// Whether the Preboot disk holds an installed system to boot: a container
/// (the boot volume's, when NVRAM names one) whose Preboot volume has a
/// boot directory. Only a missing container, Preboot volume or boot
/// directory counts as absent; any other failure is reported.
fn installed(target: &Target, volume: Option<&BootVolume>) -> Result<bool, String> {
    let mut disk = find(target).map_err(|e| format!("Preboot disk: {e}"))?;
    let partitions = match apfs::container_partitions(&mut disk) {
        Ok(partitions) => partitions,
        Err(ApfsError::NotFound(_)) => return Ok(false),
        Err(error) => return Err(format!("Preboot disk: {error}")),
    };
    for (offset, guid) in partitions {
        if volume.is_some_and(|v| guid.is_some_and(|g| g.0 != v.partition)) {
            continue;
        }
        let mut container = match Container::open(&mut disk, offset) {
            Ok(container) => container,
            Err(ApfsError::Malformed(_)) => continue,
            Err(error) => return Err(format!("container at {offset:#x}: {error}")),
        };
        match preboot::candidates(&mut container) {
            Ok(_) => return Ok(true),
            Err(PrebootError::NoBootDirectory | PrebootError::Apfs(ApfsError::NotFound(_))) => {}
            Err(error) => return Err(format!("container at {offset:#x}: {error}")),
        }
    }
    Ok(false)
}

/// The value after `name` in the options.
fn option<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let mut words = text.split_ascii_whitespace();
    words.find(|w| *w == name)?;
    words.next()
}

/// The engine's options for this boot (`boot_selection::route`).
pub fn route(options: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let text = core::str::from_utf8(&options).map_err(|_| "stela.cfg is not UTF-8")?;
    let refuse = |error: String| {
        output::arguments(format_args!("NVRAM boot refusal: {error}\n"));
        "NVRAM's boot choice could not be read or is not modeled"
    };
    let selection = match option(text, boot_selection::PREBOOT_OPTION) {
        Some(preboot) => {
            let mut selection = match option(text, "--nor") {
                Some(nor) => select(&nor.parse()?).map_err(refuse)?,
                None => boot_selection::select(
                    &Variables::parse(&empty_bank()).map_err(|e| refuse(e.into()))?,
                )
                .map_err(|e| refuse(format!("{e:#}")))?,
            };
            let recovery = option(text, boot_selection::RECOVERY_BUNDLE_OPTION).is_some();
            if recovery
                && matches!(selection.target, boot_selection::Target::MacOs { .. })
                && !installed(&preboot.parse()?, selection.volume.as_ref()).map_err(refuse)?
            {
                selection.missing_boot_media();
            }
            Some(selection)
        }
        None => None,
    };
    let (routed, log) = boot_selection::route(text, selection.as_ref()).map_err(|error| {
        output::arguments(format_args!("NVRAM boot refusal: {error:#}\n"));
        "stela.cfg cannot boot what NVRAM chose"
    })?;
    // Only an installed-system boot has a choice to report.
    if selection.is_some() {
        output::arguments(format_args!("BOOT {log}\n"));
    }
    Ok(routed.into_bytes())
}
