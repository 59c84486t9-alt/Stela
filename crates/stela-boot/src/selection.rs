//! LLB's boot choice, before boot services end: with `--nor SERIAL:GUID`
//! and `--preboot`, `stela.efi` reads the persistent NOR's current NVRAM
//! bank through the firmware's block I/O, chooses macOS or recoveryOS as
//! `stela_loader::boot_selection` does, removes the one-shot variables that
//! boot consumes (saving the next bank, as LLB saves NVRAM before it boots)
//! and hands the engine the options for that boot. A recoveryOS boot reads
//! the `--recovery-bundle` directory here, because the ESP is readable only
//! through the firmware.
//!
//! The partition is found as the engine finds it: exactly one whole disk
//! reports the serial, and exactly one of its GPT partitions has the GUID;
//! an EFI system partition is refused. A blank partition holds no
//! variables yet: the engine initializes it.
use crate::{
    output,
    payload::{Aligned, device_path, disk_serial},
};
use alloc::{string::String, vec::Vec};
use stela_loader::boot_selection::{self, Selection};
use stela_runtime::{
    machine::apple::nor::{CAPACITY, Image, SECTOR_SIZE, nvram::Variables},
    payload::gpt::{self, Disk, Role},
    pc::storage::Target,
};
use uefi::{
    Handle,
    boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol},
    proto::media::block::BlockIO,
};

/// The NOR partition on its disk.
struct Nor {
    io: ScopedProtocol<BlockIO>,
    media: u32,
    block_bytes: u64,
    first_lba: u64,
}

impl Nor {
    fn read(&mut self) -> Result<Vec<u8>, &'static str> {
        let mut buffer = Aligned::new(CAPACITY);
        self.io
            .read_blocks(self.media, self.first_lba, buffer.bytes())
            .map_err(|_| "cannot read the NOR partition")?;
        Ok(buffer.bytes().to_vec())
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

/// Open `handle`'s block I/O for reading and, on the NOR partition only,
/// writing. Not exclusive: the disk's other partitions, such as the ESP
/// this image was loaded from, stay connected.
fn block_io(handle: Handle) -> Option<ScopedProtocol<BlockIO>> {
    // SAFETY: Stela touches only the NOR partition's blocks through it.
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

fn find(target: &Target) -> Result<Nor, &'static str> {
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
    let [io] = <[_; 1]>::try_from(disks).map_err(|_| "not exactly one disk has the NOR serial")?;
    let media = io.media();
    if media.is_read_only() {
        return Err("the NOR disk is read-only");
    }
    let disk = Disk {
        block_bytes: media.block_size() as u64,
        blocks: media.last_block() + 1,
    };
    let media = media.media_id();
    let mut nor = Nor {
        io,
        media,
        block_bytes: disk.block_bytes,
        first_lba: 0,
    };
    let mut header = Aligned::new(disk.block_bytes as usize);
    nor.io
        .read_blocks(media, 1, header.bytes())
        .map_err(|_| "cannot read the NOR disk's GPT header")?;
    let info = gpt::parse_header(disk, 1, header.bytes())
        .ok()
        .flatten()
        .ok_or("the NOR disk has no valid GPT")?;
    let mut entries = Aligned::new(info.entry_array_bytes() as usize);
    nor.io
        .read_blocks(media, info.entries_lba, entries.bytes())
        .map_err(|_| "cannot read the NOR disk's GPT entries")?;
    let table = gpt::parse_entries(&info, entries.bytes()).map_err(|_| "invalid GPT entries")?;
    let matching: Vec<_> = table
        .partitions
        .iter()
        .filter(|p| p.unique_guid.0 == target.partition.0)
        .collect();
    let [partition] = matching[..] else {
        return Err("not exactly one partition has the NOR GUID");
    };
    if partition.role() == Some(Role::Esp) {
        return Err("the NOR partition is an EFI system partition");
    }
    if !SECTOR_SIZE.is_multiple_of(disk.block_bytes as usize)
        || partition.blocks() * disk.block_bytes < CAPACITY as u64
    {
        return Err("the NOR partition is smaller than the image or has odd blocks");
    }
    nor.first_lba = partition.first_lba;
    Ok(nor)
}

/// The boot NVRAM chooses, with its one-shot variables consumed and saved.
fn select(target: &Target) -> Result<Selection, String> {
    let mut nor = find(target).map_err(String::from)?;
    let bytes = nor.read()?;
    if bytes.iter().all(|&b| b == 0) {
        let empty = stela_runtime::machine::apple::nor::nvram::empty_bank();
        let variables = Variables::parse(&empty).map_err(String::from)?;
        return boot_selection::select(&variables).map_err(|e| alloc::format!("{e:#}"));
    }
    let mut image = Image::from_bytes(bytes).map_err(String::from)?;
    let current = image.current_bank().map_err(String::from)?;
    let mut variables =
        Variables::parse(image.bank(current).map_err(String::from)?).map_err(String::from)?;
    let selection = boot_selection::select(&variables).map_err(|e| alloc::format!("{e:#}"))?;
    if boot_selection::consume(&mut variables, &selection) {
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

/// The engine's options for this boot (`boot_selection::route`).
pub fn route(options: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let text = core::str::from_utf8(&options).map_err(|_| "stela.cfg is not UTF-8")?;
    let mut words = text.split_ascii_whitespace();
    let nor = words.by_ref().find(|w| *w == "--nor").and(words.next());
    let preboot = text
        .split_ascii_whitespace()
        .any(|w| w == boot_selection::PREBOOT_OPTION);
    let selection = match (nor, preboot) {
        (Some(nor), true) => {
            let target: Target = nor.parse()?;
            Some(select(&target).map_err(|error| {
                output::arguments(format_args!("NVRAM boot refusal: {error}\n"));
                "NVRAM's boot choice could not be read or is not modeled"
            })?)
        }
        _ => None,
    };
    let (routed, log) = boot_selection::route(text, selection.as_ref()).map_err(|error| {
        output::arguments(format_args!("NVRAM boot refusal: {error:#}\n"));
        "stela.cfg cannot boot what NVRAM chose"
    })?;
    output::arguments(format_args!("BOOT {log}\n"));
    Ok(routed.into_bytes())
}
