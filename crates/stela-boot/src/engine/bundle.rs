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
use crate::{
    firmware,
    handoff::{File, Region},
    layout, output,
    paging::PAGE,
};
use alloc::{format, string::String, vec::Vec};
use core::arch::{
    asm,
    x86_64::{__cpuid, __cpuid_count},
};
use stela_runtime::{
    boot_bundle::{MANIFEST_FILE, Machine, Manifest},
    machine::Host,
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
}

fn contents(file: &File) -> &'static [u8] {
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
fn read_file(root: &mut Directory, path: &str) -> Result<Region, &'static str> {
    let mut file = open(root, path)?;
    let bytes = file
        .get_boxed_info::<FileInfo>()
        .map_err(|_| "cannot read a bundle file's size")?
        .file_size();
    let length = usize::try_from(bytes).map_err(|_| "bundle file is too large")?;
    let physical = firmware::pages(length.div_ceil(PAGE).max(1))?;
    // SAFETY: fresh pages Stela owns for the whole boot, never freed.
    let buffer = unsafe { core::slice::from_raw_parts_mut(physical as *mut u8, length) };
    let mut done = 0;
    while done < length {
        let count = file
            .read(&mut buffer[done..])
            .map_err(|_| "cannot read a bundle file")?;
        if count == 0 {
            return Err("a bundle file ended early");
        }
        done += count;
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
        for file in &manifest.files {
            output::arguments(format_args!("READ {directory}\\{}\n", file.name));
            let contents = read_file(&mut root, &format!("{directory}\\{}", file.name))?;
            files.push((file.name.clone(), contents));
        }
        return Ok(files);
    }
    Err("no volume has the bundle's bundle.json")
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

/// Fill `buffer` from RDSEED, or from RDRAND on a CPU without RDSEED. A CPU
/// with neither is refused: the kernel's seeds must not be predictable.
fn entropy(buffer: &mut [u8]) -> Result<(), &'static str> {
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

/// Load the bundle into guest DRAM `[dram_base, dram_base + ram_bytes)`.
pub fn load(
    host: &mut impl Host,
    files: &[File],
    dram_base: u64,
    ram_bytes: u64,
) -> Result<Entry, String> {
    let named = |name: &str| files.iter().find(|file| file.name() == name).map(contents);
    let json = named(MANIFEST_FILE).ok_or("bundle.json was not read")?;
    let manifest = Manifest::parse(json).map_err(|e| format!("{e}"))?;
    let verified = manifest.verify(&named).map_err(|e| format!("{e}"))?;
    let machine = Machine {
        dram_base,
        ram_bytes,
        timebase_hz: TIMEBASE_HZ,
        // No guest framebuffer yet: the prepared zeros stay.
        framebuffer: None,
        boot_args: None,
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
    })
}
