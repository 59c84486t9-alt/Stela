//! What Stela takes from the firmware before leaving boot services: its
//! options and ARM image from the boot volume, RAM for the heap, stack and
//! frame arenas, the framebuffer, and the memory map its page tables cover.
use crate::console::Framebuffer;
use crate::paging::{LARGE_PAGE, NX, PAGE, PRESENT, Tables, WRITABLE};
use alloc::vec::Vec;
use core::ptr::NonNull;
use stela_runtime::freestanding::BootArena;
use uefi::{
    CStr16,
    boot::{self, AllocateType, MemoryType},
    cstr16,
    fs::FileSystem,
    mem::memory_map::MemoryMap,
    proto::{loaded_image::LoadedImage, media::fs::SimpleFileSystem},
};

/// Mount options, in the format [`crate::Options::parse`] reads.
const OPTIONS: &CStr16 = cstr16!("\\EFI\\stela\\stela.cfg");
/// The original ARM bytes, loaded unchanged.
const SOURCE: &CStr16 = cstr16!("\\EFI\\stela\\source.bin");
pub(crate) const STACK_PAGES: usize = 256;
pub const NATIVE_ARENAS: usize = 2;
pub const RAM_ARENAS: usize = 8;

const SECTION_EXECUTE: u32 = 0x2000_0000;
const SECTION_WRITE: u32 = 0x8000_0000;

pub struct Handoff {
    pub options: Vec<u8>,
    pub source: Vec<u8>,
    pub stack_top: usize,
    pub native: [BootArena; NATIVE_ARENAS],
    pub ram: [BootArena; RAM_ARENAS],
    /// The firmware's framebuffer, mapped RW+NX, when it has a usable one.
    pub screen: Option<Framebuffer>,
    /// Host storage state, when `stela.cfg` names a disk.
    pub storage: Option<crate::storage::Prepared>,
}

pub(crate) fn pages(count: usize) -> Result<usize, &'static str> {
    boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, count)
        .map(|page| page.as_ptr() as usize)
        .map_err(|_| "firmware has no memory for Stela")
}

/// Reserve `count` 2 MiB-aligned arenas, each later reached through its own
/// empty page table.
fn arenas<const N: usize>() -> Result<[BootArena; N], &'static str> {
    let base = pages((N + 1) * LARGE_PAGE / PAGE)?.next_multiple_of(LARGE_PAGE);
    Ok(core::array::from_fn(|i| BootArena {
        base: NonNull::new((base + i * LARGE_PAGE) as *mut u8).unwrap(),
        pages: LARGE_PAGE / PAGE,
    }))
}

fn configured(volume: &mut FileSystem) -> bool {
    matches!(volume.try_exists(OPTIONS), Ok(true))
}

fn boot_volume() -> Option<FileSystem> {
    boot::get_image_file_system(boot::image_handle())
        .ok()
        .map(FileSystem::new)
}

/// Connect every controller to its drivers, recursively, as a boot manager
/// does before it lists boot options (edk2 `EfiBootManagerConnectAll`). A
/// firmware that boots fast connects only the path to the boot loader, and
/// the bundle, the install medium and the host disks lie on other
/// partitions and devices. A controller no driver takes stays as it was.
pub(crate) fn connect_all() {
    let Ok(handles) = boot::locate_handle_buffer(boot::SearchType::AllHandles) else {
        return;
    };
    for &handle in handles.iter() {
        let _ = boot::connect_controller(handle, &[], None, true);
    }
}

/// The first file system that has `stela.cfg`.
fn configured_volume() -> Option<FileSystem> {
    boot::find_handles::<SimpleFileSystem>()
        .ok()?
        .into_iter()
        .find_map(|handle| {
            let volume = boot::open_protocol_exclusive::<SimpleFileSystem>(handle).ok()?;
            let mut volume = FileSystem::new(volume);
            configured(&mut volume).then_some(volume)
        })
}

/// The volume Stela was loaded from. When the firmware names no such volume,
/// as for an image a boot manager starts from memory, or that volume has no
/// `stela.cfg`, the first volume with one is used instead.
pub(crate) fn volume() -> Result<FileSystem, &'static str> {
    let own = boot_volume().map(|mut volume| {
        let configured = configured(&mut volume);
        (volume, configured)
    });
    Ok(match own {
        Some((volume, true)) => volume,
        Some((volume, false)) => {
            // Close the boot volume so the scan can open every volume.
            drop(volume);
            match configured_volume() {
                Some(volume) => volume,
                None => boot_volume().ok_or("cannot reopen the boot volume")?,
            }
        }
        None => configured_volume()
            .ok_or("no boot volume, and no volume has \\EFI\\stela\\stela.cfg")?,
    })
}

/// `stela.cfg`, or nothing when the volume has none.
pub(crate) fn options(volume: &mut FileSystem) -> Result<Vec<u8>, &'static str> {
    if configured(volume) {
        volume.read(OPTIONS).map_err(|_| "cannot read stela.cfg")
    } else {
        Ok(Vec::new())
    }
}

/// `\EFI\stela\source.bin`, the unchanged ARM bytes.
pub(crate) fn source(volume: &mut FileSystem) -> Result<Vec<u8>, &'static str> {
    volume
        .read(SOURCE)
        .map_err(|_| "cannot read \\EFI\\stela\\source.bin")
}

/// Page rights of Stela's own PE image: code RX, constants R, data RW+NX.
pub(crate) struct Image {
    pub start: usize,
    pub end: usize,
    pub sections: Vec<(usize, usize, u64)>,
}

impl Image {
    pub(crate) fn loaded() -> Result<Self, &'static str> {
        let image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
            .map_err(|_| "no loaded image")?;
        let (base, bytes) = image.info();
        let start = base as usize;
        // SAFETY: the firmware loaded these PE headers as part of the image.
        let read = |offset: usize, width: usize| unsafe {
            let address = (start + offset) as *const u8;
            match width {
                2 => address.cast::<u16>().read_unaligned() as usize,
                _ => address.cast::<u32>().read_unaligned() as usize,
            }
        };
        let header = read(0x3c, 4);
        if read(header, 4) != 0x4550 {
            return Err("Stela's image is not PE");
        }
        let count = read(header + 6, 2);
        let table = header + 24 + read(header + 20, 2);
        let sections = (0..count)
            .map(|i| {
                let section = table + i * 40;
                let address = start + read(section + 12, 4);
                let size = read(section + 8, 4).next_multiple_of(PAGE);
                let flags = read(section + 36, 4) as u32;
                let rights = if flags & SECTION_EXECUTE != 0 {
                    PRESENT
                } else if flags & SECTION_WRITE != 0 {
                    PRESENT | WRITABLE | NX
                } else {
                    PRESENT | NX
                };
                (address, address + size, rights)
            })
            .collect();
        Ok(Self {
            start,
            end: (start + bytes as usize).next_multiple_of(PAGE),
            sections,
        })
    }

    pub(crate) fn rights(&self, page: usize) -> u64 {
        self.sections
            .iter()
            .find(|(start, end, _)| (*start..*end).contains(&page))
            .map_or(PRESENT | NX, |section| section.2)
    }
}

/// Write-back RAM the firmware reports, sorted and merged.
pub(crate) fn ram() -> Result<Vec<(usize, usize)>, &'static str> {
    let map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|_| "no memory map")?;
    let mut ranges: Vec<(usize, usize)> = map
        .entries()
        .filter(|entry| {
            matches!(
                entry.ty,
                MemoryType::LOADER_CODE
                    | MemoryType::LOADER_DATA
                    | MemoryType::BOOT_SERVICES_CODE
                    | MemoryType::BOOT_SERVICES_DATA
                    | MemoryType::RUNTIME_SERVICES_CODE
                    | MemoryType::RUNTIME_SERVICES_DATA
                    | MemoryType::CONVENTIONAL
                    | MemoryType::ACPI_RECLAIM
                    | MemoryType::ACPI_NON_VOLATILE
            )
        })
        .map(|entry| {
            let start = entry.phys_start as usize;
            (start, start + entry.page_count as usize * PAGE)
        })
        .collect();
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    Ok(merged)
}

/// Identity-map RAM and the framebuffer RW+NX with 2 MiB pages where they
/// fill a whole chunk and 4 KiB pages elsewhere. Page zero and the stack
/// guard stay unmapped; the image gets its section rights, and each arena an
/// empty table.
pub(crate) fn tables(
    image: &Image,
    holes: [usize; 2],
    arenas: &[BootArena],
    screen: Option<&Framebuffer>,
) -> Result<Tables, &'static str> {
    let mut ram = ram()?;
    if let Some(screen) = screen {
        let start = screen.base & !(PAGE - 1);
        ram.push((start, (screen.base + screen.bytes).next_multiple_of(PAGE)));
        ram.sort_unstable();
    }
    let covered = |start: usize, end: usize| ram.iter().any(|r| r.0 <= start && end <= r.1);
    let overlaps = |start: usize, end: usize| ram.iter().any(|r| r.0 < end && start < r.1);
    let arena_chunks: Vec<usize> = arenas.iter().map(|a| a.base.as_ptr() as usize).collect();
    let mut tables = Tables::new()?;
    let top = ram.last().map_or(0, |r| r.1).max(image.end);
    for chunk in (0..top).step_by(LARGE_PAGE) {
        let end = chunk + LARGE_PAGE;
        if arena_chunks.contains(&chunk) {
            tables.small(chunk)?;
            continue;
        }
        let special = holes.iter().any(|&hole| (chunk..end).contains(&hole))
            || (image.start < end && chunk < image.end);
        if covered(chunk, end) && !special {
            tables.large(chunk)?;
        } else if overlaps(chunk, end) || special {
            tables.small(chunk)?;
            for page in (chunk..end).step_by(PAGE) {
                let rights = if holes.contains(&page) {
                    continue;
                } else if (image.start..image.end).contains(&page) {
                    image.rights(page)
                } else if covered(page, page + PAGE) {
                    PRESENT | WRITABLE | NX
                } else {
                    continue;
                };
                tables.page(page, rights)?;
            }
        }
    }
    Ok(tables)
}

/// Collect everything the mount needs, then leave boot services. The
/// returned tables are not active yet.
pub fn take_over(
    options: Vec<u8>,
    source: Option<Vec<u8>>,
) -> Result<(Handoff, Tables), &'static str> {
    // Install mode stages a payload and stops here; otherwise nothing changes.
    let options = crate::payload::run(options)?;
    let source = source.ok_or("cannot read \\EFI\\stela\\source.bin")?;
    let storage = crate::storage::prepare(&options)?;
    let native = arenas::<NATIVE_ARENAS>()?;
    let ram = arenas::<RAM_ARENAS>()?;
    let guard = pages(STACK_PAGES + 1)?;
    let image = Image::loaded()?;
    let screen = Framebuffer::from_firmware();
    let mut tables = tables(
        &image,
        [0, guard],
        &[&native[..], &ram[..]].concat(),
        screen.as_ref(),
    )?;
    if let Some(storage) = &storage {
        storage.map(&mut tables)?;
    }
    // SAFETY: no protocol or pool allocation outlives this call; the heap,
    // stack, arenas and tables are LOADER_DATA, which Stela keeps.
    let map = unsafe { boot::exit_boot_services(None) };
    core::mem::forget(map);
    Ok((
        Handoff {
            options,
            source,
            stack_top: guard + (STACK_PAGES + 1) * PAGE,
            native,
            ram,
            screen,
            storage,
        },
        tables,
    ))
}
