//! System mode, loader phase: everything that needs the firmware.
//!
//! It runs identity-mapped under the firmware. It keeps a pristine copy of
//! this image (taken before any Rust state exists), places a relocated copy
//! in the Stela window, allocates the engine's memory, builds five-level page
//! tables, leaves boot services, switches to LA57 and calls the engine phase
//! in the window. See `docs/design/system.md#host-placement`.
use crate::{
    console::Framebuffer,
    firmware,
    handoff::{File, Handoff, MAGIC, MAX_FILES, MAX_GUEST_RANGES, MAX_NAME, Region},
    la57, layout, output, paging,
    tables::{self, Frames, LARGE, NX, PAGE, PRESENT, WRITABLE},
};
use alloc::{format, string::String, vec::Vec};
use core::{arch::asm, cell::UnsafeCell};
use uefi::{
    boot::{self, AllocateType, MemoryType},
    fs::FileSystem,
    mem::memory_map::MemoryMap,
    proto::loaded_image::LoadedImage,
};

const HEAP_BYTES: u64 = 512 * 1024 * 1024;
const STACK_BYTES: u64 = 2 * 1024 * 1024;
const CODE_BYTES: u64 = 128 * 1024 * 1024;
const POOL_BYTES: u64 = 256 * 1024 * 1024;
const BELOW_4G: u64 = 0xffff_f000;
const RELOCATION_DIRECTORY: usize = 5;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const CPUID_LA57: u32 = 1 << 16;
const APIC_BASE_MSR: u32 = 0x1b;

#[derive(Clone, Copy)]
struct Snapshot {
    copy: usize,
    start: usize,
    bytes: usize,
}

struct Pristine(UnsafeCell<Option<Snapshot>>);
// SAFETY: written once by the boot processor before anything else runs.
unsafe impl Sync for Pristine {}
static PRISTINE: Pristine = Pristine(UnsafeCell::new(None));

/// Copy this image as the firmware loaded it, before Rust state changes it.
/// Only the firmware entry glue has run; its statics are not used later.
pub fn take_snapshot() {
    let Ok(image) = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()) else {
        return;
    };
    let (base, bytes) = image.info();
    let bytes = (bytes as usize).next_multiple_of(PAGE as usize);
    let Ok(copy) = boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        bytes / PAGE as usize,
    ) else {
        return;
    };
    // SAFETY: the loaded image and a fresh allocation of the same size.
    unsafe {
        core::ptr::copy_nonoverlapping(base.cast::<u8>(), copy.as_ptr(), bytes);
        *PRISTINE.0.get() = Some(Snapshot {
            copy: copy.as_ptr() as usize,
            start: base as usize,
            bytes,
        });
    }
}

/// Firmware pages reached by identity.
struct FirmwareFrames;

impl Frames for FirmwareFrames {
    fn frame(&mut self) -> Option<u64> {
        let page = firmware::pages(1).ok()? as u64;
        // SAFETY: a fresh page owned by Stela.
        unsafe { (page as *mut u8).write_bytes(0, PAGE as usize) };
        Some(page)
    }
    fn table(&self, physical: u64) -> *mut u64 {
        physical as *mut u64
    }
}

fn low_page(kind: MemoryType) -> Result<u64, &'static str> {
    let page = boot::allocate_pages(AllocateType::MaxAddress(BELOW_4G), kind, 1)
        .map_err(|_| "no page below 4 GiB for the LA57 switch")?;
    // SAFETY: a fresh page owned by Stela.
    unsafe { page.as_ptr().write_bytes(0, PAGE as usize) };
    Ok(page.as_ptr() as u64)
}

fn allocate(bytes: u64) -> Result<Region, &'static str> {
    Ok(Region {
        physical: firmware::pages(bytes.div_ceil(PAGE) as usize)? as u64,
        bytes,
    })
}

fn read32(base: usize, offset: usize) -> usize {
    // SAFETY: callers stay inside the image copy.
    unsafe { ((base + offset) as *const u32).read_unaligned() as usize }
}

/// Apply the image's DIR64 base relocations for a move by `delta`.
fn relocate(copy: usize, bytes: usize, delta: u64) -> Result<(), &'static str> {
    let header = read32(copy, 0x3c);
    if read32(copy, header) != 0x4550 {
        return Err("image copy is not PE");
    }
    let optional = header + 24;
    let directory = optional + 112 + RELOCATION_DIRECTORY * 8;
    let (mut block, end) = (
        read32(copy, directory),
        read32(copy, directory) + read32(copy, directory + 4),
    );
    if end > bytes {
        return Err("relocation directory outside the image");
    }
    while block < end {
        let page = read32(copy, block);
        let size = read32(copy, block + 4);
        if size < 8 || block + size > end {
            return Err("malformed relocation block");
        }
        for entry in (block + 8..block + size).step_by(2) {
            // SAFETY: inside the relocation directory checked above.
            let value = unsafe { ((copy + entry) as *const u16).read_unaligned() };
            let offset = page + usize::from(value & 0xfff);
            match value >> 12 {
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_DIR64 if offset + 8 <= bytes => {
                    let slot = (copy + offset) as *mut u64;
                    // SAFETY: a relocated pointer inside the copy.
                    unsafe { slot.write_unaligned(slot.read_unaligned().wrapping_add(delta)) };
                }
                _ => return Err("unsupported base relocation"),
            }
        }
        block += size;
    }
    Ok(())
}

fn rdtsc() -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: RDTSC has no side effects.
    unsafe { asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack)) };
    (u64::from(high) << 32) | u64::from(low)
}

/// Identity-map RAM RW+NX in 2 MiB pages where whole chunks are RAM, with the
/// listed pages given their own rights.
fn identity(
    frames: &mut dyn Frames,
    root: u64,
    ram: &[(usize, usize)],
    special: &[(u64, u64, u64)],
) -> Result<(), &'static str> {
    let covered =
        |start: u64, end: u64| ram.iter().any(|r| r.0 as u64 <= start && end <= r.1 as u64);
    let top = ram.iter().map(|r| r.1 as u64).max().unwrap_or(0);
    for chunk in (0..top).step_by(LARGE as usize) {
        let end = chunk + LARGE;
        let has_special = special.iter().any(|s| s.0 < end && chunk < s.1);
        if covered(chunk, end) && !has_special {
            tables::map_large(frames, root, chunk, chunk, PRESENT | WRITABLE | NX)?;
            continue;
        }
        for page in (chunk..end).step_by(PAGE as usize) {
            let rights = if let Some(s) = special.iter().find(|s| s.0 <= page && page < s.1) {
                s.2
            } else if covered(page, page + PAGE) {
                PRESENT | WRITABLE | NX
            } else {
                continue;
            };
            // Page zero stays unmapped.
            if page != 0 {
                tables::map_page(frames, root, page, page, rights)?;
            }
        }
    }
    Ok(())
}

/// Bundle files by name, `bundle.json` first.
type BundleFiles = Vec<(String, Vec<u8>)>;

/// The value after `name` in the options, as text.
fn option<'a>(options: &'a str, name: &str) -> Option<&'a str> {
    let mut words = options.split_ascii_whitespace();
    words.find(|word| *word == name)?;
    words.next()
}

/// The guest inputs: `source.bin`, or with `--bundle DIR` the directory's
/// `bundle.json` and every file it lists, read unchanged.
fn inputs(options: &[u8], volume: &mut FileSystem) -> Result<(Vec<u8>, BundleFiles), &'static str> {
    let text = core::str::from_utf8(options).map_err(|_| "stela.cfg is not UTF-8")?;
    let Some(directory) = option(text, "--bundle") else {
        return Ok((firmware::source(volume)?, Vec::new()));
    };
    let directory = directory.trim_end_matches('\\');
    let manifest = firmware::read(volume, &format!("{directory}\\bundle.json"))?;
    let value: serde_json::Value =
        serde_json::from_slice(&manifest).map_err(|_| "bundle.json is not JSON")?;
    let names: Vec<String> = value
        .get("files")
        .and_then(serde_json::Value::as_array)
        .ok_or("bundle.json has no files list")?
        .iter()
        .map(|file| {
            file.get("name")
                .and_then(serde_json::Value::as_str)
                .map(String::from)
                .ok_or("bundle file without a name")
        })
        .collect::<Result<_, _>>()?;
    let mut files = alloc::vec![(String::from("bundle.json"), manifest)];
    for name in names {
        if name.contains('\\') || name.contains('/') {
            return Err("bundle file names must not contain directories");
        }
        output::arguments(format_args!("READ {directory}\\{name}\n"));
        let contents = firmware::read(volume, &format!("{directory}\\{name}"))?;
        files.push((name, contents));
    }
    if files.len() > MAX_FILES {
        return Err("bundle lists too many files");
    }
    Ok((Vec::new(), files))
}

/// Run the engine; never returns.
pub fn boot(options: Vec<u8>, mut volume: FileSystem) -> ! {
    let inputs = inputs(&options, &mut volume);
    // The protocol must be closed before boot services end.
    drop(volume);
    let result = inputs.and_then(|(source, files)| load(options, source, files));
    match result {
        Ok(never) => match never {},
        Err(error) => output::fatal(error),
    }
}

fn load(
    options: Vec<u8>,
    source: Vec<u8>,
    bundle: BundleFiles,
) -> Result<core::convert::Infallible, &'static str> {
    let leaf7 = core::arch::x86_64::__cpuid_count(7, 0);
    if leaf7.ecx & CPUID_LA57 == 0 {
        return Err("system mode needs five-level paging (LA57), which this CPU lacks");
    }
    // SAFETY: written once at entry, read here.
    let snapshot = unsafe { *PRISTINE.0.get() }.ok_or("no pristine image copy")?;
    let image = firmware::Image::loaded()?;
    if image.start != snapshot.start || image.end - image.start != snapshot.bytes {
        return Err("image layout changed after the snapshot");
    }
    let engine = allocate(snapshot.bytes as u64)?;
    // SAFETY: two distinct live allocations of `bytes`.
    unsafe {
        core::ptr::copy_nonoverlapping(
            snapshot.copy as *const u8,
            engine.physical as *mut u8,
            snapshot.bytes,
        );
    }
    relocate(
        engine.physical as usize,
        snapshot.bytes,
        layout::IMAGE.wrapping_sub(image.start as u64),
    )?;
    let heap = allocate(HEAP_BYTES)?;
    let stack = allocate(STACK_BYTES)?;
    let code = allocate(CODE_BYTES)?;
    let pool = allocate(POOL_BYTES)?;
    let handoff_page = allocate(PAGE)?;
    let trampoline = low_page(MemoryType::LOADER_CODE)?;
    let root = low_page(MemoryType::LOADER_DATA)?;
    let screen = Framebuffer::from_firmware();
    let before = rdtsc();
    boot::stall(core::time::Duration::from_millis(50));
    let tsc_hz = (rdtsc() - before) * 20;
    let apic_base: u64 = {
        let (low, high): (u32, u32);
        // SAFETY: IA32_APIC_BASE exists on every x86-64 CPU.
        unsafe {
            asm!("rdmsr", in("ecx") APIC_BASE_MSR, out("eax") low, out("edx") high,
                options(nomem, nostack, preserves_flags));
        }
        (u64::from(high) << 32) | u64::from(low)
    };

    let mut frames = FirmwareFrames;
    let ram = firmware::ram()?;
    let image_rights: Vec<(u64, u64, u64)> = image
        .sections
        .iter()
        .map(|&(start, end, rights)| (start as u64, end as u64, rights))
        .chain(core::iter::once((trampoline, trampoline + PAGE, PRESENT)))
        .collect();
    identity(&mut frames, root, &ram, &image_rights)?;
    if let Some(screen) = &screen {
        let start = screen.base as u64 & !(PAGE - 1);
        let end = (screen.base + screen.bytes) as u64;
        tables::map_range(
            &mut frames,
            root,
            start,
            start,
            end.next_multiple_of(PAGE) - start,
            PRESENT | WRITABLE | NX,
        )?;
    }
    // The window: the engine image with section rights, heap, stack, code.
    for page in (0..snapshot.bytes as u64).step_by(PAGE as usize) {
        let rights = image.rights(image.start + page as usize);
        tables::map_page(
            &mut frames,
            root,
            layout::IMAGE + page,
            engine.physical + page,
            rights,
        )?;
    }
    let data = PRESENT | WRITABLE | NX;
    tables::map_range(
        &mut frames,
        root,
        layout::HEAP,
        heap.physical,
        heap.bytes,
        data,
    )?;
    tables::map_range(
        &mut frames,
        root,
        layout::STACK + PAGE,
        stack.physical,
        stack.bytes,
        data,
    )?;
    tables::map_range(
        &mut frames,
        root,
        layout::CODE,
        code.physical,
        code.bytes,
        PRESENT,
    )?;
    // The physmap: all RAM, the framebuffer and the local APIC.
    for &(start, end) in &ram {
        let (start, end) = (start as u64, end as u64);
        tables::map_range(
            &mut frames,
            root,
            layout::physical(start),
            start,
            end - start,
            data,
        )?;
    }
    if let Some(screen) = &screen {
        let start = screen.base as u64 & !(PAGE - 1);
        let end = ((screen.base + screen.bytes) as u64).next_multiple_of(PAGE);
        if !ram.iter().any(|r| r.0 as u64 <= start && end <= r.1 as u64) {
            tables::map_range(
                &mut frames,
                root,
                layout::physical(start),
                start,
                end - start,
                data,
            )?;
        }
    }
    let apic = apic_base & 0x000f_ffff_ffff_f000;
    if !ram.iter().any(|r| r.0 as u64 <= apic && apic < r.1 as u64) {
        tables::map_page(&mut frames, root, layout::physical(apic), apic, data)?;
    }
    let window = {
        // SAFETY: the root was just filled; entry 64 holds the window PML4.
        let entry = unsafe { (root as *const u64).add(layout::WINDOW_INDEX).read() };
        entry & tables::ADDRESS
    };

    let options_region = Region {
        physical: options.as_ptr() as u64,
        bytes: options.len() as u64,
    };
    let source_region = Region {
        physical: source.as_ptr() as u64,
        bytes: source.len() as u64,
    };
    let mut files = [File::default(); MAX_FILES];
    for (slot, (name, contents)) in files.iter_mut().zip(&bundle) {
        if name.len() > MAX_NAME {
            return Err("bundle file name too long");
        }
        slot.name[..name.len()].copy_from_slice(name.as_bytes());
        slot.name_bytes = name.len();
        slot.contents = Region {
            physical: contents.as_ptr() as u64,
            bytes: contents.len() as u64,
        };
    }
    let file_count = bundle.len();
    // All stay allocated: the engine reads them through the physmap.
    core::mem::forget(options);
    core::mem::forget(source);
    core::mem::forget(bundle);
    let handoff = handoff_page.physical as *mut Handoff;
    let engine_entry =
        layout::IMAGE + (crate::engine::entry as *const () as u64 - image.start as u64);

    // SAFETY: no protocol or pool allocation outlives this call; every page
    // Stela keeps is LOADER_DATA or LOADER_CODE.
    let map = unsafe { boot::exit_boot_services(None) };
    let mut guest = [Region::default(); MAX_GUEST_RANGES];
    let mut count = 0;
    for entry in map.entries() {
        if !matches!(
            entry.ty,
            MemoryType::CONVENTIONAL
                | MemoryType::BOOT_SERVICES_CODE
                | MemoryType::BOOT_SERVICES_DATA
        ) {
            continue;
        }
        let start = entry.phys_start.next_multiple_of(LARGE);
        let end = (entry.phys_start + entry.page_count * PAGE) & !(LARGE - 1);
        if end <= start || count == MAX_GUEST_RANGES {
            continue;
        }
        // Adjacent firmware entries merge into one range.
        if count > 0 && guest[count - 1].physical + guest[count - 1].bytes == start {
            guest[count - 1].bytes += end - start;
        } else {
            guest[count] = Region {
                physical: start,
                bytes: end - start,
            };
            count += 1;
        }
    }
    core::mem::forget(map);
    // SAFETY: a fresh LOADER_DATA page sized for the handoff.
    unsafe {
        handoff.write(Handoff {
            magic: MAGIC,
            options: options_region,
            source: source_region,
            files,
            file_count,
            heap,
            stack,
            code,
            pool,
            window,
            screen,
            tsc_hz,
            apic_base,
            guest,
            guest_count: count,
        });
    }
    // SAFETY: boot services are over, interrupts go off now, and the new
    // tables identity-map this code, its stack and the trampoline.
    unsafe {
        asm!("cli", options(nomem, nostack));
        paging::take_over()?;
        la57::enable(root, trampoline);
        asm!(
            "mov rsp, {stack}",
            "call {entry}",
            "ud2",
            stack = in(reg) layout::STACK + PAGE + STACK_BYTES,
            entry = in(reg) engine_entry,
            in("rdi") layout::physical(handoff as u64),
            options(noreturn),
        )
    }
}
