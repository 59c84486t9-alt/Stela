//! System mode, loader phase: everything that needs the firmware.
//!
//! It runs identity-mapped under the firmware. It keeps a pristine copy of
//! this image (taken before any Rust state exists), chooses the host
//! placement, places a relocated copy in the Stela window, allocates the
//! engine's memory, builds its page tables (five-level under LA57, else
//! four-level), leaves boot services, loads them, through the LA57
//! trampoline when five-level, and calls the engine phase in the window. See
//! `docs/design/system.md#host-placement`.
use crate::{
    console::Framebuffer,
    firmware,
    handoff::{File, Handoff, MAGIC, MAX_FILES, MAX_GUEST_RANGES, MAX_NAME, Region, Storage},
    la57, layout, output, paging,
    selection::Refusal,
    storage,
    tables::{self, Frames, LARGE, NX, PAGE, PRESENT, UNCACHED, WRITABLE, WRITE_COMBINING},
};
use alloc::{string::String, vec::Vec};
use core::{arch::asm, cell::UnsafeCell, ops::Range};
use stela_runtime::{machine::mmu::placement::Placement, pc};
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
        .map_err(|_| "no page below 4 GiB for the page-table root")?;
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

/// Bundle files by name, `bundle.json` first, each in its own pages.
type BundleFiles = Vec<(String, Region)>;

/// The names the restore inventory and its block hashes take among the
/// bundle files the engine receives.
pub const RESTORE_INVENTORY_FILE: &str = "restore-payload.json";
pub const RESTORE_BLOCKS_FILE: &str = "restore-blocks.bin";
pub const INSTALL_PIECES_FILE: &str = "install-pieces.bin";

/// The value after `name` in the options, as text.
fn option<'a>(options: &'a str, name: &str) -> Option<&'a str> {
    let mut words = options.split_ascii_whitespace();
    words.find(|word| *word == name)?;
    words.next()
}

/// The guest inputs: `source.bin`, or with `--bundle DIR` the directory's
/// `bundle.json` and every file it lists, read unchanged into their own
/// pages. The bundle reader opens the volumes itself, so the configured
/// volume is closed first. With `--preboot SERIAL:GUID` nothing is read: the
/// engine builds the bundle from that disk with the host storage drivers,
/// whose ranges are found here, as they are for every other option that
/// opens a host controller: disks, the NOR store, input and the networks.
fn inputs(options: &[u8], mut volume: FileSystem) -> Result<Inputs, &'static str> {
    let text = core::str::from_utf8(options).map_err(|_| "stela.cfg is not UTF-8")?;
    let host_devices = [
        "--storage",
        "--preboot",
        "--restore-source",
        "--install-source",
        "--nor",
        "--network-check",
        "--usb-storage",
    ]
    .iter()
    .any(|key| option(text, key).is_some())
        || text
            .split_ascii_whitespace()
            .any(|word| matches!(word, "--input" | "--tss" | "--guest-network"));
    let storage = if host_devices {
        Some(storage::discover()?)
    } else {
        None
    };
    let (source, mut files) = if option(text, "--preboot").is_some() {
        drop(volume);
        (Vec::new(), Vec::new())
    } else if let Some(directory) = option(text, "--bundle") {
        drop(volume);
        (Vec::new(), crate::engine::bundle::read(directory)?)
    } else {
        let source = firmware::source(&mut volume)?;
        drop(volume);
        (source, Vec::new())
    };
    let inventory = match (
        option(text, "--restore-manifest"),
        option(text, crate::engine::INSTALL_OPTION),
    ) {
        (Some(_), Some(_)) => return Err("--install and --restore-manifest name one inventory"),
        (Some(path), None) => Some(crate::engine::bundle::restore_inventory(path)?),
        // The install medium's pieces are checked through the firmware's
        // FAT driver now, while it is there; the engine reads them through
        // its own after boot services end.
        (None, Some(path)) => Some(crate::engine::bundle::with_inventory(
            path,
            crate::engine::install::check_pieces,
        )?),
        (None, None) => None,
    };
    if let Some(inventory) = inventory {
        let reserved = [
            RESTORE_INVENTORY_FILE,
            RESTORE_BLOCKS_FILE,
            INSTALL_PIECES_FILE,
        ];
        if files
            .iter()
            .any(|(name, _)| reserved.contains(&name.as_str()))
        {
            return Err("a bundle file takes a name the restore inventory reserves");
        }
        files.push((String::from(RESTORE_INVENTORY_FILE), inventory.manifest));
        if let Some(blocks) = inventory.blocks {
            files.push((String::from(RESTORE_BLOCKS_FILE), blocks));
        }
        if let Some(pieces) = inventory.pieces {
            files.push((String::from(INSTALL_PIECES_FILE), pieces));
        }
    }
    if files.len() > MAX_FILES {
        return Err("bundle lists too many files");
    }
    // The translation store, when a volume has one and a file slot is
    // left; rewriting its pack needs the storage drivers.
    let mut storage = storage;
    if files.len() < MAX_FILES
        && let Some((store, writable)) = crate::engine::translations::read()
    {
        files.push((String::from(crate::engine::translations::FILE), store));
        if writable && storage.is_none() {
            storage = storage::discover().ok();
        }
    }
    Ok((source, files, storage))
}

/// `source.bin`, the bundle files, and the storage drivers' ranges.
type Inputs = (Vec<u8>, BundleFiles, Option<pc::Handoff>);

/// Identity-map the storage controllers' registers uncached; none may
/// overlap RAM.
fn map_devices(
    frames: &mut dyn Frames,
    root: u64,
    ram: &[(usize, usize)],
    ranges: &[Range<u64>],
) -> Result<(), &'static str> {
    for range in ranges {
        let start = range.start & !(PAGE - 1);
        let end = range.end.next_multiple_of(PAGE);
        if ram.iter().any(|r| (r.0 as u64) < end && start < r.1 as u64) {
            return Err("storage registers overlap RAM");
        }
        tables::map_range(
            frames,
            root,
            start,
            start,
            end - start,
            PRESENT | WRITABLE | NX | UNCACHED,
        )?;
    }
    Ok(())
}

/// Run the engine; never returns.
pub fn boot(mut options: Vec<u8>, mut volume: FileSystem) -> ! {
    // NVRAM chooses macOS or recoveryOS before any input is read. A machine
    // NVRAM holds in recovery mode waits at the startup choices, as LLB
    // waits for a restore host, until one that boots is chosen.
    let options = loop {
        match crate::selection::route(options) {
            Ok(routed) => break routed,
            Err(Refusal::Other(error)) => output::fatal(error),
            Err(Refusal::RecoveryMode) => {
                options = crate::choice::hold(&mut volume).unwrap_or_else(|| {
                    output::fatal(
                        "NVRAM holds the machine in recovery mode and this volume has no \
                         startup choices to restore it from",
                    )
                });
                if !options.starts_with(b"--system") {
                    output::fatal("the chosen startup option is not a system-mode boot");
                }
            }
        }
    };
    // `inputs` closes the volume: protocols must be closed before boot
    // services end.
    let inputs = inputs(&options, volume);
    let result = inputs.and_then(|(source, files, storage)| load(options, source, files, storage));
    match result {
        Ok(never) => match never {},
        Err(error) => output::fatal(error),
    }
}

fn load(
    options: Vec<u8>,
    source: Vec<u8>,
    bundle: BundleFiles,
    storage: Option<pc::Handoff>,
) -> Result<core::convert::Infallible, &'static str> {
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
    let ram = firmware::ram()?;
    let screen = Framebuffer::from_firmware();
    let apic_base = crate::apic::base_msr();
    // The physmap reaches RAM, the framebuffer and the local APIC.
    let apic = apic_base & crate::apic::BASE_ADDRESS;
    let top = ram
        .iter()
        .map(|r| r.1 as u64)
        .chain(screen.iter().map(|s| (s.base + s.bytes) as u64))
        .chain(core::iter::once(apic + PAGE))
        .max()
        .unwrap_or(0);
    let placement = layout::choose(crate::cpu::LA57.present(), top)
        .ok_or("host physical addresses lie beyond what any placement's physmap reaches")?;
    layout::set(placement);
    relocate(
        engine.physical as usize,
        snapshot.bytes,
        layout::image().wrapping_sub(image.start as u64),
    )?;
    let heap = allocate(HEAP_BYTES)?;
    let stack = allocate(STACK_BYTES)?;
    let code = allocate(CODE_BYTES)?;
    let pool = allocate(POOL_BYTES)?;
    let handoff_page = allocate(size_of::<Handoff>() as u64)?;
    let trampoline = low_page(MemoryType::LOADER_CODE)?;
    let root = low_page(MemoryType::LOADER_DATA)?;
    let before = rdtsc();
    boot::stall(core::time::Duration::from_millis(50));
    let tsc_hz = (rdtsc() - before) * 20;
    let wall_tsc = rdtsc();
    let wall_seconds = uefi::runtime::get_time()
        .ok()
        .and_then(|time| unix_seconds(&time));
    let power = host_power();

    let mut frames = FirmwareFrames;
    let image_rights: Vec<(u64, u64, u64)> = image
        .sections
        .iter()
        .map(|&(start, end, rights)| (start as u64, end as u64, rights))
        .chain(core::iter::once((trampoline, trampoline + PAGE, PRESENT)))
        .collect();
    identity(&mut frames, root, &ram, &image_rights)?;
    if let Some(storage) = &storage {
        map_devices(&mut frames, root, &ram, &storage.mapped)?;
    }
    let storage = match &storage {
        Some(storage) => Storage::new(storage)?,
        None => Storage::absent(),
    };
    // The framebuffer is written, never read back, so its writes combine.
    let video = PRESENT | WRITABLE | NX | WRITE_COMBINING;
    if let Some(screen) = &screen {
        let start = screen.base as u64 & !(PAGE - 1);
        let end = (screen.base + screen.bytes) as u64;
        tables::map_range(
            &mut frames,
            root,
            start,
            start,
            end.next_multiple_of(PAGE) - start,
            video,
        )?;
    }
    // The window: the engine image with section rights, heap, stack, code.
    for page in (0..snapshot.bytes as u64).step_by(PAGE as usize) {
        let rights = image.rights(image.start + page as usize);
        tables::map_page(
            &mut frames,
            root,
            layout::image() + page,
            engine.physical + page,
            rights,
        )?;
    }
    let data = PRESENT | WRITABLE | NX;
    tables::map_range(
        &mut frames,
        root,
        layout::heap(),
        heap.physical,
        heap.bytes,
        data,
    )?;
    tables::map_range(
        &mut frames,
        root,
        layout::stack() + PAGE,
        stack.physical,
        stack.bytes,
        data,
    )?;
    tables::map_range(
        &mut frames,
        root,
        layout::code(),
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
                video,
            )?;
        }
    }
    // The xAPIC page must be strong uncacheable (Intel SDM Vol. 3A 11.4.1);
    // the entry says so rather than relying on the firmware's MTRRs.
    if !ram.iter().any(|r| r.0 as u64 <= apic && apic < r.1 as u64) {
        tables::map_page(
            &mut frames,
            root,
            layout::physical(apic),
            apic,
            data | UNCACHED,
        )?;
    }
    // The bounce slot's leaf entries, which the translation helper points
    // at guest frames; until then they map a scratch page.
    let scratch = allocate(PAGE)?.physical;
    let mut bounce = [0; 2];
    for (index, slot) in bounce.iter_mut().enumerate() {
        let address = layout::bounce() + index as u64 * PAGE;
        tables::map_page(&mut frames, root, address, scratch, data)?;
        let entry = tables::entry(&mut frames, root, address, 0, false)?;
        *slot = entry.ok_or("bounce slot unmapped")? as u64;
    }

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
        slot.contents = *contents;
    }
    let file_count = bundle.len();
    // All stay allocated: the engine reads them through the physmap.
    core::mem::forget(options);
    core::mem::forget(source);
    core::mem::forget(bundle);
    let handoff = handoff_page.physical as *mut Handoff;
    let engine_entry =
        layout::image() + (crate::engine::entry as *const () as u64 - image.start as u64);

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
    // SAFETY: fresh LOADER_DATA pages sized for the handoff.
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
            placement,
            root,
            bounce,
            screen,
            tsc_hz,
            apic_base,
            wall_seconds,
            wall_tsc,
            guest,
            guest_count: count,
            storage,
            power,
        });
    }
    // SAFETY: boot services are over, interrupts go off now, and the new
    // tables identity-map this code, its stack and the trampoline.
    unsafe {
        asm!("cli", options(nomem, nostack));
        paging::take_over()?;
        match placement {
            Placement::FiveLevel => la57::enable(root, trampoline),
            Placement::FourLevel { .. } => {
                asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags))
            }
        }
        asm!(
            "mov rsp, {stack}",
            "call {entry}",
            "ud2",
            stack = in(reg) layout::stack() + PAGE + STACK_BYTES,
            entry = in(reg) engine_entry,
            in("rdi") layout::physical(handoff as u64),
            options(noreturn),
        )
    }
}

/// The host's ACPI power hardware, reported while the firmware's tables
/// are still mapped; the engine gets it without the report.
pub(crate) fn host_power() -> Option<pc::power::HostPower> {
    let rsdp = storage::rsdp()?;
    // SAFETY: the firmware's RSDP, its tables mapped while boot services last.
    match unsafe { pc::power::discover(rsdp) } {
        Ok(power) => {
            if let Some(reason) = power.refused {
                output::arguments(format_args!("POWER host refusal: {reason}\n"));
            }
            Some(pc::power::HostPower {
                refused: None,
                ..power
            })
        }
        Err(error) => {
            output::arguments(format_args!("POWER host has no usable FADT: {error:?}\n"));
            None
        }
    }
}

/// UEFI `Time` as Unix seconds. A specified `TimeZone` is the local time's
/// offset from UTC in minutes (UEFI 2.7 and later: UTC = local − zone); an
/// unspecified zone is taken as UTC, as QEMU and Macs keep their RTC.
fn unix_seconds(time: &uefi::runtime::Time) -> Option<u64> {
    let (year, month, day) = (
        i64::from(time.year()),
        i64::from(time.month()),
        i64::from(time.day()),
    );
    if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Days from the civil date (Howard Hinnant's days_from_civil).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let mut seconds = days * 86_400
        + i64::from(time.hour()) * 3600
        + i64::from(time.minute()) * 60
        + i64::from(time.second());
    if let Some(zone) = time.time_zone() {
        seconds -= i64::from(zone) * 60;
    }
    u64::try_from(seconds).ok()
}
