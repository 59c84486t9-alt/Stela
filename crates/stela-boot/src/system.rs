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
use alloc::{format, string::String, vec::Vec};
use core::{
    arch::asm,
    cell::UnsafeCell,
    ops::{Range, RangeInclusive},
};
use stela_boot_core::options::{DEFAULT_WIFI_KEY, System};
use stela_runtime::{
    machine::mmu::placement::Placement,
    pc::{self, gpt::Guid},
};
use uefi::{
    boot::{self, AllocateType, MemoryType},
    fs::FileSystem,
    mem::memory_map::MemoryMap,
    proto::loaded_image::LoadedImage,
};

use crate::native_smp::resources::{Resources as NativeResources, STACK_BYTES, STACK_STRIDE};
mod handoff_phase;
mod memory;
const MIB: u64 = 1024 * 1024;
/// The bounds of the parts of Stela's memory sized from host RAM
/// ([`Sizes::for_host`]).
const HEAP_BYTES: RangeInclusive<u64> = 512 * MIB..=2048 * MIB;
const CODE_BYTES: RangeInclusive<u64> = 128 * MIB..=512 * MIB;
const POOL_BYTES: RangeInclusive<u64> = 64 * MIB..=2048 * MIB;
/// Guest DRAM bytes per byte of each native executor's shadow page-table
/// pool: room for its 8 roots to map all of guest DRAM once in 4 KiB pages
/// (8 bytes per page). An exhausted half resets and refills everything; a
/// 26A434 restore's userland filled 8 MiB halves 20 to 80 times a beat.
const POOL_SHARE: u64 = 64;
/// Free host RAM bytes per byte of the engine heap and of the code arena.
const HEAP_SHARE: u64 = 16;
const CODE_SHARE: u64 = 64;
/// The code arena divides into parts of whole 2 MiB pages.
const CODE_ALIGNMENT: u64 = 16 * MIB;
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
    let Ok(extent) = firmware::loaded_extent(base as usize, bytes) else {
        return;
    };
    let bytes = extent.mapped_bytes;
    let Ok(copy) = boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        bytes / PAGE as usize,
    ) else {
        return;
    };
    // SAFETY: exact checked firmware source extent and distinct fresh owned
    // pages. Zero only the destination tail, without reading source padding.
    unsafe {
        core::ptr::copy_nonoverlapping(base.cast::<u8>(), copy.as_ptr(), extent.bytes);
        copy.as_ptr()
            .add(extent.bytes)
            .write_bytes(0, bytes - extent.bytes);
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

/// The engine heap, native code arena and page-table pool, sized at boot
/// from the host RAM free for them and the guest DRAM asked for
/// (`docs/design/system.md#memory-sizing`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sizes {
    heap: u64,
    code: u64,
    pool: u64,
}

impl Sizes {
    /// Each part takes a share of the `free` host RAM, between its bounds;
    /// the guest gets everything left. The pool scales with the guest DRAM
    /// each of the `cores` executors maps, of which `free` is the bound, and
    /// the code arena with the executors that run PEs: every one with
    /// `parallel`, else the BSP alone. Each other executor that runs PEs
    /// adds an eighth of the heap's share, for its machine's translation
    /// metadata.
    fn for_host(free: u64, cores: usize, parallel: bool) -> Self {
        let running = if parallel { cores as u64 } else { 1 };
        let heap = free / HEAP_SHARE + (running - 1) * (free / HEAP_SHARE / 8);
        let clamp = |bytes: u64, bounds: RangeInclusive<u64>, alignment: u64| {
            (bytes / alignment * alignment).clamp(*bounds.start(), *bounds.end())
        };
        Self {
            heap: clamp(heap, HEAP_BYTES, LARGE),
            code: clamp(free / CODE_SHARE, CODE_BYTES, CODE_ALIGNMENT) * running,
            pool: clamp(
                (free / POOL_SHARE).saturating_mul(cores as u64),
                POOL_BYTES,
                LARGE,
            ),
        }
    }
}

/// The host RAM the guest and Stela's parts may take: the free and boot
/// services ranges in whole 2 MiB pages, as the guest's ranges are found
/// after boot services end.
fn free_ram() -> Result<u64, &'static str> {
    let map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|_| "no memory map")?;
    Ok(map
        .entries()
        .filter(|entry| {
            matches!(
                entry.ty,
                MemoryType::CONVENTIONAL
                    | MemoryType::BOOT_SERVICES_CODE
                    | MemoryType::BOOT_SERVICES_DATA
            )
        })
        .map(|entry| {
            let start = entry.phys_start.next_multiple_of(LARGE);
            let end = (entry.phys_start + entry.page_count * PAGE) & !(LARGE - 1);
            end.saturating_sub(start)
        })
        .sum())
}

/// Whether a firmware memory map entry is RAM: every type but the reserved,
/// unusable, MMIO and PAL code ones.
fn is_ram(ty: MemoryType) -> bool {
    !matches!(
        ty,
        MemoryType::RESERVED
            | MemoryType::UNUSABLE
            | MemoryType::MMIO
            | MemoryType::MMIO_PORT_SPACE
            | MemoryType::PAL_CODE
    )
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

/// The guest inputs: `source.bin`, or with `--bundle DIR` the directory's
/// `bundle.json` and every file it lists, read unchanged into their own
/// pages. The bundle reader opens the volumes itself, so the configured
/// volume is closed first. With `--preboot SERIAL:GUID` nothing is read: the
/// engine builds the bundle from that disk with the host storage drivers,
/// whose ranges are found here, as they are for every other option that
/// opens a host controller: disks, the NOR store, input and the networks.
fn inputs(options: &[u8], mut volume: FileSystem) -> Result<Inputs, &'static str> {
    let text = core::str::from_utf8(options).map_err(|_| "stela.cfg is not UTF-8")?;
    let system = System::parse(text)?;
    #[cfg(not(feature = "diagnostics"))]
    if system.diagnostic_option().is_some() {
        return Err("diagnostic options require a diagnostics build");
    }
    // Read while the firmware's FAT driver runs; the engine reports a file
    // it cannot use.
    let wifi_key = system
        .ssid
        .as_ref()
        .and_then(|_| {
            let path = system.wifi_key.as_deref().unwrap_or(DEFAULT_WIFI_KEY);
            let path = uefi::CString16::try_from(path).ok()?;
            volume.read(uefi::fs::PathBuf::from(path)).ok()
        })
        .unwrap_or_default();
    let host_devices = system.storage.is_some()
        || system.preboot.is_some()
        || system.restore_source.is_some()
        || system.install_source.is_some()
        || system.nor.is_some()
        || system.network_check.is_some()
        || system.audio_check.is_some()
        || !system.usb_storage.is_empty()
        || system.input
        || system.tss
        || system.guest_network;
    let storage = if host_devices {
        crate::status::begin("Finding the PCI devices Stela drives itself");
        let found = storage::discover()?;
        crate::status::done("");
        Some(found)
    } else {
        None
    };
    let (source, mut files) = if system.preboot.is_some() {
        drop(volume);
        (Vec::new(), Vec::new())
    } else if let Some(directory) = system.bundle_directory.as_deref() {
        drop(volume);
        (Vec::new(), crate::engine::bundle::read(directory)?)
    } else {
        let source = firmware::source(&mut volume)?;
        drop(volume);
        (source, Vec::new())
    };
    let inventory = match (
        system.restore_manifest_path.as_deref(),
        system.install.as_deref(),
    ) {
        (Some(_), Some(_)) => return Err("--install and --restore-manifest name one inventory"),
        (Some(path), None) => Some(crate::engine::bundle::restore_inventory(path)?),
        // The install medium's pieces are checked through the firmware's
        // FAT driver now, while it is there; the engine reads them through
        // its own after boot services end.
        (None, Some(path)) => {
            crate::status::begin("Checking the macOS install files on the USB");
            let inventory =
                crate::engine::bundle::with_inventory(path, crate::engine::install::check_pieces)?;
            crate::status::done("");
            Some(inventory)
        }
        (None, None) => None,
    };
    if let Some(inventory) = inventory {
        let reserved = [
            RESTORE_INVENTORY_FILE,
            RESTORE_BLOCKS_FILE,
            INSTALL_PIECES_FILE,
            stela_runtime::restore::fdr::FILE,
        ];
        if files
            .iter()
            .any(|(name, _)| reserved.contains(&name.as_str()))
        {
            return Err("a bundle file takes a name the restore inventory reserves");
        }
        files.push((String::from(RESTORE_INVENTORY_FILE), inventory.manifest));
        if let Some(diagnostic) = inventory.fdr_diagnostic {
            files.push((String::from(stela_runtime::restore::fdr::FILE), diagnostic));
        }
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
    crate::status::begin("Opening the translation cache");
    let translations = crate::engine::translations::read();
    match &translations {
        Some((store, true)) => crate::status::done(&format!("{} MB", store.bytes >> 20)),
        Some((store, false)) => crate::status::warn(&format!(
            "{} MB; new translations stay in memory this boot: `stela setup repair` prepares \
             the file",
            store.bytes >> 20
        )),
        None => crate::status::done("none on this USB"),
    }
    if files.len() < MAX_FILES
        && let Some((store, writable)) = translations
    {
        files.push((String::from(crate::engine::translations::FILE), store));
        if writable && storage.is_none() {
            storage = storage::discover().ok();
        }
    }
    Ok((source, files, storage, wifi_key))
}

/// `source.bin`, the bundle files, the storage drivers' ranges and the
/// Wi-Fi key file's bytes.
type Inputs = (
    Vec<u8>,
    BundleFiles,
    Option<stela_drivers::Handoff>,
    Vec<u8>,
);

/// `EFI_MEMORY_RUNTIME`: the region stays the firmware's after boot
/// services, for its runtime services.
const RUNTIME_ATTRIBUTE: u64 = 1 << 63;

/// The firmware's runtime regions, and its `ResetSystem` service: zero when
/// the system table has none.
struct Runtime {
    regions: Vec<(u64, u64, MemoryType)>,
    reset: u64,
}

impl Runtime {
    /// Read before boot services end. Without SetVirtualAddressMap the
    /// firmware's runtime services run at their physical addresses.
    fn capture() -> Result<Self, &'static str> {
        let map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|_| "no memory map")?;
        let regions = map
            .entries()
            .filter(|entry| entry.att.bits() & RUNTIME_ATTRIBUTE != 0)
            .map(|entry| {
                let start = entry.phys_start;
                (start, start + entry.page_count * PAGE, entry.ty)
            })
            .collect();
        let reset = uefi::table::system_table_raw().map_or(0, |table| {
            // SAFETY: the firmware's live system table, before EBS.
            let runtime = unsafe { table.as_ref().runtime_services };
            if runtime.is_null() {
                0
            } else {
                // SAFETY: as above; its runtime services table.
                unsafe { (*runtime).reset_system as usize as u64 }
            }
        });
        Ok(Self { regions, reset })
    }

    /// Runtime code, which the identity map makes writable and executable,
    /// as Linux maps it without a memory attributes table.
    fn code(&self) -> impl Iterator<Item = (u64, u64, u64)> + '_ {
        self.regions
            .iter()
            .filter(|&&(_, _, kind)| runtime_code(kind))
            .map(|&(start, end, _)| (start, end, PRESENT | WRITABLE))
    }

    /// Map the runtime regions outside RAM by identity: device registers
    /// uncached, anything else write-back, code RWX and the rest RW+NX. A
    /// region overlapping RAM, which the identity map holds, or the storage
    /// registers, mapped already, is left as it is.
    fn map(
        &self,
        frames: &mut dyn Frames,
        root: u64,
        ram: &[(usize, usize)],
        devices: &[Range<u64>],
    ) -> Result<(), &'static str> {
        for &(start, end, kind) in &self.regions {
            let overlaps = ram.iter().any(|r| (r.0 as u64) < end && start < r.1 as u64)
                || devices
                    .iter()
                    .any(|r| r.start & !(PAGE - 1) < end && start < r.end.next_multiple_of(PAGE));
            if overlaps {
                continue;
            }
            let attributes = match kind {
                MemoryType::MMIO | MemoryType::MMIO_PORT_SPACE => NX | UNCACHED,
                _ if runtime_code(kind) => 0,
                _ => NX,
            };
            for page in (start..end).step_by(PAGE as usize) {
                tables::map_page(frames, root, page, page, PRESENT | WRITABLE | attributes)?;
            }
        }
        Ok(())
    }
}

fn runtime_code(kind: MemoryType) -> bool {
    matches!(
        kind,
        MemoryType::RUNTIME_SERVICES_CODE | MemoryType::PAL_CODE
    )
}

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

/// What the menu says when the machine can only be restored.
fn held(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::BlankDisk => "The Mac's SSD is not prepared yet: choose Install macOS first.",
        Refusal::NoRecovery { installed: false } => {
            "No macOS is installed and the Mac's SSD holds no System Recovery: choose Install \
             macOS."
        }
        Refusal::NoRecovery { installed: true } => {
            "NVRAM asks for recoveryOS, which the Mac's SSD does not hold: choose Install macOS."
        }
        _ => "The Mac's last install did not finish: choose Install macOS again.",
    }
}

/// Why the default boot, `options`, can only wait for a restore, checked
/// before the startup menu opens so that the menu starts there.
pub fn held_at_start(options: &[u8]) -> Option<&'static str> {
    if !options.starts_with(b"--system") {
        return None;
    }
    if crate::choice::unchosen(options) {
        return Some("No disk is chosen for macOS yet: choose Install macOS first.");
    }
    crate::status::begin("Checking the internal SSD and NVRAM");
    let (held, found) = match crate::selection::peek(options.to_vec()) {
        Err(refusal @ Refusal::BlankDisk) => (Some(held(refusal)), "no macOS installed yet"),
        Err(refusal @ Refusal::RecoveryMode) => (Some(held(refusal)), "an install did not finish"),
        Err(refusal @ Refusal::NoRecovery { .. }) => (Some(held(refusal)), "no recoveryOS to boot"),
        _ => (None, ""),
    };
    crate::status::done(found);
    held
}

/// Run the engine; never returns.
/// `log` is the partition holding the USB's boot log, when the loader keeps
/// one there (`log_file`).
pub fn boot(
    mut options: Vec<u8>,
    mut volume: FileSystem,
    log: Option<Guid>,
    host_firmware: crate::host_firmware::Resources,
) -> ! {
    // NVRAM chooses macOS or recoveryOS before any input is read. A machine
    // NVRAM holds in recovery mode waits at the startup choices, as LLB
    // waits for a restore host, until one that boots is chosen.
    let options = loop {
        crate::status::begin("Reading the startup request in NVRAM");
        let routed = crate::selection::route(options);
        crate::status::done("");
        match routed {
            Ok(routed) => break routed,
            Err(Refusal::Other(error)) => output::fatal(error),
            Err(refusal) => {
                options = crate::choice::hold(&mut volume, held(refusal)).unwrap_or_else(|| {
                    output::fatal(
                        "the machine can only be restored and this volume has no startup \
                         choices to restore it from",
                    )
                });
                if !options.starts_with(b"--system") {
                    output::fatal("the chosen startup option is not a system-mode boot");
                }
                crate::status::take_screen(Framebuffer::from_firmware());
            }
        }
    };
    // `inputs` closes the volume: protocols must be closed before boot
    // services end.
    let inputs = inputs(&options, volume);
    let result = inputs.and_then(|(source, files, storage, wifi_key)| {
        load(
            options,
            source,
            files,
            storage,
            wifi_key,
            log,
            host_firmware,
        )
    });
    match result {
        Ok(never) => match never {},
        Err(error) => output::fatal(error),
    }
}

fn load(
    options: Vec<u8>,
    source: Vec<u8>,
    bundle: BundleFiles,
    storage: Option<stela_drivers::Handoff>,
    wifi_key: Vec<u8>,
    log: Option<Guid>,
    host_firmware: crate::host_firmware::Resources,
) -> Result<core::convert::Infallible, &'static str> {
    crate::status::begin("Setting up Stela's memory");
    let image = memory::prepare_image()?;
    let text = core::str::from_utf8(&options).map_err(|_| "stela.cfg is not UTF-8")?;
    let system = System::parse(text)?;
    let (native_processors, cores) =
        crate::native_smp::firmware::capture_assignment(system.native_cores)
            .map_err(crate::native_smp::firmware::Error::message)?;
    let mut memory = memory::reserve(&system, cores, &image.ram)?;
    let tsc_hz = crate::firmware::tsc_hz();
    if !crate::cpu::INVARIANT_TSC.present() {
        output::arguments(format_args!(
            "UNSUPPORTED host TSC is not invariant: guest time and every timeout follow the cores' clock changes\n"
        ));
    }
    let wall_tsc = rdtsc();
    let wall_seconds = uefi::runtime::get_time()
        .ok()
        .and_then(|time| unix_seconds(&time));
    let power = host_power();
    let random_seed = match crate::entropy::retain_seed() {
        Ok((region, source)) => {
            output::arguments(format_args!("HOST entropy seeded source={source}\n"));
            region
        }
        Err(error) => {
            output::arguments(format_args!("UNSUPPORTED host entropy: {error}\n"));
            Region::default()
        }
    };

    let remapping = crate::native_dma::firmware_units()?;

    let native_mmio = match crate::native_mmio::Prepared::capture() {
        Ok(prepared) => Some(prepared),
        Err(error) => {
            output::arguments(format_args!("NATIVE MMIO unavailable capture={error}\n"));
            None
        }
    };

    let runtime = Runtime::capture()?;
    let storage = memory::map(
        &image,
        &mut memory,
        &runtime,
        storage.as_ref(),
        native_mmio.as_ref(),
        &host_firmware,
    )?;
    let memory::EngineImage {
        image,
        placement,
        screen,
        apic_base,
        ..
    } = image;
    let memory::EngineMemory {
        heap,
        native_resources,
        stack,
        code,
        pool,
        handoff_page,
        trampoline,
        root,
    } = memory;
    let bounce = native_resources.bounce[0];
    let handoff_phase::RetainedFiles {
        options: options_region,
        source: source_region,
        files,
        file_count,
    } = handoff_phase::retain_files(options, source, bundle)?;
    let handoff = handoff_page.physical as *mut Handoff;
    let engine_entry =
        layout::image() + (crate::engine::entry as *const () as u64 - image.start as u64);

    crate::status::done("");
    // SAFETY: the fresh immutable MP observation is retained LOADER_DATA. Identity
    // mappings and the calibrated local APIC remain valid across EBS.
    let capture = unsafe {
        crate::native_smp::firmware::Capture::read(native_processors.physical as *const u8)
    };
    let sender = crate::apic::Apic::new(apic_base, apic_base & crate::apic::BASE_ADDRESS);
    crate::status::begin("Taking control of the other processors");
    crate::output::leave_boot_services();
    // SAFETY: no protocol or pool allocation outlives this call; every page
    // Stela keeps is LOADER_DATA or LOADER_CODE.
    let map = unsafe { boot::exit_boot_services(None) };
    // SAFETY: the firmware's identity map is still loaded, the APs idle in
    // firmware code, and no Stela driver or memory reuse has started.
    unsafe { crate::native_dma::release_firmware_units(&remapping, tsc_hz) };
    let native_mmio_region = match native_mmio {
        Some(prepared) => match prepared.finish(&map) {
            Ok(()) => prepared.region(),
            Err(error) => {
                output::arguments(format_args!("NATIVE MMIO unavailable final-map={error}\n"));
                Region::default()
            }
        },
        None => Region::default(),
    };
    // Stop every enabled firmware AP before offering its former code/data to
    // guest RAM, including workers that will later receive their owned SIPI.
    // The BSP alone sends ICR commands, with firmware IRQ handlers excluded.
    unsafe { asm!("cli", options(nomem, nostack)) };
    let deliveries = match unsafe {
        crate::native_smp::executor::quiesce_firmware_aps(capture, &sender, tsc_hz)
    } {
        Ok(deliveries) => deliveries,
        Err(error) => {
            output::arguments(format_args!("NATIVE FIRMWARE INIT refused: {error:?}\n"));
            output::fatal("firmware processor handoff refused before memory reuse");
        }
    };
    output::arguments(format_args!(
        "NATIVE FIRMWARE INIT deliveries={deliveries}; delivery only, no execution acknowledgement\n"
    ));
    crate::status::done("directed INIT delivery complete");
    // Keep this post-EBS boundary when the relocated engine replays status.
    let mut history = [0; crate::status::HISTORY_BYTES];
    let history_bytes = crate::status::history(&mut history);
    let handoff_phase::GuestMemory {
        ranges: guest,
        count,
        installed,
    } = handoff_phase::guest_memory(&map);
    core::mem::forget(map);
    // SAFETY: fresh LOADER_DATA pages sized for the handoff.
    unsafe {
        handoff.write(Handoff {
            magic: MAGIC,
            options: options_region,
            random_seed,
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
            history,
            history_bytes,
            log_partition: log.map(|guid| guid.0),
            tsc_hz,
            apic_base,
            native_processors,
            native_resources,
            native_mmio: native_mmio_region,
            wall_seconds,
            wall_tsc,
            guest,
            guest_count: count,
            installed,
            storage,
            host_firmware,
            power,
            efi_reset: runtime.reset,
            rsdp: storage::rsdp().unwrap_or(0),
            wifi_key: Region {
                physical: wifi_key.as_ptr() as u64,
                bytes: wifi_key.len() as u64,
            },
        });
    }
    // SAFETY: boot services ended; the completed root maps this code and
    // trampoline, and all engine-window reservations remain allocated.
    unsafe {
        handoff_phase::Transfer {
            placement,
            root,
            trampoline,
            engine_entry,
            handoff,
        }
        .enter()
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
