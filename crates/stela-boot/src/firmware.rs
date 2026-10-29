//! What Stela takes from the firmware before leaving boot services: its
//! options and guest image from the boot volume, RAM for the heap, stack and
//! frame arenas, the framebuffer, and the memory map its page tables cover.
use crate::Result;
use crate::console::Framebuffer;
use crate::paging::{LARGE_PAGE, NX, PAGE, PRESENT, Tables, WRITABLE};
use alloc::vec::Vec;
use core::{
    ffi::c_void,
    ptr::NonNull,
    sync::atomic::{AtomicPtr, AtomicU8, AtomicU64, Ordering},
    time::Duration,
};
use stela_contracts::refuse;
use stela_engine::freestanding::BootArena;
use uefi::{
    CStr16, Event,
    boot::{self, AllocateType, EventType, MemoryType, TimerTrigger, Tpl},
    cstr16,
    fs::FileSystem,
    mem::memory_map::MemoryMap,
    proto::{
        loaded_image::LoadedImage,
        media::{file::Directory, fs::SimpleFileSystem},
    },
};

/// Mount options.
const OPTIONS: &CStr16 = cstr16!("\\EFI\\stela\\stela.cfg");
/// A system-mode guest image without a bundle, loaded unchanged.
const SOURCE: &CStr16 = cstr16!("\\EFI\\stela\\source.bin");
pub(crate) const STACK_PAGES: usize = 256;

pub(crate) mod entries;
pub(crate) use pe::loaded_extent;
use stela_boot_core::pe;

/// What the host storage check runs with after boot services end.
pub struct Handoff {
    pub stack_top: usize,
    /// The builder after activation; configuration factories must
    /// additionally check resources/current context before hardware access.
    pub(crate) active_tables: Option<crate::paging::ActivatedTables>,
    /// The firmware's framebuffer, mapped RW+NX, when it has a usable one.
    pub screen: Option<Framebuffer>,
    /// The disks `stela.cfg` names, until the check takes them.
    pub storage: Option<crate::storage::Prepared>,
}

pub(crate) fn pages(count: usize) -> Result<usize> {
    boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, count)
        .map(|page| page.as_ptr() as usize)
        .map_err(|_| refuse!("firmware has no memory for Stela"))
}

fn configured(volume: &mut FileSystem) -> bool {
    matches!(volume.try_exists(OPTIONS), Ok(true))
}

fn boot_volume() -> Option<(FileSystem, Directory)> {
    let mut protocol = boot::get_image_file_system(boot::image_handle()).ok()?;
    let root = protocol.open_volume().ok()?;
    Some((FileSystem::new(protocol), root))
}

/// Connect every controller to its drivers, recursively, as a boot manager
/// does before it lists boot options (edk2 `EfiBootManagerConnectAll`). A
/// firmware that boots fast connects only the path to the boot loader, and
/// the bundle, the install medium and the host disks lie on other
/// partitions and devices. A controller no driver takes stays as it was.
/// Returns how many handles there were.
pub(crate) fn connect_all() -> usize {
    let Ok(handles) = boot::locate_handle_buffer(boot::SearchType::AllHandles) else {
        return 0;
    };
    for &handle in handles.iter() {
        let _ = boot::connect_controller(handle, &[], None, true);
    }
    handles.len()
}

/// The first file system that has `stela.cfg`.
fn configured_volume() -> Option<(FileSystem, Directory)> {
    boot::find_handles::<SimpleFileSystem>()
        .ok()?
        .into_iter()
        .find_map(|handle| {
            let mut protocol = boot::open_protocol_exclusive::<SimpleFileSystem>(handle).ok()?;
            let root = protocol.open_volume().ok()?;
            let mut volume = FileSystem::new(protocol);
            configured(&mut volume).then_some((volume, root))
        })
}

/// The volume Stela was loaded from. When the firmware names no such volume,
/// as for an image a boot manager starts from memory, or that volume has no
/// `stela.cfg`, the first volume with one is used instead.
pub(crate) fn volume() -> Result<(FileSystem, Directory)> {
    let own = boot_volume().map(|(mut volume, root)| {
        let configured = configured(&mut volume);
        ((volume, root), configured)
    });
    Ok(match own {
        Some((volume, true)) => volume,
        Some((volume, false)) => {
            // Close the boot volume so the scan can open every volume.
            drop(volume);
            match configured_volume() {
                Some(volume) => volume,
                None => boot_volume().ok_or(refuse!("cannot reopen the boot volume"))?,
            }
        }
        None => configured_volume().ok_or(refuse!(
            "no boot volume, and no volume has \\EFI\\stela\\stela.cfg"
        ))?,
    })
}

/// `stela.cfg`, or nothing when the volume has none.
pub(crate) fn options(volume: &mut FileSystem) -> Result<Vec<u8>> {
    if configured(volume) {
        volume
            .read(OPTIONS)
            .map_err(|_| refuse!("cannot read stela.cfg"))
    } else {
        Ok(Vec::new())
    }
}

/// `\EFI\stela\source.bin`, the unchanged guest image.
pub(crate) fn source(volume: &mut FileSystem) -> Result<Vec<u8>> {
    volume
        .read(SOURCE)
        .map_err(|_| refuse!("cannot read \\EFI\\stela\\source.bin"))
}

/// Page rights of Stela's own PE image: code RX, constants R, data RW+NX.
pub(crate) struct Image {
    pub start: usize,
    pub end: usize,
    pub sections: Vec<(usize, usize, u64)>,
}

impl Image {
    pub(crate) fn loaded() -> Result<Self> {
        let image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
            .map_err(|_| refuse!("no loaded image"))?;
        let (base, bytes) = image.info();
        let extent = loaded_extent(base as usize, bytes)?;
        let sections = pe::sections(extent.bytes, |offset, out| {
            // SAFETY: pe::sections checks each short read against the exact
            // firmware-owned LoadedImage extent before invoking this callback.
            // No shared slice covers live writable image statics.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    base.cast::<u8>().add(offset),
                    out.as_mut_ptr(),
                    out.len(),
                );
            }
        })?
        .into_iter()
        .map(|section| {
            let rights = if section.executable {
                PRESENT
            } else if section.writable {
                PRESENT | WRITABLE | NX
            } else {
                PRESENT | NX
            };
            // Both RVAs lie within the checked loaded extent.
            (
                extent.start + section.first,
                extent.start + section.end,
                rights,
            )
        })
        .collect();
        Ok(Self {
            start: extent.start,
            end: extent.end,
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
pub(crate) fn ram() -> Result<Vec<(usize, usize)>> {
    let map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|_| refuse!("no memory map"))?;
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
) -> Result<Tables> {
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

/// Run install mode, or collect what the host storage check needs and leave
/// boot services. The returned tables are not active yet.
pub fn take_over(
    options: Vec<u8>,
    host_firmware: crate::host_firmware::Resources,
) -> Result<(Handoff, Tables)> {
    // Install mode stages a payload and stops here; otherwise nothing changes.
    let options = crate::payload::run(options)?;
    let text = core::str::from_utf8(&options).map_err(|_| refuse!("stela.cfg is not UTF-8"))?;
    if !crate::storage::split(text)?.2.is_empty() {
        return Err(refuse!("stela.cfg names options that need --system"));
    }
    let captures = crate::storage::captures(host_firmware.wifi_observations());
    // SAFETY: standalone mount keeps identity mappings and this allocator.
    let host_firmware = unsafe { crate::host_firmware::identity_catalog(&host_firmware) }?;
    let storage = crate::storage::prepare(&options, host_firmware, captures)?.ok_or(refuse!(
        "stela.cfg starts with neither --system nor --host-check and names no install or \
         storage check"
    ))?;
    let guard = pages(STACK_PAGES + 1)?;
    let image = Image::loaded()?;
    let screen = Framebuffer::from_firmware();
    let mut tables = tables(&image, [0, guard], &[], screen.as_ref())?;
    storage.map(&mut tables)?;
    crate::output::leave_boot_services();
    // SAFETY: no protocol or pool allocation outlives this call; the heap,
    // stack and tables are LOADER_DATA, which Stela keeps.
    let map = unsafe { boot::exit_boot_services(None) };
    core::mem::forget(map);
    Ok((
        Handoff {
            active_tables: None,
            stack_top: guard + (STACK_PAGES + 1) * PAGE,
            screen,
            storage: Some(storage),
        },
        tables,
    ))
}

/// The firmware timer that moves the running step's marker while boot
/// services run, so a long firmware call (a file grown, a disk read) still
/// shows motion: an `Event` pointer, null when none runs.
static TICKER: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
/// Eight frames a second.
const TICK_PERIOD: Duration = Duration::from_millis(125);

/// Start the marker's timer. Its callback runs at `TPL_NOTIFY`, above the
/// level the firmware's file and disk drivers hold their locks at, so it
/// also runs while one of their calls takes long.
pub(crate) fn start_ticker() {
    unsafe extern "efiapi" fn tick(_: Event, _: Option<NonNull<c_void>>) {
        crate::status::tick();
    }
    // SAFETY: the callback allocates nothing and skips a frame while the
    // state or the console is in use; [`stop_ticker`] closes the event
    // before boot services end.
    let event = unsafe {
        boot::create_event(
            EventType::TIMER | EventType::NOTIFY_SIGNAL,
            Tpl::NOTIFY,
            Some(tick),
            None,
        )
    };
    let Ok(event) = event else {
        return;
    };
    if boot::set_timer(&event, TimerTrigger::Periodic(TICK_PERIOD)).is_ok() {
        TICKER.store(event.as_ptr(), Ordering::Relaxed);
    } else {
        let _ = boot::close_event(event);
    }
}

/// Close the marker's timer, before boot services end.
pub(crate) fn stop_ticker() {
    let pointer = TICKER.swap(core::ptr::null_mut(), Ordering::Relaxed);
    // SAFETY: `start_ticker` stored this event, which nothing else closes.
    if let Some(event) = unsafe { Event::from_ptr(pointer) } {
        let _ = boot::close_event(event);
    }
}

/// The time-stamp counter's rate, once found, and how ([`TscSource`]).
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
static TSC_SOURCE: AtomicU8 = AtomicU8::new(0);

/// How [`tsc_hz`] found the counter's rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TscSource {
    /// CPUID leaf 15h's crystal ratio, its crystal from 15h or 16h.
    Cpuid,
    /// The fastest of [`STALLS`] firmware stalls of [`STALL_MILLIS`].
    Stall,
}

/// Stalls measured where the CPU does not enumerate its counter's rate.
const STALLS: u64 = 5;
const STALL_MILLIS: u64 = 10;

/// The time-stamp counter's rate, found once for every user, before
/// ExitBootServices, as Linux's `native_calibrate_tsc` and then its
/// calibration loop find it: from the CPU where it enumerates the rate,
/// else measured against the firmware's stall, which only ever runs long,
/// so the lowest rate of several is the closest.
pub fn tsc_hz() -> u64 {
    let known = TSC_HZ.load(Ordering::Relaxed);
    if known != 0 {
        return known;
    }
    let rdtsc = || {
        // SAFETY: RDTSC has no memory effects.
        unsafe { core::arch::x86_64::_rdtsc() }
    };
    let (hz, source) = match enumerated_tsc_hz() {
        Some(hz) => (hz, TscSource::Cpuid),
        None => {
            let hz = (0..STALLS)
                .map(|_| {
                    let before = rdtsc();
                    boot::stall(Duration::from_millis(STALL_MILLIS));
                    (rdtsc() - before) * (1000 / STALL_MILLIS)
                })
                .min()
                .unwrap_or(0);
            (hz, TscSource::Stall)
        }
    };
    TSC_SOURCE.store(source as u8, Ordering::Relaxed);
    TSC_HZ.store(hz, Ordering::Relaxed);
    hz
}

/// How [`tsc_hz`] found the rate.
#[cfg(feature = "diagnostics")]
pub fn tsc_source() -> TscSource {
    tsc_hz();
    match TSC_SOURCE.load(Ordering::Relaxed) {
        0 => TscSource::Cpuid,
        _ => TscSource::Stall,
    }
}

/// The rate CPUID leaf 15h gives: its crystal's, times EBX over EAX. Where
/// ECX leaves the crystal out, leaf 16h's base frequency stands in for it,
/// as Linux's `native_calibrate_tsc` derives it. Linux trusts the leaf on
/// Intel processors only.
fn enumerated_tsc_hz() -> Option<u64> {
    use core::arch::x86_64::__cpuid;
    let vendor = __cpuid(0);
    let intel = (vendor.ebx, vendor.edx, vendor.ecx) == (0x756e_6547, 0x4965_6e69, 0x6c65_746e);
    if !intel || vendor.eax < 0x15 {
        return None;
    }
    let ratio = __cpuid(0x15);
    if ratio.eax == 0 || ratio.ebx == 0 {
        return None;
    }
    let crystal = match ratio.ecx {
        0 if vendor.eax >= 0x16 => {
            let base_mhz = u64::from(__cpuid(0x16).eax);
            base_mhz * 1_000_000 * u64::from(ratio.eax) / u64::from(ratio.ebx)
        }
        0 => 0,
        crystal => u64::from(crystal),
    };
    let hz = crystal * u64::from(ratio.ebx) / u64::from(ratio.eax);
    (hz != 0).then_some(hz)
}
