//! UEFI application that runs an ARM image on the shared compiler and runtime.
//!
//! The firmware starts `stela.efi`, on a USB as its removable-media boot
//! loader `\EFI\BOOT\BOOTX64.EFI`. It connects every controller to its
//! drivers and reads `\EFI\stela\stela.cfg` from its own volume. A
//! `stela.cfg` that starts with `--system` runs the guest on the system-mode
//! engine (`docs/design/system.md#system-mode-execution`); one that starts
//! with `--host-check` reports on the PC (`host_check`). Any other line runs
//! no ARM code: install mode (`payload`), or the host storage check
//! (`storage`), which leaves boot services and installs Stela's own page
//! tables first. With `\EFI\stela\choices.cfg` beside it, the startup
//! choices (`choice`) pick the option line first.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::format;
use core::{arch::asm, panic::PanicInfo};
use stela_boot_core::apic;
use uefi::{
    Status,
    boot::{AllocateType, MemoryType},
    mem::memory_map::MemoryMap,
};
#[cfg(feature = "diagnostics")]
mod audio_check;
mod choice;
mod console;
mod cpu;
mod engine;
mod entropy;
mod firmware;
mod handoff;
use stela_boot_core::heap;
#[cfg(feature = "diagnostics")]
mod host_check;
mod host_firmware;
mod installer;
mod la57;
mod layout;
mod log_file;
#[allow(dead_code)]
pub(crate) mod native_clock;
pub mod native_dma;
pub mod native_irq;
pub mod native_memory;
#[allow(dead_code)]
pub(crate) mod native_mmio;
mod native_smp;
#[allow(dead_code)]
#[cfg(feature = "diagnostics")]
mod native_stack_check;
#[allow(dead_code)]
mod native_stacks;
#[cfg(feature = "diagnostics")]
mod native_work_check;
mod output;
mod paging;
mod payload;
mod pci_io;
mod random;
mod selection;
mod serial;
mod status;
mod storage;
mod system;
mod tables;
mod ui;
#[global_allocator]
pub(crate) static ALLOCATOR: heap::Heap = heap::Heap::new().reporting_failures(|report| {
    use core::fmt::Write;
    // Serial is bounded, lock-free port I/O: no allocation or queue.
    let _ = serial::Serial.write_fmt(report);
});
/// The live firmware keeps its boot-service pages. Budget the first heap from
/// the conventional pages still available after the pristine image copy.
fn initial_heap_bytes() -> Result<usize, &'static str> {
    let map = uefi::boot::memory_map(MemoryType::LOADER_DATA)
        .map_err(|_| "firmware memory map unavailable for the boot heap")?;
    let free = map
        .entries()
        .filter(|entry| entry.ty == MemoryType::CONVENTIONAL)
        .try_fold(0u64, |total, entry| {
            entry
                .page_count
                .checked_mul(paging::PAGE as u64)
                .and_then(|bytes| total.checked_add(bytes))
        })
        .ok_or("firmware memory map overflows the boot heap budget")?;
    stela_boot_core::memory_budget::bootstrap_heap(free)
        .map(|bytes| bytes as usize)
        .map_err(|_| "not enough free firmware RAM for the boot heap budget")
}
/// What this build reads, for `stela setup` to check before installing it
/// (`stela_loader::mount_interface`).
#[used]
static MOUNT_INTERFACE: [u8; stela_loader::mount_interface::MARKER_BYTES] =
    stela_loader::mount_interface::marker(stela_loader::mount_interface::CURRENT);

/// Optional native host resource capability read by setup before publication.
#[used]
static HOST_FIRMWARE_INTERFACE: [u8; 21] = stela_loader::host_firmware::MOUNT_CAPABILITY;

#[uefi::entry]
fn main() -> Status {
    // Before any Rust state exists: the system engine runs from this copy.
    system::take_snapshot();
    // Referenced, so the linker keeps the marker setup reads.
    core::hint::black_box(&MOUNT_INTERFACE);
    core::hint::black_box(&HOST_FIRMWARE_INTERFACE);
    serial::initialize();
    output::arguments(format_args!("STELA UEFI MOUNT\n"));
    let heap_bytes = initial_heap_bytes().unwrap_or_else(|error| output::early_fatal(error));
    let heap = uefi::boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        heap_bytes / paging::PAGE,
    )
    .unwrap_or_else(|_| output::early_fatal("firmware has no memory for the heap"));
    // SAFETY: fresh LOADER_DATA pages that Stela owns for the whole boot,
    // initialized before any allocation.
    unsafe { ALLOCATOR.initialize(heap.as_ptr(), heap_bytes) };
    // SAFETY: the registered heap is the exact reserved WB identity extent.
    unsafe {
        native_memory::initialize(heap.as_ptr() as usize, heap.as_ptr() as u64, heap_bytes, 0)
    };
    status::set_clock(firmware::tsc_hz());
    firmware::start_ticker();
    let log = log_file::open();
    status::begin("Connecting the firmware's drivers to every device");
    let handles = firmware::connect_all();
    status::done(&format!("{handles} handles"));
    status::begin("Reading Stela's settings");
    let (mut volume, mut firmware_root) = firmware::volume().unwrap_or_else(|e| output::fatal(e));
    let host_firmware =
        host_firmware::read(&mut firmware_root).unwrap_or_else(|e| output::fatal(e));
    drop(firmware_root);
    let options = firmware::options(&mut volume).unwrap_or_else(|e| output::fatal(e));
    let options = choice::resolve(&mut volume, options);
    status::done("");
    let held = system::held_at_start(&options);
    let options = choice::choose(&mut volume, options, held);
    status::take_screen(console::Framebuffer::from_firmware());
    if options.starts_with(b"--system") {
        system::boot(options, volume, log, host_firmware);
    }
    if options.starts_with(stela_boot_core::options::HOST_CHECK.as_bytes()) {
        drop(volume);
        #[cfg(feature = "diagnostics")]
        host_check::boot(options);
        #[cfg(not(feature = "diagnostics"))]
        output::fatal("host checks require a diagnostics build");
    }
    drop(volume);
    let (mut handoff, tables) =
        firmware::take_over(options, host_firmware).unwrap_or_else(|e| output::fatal(e));
    if let Some(screen) = handoff.screen {
        console::install(screen);
        output::arguments(format_args!("STELA UEFI MOUNT\n"));
    }
    // SAFETY: boot services have ended; the new tables map the image, heap,
    // the stack and every RAM byte in use.
    unsafe {
        asm!("cli", options(nomem, nostack));
        handoff.active_tables = Some(paging::activate(tables).unwrap_or_else(|error| {
            output::arguments(format_args!("native table activation refused: {error}"));
            output::fatal("native table activation failed");
        }));
        asm!(
            "mov rsp, {top}",
            "call {run}",
            "ud2",
            top = in(reg) handoff.stack_top,
            run = sym run,
            in("rdi") &raw mut handoff,
            options(noreturn),
        )
    }
}

/// Run the host storage check on Stela's own stack.
extern "sysv64" fn run(handoff: &mut firmware::Handoff) -> ! {
    match handoff.active_tables.as_ref() {
        Some(tables) => tables.check_current().unwrap_or_else(|error| {
            output::arguments(format_args!("activated native root refused: {error}\n"));
            output::fatal("activated native root is unavailable");
        }),
        None => output::fatal("actual activated native table owner is missing"),
    }
    if let Some(storage) = handoff.storage.take() {
        storage.run();
    }
    output::arguments(format_args!("STORAGE CHECK END\n"));
    output::terminate(0x10)
}
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    // No allocator, formatting of caller-supplied values, Rust lock, unwind,
    // poison recovery or continuation is allowed on this terminal path.
    output::panic(info)
}
