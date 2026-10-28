//! The host firmware's AML, run by the pinned ACPICA
//! (`stela_drivers::platform::acpi`, whose README is the provider contract)
//! through the engine's own OSL services: its heap, the TSC, port I/O, PCI
//! configuration space and the loader root's mappings.
//!
//! The session is interpreter-only. ACPICA loads the firmware's tables and
//! namespace and evaluates what the engine asks for, such as `\_PTS` before
//! S5 ([`HostAcpi::prepare_soft_off`]). Hardware activation needs an SCI,
//! GPE and EC service, IRQ-safe deferred work and device `_INI`, which the
//! engine does not have; the mount reports that once and AML runs only when
//! the engine calls it.
//!
//! Every ACPICA call runs on the boot processor under the loader root
//! ([`RestoreRoot`]), with interrupts off and the host drivers' lock held.
//! There RAM, ACPI tables and NVS included, is reached through the physmap,
//! write-back; any other address, device registers, through an identity
//! mapping the provider adds to the loader root uncached on first use. As
//! Linux, configuration registers below 256 on segment 0 go through
//! configuration mechanism #1, the rest through the MCFG's ECAM windows.
use super::{
    host,
    power::{in8, in16, in32, out8, out16, out32},
    storage::RestoreRoot,
};
use crate::{
    layout, output,
    tables::{self, Frames, NX, PAGE, PRESENT, UNCACHED, WRITABLE},
};
use alloc::{boxed::Box, collections::VecDeque, string::String, vec::Vec};
use core::{
    alloc::Layout,
    arch::asm,
    cell::{Cell, RefCell},
    ffi::{c_char, c_void},
    ptr,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use stela_drivers::{
    bus::pci::EcamWindow,
    platform::acpi::{Interrupt, Mode, PciId, Services, Session, Status, Value, Work},
};
use stela_runtime::machine::mmu::placement::Placement;

// ACPICA's statuses (`acexcep.h`).
const AE_OK: Status = 0;
const AE_ERROR: Status = 0x0001;
const AE_NOT_EXIST: Status = 0x0006;
const AE_SUPPORT: Status = 0x000f;
const AE_LIMIT: Status = 0x0010;
const AE_TIME: Status = 0x0011;
const AE_BAD_PARAMETER: Status = 0x1001;
/// `ACPI_WAIT_FOREVER`, a semaphore wait with no timeout.
const WAIT_FOREVER: u16 = 0xffff;
/// `ACPI_SIGNAL_FATAL`: AML's Fatal operator.
const SIGNAL_FATAL: u32 = 0;
/// RFLAGS.IF.
const INTERRUPTS: u64 = 1 << 9;
const PCI_ADDRESS: u16 = 0xcf8;
const PCI_DATA: u16 = 0xcfc;
/// The header [`allocate`] keeps before each allocation: its layout's size.
const HEADER: usize = 16;

/// What the provider reports once, as unsupported.
#[derive(Clone, Copy)]
enum Gap {
    /// A wait no other processor or interrupt could ever end.
    Wait = 1,
    /// Configuration space beyond mechanism #1 that no ECAM window decodes.
    Config = 2,
    /// An address beyond what the loader root can map by identity.
    Address = 4,
}

struct Provider {
    /// The loader root, which takes the identity mappings of device pages.
    root: u64,
    ecam: Vec<EcamWindow>,
    tsc_hz: u64,
    /// `acpi_os_execute`'s work, run in order by [`drain_work`].
    work: RefCell<VecDeque<(Work, usize)>>,
    /// Quiesced: work is refused.
    closed: Cell<bool>,
    reported: Cell<u32>,
}

impl Provider {
    fn report(&self, gap: Gap, message: core::fmt::Arguments<'_>) {
        let bit = gap as u32;
        if self.reported.get() & bit == 0 {
            self.reported.set(self.reported.get() | bit);
            output::arguments(format_args!("UNSUPPORTED ACPI {message}\n"));
        }
    }

    /// `bytes` at `physical` under the loader root: through the physmap
    /// where it maps every page (RAM), else by identity, mapping the pages
    /// not yet mapped uncached.
    fn reach(&self, physical: u64, bytes: u64) -> Option<*mut u8> {
        let end = physical.checked_add(bytes.max(1))?;
        let pages = (physical & !(PAGE - 1)..end).step_by(PAGE as usize);
        if pages
            .clone()
            .all(|page| self.mapped(layout::physical(page)))
        {
            return Some(layout::physical(physical) as *mut u8);
        }
        let limit = match layout::placement() {
            Placement::FiveLevel => 1 << 52,
            Placement::FourLevel { .. } => 1 << 47,
        };
        if end > limit {
            self.report(
                Gap::Address,
                format_args!("firmware address {physical:#x} lies beyond the identity map"),
            );
            return None;
        }
        for page in pages {
            if !self.mapped(page) {
                let rights = PRESENT | WRITABLE | NX | UNCACHED;
                tables::map_page(&mut HeapFrames, self.root, page, page, rights).ok()?;
            }
        }
        Some(physical as *mut u8)
    }

    /// Whether the loader root maps `address`.
    fn mapped(&self, address: u64) -> bool {
        match tables::entry(&mut HeapFrames, self.root, address, 0, false) {
            // Only a 2 MiB page stops the walk early.
            Err(_) => true,
            // SAFETY: a live leaf slot of the loader root.
            Ok(slot) => slot.is_some_and(|slot| unsafe { slot.read_volatile() } & PRESENT != 0),
        }
    }

    /// The ECAM address of `register` in `id`'s configuration space.
    fn ecam(&self, id: &PciId, register: u32) -> Option<u64> {
        let bus = u8::try_from(id.bus).ok()?;
        let window = self.ecam.iter().find(|window| {
            window.segment == id.segment && (window.start_bus..=window.end_bus).contains(&bus)
        })?;
        (id.device < 32 && id.function < 8 && register < 4096).then(|| {
            window.base
                + (u64::from(bus) << 20
                    | u64::from(id.device) << 15
                    | u64::from(id.function) << 12
                    | u64::from(register))
        })
    }

    fn milliseconds(&self, milliseconds: u64) {
        let start = host::rdtsc();
        let ticks = self.tsc_hz / 1000 * milliseconds;
        while host::rdtsc().wrapping_sub(start) < ticks {
            core::hint::spin_loop();
        }
    }
}

/// Page-table frames from the engine heap, which lies in the physmap.
struct HeapFrames;

impl Frames for HeapFrames {
    fn frame(&mut self) -> Option<u64> {
        let layout = Layout::from_size_align(PAGE as usize, PAGE as usize).ok()?;
        // SAFETY: a nonzero layout; the frame stays the loader root's.
        let page = unsafe { alloc::alloc::alloc_zeroed(layout) };
        (!page.is_null()).then(|| page as u64 - layout::physical(0))
    }

    fn table(&self, physical: u64) -> *mut u64 {
        layout::physical(physical) as *mut u64
    }
}

/// # Safety
/// `context` is the session's live [`Provider`].
unsafe fn provider<'a>(context: *mut c_void) -> &'a Provider {
    // SAFETY: the caller's contract.
    unsafe { &*context.cast::<Provider>() }
}

unsafe extern "C" fn allocate(_: *mut c_void, bytes: u64) -> *mut c_void {
    let Some(layout) = usize::try_from(bytes)
        .ok()
        .and_then(|bytes| bytes.checked_add(HEADER))
        .and_then(|total| Layout::from_size_align(total, HEADER).ok())
    else {
        return ptr::null_mut();
    };
    // SAFETY: a nonzero layout.
    let raw = unsafe { alloc::alloc::alloc(layout) };
    if raw.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the header lies in this allocation, which is aligned for it.
    unsafe {
        raw.cast::<usize>().write(layout.size());
        raw.add(HEADER).cast()
    }
}

unsafe extern "C" fn free(_: *mut c_void, allocation: *mut c_void) {
    // SAFETY: `allocate` returned `allocation`, its header just before it.
    unsafe {
        let raw = allocation.cast::<u8>().sub(HEADER);
        let size = raw.cast::<usize>().read();
        alloc::alloc::dealloc(raw, Layout::from_size_align_unchecked(size, HEADER));
    }
}

unsafe extern "C" fn map(context: *mut c_void, physical: u64, bytes: u64) -> *mut c_void {
    // SAFETY: ACPICA passes the session's provider.
    unsafe { provider(context) }
        .reach(physical, bytes)
        .map_or(ptr::null_mut(), |pointer| pointer.cast())
}

/// The lease ends; the mapping stays the loader root's, as the identity
/// map's other pages do, for the next lease of the same registers.
unsafe extern "C" fn unmap(_: *mut c_void, _: *mut c_void, _: u64) {}

unsafe extern "C" fn create_lock(_: *mut c_void, out: *mut *mut c_void) -> Status {
    // SAFETY: ACPICA's writable output.
    unsafe { out.write(Box::into_raw(Box::new(AtomicBool::new(false))).cast()) };
    AE_OK
}

unsafe extern "C" fn delete_lock(_: *mut c_void, lock: *mut c_void) {
    // SAFETY: `create_lock` made `lock`, which ACPICA deletes once.
    drop(unsafe { Box::from_raw(lock.cast::<AtomicBool>()) });
}

unsafe extern "C" fn acquire_lock(_: *mut c_void, lock: *mut c_void) -> u64 {
    let flags: u64;
    // SAFETY: CPL0; `release_lock` restores IF.
    unsafe { asm!("pushfq", "pop {}", "cli", out(reg) flags, options(nomem)) };
    // SAFETY: a lock `create_lock` made.
    let lock = unsafe { &*lock.cast::<AtomicBool>() };
    while lock
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    flags
}

unsafe extern "C" fn release_lock(_: *mut c_void, lock: *mut c_void, flags: u64) {
    // SAFETY: a lock `create_lock` made.
    unsafe { &*lock.cast::<AtomicBool>() }.store(false, Ordering::Release);
    if flags & INTERRUPTS != 0 {
        // SAFETY: `acquire_lock` cleared IF, which was set.
        unsafe { asm!("sti", options(nomem, nostack)) };
    }
}

struct Semaphore {
    units: AtomicU32,
    max: u32,
}

unsafe extern "C" fn create_semaphore(
    _: *mut c_void,
    max: u32,
    initial: u32,
    out: *mut *mut c_void,
) -> Status {
    if max == 0 || initial > max {
        return AE_BAD_PARAMETER;
    }
    let semaphore = Semaphore {
        units: AtomicU32::new(initial),
        max,
    };
    // SAFETY: ACPICA's writable output.
    unsafe { out.write(Box::into_raw(Box::new(semaphore)).cast()) };
    AE_OK
}

unsafe extern "C" fn delete_semaphore(_: *mut c_void, semaphore: *mut c_void) -> Status {
    // SAFETY: `create_semaphore` made it, and ACPICA deletes it once.
    drop(unsafe { Box::from_raw(semaphore.cast::<Semaphore>()) });
    AE_OK
}

unsafe extern "C" fn wait_semaphore(
    context: *mut c_void,
    semaphore: *mut c_void,
    units: u32,
    timeout: u16,
) -> Status {
    // SAFETY: ACPICA passes the session's provider and a live semaphore.
    let (provider, semaphore) = unsafe { (provider(context), &*semaphore.cast::<Semaphore>()) };
    if units == 0 || units > semaphore.max {
        return AE_BAD_PARAMETER;
    }
    let take = || {
        semaphore
            .units
            .try_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                held.checked_sub(units)
            })
            .is_ok()
    };
    if take() {
        return AE_OK;
    }
    if timeout == WAIT_FOREVER {
        // Only this processor runs AML, with interrupts off: no one else
        // can ever signal.
        provider.report(
            Gap::Wait,
            format_args!("firmware AML waited forever on a semaphore only it holds"),
        );
        return AE_TIME;
    }
    let start = host::rdtsc();
    let ticks = provider.tsc_hz / 1000 * u64::from(timeout);
    while host::rdtsc().wrapping_sub(start) < ticks {
        if take() {
            return AE_OK;
        }
        core::hint::spin_loop();
    }
    AE_TIME
}

unsafe extern "C" fn signal_semaphore(
    _: *mut c_void,
    semaphore: *mut c_void,
    units: u32,
) -> Status {
    // SAFETY: a live semaphore `create_semaphore` made.
    let semaphore = unsafe { &*semaphore.cast::<Semaphore>() };
    match semaphore
        .units
        .try_update(Ordering::AcqRel, Ordering::Acquire, |held| {
            held.checked_add(units)
                .filter(|&next| next <= semaphore.max)
        }) {
        Ok(_) => AE_OK,
        Err(_) => AE_LIMIT,
    }
}

/// No SCI: the session is interpreter-only.
unsafe extern "C" fn install_interrupt(
    _: *mut c_void,
    _: u32,
    _: Interrupt,
    _: *mut c_void,
) -> Status {
    AE_SUPPORT
}

unsafe extern "C" fn remove_interrupt(_: *mut c_void, _: u32, _: Interrupt) -> Status {
    AE_NOT_EXIST
}

/// Only the boot processor runs AML.
unsafe extern "C" fn thread_id(_: *mut c_void) -> u64 {
    1
}

unsafe extern "C" fn execute(
    context: *mut c_void,
    _: u32,
    work: Work,
    argument: *mut c_void,
) -> Status {
    // SAFETY: ACPICA passes the session's provider.
    let provider = unsafe { provider(context) };
    if provider.closed.get() {
        return AE_NOT_EXIST;
    }
    provider
        .work
        .borrow_mut()
        .push_back((work, argument as usize));
    AE_OK
}

unsafe extern "C" fn drain_work(context: *mut c_void) {
    // SAFETY: ACPICA passes the session's provider.
    let provider = unsafe { provider(context) };
    loop {
        let next = provider.work.borrow_mut().pop_front();
        let Some((work, argument)) = next else {
            return;
        };
        // SAFETY: ACPICA queued this work with its argument.
        unsafe { work(argument as *mut c_void) };
    }
}

unsafe extern "C" fn sleep(context: *mut c_void, milliseconds: u64) {
    // SAFETY: ACPICA passes the session's provider.
    unsafe { provider(context) }.milliseconds(milliseconds);
}

unsafe extern "C" fn stall(context: *mut c_void, microseconds: u32) {
    // SAFETY: ACPICA passes the session's provider.
    let provider = unsafe { provider(context) };
    let start = host::rdtsc();
    let ticks = provider.tsc_hz / 1_000_000 * u64::from(microseconds);
    while host::rdtsc().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn read_port(_: *mut c_void, port: u64, value: *mut u32, width: u32) -> Status {
    let Ok(port) = u16::try_from(port) else {
        return AE_BAD_PARAMETER;
    };
    // SAFETY: the firmware's AML or FADT names the port; ACPICA screens it
    // as Linux's does; the output is writable.
    unsafe {
        value.write(match width {
            8 => in8(port).into(),
            16 => in16(port).into(),
            32 => in32(port),
            _ => return AE_BAD_PARAMETER,
        })
    };
    AE_OK
}

unsafe extern "C" fn write_port(_: *mut c_void, port: u64, value: u32, width: u32) -> Status {
    let Ok(port) = u16::try_from(port) else {
        return AE_BAD_PARAMETER;
    };
    // SAFETY: as in `read_port`.
    unsafe {
        match width {
            8 => out8(port, value as u8),
            16 => out16(port, value as u16),
            32 => out32(port, value),
            _ => return AE_BAD_PARAMETER,
        }
    }
    AE_OK
}

/// # Safety
/// `pointer` reaches `width` bits the firmware names.
unsafe fn read(pointer: *mut u8, width: u32) -> Option<u64> {
    // SAFETY: the caller's contract.
    unsafe {
        Some(match width {
            8 => pointer.read_volatile().into(),
            16 => pointer.cast::<u16>().read_volatile().into(),
            32 => pointer.cast::<u32>().read_volatile().into(),
            64 => pointer.cast::<u64>().read_volatile(),
            _ => return None,
        })
    }
}

/// # Safety
/// As [`read`].
unsafe fn write(pointer: *mut u8, value: u64, width: u32) -> bool {
    // SAFETY: the caller's contract.
    unsafe {
        match width {
            8 => pointer.write_volatile(value as u8),
            16 => pointer.cast::<u16>().write_volatile(value as u16),
            32 => pointer.cast::<u32>().write_volatile(value as u32),
            64 => pointer.cast::<u64>().write_volatile(value),
            _ => return false,
        }
    }
    true
}

unsafe extern "C" fn read_memory(
    context: *mut c_void,
    physical: u64,
    value: *mut u64,
    width: u32,
) -> Status {
    // SAFETY: ACPICA passes the session's provider.
    let Some(pointer) = unsafe { provider(context) }.reach(physical, u64::from(width / 8)) else {
        return AE_ERROR;
    };
    // SAFETY: the firmware's register, now mapped; the output is writable.
    match unsafe { read(pointer, width) } {
        Some(read) => {
            // SAFETY: as above.
            unsafe { value.write(read) };
            AE_OK
        }
        None => AE_BAD_PARAMETER,
    }
}

unsafe extern "C" fn write_memory(
    context: *mut c_void,
    physical: u64,
    value: u64,
    width: u32,
) -> Status {
    // SAFETY: ACPICA passes the session's provider.
    let Some(pointer) = unsafe { provider(context) }.reach(physical, u64::from(width / 8)) else {
        return AE_ERROR;
    };
    // SAFETY: the firmware's register, now mapped.
    match unsafe { write(pointer, value, width) } {
        true => AE_OK,
        false => AE_BAD_PARAMETER,
    }
}

/// Configuration mechanism #1's address, as Linux's `PCI_CONF1_ADDRESS`,
/// for segment 0's first 256 registers.
fn mechanism_one(id: &PciId, register: u32) -> Option<u32> {
    (id.segment == 0 && id.bus < 256 && id.device < 32 && id.function < 8 && register < 256).then(
        || {
            0x8000_0000
                | u32::from(id.bus) << 16
                | u32::from(id.device) << 11
                | u32::from(id.function) << 8
                | register & 0xfc
        },
    )
}

unsafe extern "C" fn read_pci(
    context: *mut c_void,
    id: *mut PciId,
    register: u32,
    value: *mut u64,
    width: u32,
) -> Status {
    // SAFETY: ACPICA passes the session's provider and a live identity.
    let (provider, id) = unsafe { (provider(context), &*id) };
    if !matches!(width, 8 | 16 | 32) {
        return AE_ERROR;
    }
    let read = if let Some(address) = mechanism_one(id, register) {
        let port = PCI_DATA + (register & 3) as u16;
        // SAFETY: mechanism #1's ports, under the host drivers' lock.
        unsafe {
            out32(PCI_ADDRESS, address);
            match width {
                8 => u64::from(in8(port)),
                16 => u64::from(in16(port & !1)),
                _ => u64::from(in32(PCI_DATA)),
            }
        }
    } else {
        let Some(pointer) = provider
            .ecam(id, register)
            .and_then(|address| provider.reach(address, u64::from(width / 8)))
        else {
            provider.report(
                Gap::Config,
                format_args!(
                    "configuration space {id:?} register {register:#x} has no ECAM window"
                ),
            );
            return AE_SUPPORT;
        };
        // SAFETY: an ECAM register, mapped uncached.
        unsafe { read(pointer, width) }.unwrap_or_default()
    };
    // SAFETY: ACPICA's writable output.
    unsafe { value.write(read) };
    AE_OK
}

unsafe extern "C" fn write_pci(
    context: *mut c_void,
    id: *mut PciId,
    register: u32,
    value: u64,
    width: u32,
) -> Status {
    // SAFETY: ACPICA passes the session's provider and a live identity.
    let (provider, id) = unsafe { (provider(context), &*id) };
    if !matches!(width, 8 | 16 | 32) {
        return AE_ERROR;
    }
    if let Some(address) = mechanism_one(id, register) {
        let port = PCI_DATA + (register & 3) as u16;
        // SAFETY: mechanism #1's ports, under the host drivers' lock.
        unsafe {
            out32(PCI_ADDRESS, address);
            match width {
                8 => out8(port, value as u8),
                16 => out16(port & !1, value as u16),
                _ => out32(PCI_DATA, value as u32),
            }
        }
        return AE_OK;
    }
    let Some(pointer) = provider
        .ecam(id, register)
        .and_then(|address| provider.reach(address, u64::from(width / 8)))
    else {
        provider.report(
            Gap::Config,
            format_args!("configuration space {id:?} register {register:#x} has no ECAM window"),
        );
        return AE_SUPPORT;
    };
    // SAFETY: an ECAM register, mapped uncached.
    unsafe { write(pointer, value, width) };
    AE_OK
}

/// 100 ns units, from the TSC.
unsafe extern "C" fn timer(context: *mut c_void) -> u64 {
    // SAFETY: ACPICA passes the session's provider.
    let hz = unsafe { provider(context) }.tsc_hz;
    (u128::from(host::rdtsc()) * 10_000_000 / u128::from(hz)) as u64
}

/// As Linux's `acpi_os_signal`: AML's Fatal is reported, and execution
/// goes on; a breakpoint is ignored.
unsafe extern "C" fn signal(_: *mut c_void, kind: u32, info: *mut c_void) -> Status {
    if kind == SIGNAL_FATAL && !info.is_null() {
        // SAFETY: ACPICA's `acpi_signal_fatal_info`: type, code, argument.
        let [kind, code, argument] = unsafe { info.cast::<[u32; 3]>().read() };
        output::arguments(format_args!(
            "ACPI firmware AML Fatal type={kind:#x} code={code:#x} argument={argument:#x}\n"
        ));
    }
    AE_OK
}

unsafe extern "C" fn log(_: *mut c_void, text: *const c_char, bytes: u64) {
    // SAFETY: ACPICA's formatted message of `bytes` bytes.
    let text = unsafe { core::slice::from_raw_parts(text.cast::<u8>(), bytes as usize) };
    output::arguments(format_args!("{}", String::from_utf8_lossy(text)));
}

unsafe extern "C" fn flush_cache(_: *mut c_void) {
    // SAFETY: CPL0; writes back and invalidates the caches.
    unsafe { asm!("wbinvd", options(nostack, preserves_flags)) };
}

/// No SCI or region callback runs beside AML: closing admission and running
/// the queued work quiesces the session.
unsafe extern "C" fn quiesce(context: *mut c_void) -> Status {
    // SAFETY: ACPICA passes the session's provider.
    unsafe { provider(context) }.closed.set(true);
    // SAFETY: as above.
    unsafe { drain_work(context) };
    AE_OK
}

unsafe extern "C" fn destroy(context: *mut c_void) {
    // SAFETY: the session's provider, which `HostAcpi::start` leaked to it.
    drop(unsafe { Box::from_raw(context.cast::<Provider>()) });
}

unsafe extern "C" fn fatal(_: *mut c_void, status: Status) -> ! {
    output::fatal(&alloc::format!(
        "ACPI quiescence before a table unload failed: ACPICA status {status:#x}"
    ))
}

/// The firmware's ACPI namespace, for the host's power transitions.
/// One namespace serves the whole program: [`HostAcpi::start`] leaks it, and
/// the host drivers and power transitions borrow it for `'static`.
pub struct HostAcpi {
    session: Session,
    root: u64,
}

impl HostAcpi {
    /// Load the tables at `rsdp` and their namespace; `None`, reported,
    /// when ACPICA refuses them. `root` is the loader root. The namespace
    /// lives until the host powers off, so it is leaked here, once.
    pub fn start(
        rsdp: u64,
        root: u64,
        ecam: Vec<EcamWindow>,
        tsc_hz: u64,
    ) -> Option<&'static Self> {
        if rsdp == 0 {
            output::arguments(format_args!("ACPI firmware AML unavailable: no RSDP\n"));
            return None;
        }
        let provider = Box::new(Provider {
            root,
            ecam,
            tsc_hz,
            work: RefCell::new(VecDeque::new()),
            closed: Cell::new(false),
            reported: Cell::new(0),
        });
        let services = Services {
            context: Box::into_raw(provider).cast(),
            root: rsdp,
            capabilities: 0,
            allocate,
            free,
            map,
            unmap,
            create_lock,
            delete_lock,
            acquire_lock,
            release_lock,
            create_semaphore,
            delete_semaphore,
            wait_semaphore,
            signal_semaphore,
            install_interrupt,
            remove_interrupt,
            thread_id,
            execute,
            drain_work,
            sleep,
            stall,
            read_port,
            write_port,
            read_memory,
            write_memory,
            read_pci,
            write_pci,
            timer,
            signal,
            log,
            flush_cache,
            quiesce,
            destroy,
            fatal,
        };
        // SAFETY: the live loader root, which the session runs under.
        let _root = unsafe { RestoreRoot::enter(root) };
        // SAFETY: every callback keeps the OSL contract above, the provider
        // is the session's, and only this processor runs ACPICA.
        let session = match unsafe { Session::start(services, Mode::InterpreterOnly) } {
            Ok(session) => session,
            Err(error) => {
                output::arguments(format_args!(
                    "ACPI firmware AML refused: ACPICA status {:#x}\n",
                    error.0
                ));
                return None;
            }
        };
        let s5 = session
            .handle("\\_S5")
            .and_then(|s5| s5.evaluate(None, &[]));
        match s5 {
            Ok(Some(Value::Package(values))) => {
                let values: Vec<_> = values
                    .iter()
                    .map(|value| match value {
                        Value::Integer(value) => alloc::format!("{value:#x}"),
                        _ => String::from("?"),
                    })
                    .collect();
                output::arguments(format_args!(
                    "ACPI firmware AML loaded: \\_S5 {}\n",
                    values.join(",")
                ));
            }
            Ok(_) => output::arguments(format_args!(
                "ACPI firmware AML loaded: \\_S5 is not a package\n"
            )),
            Err(error) => output::arguments(format_args!(
                "ACPI firmware AML loaded: no \\_S5 (ACPICA status {:#x})\n",
                error.0
            )),
        }
        output::arguments(format_args!(
            "UNSUPPORTED ACPI hardware activation: no SCI, GPE or EC events and no device _INI; firmware AML runs only when the engine calls it\n"
        ));
        Some(Box::leak(Box::new(Self { session, root })))
    }

    /// The loaded namespace. Its calls run in the loader root
    /// ([`RestoreRoot`]), as the host drivers do.
    pub fn session(&'static self) -> &'static Session {
        &self.session
    }

    /// Linux's `acpi_power_off_prepare`: S5's SLP_TYPa and SLP_TYPb as the
    /// firmware's `\_S5` evaluates, after `\_PTS(5)` and `\_SST`; `None`
    /// without S5. A failed `\_PTS` is reported, and S5 follows all the same.
    pub fn prepare_soft_off(&self) -> Option<(u8, u8)> {
        // SAFETY: the live loader root, which the session runs under.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        let types = match self.session.sleep_types(5) {
            Ok(types) => types,
            Err(error) => {
                output::arguments(format_args!(
                    "POWER the firmware's AML has no S5: ACPICA status {:#x}\n",
                    error.0
                ));
                return None;
            }
        };
        match self.session.prepare_sleep(5) {
            Ok(()) => output::arguments(format_args!(
                "POWER the firmware prepared S5: SLP_TYPa={:#x} SLP_TYPb={:#x}\n",
                types.0, types.1
            )),
            Err(error) => output::arguments(format_args!(
                "POWER \\_PTS(5) failed: ACPICA status {:#x}\n",
                error.0
            )),
        }
        Some(types)
    }
}
