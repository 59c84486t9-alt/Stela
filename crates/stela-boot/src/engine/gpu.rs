//! The host's Linux environment and the NVIDIA GPUs nouveau drives in it
//! (`docs/design/metal-device.md`).
//!
//! It lives on the boot CPU and takes time from the boot PE as Linux steals it
//! from an interrupted thread. A GPU's MSI targets that CPU and only records
//! its line ([`Fired`]), which ends the PE's run at its next chained transfer
//! (`Hub::call_host`); the run loop then runs what is ready ([`pump`]) and the
//! guest goes on. Nothing reserves a core, and a Linux environment with nothing
//! to do costs the boot PE one comparison a slice.
#[cfg(feature = "nvk")]
pub(super) mod client;
#[cfg(feature = "nvk")]
mod code;
#[cfg(feature = "nvk")]
pub(super) mod display;
#[cfg(feature = "nvk")]
mod file;
#[cfg(feature = "nvk")]
pub(super) mod gate;
/// `xtask guest`'s objects of the StelaGPU kext.
#[cfg(feature = "nvk")]
mod kext {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/guest/StelaGPU.kext.rs"
    ));
}
#[cfg(feature = "nvk")]
mod stack;

use super::{
    host,
    kernel_work::{self, KernelWork, SLOTS},
};
use crate::{handoff::RtcReading, native_irq, native_memory, native_mmio::Window, output};
use alloc::{
    borrow::ToOwned, boxed::Box, collections::BTreeMap, collections::BTreeSet, format, rc::Rc,
    string::String, sync::Arc, vec::Vec,
};
use core::{
    alloc::Layout,
    cell::{Cell, RefCell},
    ffi::{CStr, c_void},
    ops::Range,
    pin::Pin,
    ptr::{self, addr_of},
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering},
};
use stela_boot_core::page_window::{self, Cache};
#[cfg(feature = "nvk")]
use stela_drivers::gpu::metal::nvidia::PcieLink;
use stela_drivers::{
    bus::{
        dma::mapping::DmaDomain,
        irq::{Disposition, Handler, IrqError, IrqRegistration, Route, Source},
        mmio::owned,
        pci::{Bar, ConfigError, ConfigSpace, Function, owned::OwnedConfig},
    },
    firmware::{Catalog, Provider, Requirement, Target},
    gpu,
    platform::work::{
        Cpu, WorkError,
        service::{Clock, Domain, Idle},
    },
    probe::{NativeServices, ServiceError},
};
use stela_engine::machine::engine::Hub;
use stela_linux::{
    function::{self, Attached, Msi, Placement, Region},
    owner::{Entered, Errno, Owner, Platform, RawOwner, RealtimeOrigin, RealtimeRead},
    random::Seeded,
    service::{self, Environment as LinuxEnvironment},
};

type Environment = LinuxEnvironment<SLOTS>;

const PAGE: u64 = page_window::PAGE;
const ENOENT: Errno = -2;
const EIO: Errno = -5;
const EFAULT: Errno = -14;
const ERANGE: Errno = -34;
const ENODEV: Errno = -19;
const EINVAL: Errno = -22;
const ENOMEM: Errno = -12;
const EOPNOTSUPP: Errno = -95;

const MSI_CAPABILITY: u8 = 5;
#[cfg(feature = "nvk")]
const PCIE_CAPABILITY: u8 = 0x10;
/// `PCI_EXP_LNKSTA`, in the PCIe capability.
#[cfg(feature = "nvk")]
const LINK_STATUS: u16 = 0x12;
#[cfg(feature = "nvk")]
const REVISION: u16 = 0x08;
#[cfg(feature = "nvk")]
const SUBSYSTEM_ID: u16 = 0x2c;
/// Linux's `IORESOURCE_*` bits of a memory BAR.
const RESOURCE_MEMORY: u64 = 0x200;
const RESOURCE_PREFETCHABLE: u64 = 0x2000;
const RESOURCE_WIDE: u64 = 0x10_0000;
/// Every DMA mask nouveau sets holds 40 bits. A mapping past it is refused
/// (`function::Mappings`), not truncated.
const DMA_LIMIT: u64 = (1 << 40) - 1;
/// The firmware images Linux names, all under one target: nouveau picks each
/// by chip and validates its header.
const FIRMWARE: Target<'static> = Target {
    driver: "nouveau",
    hardware: "nvidia",
    revision: "linux-firmware",
    board: None,
};
/// How long the GPUs may take to boot their firmware before the guest starts.
const START_SECONDS: u64 = 60;
/// The longest idle wait while they do, which the timeout above is checked at.
const WAIT_MICROS: u64 = 10_000;

/// The boot CPU's monotonic nanoseconds, over the TSC every engine timing uses.
struct Time {
    cpu: Arc<dyn Cpu>,
    tsc_hz: u64,
}

fn nanoseconds(ticks: u64, tsc_hz: u64) -> u64 {
    (u128::from(ticks) * 1_000_000_000 / u128::from(tsc_hz)) as u64
}

// SAFETY: the TSC is the engine's calibrated, progressing boot-CPU counter, and
// reading it is bounded and calls nothing back.
unsafe impl Clock for Time {
    fn cpu(&self) -> &Arc<dyn Cpu> {
        &self.cpu
    }
    fn now_ns(&self) -> Result<u64, WorkError> {
        Ok(nanoseconds(host::rdtsc(), self.tsc_hz))
    }
}

/// Who runs PE work on the boot CPU, once the PEs run.
static HUB: AtomicPtr<Hub> = AtomicPtr::new(ptr::null_mut());
static BOOT_PE: AtomicUsize = AtomicUsize::new(0);
/// The processor the environment runs on.
#[cfg(feature = "nvk")]
static BOOT_CPU: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// End the boot PE's slices for Linux, through `hub`.
pub(super) fn set_hub(hub: Arc<Hub>, pe: usize) {
    BOOT_PE.store(pe, Ordering::Relaxed);
    HUB.store(Arc::into_raw(hub).cast_mut(), Ordering::Release);
}

/// What wakes the service: a raised line or a call.
struct Events {
    clock: Arc<dyn Clock>,
    pending: AtomicBool,
}

// SAFETY: `pending` is published before the boot PE is told, and the wait
// checks it with interrupts off, so a notification cannot be lost: one that
// comes from an interrupt during the halt ends it. The dispatcher's IF is clear
// only for the host drivers' root guard, not for a critical section of Linux
// code, so the wait may take interrupts, whose handlers only record their line.
unsafe impl Idle for Events {
    fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }
    fn notify(&self) -> Result<(), WorkError> {
        self.pending.store(true, Ordering::Release);
        // SAFETY: a published hub is leaked, so it lives for the boot.
        if let Some(hub) = unsafe { HUB.load(Ordering::Acquire).as_ref() } {
            hub.call_host(BOOT_PE.load(Ordering::Relaxed));
        }
        Ok(())
    }
    fn wait_until_ns(&self, deadline: Option<u64>) -> Result<(), WorkError> {
        if self.pending.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        let now = self.clock.now_ns()?;
        let left = deadline.map_or(u64::MAX, |deadline| deadline.saturating_sub(now));
        if left != 0 {
            host::sleep_for((left / 1000).clamp(1, WAIT_MICROS));
        }
        Ok(())
    }
}

unsafe fn allocate_zeroed(layout: Layout) -> *mut u8 {
    // SAFETY: the registration's contract, which this allocator's one attempt
    // at its lock meets; the C side frees through the global allocator.
    unsafe { crate::ALLOCATOR.try_allocate_zeroed(layout) }
}

/// A function's configuration space, which its MSI source shares with Linux.
/// The two take turns on the boot CPU, and neither calls out while it holds it.
#[derive(Clone)]
struct SharedConfig(Rc<RefCell<Function<OwnedConfig>>>);

impl ConfigSpace for SharedConfig {
    fn read32(&self, offset: u16) -> Result<u32, ConfigError> {
        self.0.borrow_mut().config().read32(offset)
    }
    fn write32(&mut self, offset: u16, value: u32) -> Result<(), ConfigError> {
        self.0.borrow_mut().config().write32(offset, value)
    }
    fn read16(&self, offset: u16) -> Result<u16, ConfigError> {
        self.0.borrow_mut().config().read16(offset)
    }
    fn read8(&self, offset: u16) -> Result<u8, ConfigError> {
        self.0.borrow_mut().config().read8(offset)
    }
    fn write16(&mut self, offset: u16, value: u16) -> Result<(), ConfigError> {
        self.0.borrow_mut().config().write16(offset, value)
    }
    fn write8(&mut self, offset: u16, value: u8) -> Result<(), ConfigError> {
        self.0.borrow_mut().config().write8(offset, value)
    }
}

/// The MSI of one function, routed to the boot CPU.
struct MsiSource {
    config: SharedConfig,
    msi: Msi,
    programmed: bool,
    event: stela_linux::service::IrqEvent,
    environment: *const Environment,
    line: u32,
}

// SAFETY: the function was stopped when claimed, with no route of its own.
// Nothing here frees: config/capability stay with the registration. Terminal
// engine/payload/Linux-work joining is unavailable, so a programmed route's
// close refuses and retains owners even if nouveau masked its local source.
unsafe impl Source for MsiSource {
    fn mask(&mut self) -> Result<(), IrqError> {
        let command = self.config.read16(4)?;
        if command == u16::MAX {
            return Err(IrqError::FailedRead);
        }
        self.config.write16(4, command | 1 << 10)?;
        self.msi.disable(&mut self.config)?;
        let actual = self.config.read16(4)?;
        let control = self.msi.control(&self.config)?;
        if actual == u16::MAX || control == u16::MAX {
            return Err(IrqError::FailedRead);
        }
        if actual & (1 << 10) == 0 || control & 1 != 0 {
            return Err(IrqError::Mask);
        }
        Ok(())
    }
    fn quiesce(&mut self) -> Result<(), IrqError> {
        if self.programmed {
            // GPU engine/payload and Linux service work have no independent
            // joined terminal acknowledgement here. Retain the old route.
            return Err(IrqError::Unsupported);
        }
        self.mask()
    }
    fn route_kind(&self) -> stela_drivers::bus::irq::RouteKind {
        stela_drivers::bus::irq::RouteKind::Msi
    }
    fn requester(&self) -> Option<&stela_drivers::bus::pci::requester::RequesterId> {
        None
    }
    unsafe fn program(
        &mut self,
        route: &stela_drivers::bus::irq::AllocatedRoute<'_>,
    ) -> Result<(), IrqError> {
        let Route::Msi(message) = route.programming() else {
            return Err(IrqError::Route);
        };
        let data = u16::try_from(message.data).map_err(|_| IrqError::Route)?;
        self.programmed = true;
        self.msi
            .program(&mut self.config, message.address, data)
            .map_err(IrqError::from)
    }
    unsafe fn unmask(&mut self) -> Result<(), IrqError> {
        self.msi.enable(&mut self.config)?;
        let control = self.msi.control(&self.config)?;
        if control == u16::MAX {
            return Err(IrqError::FailedRead);
        }
        if control & 1 == 0 {
            return Err(IrqError::Mask);
        }
        Ok(())
    }
    unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
        unsafe extern "C" {
            fn stela_linux_irq_actions_joined(irq: u32) -> bool;
        }
        // SAFETY: native callback runs below the exact entered Linux owner;
        // C free_irq retains its closing request and joined work until return.
        if !unsafe { stela_linux_irq_actions_joined(self.line) } {
            return Err(IrqError::Drain);
        }
        self.event.begin_close();
        // SAFETY: Registry already closed this exact action and drained native
        // CPU/inflight/EOI; the original pinned environment/event are retained.
        unsafe { (&*self.environment).join_irq(&self.event) }.map_err(|_| IrqError::Drain)
    }
}

/// Records an interrupt for the service task.
struct Fired {
    event: stela_linux::service::IrqEvent,
}

impl Handler for Fired {
    fn handle(&self) -> Disposition {
        match self.event.raise() {
            Ok(()) => Disposition::Handled,
            Err(_) => Disposition::NotMine,
        }
    }
}

/// A function as Linux's PCI core reaches it.
struct Device {
    config: SharedConfig,
    msi: Option<Msi>,
}

impl function::Host for Device {
    type Config = SharedConfig;
    fn config(&mut self) -> &mut SharedConfig {
        &mut self.config
    }
    fn enable_msi(&mut self) -> Result<(), function::MsiError> {
        // The line's route programs it, when nouveau requests its interrupt.
        self.msi
            .map(|_| ())
            .ok_or(function::MsiError::Native(EOPNOTSUPP))
    }
    fn disable_msi(&mut self) -> Result<(), function::MsiError> {
        if let Some(msi) = self.msi {
            msi.disable(&mut self.config)?;
        }
        Ok(())
    }
}

/// An interrupt line Linux knows a function by, its index in `Host::lines`.
struct Line {
    config: SharedConfig,
    msi: Option<Msi>,
    registration: Option<Box<dyn IrqRegistration>>,
    retired: Option<stela_drivers::bus::irq::RetiredSource<dyn Source>>,
}

/// What Linux code gets from Stela.
struct Host {
    tsc_hz: u64,
    realtime: Option<RealtimeOrigin>,
    window: &'static Window,
    firmware: Option<Arc<Catalog>>,
    image: Arc<kernel_work::ReadOnlyImage>,
    random: RefCell<Seeded>,
    environment: Cell<*const Environment>,
    /// The memory BARs Stela claimed, which are all Linux may map.
    bars: Vec<Range<u64>>,
    /// Device mappings' sizes in pages, by address.
    devices: RefCell<BTreeMap<u64, usize>>,
    lines: RefCell<Vec<Line>>,
    /// The unsupported operations already reported.
    reported: RefCell<BTreeSet<String>>,
}

impl Host {
    fn environment(&self) -> Pin<&Environment> {
        // SAFETY: set before any task runs, to a pinned box kept for the boot.
        unsafe { Pin::new_unchecked(&*self.environment.get()) }
    }

    fn map(&self, pages: usize, frame: impl Fn(u64) -> u64, cache: Cache) -> Option<*mut c_void> {
        let address = self.window.reserve(pages)?;
        for page in 0..pages as u64 {
            if !self
                .window
                .install(address + page * PAGE, frame(page), cache)
            {
                self.unmap(address, pages);
                return None;
            }
        }
        Some(address as *mut c_void)
    }

    fn unmap(&self, address: u64, pages: usize) {
        // A processor that kept the translation keeps the addresses too.
        if self.window.remove(address, pages) {
            self.window.release(address, pages);
        }
    }

    fn report(&self, line: core::fmt::Arguments<'_>) {
        output::arguments(format_args!("LINUX {line}\n"));
    }
}

impl Platform for Host {
    fn calibrated_tsc_hz(&self) -> Option<core::num::NonZeroU64> {
        core::num::NonZeroU64::new(self.tsc_hz)
    }

    fn now_ns(&self) -> i64 {
        nanoseconds(host::rdtsc(), self.tsc_hz) as i64
    }

    fn realtime_at(&self, ns: i64, read: RealtimeRead) -> Option<(i64, u32)> {
        self.realtime.as_ref()?.read(ns, read)
    }

    fn delay_us(&self, minimum: u64, _maximum: u64, atomic: bool) {
        if !atomic {
            // SAFETY: Linux calls this on a task of the environment.
            return unsafe { service::sleep_us(minimum) };
        }
        let start = host::rdtsc();
        let ticks = minimum.saturating_mul(self.tsc_hz / 1_000_000);
        while host::rdtsc().wrapping_sub(start) < ticks {
            core::hint::spin_loop();
        }
    }

    fn firmware(&self, name: &CStr) -> Result<&[u8], Errno> {
        let name = name.to_str().map_err(|_| ENOENT)?;
        let catalog = self.firmware.as_ref().ok_or(ENOENT)?;
        catalog
            .load(Requirement {
                name,
                target: FIRMWARE,
                minimum_bytes: 1,
            })
            .map(|image| image.bytes())
            .map_err(|_| {
                if let Some((chip, _)) = name
                    .strip_prefix("nvidia/")
                    .and_then(|name| name.split_once('/'))
                {
                    self.report(format_args!(
                        "{name} is missing: `stela setup host-firmware fetch --gpu {chip}` adds it"
                    ));
                }
                ENOENT
            })
    }

    fn log(&self, level: i32, message: &CStr) {
        let message = message.to_str().unwrap_or("(not UTF-8)").trim_end();
        self.report(format_args!("<{level}> {message}"));
    }

    fn warn(&self, file: &CStr, line: i32, condition: Option<&CStr>) {
        let file = file.to_str().unwrap_or("(not UTF-8)");
        let condition = condition.and_then(|text| text.to_str().ok()).unwrap_or("");
        self.report(format_args!("WARN {file}:{line} {condition}"));
    }

    fn unsupported(&self, operation: &CStr) {
        let operation = operation.to_str().unwrap_or("(not UTF-8)");
        if self.reported.borrow_mut().insert(operation.to_owned()) {
            self.report(format_args!("unsupported: {operation}"));
        }
    }

    fn random_bytes(&self, bytes: &mut [u8]) {
        self.random.borrow_mut().fill(bytes);
    }

    fn mix_random(&self, bytes: &[u8]) -> bool {
        self.random.borrow_mut().mix(host::rdtsc(), bytes);
        true
    }

    fn timer_changed(&self) -> Result<(), WorkError> {
        // SAFETY: after publication this points to the original pinned
        // environment, kept for the boot. A prepublication call is refused.
        let environment =
            unsafe { self.environment.get().as_ref() }.ok_or(WorkError::Unavailable)?;
        environment.timer_changed()
    }

    fn shutdown(&self, force: bool) {
        super::service::request_shutdown(force);
    }

    fn map_device(&self, physical: u64, size: usize, write_combining: bool) -> Option<*mut c_void> {
        let end = physical.checked_add(size as u64)?;
        if !self
            .bars
            .iter()
            .any(|bar| bar.start <= physical && end <= bar.end)
        {
            return None;
        }
        let pages = size / PAGE as usize;
        let cache = if write_combining {
            Cache::WriteCombining
        } else {
            Cache::Uncached
        };
        let address = self.map(pages, |page| physical + page * PAGE, cache)?;
        self.devices.borrow_mut().insert(address as u64, pages);
        Some(address)
    }

    unsafe fn unmap_device(&self, address: *mut c_void) {
        let pages = self.devices.borrow_mut().remove(&(address as u64));
        if let Some(pages) = pages {
            self.unmap(address as u64, pages);
        }
    }

    fn map_pages(&self, physical: &[u64]) -> Option<*mut c_void> {
        self.map(
            physical.len(),
            |page| physical[page as usize],
            Cache::WriteBack,
        )
    }

    unsafe fn unmap_pages(&self, address: *mut c_void, count: usize) {
        self.unmap(address as u64, count);
    }

    fn irq_enable(&self, irq: u32) -> Result<(), stela_linux::owner::IrqEnableError> {
        use stela_linux::owner::IrqEnableError;
        // Refuse a foreign native execution context before classifying any
        // owner return; no errno itself proves a clean unpublished attempt.
        let controller = native_irq::service().map_err(|_| IrqEnableError::retained(ENODEV))?;
        let mut lines = self.lines.borrow_mut();
        let Some(line) = lines.get_mut(irq as usize) else {
            // SAFETY: checked original process, before any route/event/source.
            return Err(unsafe { IrqEnableError::unexposed(EINVAL) });
        };
        if line.retired.is_some() {
            return Err(IrqEnableError::retained(EOPNOTSUPP));
        }
        if let Some(registration) = &mut line.registration {
            return registration
                .unmask()
                .map_err(|_| IrqEnableError::retained(EIO));
        }
        let Some(msi) = line.msi else {
            // SAFETY: no native attempt or service epoch was issued.
            return Err(unsafe { IrqEnableError::unexposed(EOPNOTSUPP) });
        };
        // SAFETY: actual original entered process; any preceding epoch joined.
        let event = unsafe { self.environment().irq_epoch(irq) }
            .map_err(|_| IrqEnableError::retained(EIO))?;
        let source = Box::new(MsiSource {
            config: line.config.clone(),
            msi,
            programmed: false,
            event: event.clone(),
            environment: self.environment.get(),
            line: irq,
        });
        let handler = Arc::new(Fired {
            event: event.clone(),
        });
        match controller.request(stela_drivers::bus::irq::Request {
            source,
            handler,
            routing: stela_drivers::bus::irq::RouteRequest::Msi(
                stela_drivers::bus::irq::posted_msi::MsiRoute::unavailable(),
            ),
        }) {
            Ok(registration) => {
                line.registration = Some(registration);
                Ok(())
            }
            Err(refusal) => {
                let errno = match refusal.error {
                    stela_drivers::bus::irq::IrqError::Exhausted => ENOMEM,
                    stela_drivers::bus::irq::IrqError::Unavailable => ENODEV,
                    stela_drivers::bus::irq::IrqError::Unsupported
                    | stela_drivers::bus::irq::IrqError::Delivery(
                        stela_drivers::bus::irq::posted_msi::Error::RootUnavailable
                        | stela_drivers::bus::irq::posted_msi::Error::Unsupported,
                    ) => EOPNOTSUPP,
                    _ => EIO,
                };
                if errno == EOPNOTSUPP {
                    self.unsupported(c"interrupt notification admission");
                } else {
                    self.report(format_args!("interrupt {irq} refused: {refusal:?}"));
                }
                let Some(untouched) = refusal.returned else {
                    return Err(IrqEnableError::retained(EIO));
                };
                // SAFETY: actual checked prepublication return; extraction
                // repeats the original process/context/provider checks.
                let (source, handler, routing) =
                    unsafe { untouched.into_parts() }.map_err(|_| IrqEnableError::retained(EIO))?;
                // Retain actual inputs before any fallible cancellation/join.
                let mut source = core::mem::ManuallyDrop::new(source);
                let mut handler = core::mem::ManuallyDrop::new(handler);
                let stela_drivers::bus::irq::RouteRequest::Msi(route) = routing else {
                    return Err(IrqEnableError::retained(EIO));
                };
                route
                    .cancel_unattached()
                    .map_err(|_| IrqEnableError::retained(EIO))?;
                event.begin_close();
                // SAFETY: RequestError returned actual untouched owners before
                // Slot/root/source publication, so this new event has no native
                // callback producer. Join still checks exact epoch/activity.
                unsafe { self.environment().join_irq(&event) }
                    .map_err(|_| IrqEnableError::retained(EIO))?;
                // SAFETY: same original process, unused route canceled and exact
                // new service epoch actually joined; no C action reachability.
                unsafe {
                    core::mem::ManuallyDrop::drop(&mut source);
                    core::mem::ManuallyDrop::drop(&mut handler);
                }
                // SAFETY: all original return/cancel/join facts above, not errno.
                Err(unsafe { IrqEnableError::unexposed(errno) })
            }
        }
    }

    fn irq_disable(&self, irq: u32) -> Result<(), Errno> {
        let mut lines = self.lines.borrow_mut();
        let line = lines.get_mut(irq as usize).ok_or(EINVAL)?;
        match &mut line.registration {
            Some(registration) => registration.mask().map_err(|_| EIO),
            None => Ok(()),
        }
    }
    fn irq_retire(&self, irq: u32) -> Result<(), Errno> {
        let mut lines = self.lines.borrow_mut();
        let line = lines.get_mut(irq as usize).ok_or(EINVAL)?;
        if line.retired.is_some() {
            return Err(EOPNOTSUPP);
        }
        let Some(registration) = line.registration.as_mut() else {
            return Ok(());
        };
        match registration.retire() {
            Err(error) => {
                self.report(format_args!("interrupt {irq} action retained: {error:?}"));
                Err(EOPNOTSUPP)
            }
            Ok(retired) => {
                // GPU has no original endpoint/entry delivery factory or
                // custody transfer yet. Do not return completed free_irq from
                // a future partial source implementation; keep typed owners.
                line.retired = Some(retired);
                Err(EOPNOTSUPP)
            }
        }
    }

    unsafe fn copy_from_user(&self, to: *mut u8, from: *const u8, size: usize) -> usize {
        // SAFETY: clients are in-process, so their addresses are ordinary
        // valid memory by the caller's contract.
        unsafe { ptr::copy_nonoverlapping(from, to, size) };
        0
    }

    unsafe fn copy_to_user(&self, to: *mut u8, from: *const u8, size: usize) -> usize {
        // SAFETY: as in `copy_from_user`.
        unsafe { ptr::copy_nonoverlapping(from, to, size) };
        0
    }

    unsafe fn copy_from_kernel_nofault(
        &self,
        to: *mut u8,
        from: *const u8,
        size: usize,
    ) -> Result<(), Errno> {
        if native_irq::current_context() != Ok(None) {
            return Err(EFAULT);
        }
        let heap = native_memory::SOURCE.registration();
        let in_heap = heap.generation != 0
            && from
                .addr()
                .checked_sub(heap.cpu)
                .is_some_and(|offset| offset <= heap.bytes && size <= heap.bytes - offset);
        if !in_heap && !self.image.contains_range(from.addr(), size) {
            return Err(ERANGE);
        }
        if from.addr().abs_diff(to.addr()) < size {
            return Err(EINVAL);
        }
        // SAFETY: the retained heap or immutable image owns the full source
        // range. The engine host IDT is active on this CPU, and the C caller
        // owns the disjoint writable destination.
        if unsafe { stela_boot_core::nofault_read::read(to, from, size) } == 0 {
            Ok(())
        } else {
            Err(EFAULT)
        }
    }

    fn available_page_frames(&self, start: usize, pages: usize) -> Result<usize, Errno> {
        if native_irq::current_context() != Ok(None) {
            return Err(EFAULT);
        }
        let heap = native_memory::SOURCE.registration();
        let bytes = pages
            .checked_mul(stela_boot_core::native_memory::PAGE)
            .ok_or(ERANGE)?;
        let end = start.checked_add(bytes).ok_or(ERANGE)?;
        if heap.generation == 0 || start < heap.cpu || end - heap.cpu > heap.bytes {
            return Err(ERANGE);
        }
        Ok(crate::ALLOCATOR.available_page_frames_in(start..end))
    }

    fn map_user(&self, space: *mut c_void, address: u64, pfn: u64, prot: u64) -> Result<(), Errno> {
        if !space.is_null() {
            return Err(EOPNOTSUPP);
        }
        let entry = page_window::client_leaf(pfn, prot).ok_or(EINVAL)?;
        if self.window.install_client(address, entry) {
            Ok(())
        } else {
            Err(ENOMEM)
        }
    }

    fn unmap_user(&self, space: *mut c_void, address: u64, size: usize) -> Result<(), Errno> {
        if !space.is_null() {
            return Err(EOPNOTSUPP);
        }
        if self.window.remove(address, size / PAGE as usize) {
            Ok(())
        } else {
            Err(EIO)
        }
    }
}

/// A function claimed from probe, before Linux sees it.
pub(super) struct Claimed {
    device: Device,
    domain: Arc<dyn DmaDomain>,
    placement: Placement,
    bars: Vec<Range<u64>>,
    name: String,
    #[cfg(feature = "nvk")]
    drm: client::DrmDevice,
    #[cfg(feature = "nvk")]
    link: Option<PcieLink>,
    /// The BARs' claims, held for the boot.
    _resources: Vec<owned::Resource>,
}

fn claim(
    services: &dyn NativeServices,
    adapter: &gpu::Adapter,
    line: u32,
) -> Result<Claimed, ServiceError> {
    let address = adapter.address;
    let requester = services.claim_stopped(address)?;
    let (requester, binding) = requester
        .into_dma_binding()
        .map_err(|(error, _)| ServiceError::Claim(error))?;
    let domain = services.domain(binding)?;
    let mut function = requester.into_function();
    let capabilities = function
        .capabilities()
        .map_err(ServiceError::PciCapability)?;
    let msi = capabilities
        .iter()
        .find(|(_, id)| *id == MSI_CAPABILITY)
        .map(|(offset, _)| Msi::at(u16::from(*offset)));
    let mut placement = Placement {
        bus: address.bus,
        devfn: address.device << 3 | address.function,
        irq: line,
        dma_limit: DMA_LIMIT,
        ..Placement::default()
    };
    let (mut bars, mut resources) = (Vec::new(), Vec::new());
    let function_bars = function.bars().map_err(ServiceError::Config)?;
    for (region, bar) in placement.regions.iter_mut().zip(function_bars) {
        let Some(
            bar @ Bar::Memory {
                address: start,
                size,
                prefetchable,
                wide,
            },
        ) = bar
        else {
            continue;
        };
        resources.push(services.bar_resource(address, bar)?);
        bars.push(start..start + size);
        *region = Region {
            start,
            size,
            flags: RESOURCE_MEMORY
                | if prefetchable {
                    RESOURCE_PREFETCHABLE
                } else {
                    0
                }
                | if wide { RESOURCE_WIDE } else { 0 },
        };
    }
    #[cfg(feature = "nvk")]
    let drm = {
        let config = function.config();
        let subsystem = config.read32(SUBSYSTEM_ID).map_err(ServiceError::Config)?;
        let revision = config.read8(REVISION).map_err(ServiceError::Config)?;
        client::DrmDevice {
            segment: address.segment,
            vendor: function.vendor,
            device: function.device,
            subsystem_vendor: subsystem as u16,
            subsystem_device: (subsystem >> 16) as u16,
            bus: address.bus,
            slot: address.device,
            function: address.function,
            revision,
        }
    };
    #[cfg(feature = "nvk")]
    let link = capabilities
        .iter()
        .find(|(_, id)| *id == PCIE_CAPABILITY)
        .map(|(offset, _)| {
            function
                .config()
                .read16(u16::from(*offset) + LINK_STATUS)
                .map(PcieLink::from_link_status)
        })
        .transpose()
        .map_err(ServiceError::Config)?;
    Ok(Claimed {
        device: Device {
            config: SharedConfig(Rc::new(RefCell::new(function))),
            msi,
        },
        domain,
        placement,
        bars,
        name: format!("{address}"),
        #[cfg(feature = "nvk")]
        drm,
        #[cfg(feature = "nvk")]
        link,
        _resources: resources,
    })
}

/// Claim every NVIDIA adapter, each reported if it cannot be. In a foreground
/// continuation, with probe finished.
pub(super) fn claim_all(services: &dyn NativeServices, adapters: &[gpu::Adapter]) -> Vec<Claimed> {
    if !cfg!(feature = "nvk") {
        for adapter in adapters
            .iter()
            .filter(|adapter| adapter.vendor == gpu::Vendor::Nvidia)
        {
            output::arguments(format_args!(
                "GPU {} left with firmware: build the image with `cargo xtask boot build --nvk`\n",
                adapter.address
            ));
        }
        return Vec::new();
    }
    let nvidia = adapters
        .iter()
        .filter(|adapter| adapter.vendor == gpu::Vendor::Nvidia);
    let mut claimed = Vec::new();
    for adapter in nvidia {
        match claim(services, adapter, claimed.len() as u32) {
            Ok(function) => claimed.push(function),
            Err(error) => {
                output::arguments(format_args!("GPU {} refused: {error:?}\n", adapter.address))
            }
        }
    }
    claimed
}

/// A GPU nouveau bound.
#[cfg(feature = "nvk")]
struct Bound {
    name: String,
    drm: client::DrmDevice,
    link: Option<PcieLink>,
}

/// The first task's work: Linux, then every GPU.
struct Start {
    owner: *const RawOwner,
    claimed: Vec<Claimed>,
    attached: Vec<Attached<Device>>,
    /// The bound GPUs, by DRM minor.
    #[cfg(feature = "nvk")]
    bound: Vec<Bound>,
    result: Result<(), Errno>,
}

unsafe extern "C" fn start(context: *mut c_void) {
    // SAFETY: `open` keeps the job through its ticket, and only this task
    // touches it until the ticket completes.
    let job = unsafe { &mut *context.cast::<Start>() };
    // SAFETY: a task of the environment, whose owner lasts for the boot.
    let _entered = unsafe { Entered::new(job.owner) };
    // SAFETY: entered, on a task.
    job.result = unsafe { gpu::nouveau::start() };
    if job.result.is_err() {
        return;
    }
    for claimed in core::mem::take(&mut job.claimed) {
        // SAFETY: entered, on a task.
        let attached = unsafe { Attached::new(claimed.device, claimed.domain, claimed.placement) };
        match attached {
            Ok(attached) => {
                // SAFETY: entered.
                if unsafe { attached.bound() } {
                    #[cfg(feature = "nvk")]
                    job.bound.push(Bound {
                        name: claimed.name,
                        drm: claimed.drm,
                        link: claimed.link,
                    });
                } else {
                    output::arguments(format_args!(
                        "GPU {}: nouveau did not bind it\n",
                        claimed.name
                    ));
                }
                job.attached.push(attached);
            }
            Err(error) => output::arguments(format_args!(
                "GPU {} presentation refused: {:?}\n",
                claimed.name, error.error
            )),
        }
    }
}

/// The running environment.
#[cfg_attr(
    not(feature = "nvk"),
    allow(
        dead_code,
        reason = "held for the boot; only Mesa's client reads these"
    )
)]
struct Installed {
    work: &'static KernelWork,
    time: Arc<dyn Clock>,
    events: Arc<Events>,
    domain: Arc<Domain<SLOTS>>,
    /// When the service is next due, in the clock's nanoseconds.
    next: AtomicU64,
    #[cfg(feature = "nvk")]
    window: &'static Window,
    #[cfg(feature = "nvk")]
    tsc_hz: u64,
    #[cfg(feature = "nvk")]
    heap_bytes: u64,
    /// Clients' mappings with their sizes in pages, by address. For tasks.
    #[cfg(feature = "nvk")]
    mappings: RefCell<BTreeMap<u64, (stela_linux::client::Mapping, usize)>>,
    /// Mesa's running threads, by the bottom of their stacks. On the boot CPU.
    #[cfg(feature = "nvk")]
    threads: RefCell<BTreeMap<u64, client::Running>>,
    owner: Pin<Box<Owner<Host>>>,
    environment: Pin<Box<Environment>>,
    start: Box<Start>,
}

static INSTALLED: AtomicPtr<Installed> = AtomicPtr::new(ptr::null_mut());

fn installed() -> Option<&'static Installed> {
    // SAFETY: a published environment is leaked, so it lives for the boot.
    unsafe { INSTALLED.load(Ordering::Acquire).as_ref() }
}

/// What [`open`] needs beyond the claimed functions.
pub(super) struct Machine {
    pub work: &'static KernelWork,
    pub window: &'static Window,
    pub firmware: Option<Arc<Catalog>>,
    pub random: Seeded,
    pub tsc_hz: u64,
    pub wall: Option<RtcReading>,
    /// What the heap can give, which is all a software device's memory.
    #[cfg(feature = "nvk")]
    pub heap_bytes: u64,
}

fn environment_error(error: WorkError) -> kernel_work::Error {
    kernel_work::Error::Work(error)
}

/// Why this boot gives macOS no Metal device, if it does not. WindowServer
/// aborts without one (docs/research/display-gpu.md section 2) and watchdogd
/// then panics the system, so a boot of macOS stops here instead.
pub(super) fn no_metal_device() -> Option<&'static str> {
    #[cfg(feature = "nvk")]
    return gate::shared()
        .is_empty()
        .then_some("no GPU started; the lines above say why");
    #[cfg(not(feature = "nvk"))]
    Some("this stela.efi was built without GPU drivers (`--nvk`)")
}

/// The kexts a boot that gives the GPUs to nouveau links into its system.
pub(super) fn kexts() -> Vec<stela_loader::aux_kc::Kext<'static>> {
    #[cfg(feature = "nvk")]
    return alloc::vec![stela_loader::aux_kc::Kext {
        info: kext::INFO,
        objects: kext::OBJECTS.to_vec(),
        bundle_path: "/Library/Extensions/StelaGPU.kext".into(),
        trusted_code: kext::TRUSTED_CODE.to_vec(),
    }];
    #[cfg(not(feature = "nvk"))]
    Vec::new()
}

/// Takes the display for the GPUs [`open`] bound, in the firmware's `screen`
/// size if it can, and opens their Metal services.
pub(super) fn serve(
    #[cfg_attr(not(feature = "nvk"), allow(unused_variables))] screen: (usize, usize),
) {
    #[cfg(feature = "nvk")]
    {
        display::take(screen);
        gate::open_service();
    }
}

/// Bring Linux up over `claimed`, and return once nouveau has bound them or
/// failed, as the guest should not start with a half-started GPU beneath it.
pub(super) fn open(machine: Machine, claimed: Vec<Claimed>) -> Result<(), Error> {
    let Machine {
        work,
        window,
        firmware,
        random,
        tsc_hz,
        wall,
        #[cfg(feature = "nvk")]
        heap_bytes,
    } = machine;
    let image = work.image()?;
    #[cfg(feature = "nvk")]
    let claiming = !claimed.is_empty();
    let lines = claimed
        .iter()
        .map(|claimed| Line {
            config: claimed.device.config.clone(),
            msi: claimed.device.msi,
            registration: None,
            retired: None,
        })
        .collect();
    let bars = claimed
        .iter()
        .flat_map(|claimed| claimed.bars.iter().cloned())
        .collect();
    let realtime = wall.and_then(|reading| {
        if tsc_hz == 0
            || !crate::cpu::INVARIANT_TSC.present()
            || reading.resolution == 0
            || reading.tsc_before > reading.tsc_after
        {
            return None;
        }
        // Correlate with the same boot-CPU TSC scale as Host::now_ns.
        let origin = u128::from(reading.tsc_after) * 1_000_000_000 / u128::from(tsc_hz);
        RealtimeOrigin::new(
            i64::try_from(origin).ok()?,
            i64::try_from(reading.utc.seconds).ok()?,
            reading.utc.nanosecond,
        )
    });
    let owner = Owner::new(Host {
        tsc_hz,
        realtime,
        window,
        firmware,
        image: image.clone(),
        random: RefCell::new(random),
        environment: Cell::new(ptr::null()),
        bars,
        devices: RefCell::new(BTreeMap::new()),
        lines: RefCell::new(lines),
        reported: RefCell::new(BTreeSet::new()),
    });
    let time: Arc<dyn Clock> = Arc::new(Time {
        cpu: work.cpu(),
        tsc_hz,
    });
    let events = Arc::new(Events {
        clock: time.clone(),
        pending: AtomicBool::new(false),
    });
    let domain = Domain::tickless(time.clone(), events.clone()).map_err(environment_error)?;
    let mut job = Box::new(Start {
        owner: owner.raw(),
        claimed,
        attached: Vec::new(),
        #[cfg(feature = "nvk")]
        bound: Vec::new(),
        result: Ok(()),
    });
    let context = (&raw mut *job).cast();
    // SAFETY: one environment for the boot, on the boot CPU before any producer
    // or PE: the image and heap are this binary's, and the page catalog is kept.
    unsafe {
        stela_linux::image::register(image).map_err(|_| kernel_work::Error::Inventory)?;
        stela_linux::heap::register(allocate_zeroed).map_err(|_| kernel_work::Error::Inventory)?;
        let catalog = native_memory::linux_pages().map_err(|_| kernel_work::Error::Inventory)?;
        core::mem::forget(catalog);
    }
    #[cfg(feature = "nvk")]
    BOOT_CPU.store(host::processor(), Ordering::Relaxed);
    let deadline = host::rdtsc() + START_SECONDS * tsc_hz;
    let opened = work.dispatch(|runtime| {
        // SAFETY: in the dispatcher; the owner and runtime last for the boot.
        let environment = unsafe { Environment::new(owner.raw(), runtime, domain.clone()) }?;
        owner.platform().environment.set(addr_of!(*environment));
        let started = (|| {
            environment.as_ref().start()?;
            // SAFETY: `start` enters the owner itself, and the job is kept.
            let ticket = unsafe { environment.as_ref().spawn(start, context) }?;
            let queue = runtime.get_ref().queue();
            while !queue.completed(ticket)? && host::rdtsc() < deadline {
                runtime.step_or_idle()?;
            }
            queue.completed(ticket)
        })();
        match started {
            Ok(finished) => Ok((environment, finished)),
            Err(error) => {
                // A failed dispatch cannot prove its native tasks stopped.
                // Their environment, owner and callback job must stay live.
                core::mem::forget(environment);
                Err(error)
            }
        }
    });
    let started = opened
        .map_err(Error::Environment)
        .and_then(|started| started.map_err(|error| Error::Environment(environment_error(error))));
    let (environment, finished) = match started {
        Ok(started) => started,
        Err(error) => {
            core::mem::forget(owner);
            core::mem::forget(job);
            return Err(error);
        }
    };
    let mut result = Ok(());
    if !finished {
        // It goes on between the guest's slices.
        crate::status::warn("the GPUs are still starting");
        result = Err(Error::Timeout);
    } else if let Err(error) = job.result {
        output::arguments(format_args!("Linux stopped starting: errno {}\n", -error));
        crate::status::warn("Linux could not start, so the GPUs are unavailable");
        result = Err(Error::Init(error));
    }
    // With nothing claimed, the environment serves software Metal.
    #[cfg(feature = "nvk")]
    if finished && result.is_ok() && claiming && job.bound.is_empty() {
        result = Err(Error::NoDevices);
    }
    let next = match domain.next_deadline() {
        Ok(deadline) => deadline.unwrap_or(u64::MAX),
        Err(error) => {
            // The tasks have started; preserve all objects their callbacks
            // borrow even when the clock can no longer schedule their work.
            core::mem::forget(environment);
            core::mem::forget(owner);
            core::mem::forget(job);
            return Err(Error::Environment(environment_error(error)));
        }
    };
    let installed = Box::new(Installed {
        work,
        time,
        events,
        domain,
        next: AtomicU64::new(next),
        #[cfg(feature = "nvk")]
        window,
        #[cfg(feature = "nvk")]
        tsc_hz,
        #[cfg(feature = "nvk")]
        heap_bytes,
        #[cfg(feature = "nvk")]
        mappings: RefCell::new(BTreeMap::new()),
        #[cfg(feature = "nvk")]
        threads: RefCell::new(BTreeMap::new()),
        owner,
        environment,
        start: job,
    });
    INSTALLED.store(Box::into_raw(installed), Ordering::Release);
    result
}

/// Startup failures distinguish the work environment from driver admission.
#[derive(Debug)]
pub(super) enum Error {
    Environment(kernel_work::Error),
    Init(Errno),
    Timeout,
    #[cfg(feature = "nvk")]
    NoDevices,
}

impl From<kernel_work::Error> for Error {
    fn from(error: kernel_work::Error) -> Self {
        Self::Environment(error)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Environment(error) => write!(f, "Linux environment: {error}"),
            Self::Init(error) => write!(f, "Linux initialization failed: errno {}", -error),
            Self::Timeout => {
                f.write_str("GPU startup exceeded its deadline; native owners remain held")
            }
            #[cfg(feature = "nvk")]
            Self::NoDevices => f.write_str("nouveau bound no NVIDIA GPUs"),
        }
    }
}

/// Run what is ready in the environment, between the boot PE's slices.
pub(super) fn pump() {
    let Some(gpu) = installed() else {
        return;
    };
    let due = match gpu.time.now_ns() {
        Ok(now) => now >= gpu.next.load(Ordering::Relaxed),
        Err(_) => true,
    };
    if !gpu.events.pending.swap(false, Ordering::AcqRel) && !due {
        return;
    }
    let ran = gpu.work.dispatch(|runtime| {
        #[cfg(feature = "nvk")]
        client::start(gpu)?;
        while runtime.step()? {
            if super::service::shutdown_pending() {
                gpu.events.pending.store(true, Ordering::Release);
                break;
            }
        }
        Ok::<_, WorkError>(())
    });
    if let Err(error) = ran.and_then(|ran| {
        ran.map_err(environment_error)?;
        let next = gpu.domain.next_deadline().map_err(environment_error)?;
        gpu.next.store(next.unwrap_or(u64::MAX), Ordering::Relaxed);
        Ok(())
    }) {
        output::fatal(format_args!("the host's Linux environment failed: {error}"));
    }
    #[cfg(feature = "nvk")]
    gate::interrupted();
}

/// `ticks` of the host counter, cut short to end at Linux's next deadline.
pub(super) fn slice(ticks: u64) -> u64 {
    let Some(gpu) = installed() else {
        return ticks;
    };
    let next = gpu.next.load(Ordering::Relaxed);
    let Ok(now) = gpu.time.now_ns() else {
        return ticks;
    };
    let left = u128::from(next.saturating_sub(now)) * u128::from(host::COUNTER_HZ) / 1_000_000_000;
    ticks.min(left.min(u128::from(u64::MAX)) as u64).max(1)
}
