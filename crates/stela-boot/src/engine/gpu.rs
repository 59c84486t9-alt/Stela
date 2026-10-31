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
pub(super) mod display;
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
use crate::{native_irq, native_memory, native_mmio::Window, output};
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
        irq::{Disposition, Handler, IrqError, IrqRegistration, Route, RouteRequest, Source},
        mmio::owned,
        pci::{Bar, ConfigSpace, Function, owned::OwnedConfig},
    },
    firmware::{Catalog, Provider, Requirement, Target},
    gpu::{
        self,
        linux::{
            self,
            function::{self, Attached, Msi, Placement, Region},
            owner::{Entered, Errno, Owner, Platform, RawOwner},
            random::Seeded,
            service::{self, Environment as LinuxEnvironment},
        },
    },
    platform::{
        image::NativeReadOnlyImage,
        work::{
            Cpu, WorkError,
            service::{Clock, Domain, Idle},
        },
    },
    probe::{NativeServices, ServiceError},
};
use stela_engine::machine::engine::Hub;

type Environment = LinuxEnvironment<SLOTS>;

const PAGE: u64 = page_window::PAGE;
const ENOENT: Errno = -2;
const EIO: Errno = -5;
const EAGAIN: Errno = -11;
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

/// `.rdata` of the running image, which Linux keeps constant names in.
struct ReadOnlyImage(Range<usize>);

unsafe extern "C" {
    /// The image's first byte, which the linker defines.
    static __ImageBase: u8;
}

impl ReadOnlyImage {
    /// The section from the headers the image was loaded with.
    fn locate() -> Option<Self> {
        const NEW_HEADER: usize = 0x3c;
        const SECTION_COUNT: usize = 6;
        const OPTIONAL_SIZE: usize = 20;
        const SECTIONS: usize = 24;
        const SECTION_BYTES: usize = 40;
        let base = addr_of!(__ImageBase);
        // SAFETY: the loader keeps the image's headers, little-endian on x86.
        let read = |at: usize, bytes: usize| unsafe {
            (0..bytes).fold(0usize, |value, byte| {
                value | usize::from(base.add(at + byte).read()) << (8 * byte)
            })
        };
        let header = read(NEW_HEADER, 4);
        let sections = header + SECTIONS + read(header + OPTIONAL_SIZE, 2);
        (0..read(header + SECTION_COUNT, 2)).find_map(|index| {
            let section = sections + index * SECTION_BYTES;
            // SAFETY: as for `read`.
            let name = unsafe { core::slice::from_raw_parts(base.add(section), 8) };
            (name == b".rdata\0\0").then(|| {
                let start = base as usize + read(section + 12, 4);
                Self(start..start + read(section + 8, 4))
            })
        })
    }
}

// SAFETY: the image's own read-only section, which never moves or changes and
// holds every literal of the Rust and C code linked into it.
unsafe impl NativeReadOnlyImage for ReadOnlyImage {
    fn contains(&self, address: usize) -> bool {
        self.0.contains(&address)
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
    fn read32(&self, offset: u16) -> u32 {
        self.0.borrow_mut().config().read32(offset)
    }
    fn write32(&mut self, offset: u16, value: u32) {
        self.0.borrow_mut().config().write32(offset, value);
    }
    fn read16(&self, offset: u16) -> u16 {
        self.0.borrow_mut().config().read16(offset)
    }
    fn read8(&self, offset: u16) -> u8 {
        self.0.borrow_mut().config().read8(offset)
    }
    fn write16(&mut self, offset: u16, value: u16) {
        self.0.borrow_mut().config().write16(offset, value);
    }
    fn write8(&mut self, offset: u16, value: u8) {
        self.0.borrow_mut().config().write8(offset, value);
    }
}

/// The MSI of one function, routed to the boot CPU.
struct MsiSource {
    config: SharedConfig,
    msi: Msi,
}

// SAFETY: the function was stopped when claimed, with no route of its own.
// Nothing here frees: the config and capability stay with the registration, and
// nouveau has masked its interrupts by the time it frees the line.
unsafe impl Source for MsiSource {
    fn mask(&mut self) -> Result<(), IrqError> {
        self.msi.disable(&mut self.config);
        Ok(())
    }
    fn quiesce(&mut self) -> Result<(), IrqError> {
        self.mask()
    }
    fn route(&self) -> RouteRequest {
        RouteRequest::Msi
    }
    unsafe fn program(&mut self, route: Route) -> Result<(), IrqError> {
        let Route::Msi(message) = route else {
            return Err(IrqError::Route);
        };
        let data = u16::try_from(message.data).map_err(|_| IrqError::Route)?;
        self.msi.program(&mut self.config, message.address, data);
        Ok(())
    }
    unsafe fn unmask(&mut self) -> Result<(), IrqError> {
        self.msi.enable(&mut self.config);
        Ok(())
    }
    unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
        Ok(())
    }
}

/// Records an interrupt for the service task.
struct Fired {
    environment: *const Environment,
    line: u32,
}

// SAFETY: `raise` is the environment's interrupt-safe entry, and it lives for
// the boot.
unsafe impl Send for Fired {}
// SAFETY: as above.
unsafe impl Sync for Fired {}

impl Handler for Fired {
    fn handle(&self) -> Disposition {
        // SAFETY: the environment outlives every route, as above.
        match unsafe { &*self.environment }.raise(self.line) {
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
    fn enable_msi(&mut self) -> Result<(), Errno> {
        // The line's route programs it, when nouveau requests its interrupt.
        self.msi.map(|_| ()).ok_or(EOPNOTSUPP)
    }
    fn disable_msi(&mut self) {
        if let Some(msi) = self.msi {
            msi.disable(&mut self.config);
        }
    }
}

/// An interrupt line Linux knows a function by, its index in `Host::lines`.
struct Line {
    config: SharedConfig,
    msi: Option<Msi>,
    registration: Option<Box<dyn IrqRegistration>>,
}

/// What Linux code gets from Stela.
struct Host {
    tsc_hz: u64,
    window: &'static Window,
    firmware: Option<Arc<Catalog>>,
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
    fn now_ns(&self) -> i64 {
        nanoseconds(host::rdtsc(), self.tsc_hz) as i64
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
                        "{name} is missing: `stela setup firmware fetch --gpu {chip}` adds it"
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

    fn start_worker(&self) -> Result<(), Errno> {
        self.environment()
            .start_worker()
            .map(|_| ())
            .map_err(|_| EAGAIN)
    }

    fn shutdown(&self, force: bool) {
        self.report(format_args!(
            "left running: a request to power off (force={force})"
        ));
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

    fn irq_enable(&self, irq: u32) -> Result<(), Errno> {
        let mut lines = self.lines.borrow_mut();
        let line = lines.get_mut(irq as usize).ok_or(EINVAL)?;
        let msi = line.msi.ok_or(EOPNOTSUPP)?;
        let controller = native_irq::service().map_err(|_| ENODEV)?;
        let source = Box::new(MsiSource {
            config: line.config.clone(),
            msi,
        });
        let handler = Arc::new(Fired {
            environment: self.environment.get(),
            line: irq,
        });
        match controller.request(source, handler) {
            Ok(registration) => {
                line.registration = Some(registration);
                Ok(())
            }
            Err(error) => {
                self.report(format_args!("interrupt {irq} refused: {error:?}"));
                Err(EIO)
            }
        }
    }

    fn irq_disable(&self, irq: u32) {
        let mut lines = self.lines.borrow_mut();
        let registration = lines
            .get_mut(irq as usize)
            .and_then(|line| line.registration.take());
        if let Some(mut registration) = registration
            && let Err(error) = registration.retire()
        {
            self.report(format_args!("interrupt {irq} kept: {error:?}"));
            // Retirement failed, so the route stays held for the boot.
            core::mem::forget(registration);
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

    fn map_user(&self, _: *mut c_void, address: u64, pfn: u64, prot: u64) -> Result<(), Errno> {
        // Clients share the window, so its one address space serves them all.
        let cache = page_window::cache_of(prot);
        if self.window.install(address, pfn * PAGE, cache) {
            Ok(())
        } else {
            Err(ENOMEM)
        }
    }

    fn unmap_user(&self, _: *mut c_void, address: u64, size: usize) {
        self.window.remove(address, size / PAGE as usize);
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
    let msi = function
        .capabilities()
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
    for (region, bar) in placement.regions.iter_mut().zip(function.bars()) {
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
        let (identity, subsystem) = (config.read32(0), config.read32(SUBSYSTEM_ID));
        client::DrmDevice {
            segment: address.segment,
            vendor: identity as u16,
            device: (identity >> 16) as u16,
            subsystem_vendor: subsystem as u16,
            subsystem_device: (subsystem >> 16) as u16,
            bus: address.bus,
            slot: address.device,
            function: address.function,
            revision: config.read8(REVISION),
        }
    };
    #[cfg(feature = "nvk")]
    let link = function
        .capabilities()
        .iter()
        .find(|(_, id)| *id == PCIE_CAPABILITY)
        .map(|(offset, _)| {
            let status = function.config().read16(u16::from(*offset) + LINK_STATUS);
            PcieLink::from_link_status(status)
        });
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
    job.result = unsafe { linux::nouveau::start() };
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
                "GPU {} not presented to Linux: errno {}\n",
                claimed.name, -error
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
    /// Clients' mappings with their sizes in pages, by address. For tasks.
    #[cfg(feature = "nvk")]
    mappings: RefCell<BTreeMap<u64, (linux::client::Mapping, usize)>>,
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
}

fn environment_error(error: WorkError) -> kernel_work::Error {
    kernel_work::Error::Work(error)
}

/// The kexts a boot that gives the GPUs to nouveau links into its system.
pub(super) fn kexts() -> Vec<stela_loader::aux_kc::Kext<'static>> {
    #[cfg(feature = "nvk")]
    return alloc::vec![stela_loader::aux_kc::Kext {
        info: kext::INFO,
        objects: kext::OBJECTS.to_vec(),
        bundle_path: "/Library/Extensions/StelaGPU.kext".into(),
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
pub(super) fn open(machine: Machine, claimed: Vec<Claimed>) -> Result<(), kernel_work::Error> {
    let Machine {
        work,
        window,
        firmware,
        random,
        tsc_hz,
    } = machine;
    let image = ReadOnlyImage::locate().ok_or(kernel_work::Error::Inventory)?;
    let lines = claimed
        .iter()
        .map(|claimed| Line {
            config: claimed.device.config.clone(),
            msi: claimed.device.msi,
            registration: None,
        })
        .collect();
    let bars = claimed
        .iter()
        .flat_map(|claimed| claimed.bars.iter().cloned())
        .collect();
    let owner = Owner::new(Host {
        tsc_hz,
        window,
        firmware,
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
        linux::image::register(Arc::new(image)).map_err(|_| kernel_work::Error::Inventory)?;
        linux::heap::register(allocate_zeroed).map_err(|_| kernel_work::Error::Inventory)?;
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
        environment.as_ref().start()?;
        // SAFETY: `start` enters the owner itself, and the job is kept.
        let ticket = unsafe { environment.as_ref().spawn(start, context) }?;
        let queue = runtime.get_ref().queue();
        while !queue.completed(ticket)? && host::rdtsc() < deadline {
            runtime.step_or_idle()?;
        }
        Ok((environment, queue.completed(ticket)?))
    })?;
    let (environment, finished) = opened.map_err(environment_error)?;
    if !finished {
        // It goes on between the guest's slices.
        crate::status::warn("the GPUs are still starting");
    } else if let Err(error) = job.result {
        output::arguments(format_args!("Linux stopped starting: errno {}\n", -error));
        crate::status::warn("Linux could not start, so the GPUs are unavailable");
    }
    let next = domain
        .next_deadline()
        .map_err(environment_error)?
        .unwrap_or(u64::MAX);
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
        mappings: RefCell::new(BTreeMap::new()),
        #[cfg(feature = "nvk")]
        threads: RefCell::new(BTreeMap::new()),
        owner,
        environment,
        start: job,
    });
    INSTALLED.store(Box::into_raw(installed), Ordering::Release);
    Ok(())
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
        while runtime.step()? {}
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
