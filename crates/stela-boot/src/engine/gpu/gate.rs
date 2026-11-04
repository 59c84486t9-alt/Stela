//! The Metal service over NVK, which the guest reaches through StelaGPU's gate,
//!
//! It opens on the boot CPU once nouveau has bound the GPUs, before the guest's
//! DeviceTree is final, so the tree has a gate only with a device behind it,
//! and one for each GPU that opened.
//!
//! Each service runs on a stack of its own, deep enough for a compile. Its
//! lock means one is enough; opening comes before any caller.
use super::{
    BOOT_CPU, Bound, Installed, PAGE, client, installed, pump,
    stack::{self, Stack},
};
use crate::{engine::host, output};
use alloc::{boxed::Box, format, sync::Arc, vec::Vec};
use core::{
    ffi::{c_char, c_void},
    hint,
    num::NonZeroU64,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering},
};
use stela_contracts::gate::{GateService, MemoryRange, window};
use stela_drivers::gpu::{
    linux::{
        client::Run,
        function::{dma_quarantine_status, quarantined_functions},
    },
    metal::{
        compiler::{self, AirCompiler},
        device::lifecycle::QuiesceStatus,
        error::Error,
        native::{ExportedMemory, Loader, MemoryExporter, NativeBackend, vk},
        nvidia::{
            Attachment,
            open::{Gpu, OpenError, open, reopen},
        },
        service::{Served, ServiceHost, SharedService, identity::DeviceEpoch, wire::Status},
        vulkan::physical::PciBusInfo,
    },
};
use stela_loader::{apple_device_tree::DeviceTree, stela_gpu};

type Shared = SharedService<NativeBackend, AirCompiler>;

/// A process's main stack, as big as the deepest compile LLVM bounds.
const STACK_BYTES: usize = 16 << 20;

/// How long a GPU's accepted work may go without progress as the PC stops:
/// with the guest stopped, an event it waits on will never signal.
const STOP_STALL_SECONDS: u64 = 5;
/// How long the stop waits for a GSP to unload.
const STOP_UNLOAD_SECONDS: u64 = 10;

/// The services for the kernel's interrupts, once all are open.
static SERVICES: AtomicPtr<Vec<Arc<Shared>>> = AtomicPtr::new(ptr::null_mut());

unsafe extern "C" {
    fn stela_nvk_nir_options(physical: vk::PhysicalDevice) -> *const c_void;
}

fn run(stack: u64, body: &mut dyn FnMut()) {
    // SAFETY: a service's stack lives for the boot, and only the opener or a
    // turn's holder is here.
    unsafe { stack::on_stack(stack, body) };
}

pub(super) fn relax() {
    // What this waits for may be retiring a mapping, which waits for this.
    crate::native_mmio::shootdown::service();
    if host::processor() == BOOT_CPU.load(Ordering::Relaxed) {
        pump();
    }
    hint::spin_loop();
}

/// Whether `text` is new to `seen`. FNV-1a: a text is built per call, so
/// only its bytes identify it; once `seen` fills, every text is new.
fn first_time(seen: &[AtomicU64], text: &str) -> bool {
    let hash = text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
    });
    for slot in seen {
        match slot.compare_exchange(0, hash, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(known) if known == hash => return false,
            Err(_) => {}
        }
    }
    true
}

/// Logs why the service refused a guest's call, once for each reason.
fn report(reason: &str) {
    static SEEN: [AtomicU64; 128] = [const { AtomicU64::new(0) }; 128];
    if first_time(&SEEN, reason) {
        output::arguments(format_args!("GPU REFUSED {reason}\n"));
    }
}

/// Logs a render pipeline the guest made, once for each distinct one.
fn note(text: &str) {
    static SEEN: [AtomicU64; 512] = [const { AtomicU64::new(0) }; 512];
    if first_time(&SEEN, text) {
        output::arguments(format_args!("GPU PIPELINE {text}\n"));
    }
}

/// The guest calls one operation's gate served since the last report.
struct Calls {
    /// The operation plus one; zero while the slot is free.
    key: AtomicU32,
    count: AtomicU64,
    /// TSC ticks holding the service, the longest one call held it, and
    /// waiting for another call's turn.
    held: AtomicU64,
    longest: AtomicU64,
    waited: AtomicU64,
    /// Calls answered `Unmapped`, which the frontend repeats.
    unmapped: AtomicU64,
    /// Requests the calls posted to the host's Linux environment, and the
    /// ticks they waited for the boot CPU to serve them.
    posted: AtomicU64,
    posted_waited: AtomicU64,
}

/// More slots than the protocol has operations.
static CALLS: [Calls; 96] = [const {
    Calls {
        key: AtomicU32::new(0),
        count: AtomicU64::new(0),
        held: AtomicU64::new(0),
        longest: AtomicU64::new(0),
        waited: AtomicU64::new(0),
        unmapped: AtomicU64::new(0),
        posted: AtomicU64::new(0),
        posted_waited: AtomicU64::new(0),
    }
}; 96];

/// Counts a call the gate served: the PE that rang runs no guest code until
/// it returns, so a call that holds the service long is guest time lost.
fn served(served: Served) {
    // The PE ran nothing but this call since the last one it served.
    let (posted, posted_waited) = client::take_mine();
    let key = served.operation.wrapping_add(1);
    // Slots fill in order and stay claimed: the first that is free or
    // already this operation's is its own.
    let Some(calls) = CALLS.iter().find(|calls| {
        match calls
            .key
            .compare_exchange(0, key, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => true,
            Err(claimed) => claimed == key,
        }
    }) else {
        return;
    };
    calls.count.fetch_add(1, Ordering::Relaxed);
    calls.held.fetch_add(served.held, Ordering::Relaxed);
    calls.longest.fetch_max(served.held, Ordering::Relaxed);
    calls.waited.fetch_add(served.waited, Ordering::Relaxed);
    if served.status == Status::Unmapped {
        calls.unmapped.fetch_add(1, Ordering::Relaxed);
    }
    calls.posted.fetch_add(posted, Ordering::Relaxed);
    calls
        .posted_waited
        .fetch_add(posted_waited, Ordering::Relaxed);
}

/// The operations whose calls held the service longest since the last
/// report: each as count/held/longest/waited/unmapped/posted/posted_waited,
/// microseconds between.
pub(in crate::engine) fn report_calls(tsc_hz: u64) {
    const SHOWN: usize = 8;
    let micros = |ticks: u64| u128::from(ticks) * 1_000_000 / u128::from(tsc_hz.max(1));
    let mut taken: Vec<_> = CALLS
        .iter()
        .filter_map(|calls| {
            let key = calls.key.load(Ordering::Relaxed);
            let count = calls.count.swap(0, Ordering::Relaxed);
            (key != 0 && count != 0).then(|| {
                (
                    key - 1,
                    count,
                    calls.held.swap(0, Ordering::Relaxed),
                    calls.longest.swap(0, Ordering::Relaxed),
                    calls.waited.swap(0, Ordering::Relaxed),
                    calls.unmapped.swap(0, Ordering::Relaxed),
                    calls.posted.swap(0, Ordering::Relaxed),
                    calls.posted_waited.swap(0, Ordering::Relaxed),
                )
            })
        })
        .collect();
    let posted = client::take_posted();
    if taken.is_empty() && posted.is_empty() {
        return;
    }
    taken.sort_unstable_by_key(|&(_, _, held, ..)| core::cmp::Reverse(held));
    let held: u64 = taken.iter().map(|&(_, _, held, ..)| held).sum();
    output::arguments(format_args!(
        "GPU CALLS held_us={} operation:count/held_us/longest_us/waited_us/unmapped/posted/posted_us",
        micros(held)
    ));
    for &(operation, count, held, longest, waited, unmapped, posted, posted_waited) in
        taken.iter().take(SHOWN)
    {
        output::arguments(format_args!(
            " {operation:#x}:{count}/{}/{}/{}/{unmapped}/{posted}/{}",
            micros(held),
            micros(longest),
            micros(waited),
            micros(posted_waited),
        ));
    }
    // The host's Linux work the calls asked the boot CPU for, by ioctl.
    let (shootdowns, shot) = crate::native_mmio::shootdown::take_waits();
    output::arguments(format_args!(
        "\nGPU POSTED shootdowns={shootdowns}/{}us request:count/waited_us",
        micros(shot)
    ));
    for &(request, count, waited) in posted.iter().take(SHOWN) {
        output::arguments(format_args!(" {request:#x}:{count}/{}", micros(waited)));
    }
    // What performing them took the service task, waits for the GPU included.
    output::arguments(format_args!("\nGPU SERVED request:count/us"));
    for &(request, count, took) in client::take_served().iter().take(SHOWN) {
        output::arguments(format_args!(" {request:#x}:{count}/{}", micros(took)));
    }
    output::arguments(format_args!("\n"));
}

/// NVK's entry point, as Vulkan types it.
unsafe extern "system" fn entry(
    instance: vk::Instance,
    name: *const c_char,
) -> vk::PFN_vkVoidFunction {
    use vk::Handle;
    // SAFETY: the loader's call, and both ends are one function pointer.
    unsafe {
        core::mem::transmute(stela_mesa::vk_icdGetInstanceProcAddr(
            instance.as_raw() as *mut c_void,
            name,
        ))
    }
}

/// The host pages behind whole pages of guest RAM.
fn guest_pages(ranges: &[MemoryRange]) -> Result<Vec<Run>, Error> {
    const NOT_RAM: Error = Error::Invalid("imported memory is whole pages of guest RAM");
    let mut runs: Vec<Run> = Vec::new();
    for range in ranges {
        if !(range.address | range.bytes).is_multiple_of(PAGE) {
            return Err(NOT_RAM);
        }
        let whole = host::guest_runs(range.address, range.bytes, |physical, bytes| {
            match runs.last_mut() {
                Some(last) if last.physical + last.bytes == physical => last.bytes += bytes,
                _ => runs.push(Run { physical, bytes }),
            }
        });
        if !whole {
            return Err(NOT_RAM);
        }
    }
    Ok(runs)
}

/// Guest RAM the kext wired, for NVK to import. The GPU reaches it through
/// the host pages behind it.
struct Exporter;

impl MemoryExporter for Exporter {
    fn export(&self, ranges: &[MemoryRange]) -> Result<ExportedMemory, Error> {
        let runs = guest_pages(ranges)?;
        let (fd, pointer) = client::export(&runs).ok_or(Error::OutOfMemory)?;
        let bytes = runs.iter().map(|run| run.bytes).sum();
        Ok(ExportedMemory { fd, pointer, bytes })
    }

    fn close(&self, exported: ExportedMemory) {
        client::close_descriptor(exported.fd);
        self.unmap(exported);
    }

    fn unmap(&self, exported: ExportedMemory) {
        client::unmap_export(exported.pointer.as_ptr() as u64, exported.bytes);
    }
}

fn service(gpu: &Gpu, stack: u64) -> Result<Arc<Shared>, OpenError> {
    let compiler = |physical| {
        // SAFETY: NVK's own physical device, whose options last as long.
        let options = unsafe { stela_nvk_nir_options(physical) };
        compiler::Service::linked(NonNull::new(options.cast_mut()).expect("NVK has NIR options"))
    };
    let loader = Loader {
        get_instance_proc_addr: entry,
    };
    // SAFETY: the linked NVK and compiler, which last for the boot.
    let service = unsafe {
        open(
            loader,
            Box::new(Exporter),
            compiler,
            gpu,
            DeviceEpoch::from_registered(NonZeroU64::MIN),
        )
    }?;
    let gpu = *gpu;
    // A lost device's channels are gone, so the next client gets a new one,
    // opened on the service's stack as the first was.
    // SAFETY: as above.
    let service = service.with_reopen(Box::new(move || unsafe {
        reopen(loader, Box::new(Exporter), compiler, &gpu)
    }));
    Ok(Arc::new(SharedService::new(
        service,
        ServiceHost {
            relax,
            stack,
            run,
            report,
            note,
            ticks: host::rdtsc,
            served,
        },
    )))
}

/// Open a service over every bound GPU. What stops one is reported, and the
/// Mac boots without Metal on that GPU.
pub(in crate::engine) fn open_service() {
    let Some(gpu) = installed() else {
        return;
    };
    let mut constructed = false;
    let services: Vec<_> = gpu
        .start
        .bound
        .iter()
        .enumerate()
        .filter_map(|(index, bound)| open_gpu(gpu, index, bound, &mut constructed))
        .collect();
    SERVICES.store(Box::into_raw(Box::new(services)), Ordering::Release);
}

/// Runs the image's C constructors once, on the stack of whoever opens first.
fn construct(constructed: &mut bool) {
    if !core::mem::replace(constructed, true) {
        // SAFETY: the one call, before any other of the C's.
        unsafe { stela_mesa::stela_constructors() };
    }
}

/// The service of `bound`, at DRM minor `index`, whose failure is reported.
fn open_gpu(
    gpu: &Installed,
    index: usize,
    bound: &Bound,
    constructed: &mut bool,
) -> Option<Arc<Shared>> {
    let refuse = |reason: &str| {
        crate::output::arguments(format_args!("GPU {}: {reason}\n", bound.name));
        None
    };
    let Some(link) = bound.link else {
        return refuse("no PCIe link");
    };
    let Some(chipset) = client::chipset(index as u32) else {
        return refuse("no chipset reported");
    };
    let Some(stack) = Stack::map(gpu.window, STACK_BYTES) else {
        return refuse("no memory for its service");
    };
    let top = stack.top();
    // It serves for the boot.
    core::mem::forget(stack);
    let target = Gpu {
        pci: PciBusInfo {
            domain: bound.drm.segment.into(),
            bus: bound.drm.bus.into(),
            device: bound.drm.slot.into(),
            function: bound.drm.function.into(),
        },
        chipset,
        // A GPU in a Thunderbolt enclosure reaches Stela as the function
        // firmware enumerated, like any other in a slot.
        attachment: Attachment {
            link,
            external: false,
            location_number: index as u64,
        },
    };
    let mut opened = None;
    run(top, &mut || {
        construct(constructed);
        opened = Some(service(&target, top));
    });
    match opened? {
        Ok(service) => Some(service),
        Err(error) => refuse(&format!("Metal could not open: {error:?}")),
    }
}

pub(super) fn shared() -> &'static [Arc<Shared>] {
    // SAFETY: the published services are leaked, so they live for the boot.
    unsafe { SERVICES.load(Ordering::Acquire).as_ref() }.map_or(&[], Vec::as_slice)
}

/// Tell the services a GPU interrupted: its MSI says nothing of which.
pub(super) fn interrupted() {
    shared().iter().for_each(|service| service.interrupted());
}

/// Bring every GPU to rest before the PC resets or turns off, on the boot CPU
/// outside Linux's callbacks. Admission closes for good and accepted work
/// finishes; `close_gates` then releases what the guest held of each GPU that
/// proved idle, answering the imports still in reach. Whatever could not be
/// proven stays alive and is reported: the transition itself ends the DMA.
pub(in crate::engine) fn stop(close_gates: impl FnOnce() -> u64) {
    let Some(gpu) = installed() else {
        return;
    };
    let services = shared();
    services.iter().for_each(|service| service.begin_quiesce());
    for (index, service) in services.iter().enumerate() {
        let status = settle(service, gpu.tsc_hz);
        output::arguments(format_args!("GPU {index} at the stop: {status:?}\n"));
    }
    let reachable = close_gates();
    let quarantine = dma_quarantine_status();
    output::arguments(format_args!(
        "GPU stopped: {reachable} imports in reach, {} DMA mappings of {} bytes and {} functions quarantined\n",
        quarantine.mappings,
        quarantine.bytes,
        quarantined_functions(),
    ));
    if client::shutdown(STOP_UNLOAD_SECONDS) {
        output::arguments(format_args!("GPU drivers stopped\n"));
    } else {
        output::arguments(format_args!(
            "GPU drivers still stopping after {STOP_UNLOAD_SECONDS} s\n"
        ));
    }
}

/// Unload the GPUs' firmware before a fatal stop ends the machine: the reset
/// that follows takes down the link of a card whose GSP still runs, until a
/// power cycle. The Linux environment that unloads it runs on the boot CPU,
/// so a stop raised there leaves the firmware running and says so. Once.
pub(in crate::engine) fn stop_for_fatal() {
    static STOPPING: AtomicBool = AtomicBool::new(false);
    if installed().is_none() || STOPPING.swap(true, Ordering::AcqRel) {
        return;
    }
    if host::processor() == BOOT_CPU.load(Ordering::Relaxed) {
        output::arguments(format_args!(
            "GPU firmware left running: the stop is on the CPU that unloads it\n"
        ));
    } else if client::shutdown_for_fatal(STOP_UNLOAD_SECONDS) {
        output::arguments(format_args!("GPU drivers stopped before the fatal stop\n"));
    } else {
        output::arguments(format_args!(
            "GPU drivers still stopping after {STOP_UNLOAD_SECONDS} s; the firmware may still run\n"
        ));
    }
}

/// Step `service` until accepted work ends or stops moving.
fn settle(service: &Shared, tsc_hz: u64) -> QuiesceStatus {
    let (mut last, mut moved) = (None, host::rdtsc());
    loop {
        let status = service.quiesce_step();
        let QuiesceStatus::Pending { completed, .. } = status else {
            return status;
        };
        if last != Some(completed) {
            (last, moved) = (Some(completed), host::rdtsc());
        } else if host::rdtsc() - moved >= STOP_STALL_SECONDS * tsc_hz {
            return status;
        }
        relax();
    }
}

/// Add each service's gate node to `tree`, for what the board mounts there.
pub(in crate::engine) fn place(
    tree: &mut DeviceTree,
) -> Vec<(stela_gpu::Placement, Arc<dyn GateService>)> {
    let mut gates = Vec::new();
    for (index, service) in shared().iter().enumerate() {
        match stela_gpu::place_gpu_gate(tree, index, window::BYTES) {
            Ok(placement) => gates.push((placement, service.clone() as Arc<dyn GateService>)),
            Err(error) => {
                crate::status::warn(&format!("GPU {index}'s gate has no place: {error}"));
            }
        }
    }
    gates
}
