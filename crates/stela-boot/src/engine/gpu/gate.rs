//! The Metal service over NVK, which the guest reaches through StelaGPU's gate,
//! or over lavapipe on a PC with no NVIDIA GPU.
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
    sync::atomic::{AtomicPtr, AtomicU64, Ordering},
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
        native::{ExportedMemory, Import, Loader, MemoryExporter, NativeBackend, vk},
        nvidia::{
            Attachment,
            open::{Gpu, OpenError, open},
        },
        service::{ServiceHost, SharedService, identity::DeviceEpoch},
        software,
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

/// The services for the kernel's interrupts, once all are open.
static SERVICES: AtomicPtr<Vec<Arc<Shared>>> = AtomicPtr::new(ptr::null_mut());

unsafe extern "C" {
    fn stela_nvk_nir_options(physical: vk::PhysicalDevice) -> *const c_void;
    fn stela_lvp_nir_options(physical: vk::PhysicalDevice) -> *const c_void;
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

/// Logs why the service refused a guest's call, once for each reason.
fn report(reason: &str) {
    static SEEN: [AtomicU64; 128] = [const { AtomicU64::new(0) }; 128];
    // FNV-1a: a reason is built per refusal, so only its text identifies it.
    let text = reason.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
    });
    for slot in &SEEN {
        match slot.compare_exchange(0, text, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(seen) if seen == text => return,
            Err(_) => {}
        }
    }
    output::arguments(format_args!("GPU REFUSED {reason}\n"));
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

/// lavapipe's entry point, as Vulkan types it.
unsafe extern "system" fn software_entry(
    instance: vk::Instance,
    name: *const c_char,
) -> vk::PFN_vkVoidFunction {
    use vk::Handle;
    // SAFETY: the loader's call, and both ends are one function pointer.
    unsafe {
        core::mem::transmute(stela_mesa::lvp_vk_icdGetInstanceProcAddr(
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
    fn import(&self) -> Import {
        Import::DmaBuf
    }

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

/// llvmpipe blends whole 4x4 blocks, so it touches up to three rows past a
/// render target's last: three of the widest texture's, at 16 bytes a texel. It
/// pads textures of its own, and a texture ending a guest buffer gets these.
const SOFTWARE_TAIL_PAGES: u64 = 3 * 16384 * 16 / PAGE;

/// Guest RAM the kext wired, for lavapipe to reach through one mapping.
struct SoftwareExporter;

impl MemoryExporter for SoftwareExporter {
    fn import(&self) -> Import {
        Import::HostPointer
    }

    fn export(&self, ranges: &[MemoryRange]) -> Result<ExportedMemory, Error> {
        let runs = guest_pages(ranges)?;
        let scratch = stack::scratch_page().ok_or(Error::OutOfMemory)?;
        let pointer =
            client::map_runs(&runs, SOFTWARE_TAIL_PAGES, scratch).ok_or(Error::OutOfMemory)?;
        let bytes = runs.iter().map(|run| run.bytes).sum();
        Ok(ExportedMemory {
            fd: -1,
            pointer,
            bytes,
        })
    }

    fn close(&self, exported: ExportedMemory) {
        self.unmap(exported);
    }

    fn unmap(&self, exported: ExportedMemory) {
        let bytes = exported.bytes + SOFTWARE_TAIL_PAGES * PAGE;
        client::unmap_export(exported.pointer.as_ptr() as u64, bytes);
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
    Ok(Arc::new(SharedService::new(
        service,
        ServiceHost {
            relax,
            stack,
            run,
            report,
        },
    )))
}

/// Open a service over every bound GPU. What stops one is reported, and the
/// Mac boots without Metal on that GPU. A PC with none to bind draws in software.
pub(in crate::engine) fn open_service() {
    let Some(gpu) = installed() else {
        return;
    };
    let mut constructed = false;
    let services: Vec<_> = if gpu.start.bound.is_empty() {
        open_software(gpu, &mut constructed).into_iter().collect()
    } else {
        gpu.start
            .bound
            .iter()
            .enumerate()
            .filter_map(|(index, bound)| open_gpu(gpu, index, bound, &mut constructed))
            .collect()
    };
    SERVICES.store(Box::into_raw(Box::new(services)), Ordering::Release);
}

/// The service over lavapipe, whose failure is reported.
fn open_software(gpu: &Installed, constructed: &mut bool) -> Option<Arc<Shared>> {
    let stack = Stack::map(gpu.window, STACK_BYTES)?;
    let top = stack.top();
    // It serves for the boot.
    core::mem::forget(stack);
    let compiler = |physical| {
        // SAFETY: lavapipe's own physical device, whose options last as long.
        let options = unsafe { stela_lvp_nir_options(physical) };
        compiler::Service::linked(
            NonNull::new(options.cast_mut()).expect("lavapipe has NIR options"),
        )
    };
    let mut opened = None;
    run(top, &mut || {
        construct(constructed);
        let loader = Loader {
            get_instance_proc_addr: software_entry,
        };
        // SAFETY: the linked lavapipe and compiler, which last for the boot.
        opened = Some(unsafe {
            software::open(
                loader,
                Box::new(SoftwareExporter),
                compiler,
                DeviceEpoch::from_registered(NonZeroU64::MIN),
            )
        });
    });
    match opened? {
        Ok(service) => Some(Arc::new(SharedService::new(
            service,
            ServiceHost {
                relax,
                stack: top,
                run,
                report,
            },
        ))),
        Err(error) => {
            crate::status::warn(&format!("Metal could not open in software: {error:?}"));
            None
        }
    }
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
        crate::status::warn(&format!("GPU {}: {reason}", bound.name));
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
