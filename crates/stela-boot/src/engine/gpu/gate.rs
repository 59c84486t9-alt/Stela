//! The Metal service over NVK, which the guest reaches through StelaGPU's gate.
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
use crate::engine::host;
use alloc::{boxed::Box, format, sync::Arc, vec::Vec};
use core::{
    ffi::{c_char, c_void},
    hint,
    num::NonZeroU64,
    ptr::{self, NonNull},
    sync::atomic::{AtomicPtr, Ordering},
};
use stela_contracts::gate::{GateService, MemoryRange, window};
use stela_drivers::gpu::{
    linux::client::Run,
    metal::{
        compiler::{self, AirCompiler},
        error::Error,
        native::{ExportedMemory, Loader, MemoryExporter, NativeBackend, vk},
        nvidia::{
            Attachment,
            open::{Gpu, OpenError, open},
        },
        service::{ServiceHost, SharedService, identity::DeviceEpoch},
        vulkan::physical::PciBusInfo,
    },
};
use stela_loader::{apple_device_tree::DeviceTree, stela_gpu};

type Shared = SharedService<NativeBackend, AirCompiler>;

/// A process's main stack, as big as the deepest compile LLVM bounds.
const STACK_BYTES: usize = 16 << 20;

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
    if host::processor() == BOOT_CPU.load(Ordering::Relaxed) {
        pump();
    }
    hint::spin_loop();
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

/// Guest RAM the kext wired, for NVK to import. The GPU reaches it through
/// the host pages behind it.
struct Exporter;

impl MemoryExporter for Exporter {
    fn export(&self, ranges: &[MemoryRange]) -> Result<ExportedMemory, Error> {
        const NOT_RAM: Error = Error::Invalid("imported memory is whole pages of guest RAM");
        let mut runs: Vec<Run> = Vec::new();
        for range in ranges {
            if !(range.address | range.bytes).is_multiple_of(PAGE) {
                return Err(NOT_RAM);
            }
            let whole = host::guest_runs(range.address, range.bytes, |physical, bytes| match runs
                .last_mut()
            {
                Some(last) if last.physical + last.bytes == physical => last.bytes += bytes,
                _ => runs.push(Run { physical, bytes }),
            });
            if !whole {
                return Err(NOT_RAM);
            }
        }
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
    Ok(Arc::new(SharedService::new(
        service,
        ServiceHost { relax, stack, run },
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
        if !core::mem::replace(constructed, true) {
            // SAFETY: the one call, before any other of the C's.
            unsafe { stela_mesa::stela_constructors() };
        }
        opened = Some(service(&target, top));
    });
    match opened? {
        Ok(service) => Some(service),
        Err(error) => refuse(&format!("Metal could not open: {error:?}")),
    }
}

fn shared() -> &'static [Arc<Shared>] {
    // SAFETY: the published services are leaked, so they live for the boot.
    unsafe { SERVICES.load(Ordering::Acquire).as_ref() }.map_or(&[], Vec::as_slice)
}

/// Tell the services a GPU interrupted: its MSI says nothing of which.
pub(super) fn interrupted() {
    shared().iter().for_each(|service| service.interrupted());
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
