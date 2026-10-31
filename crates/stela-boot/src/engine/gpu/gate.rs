//! The Metal service over NVK, which the guest reaches through StelaGPU's gate.
//!
//! It opens on the boot CPU once nouveau has bound the GPUs, before the guest's
//! DeviceTree is final, so the tree has a gate only with a device behind it.
//! The tree has one gate, so Metal gets the first GPU; the rest stay Linux's.
//!
//! The service runs on a stack of its own, deep enough for a compile. Its lock
//! means one is enough; opening comes before any caller.
use super::{
    BOOT_CPU, PAGE, client, installed, pump,
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

/// The service for the kernel's interrupts, once it is open.
static SERVICE: AtomicPtr<Shared> = AtomicPtr::new(ptr::null_mut());
/// The end of the service's stack.
static STACK: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    fn stela_nvk_nir_options(physical: vk::PhysicalDevice) -> *const c_void;
}

fn run(body: &mut dyn FnMut()) {
    // SAFETY: the stack lives for the boot, and only the opener or a turn's
    // holder is here.
    unsafe { stack::on_stack(STACK.load(Ordering::Relaxed), body) };
}

fn relax() {
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

fn service(gpu: &Gpu) -> Result<Arc<Shared>, OpenError> {
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
        ServiceHost { relax, run },
    )))
}

/// Open the service over the first bound GPU. What stops it is reported, and
/// the Mac boots without Metal.
pub(in crate::engine) fn open_service() {
    let Some(gpu) = installed() else {
        return;
    };
    let Some(first) = gpu.start.bound.first() else {
        return;
    };
    for other in &gpu.start.bound[1..] {
        output::arguments(format_args!(
            "GPU {}: Metal has the first GPU only\n",
            other.name
        ));
    }
    let Some(link) = first.link else {
        return crate::status::warn(&format!("GPU {} has no PCIe link", first.name));
    };
    let Some(chipset) = client::chipset(0) else {
        return crate::status::warn(&format!("GPU {} reports no chipset", first.name));
    };
    let Some(stack) = Stack::map(gpu.window, STACK_BYTES) else {
        return crate::status::warn("no memory for the GPU's service");
    };
    STACK.store(stack.top(), Ordering::Relaxed);
    // It serves for the boot.
    core::mem::forget(stack);
    let target = Gpu {
        pci: PciBusInfo {
            domain: first.drm.segment.into(),
            bus: first.drm.bus.into(),
            device: first.drm.slot.into(),
            function: first.drm.function.into(),
        },
        chipset,
        // A GPU in a Thunderbolt enclosure reaches Stela as the function
        // firmware enumerated, like any other in a slot.
        attachment: Attachment {
            link,
            external: false,
            location_number: 0,
        },
    };
    let mut opened = None;
    run(&mut || {
        // SAFETY: the one call, before any other of the C's.
        unsafe { stela_mesa::stela_constructors() };
        opened = Some(service(&target));
    });
    match opened {
        Some(Ok(service)) => SERVICE.store(Arc::into_raw(service).cast_mut(), Ordering::Release),
        Some(Err(error)) => {
            crate::status::warn(&format!(
                "Metal could not open on {}: {error:?}",
                first.name
            ));
        }
        None => {}
    }
}

fn shared() -> Option<&'static Shared> {
    // SAFETY: a published service is leaked, so it lives for the boot.
    unsafe { SERVICE.load(Ordering::Acquire).as_ref() }
}

/// Tell the service the GPU interrupted.
pub(super) fn interrupted() {
    if let Some(service) = shared() {
        service.interrupted();
    }
}

/// Add the gate's node to `tree`, when there is a service behind it, for what
/// the board mounts there.
pub(in crate::engine) fn place(
    tree: &mut DeviceTree,
) -> Option<(stela_gpu::Placement, Arc<dyn GateService>)> {
    let service = NonNull::new(SERVICE.load(Ordering::Acquire))?;
    match stela_gpu::place_gpu_gate(tree, window::BYTES) {
        Ok(placement) => {
            // SAFETY: from `Arc::into_raw`, and the published count is kept.
            let service = unsafe {
                Arc::increment_strong_count(service.as_ptr());
                Arc::from_raw(service.as_ptr())
            };
            Some((placement, service))
        }
        Err(error) => {
            crate::status::warn(&format!("the GPU's gate has no place: {error}"));
            None
        }
    }
}
