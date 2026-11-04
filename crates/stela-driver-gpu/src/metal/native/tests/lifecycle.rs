//! Driver acknowledgements required before releasing possibly queued objects.
use super::super::*;
use crate::metal::nvidia::{Chip, fixture::nvk};
use alloc::sync::Arc;
use core::{
    ffi::c_void,
    sync::atomic::{AtomicUsize, Ordering},
};
use vk::Handle;

struct Calls {
    result: vk::Result,
    waits: AtomicUsize,
    frees: AtomicUsize,
}

unsafe extern "system" fn wait_queue(queue: vk::Queue) -> vk::Result {
    // SAFETY: tests encode their kept Calls allocation in the queue handle.
    let calls = unsafe { &*(queue.as_raw() as *const Calls) };
    calls.waits.fetch_add(1, Ordering::Relaxed);
    calls.result
}

unsafe extern "system" fn wait_device(device: vk::Device) -> vk::Result {
    // SAFETY: tests encode their kept Calls allocation in the device handle.
    let calls = unsafe { &*(device.as_raw() as *const Calls) };
    calls.waits.fetch_add(1, Ordering::Relaxed);
    calls.result
}

unsafe extern "system" fn free_buffers(
    device: vk::Device,
    _: vk::CommandPool,
    count: u32,
    _: *const vk::CommandBuffer,
) {
    // SAFETY: as in wait_device; the callback never dereferences fake buffers.
    let calls = unsafe { &*(device.as_raw() as *const Calls) };
    assert_eq!(calls.waits.load(Ordering::Relaxed), 1);
    calls.frees.fetch_add(count as usize, Ordering::Relaxed);
}

fn device(calls: &Calls) -> ash::Device {
    // SAFETY: only the typed callbacks above are invoked; Calls outlives it.
    unsafe {
        ash::Device::load_with(
            |name| match name.to_bytes() {
                b"vkQueueWaitIdle" => wait_queue as *const c_void,
                b"vkDeviceWaitIdle" => wait_device as *const c_void,
                b"vkFreeCommandBuffers" => free_buffers as *const c_void,
                _ => core::ptr::null(),
            },
            vk::Device::from_raw(calls as *const Calls as u64),
        )
    }
}

#[test]
fn failed_idle_keeps_possibly_submitted_command_buffers() {
    for (result, freed) in [
        (vk::Result::SUCCESS, 2),
        (vk::Result::ERROR_DEVICE_LOST, 0),
        (vk::Result::ERROR_OUT_OF_HOST_MEMORY, 0),
    ] {
        let calls = Calls {
            result,
            waits: AtomicUsize::new(0),
            frees: AtomicUsize::new(0),
        };
        let device = device(&calls);
        let queue = vk::Queue::from_raw(&calls as *const Calls as u64);
        let buffers = [
            vk::CommandBuffer::from_raw(1),
            vk::CommandBuffer::from_raw(2),
        ];
        let outcome = free_after_idle(&device, queue, vk::CommandPool::null(), &buffers);
        assert_eq!(outcome.is_ok(), result == vk::Result::SUCCESS);
        assert_eq!(calls.waits.load(Ordering::Relaxed), 1);
        assert_eq!(calls.frees.load(Ordering::Relaxed), freed);
    }
}

struct Exporter(Arc<AtomicUsize>);

impl Drop for Exporter {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

impl MemoryExporter for Exporter {
    fn import(&self) -> Import {
        Import::DmaBuf
    }
    fn export(&self, _: &[MemoryRange]) -> Result<ExportedMemory> {
        unreachable!()
    }
    fn close(&self, _: ExportedMemory) {
        unreachable!()
    }
    fn unmap(&self, _: ExportedMemory) {
        unreachable!()
    }
}

unsafe extern "system" fn instance_proc(
    _: vk::Instance,
    _: *const core::ffi::c_char,
) -> vk::PFN_vkVoidFunction {
    None
}

unsafe extern "system" fn device_proc(
    _: vk::Device,
    _: *const core::ffi::c_char,
) -> vk::PFN_vkVoidFunction {
    None
}

fn backend(calls: &Calls, drops: &Arc<AtomicUsize>) -> NativeBackend {
    // SAFETY: these tables have no GPU; only wait_device runs during Drop.
    // Missing destruction callbacks fail the test if Drop tries to free state.
    let (entry, instance) = unsafe {
        (
            ash::Entry::from_static_fn(ash::StaticFn {
                get_instance_proc_addr: instance_proc,
            }),
            ash::Instance::load_with(
                |name| {
                    if name.to_bytes() == b"vkGetDeviceProcAddr" {
                        device_proc as *const c_void
                    } else {
                        core::ptr::null()
                    }
                },
                vk::Instance::null(),
            ),
        )
    };
    let device = device(calls);
    let conditional = ext::conditional_rendering::Device::new(&instance, &device);
    NativeBackend {
        _entry: ManuallyDrop::new(entry),
        instance,
        device,
        fns: ExtensionFns {
            host_image_copy: None,
            dynamic_state3: None,
            sample_locations: None,
            depth_bias: None,
            mesh: None,
            calibrated: None,
            external_memory_fd: None,
            external_memory_host: None,
            conditional,
            generated: None,
        },
        queue: vk::Queue::null(),
        snapshot: nvk(Chip::find(0x1b3).unwrap(), 16 << 30),
        heap: Heap {
            layout: vk::DescriptorSetLayout::null(),
            pool: vk::DescriptorPool::null(),
            set: vk::DescriptorSet::null(),
        },
        null_sampler: vk::Sampler::null(),
        layout: vk::PipelineLayout::null(),
        command_pool: vk::CommandPool::null(),
        in_flight: VecDeque::new(),
        mappings: BTreeMap::new(),
        exporter: ManuallyDrop::new(Box::new(Exporter(drops.clone()))),
        imports: BTreeMap::new(),
        retired: VecDeque::new(),
        new_images: Vec::new(),
        bind_timeline: vk::Semaphore::null(),
        bind_value: 0,
        accumulate: vk::Pipeline::null(),
        select: vk::Pipeline::null(),
        resolve_draws: vk::Pipeline::null(),
        resolve_dispatches: vk::Pipeline::null(),
    }
}

#[test]
fn failed_device_idle_keeps_the_export_owner() {
    let calls = Calls {
        result: vk::Result::ERROR_DEVICE_LOST,
        waits: AtomicUsize::new(0),
        frees: AtomicUsize::new(0),
    };
    let drops = Arc::new(AtomicUsize::new(0));
    let backend = backend(&calls, &drops);
    drop(backend);
    assert_eq!(calls.waits.load(Ordering::Relaxed), 1);
    assert_eq!(calls.frees.load(Ordering::Relaxed), 0);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
}

#[test]
fn idle_acknowledgement_requires_native_success_and_keeps_roots_owned() {
    for (result, expected) in [
        (vk::Result::SUCCESS, Ok(())),
        (vk::Result::ERROR_DEVICE_LOST, Err(Error::DeviceLost)),
        (
            vk::Result::ERROR_OUT_OF_HOST_MEMORY,
            Err(Error::OutOfMemory),
        ),
    ] {
        let calls = Calls {
            result,
            waits: AtomicUsize::new(0),
            frees: AtomicUsize::new(0),
        };
        let drops = Arc::new(AtomicUsize::new(0));
        let mut backend = ManuallyDrop::new(backend(&calls, &drops));
        assert_eq!(backend.acknowledge_idle(), expected);
        assert_eq!(calls.waits.load(Ordering::Relaxed), 1);
        assert_eq!(calls.frees.load(Ordering::Relaxed), 0);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        // SAFETY: this fixture has no native GPU resources. Its two owned
        // Rust roots are dropped once without invoking fake Vulkan teardown.
        unsafe {
            ManuallyDrop::drop(&mut backend.exporter);
            ManuallyDrop::drop(&mut backend._entry);
        }
    }
}
