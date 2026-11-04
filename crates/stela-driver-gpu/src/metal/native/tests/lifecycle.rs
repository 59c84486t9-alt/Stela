//! Driver acknowledgements required before releasing possibly queued objects.
use super::super::*;
use crate::metal::nvidia::{Chip, fixture::nvk};
use alloc::sync::Arc;
use core::{
    cell::Cell,
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

fn backend(device: ash::Device, drops: &Arc<AtomicUsize>) -> NativeBackend {
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
    let backend = backend(device(&calls), &drops);
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
        let mut backend = ManuallyDrop::new(backend(device(&calls), &drops));
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

struct BufferCalls {
    status: Cell<vk::Result>,
    value: Cell<u64>,
    allocated: Cell<u64>,
    freed: Cell<Option<(u32, u64)>>,
}

unsafe extern "system" fn allocate(
    device: vk::Device,
    info: *const vk::CommandBufferAllocateInfo<'_>,
    output: *mut vk::CommandBuffer,
) -> vk::Result {
    // SAFETY: the fixture owns the kept BufferCalls and Vulkan arguments.
    let (calls, info) = unsafe { (&*(device.as_raw() as *const BufferCalls), &*info) };
    assert!(info.level == vk::CommandBufferLevel::PRIMARY);
    assert_eq!(info.command_pool.as_raw(), 2);
    if calls.status.get() == vk::Result::SUCCESS {
        for index in 0..info.command_buffer_count {
            let next = calls.allocated.get() + 1;
            // SAFETY: the caller provides one writable handle per requested buffer.
            unsafe {
                output
                    .add(index as usize)
                    .write(vk::CommandBuffer::from_raw(next))
            };
            calls.allocated.set(next);
        }
    }
    calls.status.get()
}

unsafe extern "system" fn counter(
    device: vk::Device,
    _: vk::Semaphore,
    value: *mut u64,
) -> vk::Result {
    // SAFETY: the fixture owns the kept BufferCalls.
    let calls = unsafe { &*(device.as_raw() as *const BufferCalls) };
    // SAFETY: the caller provides a writable counter.
    unsafe { value.write(calls.value.get()) };
    calls.status.get()
}

unsafe extern "system" fn free_completed(
    device: vk::Device,
    pool: vk::CommandPool,
    count: u32,
    buffers: *const vk::CommandBuffer,
) {
    // SAFETY: the fixture owns the kept BufferCalls and submitted handle array.
    let (calls, buffers) = unsafe {
        (
            &*(device.as_raw() as *const BufferCalls),
            core::slice::from_raw_parts(buffers, count as usize),
        )
    };
    assert_eq!(pool.as_raw(), 2);
    let ordered = buffers
        .iter()
        .fold(0, |sum, buffer| sum * 10 + buffer.as_raw());
    assert!(calls.freed.replace(Some((count, ordered))).is_none());
}

#[test]
fn inline_and_owned_buffers_retire_once_in_queue_order() {
    let calls = BufferCalls {
        status: Cell::new(vk::Result::SUCCESS),
        value: Cell::new(0),
        allocated: Cell::new(0),
        freed: Cell::new(None),
    };
    // SAFETY: only these typed test callbacks are invoked and Calls stays live.
    let device = unsafe {
        ash::Device::load_with(
            |name| match name.to_bytes() {
                b"vkAllocateCommandBuffers" => allocate as *const c_void,
                b"vkGetSemaphoreCounterValue" => counter as *const c_void,
                b"vkFreeCommandBuffers" => free_completed as *const c_void,
                _ => core::ptr::null(),
            },
            vk::Device::from_raw(&calls as *const BufferCalls as u64),
        )
    };
    let drops = Arc::new(AtomicUsize::new(0));
    let mut backend = ManuallyDrop::new(backend(device, &drops));
    backend.command_pool = vk::CommandPool::from_raw(2);
    for (value, count) in [(1, 1), (2, 1), (3, 2), (4, 1)] {
        let buffers =
            CommandBuffers::allocate(&backend.device, backend.command_pool, count).unwrap();
        assert_eq!(buffers.as_slice().len(), count as usize);
        backend.in_flight.push_back(InFlight {
            buffers,
            timeline: vk::Semaphore::from_raw(7),
            value,
        });
    }
    calls.status.set(vk::Result::ERROR_DEVICE_LOST);
    for count in [1, 2] {
        assert!(matches!(
            CommandBuffers::allocate(&backend.device, backend.command_pool, count),
            Err(Error::DeviceLost),
        ));
    }
    assert_eq!(backend.reclaim(), Err(Error::DeviceLost));
    assert_eq!(backend.in_flight.len(), 4);
    assert_eq!(calls.allocated.get(), 5);
    assert_eq!(calls.freed.get(), None);

    calls.status.set(vk::Result::SUCCESS);
    backend.reclaim().unwrap();
    assert_eq!(calls.freed.get(), None);
    for (value, freed, remaining) in [(1, (1, 1), 3), (3, (3, 234), 1), (4, (1, 5), 0)] {
        calls.value.set(value);
        backend.reclaim().unwrap();
        assert_eq!(calls.freed.replace(None), Some(freed));
        assert_eq!(backend.in_flight.len(), remaining);
    }
    // SAFETY: the fixture has no Vulkan resources and the list is empty.
    unsafe { ManuallyDrop::drop(&mut backend.exporter) };
}
