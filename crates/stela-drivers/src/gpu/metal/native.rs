//! [`Backend`] over a Vulkan driver loaded in this process: NVK on NVIDIA,
//! or another Mesa driver the device admits.
//!
//! The platform supplies the driver's `vkGetInstanceProcAddr` and the PCI
//! function to drive. The backend creates one instance and one device with
//! the extensions in [`physical`] and the features the driver offers (less
//! robust access), takes one universal queue, and builds the bindless heap
//! and the single pipeline layout of the [binding ABI](super::binding).
//!
//! Handles cross the boundary as their raw Vulkan values. Shader code is
//! NIR, which pipelines pass in Mesa's `VkPipelineShaderStageNirCreateInfoMESA`
//! (as Mesa's own meta shaders do) without a module or SPIR-V. Images are moved to `VK_IMAGE_LAYOUT_GENERAL` once, on the host
//! when they allow host transfers and otherwise at the start of the next
//! submission, and stay there.
mod generated;
mod objects;
mod physical;
mod record;
mod sparse;
#[cfg(test)]
mod tests;

use super::{
    binding::{HEAP_SET, HeapLayout, NULL_DESCRIPTOR, PushConstants},
    command_buffer::Segment,
    error::{Error, Result, ensure},
    vulkan::{
        SampleCounts,
        backend::{Backend, BufferAllocation, Descriptor, Object, Requirements, requirements},
        command::BufferImageCopy,
        object::{
            Buffer, BufferInfo, BufferView, BufferViewInfo, ComputePipelineInfo, ExecutionSet,
            GraphicsPipelineInfo, Image, ImageInfo, ImageView, ImageViewInfo,
            IndirectCommandsLayout, IndirectCommandsLayoutInfo, Memory, MemoryRequest, Pipeline,
            QueryPool, QueryPoolInfo, Sampler, SamplerInfo, Semaphore, ShaderCode,
            SparseImageRequirements,
        },
        physical::{PciBusInfo, PhysicalDevice},
    },
};
use alloc::{collections::BTreeMap, vec::Vec};
use ash::{ext, khr, vk};
use core::ptr::NonNull;
use physical::{Extensions, FeatureChain};

/// The driver's loader entry point.
#[derive(Clone, Copy)]
pub struct Loader {
    pub get_instance_proc_addr: vk::PFN_vkGetInstanceProcAddr,
}

/// The backend's own kernels: the NIR of `stela_metal_accumulate_kernel`,
/// `stela_metal_select_kernel` and `stela_metal_resolve_kernel`
/// (`compiler/metal_abi.h`).
#[derive(Clone, Copy, Debug)]
pub struct InternalKernels {
    /// Sums query results per
    /// [`AccumulateArguments`](super::binding::AccumulateArguments), one
    /// thread per run in workgroups of `WORKGROUP_SIZE`.
    pub accumulate: ShaderCode,
    /// Flags commands of an execution range per
    /// [`SelectArguments`](super::binding::SelectArguments), one thread per
    /// command in workgroups of `WORKGROUP_SIZE`.
    pub select: ShaderCode,
    /// Resolves GPU-resident indirect commands per
    /// [`ResolveArguments`](super::binding::ResolveArguments), one thread
    /// per command in workgroups of `WORKGROUP_SIZE`.
    pub resolve: ShaderCode,
}

/// A host mapping of a `VkDeviceMemory`.
#[derive(Clone, Copy, Debug)]
struct Mapping {
    pointer: NonNull<u8>,
    size: u64,
    coherent: bool,
}

/// Command buffers of one submission, freed once the queue's timeline
/// passes `value`.
#[derive(Debug)]
struct InFlight {
    buffers: Vec<vk::CommandBuffer>,
    timeline: vk::Semaphore,
    value: u64,
}

/// The bindless descriptor heap: set 0 of every pipeline.
#[derive(Clone, Copy, Debug)]
struct Heap {
    layout: vk::DescriptorSetLayout,
    pool: vk::DescriptorPool,
    set: vk::DescriptorSet,
}

/// Device-level functions of the optional extensions.
struct ExtensionFns {
    host_image_copy: Option<ext::host_image_copy::Device>,
    dynamic_state3: Option<ext::extended_dynamic_state3::Device>,
    sample_locations: Option<ext::sample_locations::Device>,
    mesh: Option<ext::mesh_shader::Device>,
    calibrated: Option<khr::calibrated_timestamps::Device>,
    conditional: ext::conditional_rendering::Device,
    /// With the snapshot's `generated_commands` limits.
    generated: Option<generated::Fns>,
}

pub struct NativeBackend {
    _entry: ash::Entry,
    instance: ash::Instance,
    device: ash::Device,
    fns: ExtensionFns,
    queue: vk::Queue,
    snapshot: PhysicalDevice,
    heap: Heap,
    /// The sampler behind the samplers' null descriptor, which Vulkan's
    /// `nullDescriptor` does not cover.
    null_sampler: vk::Sampler,
    layout: vk::PipelineLayout,
    command_pool: vk::CommandPool,
    in_flight: Vec<InFlight>,
    mappings: BTreeMap<u64, Mapping>,
    /// Images still in `VK_IMAGE_LAYOUT_UNDEFINED`, with their aspects.
    new_images: Vec<(vk::Image, vk::ImageAspectFlags)>,
    /// Orders sparse binds between command buffers: before a segment's
    /// binds the queue signals an odd value, and the binds signal the next.
    bind_timeline: vk::Semaphore,
    bind_value: u64,
    accumulate: vk::Pipeline,
    select: vk::Pipeline,
    resolve: vk::Pipeline,
}

impl NativeBackend {
    /// The generated-commands entry points, which the Metal layer uses only
    /// with the snapshot's `generated_commands` limits.
    fn generated(&self) -> &generated::Fns {
        self.fns
            .generated
            .as_ref()
            .expect("generated commands without the extension")
    }
}

/// Maps a Vulkan failure to the Metal layer's.
fn failure(result: vk::Result) -> Error {
    match result {
        vk::Result::ERROR_DEVICE_LOST => Error::DeviceLost,
        vk::Result::ERROR_OUT_OF_HOST_MEMORY
        | vk::Result::ERROR_OUT_OF_DEVICE_MEMORY
        | vk::Result::ERROR_TOO_MANY_OBJECTS
        | vk::Result::ERROR_FRAGMENTED_POOL
        | vk::Result::ERROR_OUT_OF_POOL_MEMORY => Error::OutOfMemory,
        _ => Error::Unsupported("Vulkan device operation"),
    }
}

impl NativeBackend {
    /// Creates the instance and device for the GPU at `pci`.
    ///
    /// # Safety
    ///
    /// `loader.get_instance_proc_addr` is a Vulkan driver's entry point, and
    /// `kernels` hold shader modules the compiler made for that driver.
    pub unsafe fn new(loader: Loader, pci: PciBusInfo, kernels: InternalKernels) -> Result<Self> {
        let static_fn = ash::StaticFn {
            get_instance_proc_addr: loader.get_instance_proc_addr,
        };
        // SAFETY: the caller guarantees the entry point.
        let entry = unsafe { ash::Entry::from_static_fn(static_fn) };
        let application = vk::ApplicationInfo::default()
            .application_name(c"Stela Metal")
            .engine_name(c"Stela")
            .api_version(vk::API_VERSION_1_3);
        let info = vk::InstanceCreateInfo::default().application_info(&application);
        // SAFETY: the create info and its application info outlive the call.
        let instance = unsafe { entry.create_instance(&info, None) }.map_err(failure)?;
        // SAFETY: the instance was just created and nothing else uses it.
        let destroy_instance =
            |instance: &ash::Instance| unsafe { instance.destroy_instance(None) };
        let selected = Self::select(&instance, pci);
        let Some((physical, extensions, snapshot, family)) = selected else {
            destroy_instance(&instance);
            return Err(Error::Unsupported("Vulkan device at the GPU's PCI address"));
        };
        if let Some(missing) = requirements(&snapshot.features)
            .iter()
            .find(|requirement| !requirement.present)
        {
            destroy_instance(&instance);
            return Err(Error::Unsupported(missing.name));
        }

        let mut features = FeatureChain::new(&extensions, false);
        // SAFETY: `physical` came from this instance; the chain links only
        // structures of supported extensions.
        unsafe { instance.get_physical_device_features2(physical, &mut features.core) };
        features.for_enabling();
        let names = extensions.enabled();
        let priority = [1.0];
        let queues = [vk::DeviceQueueCreateInfo::default()
            .queue_family_index(family)
            .queue_priorities(&priority)];
        let mut info = vk::DeviceCreateInfo::default()
            .queue_create_infos(&queues)
            .enabled_extension_names(&names);
        info.p_next = core::ptr::addr_of!(features.core).cast();
        // SAFETY: every name and chained structure outlives the call.
        let device = match unsafe { instance.create_device(physical, &info, None) } {
            Ok(device) => device,
            Err(error) => {
                destroy_instance(&instance);
                return Err(failure(error));
            }
        };
        let has = |name| extensions.has(name);
        let fns = ExtensionFns {
            host_image_copy: has(ext::host_image_copy::NAME)
                .then(|| ext::host_image_copy::Device::new(&instance, &device)),
            dynamic_state3: has(ext::extended_dynamic_state3::NAME)
                .then(|| ext::extended_dynamic_state3::Device::new(&instance, &device)),
            sample_locations: has(ext::sample_locations::NAME)
                .then(|| ext::sample_locations::Device::new(&instance, &device)),
            mesh: has(ext::mesh_shader::NAME)
                .then(|| ext::mesh_shader::Device::new(&instance, &device)),
            calibrated: has(khr::calibrated_timestamps::NAME)
                .then(|| khr::calibrated_timestamps::Device::new(&instance, &device)),
            // A requirement: the device was refused without it.
            conditional: ext::conditional_rendering::Device::new(&instance, &device),
            generated: features
                .generated_commands()
                .then(|| generated::Fns::load(&instance, &device))
                .flatten(),
        };
        let mut snapshot = snapshot;
        if fns.generated.is_none() {
            snapshot.limits.generated_commands = None;
        }
        // SAFETY: the device was created with one queue in `family`.
        let queue = unsafe { device.get_device_queue(family, 0) };
        let mut backend = Self {
            _entry: entry,
            instance,
            device,
            fns,
            queue,
            snapshot,
            heap: Heap {
                layout: vk::DescriptorSetLayout::null(),
                pool: vk::DescriptorPool::null(),
                set: vk::DescriptorSet::null(),
            },
            null_sampler: vk::Sampler::null(),
            layout: vk::PipelineLayout::null(),
            command_pool: vk::CommandPool::null(),
            in_flight: Vec::new(),
            mappings: BTreeMap::new(),
            new_images: Vec::new(),
            bind_timeline: vk::Semaphore::null(),
            bind_value: 0,
            accumulate: vk::Pipeline::null(),
            select: vk::Pipeline::null(),
            resolve: vk::Pipeline::null(),
        };
        // Dropping a partly built backend destroys what was created.
        backend.create_layout(family)?;
        backend.bind_timeline = handle(backend.create_semaphore(0)?.0);
        let kernel = |code| ComputePipelineInfo {
            code,
            required_subgroup_size: 0,
            full_subgroups: false,
            indirect_bindable: false,
        };
        backend.accumulate = backend.create_compute(&kernel(kernels.accumulate))?;
        backend.select = backend.create_compute(&kernel(kernels.select))?;
        backend.resolve = backend.create_compute(&kernel(kernels.resolve))?;
        Ok(backend)
    }

    /// The device at `pci` with a universal queue family, its supported
    /// extensions, its snapshot and the family.
    fn select(
        instance: &ash::Instance,
        pci: PciBusInfo,
    ) -> Option<(vk::PhysicalDevice, Extensions, PhysicalDevice, u32)> {
        // SAFETY: the instance is valid.
        let devices = unsafe { instance.enumerate_physical_devices() }.ok()?;
        devices.into_iter().find_map(|physical| {
            // SAFETY: `physical` came from this instance.
            let available =
                unsafe { instance.enumerate_device_extension_properties(physical) }.ok()?;
            let extensions = Extensions::of(&available);
            let snapshot = physical::probe(instance, physical, &extensions)?;
            if snapshot.identity.pci_bus != Some(pci) {
                return None;
            }
            // SAFETY: as above.
            let families =
                unsafe { instance.get_physical_device_queue_family_properties(physical) };
            let universal = vk::QueueFlags::GRAPHICS | vk::QueueFlags::COMPUTE;
            let candidates = families.iter().enumerate().filter(|(_, family)| {
                family.queue_flags.contains(universal) && family.timestamp_valid_bits > 0
            });
            let sparse = |(_, family): &(usize, &vk::QueueFamilyProperties)| {
                family.queue_flags.contains(vk::QueueFlags::SPARSE_BINDING)
            };
            let (family, properties) = candidates
                .clone()
                .find(sparse)
                .or_else(|| candidates.clone().next())?;
            let mut snapshot = snapshot;
            if !properties
                .queue_flags
                .contains(vk::QueueFlags::SPARSE_BINDING)
            {
                // Sparse binds run on the universal queue.
                let features = &mut snapshot.features;
                features.sparse_binding = false;
                features.sparse_residency_buffer = false;
                features.sparse_residency_image_2d = false;
                features.sparse_residency_image_3d = false;
                features.sparse_residency_samples = SampleCounts::EMPTY;
                features.sparse_residency_aliased = false;
            }
            Some((physical, extensions, snapshot, family as u32))
        })
    }

    /// The heap's set layout, pool and set with its null descriptors, the
    /// pipeline layout and the command pool.
    fn create_layout(&mut self, family: u32) -> Result<()> {
        let counts = HeapLayout::new(&self.snapshot.limits).counts;
        let bindings = objects::heap_bindings(&counts);
        let flags = [vk::DescriptorBindingFlags::PARTIALLY_BOUND
            | vk::DescriptorBindingFlags::UPDATE_AFTER_BIND
            | vk::DescriptorBindingFlags::UPDATE_UNUSED_WHILE_PENDING; 5];
        let mut binding_flags =
            vk::DescriptorSetLayoutBindingFlagsCreateInfo::default().binding_flags(&flags);
        let info = vk::DescriptorSetLayoutCreateInfo::default()
            .flags(vk::DescriptorSetLayoutCreateFlags::UPDATE_AFTER_BIND_POOL)
            .bindings(&bindings)
            .push_next(&mut binding_flags);
        // SAFETY: the device is valid; the create info outlives the call.
        self.heap.layout =
            unsafe { self.device.create_descriptor_set_layout(&info, None) }.map_err(failure)?;
        let sizes: Vec<vk::DescriptorPoolSize> = bindings
            .iter()
            .map(|binding| vk::DescriptorPoolSize {
                ty: binding.descriptor_type,
                descriptor_count: binding.descriptor_count,
            })
            .collect();
        let info = vk::DescriptorPoolCreateInfo::default()
            .flags(vk::DescriptorPoolCreateFlags::UPDATE_AFTER_BIND)
            .max_sets(1)
            .pool_sizes(&sizes);
        // SAFETY: as above.
        self.heap.pool =
            unsafe { self.device.create_descriptor_pool(&info, None) }.map_err(failure)?;
        let layouts = [self.heap.layout];
        let info = vk::DescriptorSetAllocateInfo::default()
            .descriptor_pool(self.heap.pool)
            .set_layouts(&layouts);
        // SAFETY: the pool has room for its one set.
        self.heap.set = unsafe { self.device.allocate_descriptor_sets(&info) }.map_err(failure)?[0];
        let ranges = [vk::PushConstantRange {
            stage_flags: vk::ShaderStageFlags::ALL,
            offset: 0,
            size: PushConstants::BYTES,
        }];
        let info = vk::PipelineLayoutCreateInfo::default()
            .set_layouts(&layouts)
            .push_constant_ranges(&ranges);
        // SAFETY: as above.
        self.layout =
            unsafe { self.device.create_pipeline_layout(&info, None) }.map_err(failure)?;
        let info = vk::CommandPoolCreateInfo::default()
            .flags(vk::CommandPoolCreateFlags::TRANSIENT)
            .queue_family_index(family);
        // SAFETY: as above.
        self.command_pool =
            unsafe { self.device.create_command_pool(&info, None) }.map_err(failure)?;
        let info = vk::SamplerCreateInfo::default();
        // SAFETY: as above.
        self.null_sampler = unsafe { self.device.create_sampler(&info, None) }.map_err(failure)?;
        let nulls = [
            Descriptor::SampledImage(ImageView(0)),
            Descriptor::StorageImage(ImageView(0)),
            Descriptor::Sampler(Sampler(raw(self.null_sampler))),
            Descriptor::UniformTexelBuffer(BufferView(0)),
            Descriptor::StorageTexelBuffer(BufferView(0)),
        ];
        for descriptor in nulls {
            self.write_descriptor(NULL_DESCRIPTOR, descriptor);
        }
        debug_assert_eq!(HEAP_SET, 0);
        Ok(())
    }

    /// Allocates memory of a type `request` allows among `types`, trying
    /// the preferred properties first.
    fn allocate(
        &mut self,
        size: u64,
        request: MemoryRequest,
        types: u32,
        dedicated: Option<vk::MemoryDedicatedAllocateInfo<'_>>,
    ) -> Result<vk::DeviceMemory> {
        let memory = &self.snapshot.memory;
        let candidates = objects::memory_candidates(memory, types, request);
        ensure(!candidates.is_empty(), "no memory type suits the resource")?;
        let mut last = vk::Result::ERROR_OUT_OF_DEVICE_MEMORY;
        for index in candidates {
            let mut flags = vk::MemoryAllocateFlagsInfo::default()
                .flags(vk::MemoryAllocateFlags::DEVICE_ADDRESS);
            let mut info = vk::MemoryAllocateInfo::default()
                .allocation_size(size)
                .memory_type_index(index)
                .push_next(&mut flags);
            let mut dedicated = dedicated;
            if let Some(dedicated) = dedicated.as_mut() {
                info = info.push_next(dedicated);
            }
            // SAFETY: the allocate info and its chain outlive the call.
            match unsafe { self.device.allocate_memory(&info, None) } {
                Ok(allocation) => {
                    if request.mapped {
                        self.map(allocation, size, index)?;
                    }
                    return Ok(allocation);
                }
                Err(error) => last = error,
            }
        }
        Err(failure(last))
    }

    fn map(&mut self, memory: vk::DeviceMemory, size: u64, index: u32) -> Result<()> {
        // SAFETY: `memory` is host visible (the request required it) and
        // not mapped yet.
        let pointer = unsafe {
            self.device
                .map_memory(memory, 0, vk::WHOLE_SIZE, vk::MemoryMapFlags::empty())
        }
        .map_err(failure)?;
        let coherent = self.snapshot.memory.types[index as usize]
            .properties
            .contains(super::vulkan::MemoryProperties::HOST_COHERENT);
        let pointer = NonNull::new(pointer.cast::<u8>()).ok_or(Error::OutOfMemory)?;
        self.mappings.insert(
            ash::vk::Handle::as_raw(memory),
            Mapping {
                pointer,
                size,
                coherent,
            },
        );
        Ok(())
    }

    /// The mapping of `memory` covering `offset..offset + size`.
    fn mapping(&self, memory: Memory, offset: u64, size: u64) -> Result<Mapping> {
        let mapping = self
            .mappings
            .get(&memory.0)
            .copied()
            .ok_or(Error::Invalid("memory is not mapped"))?;
        ensure(
            offset
                .checked_add(size)
                .is_some_and(|end| end <= mapping.size),
            "range outside the mapped memory",
        )?;
        Ok(mapping)
    }

    /// The flush or invalidate range of a non-coherent mapping, widened to
    /// the device's atom size.
    fn atom_range(&self, memory: Memory, offset: u64, size: u64) -> vk::MappedMemoryRange<'_> {
        let atom = self.snapshot.limits.non_coherent_atom_size.max(1);
        let start = offset / atom * atom;
        let end = (offset + size).next_multiple_of(atom);
        vk::MappedMemoryRange::default()
            .memory(ash::vk::Handle::from_raw(memory.0))
            .offset(start)
            .size(end - start)
    }

    /// Moves a new image to `GENERAL`: on the host when it allows host
    /// transfers, otherwise at the start of the next submission.
    fn adopt_image(&mut self, image: vk::Image, info: &ImageInfo) -> Result<()> {
        let aspects = objects::aspects(info.format.aspects());
        let host = info
            .usage
            .contains(super::vulkan::ImageUsage::HOST_TRANSFER);
        match (&self.fns.host_image_copy, host) {
            (Some(copy), true) => {
                let transition = [vk::HostImageLayoutTransitionInfoEXT::default()
                    .image(image)
                    .old_layout(vk::ImageLayout::UNDEFINED)
                    .new_layout(vk::ImageLayout::GENERAL)
                    .subresource_range(objects::whole(aspects))];
                // SAFETY: the image was created with host transfer usage and
                // no command uses it yet.
                unsafe { copy.transition_image_layout(&transition) }.map_err(failure)
            }
            _ => {
                self.new_images.push((image, aspects));
                Ok(())
            }
        }
    }

    fn create_compute(&mut self, info: &ComputePipelineInfo) -> Result<vk::Pipeline> {
        objects::compute_pipeline(info, self.layout, |create| {
            // SAFETY: the create info, its stage and the NIR outlive the
            // call.
            unsafe {
                self.device
                    .create_compute_pipelines(vk::PipelineCache::null(), &[*create], None)
            }
            .map(|pipelines| pipelines[0])
            .map_err(|(_, error)| failure(error))
        })
    }

    /// Passes `result` through, destroying `objects` when it failed so a
    /// failed creation leaks nothing.
    fn or_destroy<T>(&mut self, result: Result<T>, objects: &[Object]) -> Result<T> {
        if result.is_err() {
            for &object in objects {
                self.destroy(object);
            }
        }
        result
    }

    /// Frees the command buffers of submissions the queue has finished.
    fn reclaim(&mut self) -> Result<()> {
        let mut finished = Vec::new();
        let mut index = 0;
        while index < self.in_flight.len() {
            let entry = &self.in_flight[index];
            // SAFETY: the timeline semaphore is alive while submissions use it.
            let value = unsafe { self.device.get_semaphore_counter_value(entry.timeline) }
                .map_err(failure)?;
            if value >= entry.value {
                finished.extend(self.in_flight.swap_remove(index).buffers);
            } else {
                index += 1;
            }
        }
        if !finished.is_empty() {
            // SAFETY: the queue finished every command buffer in `finished`.
            unsafe {
                self.device
                    .free_command_buffers(self.command_pool, &finished)
            };
        }
        Ok(())
    }
}

impl Drop for NativeBackend {
    fn drop(&mut self) {
        // SAFETY: after the device idles, nothing uses any object, and each
        // handle is destroyed once; null handles are ignored by Vulkan.
        unsafe {
            let _ = self.device.device_wait_idle();
            self.device.destroy_pipeline(self.accumulate, None);
            self.device.destroy_pipeline(self.resolve, None);
            self.device.destroy_pipeline(self.select, None);
            self.device.destroy_command_pool(self.command_pool, None);
            self.device.destroy_pipeline_layout(self.layout, None);
            self.device.destroy_sampler(self.null_sampler, None);
            self.device.destroy_semaphore(self.bind_timeline, None);
            self.device.destroy_descriptor_pool(self.heap.pool, None);
            self.device
                .destroy_descriptor_set_layout(self.heap.layout, None);
            self.device.destroy_device(None);
            self.instance.destroy_instance(None);
        }
    }
}

/// Converts a raw boundary handle to its Vulkan type.
fn handle<T: vk::Handle>(raw: u64) -> T {
    T::from_raw(raw)
}

fn raw<T: vk::Handle>(handle: T) -> u64 {
    handle.as_raw()
}

impl Backend for NativeBackend {
    fn physical_device(&self) -> &PhysicalDevice {
        &self.snapshot
    }

    fn allocate_memory(
        &mut self,
        size: u64,
        request: MemoryRequest,
        memory_types: u32,
    ) -> Result<Memory> {
        self.allocate(size, request, memory_types, None)
            .map(|memory| Memory(raw(memory)))
    }

    fn buffer_requirements(&mut self, info: &BufferInfo) -> Result<Requirements> {
        objects::buffer(info, |create| {
            let info = vk::DeviceBufferMemoryRequirements::default().create_info(create);
            let mut requirements = vk::MemoryRequirements2::default();
            // SAFETY: the create info outlives the call.
            unsafe {
                self.device
                    .get_device_buffer_memory_requirements(&info, &mut requirements)
            };
            Ok(objects::requirements(&requirements.memory_requirements))
        })
    }

    fn image_requirements(&mut self, info: &ImageInfo) -> Result<Requirements> {
        objects::image(info, |create| {
            let info = vk::DeviceImageMemoryRequirements::default().create_info(create);
            let mut requirements = vk::MemoryRequirements2::default();
            // SAFETY: the create info outlives the call.
            unsafe {
                self.device
                    .get_device_image_memory_requirements(&info, &mut requirements)
            };
            Ok(objects::requirements(&requirements.memory_requirements))
        })
    }

    fn create_buffer(
        &mut self,
        info: &BufferInfo,
        request: MemoryRequest,
    ) -> Result<BufferAllocation> {
        let buffer = objects::buffer(info, |create| {
            // SAFETY: the create info outlives the call.
            unsafe { self.device.create_buffer(create, None) }.map_err(failure)
        })?;
        // SAFETY: the buffer was just created.
        let needs = unsafe { self.device.get_buffer_memory_requirements(buffer) };
        let dedicated = vk::MemoryDedicatedAllocateInfo::default().buffer(buffer);
        let memory =
            match self.allocate(needs.size, request, needs.memory_type_bits, Some(dedicated)) {
                Ok(memory) => memory,
                Err(error) => {
                    // SAFETY: nothing uses the new buffer.
                    unsafe { self.device.destroy_buffer(buffer, None) };
                    return Err(error);
                }
            };
        // SAFETY: the memory was allocated for this buffer.
        let bound = unsafe { self.device.bind_buffer_memory(buffer, memory, 0) }.map_err(failure);
        self.or_destroy(
            bound,
            &[
                Object::Buffer(Buffer(raw(buffer))),
                Object::Memory(Memory(raw(memory))),
            ],
        )?;
        Ok(BufferAllocation {
            buffer: Buffer(raw(buffer)),
            memory: Memory(raw(memory)),
            address: self.address(buffer, info),
            allocated: needs.size,
        })
    }

    fn create_placed_buffer(
        &mut self,
        info: &BufferInfo,
        memory: Memory,
        offset: u64,
    ) -> Result<(Buffer, u64)> {
        let buffer = objects::buffer(info, |create| {
            // SAFETY: the create info outlives the call.
            unsafe { self.device.create_buffer(create, None) }.map_err(failure)
        })?;
        // SAFETY: the Metal heap placed the buffer within `memory`.
        let bound = unsafe {
            self.device
                .bind_buffer_memory(buffer, handle(memory.0), offset)
        }
        .map_err(failure);
        self.or_destroy(bound, &[Object::Buffer(Buffer(raw(buffer)))])?;
        Ok((Buffer(raw(buffer)), self.address(buffer, info)))
    }

    fn create_image(
        &mut self,
        info: &ImageInfo,
        request: MemoryRequest,
    ) -> Result<(Image, Memory, u64)> {
        let image = objects::image(info, |create| {
            // SAFETY: the create info and its chain outlive the call.
            unsafe { self.device.create_image(create, None) }.map_err(failure)
        })?;
        // SAFETY: the image was just created.
        let needs = unsafe { self.device.get_image_memory_requirements(image) };
        let dedicated = vk::MemoryDedicatedAllocateInfo::default().image(image);
        let memory =
            match self.allocate(needs.size, request, needs.memory_type_bits, Some(dedicated)) {
                Ok(memory) => memory,
                Err(error) => {
                    // SAFETY: nothing uses the new image.
                    unsafe { self.device.destroy_image(image, None) };
                    return Err(error);
                }
            };
        // SAFETY: the memory was allocated for this image.
        let bound = unsafe { self.device.bind_image_memory(image, memory, 0) }.map_err(failure);
        let adopted = bound.and_then(|()| self.adopt_image(image, info));
        self.or_destroy(
            adopted,
            &[
                Object::Image(Image(raw(image))),
                Object::Memory(Memory(raw(memory))),
            ],
        )?;
        Ok((Image(raw(image)), Memory(raw(memory)), needs.size))
    }

    fn create_placed_image(
        &mut self,
        info: &ImageInfo,
        memory: Memory,
        offset: u64,
    ) -> Result<Image> {
        let image = objects::image(info, |create| {
            // SAFETY: the create info and its chain outlive the call.
            unsafe { self.device.create_image(create, None) }.map_err(failure)
        })?;
        // SAFETY: the Metal heap placed the image within `memory`.
        let bound = unsafe {
            self.device
                .bind_image_memory(image, handle(memory.0), offset)
        }
        .map_err(failure);
        let adopted = bound.and_then(|()| self.adopt_image(image, info));
        self.or_destroy(adopted, &[Object::Image(Image(raw(image)))])?;
        Ok(Image(raw(image)))
    }

    fn create_sparse_image(
        &mut self,
        info: &ImageInfo,
    ) -> Result<(Image, SparseImageRequirements)> {
        let image = objects::image(info, |create| {
            // SAFETY: the create info and its chain outlive the call.
            unsafe { self.device.create_image(create, None) }.map_err(failure)
        })?;
        // SAFETY: the image was just created.
        let (needs, sparse) = unsafe {
            (
                self.device.get_image_memory_requirements(image),
                self.device.get_image_sparse_memory_requirements(image),
            )
        };
        let color = sparse.iter().find(|requirements| {
            requirements
                .format_properties
                .aspect_mask
                .contains(vk::ImageAspectFlags::COLOR)
        });
        let requirements = color
            .map(|color| {
                let granularity = color.format_properties.image_granularity;
                SparseImageRequirements {
                    memory_types: needs.memory_type_bits,
                    granularity: [granularity.width, granularity.height, granularity.depth],
                    mip_tail_first_lod: color.image_mip_tail_first_lod,
                    mip_tail_size: color.image_mip_tail_size,
                    mip_tail_offset: color.image_mip_tail_offset,
                    mip_tail_stride: color.image_mip_tail_stride,
                    single_mip_tail: color
                        .format_properties
                        .flags
                        .contains(vk::SparseImageFormatFlags::SINGLE_MIPTAIL),
                }
            })
            .ok_or(Error::Unsupported("sparse residency of this image"));
        let adopted = requirements
            .and_then(|requirements| self.adopt_image(image, info).map(|()| requirements));
        let requirements = self.or_destroy(adopted, &[Object::Image(Image(raw(image)))])?;
        Ok((Image(raw(image)), requirements))
    }

    fn create_image_view(&mut self, image: Image, info: &ImageViewInfo) -> Result<ImageView> {
        objects::image_view(handle(image.0), info, |create| {
            // SAFETY: the create info and its chain outlive the call.
            unsafe { self.device.create_image_view(create, None) }
                .map(|view| ImageView(raw(view)))
                .map_err(failure)
        })
    }

    fn create_buffer_view(&mut self, buffer: Buffer, info: &BufferViewInfo) -> Result<BufferView> {
        let create = vk::BufferViewCreateInfo::default()
            .buffer(handle(buffer.0))
            .format(objects::format(info.format))
            .offset(info.offset)
            .range(info.range);
        // SAFETY: the create info outlives the call.
        unsafe { self.device.create_buffer_view(&create, None) }
            .map(|view| BufferView(raw(view)))
            .map_err(failure)
    }

    fn create_sampler(&mut self, info: &SamplerInfo) -> Result<Sampler> {
        objects::sampler(info, |create| {
            // SAFETY: the create info and its chain outlive the call.
            unsafe { self.device.create_sampler(create, None) }
                .map(|sampler| Sampler(raw(sampler)))
                .map_err(failure)
        })
    }

    fn create_graphics_pipeline(&mut self, info: &GraphicsPipelineInfo) -> Result<Pipeline> {
        objects::graphics_pipeline(info, self.layout, |create| {
            // SAFETY: the create info, every structure it points to and the
            // NIR outlive the call.
            unsafe {
                self.device
                    .create_graphics_pipelines(vk::PipelineCache::null(), &[*create], None)
            }
            .map(|pipelines| Pipeline(raw(pipelines[0])))
            .map_err(|(_, error)| failure(error))
        })
    }

    fn create_compute_pipeline(&mut self, info: &ComputePipelineInfo) -> Result<Pipeline> {
        self.create_compute(info)
            .map(|pipeline| Pipeline(raw(pipeline)))
    }

    fn create_query_pool(&mut self, info: &QueryPoolInfo) -> Result<QueryPool> {
        let create = vk::QueryPoolCreateInfo::default()
            .query_type(vk::QueryType::from_raw(info.query_type.raw() as i32))
            .query_count(info.count)
            .pipeline_statistics(vk::QueryPipelineStatisticFlags::from_raw(
                info.statistics.bits(),
            ));
        // SAFETY: the create info outlives the call.
        let pool = unsafe { self.device.create_query_pool(&create, None) }.map_err(failure)?;
        // Pools start unavailable; Metal's first use expects reset queries.
        // SAFETY: `hostQueryReset` is enabled and nothing uses the pool.
        unsafe { self.device.reset_query_pool(pool, 0, info.count) };
        Ok(QueryPool(raw(pool)))
    }

    fn create_semaphore(&mut self, initial: u64) -> Result<Semaphore> {
        let mut timeline = vk::SemaphoreTypeCreateInfo::default()
            .semaphore_type(vk::SemaphoreType::TIMELINE)
            .initial_value(initial);
        let create = vk::SemaphoreCreateInfo::default().push_next(&mut timeline);
        // SAFETY: the create info outlives the call.
        unsafe { self.device.create_semaphore(&create, None) }
            .map(|semaphore| Semaphore(raw(semaphore)))
            .map_err(failure)
    }

    fn create_indirect_commands_layout(
        &mut self,
        info: &IndirectCommandsLayoutInfo,
    ) -> Result<IndirectCommandsLayout> {
        self.generated()
            .create_layout(info, self.layout)
            .map(IndirectCommandsLayout)
            .map_err(failure)
    }

    fn create_execution_set(&mut self, initial: Pipeline, capacity: u32) -> Result<ExecutionSet> {
        self.generated()
            .create_set(handle(initial.0), capacity)
            .map(ExecutionSet)
            .map_err(failure)
    }

    fn write_execution_set(&mut self, set: ExecutionSet, index: u32, pipeline: Pipeline) {
        // SAFETY: the Metal device writes only indices no pending
        // submission uses.
        unsafe { self.generated().write_set(set.0, index, handle(pipeline.0)) }
    }

    fn generated_commands_requirements(
        &mut self,
        layout: IndirectCommandsLayout,
        set: Option<ExecutionSet>,
        sequences: u32,
        request: MemoryRequest,
    ) -> Result<Requirements> {
        let needs = self
            .generated()
            .memory_requirements(layout.0, set.map(|set| set.0), sequences);
        // Every type the request could allocate from must hold the memory.
        let candidates = objects::memory_candidates(&self.snapshot.memory, u32::MAX, request);
        if candidates
            .iter()
            .any(|&index| needs.memory_type_bits & 1 << index == 0)
        {
            return Err(Error::Unsupported(
                "generated commands preprocessing in host-visible memory",
            ));
        }
        Ok(Requirements {
            size: needs.size,
            alignment: needs.alignment,
            memory_types: needs.memory_type_bits,
        })
    }

    fn destroy(&mut self, object: Object) {
        // SAFETY: the Metal device destroys an object only after every
        // submission that could use it completed, and only once.
        unsafe {
            match object {
                Object::Buffer(buffer) => self.device.destroy_buffer(handle(buffer.0), None),
                Object::Image(image) => {
                    let image: vk::Image = handle(image.0);
                    self.new_images.retain(|(new, _)| *new != image);
                    self.device.destroy_image(image, None);
                }
                Object::ImageView(view) => self.device.destroy_image_view(handle(view.0), None),
                Object::BufferView(view) => {
                    self.device.destroy_buffer_view(handle(view.0), None);
                }
                Object::Sampler(sampler) => self.device.destroy_sampler(handle(sampler.0), None),
                Object::Pipeline(pipeline) => {
                    self.device.destroy_pipeline(handle(pipeline.0), None);
                }
                Object::QueryPool(pool) => self.device.destroy_query_pool(handle(pool.0), None),
                Object::Semaphore(semaphore) => {
                    self.device.destroy_semaphore(handle(semaphore.0), None);
                }
                Object::Memory(memory) => {
                    self.mappings.remove(&memory.0);
                    self.device.free_memory(handle(memory.0), None);
                }
                Object::IndirectCommandsLayout(layout) => self.generated().destroy_layout(layout.0),
                Object::ExecutionSet(set) => self.generated().destroy_set(set.0),
            }
        }
    }

    fn write_descriptor(&mut self, index: u32, descriptor: Descriptor) {
        objects::descriptor_write(self.heap.set, index, descriptor, |write| {
            // SAFETY: the heap is update-after-bind and update-unused-while-
            // pending, so a slot no pending command uses may be rewritten.
            unsafe { self.device.update_descriptor_sets(&[*write], &[]) }
        });
    }

    fn write_memory(&mut self, memory: Memory, offset: u64, bytes: &[u8]) -> Result<()> {
        let mapping = self.mapping(memory, offset, bytes.len() as u64)?;
        // SAFETY: `mapping` covers the range and the slice is disjoint from
        // device memory.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                mapping.pointer.as_ptr().add(offset as usize),
                bytes.len(),
            );
        }
        if mapping.coherent {
            Ok(())
        } else {
            self.flush_memory(memory, offset, bytes.len() as u64)
        }
    }

    fn read_memory(&mut self, memory: Memory, offset: u64, bytes: &mut [u8]) -> Result<()> {
        let mapping = self.mapping(memory, offset, bytes.len() as u64)?;
        if !mapping.coherent {
            self.invalidate_memory(memory, offset, bytes.len() as u64)?;
        }
        // SAFETY: as in `write_memory`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                mapping.pointer.as_ptr().add(offset as usize),
                bytes.as_mut_ptr(),
                bytes.len(),
            );
        }
        Ok(())
    }

    fn flush_memory(&mut self, memory: Memory, offset: u64, size: u64) -> Result<()> {
        let range = self.atom_range(memory, offset, size);
        // SAFETY: the memory is mapped; the range is atom aligned.
        unsafe { self.device.flush_mapped_memory_ranges(&[range]) }.map_err(failure)
    }

    fn invalidate_memory(&mut self, memory: Memory, offset: u64, size: u64) -> Result<()> {
        let range = self.atom_range(memory, offset, size);
        // SAFETY: as in `flush_memory`.
        unsafe { self.device.invalidate_mapped_memory_ranges(&[range]) }.map_err(failure)
    }

    fn copy_to_image(
        &mut self,
        image: Image,
        region: &BufferImageCopy,
        bytes: &[u8],
    ) -> Result<()> {
        let copy = self
            .fns
            .host_image_copy
            .as_ref()
            .ok_or(Error::Unsupported("host image copies"))?;
        let regions = [objects::memory_to_image(region, bytes)];
        let info = vk::CopyMemoryToImageInfoEXT::default()
            .dst_image(handle(image.0))
            .dst_image_layout(vk::ImageLayout::GENERAL)
            .regions(&regions);
        // SAFETY: the Metal layer sized `bytes` to the region, tightly
        // packed, and the image allows host transfers.
        unsafe { copy.copy_memory_to_image(&info) }.map_err(failure)
    }

    fn copy_from_image(
        &mut self,
        image: Image,
        region: &BufferImageCopy,
        bytes: &mut [u8],
    ) -> Result<()> {
        let copy = self
            .fns
            .host_image_copy
            .as_ref()
            .ok_or(Error::Unsupported("host image copies"))?;
        let regions = [objects::image_to_memory(region, bytes)];
        let info = vk::CopyImageToMemoryInfoEXT::default()
            .src_image(handle(image.0))
            .src_image_layout(vk::ImageLayout::GENERAL)
            .regions(&regions);
        // SAFETY: as in `copy_to_image`.
        unsafe { copy.copy_image_to_memory(&info) }.map_err(failure)
    }

    fn reset_queries(&mut self, pool: QueryPool, first: u32, count: u32) {
        // SAFETY: `hostQueryReset` is enabled; no pending command uses the
        // queries the Metal device resets.
        unsafe { self.device.reset_query_pool(handle(pool.0), first, count) };
    }

    fn query_results(&mut self, pool: QueryPool, first: u32, results: &mut [u64]) -> Result<bool> {
        // SAFETY: the pool holds `results.len()` queries from `first`.
        let queried = unsafe {
            self.device.get_query_pool_results(
                handle(pool.0),
                first,
                results,
                vk::QueryResultFlags::TYPE_64,
            )
        };
        match queried {
            Ok(()) => Ok(true),
            Err(vk::Result::NOT_READY) => Ok(false),
            Err(error) => Err(failure(error)),
        }
    }

    fn semaphore_value(&mut self, semaphore: Semaphore) -> Result<u64> {
        // SAFETY: the semaphore is alive.
        unsafe { self.device.get_semaphore_counter_value(handle(semaphore.0)) }.map_err(failure)
    }

    fn signal_semaphore(&mut self, semaphore: Semaphore, value: u64) -> Result<()> {
        let info = vk::SemaphoreSignalInfo::default()
            .semaphore(handle(semaphore.0))
            .value(value);
        // SAFETY: the Metal device signals only increasing values.
        unsafe { self.device.signal_semaphore(&info) }.map_err(failure)
    }

    fn wait_semaphore(&mut self, semaphore: Semaphore, value: u64, timeout: u64) -> Result<bool> {
        let semaphores = [handle(semaphore.0)];
        let values = [value];
        let info = vk::SemaphoreWaitInfo::default()
            .semaphores(&semaphores)
            .values(&values);
        // SAFETY: the semaphore is alive.
        match unsafe { self.device.wait_semaphores(&info, timeout) } {
            Ok(()) => Ok(true),
            Err(vk::Result::TIMEOUT) => Ok(false),
            Err(error) => Err(failure(error)),
        }
    }

    fn submit(&mut self, segments: &[Segment]) -> Result<()> {
        self.reclaim()?;
        if segments.is_empty() {
            return Ok(());
        }
        let info = vk::CommandBufferAllocateInfo::default()
            .command_pool(self.command_pool)
            .level(vk::CommandBufferLevel::PRIMARY)
            .command_buffer_count(segments.len() as u32);
        // SAFETY: the pool belongs to this device and is used only here.
        let buffers = unsafe { self.device.allocate_command_buffers(&info) }.map_err(failure)?;
        let new_images = core::mem::take(&mut self.new_images);
        let recorded =
            buffers
                .iter()
                .zip(segments)
                .enumerate()
                .try_for_each(|(index, (&buffer, segment))| {
                    let adopt = if index == 0 { &new_images[..] } else { &[] };
                    record::segment(self, buffer, adopt, segment)
                });
        let submitted = recorded.and_then(|()| self.queue_segments(segments, &buffers));
        if let Err(error) = submitted {
            // SAFETY: after the queue idles nothing uses the buffers, part
            // of which may have been submitted.
            unsafe {
                let _ = self.device.queue_wait_idle(self.queue);
                self.device
                    .free_command_buffers(self.command_pool, &buffers);
            }
            self.new_images = new_images;
            return Err(error);
        }
        // A commit appends the queue's completion signal last.
        let completion = segments.last().and_then(|segment| segment.signals.last());
        match completion {
            Some(&(timeline, value)) => self.in_flight.push(InFlight {
                buffers,
                timeline: handle(timeline.0),
                value,
            }),
            // Without a completion signal the buffers are free only once the
            // queue idles.
            None => {
                // SAFETY: waiting for the queue makes the buffers free.
                unsafe {
                    self.device.queue_wait_idle(self.queue).map_err(failure)?;
                    self.device
                        .free_command_buffers(self.command_pool, &buffers);
                }
            }
        }
        Ok(())
    }

    fn calibrated_timestamps(&mut self) -> Result<(u64, u64)> {
        let calibrated = self
            .fns
            .calibrated
            .as_ref()
            .ok_or(Error::Unsupported("calibrated timestamps"))?;
        let domains = [
            vk::CalibratedTimestampInfoKHR::default().time_domain(vk::TimeDomainKHR::DEVICE),
            vk::CalibratedTimestampInfoKHR::default()
                .time_domain(vk::TimeDomainKHR::CLOCK_MONOTONIC),
        ];
        // SAFETY: both domains are valid for Linux-derived drivers.
        let (stamps, _) =
            unsafe { calibrated.get_calibrated_timestamps(&domains) }.map_err(failure)?;
        Ok((stamps[1], stamps[0]))
    }
}

/// Submits `pending` in one `vkQueueSubmit2` and empties it.
fn flush(
    device: &ash::Device,
    queue: vk::Queue,
    pending: &mut Vec<vk::SubmitInfo2<'_>>,
) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    // SAFETY: every command buffer is recorded and every array outlives the
    // call; the queue is used only by this backend.
    let submitted = unsafe { device.queue_submit2(queue, pending, vk::Fence::null()) };
    pending.clear();
    submitted.map_err(failure)
}

impl NativeBackend {
    /// Submits the recorded segments in order. A segment with sparse binds
    /// splits the submission: the queue signals the bind timeline once
    /// everything before is done, the binds wait for that and the
    /// segment's own waits, and the segment's commands wait for the binds.
    fn queue_segments(
        &mut self,
        segments: &[Segment],
        buffers: &[vk::CommandBuffer],
    ) -> Result<()> {
        let bound: Vec<Option<u64>> = segments
            .iter()
            .map(|segment| {
                (!segment.binds.is_empty()).then(|| {
                    self.bind_value += 2;
                    self.bind_value
                })
            })
            .collect();
        let timeline = |value| {
            [vk::SemaphoreSubmitInfo::default()
                .semaphore(self.bind_timeline)
                .value(value)
                .stage_mask(vk::PipelineStageFlags2::ALL_COMMANDS)]
        };
        let ready: Vec<_> = bound
            .iter()
            .map(|value| timeline(value.map_or(0, |value| value - 1)))
            .collect();
        let waits: Vec<Vec<vk::SemaphoreSubmitInfo>> = segments
            .iter()
            .zip(&bound)
            .map(|(segment, bound)| match bound {
                Some(value) => timeline(*value).to_vec(),
                None => objects::semaphores(&segment.waits),
            })
            .collect();
        let signals: Vec<Vec<vk::SemaphoreSubmitInfo>> = segments
            .iter()
            .map(|segment| objects::semaphores(&segment.signals))
            .collect();
        let commands: Vec<[vk::CommandBufferSubmitInfo; 1]> = buffers
            .iter()
            .map(|&buffer| [vk::CommandBufferSubmitInfo::default().command_buffer(buffer)])
            .collect();
        let mut pending = Vec::new();
        for (index, segment) in segments.iter().enumerate() {
            if let Some(value) = bound[index] {
                pending.push(vk::SubmitInfo2::default().signal_semaphore_infos(&ready[index]));
                flush(&self.device, self.queue, &mut pending)?;
                let mut waits: Vec<_> = segment
                    .waits
                    .iter()
                    .map(|&(semaphore, value)| (handle(semaphore.0), value))
                    .collect();
                waits.push((self.bind_timeline, value - 1));
                sparse::SparseBatch::new(&segment.binds).submit(
                    &self.device,
                    self.queue,
                    &waits,
                    (self.bind_timeline, value),
                )?;
            }
            pending.push(
                vk::SubmitInfo2::default()
                    .wait_semaphore_infos(&waits[index])
                    .command_buffer_infos(&commands[index])
                    .signal_semaphore_infos(&signals[index]),
            );
        }
        flush(&self.device, self.queue, &mut pending)
    }

    /// `vkGetBufferDeviceAddress` when the buffer allows it.
    fn address(&self, buffer: vk::Buffer, info: &BufferInfo) -> u64 {
        if !info
            .usage
            .contains(super::vulkan::BufferUsage::SHADER_DEVICE_ADDRESS)
        {
            return 0;
        }
        let info = vk::BufferDeviceAddressInfo::default().buffer(buffer);
        // SAFETY: the buffer is bound and has device-address usage.
        unsafe { self.device.get_buffer_device_address(&info) }
    }
}
