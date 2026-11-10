//! The Vulkan device the Metal layer drives.
//!
//! The native process implements [`Backend`] over the vendor's Mesa Vulkan
//! driver (NVK for NVIDIA): one `VkDevice` with the extensions and features
//! [`requirements`] lists, one universal queue, the bindless descriptor set
//! of [`binding`](crate::metal::binding) and the single pipeline layout
//! every pipeline uses. Shader code arrives as NIR the compiler built, which
//! the backend hands to the driver's internal NIR entry instead of SPIR-V.
//! Each method is one Vulkan call or a fixed sequence of them; failures map
//! to [`Error::OutOfMemory`], [`Error::DeviceLost`] or, for a result with no
//! Metal answer, [`Error::Driver`] with its raw `VkResult`.
//!
//! [`Error::OutOfMemory`]: crate::metal::error::Error::OutOfMemory
//! [`Error::DeviceLost`]: crate::metal::error::Error::DeviceLost
//! [`Error::Driver`]: crate::metal::error::Error::Driver
use super::{
    object::{
        Buffer, BufferInfo, BufferView, BufferViewInfo, ComputePipelineInfo, ExecutionSet,
        GraphicsPipelineInfo, Image, ImageInfo, ImageView, ImageViewInfo, IndirectCommandsLayout,
        IndirectCommandsLayoutInfo, Memory, MemoryRequest, Pipeline, PipelineCache, QueryPool,
        QueryPoolInfo, Sampler, SamplerInfo, Semaphore, SparseImageRequirements,
    },
    physical::{Features, PhysicalDevice},
};
use crate::metal::{binding::HeapArray, command_buffer::Segment, error::Result};
use alloc::vec::Vec;
use core::num::NonZeroU64;
use stela_contracts::gate::MemoryRange;

/// `VkMemoryRequirements`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Requirements {
    pub size: u64,
    pub alignment: u64,
    pub memory_types: u32,
}

/// A buffer with its own memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferAllocation {
    pub buffer: Buffer,
    pub memory: Memory,
    /// `vkGetBufferDeviceAddress`.
    pub address: u64,
    /// Bytes of memory allocated, for Metal's allocated-size reports.
    pub allocated: u64,
}

/// The memory blocks a backend places buffers and images in, and the
/// resources in memory of their own.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryBlocks {
    pub blocks: usize,
    pub block_bytes: u64,
    /// Resources placed in blocks, and the bytes they take.
    pub placed: usize,
    pub placed_bytes: u64,
    /// Buffers and images in memory of their own.
    pub own: usize,
}

/// A descriptor written into the bindless heap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Descriptor {
    SampledImage(ImageView),
    StorageImage(ImageView),
    Sampler(Sampler),
    UniformTexelBuffer(BufferView),
    StorageTexelBuffer(BufferView),
}

impl Descriptor {
    pub const fn array(&self) -> HeapArray {
        match self {
            Self::SampledImage(_) => HeapArray::SampledImages,
            Self::StorageImage(_) => HeapArray::StorageImages,
            Self::Sampler(_) => HeapArray::Samplers,
            Self::UniformTexelBuffer(_) => HeapArray::UniformTexelBuffers,
            Self::StorageTexelBuffer(_) => HeapArray::StorageTexelBuffers,
        }
    }
}

/// Any object the backend destroys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Object {
    Buffer(Buffer),
    Image(Image),
    ImageView(ImageView),
    BufferView(BufferView),
    Sampler(Sampler),
    Pipeline(Pipeline),
    PipelineCache(PipelineCache),
    QueryPool(QueryPool),
    Semaphore(Semaphore),
    Memory(Memory),
    IndirectCommandsLayout(IndirectCommandsLayout),
    ExecutionSet(ExecutionSet),
}

pub trait Backend {
    fn physical_device(&self) -> &PhysicalDevice;

    /// Acknowledges that no queued GPU operation can still access this
    /// backend's resources. The owner has closed admission and observed all
    /// accepted submission serials complete before calling. Failure provides
    /// no evidence of idleness; resources and native roots must stay owned.
    /// This does not acknowledge PCI reset/removal or DMA-domain invalidation.
    fn acknowledge_idle(&mut self) -> Result<()> {
        Err(crate::metal::error::Error::Unsupported(
            "GPU idle acknowledgement",
        ))
    }

    /// Memory of its own, zeroed before the host or the GPU reaches it.
    fn allocate_memory(
        &mut self,
        size: u64,
        request: MemoryRequest,
        memory_types: u32,
    ) -> Result<Memory>;
    fn buffer_requirements(&mut self, info: &BufferInfo) -> Result<Requirements>;
    fn image_requirements(&mut self, info: &ImageInfo) -> Result<Requirements>;
    /// A buffer with memory the backend chooses, mapped when the request
    /// says so: a place in a larger allocation, or memory of its own. The
    /// memory starts at least at a 256-byte boundary, where a linear image
    /// over the buffer can bind. All of it reads zero, as Metal's new
    /// buffers do.
    fn create_buffer(
        &mut self,
        info: &BufferInfo,
        request: MemoryRequest,
    ) -> Result<BufferAllocation>;
    /// The wired guest RAM of `ranges`, which the GPU reaches where it is.
    /// Destroying the memory lets [`Self::retired`] answer `token`.
    fn import_memory(&mut self, ranges: &[MemoryRange], token: NonZeroU64) -> Result<Memory>;
    /// The token of imported memory now destroyed.
    fn retired(&mut self) -> Option<NonZeroU64>;
    /// Whether [`Self::retired`] has an answer.
    fn retiring(&self) -> bool;
    /// A buffer bound at `offset` in `memory`; returns its device address.
    fn create_placed_buffer(
        &mut self,
        info: &BufferInfo,
        memory: Memory,
        offset: u64,
    ) -> Result<(Buffer, u64)>;
    /// An image with memory the backend chooses, as [`Self::create_buffer`]
    /// does, its memory and the bytes it needs. Every subresource reads zero
    /// until written.
    fn create_image(
        &mut self,
        info: &ImageInfo,
        request: MemoryRequest,
    ) -> Result<(Image, Memory, u64)>;
    fn create_placed_image(
        &mut self,
        info: &ImageInfo,
        memory: Memory,
        offset: u64,
    ) -> Result<Image>;
    /// Zeroes every subresource of `image`, which `info` created and an
    /// earlier texture used, as [`Self::create_image`] zeroes a new one:
    /// before the next submission's commands, unless they overwrite it
    /// whole first. The earlier texture's work has completed.
    fn clear_reused_image(&mut self, image: Image, info: &ImageInfo);
    /// A sparse-residency color image with no memory bound; segments bind
    /// its blocks.
    fn create_sparse_image(&mut self, info: &ImageInfo)
    -> Result<(Image, SparseImageRequirements)>;
    fn create_image_view(&mut self, image: Image, info: &ImageViewInfo) -> Result<ImageView>;
    fn create_buffer_view(&mut self, buffer: Buffer, info: &BufferViewInfo) -> Result<BufferView>;
    fn create_sampler(&mut self, info: &SamplerInfo) -> Result<Sampler>;
    fn create_graphics_pipeline(&mut self, info: &GraphicsPipelineInfo) -> Result<Pipeline>;
    fn create_compute_pipeline(&mut self, info: &ComputePipelineInfo) -> Result<Pipeline>;
    /// While `deferring` names the lock jobs run under, a pipeline creation
    /// that would compile and that no cache holds fails with
    /// [`DEFERRED`](crate::metal::compiler::DEFERRED) and leaves a job that
    /// compiles it outside the service's turn ([`crate::metal::deferred`]).
    fn defer_pipelines(&mut self, _deferring: Option<&crate::metal::deferred::JobLock>) {}
    /// Creates in the call from here on: the call changed what a second run
    /// would change again.
    fn stop_deferring(&mut self) {}
    /// Whether the call deferred a pipeline creation.
    fn deferred(&self) -> bool {
        false
    }
    /// The pipeline creation the call deferred.
    fn take_job(&mut self) -> Option<crate::metal::deferred::Job> {
        None
    }
    /// Keeps what a job this backend deferred made.
    fn adopt_job(&mut self, _done: crate::metal::deferred::Done) {}
    /// A pipeline cache of `data`, an earlier one's bytes. Bytes of another
    /// device or driver, or of nothing, leave it empty.
    fn create_pipeline_cache(&mut self, data: &[u8]) -> Result<PipelineCache>;
    /// The bytes of `cache`.
    fn pipeline_cache_data(&mut self, cache: PipelineCache) -> Result<Vec<u8>>;
    fn create_query_pool(&mut self, info: &QueryPoolInfo) -> Result<QueryPool>;
    fn create_semaphore(&mut self, initial: u64) -> Result<Semaphore>;
    /// A file descriptor of `semaphore` the platform can wait on outside the
    /// device (a DRM syncobj), which it owns; `None` when the driver has
    /// none to give, and completions are then found by polling.
    fn export_semaphore(&mut self, semaphore: Semaphore) -> Option<i32>;
    /// `vkCreateIndirectCommandsLayoutEXT`; only with
    /// [`Limits::generated_commands`].
    ///
    /// [`Limits::generated_commands`]: super::physical::Limits::generated_commands
    fn create_indirect_commands_layout(
        &mut self,
        info: &IndirectCommandsLayoutInfo,
    ) -> Result<IndirectCommandsLayout>;
    /// `vkCreateIndirectExecutionSetEXT` of up to `capacity` pipelines, with
    /// `initial`, an indirect-bindable pipeline, at index 0.
    fn create_execution_set(&mut self, initial: Pipeline, capacity: u32) -> Result<ExecutionSet>;
    /// `vkUpdateIndirectExecutionSetPipelineEXT` of one index, which no
    /// pending submission uses.
    fn write_execution_set(&mut self, set: ExecutionSet, index: u32, pipeline: Pipeline);
    /// The size and alignment of the preprocess memory `sequences` of
    /// `layout` need (`vkGetGeneratedCommandsMemoryRequirementsEXT`), in
    /// memory of `request`; refused when no memory `request` allows can
    /// hold it.
    fn generated_commands_requirements(
        &mut self,
        layout: IndirectCommandsLayout,
        set: Option<ExecutionSet>,
        sequences: u32,
        request: MemoryRequest,
    ) -> Result<Requirements>;
    fn destroy(&mut self, object: Object);

    /// `vkUpdateDescriptorSets` into heap slot `index`.
    fn write_descriptor(&mut self, index: u32, descriptor: Descriptor);

    /// Copies into mapped memory and flushes it.
    fn write_memory(&mut self, memory: Memory, offset: u64, bytes: &[u8]) -> Result<()>;
    /// Invalidates mapped memory and copies out of it.
    fn read_memory(&mut self, memory: Memory, offset: u64, bytes: &mut [u8]) -> Result<()>;
    /// `vkFlushMappedMemoryRanges` after CPU writes through another mapping.
    fn flush_memory(&mut self, memory: Memory, offset: u64, size: u64) -> Result<()>;
    /// `vkInvalidateMappedMemoryRanges` before CPU reads.
    fn invalidate_memory(&mut self, memory: Memory, offset: u64, size: u64) -> Result<()>;
    /// `vkCopyMemoryToImage` of tightly packed rows into one subresource
    /// region (`hostImageCopy`).
    fn copy_to_image(
        &mut self,
        image: Image,
        region: &super::command::BufferImageCopy,
        bytes: &[u8],
    ) -> Result<()>;
    /// `vkCopyImageToMemory`.
    fn copy_from_image(
        &mut self,
        image: Image,
        region: &super::command::BufferImageCopy,
        bytes: &mut [u8],
    ) -> Result<()>;

    /// `vkResetQueryPool` from the host.
    fn reset_queries(&mut self, pool: QueryPool, first: u32, count: u32);
    /// 64-bit results; `false` while any is still unavailable.
    fn query_results(&mut self, pool: QueryPool, first: u32, results: &mut [u64]) -> Result<bool>;

    fn semaphore_value(&mut self, semaphore: Semaphore) -> Result<u64>;
    fn signal_semaphore(&mut self, semaphore: Semaphore, value: u64) -> Result<()>;
    /// Waits until `semaphore` reaches `value` or `timeout` nanoseconds pass.
    fn wait_semaphore(&mut self, semaphore: Semaphore, value: u64, timeout: u64) -> Result<bool>;

    /// Records each segment into a command buffer and submits them in
    /// order. A segment's sparse binds wait for everything submitted before
    /// it, and its commands wait for the binds.
    fn submit(&mut self, segments: &[Segment]) -> Result<()>;

    /// `vkGetCalibratedTimestampsKHR`: (host nanoseconds, GPU ticks).
    fn calibrated_timestamps(&mut self) -> Result<(u64, u64)>;

    /// Gives the backend the platform's tick counter, which times the
    /// phases of its own calls that [`Self::take_split`] answers.
    fn set_clock(&mut self, _ticks: fn() -> u64) {}

    /// The ticks spent since the last take in phases inside the backend's
    /// own calls, each summed into its slot: [`Self::create_image`]'s image
    /// creation, allocation and binding, and [`Self::submit`]'s reclaim,
    /// recording and queue submission. Zeros for a backend that does not
    /// time them; the device takes before and after the call it splits.
    fn take_split(&mut self) -> [u64; 3] {
        [0; 3]
    }

    /// The blocks [`Self::create_buffer`] and [`Self::create_image`] place
    /// resources in; zeros for a backend that gives each its own memory.
    fn memory_blocks(&self) -> MemoryBlocks {
        MemoryBlocks::default()
    }
}

/// A Vulkan feature or extension the Metal layer needs from every device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Requirement {
    pub name: &'static str,
    pub present: bool,
}

/// The features the binding ABI, dynamic state model and synchronization
/// rely on; a device missing any is refused rather than half-supported.
pub fn requirements(features: &Features) -> [Requirement; 20] {
    let requirement = |name, present| Requirement { name, present };
    [
        requirement("bufferDeviceAddress", features.buffer_device_address),
        requirement("timelineSemaphore", features.timeline_semaphore),
        requirement("synchronization2", features.synchronization2),
        requirement("shaderFloat16", features.shader_float16),
        requirement("dynamicRendering", features.dynamic_rendering),
        requirement(
            "descriptorIndexing",
            features.descriptor_indexing && features.runtime_descriptor_array,
        ),
        requirement(
            "descriptorBindingPartiallyBound",
            features.descriptor_binding_partially_bound,
        ),
        requirement(
            "descriptorBindingUpdateAfterBind",
            features.descriptor_binding_sampled_image_update_after_bind
                && features.descriptor_binding_storage_image_update_after_bind
                && features.descriptor_binding_uniform_texel_buffer_update_after_bind
                && features.descriptor_binding_storage_texel_buffer_update_after_bind
                && features.descriptor_binding_update_unused_while_pending,
        ),
        requirement(
            "shaderImageArrayNonUniformIndexing",
            features.shader_sampled_image_array_non_uniform_indexing
                && features.shader_storage_image_array_non_uniform_indexing,
        ),
        requirement(
            "extendedDynamicState",
            features.extended_dynamic_state && features.extended_dynamic_state2,
        ),
        requirement("unifiedImageLayouts", features.unified_image_layouts),
        requirement(
            "maintenance5",
            features.maintenance4 && features.maintenance5,
        ),
        requirement("vulkanMemoryModel", features.vulkan_memory_model),
        requirement(
            "storageImageWithoutFormat",
            features.shader_storage_image_read_without_format
                && features.shader_storage_image_write_without_format,
        ),
        requirement("independentBlend", features.independent_blend),
        requirement("nullDescriptor", features.null_descriptor),
        requirement("conditionalRendering", features.conditional_rendering),
        requirement(
            "dynamicRenderingUnusedAttachments",
            features.dynamic_rendering_unused_attachments,
        ),
        requirement(
            "dynamicPrimitiveTopologyUnrestricted",
            features.dynamic_primitive_topology_unrestricted,
        ),
        requirement("hostQueryReset", features.host_query_reset),
    ]
}
