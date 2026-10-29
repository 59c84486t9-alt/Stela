//! The Vulkan device the Metal layer drives.
//!
//! The native process implements [`Backend`] over the vendor's Mesa Vulkan
//! driver (NVK for NVIDIA): one `VkDevice` with the extensions and features
//! [`requirements`] lists, one universal queue, the bindless descriptor set
//! of [`binding`](crate::gpu::metal::binding) and the single pipeline layout
//! every pipeline uses. Shader code arrives as NIR the compiler built, which
//! the backend hands to the driver's internal NIR entry instead of SPIR-V.
//! Each method is one Vulkan call or a fixed sequence of them; failures map
//! to [`Error::OutOfMemory`] or [`Error::DeviceLost`].
//!
//! [`Error::OutOfMemory`]: crate::gpu::metal::error::Error::OutOfMemory
//! [`Error::DeviceLost`]: crate::gpu::metal::error::Error::DeviceLost
use super::{
    object::{
        Buffer, BufferInfo, BufferView, BufferViewInfo, ComputePipelineInfo, ExecutionSet,
        GraphicsPipelineInfo, Image, ImageInfo, ImageView, ImageViewInfo, IndirectCommandsLayout,
        IndirectCommandsLayoutInfo, Memory, MemoryRequest, Pipeline, QueryPool, QueryPoolInfo,
        Sampler, SamplerInfo, Semaphore, SparseImageRequirements,
    },
    physical::{Features, PhysicalDevice},
};
use crate::gpu::metal::{binding::HeapArray, command_buffer::Segment, error::Result};

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
    QueryPool(QueryPool),
    Semaphore(Semaphore),
    Memory(Memory),
    IndirectCommandsLayout(IndirectCommandsLayout),
    ExecutionSet(ExecutionSet),
}

pub trait Backend {
    fn physical_device(&self) -> &PhysicalDevice;

    fn allocate_memory(
        &mut self,
        size: u64,
        request: MemoryRequest,
        memory_types: u32,
    ) -> Result<Memory>;
    fn buffer_requirements(&mut self, info: &BufferInfo) -> Result<Requirements>;
    fn image_requirements(&mut self, info: &ImageInfo) -> Result<Requirements>;
    /// A buffer with dedicated memory, mapped when the request says so.
    fn create_buffer(
        &mut self,
        info: &BufferInfo,
        request: MemoryRequest,
    ) -> Result<BufferAllocation>;
    /// A buffer bound at `offset` in `memory`; returns its device address.
    fn create_placed_buffer(
        &mut self,
        info: &BufferInfo,
        memory: Memory,
        offset: u64,
    ) -> Result<(Buffer, u64)>;
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
    /// A sparse-residency color image with no memory bound; segments bind
    /// its blocks.
    fn create_sparse_image(&mut self, info: &ImageInfo)
    -> Result<(Image, SparseImageRequirements)>;
    fn create_image_view(&mut self, image: Image, info: &ImageViewInfo) -> Result<ImageView>;
    fn create_buffer_view(&mut self, buffer: Buffer, info: &BufferViewInfo) -> Result<BufferView>;
    fn create_sampler(&mut self, info: &SamplerInfo) -> Result<Sampler>;
    fn create_graphics_pipeline(&mut self, info: &GraphicsPipelineInfo) -> Result<Pipeline>;
    fn create_compute_pipeline(&mut self, info: &ComputePipelineInfo) -> Result<Pipeline>;
    fn create_query_pool(&mut self, info: &QueryPoolInfo) -> Result<QueryPool>;
    fn create_semaphore(&mut self, initial: u64) -> Result<Semaphore>;
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
}

/// A Vulkan feature or extension the Metal layer needs from every device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Requirement {
    pub name: &'static str,
    pub present: bool,
}

/// The features the binding ABI, dynamic state model and synchronization
/// rely on; a device missing any is refused rather than half-supported.
pub fn requirements(features: &Features) -> [Requirement; 19] {
    let requirement = |name, present| Requirement { name, present };
    [
        requirement("bufferDeviceAddress", features.buffer_device_address),
        requirement("timelineSemaphore", features.timeline_semaphore),
        requirement("synchronization2", features.synchronization2),
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
