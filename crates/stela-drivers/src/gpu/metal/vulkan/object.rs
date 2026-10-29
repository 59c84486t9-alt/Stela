//! Create-info descriptions for the Vulkan objects Metal resources lower to.
//! Each mirrors the Vulkan create-info members the Metal layer sets; the
//! backend supplies `sType`/`pNext` chains and the extension structures named
//! on each field.
use super::{
    BlendFactor, BlendOp, BorderColor, BufferCreate, BufferUsage, ColorComponents, CompareOp,
    ComponentSwizzle, DynamicState, Filter, Format, ImageAspects, ImageCreate, ImageTiling,
    ImageType, ImageUsage, ImageViewType, MemoryProperties, PipelineStatistics, PrimitiveTopology,
    SampleCounts, SamplerAddressMode, SamplerMipmapMode, SamplerReductionMode, ShaderStages,
    VertexInputRate,
};
use alloc::vec::Vec;

/// Memory a resource needs: every `required` property, and `preferred`
/// properties when a type with them has room. The backend falls back to
/// `required` alone when the preferred allocation fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRequest {
    pub required: MemoryProperties,
    pub preferred: MemoryProperties,
    /// The CPU maps the allocation (`vkMapMemory2`).
    pub mapped: bool,
}

/// `VkBufferCreateInfo` with `VkBufferUsageFlags2CreateInfo`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferInfo {
    pub size: u64,
    pub usage: BufferUsage,
    pub flags: BufferCreate,
}

/// An explicit `DRM_FORMAT_MOD_LINEAR` layout
/// (`VkImageDrmFormatModifierExplicitCreateInfoEXT`) for images that alias
/// buffer memory row by row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinearLayout {
    pub row_pitch: u64,
}

/// `VkImageCreateInfo`, with `VkImageFormatListCreateInfo` when
/// `view_formats` is not empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageInfo {
    pub flags: ImageCreate,
    pub image_type: ImageType,
    pub format: Format,
    pub extent: [u32; 3],
    pub mip_levels: u32,
    pub array_layers: u32,
    pub samples: SampleCounts,
    pub tiling: ImageTiling,
    pub usage: ImageUsage,
    pub view_formats: Vec<Format>,
    pub linear: Option<LinearLayout>,
}

/// `VkImageSubresourceRange`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubresourceRange {
    pub aspects: ImageAspects,
    pub base_mip_level: u32,
    pub level_count: u32,
    pub base_array_layer: u32,
    pub layer_count: u32,
}

/// `VkImageViewCreateInfo` with `VkImageViewUsageCreateInfo`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageViewInfo {
    pub view_type: ImageViewType,
    pub format: Format,
    pub components: [ComponentSwizzle; 4],
    pub range: SubresourceRange,
    pub usage: ImageUsage,
}

/// `VkBufferViewCreateInfo`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferViewInfo {
    pub format: Format,
    pub offset: u64,
    pub range: u64,
}

/// `VkSamplerCreateInfo` with `VkSamplerReductionModeCreateInfo`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SamplerInfo {
    pub mag_filter: Filter,
    pub min_filter: Filter,
    pub mipmap_mode: SamplerMipmapMode,
    pub address_modes: [SamplerAddressMode; 3],
    pub anisotropy: Option<f32>,
    pub compare: Option<CompareOp>,
    pub min_lod: f32,
    pub max_lod: f32,
    pub border_color: BorderColor,
    pub unnormalized_coordinates: bool,
    pub reduction_mode: SamplerReductionMode,
}

/// NIR the compiler registered with the backend, which hands it to the
/// driver's shader compiler in place of SPIR-V.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ShaderCode(pub u64);

/// `VkVertexInputBindingDescription` with its divisor
/// (`VkVertexInputBindingDivisorDescription`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VertexBinding {
    pub binding: u32,
    pub input_rate: VertexInputRate,
    pub divisor: u32,
    /// The pipeline's stride; `None` when only the command binds it
    /// (`VK_DYNAMIC_STATE_VERTEX_INPUT_BINDING_STRIDE`).
    pub stride: Option<u32>,
}

/// `VkVertexInputAttributeDescription`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VertexAttribute {
    pub location: u32,
    pub binding: u32,
    pub format: Format,
    pub offset: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VertexInput {
    pub bindings: Vec<VertexBinding>,
    pub attributes: Vec<VertexAttribute>,
}

/// `VkPipelineColorBlendAttachmentState`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColorBlendAttachment {
    pub blend_enable: bool,
    pub src_color: BlendFactor,
    pub dst_color: BlendFactor,
    pub color_op: BlendOp,
    pub src_alpha: BlendFactor,
    pub dst_alpha: BlendFactor,
    pub alpha_op: BlendOp,
    pub write_mask: ColorComponents,
}

/// `VkGraphicsPipelineCreateInfo` for dynamic rendering
/// (`VkPipelineRenderingCreateInfo`) over the device's single pipeline
/// layout. Everything Metal sets on the encoder is in `dynamic_states`.
#[derive(Clone, Debug, PartialEq)]
pub struct GraphicsPipelineInfo {
    pub stages: Vec<(ShaderStages, ShaderCode)>,
    pub vertex_input: VertexInput,
    pub topology: PrimitiveTopology,
    pub patch_control_points: u32,
    pub samples: SampleCounts,
    pub alpha_to_coverage: bool,
    pub alpha_to_one: bool,
    /// Every color attachment slot's format; `None` is
    /// `VK_FORMAT_UNDEFINED`. Pipelines and passes always declare all slots
    /// (`dynamicRenderingUnusedAttachments`), so any pipeline can draw in
    /// any pass whose used formats match.
    pub color_formats: Vec<Option<Format>>,
    pub depth_format: Option<Format>,
    pub stencil_format: Option<Format>,
    pub color_blend: Vec<ColorBlendAttachment>,
    pub dynamic_states: Vec<DynamicState>,
}

/// `VkComputePipelineCreateInfo` over the device's single pipeline layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComputePipelineInfo {
    pub code: ShaderCode,
    /// `VkPipelineShaderStageRequiredSubgroupSizeCreateInfo`.
    pub required_subgroup_size: u32,
    /// `VK_PIPELINE_SHADER_STAGE_CREATE_REQUIRE_FULL_SUBGROUPS_BIT`.
    pub full_subgroups: bool,
}

macro_rules! handles {
    ($($(#[$meta:meta])* $name:ident;)*) => {$(
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub u64);
    )*};
}

handles! {
    /// `VkBuffer` with its bound memory.
    Buffer;
    /// `VkImage` with its bound memory.
    Image;
    ImageView;
    BufferView;
    Sampler;
    Pipeline;
    QueryPool;
    /// A timeline `VkSemaphore`.
    Semaphore;
    /// `VkDeviceMemory`, for heaps and sparse backing.
    Memory;
}

raw_enum! {
    /// `VkQueryType`.
    pub enum QueryType: u32 {
        Occlusion = 0,
        PipelineStatistics = 1,
        Timestamp = 2,
    }
}

/// `VkQueryPoolCreateInfo`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryPoolInfo {
    pub query_type: QueryType,
    pub count: u32,
    pub statistics: PipelineStatistics,
}
