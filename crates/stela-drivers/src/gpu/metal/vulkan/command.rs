//! The Vulkan commands Metal encoders lower to.
//!
//! A [`Command`] is one `vkCmd*` call (or a fixed group the backend issues
//! together, such as the dynamic depth-stencil state) recorded into a
//! primary command buffer of the device's universal queue. Each command
//! buffer starts with descriptor set 0 bound at the graphics and compute
//! bind points over the device's single pipeline layout. Every image stays
//! in `VK_IMAGE_LAYOUT_GENERAL` (`unifiedImageLayouts`), so synchronization
//! needs only global memory barriers.
use super::{
    AttachmentLoadOp, AttachmentStoreOp, CompareOp, CullMode, Filter, FrontFace, ImageAspects,
    IndexType, PipelineStages, PolygonMode, PrimitiveTopology, ResolveModes, SampleCounts,
    StencilOp,
    object::{Buffer, Image, ImageView, Pipeline, QueryPool},
};
use crate::gpu::metal::{binding::PushConstants, pass::ClearValue};
use alloc::vec::Vec;

/// `VkMemoryBarrier2` in a `vkCmdPipelineBarrier2` without buffer or image
/// barriers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Barrier {
    pub src_stages: PipelineStages,
    pub src_access: super::Access,
    pub dst_stages: PipelineStages,
    pub dst_access: super::Access,
}

/// `VkRenderingAttachmentInfo` with resolved views.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Attachment {
    pub view: ImageView,
    pub resolve: Option<(ResolveModes, ImageView)>,
    pub load_op: AttachmentLoadOp,
    pub store_op: AttachmentStoreOp,
    pub clear: ClearValue,
}

/// `VkRenderingInfo`. Color attachments keep their Metal indices; `None`
/// is an attachment with a null view.
#[derive(Clone, Debug, PartialEq)]
pub struct Rendering {
    pub extent: [u32; 2],
    pub layer_count: u32,
    pub color: Vec<Option<Attachment>>,
    pub depth: Option<Attachment>,
    pub stencil: Option<Attachment>,
}

/// `VkViewport`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Viewport {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub min_depth: f32,
    pub max_depth: f32,
}

/// `VkRect2D`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rect {
    pub offset: [i32; 2],
    pub extent: [u32; 2],
}

/// The dynamic depth and stencil state, issued as its `vkCmdSet*` calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepthStencil {
    pub depth_test: bool,
    pub depth_write: bool,
    pub depth_compare: CompareOp,
    pub stencil_test: bool,
    /// (fail, pass, depth fail, compare, compare mask, write mask) for the
    /// front and back faces.
    pub faces: [(StencilOp, StencilOp, StencilOp, CompareOp, u32, u32); 2],
}

/// `VkBufferCopy2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferCopy {
    pub src_offset: u64,
    pub dst_offset: u64,
    pub size: u64,
}

/// `VkImageSubresourceLayers`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Subresource {
    pub aspects: ImageAspects,
    pub mip_level: u32,
    pub base_array_layer: u32,
    pub layer_count: u32,
}

/// `VkBufferImageCopy2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferImageCopy {
    pub buffer_offset: u64,
    /// Texels per row and rows per image, as Vulkan counts them.
    pub buffer_row_length: u32,
    pub buffer_image_height: u32,
    pub subresource: Subresource,
    pub offset: [i32; 3],
    pub extent: [u32; 3],
}

/// `VkImageCopy2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageCopy {
    pub src: Subresource,
    pub src_offset: [i32; 3],
    pub dst: Subresource,
    pub dst_offset: [i32; 3],
    pub extent: [u32; 3],
}

/// `VkImageBlit2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageBlit {
    pub src: Subresource,
    pub src_bounds: [[i32; 3]; 2],
    pub dst: Subresource,
    pub dst_bounds: [[i32; 3]; 2],
}

/// `vkCmdBindVertexBuffers2` element; a `None` stride keeps the pipeline's.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VertexBuffer {
    pub buffer: Buffer,
    pub offset: u64,
    pub size: u64,
    pub stride: Option<u64>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    Barrier(Barrier),
    BeginRendering(Rendering),
    EndRendering,
    BindPipeline(Pipeline),
    PushConstants(PushConstants),
    SetViewports(Vec<Viewport>),
    SetScissors(Vec<Rect>),
    SetDepthBias {
        enable: bool,
        constant: f32,
        clamp: f32,
        slope: f32,
    },
    SetBlendConstants([f32; 4]),
    SetStencilReference {
        front: u32,
        back: u32,
    },
    SetDepthStencil(DepthStencil),
    SetCullMode(CullMode),
    SetFrontFace(FrontFace),
    SetPrimitiveTopology(PrimitiveTopology),
    SetPrimitiveRestart(bool),
    SetRasterizerDiscard(bool),
    SetPolygonMode(PolygonMode),
    /// `vkCmdSetDepthClampEnableEXT` and `vkCmdSetDepthClipEnableEXT`.
    SetDepthClamp(bool),
    /// `vkCmdSetSampleLocationsEnableEXT` and, when enabled,
    /// `vkCmdSetSampleLocationsEXT` for `samples`.
    SetSampleLocations {
        samples: SampleCounts,
        locations: Vec<[f32; 2]>,
    },
    BindVertexBuffers {
        first: u32,
        buffers: Vec<VertexBuffer>,
    },
    BindIndexBuffer {
        buffer: Buffer,
        offset: u64,
        index_type: IndexType,
    },
    Draw {
        vertex_count: u32,
        instance_count: u32,
        first_vertex: u32,
        first_instance: u32,
    },
    DrawIndexed {
        index_count: u32,
        instance_count: u32,
        first_index: u32,
        vertex_offset: i32,
        first_instance: u32,
    },
    DrawIndirect {
        buffer: Buffer,
        offset: u64,
    },
    DrawIndexedIndirect {
        buffer: Buffer,
        offset: u64,
    },
    DrawMeshTasks([u32; 3]),
    DrawMeshTasksIndirect {
        buffer: Buffer,
        offset: u64,
    },
    Dispatch([u32; 3]),
    DispatchIndirect {
        buffer: Buffer,
        offset: u64,
    },
    CopyBuffer {
        src: Buffer,
        dst: Buffer,
        regions: Vec<BufferCopy>,
    },
    CopyBufferToImage {
        src: Buffer,
        dst: Image,
        regions: Vec<BufferImageCopy>,
    },
    CopyImageToBuffer {
        src: Image,
        dst: Buffer,
        regions: Vec<BufferImageCopy>,
    },
    CopyImage {
        src: Image,
        dst: Image,
        regions: Vec<ImageCopy>,
    },
    BlitImage {
        src: Image,
        dst: Image,
        regions: Vec<ImageBlit>,
        filter: Filter,
    },
    /// `vkCmdFillBuffer`: offset and size are multiples of four.
    FillBuffer {
        buffer: Buffer,
        offset: u64,
        size: u64,
        data: u32,
    },
    ResetQueryPool {
        pool: QueryPool,
        first: u32,
        count: u32,
    },
    BeginQuery {
        pool: QueryPool,
        query: u32,
        precise: bool,
    },
    EndQuery {
        pool: QueryPool,
        query: u32,
    },
    WriteTimestamp {
        pool: QueryPool,
        query: u32,
        stage: PipelineStages,
    },
    /// 64-bit results, waiting for availability.
    CopyQueryResults {
        pool: QueryPool,
        first: u32,
        count: u32,
        dst: Buffer,
        offset: u64,
        stride: u64,
    },
    /// Writes the sum of each run of 64-bit results to its destination:
    /// the backend's internal compute kernel for queries Metal accumulates
    /// into one visibility result. `sums` holds (first result, result count,
    /// destination offset); results start at `results_offset`.
    AccumulateResults {
        results: Buffer,
        results_offset: u64,
        sums: Vec<(u32, u32, u64)>,
        dst: Buffer,
    },
}
