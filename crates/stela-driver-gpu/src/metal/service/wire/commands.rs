//! The command stream `Commit` replays into one command buffer.
//!
//! A stream is a run of entries, each a [`CommandHeader`], the command's
//! record and the variable data the command takes, padded to 8 bytes.
//! Commands keep Metal's encoding rules: one encoder at a time, opened by
//! its `Begin*` command and closed by `EndEncoding`. Handles name objects of
//! the committing connection, zero for nil; sizes are `MTLSize`s and
//! origins `MTLOrigin`s. Commands taking a list (viewports, scissor
//! rectangles, view mappings) carry it as their data.
use super::{Record, RegionRecord, Span};

records! {
    /// `commit` of the command buffer `commands` encode.
    pub struct CommitRequest {
        pub commands: Span,
    }

    /// A command's `CommandCode` and the length of its record and data,
    /// without the padding after them.
    pub struct CommandHeader {
        pub code: u32,
        pub length: u32,
    }

    /// `encodeSignalEvent:value:` and `encodeWaitForEvent:value:`.
    pub struct EventCommand {
        pub event: u64,
        pub value: u64,
    }

    /// `sampleCountersInBuffer:atSampleIndex:withBarrier:` of any encoder.
    pub struct SampleCounters {
        pub buffer: u64,
        pub index: u64,
        pub barrier: u32,
        pub reserved: u32,
    }

    /// `computeCommandEncoderWithDispatchType:`.
    pub struct BeginCompute {
        pub dispatch_type: u64,
    }

    /// `set*PipelineState:`.
    pub struct SetPipeline {
        pub pipeline: u64,
    }

    /// `set*Buffer:offset:atIndex:`.
    pub struct SetBuffer {
        pub buffer: u64,
        pub offset: u64,
        pub index: u64,
    }

    /// `set*BufferOffset:atIndex:`.
    pub struct SetBufferOffset {
        pub offset: u64,
        pub index: u64,
    }

    /// `set*Bytes:length:atIndex:`; the bytes follow.
    pub struct SetBytes {
        pub index: u64,
    }

    /// `set*Texture:atIndex:`.
    pub struct SetTexture {
        pub texture: u64,
        pub index: u64,
    }

    /// `set*SamplerState:atIndex:`, or with `lodMinClamp:lodMaxClamp:`
    /// when `clamped`.
    pub struct SetSampler {
        pub sampler: u64,
        pub index: u64,
        pub clamped: u32,
        pub lod_min: f32,
        pub lod_max: f32,
        pub reserved: u32,
    }

    /// `setThreadgroupMemoryLength:atIndex:`.
    pub struct SetThreadgroupMemory {
        pub length: u64,
        pub index: u64,
    }

    /// `dispatchThreadgroups:threadsPerThreadgroup:`, whose `size` counts
    /// threadgroups, and `dispatchThreads:threadsPerThreadgroup:`, whose
    /// `size` counts threads.
    pub struct Dispatch {
        pub size: [u64; 3],
        pub threads: [u64; 3],
    }

    /// `dispatchThreadgroupsWithIndirectBuffer:indirectBufferOffset:
    /// threadsPerThreadgroup:`.
    pub struct DispatchIndirect {
        pub buffer: u64,
        pub offset: u64,
        pub threads: [u64; 3],
    }

    /// `memoryBarrierWithScope:`.
    pub struct MemoryBarrier {
        pub scope: u64,
    }

    /// `setStageInRegion:`.
    pub struct StageInRegion {
        pub origin: [u64; 3],
        pub size: [u64; 3],
    }

    /// A buffer and an offset into it: of
    /// `setStageInRegionWithIndirectBuffer:indirectBufferOffset:`.
    pub struct BufferOffset {
        pub buffer: u64,
        pub offset: u64,
    }

    /// `copyFromBuffer:sourceOffset:toBuffer:destinationOffset:size:`.
    pub struct CopyBuffer {
        pub source: u64,
        pub source_offset: u64,
        pub destination: u64,
        pub destination_offset: u64,
        pub size: u64,
    }

    /// Texel data in a buffer at Metal's row and image strides; zero
    /// `bytes_per_image` for a single image.
    pub struct BufferLayoutRecord {
        pub buffer: u64,
        pub offset: u64,
        pub bytes_per_row: u64,
        pub bytes_per_image: u64,
    }

    /// `copyFromBuffer:...toTexture:...options:`.
    pub struct CopyBufferToTexture {
        pub source: BufferLayoutRecord,
        pub texture: u64,
        pub region: RegionRecord,
        pub options: u64,
    }

    /// `copyFromTexture:...toBuffer:...options:`.
    pub struct CopyTextureToBuffer {
        pub texture: u64,
        pub region: RegionRecord,
        pub destination: BufferLayoutRecord,
        pub options: u64,
    }

    /// `copyFromTexture:sourceSlice:sourceLevel:sourceOrigin:sourceSize:
    /// toTexture:destinationSlice:destinationLevel:destinationOrigin:`.
    pub struct CopyTexture {
        pub source: u64,
        pub region: RegionRecord,
        pub destination: u64,
        pub destination_slice: u64,
        pub destination_level: u64,
        pub destination_origin: [u64; 3],
    }

    /// `copyFromTexture:sourceSlice:sourceLevel:toTexture:
    /// destinationSlice:destinationLevel:sliceCount:levelCount:`.
    pub struct CopyTextureSlices {
        pub source: u64,
        pub source_slice: u64,
        pub source_level: u64,
        pub destination: u64,
        pub destination_slice: u64,
        pub destination_level: u64,
        pub slice_count: u64,
        pub level_count: u64,
    }

    /// `fillBuffer:range:value:`, of a byte `value`.
    pub struct FillBuffer {
        pub buffer: u64,
        pub start: u64,
        pub length: u64,
        pub value: u64,
    }

    /// A buffer or texture: of `generateMipmapsForTexture:` and
    /// `synchronizeResource:`.
    pub struct Resource {
        pub resource: u64,
    }

    /// `synchronizeTexture:slice:level:`.
    pub struct SynchronizeTexture {
        pub texture: u64,
        pub slice: u64,
        pub level: u64,
    }

    /// `resolveCounters:inRange:destinationBuffer:destinationOffset:`.
    pub struct ResolveCounters {
        pub buffer: u64,
        pub first: u64,
        pub count: u64,
        pub destination: u64,
        pub offset: u64,
    }

    /// `updateTextureMappings:mode:…` of a sparse texture; its
    /// `MappingRecord`s follow.
    pub struct UpdateMappings {
        pub texture: u64,
        pub mode: u64,
    }

    /// One region of `updateTextureMappings:mode:…`, in tiles.
    pub struct MappingRecord {
        pub level: u64,
        pub slice: u64,
        pub origin: [u64; 3],
        pub size: [u64; 3],
    }

    /// `updateTextureMapping:mode:indirectBuffer:indirectBufferOffset:`.
    pub struct UpdateMappingIndirect {
        pub texture: u64,
        pub mode: u64,
        pub buffer: u64,
        pub offset: u64,
    }

    /// One texture's side of a mapping move: a tile-aligned pixel origin.
    pub struct MoveEndRecord {
        pub texture: u64,
        pub slice: u64,
        pub level: u64,
        pub origin: [u64; 3],
    }

    /// `moveTextureMappingsFromTexture:…toTexture:…`, of a size in pixels.
    pub struct MoveMappings {
        pub source: MoveEndRecord,
        pub destination: MoveEndRecord,
        pub size: [u64; 3],
    }

    /// An attachment of a render pass: its texture (zero for none), the
    /// slice, level and depth plane it renders to, those of its resolve
    /// texture (zero for none), and its actions.
    pub struct PassAttachmentRecord {
        pub texture: u64,
        pub level: u64,
        pub slice: u64,
        pub depth_plane: u64,
        pub resolve_texture: u64,
        pub resolve_level: u64,
        pub resolve_slice: u64,
        pub resolve_depth_plane: u64,
        pub load_action: u64,
        pub store_action: u64,
        pub store_action_options: u64,
    }

    /// `MTLRenderPassColorAttachmentDescriptor`.
    pub struct PassColorRecord {
        pub attachment: PassAttachmentRecord,
        pub clear_color: [f64; 4],
    }

    /// `MTLRenderPassDepthAttachmentDescriptor`.
    pub struct PassDepthRecord {
        pub attachment: PassAttachmentRecord,
        pub clear_depth: f64,
        pub resolve_filter: u64,
    }

    /// `MTLRenderPassStencilAttachmentDescriptor`.
    pub struct PassStencilRecord {
        pub attachment: PassAttachmentRecord,
        pub clear_stencil: u32,
        pub reserved: u32,
        pub resolve_filter: u64,
    }

    /// `renderCommandEncoderWithDescriptor:`; `sample_position_count`
    /// `[f32; 2]` sample positions follow, then `counter_sample_count`
    /// `CounterSampleRecord`s. Tile memory is any nonzero imageblock
    /// sample length, threadgroup memory length or tile size.
    pub struct BeginRender {
        pub color_attachments: [PassColorRecord; 8],
        pub depth_attachment: PassDepthRecord,
        pub stencil_attachment: PassStencilRecord,
        pub visibility_result_buffer: u64,
        pub render_target_array_length: u64,
        pub render_target_width: u64,
        pub render_target_height: u64,
        pub default_raster_sample_count: u64,
        pub tile_memory: u32,
        pub rasterization_rate_map: u32,
        pub sample_position_count: u32,
        pub counter_sample_count: u32,
    }

    /// A sample a pass writes at one of its boundaries
    /// (`sampleBufferAttachments`): a `PassBoundaryCode`.
    pub struct CounterSampleRecord {
        pub buffer: u64,
        pub index: u64,
        pub boundary: u64,
    }

    /// A render stage's binding: `stage` is one `MTLRenderStages` bit.
    pub struct StageBuffer {
        pub stage: u64,
        pub buffer: u64,
        pub offset: u64,
        pub index: u64,
    }

    /// `set*BufferOffset:atIndex:` of a render stage.
    pub struct StageBufferOffset {
        pub stage: u64,
        pub offset: u64,
        pub index: u64,
    }

    /// `set*Bytes:length:atIndex:` of a render stage; the bytes follow.
    pub struct StageBytes {
        pub stage: u64,
        pub index: u64,
    }

    /// `set*Texture:atIndex:` of a render stage.
    pub struct StageTexture {
        pub stage: u64,
        pub texture: u64,
        pub index: u64,
    }

    /// `set*SamplerState:atIndex:` of a render stage, or with
    /// `lodMinClamp:lodMaxClamp:` when `clamped`.
    pub struct StageSampler {
        pub stage: u64,
        pub sampler: u64,
        pub index: u64,
        pub clamped: u32,
        pub lod_min: f32,
        pub lod_max: f32,
        pub reserved: u32,
    }

    /// `setVertexBuffer:offset:attributeStride:atIndex:`.
    pub struct VertexBufferStride {
        pub buffer: u64,
        pub offset: u64,
        pub stride: u64,
        pub index: u64,
    }

    /// `MTLViewport`.
    pub struct ViewportRecord {
        pub origin_x: f64,
        pub origin_y: f64,
        pub width: f64,
        pub height: f64,
        pub znear: f64,
        pub zfar: f64,
    }

    /// `MTLScissorRect`.
    pub struct ScissorRecord {
        pub x: u64,
        pub y: u64,
        pub width: u64,
        pub height: u64,
    }

    /// One raw value: a cull mode, winding, fill mode, clip mode or store
    /// action.
    pub struct Mode {
        pub mode: u64,
    }

    /// `setDepthBias:slopeScale:clamp:`.
    pub struct DepthBias {
        pub constant: f32,
        pub slope: f32,
        pub clamp: f32,
        pub reserved: u32,
    }

    /// `MTLStencilDescriptor`.
    pub struct StencilRecord {
        pub compare_function: u64,
        pub stencil_failure_operation: u64,
        pub depth_failure_operation: u64,
        pub depth_stencil_pass_operation: u64,
        pub read_mask: u32,
        pub write_mask: u32,
    }

    /// `setDepthStencilState:` of a state made from this
    /// `MTLDepthStencilDescriptor`; nil is the default descriptor.
    pub struct DepthStencilRecord {
        pub depth_compare_function: u64,
        pub depth_write_enabled: u32,
        pub reserved: u32,
        pub front_face_stencil: StencilRecord,
        pub back_face_stencil: StencilRecord,
    }

    /// `setStencilFrontReferenceValue:backReferenceValue:`.
    pub struct StencilReference {
        pub front: u32,
        pub back: u32,
    }

    /// `setBlendColorRed:green:blue:alpha:`.
    pub struct BlendColor {
        pub color: [f32; 4],
    }

    /// `MTLVertexAmplificationViewMapping`.
    pub struct ViewMappingRecord {
        pub viewport_array_index_offset: u32,
        pub render_target_array_index_offset: u32,
    }

    /// `setVisibilityResultMode:offset:`.
    pub struct VisibilityMode {
        pub mode: u64,
        pub offset: u64,
    }

    /// `setColorStoreAction:atIndex:`.
    pub struct ColorStoreAction {
        pub action: u64,
        pub index: u64,
    }

    /// `setColorStoreActionOptions:atIndex:`.
    pub struct ColorStoreActionOptions {
        pub options: u64,
        pub index: u64,
    }

    /// `memoryBarrierWithScope:afterStages:beforeStages:`.
    pub struct RenderBarrier {
        pub scope: u64,
        pub after: u64,
        pub before: u64,
    }

    /// `drawPrimitives:vertexStart:vertexCount:instanceCount:baseInstance:`.
    pub struct DrawPrimitives {
        pub primitive: u64,
        pub vertex_start: u64,
        pub vertex_count: u64,
        pub instance_count: u64,
        pub base_instance: u64,
    }

    /// `drawIndexedPrimitives:indexCount:indexType:indexBuffer:
    /// indexBufferOffset:instanceCount:baseVertex:baseInstance:`.
    pub struct DrawIndexed {
        pub primitive: u64,
        pub index_count: u64,
        pub index_type: u64,
        pub index_buffer: u64,
        pub index_buffer_offset: u64,
        pub instance_count: u64,
        pub base_vertex: i64,
        pub base_instance: u64,
    }

    /// `drawPrimitives:indirectBuffer:indirectBufferOffset:`.
    pub struct DrawIndirect {
        pub primitive: u64,
        pub buffer: u64,
        pub offset: u64,
    }

    /// `drawIndexedPrimitives:indexType:indexBuffer:indexBufferOffset:
    /// indirectBuffer:indirectBufferOffset:`.
    pub struct DrawIndexedIndirect {
        pub primitive: u64,
        pub index_type: u64,
        pub index_buffer: u64,
        pub index_buffer_offset: u64,
        pub buffer: u64,
        pub offset: u64,
    }

    /// `setTessellationFactorBuffer:offset:instanceStride:`.
    pub struct FactorBuffer {
        pub buffer: u64,
        pub offset: u64,
        pub instance_stride: u64,
    }

    /// `setTessellationFactorScale:`.
    pub struct FactorScale {
        pub scale: f32,
        pub reserved: u32,
    }

    /// The patches a patch draw reads: its control points per patch, and
    /// its patch index buffer and control point index buffer (zero for
    /// none) with their offsets.
    pub struct PatchSourceRecord {
        pub control_points: u64,
        pub patch_index_buffer: u64,
        pub patch_index_offset: u64,
        pub control_point_index_buffer: u64,
        pub control_point_index_offset: u64,
    }

    /// `drawPatches:patchStart:patchCount:…` and `drawIndexedPatches:…`.
    pub struct DrawPatches {
        pub source: PatchSourceRecord,
        pub patch_start: u64,
        pub patch_count: u64,
        pub instance_count: u64,
        pub base_instance: u64,
    }

    /// `drawPatches:…indirectBuffer:indirectBufferOffset:` and its indexed
    /// form.
    pub struct DrawPatchesIndirect {
        pub source: PatchSourceRecord,
        pub buffer: u64,
        pub offset: u64,
    }

    /// `drawMeshThreadgroups:…`, whose `size` counts threadgroups, and
    /// `drawMeshThreads:…`, whose `size` counts threads.
    pub struct DrawMesh {
        pub size: [u64; 3],
        pub object_threads: [u64; 3],
        pub mesh_threads: [u64; 3],
    }

    /// `drawMeshThreadgroupsWithIndirectBuffer:…`.
    pub struct DrawMeshIndirect {
        pub buffer: u64,
        pub offset: u64,
        pub object_threads: [u64; 3],
        pub mesh_threads: [u64; 3],
    }
}

records! {
    /// `executeCommandsInBuffer:withRange:`, and the blit encoder's
    /// `resetCommandsInBuffer:withRange:` and
    /// `optimizeIndirectCommandBuffer:withRange:`.
    pub struct IndirectRange {
        pub buffer: u64,
        pub first: u64,
        pub count: u64,
    }

    /// `executeCommandsInBuffer:indirectBuffer:indirectBufferOffset:`.
    pub struct ExecuteIndirect {
        pub buffer: u64,
        pub range_buffer: u64,
        pub offset: u64,
    }

    /// `copyIndirectCommandBuffer:sourceRange:destination:
    /// destinationIndex:`.
    pub struct CopyCommands {
        pub source: u64,
        pub first: u64,
        pub count: u64,
        pub destination: u64,
        pub index: u64,
    }

    /// The command of an indirect command buffer that an encoding entry
    /// edits; the entry's record follows.
    pub struct IndirectTarget {
        pub command: u64,
    }

    /// `drawPatches:…` of an indirect render command and its tessellation
    /// factor buffer.
    pub struct IndirectPatches {
        pub draw: DrawPatches,
        pub factors: FactorBuffer,
    }
}

raw_enum! {
    /// Where a pass writes a counter sample.
    pub enum PassBoundaryCode: u64 {
        StartOfVertex = 0,
        EndOfVertex = 1,
        StartOfFragment = 2,
        EndOfFragment = 3,
    }
}

raw_enum! {
    /// Commands of the command buffer itself.
    pub enum CommandBufferCode: u32 {
        /// `endEncoding` of the open encoder, without a record.
        EndEncoding = 0x0001,
        /// `EventCommand`.
        SignalEvent = 0x0002,
        /// `EventCommand`.
        WaitForEvent = 0x0003,
        /// `SampleCounters`.
        SampleCounters = 0x0004,
    }
}

raw_enum! {
    /// Commands of `MTLComputeCommandEncoder`.
    pub enum ComputeCode: u32 {
        /// `BeginCompute`.
        Begin = 0x0101,
        /// `SetPipeline`.
        SetPipeline = 0x0102,
        /// `SetBuffer`.
        SetBuffer = 0x0103,
        /// `SetBufferOffset`.
        SetBufferOffset = 0x0104,
        /// `SetBytes` and the bytes.
        SetBytes = 0x0105,
        /// `SetTexture`.
        SetTexture = 0x0106,
        /// `SetSampler`.
        SetSampler = 0x0107,
        /// `SetThreadgroupMemory`.
        SetThreadgroupMemory = 0x0108,
        /// `Dispatch`.
        DispatchThreadgroups = 0x0109,
        /// `Dispatch`.
        DispatchThreads = 0x010a,
        /// `DispatchIndirect`.
        DispatchIndirect = 0x010b,
        /// `MemoryBarrier`.
        MemoryBarrier = 0x010c,
        /// `StageInRegion`.
        SetStageInRegion = 0x010d,
        /// `BufferOffset`.
        SetStageInRegionIndirect = 0x010e,
    }
}

raw_enum! {
    /// Commands of `MTLBlitCommandEncoder`.
    pub enum BlitCode: u32 {
        /// `blitCommandEncoder`, without a record.
        Begin = 0x0201,
        /// `CopyBuffer`.
        CopyBuffer = 0x0202,
        /// `CopyBufferToTexture`.
        CopyBufferToTexture = 0x0203,
        /// `CopyTextureToBuffer`.
        CopyTextureToBuffer = 0x0204,
        /// `CopyTexture`.
        CopyTexture = 0x0205,
        /// `CopyTextureSlices`.
        CopyTextureSlices = 0x0206,
        /// `FillBuffer`.
        FillBuffer = 0x0207,
        /// `Resource`.
        GenerateMipmaps = 0x0208,
        /// `Resource`: a managed buffer or texture.
        Synchronize = 0x0209,
        /// `SynchronizeTexture`.
        SynchronizeTexture = 0x020a,
        /// `ResolveCounters`.
        ResolveCounters = 0x020b,
    }
}

raw_enum! {
    /// Commands of render, compute and blit encoders on indirect command
    /// buffers.
    pub enum IndirectCode: u32 {
        /// `IndirectRange`, of a render or compute encoder.
        Execute = 0x0501,
        /// `ExecuteIndirect`, of a render or compute encoder.
        ExecuteIndirect = 0x0502,
        /// `IndirectRange`, of a blit encoder.
        Reset = 0x0503,
        /// `CopyCommands`, of a blit encoder.
        Copy = 0x0504,
        /// `IndirectRange`, of a blit encoder.
        Optimize = 0x0505,
    }
}

raw_enum! {
    /// `EncodeIndirect` entries for `MTLIndirectRenderCommand`: each is an
    /// `IndirectTarget` and the record of the render command alike.
    pub enum IndirectRenderCode: u32 {
        /// `SetPipeline`.
        SetPipeline = 0x0601,
        /// `StageBuffer`.
        SetBuffer = 0x0602,
        /// `VertexBufferStride`.
        SetVertexBufferStride = 0x0603,
        /// `Mode`: an `MTLCullMode`.
        SetCullMode = 0x0604,
        /// `Mode`: an `MTLWinding`.
        SetFrontFacingWinding = 0x0605,
        /// `DepthBias`.
        SetDepthBias = 0x0606,
        /// `DepthStencilRecord`.
        SetDepthStencilState = 0x0607,
        /// `Mode`: an `MTLTriangleFillMode`.
        SetTriangleFillMode = 0x0608,
        /// `Mode`: an `MTLDepthClipMode`.
        SetDepthClipMode = 0x0609,
        /// No record.
        SetBarrier = 0x060a,
        /// No record.
        ClearBarrier = 0x060b,
        /// `DrawPrimitives`.
        DrawPrimitives = 0x060c,
        /// `DrawIndexed`.
        DrawIndexed = 0x060d,
        /// `IndirectPatches`.
        DrawPatches = 0x060e,
        /// `DrawMesh`.
        DrawMeshThreadgroups = 0x060f,
        /// `DrawMesh`.
        DrawMeshThreads = 0x0610,
        /// No record.
        Reset = 0x0611,
        /// `SetThreadgroupMemory`.
        SetObjectThreadgroupMemory = 0x0612,
    }
}

raw_enum! {
    /// `EncodeIndirect` entries for `MTLIndirectComputeCommand`.
    pub enum IndirectComputeCode: u32 {
        /// `SetPipeline`.
        SetPipeline = 0x0701,
        /// `SetBuffer`.
        SetBuffer = 0x0702,
        /// `SetThreadgroupMemory`.
        SetThreadgroupMemory = 0x0703,
        /// `StageInRegion`.
        SetStageInRegion = 0x0704,
        /// No record.
        SetBarrier = 0x0705,
        /// No record.
        ClearBarrier = 0x0706,
        /// `Dispatch`.
        DispatchThreadgroups = 0x0707,
        /// `Dispatch`.
        DispatchThreads = 0x0708,
        /// No record.
        Reset = 0x0709,
    }
}

/// An `EncodeIndirect` entry's code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeCode {
    Render(IndirectRenderCode),
    Compute(IndirectComputeCode),
}

impl EncodeCode {
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw >> 8 {
            0x06 => IndirectRenderCode::from_raw(raw).map(Self::Render),
            0x07 => IndirectComputeCode::from_raw(raw).map(Self::Compute),
            _ => None,
        }
    }
}

raw_enum! {
    /// Commands of `MTLResourceStateCommandEncoder`.
    pub enum ResourceStateCode: u32 {
        /// `resourceStateCommandEncoder`, without a record.
        Begin = 0x0401,
        /// `UpdateMappings` and its `MappingRecord`s.
        UpdateMappings = 0x0402,
        /// `UpdateMappingIndirect`.
        UpdateMappingIndirect = 0x0403,
        /// `MoveMappings`.
        MoveMappings = 0x0404,
    }
}

raw_enum! {
    /// Commands of `MTLRenderCommandEncoder`.
    pub enum RenderCode: u32 {
        /// `BeginRender` and its sample positions and counter samples.
        Begin = 0x0301,
        /// `SetPipeline`.
        SetPipeline = 0x0302,
        /// `StageBuffer`.
        SetBuffer = 0x0303,
        /// `StageBufferOffset`.
        SetBufferOffset = 0x0304,
        /// `StageBytes` and the bytes.
        SetBytes = 0x0305,
        /// `StageTexture`.
        SetTexture = 0x0306,
        /// `StageSampler`.
        SetSampler = 0x0307,
        /// `VertexBufferStride`.
        SetVertexBufferStride = 0x0308,
        /// `ViewportRecord`s, without a record of their own.
        SetViewports = 0x0309,
        /// `ScissorRecord`s, without a record of their own.
        SetScissorRects = 0x030a,
        /// `Mode`: an `MTLCullMode`.
        SetCullMode = 0x030b,
        /// `Mode`: an `MTLWinding`.
        SetFrontFacingWinding = 0x030c,
        /// `DepthBias`.
        SetDepthBias = 0x030d,
        /// `DepthStencilRecord`.
        SetDepthStencilState = 0x030e,
        /// `StencilReference`.
        SetStencilReference = 0x030f,
        /// `BlendColor`.
        SetBlendColor = 0x0310,
        /// `Mode`: an `MTLTriangleFillMode`.
        SetTriangleFillMode = 0x0311,
        /// `Mode`: an `MTLDepthClipMode`.
        SetDepthClipMode = 0x0312,
        /// `ViewMappingRecord`s, without a record of their own.
        SetVertexAmplification = 0x0313,
        /// `VisibilityMode`.
        SetVisibilityResultMode = 0x0314,
        /// `ColorStoreAction`.
        SetColorStoreAction = 0x0315,
        /// `Mode`: an `MTLStoreAction`.
        SetDepthStoreAction = 0x0316,
        /// `Mode`: an `MTLStoreAction`.
        SetStencilStoreAction = 0x0317,
        /// `RenderBarrier`.
        MemoryBarrier = 0x0318,
        /// `DrawPrimitives`.
        DrawPrimitives = 0x0319,
        /// `DrawIndexed`.
        DrawIndexed = 0x031a,
        /// `DrawIndirect`.
        DrawIndirect = 0x031b,
        /// `DrawIndexedIndirect`.
        DrawIndexedIndirect = 0x031c,
        /// `FactorBuffer`.
        SetTessellationFactorBuffer = 0x031d,
        /// `FactorScale`.
        SetTessellationFactorScale = 0x031e,
        /// `DrawPatches`.
        DrawPatches = 0x031f,
        /// `DrawPatchesIndirect`.
        DrawPatchesIndirect = 0x0320,
        /// `DrawMesh`.
        DrawMeshThreadgroups = 0x0321,
        /// `DrawMesh`.
        DrawMeshThreads = 0x0322,
        /// `DrawMeshIndirect`.
        DrawMeshIndirect = 0x0323,
        /// `ColorStoreActionOptions`.
        SetColorStoreActionOptions = 0x0324,
        /// `Mode`: an `MTLStoreActionOptions`.
        SetDepthStoreActionOptions = 0x0325,
        /// `Mode`: an `MTLStoreActionOptions`.
        SetStencilStoreActionOptions = 0x0326,
        /// `SetThreadgroupMemory`.
        SetObjectThreadgroupMemory = 0x0327,
    }
}

/// A command's code, grouped by encoder in the high byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandCode {
    CommandBuffer(CommandBufferCode),
    Compute(ComputeCode),
    Blit(BlitCode),
    Render(RenderCode),
    ResourceState(ResourceStateCode),
    Indirect(IndirectCode),
}

impl CommandCode {
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw >> 8 {
            0x00 => CommandBufferCode::from_raw(raw).map(Self::CommandBuffer),
            0x01 => ComputeCode::from_raw(raw).map(Self::Compute),
            0x02 => BlitCode::from_raw(raw).map(Self::Blit),
            0x03 => RenderCode::from_raw(raw).map(Self::Render),
            0x04 => ResourceStateCode::from_raw(raw).map(Self::ResourceState),
            0x05 => IndirectCode::from_raw(raw).map(Self::Indirect),
            _ => None,
        }
    }
}
