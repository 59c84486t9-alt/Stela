//! The service's wire format: fixed-width records, their status and the
//! operations that carry them.
//!
//! A record is `#[repr(C)]` without padding, of integers, floats and arrays
//! of them, little-endian on both sides of the call gate, so every byte
//! pattern is a value and a request is read by copying its bytes. A request
//! or response is exactly its record's size. Enumerations and option sets
//! cross as Metal's raw values and are decoded with their declarations'
//! own checks; a handle is a connection's `ObjectHandle`, zero for none.
use super::identity::TableError;
use crate::metal::{capabilities::block::Block, error::Error};
use alloc::vec::Vec;

/// The protocol version a connection negotiates. A major version changes
/// records; a minor version only adds operations.
pub const MAJOR: u32 = 1;
pub const MINOR: u32 = 0;

/// A fixed-width wire record.
///
/// # Safety
///
/// The type is `#[repr(C)]` without padding bytes and every bit pattern is
/// one of its values.
pub unsafe trait Record: Copy + 'static {}

macro_rules! primitives {
    ($($ty:ty),*) => {$(
        // SAFETY: integers and floats have no padding and accept every bit
        // pattern.
        unsafe impl Record for $ty {}
    )*};
}

primitives!(u8, u32, u64, i32, i64, f32, f64);
// SAFETY: an array of records has no padding between its elements.
unsafe impl<T: Record, const N: usize> Record for [T; N] {}
// SAFETY: the block's layout is checked to be its fields' sizes, all of
// them integers, floats and arrays of them.
unsafe impl Record for Block {}

/// Declares records: `#[repr(C)]` structures of records, checked to have
/// no padding.
macro_rules! records {
    ($(
        $(#[$meta:meta])*
        pub struct $name:ident {
            $($(#[$field_meta:meta])* pub $field:ident: $ty:ty,)*
        }
    )*) => {$(
        $(#[$meta])*
        #[repr(C)]
        #[derive(Clone, Copy, Debug, Default, PartialEq)]
        pub struct $name {
            $($(#[$field_meta])* pub $field: $ty,)*
        }

        const _: () = assert!(
            core::mem::size_of::<$name>() == 0 $(+ core::mem::size_of::<$ty>())*,
            "records have no padding"
        );

        // SAFETY: the fields are records and the assertion above rules out
        // padding.
        unsafe impl Record for $name where $($ty: Record,)* {}
    )*};
}

/// The records filling `bytes`.
pub fn read_array<T: Record>(bytes: &[u8]) -> Result<Vec<T>, Fault> {
    if !bytes.len().is_multiple_of(core::mem::size_of::<T>()) {
        return Err(Fault::MALFORMED);
    }
    bytes
        .chunks_exact(core::mem::size_of::<T>())
        .map(read)
        .collect()
}

/// The record in `bytes`, which must be exactly its size.
pub fn read<T: Record>(bytes: &[u8]) -> Result<T, Fault> {
    if bytes.len() != core::mem::size_of::<T>() {
        return Err(Fault::MALFORMED);
    }
    // SAFETY: `bytes` holds `size_of::<T>()` bytes, and every bit pattern is
    // a `T`.
    Ok(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
}

/// The bytes of `value`.
pub fn bytes<T: Record>(value: &T) -> &[u8] {
    // SAFETY: a record has no padding, so its bytes are initialized.
    unsafe {
        core::slice::from_raw_parts((value as *const T).cast::<u8>(), core::mem::size_of::<T>())
    }
}

/// Writes `value` to `out`, which must be exactly its size.
pub fn write<T: Record>(value: &T, out: &mut [u8]) -> Result<(), Fault> {
    if out.len() != core::mem::size_of::<T>() {
        return Err(Fault::MALFORMED);
    }
    out.copy_from_slice(bytes(value));
    Ok(())
}

records! {
    /// A range of the guest's address space, which the call gate resolves.
    pub struct Span {
        pub address: u64,
        pub length: u64,
    }

    /// No data.
    pub struct Empty {}

    /// The call a gate doorbell names, in the calling thread's memory:
    /// an operation with its request and response records, which the gate
    /// completes in place with the call's `Status` and, when `reason`
    /// holds it, why it failed as UTF-8 of `reason_length` bytes.
    pub struct GateCall {
        pub operation: u32,
        pub status: u32,
        pub request: Span,
        pub response: Span,
        pub reason: Span,
        pub reason_length: u64,
    }

    /// `Negotiate`: the versions the frontend speaks.
    pub struct NegotiateRequest {
        pub major: u32,
        pub minor: u32,
    }

    /// The service's version and the size of the capability block.
    pub struct NegotiateResponse {
        pub major: u32,
        pub minor: u32,
        pub capability_bytes: u32,
        pub reserved: u32,
    }

    /// An object of the connection.
    pub struct Handle {
        pub handle: u64,
    }

    /// The length of variable data, which the response's span received
    /// when it was long enough.
    pub struct Length {
        pub length: u64,
    }

    /// `NewLibrary`: a Metal library's bytes.
    pub struct NewLibraryRequest {
        pub data: Span,
    }

    /// `LibraryFunctionNames`: the span receiving the names, each ended by
    /// a zero byte.
    pub struct LibraryFunctionNamesRequest {
        pub library: u64,
        pub out: Span,
    }

    /// `LibraryIdentity`: the span receiving the library's install name.
    pub struct LibraryIdentityRequest {
        pub library: u64,
        pub out: Span,
    }

    /// `MTLLibraryType` and the length of the install name, zero for none.
    pub struct LibraryIdentityResponse {
        pub library_type: u64,
        pub length: u64,
    }

    /// `LibraryData`: the span receiving the library's bytes.
    pub struct LibraryDataRequest {
        pub library: u64,
        pub out: Span,
    }

    /// `NewFunction`: the function's name and its `ConstantRecord`s.
    pub struct NewFunctionRequest {
        pub library: u64,
        pub name: Span,
        pub constants: Span,
    }

    /// A function constant value: an `MTLDataType` and the value's packed
    /// lanes, for the constant of `name`, or at `index` when it is empty.
    pub struct ConstantRecord {
        pub data_type: u64,
        pub index: u64,
        pub name: Span,
        pub value: Span,
    }

    /// `FunctionReflection`: the span receiving the function's
    /// `ConstantInfo`s, then its `AttributeInfo`s, then their names.
    pub struct FunctionReflectionRequest {
        pub function: u64,
        pub out: Span,
    }

    /// `functionType`, `patchType`, the control points the function
    /// declares (zero for none), and the counts and length of the
    /// reflection written when it fit.
    pub struct FunctionReflectionResponse {
        pub function_type: u64,
        pub patch_type: u64,
        pub patch_control_points: u64,
        pub constant_count: u32,
        pub attribute_count: u32,
        pub length: u64,
    }

    /// An entry of `functionConstantsDictionary`; names are offsets and
    /// lengths in the reflection.
    pub struct ConstantInfo {
        pub name: u32,
        pub name_length: u32,
        pub data_type: u64,
        pub index: u32,
        pub required: u32,
    }

    /// An `MTLVertexAttribute` of `vertexAttributes`, or an `MTLAttribute`
    /// of a kernel's `stageInputAttributes`.
    pub struct AttributeInfo {
        pub name: u32,
        pub name_length: u32,
        pub data_type: u64,
        pub index: u32,
        pub active: u32,
        pub patch_control_point: u32,
        pub reserved: u32,
    }

    /// `FunctionBindings`: the span receiving the function's
    /// `BindingInfo`s, then the `TypeInfo`s and `MemberInfo`s they reach,
    /// then their names.
    pub struct FunctionBindingsRequest {
        pub function: u64,
        pub out: Span,
    }

    /// The counts and length of the bindings written when they fit.
    pub struct FunctionBindingsResponse {
        pub binding_count: u32,
        pub type_count: u32,
        pub member_count: u32,
        pub reserved: u32,
        pub length: u64,
    }

    /// An `MTLBinding`; names are offsets and lengths in the bindings, and
    /// `ty` is the index of a `TypeInfo`, or `NO_TYPE`. A buffer's is its
    /// pointer type, whose element gives `bufferDataType` and
    /// `bufferStructType`; a texture's its texture reference type. A
    /// threadgroup buffer or payload has an alignment and data size, and a
    /// texture or sampler an array length.
    pub struct BindingInfo {
        pub name: u32,
        pub name_length: u32,
        pub binding_type: u32,
        pub access: u32,
        pub index: u32,
        pub used: u32,
        pub array_length: u32,
        pub alignment: u32,
        pub data_size: u32,
        pub ty: u32,
    }

    /// An `MTLStructType`, `MTLArrayType`, `MTLPointerType` or
    /// `MTLTextureReferenceType`, by `data_type`. A structure's members are
    /// `MemberInfo`s `[first_member, first_member + member_count)`. An
    /// array's or pointer's element has `element_data_type` and the
    /// `TypeInfo` `element`, or `NO_TYPE` for a datum; a texture's
    /// component type is its `element_data_type`. `access` is a pointer's or
    /// texture's `MTLBindingAccess`.
    pub struct TypeInfo {
        pub data_type: u64,
        pub element_data_type: u64,
        pub element: u32,
        pub first_member: u32,
        pub member_count: u32,
        pub length: u32,
        pub stride: u32,
        pub argument_index_stride: u32,
        pub access: u32,
        pub alignment: u32,
        pub data_size: u32,
        pub element_is_argument_buffer: u32,
        pub texture_type: u32,
        pub depth: u32,
    }

    /// An `MTLStructMember`: its `TypeInfo` `ty`, or `NO_TYPE` for a datum.
    pub struct MemberInfo {
        pub name: u32,
        pub name_length: u32,
        pub data_type: u64,
        pub offset: u32,
        pub argument_index: u32,
        pub ty: u32,
        pub reserved: u32,
    }

    /// `ArgumentLayout`: `ArgumentRecord`s, and the span receiving each
    /// one's `u32` offset in their order.
    pub struct ArgumentLayoutRequest {
        pub arguments: Span,
        pub out: Span,
    }

    /// An `MTLArgumentDescriptor`.
    pub struct ArgumentRecord {
        pub data_type: u64,
        pub index: u32,
        pub array_length: u32,
        pub constant_block_alignment: u32,
        pub reserved: u32,
    }

    /// `encodedLength` and `alignment`, and the length of the offsets
    /// written when they fit.
    pub struct ArgumentLayoutResponse {
        pub encoded_length: u32,
        pub alignment: u32,
        pub length: u64,
    }

    /// `newBufferWithLength:options:`.
    pub struct NewBufferRequest {
        pub length: u64,
        pub options: u64,
    }

    /// A new buffer: its `gpuAddress`, `allocatedSize` and `heapOffset`.
    pub struct BufferResponse {
        pub handle: u64,
        pub gpu_address: u64,
        pub allocated_size: u64,
        pub heap_offset: u64,
    }

    /// A buffer over imported memory, which the frontend keeps mapped: what
    /// a CPU reaches. `newBufferWithBytesNoCopy:length:options:deallocator:`
    /// imports the app's pages; shared and managed buffers its own. The
    /// buffer takes the memory's handle.
    pub struct NewImportedBufferRequest {
        pub memory: u64,
        pub length: u64,
        pub options: u64,
    }

    /// `didModifyRange:`.
    pub struct BufferRangeRequest {
        pub buffer: u64,
        pub offset: u64,
        pub length: u64,
    }

    /// `MTLTextureDescriptor`.
    pub struct TextureDescriptorRecord {
        pub texture_type: u64,
        pub pixel_format: u64,
        pub width: u64,
        pub height: u64,
        pub depth: u64,
        pub mipmap_level_count: u64,
        pub sample_count: u64,
        pub array_length: u64,
        pub options: u64,
        pub usage: u64,
        /// `MTLTextureSwizzleChannels`: red, green, blue and alpha.
        pub swizzle: [u8; 4],
        pub reserved: u32,
    }

    /// A new texture: its `gpuResourceID`, `allocatedSize`, `heapOffset`
    /// and, when `sparse`, `firstMipmapInTail` and `tailSizeInBytes`.
    pub struct TextureResponse {
        pub handle: u64,
        pub resource_id: u64,
        pub allocated_size: u64,
        pub heap_offset: u64,
        pub first_mipmap_in_tail: u64,
        pub tail_size: u64,
        pub sparse: u32,
        pub reserved: u32,
    }

    /// `newTextureViewWithPixelFormat:textureType:levels:slices:swizzle:`;
    /// ranges are a location and a length.
    pub struct NewTextureViewRequest {
        pub texture: u64,
        pub pixel_format: u64,
        pub texture_type: u64,
        pub levels: [u64; 2],
        pub slices: [u64; 2],
        pub swizzle: [u8; 4],
        pub reserved: u32,
    }

    /// `newTextureWithDescriptor:offset:bytesPerRow:` of a buffer.
    pub struct NewBufferTextureRequest {
        pub buffer: u64,
        pub descriptor: TextureDescriptorRecord,
        pub offset: u64,
        pub bytes_per_row: u64,
    }

    /// What depends on a pixel format's size or support.
    pub struct PixelFormatRequest {
        pub pixel_format: u64,
    }

    /// `minimumLinearTextureAlignmentForPixelFormat:` and
    /// `minimumTextureBufferAlignmentForPixelFormat:`.
    pub struct FormatAlignmentsResponse {
        pub linear_texture: u64,
        pub texture_buffer: u64,
    }

    /// `sparseTileSizeWithTextureType:pixelFormat:sampleCount:`.
    pub struct SparseTileRequest {
        pub texture_type: u64,
        pub pixel_format: u64,
        pub sample_count: u64,
    }

    /// Texels per tile, zero when the texture cannot be sparse.
    pub struct SparseTileResponse {
        pub size: [u64; 3],
    }

    /// `MTLRegion` of one mipmap level and slice.
    pub struct RegionRecord {
        pub slice: u64,
        pub level: u64,
        pub origin: [u64; 3],
        pub size: [u64; 3],
    }

    /// `replaceRegion:…` from `bytes`, or `getBytes:…` into them.
    pub struct TextureBytesRequest {
        pub texture: u64,
        pub region: RegionRecord,
        pub bytes: Span,
        pub bytes_per_row: u64,
        pub bytes_per_image: u64,
    }

    /// `MTLSamplerDescriptor`; address modes are s, t and r.
    pub struct SamplerDescriptorRecord {
        pub min_filter: u64,
        pub mag_filter: u64,
        pub mip_filter: u64,
        pub max_anisotropy: u64,
        pub address_modes: [u64; 3],
        pub border_color: u64,
        pub reduction_mode: u64,
        pub compare_function: u64,
        pub lod_min_clamp: f32,
        pub lod_max_clamp: f32,
        pub normalized_coordinates: u32,
        pub reserved: u32,
    }

    /// A new sampler and its `gpuResourceID`.
    pub struct SamplerResponse {
        pub handle: u64,
        pub resource_id: u64,
    }

    /// `MTLHeapDescriptor`, over imported memory when `memory` is nonzero,
    /// as a heap the CPU reaches is; the heap takes the handle.
    pub struct HeapDescriptorRecord {
        pub memory: u64,
        pub size: u64,
        pub options: u64,
        pub heap_type: u64,
        pub sparse_page_size: u64,
    }

    /// `heapBufferSizeAndAlignWithLength:options:`.
    pub struct HeapBufferSizeRequest {
        pub length: u64,
        pub options: u64,
    }

    /// `MTLSizeAndAlign`.
    pub struct SizeAndAlignRecord {
        pub size: u64,
        pub align: u64,
    }

    /// `newBufferWithLength:options:offset:` of a heap, or without an offset
    /// when it is `AUTOMATIC`.
    pub struct NewHeapBufferRequest {
        pub heap: u64,
        pub length: u64,
        pub options: u64,
        pub offset: u64,
    }

    /// `newTextureWithDescriptor:offset:` of a heap, or without an offset
    /// when it is `AUTOMATIC`.
    pub struct NewHeapTextureRequest {
        pub heap: u64,
        pub descriptor: TextureDescriptorRecord,
        pub offset: u64,
    }

    /// `maxAvailableSizeWithAlignment:` of a heap.
    pub struct HeapUsageRequest {
        pub heap: u64,
        pub alignment: u64,
    }

    /// `usedSize` and `maxAvailableSizeWithAlignment:`.
    pub struct HeapUsageResponse {
        pub used_size: u64,
        pub max_available_size: u64,
    }
}

records! {
    /// `MTLRenderPipelineColorAttachmentDescriptor`; pixel format zero
    /// leaves the attachment unused.
    pub struct ColorAttachmentRecord {
        pub pixel_format: u64,
        pub source_rgb_blend_factor: u64,
        pub destination_rgb_blend_factor: u64,
        pub rgb_blend_operation: u64,
        pub source_alpha_blend_factor: u64,
        pub destination_alpha_blend_factor: u64,
        pub alpha_blend_operation: u64,
        pub write_mask: u64,
        pub blending_enabled: u32,
        pub reserved: u32,
    }

    /// The attachments and rasterization a render pipeline draws with.
    pub struct RenderTargetsRecord {
        pub color_attachments: [ColorAttachmentRecord; 8],
        pub depth_attachment_pixel_format: u64,
        pub stencil_attachment_pixel_format: u64,
        pub raster_sample_count: u64,
        pub alpha_to_coverage_enabled: u32,
        pub alpha_to_one_enabled: u32,
        pub rasterization_enabled: u32,
        pub reserved: u32,
    }

    /// An attribute of a vertex or stage-input descriptor, at its index;
    /// format zero leaves it unused.
    pub struct AttributeRecord {
        pub format: u64,
        pub offset: u64,
        pub buffer_index: u64,
    }

    /// A buffer layout of a vertex or stage-input descriptor, at its
    /// buffer index; only those its attributes read are taken.
    pub struct LayoutRecord {
        pub stride: u64,
        pub step_function: u64,
        pub step_rate: u64,
    }

    /// `MTLVertexDescriptor`.
    pub struct VertexDescriptorRecord {
        pub attributes: [AttributeRecord; 31],
        pub layouts: [LayoutRecord; 31],
    }

    /// `MTLStageInputOutputDescriptor`.
    pub struct StageInputRecord {
        pub attributes: [AttributeRecord; 31],
        pub layouts: [LayoutRecord; 31],
        pub index_type: u64,
        pub index_buffer_index: u64,
    }

    /// A render pipeline's tessellation state.
    pub struct TessellationRecord {
        pub partition_mode: u64,
        pub max_tessellation_factor: u64,
        pub factor_format: u64,
        pub control_point_index_type: u64,
        pub factor_step_function: u64,
        pub output_winding_order: u64,
        pub factor_scale_enabled: u32,
        pub reserved: u32,
    }

    /// `MTLLinkedFunctions` and the stage's call stack depth: spans of
    /// function and library handles.
    pub struct LinkedFunctionsRecord {
        pub functions: Span,
        pub private_functions: Span,
        pub libraries: Span,
        pub max_call_stack_depth: u64,
    }

    /// `newRenderPipelineStateWithDescriptor:`; a zero fragment function
    /// is none.
    pub struct NewRenderPipelineRequest {
        pub vertex_function: u64,
        pub fragment_function: u64,
        pub input_primitive_topology: u64,
        pub max_vertex_amplification_count: u64,
        pub targets: RenderTargetsRecord,
        pub vertex_descriptor: VertexDescriptorRecord,
        pub tessellation: TessellationRecord,
        pub vertex_linked_functions: LinkedFunctionsRecord,
        pub fragment_linked_functions: LinkedFunctionsRecord,
        /// `PipelineFlags`.
        pub flags: u64,
    }

    /// `newRenderPipelineStateWithMeshDescriptor:`; zero object and
    /// fragment functions are none.
    /// `MTLMeshRenderPipelineDescriptor`; zero total threads leave the
    /// device's limits, and `flags` may say each stage's threadgroup sizes
    /// are multiples of the thread execution width.
    pub struct NewMeshPipelineRequest {
        pub object_function: u64,
        pub mesh_function: u64,
        pub fragment_function: u64,
        pub max_vertex_amplification_count: u64,
        pub max_total_threads_per_object_threadgroup: u64,
        pub max_total_threads_per_mesh_threadgroup: u64,
        pub payload_memory_length: u64,
        /// `PipelineFlags`.
        pub flags: u64,
        pub targets: RenderTargetsRecord,
        pub object_linked_functions: LinkedFunctionsRecord,
        pub mesh_linked_functions: LinkedFunctionsRecord,
        pub fragment_linked_functions: LinkedFunctionsRecord,
    }

    /// A new render pipeline and its `gpuResourceID`, zero when indirect
    /// command buffers cannot switch to it; a mesh pipeline's threadgroup
    /// properties, zero for others and for a missing object stage.
    pub struct RenderPipelineResponse {
        pub handle: u64,
        pub resource_id: u64,
        pub max_total_threads_per_object_threadgroup: u64,
        pub max_total_threads_per_mesh_threadgroup: u64,
        pub object_thread_execution_width: u64,
        pub mesh_thread_execution_width: u64,
    }

    /// `newComputePipelineStateWithDescriptor:`; zero total threads leaves
    /// the device's limit.
    pub struct NewComputePipelineRequest {
        pub compute_function: u64,
        pub max_total_threads_per_threadgroup: u64,
        pub stage_input: StageInputRecord,
        pub linked_functions: LinkedFunctionsRecord,
        /// `PipelineFlags`.
        pub flags: u64,
    }

    /// A new compute pipeline: its `gpuResourceID` (zero when indirect
    /// command buffers cannot switch to it),
    /// `maxTotalThreadsPerThreadgroup`, `threadExecutionWidth` and
    /// `staticThreadgroupMemoryLength`.
    pub struct ComputePipelineResponse {
        pub handle: u64,
        pub resource_id: u64,
        pub max_total_threads_per_threadgroup: u64,
        pub thread_execution_width: u64,
        pub static_threadgroup_memory_length: u64,
    }

    /// `functionHandleWithFunction:` (`stage` zero) or
    /// `functionHandleWithFunction:stage:` (one `MTLRenderStages` bit).
    pub struct FunctionHandleRequest {
        pub pipeline: u64,
        pub function: u64,
        pub stage: u64,
    }

    /// A function handle's value, zero when the pipeline does not link the
    /// function.
    pub struct FunctionHandleResponse {
        pub value: u64,
    }

    /// `newVisibleFunctionTableWithDescriptor:`.
    pub struct NewFunctionTableRequest {
        pub function_count: u64,
    }

    /// `setFunctions:withRange:` from a span of handle values, zero for
    /// none.
    pub struct SetFunctionsRequest {
        pub table: u64,
        pub index: u64,
        pub handles: Span,
    }
}

records! {
    /// A 64-bit value: an event's, a serial, a byte count.
    pub struct Value {
        pub value: u64,
    }

    /// `setSignaledValue:` of an event.
    pub struct EventValueRequest {
        pub event: u64,
        pub value: u64,
    }

    /// `waitUntilSignaledValue:timeoutMS:` of an event, in nanoseconds.
    pub struct WaitEventRequest {
        pub event: u64,
        pub value: u64,
        pub timeout: u64,
    }

    /// Whether a wait saw its value before its timeout.
    pub struct WaitResponse {
        pub reached: u32,
        pub reserved: u32,
    }

    /// `newCounterSampleBufferWithDescriptor:` of a `CounterSetCode`.
    pub struct NewCounterBufferRequest {
        pub counter_set: u64,
        pub sample_count: u64,
    }

    /// `resolveCounterRange:` into a span of 64-bit values.
    pub struct ResolveCountersRequest {
        pub buffer: u64,
        pub first: u64,
        pub count: u64,
        pub out: Span,
    }

    /// Whether the samples were resolved (`resolveCounterRange:` answers
    /// nil while a timestamp is pending) and their length.
    pub struct ResolveCountersResponse {
        pub resolved: u32,
        pub reserved: u32,
        pub length: u64,
    }

    /// `sampleTimestamps:gpuTimestamp:`.
    pub struct TimestampsResponse {
        pub cpu: u64,
        pub gpu: u64,
    }

    /// `GPUStartTime` and `GPUEndTime` in timestamp ticks, which the
    /// frontend converts with `sampleTimestamps:gpuTimestamp:`.
    pub struct CommandBufferTimesResponse {
        pub start: u64,
        pub end: u64,
    }
}

raw_enum! {
    /// The `MTLCounterSet`s the device samples, which the frontend names.
    pub enum CounterSetCode: u64 {
        Timestamp = 0,
        Statistic = 1,
    }
}

records! {
    /// `newIndirectCommandBufferWithDescriptor:maxCommandCount:options:`:
    /// an `MTLIndirectCommandType` set and the `IndirectInherits` set.
    pub struct NewIndirectRequest {
        pub command_types: u64,
        pub inherits: u64,
        pub max_command_count: u64,
        pub max_vertex_buffer_bind_count: u64,
        pub max_fragment_buffer_bind_count: u64,
        pub max_kernel_buffer_bind_count: u64,
        pub max_kernel_threadgroup_memory_bind_count: u64,
        pub max_object_buffer_bind_count: u64,
        pub max_mesh_buffer_bind_count: u64,
        pub support_ray_tracing: u32,
        pub support_dynamic_attribute_stride: u32,
    }

    /// `EncodeIndirect`: a stream of `IndirectTarget`ed entries for the
    /// buffer's commands.
    pub struct EncodeIndirectRequest {
        pub buffer: u64,
        pub commands: Span,
    }
}

option_set! {
    /// The state an indirect command buffer's commands inherit from the
    /// encoder that executes them.
    pub struct IndirectInherits: u64 {
        const PIPELINE_STATE = 1 << 0;
        const BUFFERS = 1 << 1;
        const CULL_MODE = 1 << 2;
        const DEPTH_STENCIL_STATE = 1 << 3;
        const DEPTH_BIAS = 1 << 4;
        const DEPTH_CLIP_MODE = 1 << 5;
        const FRONT_FACING_WINDING = 1 << 6;
        const TRIANGLE_FILL_MODE = 1 << 7;
    }
}

option_set! {
    /// What a pipeline request asks besides its records.
    pub struct PipelineFlags: u64 {
        /// The request's vertex or stage-input descriptor is set.
        const DESCRIBED_INPUT = 1 << 0;
        /// `supportIndirectCommandBuffers`.
        const INDIRECT_COMMAND_BUFFERS = 1 << 1;
        /// `threadGroupSizeIsMultipleOfThreadExecutionWidth`.
        const THREADGROUP_SIZE_IS_MULTIPLE_OF_WIDTH = 1 << 2;
        /// `objectThreadgroupSizeIsMultipleOfThreadExecutionWidth`.
        const OBJECT_THREADGROUP_SIZE_IS_MULTIPLE_OF_WIDTH = 1 << 3;
        /// `meshThreadgroupSizeIsMultipleOfThreadExecutionWidth`.
        const MESH_THREADGROUP_SIZE_IS_MULTIPLE_OF_WIDTH = 1 << 4;
    }
}

/// The offset of a resource the heap places itself.
pub const AUTOMATIC: u64 = u64::MAX;
/// `ResolveCounters`' 64-bit values per sample of the statistic counter set; a
/// timestamp sample is one.
pub const STATISTIC_SAMPLE_VALUES: u64 = 8;
const _: () = assert!(
    STATISTIC_SAMPLE_VALUES * size_of::<u64>() as u64
        == crate::metal::command_buffer::counters::STATISTIC_SAMPLE_BYTES
);

/// A binding, member or element without a `TypeInfo`: a datum.
pub const NO_TYPE: u32 = u32::MAX;

raw_enum! {
    /// How an operation ended.
    pub enum Status: u32 {
        Ok = 0,
        /// The call violates Metal's API contract.
        Invalid = 1,
        /// Valid Metal this device cannot honor.
        Unsupported = 2,
        OutOfMemory = 3,
        DeviceLost = 4,
        UnknownOperation = 5,
        /// A record of the wrong size, or a value its type does not name.
        Malformed = 6,
        /// A handle this connection does not hold, or holds for another
        /// kind of object.
        StaleHandle = 7,
        /// The connection is unknown or closed.
        Closed = 8,
        /// A span's page is not mapped for the caller now, as any page of a
        /// task may not be: the frontend touches it and calls again.
        Unmapped = 9,
    }
}

/// A failed operation: its status and why.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fault {
    pub status: Status,
    pub reason: &'static str,
}

impl Fault {
    pub const MALFORMED: Self = Self::new(Status::Malformed, "malformed record");
    pub const STALE: Self = Self::new(Status::StaleHandle, "unknown or destroyed handle");
    pub const CLOSED: Self = Self::new(Status::Closed, "the connection is closed");

    pub const fn new(status: Status, reason: &'static str) -> Self {
        Self { status, reason }
    }

    /// A value its type does not name.
    pub const fn malformed(reason: &'static str) -> Self {
        Self::new(Status::Malformed, reason)
    }
}

impl From<Error> for Fault {
    fn from(error: Error) -> Self {
        match error {
            Error::Invalid(reason) => Self::new(Status::Invalid, reason),
            Error::Unsupported(capability) => Self::new(Status::Unsupported, capability),
            Error::OutOfMemory => Self::new(Status::OutOfMemory, "out of memory"),
            Error::DeviceLost => Self::new(Status::DeviceLost, "the device was lost"),
        }
    }
}

impl From<TableError> for Fault {
    fn from(error: TableError) -> Self {
        match error {
            TableError::StaleHandle => Self::STALE,
            TableError::Full => {
                Self::new(Status::OutOfMemory, "the connection holds too many objects")
            }
            TableError::OutOfMemory => Self::new(Status::OutOfMemory, "out of memory"),
            TableError::WrongConnection | TableError::WrongEpoch | TableError::Closed => {
                Self::CLOSED
            }
        }
    }
}

/// Declares the operations: their codes, grouped by area in the high byte,
/// and their request and response records.
macro_rules! operations {
    ($($(#[$meta:meta])* $name:ident = $code:expr => $request:ty, $response:ty;)*) => {
        raw_enum! {
            pub enum Operation: u32 {
                $($(#[$meta])* $name = $code,)*
            }
        }

        impl Operation {
            /// The sizes of the operation's request and response records.
            pub const fn sizes(self) -> (usize, usize) {
                match self {
                    $(Self::$name => (
                        core::mem::size_of::<$request>(),
                        core::mem::size_of::<$response>(),
                    ),)*
                }
            }
        }
    };
}

operations! {
    /// Agrees on the protocol version.
    Negotiate = 0x0001 => NegotiateRequest, NegotiateResponse;
    /// The device's capability block.
    Capabilities = 0x0002 => Empty, Block;
    /// Releases an object; the device keeps what other objects and
    /// in-flight work still use.
    Release = 0x0003 => Handle, Empty;
    /// `newLibraryWithData:`.
    NewLibrary = 0x0101 => NewLibraryRequest, Handle;
    /// `functionNames`.
    LibraryFunctionNames = 0x0102 => LibraryFunctionNamesRequest, Length;
    /// `type` and `installName`.
    LibraryIdentity = 0x0107 => LibraryIdentityRequest, LibraryIdentityResponse;
    /// The bytes `serializeToURL:` writes.
    LibraryData = 0x0108 => LibraryDataRequest, Length;
    /// `newFunctionWithName:constantValues:`.
    NewFunction = 0x0103 => NewFunctionRequest, Handle;
    /// What `MTLFunction` reports of the function.
    FunctionReflection = 0x0104 => FunctionReflectionRequest, FunctionReflectionResponse;
    /// `MTLPipelineOptionBindingInfo`'s bindings of a function, which a
    /// pipeline's reflection gathers from its functions, and the layouts
    /// of `newArgumentEncoderWithBufferIndex:`.
    FunctionBindings = 0x0105 => FunctionBindingsRequest, FunctionBindingsResponse;
    /// The layout of `newArgumentEncoderWithArguments:`.
    ArgumentLayout = 0x0106 => ArgumentLayoutRequest, ArgumentLayoutResponse;
    /// `newBufferWithLength:options:`.
    NewBuffer = 0x0201 => NewBufferRequest, BufferResponse;
    /// `didModifyRange:`.
    BufferDidModifyRange = 0x0202 => BufferRangeRequest, Empty;
    /// `newTextureWithDescriptor:`.
    NewTexture = 0x0203 => TextureDescriptorRecord, TextureResponse;
    NewTextureView = 0x0204 => NewTextureViewRequest, TextureResponse;
    NewBufferTexture = 0x0205 => NewBufferTextureRequest, TextureResponse;
    ReplaceRegion = 0x0206 => TextureBytesRequest, Empty;
    GetBytes = 0x0207 => TextureBytesRequest, Empty;
    /// `newSamplerStateWithDescriptor:`.
    NewSampler = 0x0208 => SamplerDescriptorRecord, SamplerResponse;
    /// `newHeapWithDescriptor:`.
    NewHeap = 0x0209 => HeapDescriptorRecord, Handle;
    HeapBufferSizeAndAlign = 0x020a => HeapBufferSizeRequest, SizeAndAlignRecord;
    /// `heapTextureSizeAndAlignWithDescriptor:`.
    HeapTextureSizeAndAlign = 0x020b => TextureDescriptorRecord, SizeAndAlignRecord;
    NewHeapBuffer = 0x020c => NewHeapBufferRequest, BufferResponse;
    NewHeapTexture = 0x020d => NewHeapTextureRequest, TextureResponse;
    HeapUsage = 0x020e => HeapUsageRequest, HeapUsageResponse;
    /// `makeAliasable` of a heap buffer or texture.
    MakeAliasable = 0x020f => Handle, Empty;
    /// The frontend runs a deallocator once the last command buffer that
    /// used the buffer completes.
    NewImportedBuffer = 0x0210 => NewImportedBufferRequest, BufferResponse;
    FormatAlignments = 0x0211 => PixelFormatRequest, FormatAlignmentsResponse;
    SparseTileSize = 0x0212 => SparseTileRequest, SparseTileResponse;
    NewRenderPipeline = 0x0301 => NewRenderPipelineRequest, RenderPipelineResponse;
    NewMeshPipeline = 0x0302 => NewMeshPipelineRequest, RenderPipelineResponse;
    NewComputePipeline = 0x0303 => NewComputePipelineRequest, ComputePipelineResponse;
    FunctionHandle = 0x0304 => FunctionHandleRequest, FunctionHandleResponse;
    /// A visible function table: a buffer of function handle values whose
    /// `gpuAddress` is the table's `gpuResourceID`.
    NewFunctionTable = 0x0305 => NewFunctionTableRequest, BufferResponse;
    SetFunctions = 0x0306 => SetFunctionsRequest, Empty;
    /// `newEvent` and `newSharedEvent`.
    NewEvent = 0x0401 => Empty, Handle;
    /// `signaledValue`.
    EventSignaledValue = 0x0402 => Handle, Value;
    SetEventSignaledValue = 0x0403 => EventValueRequest, Empty;
    WaitEvent = 0x0404 => WaitEventRequest, WaitResponse;
    NewCounterBuffer = 0x0405 => NewCounterBufferRequest, Handle;
    ResolveCounters = 0x0406 => ResolveCountersRequest, ResolveCountersResponse;
    SampleTimestamps = 0x0407 => Empty, TimestampsResponse;
    /// `currentAllocatedSize`.
    AllocatedSize = 0x0408 => Empty, Value;
    /// Submits ready work and answers the completed serial.
    Poll = 0x0409 => Empty, Value;
    /// Replays a command stream into a command buffer, submits it and
    /// answers its serial.
    Commit = 0x040b => commands::CommitRequest, Value;
    /// The GPU times of the completed command buffer with a serial.
    CommandBufferTimes = 0x040c => Value, CommandBufferTimesResponse;
    NewIndirectCommandBuffer = 0x0501 => NewIndirectRequest, Handle;
    /// `gpuResourceID`, which makes the buffer GPU-resident.
    IndirectResourceId = 0x0502 => Handle, Value;
    /// Encodes commands from the CPU (`indirectRenderCommandAtIndex:`,
    /// `indirectComputeCommandAtIndex:`).
    EncodeIndirect = 0x0503 => EncodeIndirectRequest, Empty;
    /// `resetWithRange:`.
    ResetIndirect = 0x0504 => commands::IndirectRange, Empty;
}

pub mod commands;
