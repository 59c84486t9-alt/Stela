//! The command stream `Commit` replays into one command buffer.
//!
//! A stream is a run of entries, each a [`CommandHeader`], the command's
//! record and the variable data the command takes, padded to 8 bytes.
//! Commands keep Metal's encoding rules: one encoder at a time, opened by
//! its `Begin*` command and closed by `EndEncoding`. Handles name objects of
//! the committing connection, zero for nil; sizes are `MTLSize`s and
//! origins `MTLOrigin`s.
use super::{Record, Span};

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

    /// A region of one slice and mipmap level of a texture.
    pub struct RegionRecord {
        pub slice: u64,
        pub level: u64,
        pub origin: [u64; 3],
        pub size: [u64; 3],
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
    }
}

/// A command's code, grouped by encoder in the high byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandCode {
    CommandBuffer(CommandBufferCode),
    Compute(ComputeCode),
    Blit(BlitCode),
}

impl CommandCode {
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw >> 8 {
            0x00 => CommandBufferCode::from_raw(raw).map(Self::CommandBuffer),
            0x01 => ComputeCode::from_raw(raw).map(Self::Compute),
            0x02 => BlitCode::from_raw(raw).map(Self::Blit),
            _ => None,
        }
    }
}
