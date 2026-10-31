//! `MTLCommandBuffer` recording: encoders lowered to Vulkan commands.
//!
//! A command buffer records into segments. Encoding a wait for an event
//! starts a new segment that waits on the event's timeline semaphore, and
//! encoding a signal ends the current one, so each segment is one
//! `VkSubmitInfo2` of one Vulkan command buffer. Every segment begins with a
//! full barrier, which orders it after everything submitted earlier on the
//! queue; the [`Hazards`] tracker adds barriers inside a segment.
//!
//! Encoder state is the command buffer's: one encoder is active at a time,
//! as in Metal. Its operations are in [`render`], [`compute`] and [`blit`].
use super::{
    binding::{ArgumentTable, BufferBinding, PushConstants, ResourceId},
    error::{Error, Result, ensure},
    hazard::{FULL, Hazards, Use},
    indirect::{IndirectCommandBuffer, IndirectCommandBufferId, IndirectPipeline, RecordLayout},
    pipeline::{ComputePipelinePlan, RenderPipelinePlan},
    shader::{Interface, Specialization, Stage},
    sparse::Mapping,
    upload::{Chunk, ChunkSource, Upload, UploadArena},
    vulkan::{
        backend::Requirements,
        command::{Command, SparseBind},
        object::{
            Buffer, ExecutionSet, IndirectCommandsLayout, Memory, Pipeline, QueryPool, QueryType,
            Semaphore,
        },
    },
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};

pub mod blit;
pub mod compute;
pub mod counters;
pub mod generated;
pub mod indirect;
pub mod render;
pub mod resource_state;

/// A Metal buffer as commands see it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferRef {
    pub buffer: Buffer,
    /// Where the Metal buffer starts in `buffer`: zero for buffers with
    /// their own `VkBuffer`, nonzero for upload suballocations.
    pub offset: u64,
    /// The device address of the Metal buffer's first byte.
    pub address: u64,
    pub length: u64,
}

/// The mapped bytes of a managed buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappedRange {
    pub memory: Memory,
    pub offset: u64,
    pub length: u64,
}

impl BufferRef {
    /// `offset` within the Metal buffer as an offset within `buffer`, when
    /// `bytes` from there fit.
    pub fn at(&self, offset: u64, bytes: u64) -> Result<u64> {
        let end = offset.checked_add(bytes).filter(|&end| end <= self.length);
        end.map(|_| self.offset + offset)
            .ok_or(Error::Invalid("range extends past the buffer"))
    }
}

/// A render pipeline state object.
#[derive(Clone, Debug, PartialEq)]
pub struct RenderPipelineState {
    /// The device's id for the state, which names its variants.
    pub id: u64,
    /// The Vulkan pipeline; `None` for mesh pipelines, which bind a variant
    /// per draw.
    pub pipeline: Option<Pipeline>,
    pub plan: RenderPipelinePlan,
    /// Interfaces of the pipeline's functions, by table slot.
    pub interfaces: Vec<Interface>,
    /// Its place in the execution sets when GPU-resident indirect commands
    /// can switch to it.
    pub indirect: Option<IndirectPipeline>,
}

/// A compute pipeline state object; its Vulkan pipelines are variants.
#[derive(Clone, Debug, PartialEq)]
pub struct ComputePipelineState {
    pub id: u64,
    pub plan: ComputePipelinePlan,
    pub interface: Interface,
    /// Its variant for GPU-resident indirect commands, when they can
    /// switch to it.
    pub indirect: Option<IndirectCompute>,
}

/// A compute pipeline's variant whose dispatches shape its threadgroups
/// ([`Specialization::dynamic_threadgroups`]), which GPU-resident indirect
/// commands run, and its place in the compute execution set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndirectCompute {
    pub pipeline: Pipeline,
    pub place: IndirectPipeline,
}

/// Device services encoding needs.
pub trait Resolver: ChunkSource {
    /// The compute pipeline for one specialization, compiled on first use.
    fn compute_pipeline(
        &mut self,
        state: &ComputePipelineState,
        specialization: &Specialization,
    ) -> Result<Pipeline>;

    /// A sampler like `sampler` with its LOD range clamped
    /// (`setSamplerState:lodMinClamp:lodMaxClamp:`).
    fn clamped_sampler(
        &mut self,
        sampler: ResourceId,
        lod_min: f32,
        lod_max: f32,
    ) -> Result<ResourceId>;

    /// The mesh pipeline variant for the object and mesh threadgroup sizes
    /// and object threadgroup memory of a draw, compiled on first use.
    fn mesh_pipeline(
        &mut self,
        state: &RenderPipelineState,
        object: [u32; 3],
        mesh: [u32; 3],
        object_lengths: &[(u32, u64)],
    ) -> Result<Pipeline>;

    /// A reset query pool of `query_type` and its query count; pipeline
    /// statistics pools count [`counters::STATISTICS`].
    fn query_pool(&mut self, query_type: QueryType) -> Result<(QueryPool, u32)>;

    /// The render pipeline state with device id `id`, which an indirect
    /// command names.
    fn render_pipeline_state(&mut self, id: u64) -> Result<RenderPipelineState>;

    /// The compute pipeline state with device id `id`.
    fn compute_pipeline_state(&mut self, id: u64) -> Result<ComputePipelineState>;

    /// The current contents of an indirect command buffer.
    fn indirect_commands(
        &mut self,
        id: IndirectCommandBufferId,
    ) -> Result<Arc<IndirectCommandBuffer>>;

    /// The live state classes of indirect-bindable render pipelines.
    fn indirect_render_classes(&mut self) -> Vec<generated::IndirectRenderClass>;

    /// The compute execution set and a live pipeline of it, while any
    /// indirect-bindable compute pipeline lives.
    fn indirect_compute_set(&mut self) -> Option<(ExecutionSet, Pipeline)>;

    /// The indirect commands layout of `key`, created on first use, and the
    /// preprocess memory `sequences` sequences of it need with `set` in
    /// upload memory.
    fn generated_layout(
        &mut self,
        key: &generated::GeneratedLayoutKey,
        set: Option<ExecutionSet>,
        sequences: u32,
    ) -> Result<(IndirectCommandsLayout, Requirements)>;

    /// The layout and buffer of an indirect command buffer's records,
    /// making it GPU-resident.
    fn indirect_records(
        &mut self,
        id: IndirectCommandBufferId,
    ) -> Result<(RecordLayout, BufferRef)>;

    /// Changes an indirect command buffer's contents, for blit resets and
    /// copies; a failed `update` leaves them unchanged.
    fn update_indirect_commands(
        &mut self,
        id: IndirectCommandBufferId,
        update: &mut dyn FnMut(&mut IndirectCommandBuffer) -> Result<()>,
    ) -> Result<()>;
}

/// Optional dynamic states the device enabled; see [`Capabilities`].
///
/// [`Capabilities`]: super::capabilities::Capabilities
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DynamicFeatures {
    pub depth_clamp: bool,
    pub polygon_mode: bool,
    pub sample_locations: bool,
}

impl DynamicFeatures {
    pub fn new(capabilities: &super::capabilities::Capabilities) -> Self {
        Self {
            depth_clamp: capabilities.depth_clamp,
            polygon_mode: capabilities.wireframe,
            sample_locations: capabilities.programmable_sample_positions,
        }
    }
}

/// One Vulkan submission of a command buffer.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Segment {
    pub waits: Vec<(Semaphore, u64)>,
    /// Sparse bindings applied after the waits and everything submitted
    /// before, ahead of `commands`.
    pub binds: Vec<SparseBind>,
    pub commands: Vec<Command>,
    pub signals: Vec<(Semaphore, u64)>,
}

/// A committed command buffer, ready for the queue.
#[derive(Debug)]
pub struct Recording {
    pub segments: Vec<Segment>,
    /// Upload chunks and the bytes to copy into them before submission;
    /// they return to the pool on completion.
    pub uploads: Vec<(Chunk, Vec<u8>)>,
    /// Query pools to reset and recycle on completion.
    pub query_pools: Vec<(QueryType, QueryPool)>,
    /// Sparse mapping operations and the segment whose binds they become.
    pub mappings: Vec<(usize, Mapping)>,
    /// Managed buffers to invalidate on completion, for the host to read
    /// what the GPU wrote.
    pub invalidations: Vec<MappedRange>,
}

/// One stage's argument table and whether the GPU copy is current.
#[derive(Clone, Debug, Default)]
struct Table {
    slots: ArgumentTable,
    buffers: [Option<BufferRef>; super::capabilities::MAX_BUFFER_BINDINGS as usize],
    address: Option<u64>,
}

/// Bindings shared by the stages of an encoder.
#[derive(Clone, Debug, Default)]
struct Bindings {
    tables: [Table; 3],
    constants: PushConstants,
    pushed: Option<PushConstants>,
}

impl Bindings {
    fn table(&mut self, stage: Stage) -> &mut Table {
        &mut self.tables[stage.table().raw() as usize]
    }

    fn set_buffer(
        &mut self,
        stage: Stage,
        buffer: Option<BufferRef>,
        offset: u64,
        index: u32,
    ) -> Result<()> {
        let slot = buffer_slot(index)?;
        let binding = match buffer {
            Some(buffer) => {
                ensure(offset <= buffer.length, "buffer offset beyond the buffer")?;
                BufferBinding {
                    address: buffer.address + offset,
                    length: buffer.length - offset,
                }
            }
            None => BufferBinding::default(),
        };
        let table = self.table(stage);
        table.slots.buffers[slot] = binding;
        table.buffers[slot] = buffer;
        table.address = None;
        Ok(())
    }

    /// `set*BufferOffset:atIndex:` keeps the buffer and moves its offset.
    fn set_buffer_offset(&mut self, stage: Stage, offset: u64, index: u32) -> Result<()> {
        let bound = self.table(stage).buffers[buffer_slot(index)?];
        let bound = bound.ok_or(Error::Invalid("no buffer is bound at that index"))?;
        self.set_buffer(stage, Some(bound), offset, index)
    }

    /// Unbinds the buffers of `stages`, keeping their textures and samplers.
    fn clear_buffers(&mut self, stages: &[Stage]) {
        for &stage in stages {
            let table = self.table(stage);
            if table.buffers.iter().any(Option::is_some) {
                table.slots.buffers = ArgumentTable::default().buffers;
                table.buffers = [None; super::capabilities::MAX_BUFFER_BINDINGS as usize];
                table.address = None;
            }
        }
    }

    fn set_texture(&mut self, stage: Stage, texture: ResourceId, index: u32) -> Result<()> {
        ensure(
            (index as usize) < self.tables[0].slots.textures.len(),
            "texture index exceeds the argument table",
        )?;
        let table = self.table(stage);
        table.slots.textures[index as usize] = texture;
        table.address = None;
        Ok(())
    }

    fn set_sampler(&mut self, stage: Stage, sampler: ResourceId, index: u32) -> Result<()> {
        ensure(
            (index as usize) < self.tables[0].slots.samplers.len(),
            "sampler index exceeds the argument table",
        )?;
        let table = self.table(stage);
        table.slots.samplers[index as usize] = sampler;
        table.address = None;
        Ok(())
    }

    /// Uploads changed tables of `stages` and pushes constants when they
    /// changed.
    fn flush(
        &mut self,
        recorder: &mut Recorder,
        resolver: &mut dyn Resolver,
        stages: &[Stage],
    ) -> Result<()> {
        for stage in stages {
            let slot = stage.table().raw() as usize;
            let table = &mut self.tables[slot];
            let address = match table.address {
                Some(address) => address,
                None => {
                    let upload = recorder.upload(
                        resolver,
                        &table.slots.encode(),
                        ArgumentTable::ALIGNMENT,
                    )?;
                    table.address = Some(upload.address);
                    upload.address
                }
            };
            self.constants.tables[slot] = address;
        }
        if self.pushed != Some(self.constants) {
            recorder.push(Command::PushConstants(self.constants));
            self.pushed = Some(self.constants);
        }
        Ok(())
    }

    /// Bindings carry over between encoders only through the table memory
    /// already uploaded; a new encoder starts empty, as Metal's do.
    fn reset(&mut self) {
        *self = Self::default();
    }
}

fn buffer_slot(index: u32) -> Result<usize> {
    ensure(
        index < super::capabilities::MAX_BUFFER_BINDINGS,
        "buffer index exceeds the argument table",
    )?;
    Ok(index as usize)
}

/// The command stream of a command buffer, independent of encoder state.
#[derive(Debug)]
struct Recorder {
    segments: Vec<Segment>,
    hazards: Hazards,
    uploads: UploadArena,
    query_pools: Vec<(QueryType, QueryPool)>,
    statistics: Option<counters::Statistics>,
    mappings: Vec<(usize, Mapping)>,
    invalidations: Vec<MappedRange>,
}

impl Recorder {
    fn new() -> Self {
        let mut recorder = Self {
            segments: Vec::new(),
            hazards: Hazards::default(),
            uploads: UploadArena::default(),
            query_pools: Vec::new(),
            statistics: None,
            mappings: Vec::new(),
            invalidations: Vec::new(),
        };
        recorder.start_segment(Vec::new());
        recorder
    }

    fn start_segment(&mut self, waits: Vec<(Semaphore, u64)>) {
        self.segments.push(Segment {
            waits,
            binds: Vec::new(),
            commands: alloc::vec![Command::Barrier(FULL)],
            signals: Vec::new(),
        });
        self.hazards = Hazards::default();
    }

    fn commands(&mut self) -> &mut Vec<Command> {
        &mut self
            .segments
            .last_mut()
            .expect("a command buffer always has a segment")
            .commands
    }

    fn push(&mut self, command: Command) {
        self.commands().push(command);
    }

    /// Orders `next` after the pending work it depends on.
    fn access(&mut self, next: Use) {
        if let Some(barrier) = self.hazards.access(next) {
            self.push(Command::Barrier(barrier));
        }
    }

    fn full_barrier(&mut self) {
        if let Some(barrier) = self.hazards.full() {
            self.push(Command::Barrier(barrier));
        }
    }

    fn upload(
        &mut self,
        resolver: &mut dyn Resolver,
        bytes: &[u8],
        alignment: u64,
    ) -> Result<Upload> {
        self.uploads.write(resolver, bytes, alignment)
    }
}

enum Encoder {
    None,
    Render(Box<render::RenderState>),
    Compute(Box<compute::ComputeState>),
    Blit,
    ResourceState,
}

/// A command buffer being encoded.
pub struct CommandBuffer {
    recorder: Recorder,
    bindings: Bindings,
    encoder: Encoder,
    features: DynamicFeatures,
}

impl CommandBuffer {
    pub fn new(features: DynamicFeatures) -> Self {
        Self {
            recorder: Recorder::new(),
            bindings: Bindings::default(),
            encoder: Encoder::None,
            features,
        }
    }

    fn idle(&self) -> Result<()> {
        ensure(
            matches!(self.encoder, Encoder::None),
            "another encoder is still encoding",
        )
    }

    /// Copies `set*Bytes` data into upload memory as a buffer of its own.
    fn upload_bytes(&mut self, resolver: &mut dyn Resolver, bytes: &[u8]) -> Result<BufferRef> {
        ensure(bytes.len() <= 4096, "set*Bytes holds at most 4 KiB")?;
        let upload = self.recorder.upload(resolver, bytes, 16)?;
        Ok(BufferRef {
            buffer: upload.buffer,
            offset: upload.offset,
            address: upload.address,
            length: bytes.len() as u64,
        })
    }

    /// `endEncoding` of the active encoder.
    pub fn end_encoding(&mut self, resolver: &mut dyn Resolver) -> Result<()> {
        match core::mem::replace(&mut self.encoder, Encoder::None) {
            Encoder::None => Err(Error::Invalid("no encoder is encoding")),
            Encoder::Render(state) => self.end_render(resolver, *state),
            Encoder::Compute(_) | Encoder::Blit | Encoder::ResourceState => Ok(()),
        }?;
        self.bindings.reset();
        Ok(())
    }

    /// `encodeSignalEvent:value:`: work encoded so far signals the event.
    pub fn encode_signal_event(
        &mut self,
        resolver: &mut dyn Resolver,
        event: Semaphore,
        value: u64,
    ) -> Result<()> {
        self.idle()?;
        // Statistics queries end with their segment.
        self.recorder.pause_statistics();
        self.recorder
            .segments
            .last_mut()
            .expect("a segment")
            .signals
            .push((event, value));
        self.recorder.start_segment(Vec::new());
        self.recorder.resume_statistics(resolver, false)
    }

    /// `encodeWaitForEvent:value:`: later work waits for the event.
    pub fn encode_wait_for_event(
        &mut self,
        resolver: &mut dyn Resolver,
        event: Semaphore,
        value: u64,
    ) -> Result<()> {
        self.idle()?;
        let current = self.recorder.segments.last().expect("a segment");
        // A segment holding only its opening barrier can take the wait.
        if current.commands.len() == 1 && current.signals.is_empty() {
            self.recorder
                .segments
                .last_mut()
                .expect("a segment")
                .waits
                .push((event, value));
            return Ok(());
        }
        self.recorder.pause_statistics();
        self.recorder.start_segment(alloc::vec![(event, value)]);
        self.recorder.resume_statistics(resolver, false)
    }

    /// `commit`: ends the commands; the last segment signals `completion`.
    /// Statistic samples not yet resolved are written last.
    pub fn finish(
        &mut self,
        resolver: &mut dyn Resolver,
        completion: (Semaphore, u64),
    ) -> Result<()> {
        self.idle()?;
        self.recorder.pause_statistics();
        self.recorder.resolve_statistics(resolver)?;
        let last = self.recorder.segments.last_mut().expect("a segment");
        last.signals.push(completion);
        // An empty trailing segment left by a final signal still carries the
        // completion signal; it orders after everything before it.
        Ok(())
    }

    /// The recording: once finished, for the queue to submit; otherwise
    /// for the device to take back what the commands acquired.
    pub fn into_recording(self) -> Recording {
        Recording {
            segments: self.recorder.segments,
            uploads: self.recorder.uploads.finish(),
            query_pools: self.recorder.query_pools,
            mappings: self.recorder.mappings,
            invalidations: self.recorder.invalidations,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
