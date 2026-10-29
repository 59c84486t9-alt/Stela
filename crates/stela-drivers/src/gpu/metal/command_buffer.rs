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
    pipeline::{ComputePipelinePlan, RenderPipelinePlan},
    shader::{Interface, Specialization, Stage},
    upload::{Chunk, ChunkSource, Upload, UploadArena},
    vulkan::{
        PipelineStages,
        command::Command,
        object::{Buffer, Pipeline, QueryPool, Semaphore},
    },
};
use alloc::{boxed::Box, vec::Vec};

pub mod blit;
pub mod compute;
pub mod render;

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
}

/// A compute pipeline state object; its Vulkan pipelines are variants.
#[derive(Clone, Debug, PartialEq)]
pub struct ComputePipelineState {
    pub id: u64,
    pub plan: ComputePipelinePlan,
    pub interface: Interface,
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
    /// of a draw, compiled on first use.
    fn mesh_pipeline(
        &mut self,
        state: &RenderPipelineState,
        object: [u32; 3],
        mesh: [u32; 3],
    ) -> Result<Pipeline>;

    /// A reset occlusion query pool and its query count.
    fn occlusion_pool(&mut self) -> Result<(QueryPool, u32)>;
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
    /// Occlusion pools to recycle on completion.
    pub query_pools: Vec<QueryPool>,
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
    query_pools: Vec<QueryPool>,
}

impl Recorder {
    fn new() -> Self {
        let mut recorder = Self {
            segments: Vec::new(),
            hazards: Hazards::default(),
            uploads: UploadArena::default(),
            query_pools: Vec::new(),
        };
        recorder.start_segment(Vec::new());
        recorder
    }

    fn start_segment(&mut self, waits: Vec<(Semaphore, u64)>) {
        self.segments.push(Segment {
            waits,
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
            Encoder::Compute(_) | Encoder::Blit => Ok(()),
        }?;
        self.bindings.reset();
        Ok(())
    }

    /// `encodeSignalEvent:value:`: work encoded so far signals the event.
    pub fn encode_signal_event(&mut self, event: Semaphore, value: u64) -> Result<()> {
        self.idle()?;
        self.recorder
            .segments
            .last_mut()
            .expect("a segment")
            .signals
            .push((event, value));
        self.recorder.start_segment(Vec::new());
        Ok(())
    }

    /// `encodeWaitForEvent:value:`: later work waits for the event.
    pub fn encode_wait_for_event(&mut self, event: Semaphore, value: u64) -> Result<()> {
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
        } else {
            self.recorder.start_segment(alloc::vec![(event, value)]);
        }
        Ok(())
    }

    /// `commit`: the recording, whose last segment signals `completion`.
    pub fn commit(mut self, completion: (Semaphore, u64)) -> Result<Recording> {
        self.idle()?;
        let last = self.recorder.segments.last_mut().expect("a segment");
        last.signals.push(completion);
        // An empty trailing segment left by a final signal still carries the
        // completion signal; it orders after everything before it.
        Ok(Recording {
            segments: self.recorder.segments,
            uploads: self.recorder.uploads.finish(),
            query_pools: self.recorder.query_pools,
        })
    }

    /// `sampleCountersInBuffer:atSampleIndex:withBarrier:` outside render
    /// passes, and encoder-boundary samples: a timestamp after the work so
    /// far (`barrier`) or as soon as the GPU reaches it.
    pub fn sample_timestamp(&mut self, pool: QueryPool, index: u32, barrier: bool) -> Result<()> {
        ensure(
            !matches!(self.encoder, Encoder::Render(_)),
            "render passes sample at stage boundaries",
        )?;
        if barrier {
            self.recorder.full_barrier();
        }
        self.recorder.push(Command::ResetQueryPool {
            pool,
            first: index,
            count: 1,
        });
        let stage = if barrier {
            PipelineStages::ALL_COMMANDS
        } else {
            PipelineStages::TOP_OF_PIPE
        };
        self.recorder.push(Command::WriteTimestamp {
            pool,
            query: index,
            stage,
        });
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
