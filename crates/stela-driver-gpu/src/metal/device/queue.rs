//! Command buffers, submission, completion, events and counters.
//!
//! Every `MTLCommandQueue` submits to the device's one universal queue in
//! commit order, which satisfies Metal's per-queue ordering and makes fences
//! between queues hold by construction. Command buffer `n` signals `n` on
//! the queue's timeline semaphore; [`Device::poll`] retires everything up to
//! the completed value.
//!
//! An indirect sparse mapping update splits its command buffer: the segments
//! from the update's on are held until the GPU has copied its arguments,
//! when the device reads them, makes the binds and submits the segments.
//! Command buffers committed meanwhile are held behind them, keeping the
//! queue's order; polling and waiting submit held work as it becomes ready.
use super::{
    BufferId, ComputePipelineId, CounterBufferId, Device, EventId, RenderPipelineId, Slab,
    TextureId,
};
use crate::metal::{
    abi::{
        LoadAction, MultisampleDepthResolveFilter, MultisampleStencilResolveFilter, StoreAction,
        StoreActionOptions,
    },
    binding::ResourceId,
    command_buffer::{
        BufferRef, CommandBuffer, ComputePipelineState, DynamicFeatures, MappedRange, Recording,
        RenderPipelineState, Resolver, Segment,
        counters::{self, CounterRange, CounterSample, STATISTIC_SAMPLE_BYTES},
        generated::{GeneratedLayoutKey, IndirectRenderClass},
        render::PassBoundary,
    },
    error::{Error, Result, ensure, require},
    indirect::{IndirectCommandBuffer, IndirectCommandBufferId, RecordLayout},
    pass::{
        self, AttachedTexture, AttachmentDescriptor, AttachmentView, RenderPassDescriptor,
        RenderPassPlan, RenderingAttachment, Target,
    },
    pipeline::MAX_COLOR_ATTACHMENTS,
    resource::TextureDescriptor,
    shader::{Compiler, Specialization},
    sparse::{MAP_INDIRECT_ARGUMENTS_BYTES, Mapping, MappingRequest, MappingUpdate},
    upload::{Chunk, ChunkSource},
    vulkan::{
        BufferCreate, BufferUsage, MemoryProperties, PipelineStages, PipelineStatistics,
        backend::{Backend, BufferAllocation, Object, Requirements},
        command::Command,
        object::{
            BufferInfo, ExecutionSet, ImageView, IndirectCommandsLayout, Memory, MemoryRequest,
            Pipeline, QueryPool, QueryPoolInfo, QueryType, Semaphore,
        },
    },
};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

/// Queries per occlusion, statistics or timestamp pool.
const POOL_QUERIES: u32 = 256;

/// Completed command buffers whose GPU times are kept.
const TIMES_KEPT: usize = 1024;

/// A `MTLCounterSet` the device samples.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterSet {
    Timestamp,
    Statistic,
}

/// A counter sample buffer's samples.
#[derive(Clone, Copy, Debug)]
enum CounterStorage {
    Timestamps(QueryPool),
    /// `MTLCounterResultStatistic`s in host-visible memory, initially
    /// `MTLCounterErrorValue`.
    Statistics(BufferAllocation),
}

#[derive(Clone, Copy, Debug)]
struct CounterBuffer {
    storage: CounterStorage,
    count: u32,
}

/// What a submitted command buffer holds until it completes.
#[derive(Debug)]
struct InFlight {
    serial: u64,
    chunks: Vec<Chunk>,
    pools: Vec<(QueryType, QueryPool)>,
    invalidations: Vec<MappedRange>,
    /// The pool, among `pools`, whose first two queries time the command
    /// buffer.
    times: Option<QueryPool>,
}

/// Segments of a committed command buffer that the host submits: either all
/// of them, or those from an indirect mapping update's on.
#[derive(Debug)]
struct Held {
    serial: u64,
    /// The step value the copy of the update's arguments signals; zero
    /// when only the held work ahead delays the segments.
    step: u64,
    segments: Vec<Segment>,
    /// Mapping operations by index into `segments`.
    mappings: Vec<(usize, Mapping)>,
}

#[derive(Debug, Default)]
pub(super) struct Queue {
    /// Upload chunks with their memory; free ones are reused.
    chunks: Vec<(Chunk, Memory)>,
    free_chunks: Vec<Chunk>,
    free_pools: Vec<(QueryType, QueryPool)>,
    in_flight: Vec<InFlight>,
    events: Slab<Semaphore>,
    counters: Slab<CounterBuffer>,
    /// Committed work not yet submitted, in commit order.
    held: VecDeque<Held>,
    /// Signals each indirect mapping update's step once its arguments are
    /// copied; created with the first.
    steps: Option<Semaphore>,
    step: u64,
    /// GPU start and end ticks of the latest completed command buffers, by
    /// serial, oldest first.
    times: VecDeque<(u64, [u64; 2])>,
}

/// One attachment of a [`RenderPassRequest`].
#[derive(Clone, Copy, Debug)]
pub struct AttachmentRequest<Clear> {
    pub texture: TextureId,
    pub level: u64,
    pub slice: u64,
    pub depth_plane: u64,
    /// (texture, level, slice, depth plane).
    pub resolve: Option<(TextureId, u64, u64, u64)>,
    pub load_action: LoadAction,
    pub store_action: StoreAction,
    pub store_action_options: StoreActionOptions,
    pub clear: Clear,
}

/// `MTLRenderPassDescriptor` with the device's object ids.
#[derive(Clone, Debug)]
pub struct RenderPassRequest {
    pub color_attachments: [Option<AttachmentRequest<[f64; 4]>>; MAX_COLOR_ATTACHMENTS],
    pub depth_attachment: Option<AttachmentRequest<f64>>,
    pub depth_resolve_filter: MultisampleDepthResolveFilter,
    pub stencil_attachment: Option<AttachmentRequest<u32>>,
    pub stencil_resolve_filter: MultisampleStencilResolveFilter,
    pub visibility_result_buffer: Option<BufferId>,
    pub render_target_array_length: u64,
    pub render_target_width: u64,
    pub render_target_height: u64,
    pub default_raster_sample_count: u64,
    pub tile_memory: bool,
    pub sample_positions: Vec<[f32; 2]>,
    pub rasterization_rate_map: bool,
    /// `sampleBufferAttachments`: (sample buffer, sample index, boundary).
    pub counter_samples: Vec<(CounterBufferId, u32, PassBoundary)>,
}

impl<B: Backend, C: Compiler> Device<B, C> {
    /// `commandBuffer` of any queue.
    pub fn new_command_buffer(&self) -> CommandBuffer {
        CommandBuffer::new(DynamicFeatures::new(&self.capabilities))
    }

    /// The services encoding calls need.
    pub fn resolver(&mut self) -> DeviceResolver<'_, B, C> {
        DeviceResolver { device: self }
    }

    /// `renderCommandEncoderWithDescriptor:`.
    pub fn begin_render(
        &mut self,
        commands: &mut CommandBuffer,
        request: &RenderPassRequest,
    ) -> Result<()> {
        // Copy the descriptors so the pass can borrow them while views are
        // created.
        let textures = self.pass_textures(request)?;
        let lookup = |id: TextureId| {
            textures
                .iter()
                .find(|(known, _)| *known == id)
                .map(|(_, descriptor)| descriptor)
        };
        let target = |id: TextureId, level, slice, depth_plane| -> Result<Target<'_, TextureId>> {
            let descriptor = lookup(id).ok_or(Error::Invalid("unknown texture"))?;
            Ok(Target {
                texture: AttachedTexture {
                    texture: id,
                    descriptor,
                },
                level,
                slice,
                depth_plane,
            })
        };
        fn attachment<'a, Clear: Copy>(
            request: &AttachmentRequest<Clear>,
            target: &impl Fn(TextureId, u64, u64, u64) -> Result<Target<'a, TextureId>>,
        ) -> Result<AttachmentDescriptor<'a, TextureId, Clear>> {
            Ok(AttachmentDescriptor {
                target: target(
                    request.texture,
                    request.level,
                    request.slice,
                    request.depth_plane,
                )?,
                resolve: request
                    .resolve
                    .map(|(texture, level, slice, plane)| target(texture, level, slice, plane))
                    .transpose()?,
                load_action: request.load_action,
                store_action: request.store_action,
                store_action_options: request.store_action_options,
                clear: request.clear,
            })
        }
        let mut color_attachments = [None; MAX_COLOR_ATTACHMENTS];
        for (slot, color) in color_attachments.iter_mut().zip(&request.color_attachments) {
            *slot = color
                .as_ref()
                .map(|color| attachment(color, &target))
                .transpose()?;
        }
        let descriptor = RenderPassDescriptor {
            color_attachments,
            depth_attachment: request
                .depth_attachment
                .as_ref()
                .map(|depth| attachment(depth, &target))
                .transpose()?,
            depth_resolve_filter: request.depth_resolve_filter,
            stencil_attachment: request
                .stencil_attachment
                .as_ref()
                .map(|stencil| attachment(stencil, &target))
                .transpose()?,
            stencil_resolve_filter: request.stencil_resolve_filter,
            visibility_results: request.visibility_result_buffer.is_some(),
            render_target_array_length: request.render_target_array_length,
            render_target_width: request.render_target_width,
            render_target_height: request.render_target_height,
            default_raster_sample_count: request.default_raster_sample_count,
            tile_memory: request.tile_memory,
            sample_positions: request.sample_positions.clone(),
            rasterization_rate_map: request.rasterization_rate_map,
        };
        let plan = pass::render_pass(&self.capabilities, &descriptor)?;
        let plan = self.resolve_views(plan)?;
        let visibility = request
            .visibility_result_buffer
            .map(|buffer| self.buffer(buffer))
            .transpose()?;
        let samples = request
            .counter_samples
            .iter()
            .map(|&(counters, index, boundary)| {
                Ok((self.counter_sample(counters, index)?, boundary))
            })
            .collect::<Result<Vec<_>>>()?;
        commands.begin_render(&mut self.resolver(), plan, visibility, samples)
    }

    fn pass_textures(
        &self,
        request: &RenderPassRequest,
    ) -> Result<Vec<(TextureId, TextureDescriptor)>> {
        let colors = request
            .color_attachments
            .iter()
            .flatten()
            .flat_map(|color| [Some(color.texture), color.resolve.map(|r| r.0)]);
        let depth = request
            .depth_attachment
            .iter()
            .flat_map(|depth| [Some(depth.texture), depth.resolve.map(|r| r.0)]);
        let stencil = request
            .stencil_attachment
            .iter()
            .flat_map(|stencil| [Some(stencil.texture), stencil.resolve.map(|r| r.0)]);
        colors
            .chain(depth)
            .chain(stencil)
            .flatten()
            .map(|id| Ok((id, *self.texture_descriptor(id)?)))
            .collect()
    }

    /// Replaces texture ids in a pass plan with attachment views.
    fn resolve_views(
        &mut self,
        plan: RenderPassPlan<TextureId>,
    ) -> Result<RenderPassPlan<ImageView>> {
        let mut view = |view: AttachmentView<TextureId>| -> Result<AttachmentView<ImageView>> {
            let key = AttachmentView {
                texture: (),
                view_type: view.view_type,
                range: view.range,
            };
            let image_view = self.attachment_view(view.texture, key)?;
            Ok(AttachmentView {
                texture: image_view,
                view_type: view.view_type,
                range: view.range,
            })
        };
        let mut attachment =
            |attachment: RenderingAttachment<TextureId>| -> Result<RenderingAttachment<ImageView>> {
                Ok(RenderingAttachment {
                    view: view(attachment.view)?,
                    resolve: attachment
                        .resolve
                        .map(|(mode, resolve)| Ok::<_, Error>((mode, view(resolve)?)))
                        .transpose()?,
                    load_op: attachment.load_op,
                    store_op: attachment.store_op,
                    clear: attachment.clear,
                    store_action: attachment.store_action,
                })
            };
        let color = plan
            .color
            .into_iter()
            .map(|color| color.map(&mut attachment).transpose())
            .collect::<Result<_>>()?;
        let depth = plan.depth.map(&mut attachment).transpose()?;
        let stencil = plan.stencil.map(&mut attachment).transpose()?;
        Ok(RenderPassPlan {
            extent: plan.extent,
            layer_count: plan.layer_count,
            color,
            depth,
            stencil,
            sample_count: plan.sample_count,
            color_formats: plan.color_formats,
            depth_format: plan.depth_format,
            stencil_format: plan.stencil_format,
            visibility_results: plan.visibility_results,
            sample_locations: plan.sample_locations,
        })
    }

    /// `commit`: submits the command buffer and returns its serial. A
    /// command buffer that cannot be submitted is discarded.
    pub fn commit(&mut self, mut commands: CommandBuffer) -> Result<u64> {
        let serial = self.submitted + 1;
        let completion = (self.timeline, serial);
        let finished = self
            .flush_indirect_writes()
            .and_then(|()| commands.finish(&mut self.resolver(), completion));
        let recording = commands.into_recording();
        if let Err(error) = finished.and_then(|()| self.check_mappings(&recording.mappings)) {
            self.recycle(recording);
            return Err(error);
        }
        let mut held = self.hold(serial, recording.segments, recording.mappings)?;
        let mut pools = recording.query_pools;
        let times = self.time(&mut held)?;
        pools.extend(times.map(|pool| (QueryType::Timestamp, pool)));
        // CPU-copy writes reach the images first, after the opening barrier
        // and outside the command buffer's GPU times.
        let uploads = self.take_cpu_copy_uploads();
        held[0].segments[0].commands.splice(1..1, uploads);
        let mut chunks = Vec::with_capacity(recording.uploads.len());
        for (chunk, bytes) in &recording.uploads {
            let memory = self.chunk_memory(chunk.buffer)?;
            self.backend.write_memory(memory, 0, bytes)?;
            chunks.push(*chunk);
        }
        self.submitted = serial;
        self.queue.in_flight.push(InFlight {
            serial,
            chunks,
            pools,
            invalidations: recording.invalidations,
            times,
        });
        self.queue.held.extend(held);
        self.advance()?;
        Ok(serial)
    }

    /// Brackets a command buffer's work with timestamps for `GPUStartTime`
    /// and `GPUEndTime`; `None` without timestamps.
    fn time(&mut self, held: &mut [Held]) -> Result<Option<QueryPool>> {
        if self.capabilities.timestamp_frequency == 0 {
            return Ok(None);
        }
        let (pool, _) = self.resolver().query_pool(QueryType::Timestamp)?;
        held[0].segments[0].commands.insert(
            1,
            Command::WriteTimestamp {
                pool,
                query: 0,
                stage: PipelineStages::TOP_OF_PIPE,
            },
        );
        let last = held.last_mut().and_then(|held| held.segments.last_mut());
        last.expect("a segment")
            .commands
            .push(Command::WriteTimestamp {
                pool,
                query: 1,
                stage: PipelineStages::ALL_COMMANDS,
            });
        Ok(Some(pool))
    }

    /// `GPUStartTime` and `GPUEndTime` of the completed command buffer with
    /// `serial`, in timestamp ticks; the latest [`TIMES_KEPT`] are kept.
    pub fn command_buffer_times(&self, serial: u64) -> Result<[u64; 2]> {
        ensure(
            serial != 0 && serial <= self.completed,
            "the command buffer has not completed",
        )?;
        require(self.capabilities.timestamp_frequency != 0, "GPU times")?;
        let times = &self.queue.times;
        let found = times.binary_search_by_key(&serial, |&(serial, _)| serial);
        found
            .map(|index| times[index].1)
            .map_err(|_| Error::Invalid("the command buffer's GPU times are no longer kept"))
    }

    /// Drops a command buffer that will not be committed.
    pub fn discard(&mut self, commands: CommandBuffer) {
        self.recycle(commands.into_recording());
    }

    /// Takes back the upload chunks and query pools of a recording that was
    /// never submitted, so its queries are still reset.
    fn recycle(&mut self, recording: Recording) {
        let chunks = recording.uploads.into_iter().map(|(chunk, _)| chunk);
        self.queue.free_chunks.extend(chunks);
        self.queue.free_pools.extend(recording.query_pools);
    }

    fn check_mappings(&self, mappings: &[(usize, Mapping)]) -> Result<()> {
        for (_, mapping) in mappings {
            match mapping {
                Mapping::Request(request) => self.check_mapping(request)?,
                // The region is checked once the host reads it.
                Mapping::Indirect { image, .. } => {
                    self.sparse_texture(*image)?;
                }
            }
        }
        Ok(())
    }

    /// Splits a command buffer before each segment whose mapping operations
    /// include an indirect update; the segment before it, which copies the
    /// arguments, signals the next step.
    fn hold(
        &mut self,
        serial: u64,
        mut segments: Vec<Segment>,
        mut mappings: Vec<(usize, Mapping)>,
    ) -> Result<Vec<Held>> {
        let mut starts: Vec<_> = mappings
            .iter()
            .filter(|(_, mapping)| matches!(mapping, Mapping::Indirect { .. }))
            .map(|(segment, _)| *segment)
            .collect();
        starts.dedup();
        let rebase = |mappings: Vec<(usize, Mapping)>, base: usize| {
            mappings
                .into_iter()
                .map(|(segment, mapping)| (segment - base, mapping))
                .collect()
        };
        let mut held = Vec::with_capacity(starts.len() + 1);
        let (mut base, mut step) = (0, 0);
        for start in starts {
            let rest = segments.split_off(start - base);
            let steps = match self.queue.steps {
                Some(steps) => steps,
                None => *self.queue.steps.insert(self.backend.create_semaphore(0)?),
            };
            self.queue.step += 1;
            let copy = segments.last_mut().expect("the arguments' copy");
            copy.signals.push((steps, self.queue.step));
            let later = mappings.split_off(mappings.partition_point(|(at, _)| *at < start));
            held.push(Held {
                serial,
                step,
                segments,
                mappings: rebase(mappings, base),
            });
            (base, step, segments, mappings) = (start, self.queue.step, rest, later);
        }
        held.push(Held {
            serial,
            step,
            segments,
            mappings: rebase(mappings, base),
        });
        Ok(held)
    }

    /// Submits held work, in order, as far as its arguments are readable.
    fn advance(&mut self) -> Result<()> {
        while let Some(held) = self.queue.held.front() {
            if self.lost {
                return Err(Error::DeviceLost);
            }
            if held.step > 0 {
                let steps = self.queue.steps.expect("steps have their semaphore");
                if self.backend.semaphore_value(steps)? < held.step {
                    break;
                }
            }
            let held = self.queue.held.pop_front().expect("held work");
            // A failed submission never signals; record the loss so waits end.
            self.submit_held(held).inspect_err(|_| self.lost = true)?;
        }
        Ok(())
    }

    /// Makes held segments' binds, reading indirect regions from the copies
    /// of their arguments, and submits the segments. Metal leaves regions
    /// outside a texture undefined, as it does textures destroyed while in
    /// use; neither maps anything.
    fn submit_held(&mut self, mut held: Held) -> Result<()> {
        for (segment, mapping) in held.mappings {
            let request = match mapping {
                Mapping::Request(request) => request,
                Mapping::Indirect {
                    image,
                    mode,
                    arguments,
                } => {
                    let memory = self.chunk_memory(arguments.buffer)?;
                    let mut bytes = [0; MAP_INDIRECT_ARGUMENTS_BYTES];
                    self.backend
                        .read_memory(memory, arguments.offset, &mut bytes)?;
                    MappingRequest::Update {
                        image,
                        mode,
                        updates: alloc::vec![MappingUpdate::from_indirect(&bytes)],
                    }
                }
            };
            if self.check_mapping(&request).is_ok() {
                let binds = self.sparse_binds(&request)?;
                held.segments[segment].binds.extend(binds);
            }
        }
        self.backend.submit(&held.segments)
    }

    /// Waits for the held work ahead of `serial`, or all of it, to be
    /// submitted; `false` when a step's wait times out.
    fn submit_held_through(&mut self, serial: u64, timeout: u64) -> Result<bool> {
        self.advance()?;
        while let Some(held) = self.queue.held.front().filter(|held| held.serial <= serial) {
            let steps = self.queue.steps.expect("steps have their semaphore");
            if !self.backend.wait_semaphore(steps, held.step, timeout)? {
                return Ok(false);
            }
            self.advance()?;
        }
        Ok(true)
    }

    fn chunk_memory(&self, buffer: crate::metal::vulkan::object::Buffer) -> Result<Memory> {
        let found = self
            .queue
            .chunks
            .iter()
            .find(|(chunk, _)| chunk.buffer == buffer);
        found
            .map(|(_, memory)| *memory)
            .ok_or(Error::Invalid("unknown upload chunk"))
    }

    /// Submits ready held work, retires completed command buffers and
    /// returns the completed serial.
    pub fn poll(&mut self) -> Result<u64> {
        self.advance()?;
        if self.lost {
            return Err(Error::DeviceLost);
        }
        let completed = self.backend.semaphore_value(self.timeline)?;
        self.retire(completed)?;
        Ok(completed)
    }

    /// `waitUntilCompleted` for the command buffer with `serial`; `timeout`
    /// bounds each wait for held work, then the command buffer's.
    pub fn wait(&mut self, serial: u64, timeout: u64) -> Result<bool> {
        ensure(
            serial <= self.submitted,
            "the command buffer was not committed",
        )?;
        if self.lost {
            return Err(Error::DeviceLost);
        }
        if !self.submit_held_through(serial, timeout)? {
            return Ok(false);
        }
        let reached = self
            .backend
            .wait_semaphore(self.timeline, serial, timeout)?;
        self.poll()?;
        Ok(reached)
    }

    /// Recycles what completed work held, keeps its GPU times and destroys
    /// what it kept alive; a failed invalidation or read is answered once
    /// the bookkeeping is done.
    fn retire(&mut self, completed: u64) -> Result<()> {
        if completed <= self.completed {
            return Ok(());
        }
        self.completed = completed;
        let (done, pending): (Vec<_>, Vec<_>) = core::mem::take(&mut self.queue.in_flight)
            .into_iter()
            .partition(|flight| flight.serial <= completed);
        self.queue.in_flight = pending;
        let mut outcome = Ok(());
        for flight in done {
            // Before deferred destruction, which may free the memory.
            for range in flight.invalidations {
                outcome = outcome.and(self.backend.invalidate_memory(
                    range.memory,
                    range.offset,
                    range.length,
                ));
            }
            // Before the pool is reset.
            if let Some(pool) = flight.times {
                let mut times = [0; 2];
                match self.backend.query_results(pool, 0, &mut times) {
                    Ok(true) => self.keep_times(flight.serial, times),
                    Ok(false) => {}
                    Err(error) => outcome = outcome.and(Err(error)),
                }
            }
            self.queue.free_chunks.extend(flight.chunks);
            for (query_type, pool) in flight.pools {
                self.backend.reset_queries(pool, 0, POOL_QUERIES);
                self.queue.free_pools.push((query_type, pool));
            }
        }
        let (ready, waiting): (Vec<_>, Vec<_>) = core::mem::take(&mut self.deferred)
            .into_iter()
            .partition(|(serial, _)| *serial <= completed);
        self.deferred = waiting;
        ready
            .into_iter()
            .for_each(|(_, object)| self.backend.destroy(object));
        self.descriptors.retire(completed);
        self.execution_sets.retire(completed);
        outcome
    }

    fn keep_times(&mut self, serial: u64, times: [u64; 2]) {
        let kept = &mut self.queue.times;
        if kept.len() == TIMES_KEPT {
            kept.pop_front();
        }
        kept.push_back((serial, times));
    }

    /// `newEvent` and `newSharedEvent`: both are timeline semaphores.
    pub fn new_event(&mut self) -> Result<EventId> {
        let semaphore = self.backend.create_semaphore(0)?;
        Ok(EventId(self.queue.events.insert(semaphore)))
    }

    /// The semaphore command buffers signal and wait on.
    pub fn event_semaphore(&self, id: EventId) -> Result<Semaphore> {
        self.queue.events.get(id.0).copied()
    }

    /// `signaledValue` of a shared event.
    pub fn signaled_value(&mut self, id: EventId) -> Result<u64> {
        let semaphore = self.event_semaphore(id)?;
        self.backend.semaphore_value(semaphore)
    }

    /// `setSignaledValue:` from the CPU; timeline values only increase.
    pub fn set_signaled_value(&mut self, id: EventId, value: u64) -> Result<()> {
        let semaphore = self.event_semaphore(id)?;
        let current = self.backend.semaphore_value(semaphore)?;
        if value > current {
            self.backend.signal_semaphore(semaphore, value)?;
        }
        Ok(())
    }

    /// `waitUntilSignaledValue:timeoutMS:`. Held work may signal the event,
    /// so it is submitted first; `timeout` bounds each wait.
    pub fn wait_event(&mut self, id: EventId, value: u64, timeout: u64) -> Result<bool> {
        let semaphore = self.event_semaphore(id)?;
        if self.backend.semaphore_value(semaphore)? >= value {
            return Ok(true);
        }
        if !self.submit_held_through(self.submitted, timeout)? {
            return Ok(false);
        }
        self.backend.wait_semaphore(semaphore, value, timeout)
    }

    pub fn destroy_event(&mut self, id: EventId) -> Result<()> {
        let semaphore = self.queue.events.remove(id.0)?;
        self.defer(Object::Semaphore(semaphore));
        Ok(())
    }

    /// `newCounterSampleBufferWithDescriptor:`.
    pub fn new_counter_sample_buffer(
        &mut self,
        set: CounterSet,
        count: u32,
    ) -> Result<CounterBufferId> {
        ensure(count > 0, "counter sample buffers hold samples")?;
        let storage = match set {
            CounterSet::Timestamp => {
                require(
                    self.capabilities.timestamp_frequency != 0,
                    "timestamp counters",
                )?;
                let info = QueryPoolInfo {
                    query_type: QueryType::Timestamp,
                    count,
                    statistics: PipelineStatistics::EMPTY,
                };
                let pool = self.backend.create_query_pool(&info)?;
                self.backend.reset_queries(pool, 0, count);
                CounterStorage::Timestamps(pool)
            }
            CounterSet::Statistic => {
                require(self.capabilities.statistic_counters, "statistic counters")?;
                let size = u64::from(count) * STATISTIC_SAMPLE_BYTES;
                let info = BufferInfo {
                    size,
                    usage: BufferUsage::TRANSFER_SRC
                        | BufferUsage::TRANSFER_DST
                        | BufferUsage::STORAGE_BUFFER
                        | BufferUsage::SHADER_DEVICE_ADDRESS,
                    flags: BufferCreate::EMPTY,
                };
                let request = MemoryRequest {
                    required: MemoryProperties::HOST_VISIBLE | MemoryProperties::HOST_COHERENT,
                    preferred: MemoryProperties::HOST_CACHED,
                    mapped: true,
                };
                let allocation = self.backend.create_buffer(&info, request)?;
                let unsampled = alloc::vec![0xff; size as usize];
                if let Err(error) = self.backend.write_memory(allocation.memory, 0, &unsampled) {
                    self.backend.destroy(Object::Buffer(allocation.buffer));
                    self.backend.destroy(Object::Memory(allocation.memory));
                    return Err(error);
                }
                self.allocated += allocation.allocated;
                CounterStorage::Statistics(allocation)
            }
        };
        let buffer = CounterBuffer { storage, count };
        Ok(CounterBufferId(self.queue.counters.insert(buffer)))
    }

    fn counter_buffer(&self, id: CounterBufferId) -> Result<CounterBuffer> {
        self.queue.counters.get(id.0).copied()
    }

    /// Where sample `index` of `id` lands.
    pub fn counter_sample(&self, id: CounterBufferId, index: u32) -> Result<CounterSample> {
        let buffer = self.counter_buffer(id)?;
        ensure(
            index < buffer.count,
            "sample index beyond the counter sample buffer",
        )?;
        Ok(match buffer.storage {
            CounterStorage::Timestamps(pool) => CounterSample::Timestamp { pool, query: index },
            CounterStorage::Statistics(allocation) => CounterSample::Statistic(
                allocation.address + u64::from(index) * STATISTIC_SAMPLE_BYTES,
            ),
        })
    }

    /// The samples `resolveCounters:inRange:…` copies.
    pub fn counter_range(
        &self,
        id: CounterBufferId,
        first: u32,
        count: u32,
    ) -> Result<CounterRange> {
        let buffer = self.counter_buffer(id)?;
        ensure(
            first
                .checked_add(count)
                .is_some_and(|end| end <= buffer.count),
            "range beyond the counter sample buffer",
        )?;
        Ok(match buffer.storage {
            CounterStorage::Timestamps(pool) => CounterRange::Timestamps { pool, first, count },
            CounterStorage::Statistics(allocation) => CounterRange::Statistics(BufferRef {
                buffer: allocation.buffer,
                offset: u64::from(first) * STATISTIC_SAMPLE_BYTES,
                address: allocation.address + u64::from(first) * STATISTIC_SAMPLE_BYTES,
                length: u64::from(count) * STATISTIC_SAMPLE_BYTES,
            }),
        })
    }

    /// `resolveCounterRange:` on the CPU, as 64-bit values. Timestamps are
    /// `None` while a sample is pending; statistics read as their command
    /// buffers last wrote them, which Metal resolves only after completion.
    pub fn resolve_counters(
        &mut self,
        id: CounterBufferId,
        first: u32,
        count: u32,
    ) -> Result<Option<Vec<u64>>> {
        let buffer = self.counter_buffer(id)?;
        ensure(
            first
                .checked_add(count)
                .is_some_and(|end| end <= buffer.count),
            "range beyond the counter sample buffer",
        )?;
        match buffer.storage {
            CounterStorage::Timestamps(pool) => {
                let mut results = alloc::vec![0; count as usize];
                Ok(self
                    .backend
                    .query_results(pool, first, &mut results)?
                    .then_some(results))
            }
            CounterStorage::Statistics(allocation) => {
                let mut bytes =
                    alloc::vec![0; (u64::from(count) * STATISTIC_SAMPLE_BYTES) as usize];
                let offset = u64::from(first) * STATISTIC_SAMPLE_BYTES;
                self.backend
                    .read_memory(allocation.memory, offset, &mut bytes)?;
                let values = bytes
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|&value| u64::from_le_bytes(value))
                    .collect();
                Ok(Some(values))
            }
        }
    }

    pub fn destroy_counter_sample_buffer(&mut self, id: CounterBufferId) -> Result<()> {
        let buffer = self.queue.counters.remove(id.0)?;
        match buffer.storage {
            CounterStorage::Timestamps(pool) => self.defer(Object::QueryPool(pool)),
            CounterStorage::Statistics(allocation) => {
                self.defer(Object::Buffer(allocation.buffer));
                self.release_memory(allocation.memory, allocation.allocated);
            }
        }
        Ok(())
    }

    /// `sampleTimestamps:gpuTimestamp:`.
    pub fn sample_timestamps(&mut self) -> Result<(u64, u64)> {
        self.backend.calibrated_timestamps()
    }
}

/// [`Resolver`] over a device.
pub struct DeviceResolver<'a, B: Backend, C: Compiler> {
    device: &'a mut Device<B, C>,
}

/// Upload chunks: host-visible memory the GPU reads and copies from,
/// preferably device-local (resizable BAR). Internal kernels also write
/// scratch there, such as the select kernel's conditional rendering flags.
const CHUNK_USAGE: BufferUsage = BufferUsage::SHADER_DEVICE_ADDRESS
    .union(BufferUsage::STORAGE_BUFFER)
    .union(BufferUsage::UNIFORM_BUFFER)
    .union(BufferUsage::VERTEX_BUFFER)
    .union(BufferUsage::INDEX_BUFFER)
    .union(BufferUsage::INDIRECT_BUFFER)
    .union(BufferUsage::CONDITIONAL_RENDERING)
    .union(BufferUsage::TRANSFER_SRC)
    .union(BufferUsage::TRANSFER_DST);

/// Upload chunks' memory.
const CHUNK_MEMORY: MemoryRequest = MemoryRequest {
    required: MemoryProperties::HOST_VISIBLE.union(MemoryProperties::HOST_COHERENT),
    preferred: MemoryProperties::DEVICE_LOCAL,
    mapped: true,
};

impl<B: Backend, C: Compiler> ChunkSource for DeviceResolver<'_, B, C> {
    fn acquire(&mut self, bytes: u64) -> Result<Chunk> {
        let queue = &mut self.device.queue;
        if let Some(index) = queue
            .free_chunks
            .iter()
            .position(|chunk| chunk.size >= bytes)
        {
            return Ok(queue.free_chunks.swap_remove(index));
        }
        // Generated commands preprocess into chunks too.
        let generated = self
            .device
            .backend
            .physical_device()
            .limits
            .generated_commands;
        let usage = CHUNK_USAGE.with(BufferUsage::PREPROCESS_BUFFER, generated.is_some());
        let info = BufferInfo {
            size: bytes,
            usage,
            flags: BufferCreate::EMPTY,
        };
        let allocation = self.device.backend.create_buffer(&info, CHUNK_MEMORY)?;
        let chunk = Chunk {
            buffer: allocation.buffer,
            address: allocation.address,
            size: bytes,
        };
        self.device.queue.chunks.push((chunk, allocation.memory));
        Ok(chunk)
    }
}

impl<B: Backend, C: Compiler> Resolver for DeviceResolver<'_, B, C> {
    fn compute_pipeline(
        &mut self,
        state: &ComputePipelineState,
        specialization: &Specialization,
    ) -> Result<Pipeline> {
        self.device.compute_variant(state.id, specialization)
    }

    fn clamped_sampler(
        &mut self,
        sampler: ResourceId,
        lod_min: f32,
        lod_max: f32,
    ) -> Result<ResourceId> {
        self.device.clamped_sampler(sampler, lod_min, lod_max)
    }

    fn mesh_pipeline(
        &mut self,
        state: &RenderPipelineState,
        object: [u32; 3],
        mesh: [u32; 3],
    ) -> Result<Pipeline> {
        self.device.mesh_variant(state.id, object, mesh)
    }

    fn query_pool(&mut self, query_type: QueryType) -> Result<(QueryPool, u32)> {
        let free = &mut self.device.queue.free_pools;
        if let Some(index) = free.iter().position(|&(free, _)| free == query_type) {
            return Ok((free.swap_remove(index).1, POOL_QUERIES));
        }
        let statistics = if query_type == QueryType::PipelineStatistics {
            counters::STATISTICS
        } else {
            PipelineStatistics::EMPTY
        };
        let info = QueryPoolInfo {
            query_type,
            count: POOL_QUERIES,
            statistics,
        };
        let pool = self.device.backend.create_query_pool(&info)?;
        self.device.backend.reset_queries(pool, 0, POOL_QUERIES);
        Ok((pool, POOL_QUERIES))
    }

    fn render_pipeline_state(&mut self, id: u64) -> Result<RenderPipelineState> {
        let id = u32::try_from(id).map_err(|_| Error::Invalid("unknown pipeline"))?;
        self.device
            .render_pipeline_state(RenderPipelineId(id))
            .cloned()
    }

    fn compute_pipeline_state(&mut self, id: u64) -> Result<ComputePipelineState> {
        let id = u32::try_from(id).map_err(|_| Error::Invalid("unknown pipeline"))?;
        self.device
            .compute_pipeline_state(ComputePipelineId(id))
            .cloned()
    }

    fn indirect_commands(
        &mut self,
        id: IndirectCommandBufferId,
    ) -> Result<Arc<IndirectCommandBuffer>> {
        self.device.indirect_snapshot(id)
    }

    fn indirect_records(
        &mut self,
        id: IndirectCommandBufferId,
    ) -> Result<(RecordLayout, BufferRef)> {
        self.device.indirect_records(id)
    }

    fn indirect_render_classes(&mut self) -> Vec<IndirectRenderClass> {
        self.device.indirect_render_classes()
    }

    fn indirect_compute_set(&mut self) -> Option<(ExecutionSet, Pipeline)> {
        self.device.indirect_compute_set()
    }

    fn generated_layout(
        &mut self,
        key: &GeneratedLayoutKey,
        set: Option<ExecutionSet>,
        sequences: u32,
    ) -> Result<(IndirectCommandsLayout, Requirements)> {
        self.device
            .generated_layout(key, set, sequences, CHUNK_MEMORY)
    }

    fn update_indirect_commands(
        &mut self,
        id: IndirectCommandBufferId,
        update: &mut dyn FnMut(&mut IndirectCommandBuffer) -> Result<()>,
    ) -> Result<()> {
        update(self.device.indirect_command_buffer_mut(id)?)
    }
}
