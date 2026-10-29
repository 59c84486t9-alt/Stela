//! Command buffers, submission, completion, events and counters.
//!
//! Every `MTLCommandQueue` submits to the device's one universal queue in
//! commit order, which satisfies Metal's per-queue ordering and makes fences
//! between queues hold by construction. Command buffer `n` signals `n` on
//! the queue's timeline semaphore; [`Device::poll`] retires everything up to
//! the completed value.
use super::{BufferId, CounterBufferId, Device, EventId, Slab, TextureId};
use crate::gpu::metal::{
    abi::{
        LoadAction, MultisampleDepthResolveFilter, MultisampleStencilResolveFilter, StoreAction,
        StoreActionOptions,
    },
    binding::ResourceId,
    command_buffer::{
        BufferRef, CommandBuffer, ComputePipelineState, DynamicFeatures, RenderPipelineState,
        Resolver,
        counters::{self, CounterRange, CounterSample, STATISTIC_SAMPLE_BYTES},
        render::PassBoundary,
    },
    error::{Error, Result, ensure, require},
    pass::{
        self, AttachedTexture, AttachmentDescriptor, AttachmentView, RenderPassDescriptor,
        RenderPassPlan, RenderingAttachment, Target,
    },
    pipeline::MAX_COLOR_ATTACHMENTS,
    resource::TextureDescriptor,
    shader::{Compiler, Specialization},
    upload::{Chunk, ChunkSource},
    vulkan::{
        BufferCreate, BufferUsage, MemoryProperties, PipelineStatistics,
        backend::{Backend, BufferAllocation, Object},
        object::{
            BufferInfo, ImageView, Memory, MemoryRequest, Pipeline, QueryPool, QueryPoolInfo,
            QueryType, Semaphore,
        },
    },
};
use alloc::vec::Vec;

/// Queries per occlusion or statistics pool.
const POOL_QUERIES: u32 = 256;

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

    /// `commit`: submits the command buffer and returns its serial.
    pub fn commit(&mut self, commands: CommandBuffer) -> Result<u64> {
        let serial = self.submitted + 1;
        let completion = (self.timeline, serial);
        let mut recording = commands.commit(&mut self.resolver(), completion)?;
        let mappings = core::mem::take(&mut recording.mappings);
        for (_, request) in &mappings {
            self.check_mapping(request)?;
        }
        for (segment, request) in &mappings {
            let binds = self.sparse_binds(request)?;
            recording.segments[*segment].binds.extend(binds);
        }
        // CPU-copy writes reach the images first, after the opening barrier.
        let uploads = self.take_cpu_copy_uploads();
        recording.segments[0].commands.splice(1..1, uploads);
        let mut chunks = Vec::with_capacity(recording.uploads.len());
        for (chunk, bytes) in &recording.uploads {
            let memory = self.chunk_memory(chunk.buffer)?;
            self.backend.write_memory(memory, 0, bytes)?;
            chunks.push(*chunk);
        }
        let submitted = self.backend.submit(&recording.segments);
        self.submitted = serial;
        self.queue.in_flight.push(InFlight {
            serial,
            chunks,
            pools: recording.query_pools,
        });
        // A failed submission never signals; record the loss so waits end.
        submitted.inspect_err(|_| self.lost = true)?;
        Ok(serial)
    }

    fn chunk_memory(&self, buffer: crate::gpu::metal::vulkan::object::Buffer) -> Result<Memory> {
        let found = self
            .queue
            .chunks
            .iter()
            .find(|(chunk, _)| chunk.buffer == buffer);
        found
            .map(|(_, memory)| *memory)
            .ok_or(Error::Invalid("unknown upload chunk"))
    }

    /// Retires completed command buffers and returns the completed serial.
    pub fn poll(&mut self) -> Result<u64> {
        if self.lost {
            return Err(Error::DeviceLost);
        }
        let completed = self.backend.semaphore_value(self.timeline)?;
        self.retire(completed);
        Ok(completed)
    }

    /// `waitUntilCompleted` for the command buffer with `serial`.
    pub fn wait(&mut self, serial: u64, timeout: u64) -> Result<bool> {
        ensure(
            serial <= self.submitted,
            "the command buffer was not committed",
        )?;
        if self.lost {
            return Err(Error::DeviceLost);
        }
        let reached = self
            .backend
            .wait_semaphore(self.timeline, serial, timeout)?;
        self.poll()?;
        Ok(reached)
    }

    fn retire(&mut self, completed: u64) {
        if completed <= self.completed {
            return;
        }
        self.completed = completed;
        let (done, pending): (Vec<_>, Vec<_>) = core::mem::take(&mut self.queue.in_flight)
            .into_iter()
            .partition(|flight| flight.serial <= completed);
        self.queue.in_flight = pending;
        for flight in done {
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

    /// `waitUntilSignaledValue:timeoutMS:`.
    pub fn wait_event(&mut self, id: EventId, value: u64, timeout: u64) -> Result<bool> {
        let semaphore = self.event_semaphore(id)?;
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
/// preferably device-local (resizable BAR).
const CHUNK_USAGE: BufferUsage = BufferUsage::SHADER_DEVICE_ADDRESS
    .union(BufferUsage::STORAGE_BUFFER)
    .union(BufferUsage::UNIFORM_BUFFER)
    .union(BufferUsage::VERTEX_BUFFER)
    .union(BufferUsage::INDEX_BUFFER)
    .union(BufferUsage::INDIRECT_BUFFER)
    .union(BufferUsage::TRANSFER_SRC)
    .union(BufferUsage::TRANSFER_DST);

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
        let info = BufferInfo {
            size: bytes,
            usage: CHUNK_USAGE,
            flags: BufferCreate::EMPTY,
        };
        let request = MemoryRequest {
            required: MemoryProperties::HOST_VISIBLE | MemoryProperties::HOST_COHERENT,
            preferred: MemoryProperties::DEVICE_LOCAL,
            mapped: true,
        };
        let allocation = self.device.backend.create_buffer(&info, request)?;
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
}
