//! `MTLRenderCommandEncoder`.
//!
//! A render encoder is one Vulkan render pass instance, split only by
//! Metal memory barriers: the instance ends, a barrier orders the stages,
//! and an instance that loads every attachment resumes. Store actions,
//! resolves and the first instance's clears are patched into the
//! `vkCmdBeginRendering` commands when the encoder ends, after deferred
//! store actions are known.
//!
//! Patch draws are point-patch draws of the pipeline's tessellation stages,
//! each with an upload of its [`TessellationArguments`].
//!
//! Metal's clip space has y up and Vulkan's y down, so viewports are flipped
//! with a negative height; winding is defined in window space by both APIs
//! and maps unchanged.
use super::{
    BufferRef, CommandBuffer, Encoder, Recorder, RenderPipelineState, Resolver, buffer_slot,
    counters::CounterSample,
};
use crate::metal::{
    abi::{
        BarrierScope, CullMode as MtlCullMode, DepthClipMode, IndexType as MtlIndexType,
        PrimitiveTopologyClass, PrimitiveType, RenderStages, StoreAction, StoreActionOptions,
        TessellationControlPointIndexType, TriangleFillMode, VisibilityResultMode, Winding,
    },
    binding::{
        AccumulateArguments, BufferBinding, ResourceId, SequenceVertexBuffer, TessellationArguments,
    },
    capabilities::MAX_BUFFER_BINDINGS,
    error::{Error, Result, ensure},
    hazard::{RENDER_PASS, Use},
    pass::{AttachmentSlot, RenderPassPlan, RenderingAttachment},
    pipeline::{DepthStencilState, MAX_COLOR_ATTACHMENTS},
    shader::{Interface, MAX_PATCH_CONTROL_POINTS, Stage},
    vertex::{STRIDE_DYNAMIC, VertexDescriptor},
    vulkan::{
        Access, AttachmentLoadOp, AttachmentStoreOp, CullMode, FrontFace, IndexType,
        PipelineBindPoint, PipelineStages, PolygonMode, PrimitiveTopology, SampleCounts,
        command::{
            Attachment, Barrier, Command, DepthStencil, Rect, Rendering, VertexBuffer,
            Viewport as VkViewport,
        },
        object::{Buffer, ImageView, QueryPool, QueryType},
    },
};
use alloc::{boxed::Box, vec::Vec};

/// `MTLViewport`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Viewport {
    pub origin_x: f64,
    pub origin_y: f64,
    pub width: f64,
    pub height: f64,
    pub znear: f64,
    pub zfar: f64,
}

/// `MTLScissorRect`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScissorRect {
    pub x: u64,
    pub y: u64,
    pub width: u64,
    pub height: u64,
}

/// Where a render pass samples counters (`sampleBufferAttachments`).
/// Statistics count whole pass instances, so start boundaries sample before
/// the pass and end boundaries after it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassBoundary {
    StartOfVertex,
    EndOfVertex,
    StartOfFragment,
    EndOfFragment,
}

impl PassBoundary {
    const fn starts(self) -> bool {
        matches!(self, Self::StartOfVertex | Self::StartOfFragment)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct VertexBinding {
    buffer: BufferRef,
    offset: u64,
    /// `setVertexBuffer:offset:attributeStride:`.
    stride: Option<u64>,
}

/// `setTessellationFactorBuffer:offset:instanceStride:`.
#[derive(Clone, Copy, Debug)]
pub(super) struct FactorBuffer {
    buffer: BufferRef,
    offset: u64,
    instance_stride: u32,
}

/// The rasterizer state Metal sets per encoder and an indirect command may
/// set for itself: cull mode, winding, depth bias (constant, slope, clamp),
/// depth-stencil state, triangle fill mode and depth clip mode.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RasterState {
    pub cull_mode: MtlCullMode,
    pub winding: Winding,
    pub depth_bias: [f32; 3],
    pub depth_stencil: DepthStencilState,
    pub fill_mode: TriangleFillMode,
    pub clip_mode: DepthClipMode,
}

/// Metal's initial encoder values.
impl Default for RasterState {
    fn default() -> Self {
        Self {
            cull_mode: MtlCullMode::None,
            winding: Winding::Clockwise,
            depth_bias: [0.0; 3],
            depth_stencil: DepthStencilState::default(),
            fill_mode: TriangleFillMode::Fill,
            clip_mode: DepthClipMode::Clip,
        }
    }
}

/// What a patch draw reads besides the tessellation factors.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PatchSource {
    /// `numberOfPatchControlPoints`.
    pub control_points: u32,
    /// `patchIndexBuffer` and its offset: `uint` patch numbers.
    pub patch_indices: Option<(BufferRef, u64)>,
    /// `controlPointIndexBuffer` and its offset, for indexed patch draws.
    pub control_point_indices: Option<(BufferRef, u64)>,
}

/// The strides of the vertex buffers a patch draw's evaluation stage
/// fetches `function`'s stage-in from, by `layout`: each buffer is bound at
/// a multiple of four, and those of dynamic stride with a stride. Zero for
/// the buffers whose layout fixes it.
fn patch_strides(
    vertex_buffers: &[Option<VertexBinding>; 31],
    function: &Interface,
    layout: Option<&VertexDescriptor>,
) -> Result<[u32; 31]> {
    let mut strides = [0; 31];
    let Some(layout) = layout else {
        return Ok(strides);
    };
    for used in &function.attributes {
        let attribute = layout
            .attributes
            .iter()
            .find(|attribute| attribute.index == used.index)
            .ok_or(Error::Invalid(
                "stage-in attribute missing from the vertex descriptor",
            ))?;
        let index = attribute.buffer_index as usize;
        let bound = vertex_buffers
            .get(index)
            .copied()
            .flatten()
            .ok_or(Error::Invalid(
                "a vertex buffer the pipeline reads is unbound",
            ))?;
        ensure(
            bound.offset.is_multiple_of(4),
            "stage-in vertex buffers are bound at multiples of four",
        )?;
        let dynamic = layout.layouts.iter().any(|layout| {
            layout.buffer_index == attribute.buffer_index && layout.stride == STRIDE_DYNAMIC
        });
        if dynamic {
            let stride = bound.stride.ok_or(Error::Invalid(
                "a dynamic-stride vertex buffer was bound without a stride",
            ))?;
            ensure(
                stride.is_multiple_of(4),
                "vertex strides are multiples of four",
            )?;
            strides[index] =
                u32::try_from(stride).map_err(|_| Error::Invalid("vertex buffer stride"))?;
        }
    }
    Ok(strides)
}

/// Visibility queries of one pass: each mode change or pass restart ends
/// the active query, and offsets used by several queries are summed.
#[derive(Debug, Default)]
struct Visibility {
    buffer: Option<BufferRef>,
    mode: Option<(VisibilityResultMode, u64)>,
    pool: Option<(QueryPool, u32, u32)>,
    active: Option<(QueryPool, u32)>,
    /// (pool, query, offset), in query order.
    queries: Vec<(QueryPool, u32, u64)>,
}

pub(super) struct RenderState {
    pass: RenderPassPlan<ImageView>,
    /// Indices of this pass's `BeginRendering` commands in the segment.
    begins: Vec<usize>,
    pub(super) pipeline: Option<RenderPipelineState>,
    pub(super) vertex_buffers: [Option<VertexBinding>; 31],
    bound_vertex_buffers: [Option<VertexBuffer>; 31],
    index_buffer: Option<(Buffer, u64, IndexType)>,
    topology: Option<PrimitiveTopology>,
    restart: Option<bool>,
    pub(super) amplification: Vec<u32>,
    pub(super) factors: Option<FactorBuffer>,
    factor_scale: f32,
    pub(super) raster: RasterState,
    visibility: Visibility,
    samples: Vec<(CounterSample, PassBoundary)>,
    /// Timestamp queries the pass writes, reset before it begins.
    pub(super) timestamp_resets: Vec<(QueryPool, u32)>,
}

impl RenderState {
    /// The encoder's vertex buffers as a generated command sequence binds
    /// them, with their own strides.
    pub(super) fn sequence_vertex_buffers(
        &self,
    ) -> Result<[SequenceVertexBuffer; MAX_BUFFER_BINDINGS as usize]> {
        let mut buffers = [SequenceVertexBuffer::default(); MAX_BUFFER_BINDINGS as usize];
        for (buffer, bound) in buffers.iter_mut().zip(&self.vertex_buffers) {
            if let Some(bound) = bound {
                let size = bound.buffer.length - bound.offset;
                *buffer = SequenceVertexBuffer {
                    address: bound.buffer.address + bound.offset,
                    size: size.min(u32::MAX.into()) as u32,
                    stride: u32::try_from(bound.stride.unwrap_or(0))
                        .map_err(|_| Error::Invalid("vertex buffer stride"))?,
                };
            }
        }
        Ok(buffers)
    }
}

/// The Vulkan topology of a Metal primitive type.
pub(super) const fn primitive_topology(primitive: PrimitiveType) -> PrimitiveTopology {
    match primitive {
        PrimitiveType::Point => PrimitiveTopology::PointList,
        PrimitiveType::Line => PrimitiveTopology::LineList,
        PrimitiveType::LineStrip => PrimitiveTopology::LineStrip,
        PrimitiveType::Triangle => PrimitiveTopology::TriangleList,
        PrimitiveType::TriangleStrip => PrimitiveTopology::TriangleStrip,
    }
}

/// The active render encoder, borrowing only the encoder field so the
/// recorder and bindings stay available.
pub(super) fn render(encoder: &mut Encoder) -> Result<&mut RenderState> {
    match encoder {
        Encoder::Render(state) => Ok(state),
        _ => Err(Error::Invalid("no render command encoder is encoding")),
    }
}

impl CommandBuffer {
    /// `renderCommandEncoderWithDescriptor:` for a pass whose attachment
    /// views the device resolved.
    pub fn begin_render(
        &mut self,
        resolver: &mut dyn Resolver,
        pass: RenderPassPlan<ImageView>,
        visibility_buffer: Option<BufferRef>,
        samples: Vec<(CounterSample, PassBoundary)>,
    ) -> Result<()> {
        self.idle()?;
        ensure(
            pass.visibility_results == visibility_buffer.is_some(),
            "the visibility result buffer was not resolved",
        )?;
        self.bindings.reset();
        for &(sample, boundary) in &samples {
            if let (CounterSample::Statistic(destination), true) = (sample, boundary.starts()) {
                self.recorder.sample_statistics(resolver, destination)?;
            }
        }
        self.recorder.access(RENDER_PASS);
        self.recorder.pause_statistics();
        let begin = self.recorder.commands().len();
        self.recorder
            .push(Command::BeginRendering(rendering(&pass, true, true)));
        self.recorder.resume_statistics(resolver, false)?;
        let mut state = RenderState {
            pass,
            begins: alloc::vec![begin],
            pipeline: None,
            vertex_buffers: [None; 31],
            bound_vertex_buffers: [None; 31],
            index_buffer: None,
            topology: None,
            restart: None,
            amplification: alloc::vec![0],
            factors: None,
            factor_scale: 1.0,
            raster: RasterState::default(),
            visibility: Visibility {
                buffer: visibility_buffer,
                ..Visibility::default()
            },
            samples,
            timestamp_resets: Vec::new(),
        };
        for &(sample, boundary) in &state.samples {
            if let (CounterSample::Timestamp { pool, query }, true) = (sample, boundary.starts()) {
                state.timestamp_resets.push((pool, query));
                self.recorder.push(Command::WriteTimestamp {
                    pool,
                    query,
                    stage: PipelineStages::TOP_OF_PIPE,
                });
            }
        }
        self.default_render_state(&mut state);
        self.encoder = Encoder::Render(Box::new(state));
        Ok(())
    }

    /// Metal's initial encoder state, as dynamic state.
    fn default_render_state(&mut self, state: &mut RenderState) {
        let [width, height] = state.pass.extent;
        let viewport = Viewport {
            origin_x: 0.0,
            origin_y: 0.0,
            width: f64::from(width),
            height: f64::from(height),
            znear: 0.0,
            zfar: 1.0,
        };
        let features = self.features;
        let recorder = &mut self.recorder;
        recorder.push(Command::SetViewports(alloc::vec![flip(viewport)]));
        recorder.push(Command::SetScissors(alloc::vec![Rect {
            offset: [0, 0],
            extent: [width, height]
        }]));
        recorder.push(Command::SetCullMode(CullMode::EMPTY));
        recorder.push(Command::SetFrontFace(FrontFace::Clockwise));
        recorder.push(Command::SetDepthBias {
            enable: false,
            constant: 0.0,
            clamp: 0.0,
            slope: 0.0,
        });
        recorder.push(Command::SetDepthStencil(depth_stencil(
            &DepthStencilState::default(),
        )));
        recorder.push(Command::SetStencilReference { front: 0, back: 0 });
        recorder.push(Command::SetBlendConstants([0.0; 4]));
        if features.polygon_mode {
            recorder.push(Command::SetPolygonMode(PolygonMode::Fill));
        }
        if features.depth_clamp {
            recorder.push(Command::SetDepthClamp(false));
        }
        if features.sample_locations {
            let samples = SampleCounts::single(state.pass.sample_count).unwrap_or(SampleCounts::C1);
            let locations = state.pass.sample_locations.clone();
            recorder.push(Command::SetSampleLocations { samples, locations });
        }
    }

    pub(super) fn end_render(
        &mut self,
        resolver: &mut dyn Resolver,
        mut state: RenderState,
    ) -> Result<()> {
        state.pass.finish()?;
        end_query(&mut self.recorder, &mut state.visibility);
        for &(sample, boundary) in &state.samples {
            let stage = match boundary {
                PassBoundary::EndOfVertex => PipelineStages::VERTEX_SHADER,
                PassBoundary::EndOfFragment => PipelineStages::FRAGMENT_SHADER,
                PassBoundary::StartOfVertex | PassBoundary::StartOfFragment => continue,
            };
            if let CounterSample::Timestamp { pool, query } = sample {
                state.timestamp_resets.push((pool, query));
                self.recorder
                    .push(Command::WriteTimestamp { pool, query, stage });
            }
        }
        self.recorder.pause_statistics();
        self.recorder.push(Command::EndRendering);
        self.recorder.resume_statistics(resolver, false)?;
        for &(sample, boundary) in &state.samples {
            if let (CounterSample::Statistic(destination), false) = (sample, boundary.starts()) {
                self.recorder.sample_statistics(resolver, destination)?;
            }
        }

        let last = state.begins.len() - 1;
        let commands = self.recorder.commands();
        for (instance, &index) in state.begins.iter().enumerate() {
            commands[index] =
                Command::BeginRendering(rendering(&state.pass, instance == 0, instance == last));
        }
        if !state.timestamp_resets.is_empty() {
            let resets =
                state
                    .timestamp_resets
                    .iter()
                    .map(|&(pool, first)| Command::ResetQueryPool {
                        pool,
                        first,
                        count: 1,
                    });
            let at = state.begins[0];
            commands.splice(at..at, resets.collect::<Vec<_>>());
        }
        self.resolve_visibility(resolver, state.visibility)
    }

    /// Writes each used offset's sample count (or nonzero flag) into the
    /// visibility result buffer.
    fn resolve_visibility(
        &mut self,
        resolver: &mut dyn Resolver,
        visibility: Visibility,
    ) -> Result<()> {
        let (Some(buffer), false) = (visibility.buffer, visibility.queries.is_empty()) else {
            return Ok(());
        };
        let mut offsets: Vec<u64> = visibility.queries.iter().map(|query| query.2).collect();
        offsets.sort_unstable();
        offsets.dedup();
        for &offset in &offsets {
            ensure(
                offset.is_multiple_of(8) && offset + 8 <= buffer.length,
                "visibility result offset",
            )?;
        }
        self.recorder.access(Use::new(
            PipelineStages::ALL_TRANSFER,
            Access::TRANSFER_WRITE,
        ));
        if offsets.len() == visibility.queries.len() {
            for &(pool, query, offset) in &visibility.queries {
                let (dst, offset) = (buffer.buffer, buffer.at(offset, 8)?);
                self.recorder.push(Command::CopyQueryResults {
                    pool,
                    first: query,
                    count: 1,
                    dst,
                    offset,
                    stride: 8,
                    wait: true,
                });
            }
            return Ok(());
        }
        // Gather each offset's results contiguously, then sum them.
        let scratch =
            self.recorder
                .upload(resolver, &alloc::vec![0; visibility.queries.len() * 8], 8)?;
        let mut runs = Vec::with_capacity(offsets.len());
        let mut next = 0u32;
        for &offset in &offsets {
            let first = next;
            for &(pool, query, _) in visibility.queries.iter().filter(|query| query.2 == offset) {
                let at = scratch.offset + u64::from(next) * 8;
                let dst = scratch.buffer;
                self.recorder.push(Command::CopyQueryResults {
                    pool,
                    first: query,
                    count: 1,
                    dst,
                    offset: at,
                    stride: 8,
                    wait: true,
                });
                next += 1;
            }
            runs.push((first, next - first, buffer.address + offset));
        }
        let count = runs.len() as u32;
        let arguments = AccumulateArguments {
            results: scratch.address,
            stride: 1,
            runs,
        };
        let arguments = self.recorder.upload(
            resolver,
            &arguments.encode(),
            AccumulateArguments::ALIGNMENT,
        )?;
        self.recorder.access(Use::new(
            PipelineStages::COMPUTE_SHADER,
            Access::SHADER_READ | Access::SHADER_WRITE,
        ));
        self.recorder.push(Command::AccumulateResults {
            arguments: arguments.address,
            runs: count,
        });
        // The kernel replaced the pipeline and push constants.
        self.bindings.reset();
        Ok(())
    }
}

fn end_query(recorder: &mut Recorder, visibility: &mut Visibility) {
    if let Some((pool, query)) = visibility.active.take() {
        recorder.push(Command::EndQuery { pool, query });
    }
}

/// The `VkRenderingInfo` of one instance of a pass: only the first loads
/// as Metal asked and only the last stores and resolves as Metal asked.
fn rendering(pass: &RenderPassPlan<ImageView>, first: bool, last: bool) -> Rendering {
    let attachment = |attachment: &RenderingAttachment<ImageView>| Attachment {
        view: attachment.view.texture,
        resolve: if last {
            attachment.resolve.map(|(mode, view)| (mode, view.texture))
        } else {
            None
        },
        load_op: if first {
            attachment.load_op
        } else {
            AttachmentLoadOp::Load
        },
        store_op: if last {
            attachment.store_op
        } else {
            AttachmentStoreOp::Store
        },
        clear: attachment.clear,
    };
    Rendering {
        extent: pass.extent,
        layer_count: pass.layer_count,
        color: pass
            .color
            .iter()
            .map(|color| color.as_ref().map(attachment))
            .collect(),
        depth: pass.depth.as_ref().map(attachment),
        stencil: pass.stencil.as_ref().map(attachment),
    }
}

fn flip(viewport: Viewport) -> VkViewport {
    VkViewport {
        x: viewport.origin_x as f32,
        y: (viewport.origin_y + viewport.height) as f32,
        width: viewport.width as f32,
        height: -viewport.height as f32,
        min_depth: viewport.znear as f32,
        max_depth: viewport.zfar as f32,
    }
}

fn depth_stencil(state: &DepthStencilState) -> DepthStencil {
    let face = |face: &crate::metal::pipeline::StencilFace| {
        (
            face.fail_op,
            face.pass_op,
            face.depth_fail_op,
            face.compare_op,
            face.compare_mask,
            face.write_mask,
        )
    };
    DepthStencil {
        depth_test: state.depth_test_enable,
        depth_write: state.depth_write_enable,
        depth_compare: state.depth_compare_op,
        stencil_test: state.stencil_test_enable,
        faces: [face(&state.front), face(&state.back)],
    }
}

/// Render encoder operations.
impl CommandBuffer {
    pub fn set_render_pipeline_state(&mut self, state: &RenderPipelineState) -> Result<()> {
        let render = render(&mut self.encoder)?;
        let plan = &state.plan;
        let pass = &render.pass;
        ensure(
            plan.sample_count == pass.sample_count,
            "pipeline and pass sample counts differ",
        )?;
        let matches = |pipeline: Option<_>, pass: Option<_>| pipeline.is_none() || pipeline == pass;
        ensure(
            (0..MAX_COLOR_ATTACHMENTS)
                .all(|index| matches(plan.color_formats[index], pass.color_formats[index])),
            "pipeline color formats differ from the pass",
        )?;
        ensure(
            matches(plan.depth_format, pass.depth_format),
            "pipeline depth format differs from the pass",
        )?;
        ensure(
            matches(plan.stencil_format, pass.stencil_format),
            "pipeline stencil format differs from the pass",
        )?;
        let rebind = render
            .pipeline
            .as_ref()
            .is_none_or(|bound| (bound.id, bound.pipeline) != (state.id, state.pipeline));
        let views = plan.amplification_count;
        if render.amplification.len() != views as usize {
            // Each view maps to itself until the encoder sets mappings.
            render.amplification = (0..views).map(|view| view << 16 | view).collect();
        }
        render.pipeline = Some(state.clone());
        if rebind {
            if let Some(pipeline) = state.pipeline {
                render.topology = None;
                render.restart = None;
                self.recorder.push(Command::BindPipeline {
                    bind_point: PipelineBindPoint::Graphics,
                    pipeline,
                });
            }
            self.recorder
                .push(Command::SetRasterizerDiscard(!plan.rasterization_enabled));
        }
        Ok(())
    }

    pub fn set_render_buffer(
        &mut self,
        stage: Stage,
        buffer: Option<BufferRef>,
        offset: u64,
        index: u32,
    ) -> Result<()> {
        let render = render(&mut self.encoder)?;
        if stage == Stage::Vertex {
            render.vertex_buffers[buffer_slot(index)?] = buffer.map(|buffer| VertexBinding {
                buffer,
                offset,
                stride: None,
            });
        }
        self.bindings.set_buffer(stage, buffer, offset, index)
    }

    /// `setVertexBuffer:offset:attributeStride:atIndex:`, for layouts with a
    /// dynamic stride.
    pub fn set_vertex_buffer_with_stride(
        &mut self,
        buffer: BufferRef,
        offset: u64,
        stride: u64,
        index: u32,
    ) -> Result<()> {
        let render = render(&mut self.encoder)?;
        render.vertex_buffers[buffer_slot(index)?] = Some(VertexBinding {
            buffer,
            offset,
            stride: Some(stride),
        });
        self.bindings
            .set_buffer(Stage::Vertex, Some(buffer), offset, index)
    }

    pub fn set_render_buffer_offset(
        &mut self,
        stage: Stage,
        offset: u64,
        index: u32,
    ) -> Result<()> {
        let render = render(&mut self.encoder)?;
        if stage == Stage::Vertex
            && let Some(binding) = &mut render.vertex_buffers[buffer_slot(index)?]
        {
            binding.offset = offset;
        }
        self.bindings.set_buffer_offset(stage, offset, index)
    }

    /// `set*Bytes:length:atIndex:`: the bytes are copied into upload memory.
    pub fn set_render_bytes(
        &mut self,
        resolver: &mut dyn Resolver,
        stage: Stage,
        bytes: &[u8],
        index: u32,
    ) -> Result<()> {
        render(&mut self.encoder)?;
        let buffer = self.upload_bytes(resolver, bytes)?;
        self.set_render_buffer(stage, Some(buffer), 0, index)
    }

    pub fn set_render_texture(
        &mut self,
        stage: Stage,
        texture: ResourceId,
        index: u32,
    ) -> Result<()> {
        render(&mut self.encoder)?;
        self.bindings.set_texture(stage, texture, index)
    }

    pub fn set_render_sampler(
        &mut self,
        resolver: &mut dyn Resolver,
        stage: Stage,
        sampler: ResourceId,
        clamp: Option<(f32, f32)>,
        index: u32,
    ) -> Result<()> {
        render(&mut self.encoder)?;
        let sampler = match clamp {
            Some((min, max)) => resolver.clamped_sampler(sampler, min, max)?,
            None => sampler,
        };
        self.bindings.set_sampler(stage, sampler, index)
    }

    pub fn set_viewports(&mut self, viewports: &[Viewport]) -> Result<()> {
        render(&mut self.encoder)?;
        ensure(
            (1..=16).contains(&viewports.len()),
            "between 1 and 16 viewports",
        )?;
        self.recorder.push(Command::SetViewports(
            viewports.iter().copied().map(flip).collect(),
        ));
        Ok(())
    }

    pub fn set_scissor_rects(&mut self, rects: &[ScissorRect]) -> Result<()> {
        let [width, height] = render(&mut self.encoder)?.pass.extent;
        ensure(
            (1..=16).contains(&rects.len()),
            "between 1 and 16 scissor rectangles",
        )?;
        let mut scissors = Vec::with_capacity(rects.len());
        for rect in rects {
            let inside = rect
                .x
                .checked_add(rect.width)
                .is_some_and(|right| right <= u64::from(width))
                && rect
                    .y
                    .checked_add(rect.height)
                    .is_some_and(|bottom| bottom <= u64::from(height));
            ensure(inside, "scissor rectangles lie within the render target")?;
            scissors.push(Rect {
                offset: [rect.x as i32, rect.y as i32],
                extent: [rect.width as u32, rect.height as u32],
            });
        }
        self.recorder.push(Command::SetScissors(scissors));
        Ok(())
    }

    pub fn set_cull_mode(&mut self, mode: MtlCullMode) -> Result<()> {
        render(&mut self.encoder)?.raster.cull_mode = mode;
        let mode = match mode {
            MtlCullMode::None => CullMode::EMPTY,
            MtlCullMode::Front => CullMode::FRONT,
            MtlCullMode::Back => CullMode::BACK,
        };
        self.recorder.push(Command::SetCullMode(mode));
        Ok(())
    }

    pub fn set_front_facing_winding(&mut self, winding: Winding) -> Result<()> {
        render(&mut self.encoder)?.raster.winding = winding;
        let face = match winding {
            Winding::Clockwise => FrontFace::Clockwise,
            Winding::CounterClockwise => FrontFace::CounterClockwise,
        };
        self.recorder.push(Command::SetFrontFace(face));
        Ok(())
    }

    pub fn set_depth_bias(&mut self, constant: f32, slope: f32, clamp: f32) -> Result<()> {
        render(&mut self.encoder)?.raster.depth_bias = [constant, slope, clamp];
        let enable = constant != 0.0 || slope != 0.0;
        self.recorder.push(Command::SetDepthBias {
            enable,
            constant,
            clamp,
            slope,
        });
        Ok(())
    }

    pub fn set_depth_stencil_state(&mut self, state: Option<&DepthStencilState>) -> Result<()> {
        let state = state.copied().unwrap_or_default();
        render(&mut self.encoder)?.raster.depth_stencil = state;
        self.recorder
            .push(Command::SetDepthStencil(depth_stencil(&state)));
        Ok(())
    }

    pub fn set_stencil_reference_values(&mut self, front: u32, back: u32) -> Result<()> {
        render(&mut self.encoder)?;
        self.recorder
            .push(Command::SetStencilReference { front, back });
        Ok(())
    }

    pub fn set_blend_color(&mut self, color: [f32; 4]) -> Result<()> {
        render(&mut self.encoder)?;
        self.recorder.push(Command::SetBlendConstants(color));
        Ok(())
    }

    pub fn set_triangle_fill_mode(&mut self, mode: TriangleFillMode) -> Result<()> {
        let render = render(&mut self.encoder)?;
        match (mode, self.features.polygon_mode) {
            (TriangleFillMode::Fill, false) => {}
            (TriangleFillMode::Lines, false) => {
                return Err(Error::Unsupported("triangle line fill"));
            }
            (mode, true) => {
                let polygon = if mode == TriangleFillMode::Lines {
                    PolygonMode::Line
                } else {
                    PolygonMode::Fill
                };
                self.recorder.push(Command::SetPolygonMode(polygon));
            }
        }
        render.raster.fill_mode = mode;
        Ok(())
    }

    pub fn set_depth_clip_mode(&mut self, mode: DepthClipMode) -> Result<()> {
        let render = render(&mut self.encoder)?;
        match (mode, self.features.depth_clamp) {
            (DepthClipMode::Clip, false) => {}
            (DepthClipMode::Clamp, false) => return Err(Error::Unsupported("depth clamping")),
            (mode, true) => {
                self.recorder
                    .push(Command::SetDepthClamp(mode == DepthClipMode::Clamp));
            }
        }
        render.raster.clip_mode = mode;
        Ok(())
    }

    /// Sets each part of `raster` that differs from the encoder's.
    pub(super) fn set_raster_state(&mut self, raster: &RasterState) -> Result<()> {
        let current = render(&mut self.encoder)?.raster;
        if current.cull_mode != raster.cull_mode {
            self.set_cull_mode(raster.cull_mode)?;
        }
        if current.winding != raster.winding {
            self.set_front_facing_winding(raster.winding)?;
        }
        if current.depth_bias != raster.depth_bias {
            let [constant, slope, clamp] = raster.depth_bias;
            self.set_depth_bias(constant, slope, clamp)?;
        }
        if current.depth_stencil != raster.depth_stencil {
            self.set_depth_stencil_state(Some(&raster.depth_stencil))?;
        }
        if current.fill_mode != raster.fill_mode {
            self.set_triangle_fill_mode(raster.fill_mode)?;
        }
        if current.clip_mode != raster.clip_mode {
            self.set_depth_clip_mode(raster.clip_mode)?;
        }
        Ok(())
    }

    /// `setVertexAmplificationCount:viewMappings:`; each mapping is
    /// (viewport offset, render target array index offset).
    pub fn set_vertex_amplification(&mut self, mappings: &[(u32, u32)]) -> Result<()> {
        let render = render(&mut self.encoder)?;
        ensure(
            !mappings.is_empty(),
            "the amplification count is at least one",
        )?;
        ensure(
            mappings
                .iter()
                .all(|&(viewport, layer)| viewport <= 0xffff && layer <= 0xffff),
            "view mapping offsets",
        )?;
        render.amplification = mappings
            .iter()
            .map(|&(viewport, layer)| layer << 16 | viewport)
            .collect();
        Ok(())
    }

    pub fn set_visibility_result_mode(
        &mut self,
        mode: VisibilityResultMode,
        offset: u64,
    ) -> Result<()> {
        let render = render(&mut self.encoder)?;
        ensure(
            mode == VisibilityResultMode::Disabled || render.visibility.buffer.is_some(),
            "visibility results need a visibility result buffer",
        )?;
        end_query(&mut self.recorder, &mut render.visibility);
        render.visibility.mode = (mode != VisibilityResultMode::Disabled).then_some((mode, offset));
        Ok(())
    }

    /// `set{Color,Depth,Stencil}StoreAction:` for a deferred action.
    pub fn set_store_action(&mut self, slot: AttachmentSlot, action: StoreAction) -> Result<()> {
        render(&mut self.encoder)?
            .pass
            .set_store_action(slot, action)
    }

    /// `set{Color,Depth,Stencil}StoreActionOptions:`.
    pub fn set_store_action_options(
        &mut self,
        slot: AttachmentSlot,
        options: StoreActionOptions,
    ) -> Result<()> {
        render(&mut self.encoder)?
            .pass
            .set_store_action_options(slot, options)
    }

    /// `memoryBarrierWithScope:afterStages:beforeStages:` (and the
    /// resource form, which orders the same stages): the pass instance ends
    /// and resumes behind a barrier.
    pub fn render_memory_barrier(
        &mut self,
        resolver: &mut dyn Resolver,
        scope: BarrierScope,
        after: RenderStages,
        before: RenderStages,
    ) -> Result<()> {
        render(&mut self.encoder)?;
        ensure(!scope.is_empty(), "a barrier names a scope")?;
        let (src_stages, dst_stages) = (render_stages(after), render_stages(before));
        ensure(
            !src_stages.is_empty() && !dst_stages.is_empty(),
            "barriers name stages Vulkan has",
        )?;
        self.outside_pass(resolver, |recorder| {
            recorder.push(Command::Barrier(Barrier {
                src_stages,
                src_access: Access::MEMORY_WRITE,
                dst_stages,
                dst_access: Access::MEMORY_READ | Access::MEMORY_WRITE,
            }));
        })
    }

    /// Forgets the bindings generated commands left undefined: the bound
    /// pipeline, vertex and index buffers, and push constants. The
    /// encoder's pipeline, if any, is bound again.
    pub(super) fn after_generated_commands(&mut self) -> Result<()> {
        let render = render(&mut self.encoder)?;
        render.bound_vertex_buffers = [None; 31];
        render.index_buffer = None;
        render.topology = None;
        render.restart = None;
        self.bindings.pushed = None;
        if let Some(state) = &render.pipeline {
            if let Some(pipeline) = state.pipeline {
                self.recorder.push(Command::BindPipeline {
                    bind_point: PipelineBindPoint::Graphics,
                    pipeline,
                });
            }
            let discard = !state.plan.rasterization_enabled;
            self.recorder.push(Command::SetRasterizerDiscard(discard));
        }
        Ok(())
    }

    /// Ends the pass instance, records `between` outside it and resumes
    /// with an instance that loads every attachment.
    pub(super) fn outside_pass(
        &mut self,
        resolver: &mut dyn Resolver,
        between: impl FnOnce(&mut Recorder),
    ) -> Result<()> {
        let render = render(&mut self.encoder)?;
        end_query(&mut self.recorder, &mut render.visibility);
        self.recorder.pause_statistics();
        self.recorder.push(Command::EndRendering);
        between(&mut self.recorder);
        let index = self.recorder.commands().len();
        // Patched with the final attachment operations at endEncoding.
        self.recorder.push(Command::BeginRendering(rendering(
            &render.pass,
            false,
            false,
        )));
        render.begins.push(index);
        self.recorder.resume_statistics(resolver, false)
    }

    pub fn draw_primitives(
        &mut self,
        resolver: &mut dyn Resolver,
        primitive: PrimitiveType,
        vertex_start: u32,
        vertex_count: u32,
        instance_count: u32,
        base_instance: u32,
    ) -> Result<()> {
        self.prepare_draw(resolver, primitive)?;
        if vertex_count == 0 || instance_count == 0 {
            return Ok(());
        }
        let first_vertex = vertex_start;
        let draw = Command::Draw {
            vertex_count,
            instance_count,
            first_vertex,
            first_instance: base_instance,
        };
        self.amplified(resolver, draw)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn draw_indexed_primitives(
        &mut self,
        resolver: &mut dyn Resolver,
        primitive: PrimitiveType,
        index_count: u32,
        index_type: MtlIndexType,
        index_buffer: BufferRef,
        index_buffer_offset: u64,
        instance_count: u32,
        base_vertex: i32,
        base_instance: u32,
    ) -> Result<()> {
        index_buffer.at(
            index_buffer_offset,
            u64::from(index_count) * index_type.bytes(),
        )?;
        self.prepare_draw(resolver, primitive)?;
        self.bind_index_buffer(index_type, index_buffer, index_buffer_offset)?;
        if index_count == 0 || instance_count == 0 {
            return Ok(());
        }
        let draw = Command::DrawIndexed {
            index_count,
            instance_count,
            first_index: 0,
            vertex_offset: base_vertex,
            first_instance: base_instance,
        };
        self.amplified(resolver, draw)
    }

    /// `drawPrimitives:indirectBuffer:indirectBufferOffset:`; Metal's
    /// argument layout is `VkDrawIndirectCommand`.
    pub fn draw_primitives_indirect(
        &mut self,
        resolver: &mut dyn Resolver,
        primitive: PrimitiveType,
        indirect: BufferRef,
        offset: u64,
    ) -> Result<()> {
        ensure(
            offset.is_multiple_of(4),
            "indirect arguments are 4-byte aligned",
        )?;
        let offset = indirect.at(offset, 16)?;
        self.prepare_draw(resolver, primitive)?;
        self.amplified(
            resolver,
            Command::DrawIndirect {
                buffer: indirect.buffer,
                offset,
            },
        )
    }

    /// Metal's indexed argument layout is `VkDrawIndexedIndirectCommand`,
    /// with indices counted from the index buffer offset.
    #[allow(clippy::too_many_arguments)]
    pub fn draw_indexed_primitives_indirect(
        &mut self,
        resolver: &mut dyn Resolver,
        primitive: PrimitiveType,
        index_type: MtlIndexType,
        index_buffer: BufferRef,
        index_buffer_offset: u64,
        indirect: BufferRef,
        offset: u64,
    ) -> Result<()> {
        ensure(
            offset.is_multiple_of(4),
            "indirect arguments are 4-byte aligned",
        )?;
        let offset = indirect.at(offset, 20)?;
        self.prepare_draw(resolver, primitive)?;
        self.bind_index_buffer(index_type, index_buffer, index_buffer_offset)?;
        self.amplified(
            resolver,
            Command::DrawIndexedIndirect {
                buffer: indirect.buffer,
                offset,
            },
        )
    }

    pub fn set_tessellation_factor_buffer(
        &mut self,
        buffer: Option<BufferRef>,
        offset: u64,
        instance_stride: u64,
    ) -> Result<()> {
        let render = render(&mut self.encoder)?;
        ensure(
            offset.is_multiple_of(4),
            "tessellation factor offsets are 4-byte aligned",
        )?;
        let instance_stride = u32::try_from(instance_stride)
            .map_err(|_| Error::Invalid("tessellation factor instance stride"))?;
        render.factors = buffer.map(|buffer| FactorBuffer {
            buffer,
            offset,
            instance_stride,
        });
        Ok(())
    }

    pub fn set_tessellation_factor_scale(&mut self, scale: f32) -> Result<()> {
        let render = render(&mut self.encoder)?;
        ensure(
            scale.is_finite() && scale >= 0.0,
            "tessellation factor scales are finite and nonnegative",
        )?;
        render.factor_scale = scale;
        Ok(())
    }

    /// `drawPatches:…` and `drawIndexedPatches:…`: patch `n` of the draw is
    /// vertex `patch_start + n` of a single-point patch list.
    pub fn draw_patches(
        &mut self,
        resolver: &mut dyn Resolver,
        source: &PatchSource,
        patch_start: u32,
        patch_count: u32,
        instance_count: u32,
        base_instance: u32,
    ) -> Result<()> {
        self.prepare_patches(resolver, source)?;
        if patch_count == 0 || instance_count == 0 {
            return Ok(());
        }
        let draw = Command::Draw {
            vertex_count: patch_count,
            instance_count,
            first_vertex: patch_start,
            first_instance: base_instance,
        };
        self.patch_draw(resolver, draw)
    }

    /// The indirect patch draws: `MTLDrawPatchIndirectArguments` (patch
    /// count, instance count, patch start, base instance) is the
    /// `VkDrawIndirectCommand` of [`Self::draw_patches`].
    pub fn draw_patches_indirect(
        &mut self,
        resolver: &mut dyn Resolver,
        source: &PatchSource,
        indirect: BufferRef,
        offset: u64,
    ) -> Result<()> {
        ensure(
            offset.is_multiple_of(4),
            "indirect arguments are 4-byte aligned",
        )?;
        let offset = indirect.at(offset, 16)?;
        self.prepare_patches(resolver, source)?;
        self.patch_draw(
            resolver,
            Command::DrawIndirect {
                buffer: indirect.buffer,
                offset,
            },
        )
    }

    /// A patch draw counts in its own statistics interval: its synthesized
    /// vertex stage is not a Metal vertex function.
    fn patch_draw(&mut self, resolver: &mut dyn Resolver, draw: Command) -> Result<()> {
        self.recorder.split_statistics(resolver, true)?;
        self.amplified(resolver, draw)?;
        self.recorder.split_statistics(resolver, false)
    }

    /// `drawMeshThreadgroups:threadsPerObjectThreadgroup:threadsPerMeshThreadgroup:`.
    pub fn draw_mesh_threadgroups(
        &mut self,
        resolver: &mut dyn Resolver,
        threadgroups: [u32; 3],
        object_threads: [u32; 3],
        mesh_threads: [u32; 3],
    ) -> Result<()> {
        self.prepare_mesh(resolver, object_threads, mesh_threads, [0; 3])?;
        if threadgroups.contains(&0) {
            return Ok(());
        }
        self.amplified(resolver, Command::DrawMeshTasks(threadgroups))
    }

    /// `drawMeshThreads:…`: whole threadgroups cover the grid, and the grid
    /// size bounds the threads that run.
    pub fn draw_mesh_threads(
        &mut self,
        resolver: &mut dyn Resolver,
        threads: [u32; 3],
        object_threads: [u32; 3],
        mesh_threads: [u32; 3],
    ) -> Result<()> {
        let pipeline = render(&mut self.encoder)?
            .pipeline
            .as_ref()
            .ok_or(Error::Invalid("no render pipeline state is set"))?;
        // Variants add the object and mesh stages, so the plan lacks them.
        let has_object = pipeline
            .interfaces
            .iter()
            .any(|interface| interface.stage == Stage::Object);
        let group = if has_object {
            object_threads
        } else {
            mesh_threads
        };
        ensure(!group.contains(&0), "threadgroups have at least one thread")?;
        let groups = [0, 1, 2].map(|axis| threads[axis].div_ceil(group[axis]));
        self.prepare_mesh(resolver, object_threads, mesh_threads, threads)?;
        if groups.contains(&0) {
            return Ok(());
        }
        self.amplified(resolver, Command::DrawMeshTasks(groups))
    }

    /// Metal's threadgroup arguments are `VkDrawMeshTasksIndirectCommandEXT`.
    pub fn draw_mesh_threadgroups_indirect(
        &mut self,
        resolver: &mut dyn Resolver,
        indirect: BufferRef,
        offset: u64,
        object_threads: [u32; 3],
        mesh_threads: [u32; 3],
    ) -> Result<()> {
        ensure(
            offset.is_multiple_of(4),
            "indirect arguments are 4-byte aligned",
        )?;
        let offset = indirect.at(offset, 12)?;
        self.prepare_mesh(resolver, object_threads, mesh_threads, [0; 3])?;
        self.amplified(
            resolver,
            Command::DrawMeshTasksIndirect {
                buffer: indirect.buffer,
                offset,
            },
        )
    }

    fn bind_index_buffer(
        &mut self,
        index_type: MtlIndexType,
        buffer: BufferRef,
        offset: u64,
    ) -> Result<()> {
        ensure(
            offset.is_multiple_of(index_type.bytes()),
            "index buffer offsets are aligned to the index size",
        )?;
        let offset = buffer.at(offset, 0)?;
        let index_type = match index_type {
            MtlIndexType::UInt16 => IndexType::Uint16,
            MtlIndexType::UInt32 => IndexType::Uint32,
        };
        let render = render(&mut self.encoder)?;
        let binding = (buffer.buffer, offset, index_type);
        if render.index_buffer != Some(binding) {
            render.index_buffer = Some(binding);
            self.recorder.push(Command::BindIndexBuffer {
                buffer: buffer.buffer,
                offset,
                index_type,
            });
        }
        Ok(())
    }

    /// Validates the pipeline for a vertex draw and brings topology, vertex
    /// buffers, the visibility query and the tables up to date.
    fn prepare_draw(
        &mut self,
        resolver: &mut dyn Resolver,
        primitive: PrimitiveType,
    ) -> Result<()> {
        let render = render(&mut self.encoder)?;
        let pipeline = render
            .pipeline
            .as_ref()
            .ok_or(Error::Invalid("no render pipeline state is set"))?;
        ensure(
            pipeline.plan.mesh.is_none(),
            "mesh pipelines draw with drawMeshThreadgroups",
        )?;
        ensure(
            pipeline.plan.tessellation.is_none(),
            "tessellated pipelines draw with drawPatches",
        )?;
        let class = pipeline.plan.topology_class;
        ensure(
            class == PrimitiveTopologyClass::Unspecified || class == primitive.class(),
            "the primitive type is outside the pipeline's topology class",
        )?;
        let topology = primitive_topology(primitive);
        let mut commands = Vec::new();
        if render.topology != Some(topology) {
            render.topology = Some(topology);
            commands.push(Command::SetPrimitiveTopology(topology));
        }
        // Metal restarts strips at the all-ones index, and never lists.
        let restart = primitive.is_strip();
        if render.restart != Some(restart) {
            render.restart = Some(restart);
            commands.push(Command::SetPrimitiveRestart(restart));
        }
        for binding in &pipeline.plan.info.vertex_input.bindings {
            let index = binding.binding as usize;
            let bound = render.vertex_buffers[index].ok_or(Error::Invalid(
                "a vertex buffer the pipeline reads is unbound",
            ))?;
            let stride = match (binding.stride, bound.stride) {
                (Some(stride), _) => u64::from(stride),
                (None, Some(stride)) => stride,
                (None, None) => {
                    return Err(Error::Invalid(
                        "a dynamic-stride vertex buffer was bound without a stride",
                    ));
                }
            };
            let offset = bound.buffer.at(bound.offset, 0)?;
            let size = bound.buffer.length - bound.offset;
            let buffer = VertexBuffer {
                buffer: bound.buffer.buffer,
                offset,
                size,
                stride: Some(stride),
            };
            if render.bound_vertex_buffers[index] != Some(buffer) {
                render.bound_vertex_buffers[index] = Some(buffer);
                commands.push(Command::BindVertexBuffers {
                    first: binding.binding,
                    buffers: alloc::vec![buffer],
                });
            }
        }
        commands
            .into_iter()
            .for_each(|command| self.recorder.push(command));
        self.begin_query(resolver)?;
        self.bindings.flush(
            &mut self.recorder,
            resolver,
            &[Stage::Vertex, Stage::Fragment],
        )
    }

    /// Validates the pipeline and buffers of a patch draw, uploads its
    /// arguments and brings topology, the visibility query and the tables up
    /// to date.
    fn prepare_patches(&mut self, resolver: &mut dyn Resolver, source: &PatchSource) -> Result<()> {
        let render = render(&mut self.encoder)?;
        let pipeline = render
            .pipeline
            .as_ref()
            .ok_or(Error::Invalid("no render pipeline state is set"))?;
        let tessellation = pipeline.plan.tessellation.as_ref().ok_or(Error::Invalid(
            "patch draws need a post-tessellation vertex function",
        ))?;
        ensure(
            (1..=MAX_PATCH_CONTROL_POINTS).contains(&source.control_points),
            "patch control point count",
        )?;
        ensure(
            tessellation
                .patch
                .control_points
                .is_none_or(|count| count == source.control_points),
            "the draw's control point count differs from the function's",
        )?;
        let index_bytes = match tessellation.control_point_index {
            TessellationControlPointIndexType::None => None,
            TessellationControlPointIndexType::UInt16 => Some(2),
            TessellationControlPointIndexType::UInt32 => Some(4),
        };
        ensure(
            index_bytes.is_some() == source.control_point_indices.is_some(),
            "indexed patch draws match the pipeline's control point index type",
        )?;
        let factors = render
            .factors
            .ok_or(Error::Invalid("no tessellation factor buffer is set"))?;
        let binding = |(buffer, offset): (BufferRef, u64), alignment: u64| {
            ensure(
                offset.is_multiple_of(alignment),
                "patch buffer offsets are aligned to their elements",
            )?;
            buffer.at(offset, 0)?;
            Ok::<_, Error>(BufferBinding {
                address: buffer.address + offset,
                length: buffer.length - offset,
            })
        };
        let arguments = TessellationArguments {
            factors: binding((factors.buffer, factors.offset), 4)?,
            patch_indices: match source.patch_indices {
                Some(indices) => binding(indices, 4)?,
                None => BufferBinding::default(),
            },
            control_point_indices: match (source.control_point_indices, index_bytes) {
                (Some(indices), Some(bytes)) => binding(indices, bytes)?,
                _ => BufferBinding::default(),
            },
            instance_stride: factors.instance_stride,
            factor_scale: if tessellation.factor_scale {
                render.factor_scale
            } else {
                1.0
            },
            control_points: source.control_points,
            strides: patch_strides(
                &render.vertex_buffers,
                pipeline.interfaces.first().ok_or(Error::Invalid(
                    "the pipeline has no post-tessellation vertex function",
                ))?,
                tessellation.vertex_descriptor.as_ref(),
            )?,
        };
        if render.topology != Some(PrimitiveTopology::PatchList) {
            render.topology = Some(PrimitiveTopology::PatchList);
            self.recorder
                .push(Command::SetPrimitiveTopology(PrimitiveTopology::PatchList));
        }
        if render.restart != Some(false) {
            render.restart = Some(false);
            self.recorder.push(Command::SetPrimitiveRestart(false));
        }
        let upload = self.recorder.upload(
            resolver,
            &arguments.encode(),
            TessellationArguments::ALIGNMENT,
        )?;
        self.bindings.constants.arguments = upload.address;
        self.begin_query(resolver)?;
        self.bindings.flush(
            &mut self.recorder,
            resolver,
            &[Stage::Vertex, Stage::Fragment],
        )
    }

    fn prepare_mesh(
        &mut self,
        resolver: &mut dyn Resolver,
        object_threads: [u32; 3],
        mesh_threads: [u32; 3],
        grid: [u32; 3],
    ) -> Result<()> {
        let render = render(&mut self.encoder)?;
        let state = render
            .pipeline
            .as_ref()
            .ok_or(Error::Invalid("no render pipeline state is set"))?;
        ensure(
            state.plan.mesh.is_some(),
            "vertex pipelines draw with drawPrimitives",
        )?;
        ensure(
            !mesh_threads.contains(&0),
            "mesh threadgroups have at least one thread",
        )?;
        let pipeline = resolver.mesh_pipeline(state, object_threads, mesh_threads)?;
        self.recorder.push(Command::BindPipeline {
            bind_point: PipelineBindPoint::Graphics,
            pipeline,
        });
        self.bindings.constants.grid = grid;
        self.begin_query(resolver)?;
        self.bindings.flush(
            &mut self.recorder,
            resolver,
            &[Stage::Object, Stage::Mesh, Stage::Fragment],
        )
    }

    /// Begins an occlusion query for the current visibility mode if none is
    /// active.
    pub(super) fn begin_query(&mut self, resolver: &mut dyn Resolver) -> Result<()> {
        let render = render(&mut self.encoder)?;
        let visibility = &mut render.visibility;
        let (Some((mode, offset)), None) = (visibility.mode, visibility.active) else {
            return Ok(());
        };
        let (pool, query) = match visibility.pool {
            Some((pool, next, count)) if next < count => {
                visibility.pool = Some((pool, next + 1, count));
                (pool, next)
            }
            _ => {
                let (pool, count) = resolver.query_pool(QueryType::Occlusion)?;
                ensure(count > 0, "occlusion pools hold queries")?;
                self.recorder.query_pools.push((QueryType::Occlusion, pool));
                visibility.pool = Some((pool, 1, count));
                (pool, 0)
            }
        };
        visibility.active = Some((pool, query));
        visibility.queries.push((pool, query, offset));
        let precise = mode == VisibilityResultMode::Counting;
        self.recorder.push(Command::BeginQuery {
            pool,
            query,
            precise,
        });
        Ok(())
    }

    /// Records `draw` once per amplified view, each with its view's push
    /// constants.
    fn amplified(&mut self, resolver: &mut dyn Resolver, draw: Command) -> Result<()> {
        let views = render(&mut self.encoder)?.amplification.clone();
        if views.len() == 1 {
            self.recorder.push(draw);
            return Ok(());
        }
        for (view, mapping) in views.into_iter().enumerate() {
            self.bindings.constants.amplification_id = view as u32;
            self.bindings.constants.view_mapping = mapping;
            self.bindings.flush(&mut self.recorder, resolver, &[])?;
            self.recorder.push(draw.clone());
        }
        Ok(())
    }
}

fn render_stages(stages: RenderStages) -> PipelineStages {
    let fragment = PipelineStages::FRAGMENT_SHADER
        .union(PipelineStages::EARLY_FRAGMENT_TESTS)
        .union(PipelineStages::LATE_FRAGMENT_TESTS)
        .union(PipelineStages::COLOR_ATTACHMENT_OUTPUT);
    PipelineStages::EMPTY
        .with(
            PipelineStages::VERTEX_INPUT
                | PipelineStages::VERTEX_SHADER
                | PipelineStages::TESSELLATION_CONTROL_SHADER
                | PipelineStages::TESSELLATION_EVALUATION_SHADER,
            stages.contains(RenderStages::VERTEX),
        )
        .with(fragment, stages.contains(RenderStages::FRAGMENT))
        .with(
            PipelineStages::TASK_SHADER,
            stages.contains(RenderStages::OBJECT),
        )
        .with(
            PipelineStages::MESH_SHADER,
            stages.contains(RenderStages::MESH),
        )
}
