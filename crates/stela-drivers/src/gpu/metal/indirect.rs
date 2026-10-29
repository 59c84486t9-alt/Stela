//! `MTLIndirectCommandBuffer`: render or compute commands encoded ahead of
//! time and executed by encoders (`executeCommandsInBuffer:…`).
//!
//! The device keeps an indirect command buffer's commands as values: the
//! CPU encodes them through [`IndirectRenderCommand`] and
//! [`IndirectComputeCommand`], and blit encoders reset and copy them. An
//! encoder executing a range replays each command through its own
//! operations (see `command_buffer::indirect`), so a command gets exactly
//! the validation and lowering of the same command encoded directly:
//! pipeline variants, vertex strides, tessellation arguments, amplification
//! and visibility all apply unchanged.
//!
//! Contents are read when an execution is encoded, and blit resets and
//! copies apply when they are encoded, in encoding order. Shaders cannot
//! encode commands, which needs the compiler's
//! [`ShaderFeatures::INDIRECT_COMMAND_ENCODING`].
//!
//! [`ShaderFeatures::INDIRECT_COMMAND_ENCODING`]: super::capabilities::ShaderFeatures::INDIRECT_COMMAND_ENCODING
use super::{
    abi::{
        CullMode, DepthClipMode, IndexType, IndirectCommandType, PrimitiveType, TriangleFillMode,
        Winding,
    },
    capabilities::{Capabilities, MAX_BUFFER_BINDINGS, Size},
    command_buffer::{
        BufferRef, ComputePipelineState, RenderPipelineState,
        render::{PatchSource, RasterState},
    },
    error::{Error, Result, ensure, require},
    pipeline::DepthStencilState,
    shader::Stage,
};
use alloc::vec::Vec;
use core::ops::Range;

/// A render pipeline's place in the device's execution sets: its state
/// class and its index in the class's set. Its `gpuResourceID` is
/// [`handle`](Self::handle).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IndirectPipeline {
    pub class: u32,
    pub index: u32,
}

impl IndirectPipeline {
    /// The class plus one in the high half and the index in the low half,
    /// so zero names no pipeline.
    pub const fn handle(self) -> u64 {
        (self.class as u64 + 1) << 32 | self.index as u64
    }
}

/// Names an indirect command buffer on its device.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IndirectCommandBufferId(pub u32);

/// `MTLIndirectCommandBufferDescriptor`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndirectCommandBufferDescriptor {
    pub command_types: IndirectCommandType,
    pub inherit_pipeline_state: bool,
    pub inherit_buffers: bool,
    pub inherit_cull_mode: bool,
    pub inherit_depth_stencil_state: bool,
    pub inherit_depth_bias: bool,
    pub inherit_depth_clip_mode: bool,
    pub inherit_front_facing_winding: bool,
    pub inherit_triangle_fill_mode: bool,
    pub max_vertex_buffer_bind_count: u64,
    pub max_fragment_buffer_bind_count: u64,
    pub max_kernel_buffer_bind_count: u64,
    pub max_kernel_threadgroup_memory_bind_count: u64,
    pub max_object_buffer_bind_count: u64,
    pub max_mesh_buffer_bind_count: u64,
    pub support_ray_tracing: bool,
    pub support_dynamic_attribute_stride: bool,
}

const RENDER_TYPES: IndirectCommandType = IndirectCommandType::DRAW
    .union(IndirectCommandType::DRAW_INDEXED)
    .union(IndirectCommandType::DRAW_PATCHES)
    .union(IndirectCommandType::DRAW_INDEXED_PATCHES)
    .union(IndirectCommandType::DRAW_MESH_THREADGROUPS)
    .union(IndirectCommandType::DRAW_MESH_THREADS);

const COMPUTE_TYPES: IndirectCommandType = IndirectCommandType::CONCURRENT_DISPATCH
    .union(IndirectCommandType::CONCURRENT_DISPATCH_THREADS);

impl IndirectCommandBufferDescriptor {
    /// Whether render encoders execute the buffer; compute encoders execute
    /// the others.
    pub fn renders(&self) -> bool {
        self.command_types.intersects(RENDER_TYPES)
    }

    fn validate(&self, capabilities: &Capabilities) -> Result<()> {
        let types = self.command_types;
        ensure(
            !types.is_empty(),
            "indirect command buffers name a command type",
        )?;
        ensure(
            !(types.intersects(RENDER_TYPES) && types.intersects(COMPUTE_TYPES)),
            "indirect command buffers hold render or compute commands, not both",
        )?;
        if types.intersects(
            IndirectCommandType::DRAW_MESH_THREADGROUPS | IndirectCommandType::DRAW_MESH_THREADS,
        ) {
            require(capabilities.supports_mesh_shaders, "mesh shaders")?;
        }
        if self.support_ray_tracing {
            return Err(Error::Unsupported("ray tracing in indirect commands"));
        }
        let counts = [
            self.max_vertex_buffer_bind_count,
            self.max_fragment_buffer_bind_count,
            self.max_kernel_buffer_bind_count,
            self.max_kernel_threadgroup_memory_bind_count,
            self.max_object_buffer_bind_count,
            self.max_mesh_buffer_bind_count,
        ];
        ensure(
            counts
                .iter()
                .all(|&count| count <= u64::from(MAX_BUFFER_BINDINGS)),
            "indirect command bind counts are within the argument table",
        )
    }

    /// Buffers a command may bind for `stage`.
    fn buffer_count(&self, stage: Stage) -> u64 {
        match stage {
            Stage::Vertex => self.max_vertex_buffer_bind_count,
            Stage::Fragment => self.max_fragment_buffer_bind_count,
            Stage::Kernel => self.max_kernel_buffer_bind_count,
            Stage::Object => self.max_object_buffer_bind_count,
            Stage::Mesh => self.max_mesh_buffer_bind_count,
        }
    }
}

/// A buffer an indirect command binds.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IndirectBuffer {
    pub stage: Stage,
    pub index: u32,
    pub buffer: BufferRef,
    pub offset: u64,
    /// `setVertexBuffer:offset:attributeStride:atIndex:`.
    pub stride: Option<u64>,
}

/// The draw or dispatch of an indirect command, with Metal's arguments.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IndirectAction {
    Draw {
        primitive: PrimitiveType,
        vertex_start: u32,
        vertex_count: u32,
        instance_count: u32,
        base_instance: u32,
    },
    DrawIndexed {
        primitive: PrimitiveType,
        index_count: u32,
        index_type: IndexType,
        index_buffer: BufferRef,
        index_buffer_offset: u64,
        instance_count: u32,
        base_vertex: i32,
        base_instance: u32,
    },
    /// `drawPatches:…` and `drawIndexedPatches:…`, which name their
    /// tessellation factor buffer, offset and instance stride.
    DrawPatches {
        source: PatchSource,
        patch_start: u32,
        patch_count: u32,
        instance_count: u32,
        base_instance: u32,
        factors: (BufferRef, u64, u64),
    },
    DrawMeshThreadgroups {
        threadgroups: [u32; 3],
        object_threads: [u32; 3],
        mesh_threads: [u32; 3],
    },
    DrawMeshThreads {
        threads: [u32; 3],
        object_threads: [u32; 3],
        mesh_threads: [u32; 3],
    },
    /// `concurrentDispatchThreadgroups:threadsPerThreadgroup:`.
    Dispatch {
        threadgroups: [u32; 3],
        threads: Size,
    },
    /// `concurrentDispatchThreads:threadsPerThreadgroup:`.
    DispatchThreads { grid: [u32; 3], threads: Size },
}

impl IndirectAction {
    fn command_type(&self) -> IndirectCommandType {
        match self {
            Self::Draw { .. } => IndirectCommandType::DRAW,
            Self::DrawIndexed { .. } => IndirectCommandType::DRAW_INDEXED,
            Self::DrawPatches { source, .. } if source.control_point_indices.is_some() => {
                IndirectCommandType::DRAW_INDEXED_PATCHES
            }
            Self::DrawPatches { .. } => IndirectCommandType::DRAW_PATCHES,
            Self::DrawMeshThreadgroups { .. } => IndirectCommandType::DRAW_MESH_THREADGROUPS,
            Self::DrawMeshThreads { .. } => IndirectCommandType::DRAW_MESH_THREADS,
            Self::Dispatch { .. } => IndirectCommandType::CONCURRENT_DISPATCH,
            Self::DispatchThreads { .. } => IndirectCommandType::CONCURRENT_DISPATCH_THREADS,
        }
    }
}

/// One command; the default is a reset command, which does nothing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct IndirectCommand {
    /// The device id of the command's pipeline state, unless the buffer
    /// inherits the encoder's.
    pub pipeline: Option<u64>,
    /// The command's buffers, unless the buffer inherits the encoder's.
    pub buffers: Vec<IndirectBuffer>,
    /// Kernel threadgroup memory lengths by index.
    pub threadgroup_lengths: Vec<(u32, u64)>,
    /// The rasterizer state parts the buffer does not inherit.
    pub raster: RasterState,
    /// `setStageInRegion:` origin and size.
    pub stage_in: Option<([u64; 3], [u64; 3])>,
    /// Earlier commands' memory accesses complete before this one's.
    pub barrier: bool,
    pub action: Option<IndirectAction>,
}

/// `MTLIndirectCommandBuffer`'s contents.
#[derive(Clone, Debug, PartialEq)]
pub struct IndirectCommandBuffer {
    descriptor: IndirectCommandBufferDescriptor,
    commands: Vec<IndirectCommand>,
}

impl IndirectCommandBuffer {
    /// `newIndirectCommandBufferWithDescriptor:maxCommandCount:options:`.
    pub fn new(
        capabilities: &Capabilities,
        descriptor: &IndirectCommandBufferDescriptor,
        max_command_count: u64,
    ) -> Result<Self> {
        descriptor.validate(capabilities)?;
        ensure(
            max_command_count >= 1,
            "indirect command buffers hold a command",
        )?;
        let count = usize::try_from(max_command_count)
            .map_err(|_| Error::Invalid("indirect command count"))?;
        let mut commands = Vec::new();
        commands
            .try_reserve_exact(count)
            .map_err(|_| Error::OutOfMemory)?;
        commands.resize_with(count, IndirectCommand::default);
        Ok(Self {
            descriptor: *descriptor,
            commands,
        })
    }

    pub fn descriptor(&self) -> &IndirectCommandBufferDescriptor {
        &self.descriptor
    }

    /// `size`.
    pub fn size(&self) -> usize {
        self.commands.len()
    }

    /// The commands of `range`.
    pub fn commands(&self, range: Range<usize>) -> Result<&[IndirectCommand]> {
        self.commands.get(range).ok_or(Error::Invalid(
            "range extends past the indirect command buffer",
        ))
    }

    fn command(&mut self, index: usize) -> Result<&mut IndirectCommand> {
        self.commands
            .get_mut(index)
            .ok_or(Error::Invalid("index past the indirect command buffer"))
    }

    /// `indirectRenderCommandAtIndex:`.
    pub fn render_command(&mut self, index: usize) -> Result<IndirectRenderCommand<'_>> {
        ensure(
            self.descriptor.renders(),
            "the indirect command buffer holds compute commands",
        )?;
        Ok(IndirectRenderCommand {
            descriptor: self.descriptor,
            command: self.command(index)?,
        })
    }

    /// `indirectComputeCommandAtIndex:`.
    pub fn compute_command(&mut self, index: usize) -> Result<IndirectComputeCommand<'_>> {
        ensure(
            !self.descriptor.renders(),
            "the indirect command buffer holds render commands",
        )?;
        Ok(IndirectComputeCommand {
            descriptor: self.descriptor,
            command: self.command(index)?,
        })
    }

    /// `resetWithRange:` and the blit `resetCommandsInBuffer:withRange:`.
    pub fn reset(&mut self, range: Range<usize>) -> Result<()> {
        self.commands
            .get_mut(range)
            .ok_or(Error::Invalid(
                "range extends past the indirect command buffer",
            ))?
            .fill_with(IndirectCommand::default);
        Ok(())
    }

    /// `copyIndirectCommandBuffer:sourceRange:destination:destinationIndex:`.
    /// Every copied command must be one this buffer could have encoded.
    pub fn copy_from(&mut self, source: &Self, range: Range<usize>, index: usize) -> Result<()> {
        let commands = source.commands(range)?;
        let end = index
            .checked_add(commands.len())
            .filter(|&end| end <= self.commands.len())
            .ok_or(Error::Invalid(
                "range extends past the indirect command buffer",
            ))?;
        for command in commands {
            self.descriptor.admits(command)?;
        }
        self.commands[index..end].clone_from_slice(commands);
        Ok(())
    }
}

impl IndirectCommandBufferDescriptor {
    /// Checks that a command encoded under another descriptor fits this one.
    fn admits(&self, command: &IndirectCommand) -> Result<()> {
        if let Some(action) = &command.action {
            ensure(
                self.command_types.contains(action.command_type()),
                "the command type is not in the indirect command buffer's types",
            )?;
        }
        ensure(
            command.pipeline.is_none() || !self.inherit_pipeline_state,
            "the indirect command buffer inherits pipeline state",
        )?;
        ensure(
            command.buffers.is_empty() || !self.inherit_buffers,
            "the indirect command buffer inherits buffers",
        )?;
        for buffer in &command.buffers {
            ensure(
                u64::from(buffer.index) < self.buffer_count(buffer.stage),
                "buffer index exceeds the indirect command buffer's bind count",
            )?;
        }
        ensure(
            command.threadgroup_lengths.iter().all(|&(index, _)| {
                u64::from(index) < self.max_kernel_threadgroup_memory_bind_count
            }),
            "threadgroup memory index exceeds the bind count",
        )
    }
}

/// Encodes one command of `stage`'s buffer slots and checks the descriptor.
fn set_buffer(
    descriptor: &IndirectCommandBufferDescriptor,
    command: &mut IndirectCommand,
    binding: IndirectBuffer,
) -> Result<()> {
    ensure(
        !descriptor.inherit_buffers,
        "the indirect command buffer inherits buffers",
    )?;
    ensure(
        u64::from(binding.index) < descriptor.buffer_count(binding.stage),
        "buffer index exceeds the indirect command buffer's bind count",
    )?;
    ensure(
        binding.offset <= binding.buffer.length,
        "buffer offset beyond the buffer",
    )?;
    command
        .buffers
        .retain(|bound| (bound.stage, bound.index) != (binding.stage, binding.index));
    command.buffers.push(binding);
    Ok(())
}

fn set_action(
    descriptor: &IndirectCommandBufferDescriptor,
    command: &mut IndirectCommand,
    action: IndirectAction,
) -> Result<()> {
    ensure(
        descriptor.command_types.contains(action.command_type()),
        "the command type is not in the indirect command buffer's types",
    )?;
    command.action = Some(action);
    Ok(())
}

/// `MTLIndirectRenderCommand`.
pub struct IndirectRenderCommand<'a> {
    descriptor: IndirectCommandBufferDescriptor,
    command: &'a mut IndirectCommand,
}

impl IndirectRenderCommand<'_> {
    pub fn set_render_pipeline_state(&mut self, state: &RenderPipelineState) -> Result<()> {
        ensure(
            !self.descriptor.inherit_pipeline_state,
            "the indirect command buffer inherits pipeline state",
        )?;
        self.command.pipeline = Some(state.id);
        Ok(())
    }

    /// `set{Vertex,Fragment,Object,Mesh}Buffer:offset:atIndex:`.
    pub fn set_buffer(
        &mut self,
        stage: Stage,
        buffer: BufferRef,
        offset: u64,
        index: u32,
    ) -> Result<()> {
        ensure(stage != Stage::Kernel, "render commands bind render stages")?;
        let binding = IndirectBuffer {
            stage,
            index,
            buffer,
            offset,
            stride: None,
        };
        set_buffer(&self.descriptor, self.command, binding)
    }

    /// `setVertexBuffer:offset:attributeStride:atIndex:`.
    pub fn set_vertex_buffer_with_stride(
        &mut self,
        buffer: BufferRef,
        offset: u64,
        stride: u64,
        index: u32,
    ) -> Result<()> {
        ensure(
            self.descriptor.support_dynamic_attribute_stride,
            "the indirect command buffer has no dynamic attribute strides",
        )?;
        let binding = IndirectBuffer {
            stage: Stage::Vertex,
            index,
            buffer,
            offset,
            stride: Some(stride),
        };
        set_buffer(&self.descriptor, self.command, binding)
    }

    pub fn set_cull_mode(&mut self, mode: CullMode) -> Result<()> {
        ensure(
            !self.descriptor.inherit_cull_mode,
            "the indirect command buffer inherits the cull mode",
        )?;
        self.command.raster.cull_mode = mode;
        Ok(())
    }

    pub fn set_front_facing_winding(&mut self, winding: Winding) -> Result<()> {
        ensure(
            !self.descriptor.inherit_front_facing_winding,
            "the indirect command buffer inherits the winding",
        )?;
        self.command.raster.winding = winding;
        Ok(())
    }

    pub fn set_depth_bias(&mut self, constant: f32, slope: f32, clamp: f32) -> Result<()> {
        ensure(
            !self.descriptor.inherit_depth_bias,
            "the indirect command buffer inherits the depth bias",
        )?;
        self.command.raster.depth_bias = [constant, slope, clamp];
        Ok(())
    }

    pub fn set_depth_stencil_state(&mut self, state: Option<&DepthStencilState>) -> Result<()> {
        ensure(
            !self.descriptor.inherit_depth_stencil_state,
            "the indirect command buffer inherits the depth-stencil state",
        )?;
        self.command.raster.depth_stencil = state.copied().unwrap_or_default();
        Ok(())
    }

    pub fn set_triangle_fill_mode(&mut self, mode: TriangleFillMode) -> Result<()> {
        ensure(
            !self.descriptor.inherit_triangle_fill_mode,
            "the indirect command buffer inherits the fill mode",
        )?;
        self.command.raster.fill_mode = mode;
        Ok(())
    }

    pub fn set_depth_clip_mode(&mut self, mode: DepthClipMode) -> Result<()> {
        ensure(
            !self.descriptor.inherit_depth_clip_mode,
            "the indirect command buffer inherits the depth clip mode",
        )?;
        self.command.raster.clip_mode = mode;
        Ok(())
    }

    /// `setBarrier`.
    pub fn set_barrier(&mut self) {
        self.command.barrier = true;
    }

    /// `clearBarrier`.
    pub fn clear_barrier(&mut self) {
        self.command.barrier = false;
    }

    /// `drawPrimitives:vertexStart:vertexCount:instanceCount:baseInstance:`.
    pub fn draw_primitives(
        &mut self,
        primitive: PrimitiveType,
        vertex_start: u32,
        vertex_count: u32,
        instance_count: u32,
        base_instance: u32,
    ) -> Result<()> {
        let action = IndirectAction::Draw {
            primitive,
            vertex_start,
            vertex_count,
            instance_count,
            base_instance,
        };
        set_action(&self.descriptor, self.command, action)
    }

    /// `drawIndexedPrimitives:indexCount:indexType:indexBuffer:…`.
    #[allow(clippy::too_many_arguments)]
    pub fn draw_indexed_primitives(
        &mut self,
        primitive: PrimitiveType,
        index_count: u32,
        index_type: IndexType,
        index_buffer: BufferRef,
        index_buffer_offset: u64,
        instance_count: u32,
        base_vertex: i32,
        base_instance: u32,
    ) -> Result<()> {
        let action = IndirectAction::DrawIndexed {
            primitive,
            index_count,
            index_type,
            index_buffer,
            index_buffer_offset,
            instance_count,
            base_vertex,
            base_instance,
        };
        set_action(&self.descriptor, self.command, action)
    }

    /// `drawPatches:…` and `drawIndexedPatches:…`; `factors` is the
    /// tessellation factor buffer, its offset and its instance stride.
    pub fn draw_patches(
        &mut self,
        source: &PatchSource,
        patch_start: u32,
        patch_count: u32,
        instance_count: u32,
        base_instance: u32,
        factors: (BufferRef, u64, u64),
    ) -> Result<()> {
        let action = IndirectAction::DrawPatches {
            source: *source,
            patch_start,
            patch_count,
            instance_count,
            base_instance,
            factors,
        };
        set_action(&self.descriptor, self.command, action)
    }

    /// `drawMeshThreadgroups:threadsPerObjectThreadgroup:threadsPerMeshThreadgroup:`.
    pub fn draw_mesh_threadgroups(
        &mut self,
        threadgroups: [u32; 3],
        object_threads: [u32; 3],
        mesh_threads: [u32; 3],
    ) -> Result<()> {
        let action = IndirectAction::DrawMeshThreadgroups {
            threadgroups,
            object_threads,
            mesh_threads,
        };
        set_action(&self.descriptor, self.command, action)
    }

    /// `drawMeshThreads:threadsPerObjectThreadgroup:threadsPerMeshThreadgroup:`.
    pub fn draw_mesh_threads(
        &mut self,
        threads: [u32; 3],
        object_threads: [u32; 3],
        mesh_threads: [u32; 3],
    ) -> Result<()> {
        let action = IndirectAction::DrawMeshThreads {
            threads,
            object_threads,
            mesh_threads,
        };
        set_action(&self.descriptor, self.command, action)
    }

    /// `reset`.
    pub fn reset(&mut self) {
        *self.command = IndirectCommand::default();
    }
}

/// `MTLIndirectComputeCommand`.
pub struct IndirectComputeCommand<'a> {
    descriptor: IndirectCommandBufferDescriptor,
    command: &'a mut IndirectCommand,
}

impl IndirectComputeCommand<'_> {
    pub fn set_compute_pipeline_state(&mut self, state: &ComputePipelineState) -> Result<()> {
        ensure(
            !self.descriptor.inherit_pipeline_state,
            "the indirect command buffer inherits pipeline state",
        )?;
        self.command.pipeline = Some(state.id);
        Ok(())
    }

    /// `setKernelBuffer:offset:atIndex:`.
    pub fn set_kernel_buffer(&mut self, buffer: BufferRef, offset: u64, index: u32) -> Result<()> {
        let binding = IndirectBuffer {
            stage: Stage::Kernel,
            index,
            buffer,
            offset,
            stride: None,
        };
        set_buffer(&self.descriptor, self.command, binding)
    }

    /// `setThreadgroupMemoryLength:atIndex:`.
    pub fn set_threadgroup_memory_length(&mut self, length: u64, index: u32) -> Result<()> {
        ensure(
            u64::from(index) < self.descriptor.max_kernel_threadgroup_memory_bind_count,
            "threadgroup memory index exceeds the bind count",
        )?;
        let lengths = &mut self.command.threadgroup_lengths;
        lengths.retain(|&(slot, _)| slot != index);
        lengths.push((index, length));
        Ok(())
    }

    /// `setStageInRegion:`.
    pub fn set_stage_in_region(&mut self, origin: [u64; 3], size: [u64; 3]) {
        self.command.stage_in = Some((origin, size));
    }

    /// `setBarrier`.
    pub fn set_barrier(&mut self) {
        self.command.barrier = true;
    }

    /// `clearBarrier`.
    pub fn clear_barrier(&mut self) {
        self.command.barrier = false;
    }

    pub fn concurrent_dispatch_threadgroups(
        &mut self,
        threadgroups: [u32; 3],
        threads: Size,
    ) -> Result<()> {
        let action = IndirectAction::Dispatch {
            threadgroups,
            threads,
        };
        set_action(&self.descriptor, self.command, action)
    }

    pub fn concurrent_dispatch_threads(&mut self, grid: [u32; 3], threads: Size) -> Result<()> {
        let action = IndirectAction::DispatchThreads { grid, threads };
        set_action(&self.descriptor, self.command, action)
    }

    /// `reset`.
    pub fn reset(&mut self) {
        *self.command = IndirectCommand::default();
    }
}

#[cfg(test)]
mod tests;
