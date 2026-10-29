use super::{
    blit::{BlitTexture, BufferLayout, Region},
    counters::{CounterRange, CounterSample},
    indirect::ExecutionRange,
    render::{PassBoundary, PatchSource, Viewport},
    *,
};
use crate::gpu::metal::{
    abi::{
        BarrierScope, BlitOption, CpuCacheMode, CullMode as CullModeAbi, DispatchType,
        HazardTrackingMode, IndexType, IndirectCommandType, LoadAction, PrimitiveTopologyClass,
        PrimitiveType, RenderStages, ResourceOptions, StorageMode, StoreAction, StoreActionOptions,
        SwizzleChannels, TessellationControlPointIndexType, TextureType, TextureUsage,
        VisibilityResultMode,
    },
    binding::{
        AccumulateArguments, ArgumentTable, BufferBinding, PushConstants, TessellationArguments,
    },
    capabilities::Size,
    error::Error,
    hazard::FULL,
    indirect::{
        IndirectCommandBuffer, IndirectCommandBufferDescriptor, IndirectCommandBufferId,
        RecordLayout,
    },
    nvidia::fixture::capabilities,
    pass::{AttachedTexture, AttachmentDescriptor, RenderPassDescriptor, Target, render_pass},
    pipeline::{
        ColorAttachmentDescriptor, ComputePipelineDescriptor, MAX_COLOR_ATTACHMENTS,
        MeshRenderPipelineDescriptor, RenderPipelineDescriptor, RenderTargets, TessellatedVertex,
        TessellationDescriptor, compute_pipeline, mesh_render_pipeline, render_pipeline,
        tessellation,
    },
    pixel_format::PixelFormat,
    resource::TextureDescriptor,
    shader::{
        Access as ShaderAccess, AttributeUse, BufferUse, CompiledShader, NumericClass, Patch,
        PatchDomain, Provenance, tests::interface,
    },
    vertex::{
        Attribute, Layout, STRIDE_DYNAMIC, StageInLayout, StageInStep, StageInputDescriptor,
        StepFunction, VertexDescriptor, VertexFormat,
    },
    vulkan::{
        Access, AttachmentLoadOp, AttachmentStoreOp, CullMode, PipelineBindPoint, PipelineStages,
        command::{Barrier, BufferCopy},
        object::{Image, ImageView, QueryType, ShaderCode},
    },
};
use alloc::{sync::Arc, vec::Vec};

#[derive(Default)]
struct MockResolver {
    chunks: u64,
    compiled: Vec<Specialization>,
    pools: u64,
    /// Pipeline states by id, for indirect commands.
    render_states: Vec<RenderPipelineState>,
    compute_states: Vec<ComputePipelineState>,
    indirect: Vec<Arc<IndirectCommandBuffer>>,
}

impl ChunkSource for MockResolver {
    fn acquire(&mut self, bytes: u64) -> Result<Chunk> {
        self.chunks += 1;
        Ok(Chunk {
            buffer: Buffer(1000 + self.chunks),
            address: self.chunks << 40,
            size: bytes,
        })
    }
}

impl Resolver for MockResolver {
    fn compute_pipeline(
        &mut self,
        _: &ComputePipelineState,
        specialization: &Specialization,
    ) -> Result<Pipeline> {
        let index = match self
            .compiled
            .iter()
            .position(|known| known == specialization)
        {
            Some(index) => index,
            None => {
                self.compiled.push(specialization.clone());
                self.compiled.len() - 1
            }
        };
        Ok(Pipeline(500 + index as u64))
    }

    fn clamped_sampler(&mut self, sampler: ResourceId, _: f32, _: f32) -> Result<ResourceId> {
        Ok(ResourceId(sampler.0 + 100))
    }

    fn mesh_pipeline(
        &mut self,
        _: &RenderPipelineState,
        _: [u32; 3],
        _: [u32; 3],
    ) -> Result<Pipeline> {
        Ok(Pipeline(900))
    }

    fn query_pool(&mut self, _: QueryType) -> Result<(QueryPool, u32)> {
        self.pools += 1;
        Ok((QueryPool(self.pools), 2))
    }

    fn render_pipeline_state(&mut self, id: u64) -> Result<RenderPipelineState> {
        let known = self.render_states.iter().find(|state| state.id == id);
        known.cloned().ok_or(Error::Invalid("unknown pipeline"))
    }

    fn compute_pipeline_state(&mut self, id: u64) -> Result<ComputePipelineState> {
        let known = self.compute_states.iter().find(|state| state.id == id);
        known.cloned().ok_or(Error::Invalid("unknown pipeline"))
    }

    fn indirect_commands(
        &mut self,
        id: IndirectCommandBufferId,
    ) -> Result<Arc<IndirectCommandBuffer>> {
        let known = self.indirect.get(id.0 as usize);
        known.cloned().ok_or(Error::Invalid("unknown object"))
    }

    /// Places records in buffer `2000 + id` at address `id << 44`.
    fn indirect_records(
        &mut self,
        id: IndirectCommandBufferId,
    ) -> Result<(RecordLayout, BufferRef)> {
        let known = self.indirect.get_mut(id.0 as usize);
        let contents = Arc::make_mut(known.ok_or(Error::Invalid("unknown object"))?);
        let layout = match contents.records() {
            Some(layout) => *layout,
            None => {
                let (layout, _) = contents.resident_image()?;
                contents.make_resident(layout);
                layout
            }
        };
        let records = BufferRef {
            buffer: Buffer(2000 + u64::from(id.0)),
            offset: 0,
            address: u64::from(id.0) << 44,
            length: layout.bytes(),
        };
        Ok((layout, records))
    }

    fn update_indirect_commands(
        &mut self,
        id: IndirectCommandBufferId,
        update: &mut dyn FnMut(&mut IndirectCommandBuffer) -> Result<()>,
    ) -> Result<()> {
        let known = self.indirect.get_mut(id.0 as usize);
        update(Arc::make_mut(
            known.ok_or(Error::Invalid("unknown object"))?,
        ))
    }
}

const FEATURES: DynamicFeatures = DynamicFeatures {
    depth_clamp: true,
    polygon_mode: true,
    sample_locations: false,
};

fn texture(pixel_format: PixelFormat) -> TextureDescriptor {
    TextureDescriptor {
        texture_type: TextureType::D2,
        pixel_format,
        width: 64,
        height: 32,
        depth: 1,
        mipmap_level_count: 3,
        sample_count: 1,
        array_length: 1,
        options: ResourceOptions {
            cpu_cache_mode: CpuCacheMode::DefaultCache,
            storage_mode: StorageMode::Private,
            hazard_tracking_mode: HazardTrackingMode::Default,
        },
        usage: TextureUsage::RENDER_TARGET | TextureUsage::SHADER_READ,
        swizzle: SwizzleChannels::IDENTITY,
    }
}

fn pass(
    color: &TextureDescriptor,
    store: StoreAction,
    visibility: bool,
) -> crate::gpu::metal::pass::RenderPassPlan<ImageView> {
    let mut descriptor = RenderPassDescriptor {
        color_attachments: [None; MAX_COLOR_ATTACHMENTS],
        depth_attachment: None,
        depth_resolve_filter: crate::gpu::metal::abi::MultisampleDepthResolveFilter::Sample0,
        stencil_attachment: None,
        stencil_resolve_filter: crate::gpu::metal::abi::MultisampleStencilResolveFilter::Sample0,
        visibility_results: visibility,
        render_target_array_length: 0,
        render_target_width: 0,
        render_target_height: 0,
        default_raster_sample_count: 0,
        tile_memory: false,
        sample_positions: Vec::new(),
        rasterization_rate_map: false,
    };
    descriptor.color_attachments[0] = Some(AttachmentDescriptor {
        target: Target {
            texture: AttachedTexture {
                texture: ImageView(7),
                descriptor: color,
            },
            level: 0,
            slice: 0,
            depth_plane: 0,
        },
        resolve: None,
        load_action: LoadAction::Clear,
        store_action: store,
        store_action_options: StoreActionOptions::EMPTY,
        clear: [0.0, 0.0, 0.0, 1.0],
    });
    render_pass(&capabilities(), &descriptor).unwrap()
}

fn shader(stage: Stage, edit: impl FnOnce(&mut Interface)) -> CompiledShader {
    let mut interface = interface(stage);
    edit(&mut interface);
    CompiledShader {
        code: ShaderCode(stage.raw()),
        interface,
        provenance: Provenance::default(),
    }
}

fn render_state(amplification: u64) -> RenderPipelineState {
    let vertex = shader(Stage::Vertex, |_| {});
    let fragment = shader(Stage::Fragment, |_| {});
    let layout = VertexDescriptor {
        attributes: alloc::vec![Attribute {
            index: 0,
            format: VertexFormat::Float4,
            offset: 0,
            buffer_index: 2
        }],
        layouts: alloc::vec![Layout {
            buffer_index: 2,
            stride: 16,
            step_function: StepFunction::PerVertex,
            step_rate: 1
        }],
    };
    let mut targets = RenderTargets::default();
    targets.color_attachments[0] = ColorAttachmentDescriptor {
        pixel_format: Some(PixelFormat::Rgba8Unorm),
        ..ColorAttachmentDescriptor::default()
    };
    let descriptor = RenderPipelineDescriptor {
        vertex_function: &vertex,
        fragment_function: Some(&fragment),
        vertex_descriptor: Some(&layout),
        targets,
        input_primitive_topology: PrimitiveTopologyClass::Triangle,
        max_vertex_amplification_count: amplification,
        tessellation: None,
    };
    let plan = render_pipeline(&capabilities(), &descriptor).unwrap();
    RenderPipelineState {
        id: 0,
        pipeline: Some(Pipeline(42)),
        plan,
        interfaces: alloc::vec![vertex.interface, fragment.interface],
        indirect: None,
    }
}

/// A pipeline of a quad post-tessellation function with four control
/// points, indexed by 16-bit control point indices, which fetches its
/// stage-in by `layout`.
fn patch_state(layout: Option<&VertexDescriptor>) -> RenderPipelineState {
    let evaluation = shader(Stage::Vertex, |interface| {
        interface.patch = Some(Patch {
            domain: PatchDomain::Quad,
            control_points: Some(4),
        });
        if let Some(layout) = layout {
            interface.attributes = layout
                .attributes
                .iter()
                .map(|attribute| AttributeUse {
                    index: attribute.index,
                    numeric: NumericClass::Float,
                    components: 4,
                })
                .collect();
        }
    });
    let properties = TessellationDescriptor {
        factor_scale_enabled: true,
        control_point_index_type: TessellationControlPointIndexType::UInt16,
        ..TessellationDescriptor::default()
    };
    let tessellation = tessellation(&capabilities(), &evaluation.interface, &properties, layout)
        .unwrap()
        .unwrap();
    let mut targets = RenderTargets::default();
    targets.color_attachments[0].pixel_format = Some(PixelFormat::Rgba8Unorm);
    let descriptor = RenderPipelineDescriptor {
        vertex_function: &evaluation,
        fragment_function: None,
        vertex_descriptor: None,
        targets,
        input_primitive_topology: PrimitiveTopologyClass::Unspecified,
        max_vertex_amplification_count: 1,
        tessellation: Some(TessellatedVertex {
            tessellation: &tessellation,
            vertex: ShaderCode(100),
            control: ShaderCode(200),
        }),
    };
    RenderPipelineState {
        id: 1,
        pipeline: Some(Pipeline(43)),
        plan: render_pipeline(&capabilities(), &descriptor).unwrap(),
        interfaces: alloc::vec![evaluation.interface],
        indirect: None,
    }
}

#[test]
fn patch_draws_upload_their_tessellation_arguments() {
    let color = texture(PixelFormat::Rgba8Unorm);
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands
        .begin_render(
            &mut resolver,
            pass(&color, StoreAction::Store, false),
            None,
            Vec::new(),
        )
        .unwrap();
    commands
        .set_render_pipeline_state(&patch_state(None))
        .unwrap();
    let source = PatchSource {
        control_points: 4,
        patch_indices: None,
        control_point_indices: Some((buffer(5, 4096), 64)),
    };
    assert_eq!(
        commands.draw_patches(&mut resolver, &source, 0, 1, 1, 0),
        Err(Error::Invalid("no tessellation factor buffer is set"))
    );
    commands
        .set_tessellation_factor_buffer(Some(buffer(4, 1024)), 96, 48)
        .unwrap();
    commands.set_tessellation_factor_scale(2.0).unwrap();
    assert!(
        commands
            .draw_primitives(&mut resolver, PrimitiveType::Triangle, 0, 3, 1, 0)
            .is_err()
    );
    let wrong_count = PatchSource {
        control_points: 3,
        ..source
    };
    assert!(
        commands
            .draw_patches(&mut resolver, &wrong_count, 0, 1, 1, 0)
            .is_err()
    );
    let unindexed = PatchSource {
        control_point_indices: None,
        ..source
    };
    assert!(
        commands
            .draw_patches(&mut resolver, &unindexed, 0, 1, 1, 0)
            .is_err()
    );
    commands
        .draw_patches(&mut resolver, &source, 8, 6, 2, 1)
        .unwrap();
    commands
        .draw_patches_indirect(&mut resolver, &source, buffer(6, 64), 16)
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let commands = &recording.segments[0].commands;

    assert!(commands.contains(&Command::SetPrimitiveTopology(
        crate::gpu::metal::vulkan::PrimitiveTopology::PatchList
    )));
    assert!(commands.contains(&Command::Draw {
        vertex_count: 6,
        instance_count: 2,
        first_vertex: 8,
        first_instance: 1,
    }));
    assert!(commands.contains(&Command::DrawIndirect {
        buffer: Buffer(6),
        offset: 16,
    }));
    let constants = commands.iter().rev().find_map(|command| match command {
        Command::PushConstants(constants) => Some(*constants),
        _ => None,
    });
    let constants: PushConstants = constants.unwrap();
    let (chunk, bytes) = &recording.uploads[0];
    let arguments = &bytes[(constants.arguments - chunk.address) as usize..]
        [..TessellationArguments::BYTES as usize];
    let expected = TessellationArguments {
        factors: BufferBinding {
            address: (4 << 32) + 96,
            length: 1024 - 96,
        },
        patch_indices: BufferBinding::default(),
        control_point_indices: BufferBinding {
            address: (5 << 32) + 64,
            length: 4096 - 64,
        },
        instance_stride: 48,
        factor_scale: 2.0,
        control_points: 4,
        strides: [0; 31],
    };
    assert_eq!(arguments, expected.encode());
}

/// The evaluation stage fetches stage-in from the bound vertex buffers, at
/// the strides bound with layouts of dynamic stride.
#[test]
fn patch_draws_bind_their_stage_in_strides() {
    let layout = VertexDescriptor {
        attributes: alloc::vec![Attribute {
            index: 0,
            format: VertexFormat::Float4,
            offset: 0,
            buffer_index: 2,
        }],
        layouts: alloc::vec![Layout {
            buffer_index: 2,
            stride: STRIDE_DYNAMIC,
            step_function: StepFunction::PerPatchControlPoint,
            step_rate: 1,
        }],
    };
    let color = texture(PixelFormat::Rgba8Unorm);
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands
        .begin_render(
            &mut resolver,
            pass(&color, StoreAction::Store, false),
            None,
            Vec::new(),
        )
        .unwrap();
    commands
        .set_render_pipeline_state(&patch_state(Some(&layout)))
        .unwrap();
    commands
        .set_tessellation_factor_buffer(Some(buffer(4, 1024)), 0, 0)
        .unwrap();
    let source = PatchSource {
        control_points: 4,
        patch_indices: None,
        control_point_indices: Some((buffer(5, 4096), 0)),
    };
    let mut draw =
        |commands: &mut CommandBuffer| commands.draw_patches(&mut resolver, &source, 0, 1, 1, 0);
    assert_eq!(
        draw(&mut commands),
        Err(Error::Invalid(
            "a vertex buffer the pipeline reads is unbound"
        ))
    );
    commands
        .set_render_buffer(Stage::Vertex, Some(buffer(7, 256)), 0, 2)
        .unwrap();
    assert_eq!(
        draw(&mut commands),
        Err(Error::Invalid(
            "a dynamic-stride vertex buffer was bound without a stride"
        ))
    );
    commands
        .set_vertex_buffer_with_stride(buffer(7, 256), 2, 32, 2)
        .unwrap();
    assert!(
        draw(&mut commands).is_err(),
        "offsets are multiples of four"
    );
    commands
        .set_vertex_buffer_with_stride(buffer(7, 256), 16, 32, 2)
        .unwrap();
    draw(&mut commands).unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let constants = recording.segments[0]
        .commands
        .iter()
        .rev()
        .find_map(|command| match command {
            Command::PushConstants(constants) => Some(*constants),
            _ => None,
        })
        .unwrap();
    let (chunk, bytes) = &recording.uploads[0];
    let arguments = &bytes[(constants.arguments - chunk.address) as usize..];
    let stride = TessellationArguments::STRIDES_OFFSET as usize + 4 * 2;
    assert_eq!(arguments[stride..][..4], 32u32.to_le_bytes());
    let count = TessellationArguments::CONTROL_POINTS_OFFSET as usize;
    assert_eq!(arguments[count..][..4], 4u32.to_le_bytes());
}

/// The grid of `drawMeshThreads` is covered by threadgroups of the stage it
/// launches: the object function when there is one.
#[test]
fn mesh_thread_draws_cover_the_grid_with_the_first_stage() {
    let color = texture(PixelFormat::Rgba8Unorm);
    let mut targets = RenderTargets::default();
    targets.color_attachments[0].pixel_format = Some(PixelFormat::Rgba8Unorm);
    for (object, groups) in [(true, [4, 1, 1]), (false, [13, 1, 1])] {
        let object_function = interface(Stage::Object);
        let mesh_function = interface(Stage::Mesh);
        let descriptor = MeshRenderPipelineDescriptor {
            object_function: object.then_some(&object_function),
            mesh_function: &mesh_function,
            fragment_function: None,
            targets,
            max_vertex_amplification_count: 1,
        };
        let state = RenderPipelineState {
            id: 2,
            pipeline: None,
            plan: mesh_render_pipeline(&capabilities(), &descriptor).unwrap(),
            interfaces: object
                .then(|| object_function.clone())
                .into_iter()
                .chain([mesh_function.clone()])
                .collect(),
            indirect: None,
        };
        let mut resolver = MockResolver::default();
        let mut commands = CommandBuffer::new(FEATURES);
        commands
            .begin_render(
                &mut resolver,
                pass(&color, StoreAction::Store, false),
                None,
                Vec::new(),
            )
            .unwrap();
        commands.set_render_pipeline_state(&state).unwrap();
        commands
            .draw_mesh_threads(&mut resolver, [100, 1, 1], [32, 1, 1], [8, 1, 1])
            .unwrap();
        commands.end_encoding(&mut resolver).unwrap();
        let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
        assert!(
            recording.segments[0]
                .commands
                .contains(&Command::DrawMeshTasks(groups))
        );
    }
}

fn buffer(id: u64, length: u64) -> BufferRef {
    BufferRef {
        buffer: Buffer(id),
        offset: 0,
        address: id << 32,
        length,
    }
}

fn count(commands: &[Command], matches: impl Fn(&Command) -> bool) -> usize {
    commands.iter().filter(|command| matches(command)).count()
}

#[test]
fn a_draw_binds_state_buffers_and_tables() {
    let color = texture(PixelFormat::Rgba8Unorm);
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands
        .begin_render(
            &mut resolver,
            pass(&color, StoreAction::Store, false),
            None,
            Vec::new(),
        )
        .unwrap();
    commands
        .set_render_pipeline_state(&render_state(1))
        .unwrap();
    commands
        .set_render_buffer(Stage::Vertex, Some(buffer(3, 256)), 64, 2)
        .unwrap();
    commands
        .set_render_bytes(&mut resolver, Stage::Fragment, &[9; 12], 0)
        .unwrap();
    commands
        .set_viewports(&[Viewport {
            origin_x: 0.0,
            origin_y: 0.0,
            width: 64.0,
            height: 32.0,
            znear: 0.0,
            zfar: 1.0,
        }])
        .unwrap();
    commands
        .draw_primitives(&mut resolver, PrimitiveType::TriangleStrip, 0, 4, 1, 0)
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 5)).unwrap();

    assert_eq!(recording.segments.len(), 1);
    let segment = &recording.segments[0];
    assert_eq!(segment.signals, [(Semaphore(1), 5)]);
    let commands = &segment.commands;
    assert_eq!(commands[0], Command::Barrier(FULL));
    let Command::BeginRendering(rendering) = &commands[1] else {
        panic!("{:?}", commands[1])
    };
    let attachment = rendering.color[0].unwrap();
    assert_eq!(
        (attachment.view, attachment.load_op, attachment.store_op),
        (
            ImageView(7),
            AttachmentLoadOp::Clear,
            AttachmentStoreOp::Store
        )
    );
    assert!(commands.contains(&Command::SetPrimitiveTopology(
        crate::gpu::metal::vulkan::PrimitiveTopology::TriangleStrip
    )));
    assert!(commands.contains(&Command::SetPrimitiveRestart(true)));
    assert!(commands.contains(&Command::BindPipeline {
        bind_point: PipelineBindPoint::Graphics,
        pipeline: Pipeline(42),
    }));
    let flipped = commands.iter().find_map(|command| match command {
        Command::SetViewports(viewports) if viewports[0].height < 0.0 => Some(viewports[0]),
        _ => None,
    });
    assert_eq!(
        flipped.map(|viewport| (viewport.y, viewport.height)),
        Some((32.0, -32.0))
    );
    let vertex = commands.iter().find_map(|command| match command {
        Command::BindVertexBuffers { first: 2, buffers } => Some(buffers[0]),
        _ => None,
    });
    assert_eq!(
        vertex.map(|vertex| (vertex.buffer, vertex.offset, vertex.size, vertex.stride)),
        Some((Buffer(3), 64, 192, Some(16)))
    );
    let draw = commands
        .iter()
        .position(|command| {
            matches!(
                command,
                Command::Draw {
                    vertex_count: 4,
                    ..
                }
            )
        })
        .unwrap();
    let push = commands
        .iter()
        .position(|command| matches!(command, Command::PushConstants(_)))
        .unwrap();
    assert!(push < draw);
    assert_eq!(commands.last(), Some(&Command::EndRendering));

    // Both stages' tables were uploaded after the inline bytes.
    let Command::PushConstants(constants) = commands[push] else {
        unreachable!()
    };
    let (chunk, bytes) = &recording.uploads[0];
    let table_at = |address: u64| {
        &bytes[(address - chunk.address) as usize..][..ArgumentTable::BYTES as usize]
    };
    let vertex_table = table_at(constants.tables[0]);
    assert_eq!(
        u64::from_le_bytes(vertex_table[16..24].try_into().unwrap()),
        (3 << 32) + 64
    );
    let fragment_table = table_at(constants.tables[1]);
    let bytes_address = u64::from_le_bytes(fragment_table[..8].try_into().unwrap());
    assert_eq!(
        &bytes[(bytes_address - chunk.address) as usize..][..12],
        &[9; 12]
    );
}

#[test]
fn render_barriers_split_the_pass_and_keep_its_contents() {
    let color = texture(PixelFormat::Rgba8Unorm);
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands
        .begin_render(
            &mut resolver,
            pass(&color, StoreAction::DontCare, false),
            None,
            Vec::new(),
        )
        .unwrap();
    commands
        .render_memory_barrier(
            &mut resolver,
            BarrierScope::TEXTURES,
            RenderStages::FRAGMENT,
            RenderStages::FRAGMENT,
        )
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let begins: Vec<_> = recording.segments[0]
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::BeginRendering(rendering) => {
                rendering.color[0].map(|color| (color.load_op, color.store_op))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        begins,
        [
            (AttachmentLoadOp::Clear, AttachmentStoreOp::Store),
            (AttachmentLoadOp::Load, AttachmentStoreOp::DontCare)
        ]
    );
    assert_eq!(
        count(&recording.segments[0].commands, |command| *command
            == Command::EndRendering),
        2
    );
}

#[test]
fn deferred_store_actions_must_be_set() {
    let color = texture(PixelFormat::Rgba8Unorm);
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands
        .begin_render(
            &mut resolver,
            pass(&color, StoreAction::Unknown, false),
            None,
            Vec::new(),
        )
        .unwrap();
    assert_eq!(
        commands.end_encoding(&mut resolver),
        Err(Error::Invalid("a store action was never set"))
    );

    let mut commands = CommandBuffer::new(FEATURES);
    commands
        .begin_render(
            &mut resolver,
            pass(&color, StoreAction::Unknown, false),
            None,
            Vec::new(),
        )
        .unwrap();
    commands
        .set_store_action(
            crate::gpu::metal::pass::AttachmentSlot::Color(0),
            StoreAction::DontCare,
        )
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
}

#[test]
fn visibility_results_copy_or_sum_their_queries() {
    let color = texture(PixelFormat::Rgba8Unorm);
    let visibility = buffer(8, 64);
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands
        .begin_render(
            &mut resolver,
            pass(&color, StoreAction::Store, true),
            Some(visibility),
            Vec::new(),
        )
        .unwrap();
    commands
        .set_render_pipeline_state(&render_state(1))
        .unwrap();
    commands
        .set_render_buffer(Stage::Vertex, Some(buffer(3, 256)), 0, 2)
        .unwrap();
    for offset in [0, 8, 0] {
        commands
            .set_visibility_result_mode(VisibilityResultMode::Counting, offset)
            .unwrap();
        commands
            .draw_primitives(&mut resolver, PrimitiveType::Triangle, 0, 3, 1, 0)
            .unwrap();
    }
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let commands = &recording.segments[0].commands;
    assert_eq!(
        count(commands, |command| matches!(
            command,
            Command::BeginQuery { precise: true, .. }
        )),
        3
    );
    assert_eq!(
        count(commands, |command| matches!(
            command,
            Command::EndQuery { .. }
        )),
        3
    );
    assert_eq!(
        recording.query_pools,
        [
            (QueryType::Occlusion, QueryPool(1)),
            (QueryType::Occlusion, QueryPool(2))
        ],
        "a second pool once the first is full"
    );
    let Some(&Command::AccumulateResults { arguments, runs }) = commands.last() else {
        panic!("{:?}", commands.last())
    };
    assert_eq!(runs, 2);
    let (chunk, bytes) = recording
        .uploads
        .iter()
        .find(|(chunk, _)| (chunk.address..chunk.address + chunk.size).contains(&arguments))
        .unwrap();
    let encoded = &bytes[(arguments - chunk.address) as usize..];
    let run = |index: usize| {
        let at = AccumulateArguments::RUNS_OFFSET as usize + 16 * index;
        let word =
            |offset: usize| u32::from_le_bytes(encoded[at + offset..][..4].try_into().unwrap());
        let destination = u64::from_le_bytes(encoded[at + 8..][..8].try_into().unwrap());
        (word(0), word(4), destination)
    };
    assert_eq!(run(0), (0, 2, 8 << 32));
    assert_eq!(run(1), (2, 1, (8 << 32) + 8));
    let end = commands
        .iter()
        .position(|command| *command == Command::EndRendering)
        .unwrap();
    let copy = commands
        .iter()
        .position(|command| matches!(command, Command::CopyQueryResults { .. }))
        .unwrap();
    assert!(end < copy, "results are copied after the pass");
}

#[test]
fn amplified_draws_repeat_per_view() {
    let color = texture(PixelFormat::Rgba8Unorm);
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands
        .begin_render(
            &mut resolver,
            pass(&color, StoreAction::Store, false),
            None,
            Vec::new(),
        )
        .unwrap();
    commands
        .set_render_pipeline_state(&render_state(2))
        .unwrap();
    commands
        .set_vertex_amplification(&[(0, 0), (1, 3)])
        .unwrap();
    commands
        .set_render_buffer(Stage::Vertex, Some(buffer(3, 256)), 0, 2)
        .unwrap();
    commands
        .draw_primitives(&mut resolver, PrimitiveType::Triangle, 0, 3, 1, 0)
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let views: Vec<_> = recording.segments[0]
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::PushConstants(constants) => {
                Some((constants.amplification_id, constants.view_mapping))
            }
            _ => None,
        })
        .collect();
    assert_eq!(views[views.len() - 2..], [(0, 0), (1, 3 << 16 | 1)]);
    assert_eq!(
        count(&recording.segments[0].commands, |command| matches!(
            command,
            Command::Draw { .. }
        )),
        2
    );
}

#[test]
fn draws_are_validated_against_the_pipeline_and_pass() {
    let color = texture(PixelFormat::Rgba8Unorm);
    let other = texture(PixelFormat::Bgra8Unorm);
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    assert!(
        commands
            .draw_primitives(&mut resolver, PrimitiveType::Triangle, 0, 3, 1, 0)
            .is_err(),
        "no encoder"
    );
    commands
        .begin_render(
            &mut resolver,
            pass(&color, StoreAction::Store, false),
            None,
            Vec::new(),
        )
        .unwrap();
    assert_eq!(
        commands.begin_blit(),
        Err(Error::Invalid("another encoder is still encoding"))
    );
    assert_eq!(
        commands.draw_primitives(&mut resolver, PrimitiveType::Triangle, 0, 3, 1, 0),
        Err(Error::Invalid("no render pipeline state is set"))
    );
    commands
        .set_render_pipeline_state(&render_state(1))
        .unwrap();
    assert_eq!(
        commands.draw_primitives(&mut resolver, PrimitiveType::Triangle, 0, 3, 1, 0),
        Err(Error::Invalid(
            "a vertex buffer the pipeline reads is unbound"
        ))
    );
    commands
        .set_render_buffer(Stage::Vertex, Some(buffer(3, 256)), 0, 2)
        .unwrap();
    assert!(
        commands
            .draw_primitives(&mut resolver, PrimitiveType::Line, 0, 2, 1, 0)
            .is_err(),
        "outside the class"
    );
    commands.end_encoding(&mut resolver).unwrap();

    commands
        .begin_render(
            &mut resolver,
            pass(&other, StoreAction::Store, false),
            None,
            Vec::new(),
        )
        .unwrap();
    assert_eq!(
        commands.set_render_pipeline_state(&render_state(1)),
        Err(Error::Invalid(
            "pipeline color formats differ from the pass"
        ))
    );
}

fn kernel_state(writes: bool) -> ComputePipelineState {
    let kernel = shader(Stage::Kernel, |interface| {
        let access = if writes {
            ShaderAccess::READ | ShaderAccess::WRITE
        } else {
            ShaderAccess::READ
        };
        interface.buffers = alloc::vec![BufferUse {
            index: 0,
            access,
            argument_buffer: false
        }];
    });
    let descriptor = ComputePipelineDescriptor {
        compute_function: &kernel.interface,
        threadgroup_size_is_multiple_of_thread_execution_width: false,
        max_total_threads_per_threadgroup: 0,
        stage_input: None,
    };
    let plan = compute_pipeline(&capabilities(), &descriptor).unwrap();
    ComputePipelineState {
        id: 1,
        plan,
        interface: kernel.interface,
    }
}

#[test]
fn stage_in_dispatches_pass_their_region() {
    let kernel = shader(Stage::Kernel, |interface| {
        interface.attributes = alloc::vec![AttributeUse {
            index: 0,
            numeric: NumericClass::Float,
            components: 4,
        }];
    });
    let layout = StageInputDescriptor {
        attributes: alloc::vec![Attribute {
            index: 0,
            format: VertexFormat::Float4,
            offset: 0,
            buffer_index: 1,
        }],
        layouts: alloc::vec![StageInLayout {
            buffer_index: 1,
            stride: 16,
            step_function: StageInStep::ThreadPositionInGridX,
            step_rate: 1,
        }],
        index_type: IndexType::UInt16,
        index_buffer_index: 0,
    };
    let descriptor = ComputePipelineDescriptor {
        compute_function: &kernel.interface,
        threadgroup_size_is_multiple_of_thread_execution_width: false,
        max_total_threads_per_threadgroup: 0,
        stage_input: Some(&layout),
    };
    let state = ComputePipelineState {
        id: 1,
        plan: compute_pipeline(&capabilities(), &descriptor).unwrap(),
        interface: kernel.interface,
    };
    let threads = Size {
        width: 32,
        height: 1,
        depth: 1,
    };
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands.begin_compute(DispatchType::Serial).unwrap();
    commands.set_compute_pipeline_state(&state).unwrap();
    assert_eq!(
        commands.dispatch_threadgroups(&mut resolver, [1, 1, 1], threads),
        Err(Error::Invalid("no stage-in region is set"))
    );
    commands.set_stage_in_region([4, 0, 0], [60, 1, 1]).unwrap();
    commands
        .dispatch_threadgroups(&mut resolver, [2, 1, 1], threads)
        .unwrap();
    commands
        .set_stage_in_region_indirect(buffer(9, 64), 8)
        .unwrap();
    commands
        .dispatch_threadgroups(&mut resolver, [2, 1, 1], threads)
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    assert_eq!(
        resolver.compiled[0].stage_in.as_ref(),
        Some(&layout),
        "the compiler specializes on the layout"
    );
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let pushed: Vec<PushConstants> = recording.segments[0]
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::PushConstants(constants) => Some(*constants),
            _ => None,
        })
        .collect();
    let (chunk, bytes) = &recording.uploads[0];
    let region = &bytes[(pushed[0].arguments - chunk.address) as usize..][..24];
    let expected: Vec<u8> = [4u32, 0, 0, 60, 1, 1]
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    assert_eq!(region, &expected[..]);
    assert_eq!(pushed[1].arguments, (9 << 32) + 8);
}

fn barriers(recording: &Recording) -> usize {
    count(&recording.segments[0].commands[1..], |command| {
        matches!(command, Command::Barrier(_))
    })
}

#[test]
fn serial_dispatches_order_writes_and_concurrent_ones_do_not() {
    let threads = Size {
        width: 64,
        height: 1,
        depth: 1,
    };
    let run = |dispatch_type, writes| {
        let mut resolver = MockResolver::default();
        let mut commands = CommandBuffer::new(FEATURES);
        commands.begin_compute(dispatch_type).unwrap();
        commands
            .set_compute_pipeline_state(&kernel_state(writes))
            .unwrap();
        commands
            .set_compute_buffer(Some(buffer(4, 1024)), 0, 0)
            .unwrap();
        commands
            .dispatch_threadgroups(&mut resolver, [4, 1, 1], threads)
            .unwrap();
        commands
            .dispatch_threads(&mut resolver, [100, 1, 1], threads)
            .unwrap();
        commands.end_encoding(&mut resolver).unwrap();
        (
            commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap(),
            resolver,
        )
    };
    let (serial, resolver) = run(DispatchType::Serial, true);
    assert_eq!(barriers(&serial), 1);
    assert_eq!(
        resolver.compiled.len(),
        1,
        "both dispatches share a variant"
    );
    assert_eq!(resolver.compiled[0].workgroup_size, Some([64, 1, 1]));
    let dispatches: Vec<_> = serial.segments[0]
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Dispatch(groups) => Some(*groups),
            _ => None,
        })
        .collect();
    assert_eq!(dispatches, [[4, 1, 1], [2, 1, 1]]);
    let grid = serial.segments[0]
        .commands
        .iter()
        .rev()
        .find_map(|command| match command {
            Command::PushConstants(constants) => Some(constants.grid),
            _ => None,
        });
    assert_eq!(grid, Some([100, 1, 1]));

    assert_eq!(
        barriers(&run(DispatchType::Serial, false).0),
        0,
        "read-only dispatches never wait"
    );
    assert_eq!(barriers(&run(DispatchType::Concurrent, true).0), 0);
}

#[test]
fn encoders_after_writes_wait_for_them() {
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands.begin_compute(DispatchType::Serial).unwrap();
    commands
        .set_compute_pipeline_state(&kernel_state(true))
        .unwrap();
    commands
        .dispatch_threadgroups(
            &mut resolver,
            [1, 1, 1],
            Size {
                width: 32,
                height: 1,
                depth: 1,
            },
        )
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    commands.begin_blit().unwrap();
    commands
        .copy_buffer(buffer(4, 64), 0, buffer(5, 64), 0, 64)
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let barrier = recording.segments[0]
        .commands
        .iter()
        .skip(1)
        .find_map(|command| match command {
            Command::Barrier(barrier) => Some(*barrier),
            _ => None,
        });
    assert_eq!(
        barrier,
        Some(Barrier {
            src_stages: PipelineStages::COMPUTE_SHADER,
            src_access: Access::SHADER_WRITE,
            dst_stages: PipelineStages::ALL_TRANSFER,
            dst_access: Access::TRANSFER_READ | Access::TRANSFER_WRITE,
        })
    );
}

#[test]
fn unaligned_fills_copy_their_edges() {
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands.begin_blit().unwrap();
    commands
        .fill_buffer(&mut resolver, buffer(6, 64), 3, 10, 0xab)
        .unwrap();
    commands
        .fill_buffer(&mut resolver, buffer(6, 64), 41, 2, 0xcd)
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let commands = &recording.segments[0].commands;
    assert!(commands.contains(&Command::FillBuffer {
        buffer: Buffer(6),
        offset: 4,
        size: 8,
        data: 0xabab_abab
    }));
    let copies: Vec<_> = commands
        .iter()
        .filter_map(|command| match command {
            Command::CopyBuffer {
                dst: Buffer(6),
                regions,
                ..
            } => Some((regions[0].dst_offset, regions[0].size)),
            _ => None,
        })
        .collect();
    assert_eq!(copies, [(3, 1), (12, 1), (41, 2)]);
}

#[test]
fn buffer_texture_copies_use_texel_strides() {
    let color = texture(PixelFormat::Rgba16Float);
    let depth = texture(PixelFormat::Depth32FloatStencil8);
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands.begin_blit().unwrap();
    let source = BufferLayout {
        buffer: buffer(2, 1 << 16),
        offset: 256,
        bytes_per_row: 512,
        bytes_per_image: 0,
    };
    let region = Region {
        slice: 0,
        level: 1,
        origin: [8, 0, 0],
        size: [16, 16, 1],
    };
    let target = BlitTexture {
        image: Image(9),
        descriptor: &color,
    };
    commands
        .copy_buffer_to_texture(source, target, region, BlitOption::EMPTY)
        .unwrap();
    let outside = Region {
        level: 1,
        origin: [24, 0, 0],
        ..region
    };
    assert!(
        commands
            .copy_buffer_to_texture(source, target, outside, BlitOption::EMPTY)
            .is_err()
    );
    let depth_target = BlitTexture {
        image: Image(10),
        descriptor: &depth,
    };
    assert_eq!(
        commands.copy_buffer_to_texture(source, depth_target, region, BlitOption::EMPTY),
        Err(Error::Invalid("depth-stencil copies name one aspect"))
    );
    commands
        .copy_buffer_to_texture(
            source,
            depth_target,
            region,
            BlitOption::STENCIL_FROM_DEPTH_STENCIL,
        )
        .unwrap();
    commands.generate_mipmaps(target, true).unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let copies: Vec<_> = recording.segments[0]
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::CopyBufferToImage { regions, .. } => Some(regions[0]),
            _ => None,
        })
        .collect();
    assert_eq!(
        (
            copies[0].buffer_offset,
            copies[0].buffer_row_length,
            copies[0].buffer_image_height
        ),
        (256, 64, 16)
    );
    assert_eq!(
        (copies[1].subresource.aspects, copies[1].buffer_row_length),
        (crate::gpu::metal::vulkan::ImageAspects::STENCIL, 512)
    );
    let blits = count(&recording.segments[0].commands, |command| {
        matches!(command, Command::BlitImage { .. })
    });
    assert_eq!(blits, 2, "levels 1 and 2 are generated");
    let _ = BufferCopy {
        src_offset: 0,
        dst_offset: 0,
        size: 0,
    };
}

#[test]
fn events_split_command_buffers_into_submissions() {
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands
        .encode_wait_for_event(&mut resolver, Semaphore(7), 3)
        .unwrap();
    commands.begin_blit().unwrap();
    commands
        .copy_buffer(buffer(4, 64), 0, buffer(5, 64), 0, 64)
        .unwrap();
    assert!(
        commands
            .encode_signal_event(&mut resolver, Semaphore(8), 1)
            .is_err(),
        "events wait for the encoder to end"
    );
    commands.end_encoding(&mut resolver).unwrap();
    commands
        .encode_signal_event(&mut resolver, Semaphore(8), 1)
        .unwrap();
    commands
        .encode_wait_for_event(&mut resolver, Semaphore(7), 4)
        .unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 9)).unwrap();
    let shape: Vec<_> = recording
        .segments
        .iter()
        .map(|segment| {
            (
                segment.waits.clone(),
                segment.commands.len(),
                segment.signals.clone(),
            )
        })
        .collect();
    assert_eq!(
        shape,
        [
            (
                alloc::vec![(Semaphore(7), 3)],
                2,
                alloc::vec![(Semaphore(8), 1)]
            ),
            (
                alloc::vec![(Semaphore(7), 4)],
                1,
                alloc::vec![(Semaphore(1), 9)]
            ),
        ]
    );
}

#[test]
fn bindings_validate_slots_and_offsets() {
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands.begin_compute(DispatchType::Serial).unwrap();
    assert!(
        commands
            .set_compute_buffer(Some(buffer(1, 16)), 32, 0)
            .is_err()
    );
    assert!(
        commands
            .set_compute_buffer(Some(buffer(1, 16)), 0, 31)
            .is_err()
    );
    assert!(
        commands.set_compute_buffer_offset(4, 3).is_err(),
        "nothing bound"
    );
    commands
        .set_compute_buffer(Some(buffer(1, 16)), 0, 3)
        .unwrap();
    commands.set_compute_buffer_offset(4, 3).unwrap();
    assert!(commands.set_compute_texture(ResourceId::NULL, 128).is_err());
    assert!(
        commands
            .set_compute_bytes(&mut resolver, &[0; 4097], 0)
            .is_err()
    );
    commands
        .set_compute_sampler(&mut resolver, ResourceId(5), Some((0.0, 2.0)), 0)
        .unwrap();
    assert!(
        commands
            .set_compute_sampler(&mut resolver, ResourceId(5), None, 16)
            .is_err()
    );
}

/// The bytes uploaded at `address`.
fn uploaded(recording: &Recording, address: u64) -> &[u8] {
    let (chunk, bytes) = recording
        .uploads
        .iter()
        .find(|(chunk, _)| (chunk.address..chunk.address + chunk.size).contains(&address))
        .expect("an upload holds the address");
    &bytes[(address - chunk.address) as usize..]
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn double(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

#[test]
fn statistic_samples_sum_intervals_no_query_spans() {
    let color = texture(PixelFormat::Rgba8Unorm);
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    let first = 9 << 32;
    commands
        .sample_counters(&mut resolver, CounterSample::Statistic(first), false)
        .unwrap();
    commands
        .begin_render(
            &mut resolver,
            pass(&color, StoreAction::Store, false),
            None,
            Vec::new(),
        )
        .unwrap();
    commands
        .set_render_pipeline_state(&patch_state(None))
        .unwrap();
    commands
        .set_tessellation_factor_buffer(Some(buffer(4, 1024)), 96, 48)
        .unwrap();
    let source = PatchSource {
        control_points: 4,
        patch_indices: None,
        control_point_indices: Some((buffer(5, 4096), 64)),
    };
    commands
        .draw_patches(&mut resolver, &source, 0, 1, 1, 0)
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    commands
        .sample_counters(&mut resolver, CounterSample::Statistic(first + 64), false)
        .unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let commands = &recording.segments[0].commands;

    let mut active = false;
    for command in commands {
        match command {
            Command::BeginQuery { .. } => active = true,
            Command::EndQuery { .. } => active = false,
            Command::BeginRendering(_) | Command::EndRendering => {
                assert!(!active, "no statistics query spans a pass boundary");
            }
            _ => {}
        }
    }
    assert!(!active, "commit ends the last interval");
    // Before the pass, the pass up to the patch draw, the patch draw, the
    // rest of the pass, after the pass, and after the second sample.
    assert_eq!(
        count(commands, |c| matches!(c, Command::BeginQuery { .. })),
        6
    );
    assert!(
        recording
            .query_pools
            .iter()
            .all(|&(query_type, _)| query_type == QueryType::PipelineStatistics)
    );
    let copies: Vec<_> = commands
        .iter()
        .filter_map(|command| match command {
            &Command::CopyQueryResults {
                first,
                count,
                stride,
                wait,
                ..
            } => Some((first, count, stride, wait)),
            _ => None,
        })
        .collect();
    // Two queries per mock pool: the five ended intervals copy in three runs.
    assert_eq!(
        copies,
        [(0, 2, 56, true), (0, 2, 56, true), (0, 1, 56, true)]
    );
    let cleared: Vec<_> = commands
        .iter()
        .filter_map(|command| match command {
            &Command::FillBuffer { size, data, .. } => Some((size, data)),
            _ => None,
        })
        .collect();
    assert_eq!(cleared, [(8, 0)], "the patch draw's vertex invocations");

    let Some(&Command::AccumulateResults { arguments, runs }) = commands.last() else {
        panic!("{:?}", commands.last())
    };
    assert_eq!(runs, 14, "seven counted members per sample");
    let encoded = uploaded(&recording, arguments);
    assert_eq!(word(encoded, 12), 7, "one interval's results apart");
    let run = |index: usize| {
        let at = AccumulateArguments::RUNS_OFFSET as usize + 16 * index;
        (
            word(encoded, at),
            word(encoded, at + 4),
            double(encoded, at + 8),
        )
    };
    assert_eq!(
        run(0),
        (4, 0, first),
        "the first sample precedes every interval"
    );
    assert_eq!(run(7), (4, 5, first + 64), "tessellation input patches");
    assert_eq!(run(8), (0, 5, first + 72), "vertex invocations");
    assert_eq!(run(13), (6, 5, first + 120), "compute kernel invocations");
    assert!(
        (0..14).all(|index| run(index).2 != first + 64 + 48),
        "fragments passed keeps the error value"
    );
}

#[test]
fn render_pass_timestamps_reset_before_the_pass() {
    let color = texture(PixelFormat::Rgba8Unorm);
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    let pool = QueryPool(30);
    let sample = |query| CounterSample::Timestamp { pool, query };
    commands
        .begin_render(
            &mut resolver,
            pass(&color, StoreAction::Store, false),
            None,
            alloc::vec![
                (sample(0), PassBoundary::StartOfVertex),
                (sample(1), PassBoundary::EndOfFragment),
            ],
        )
        .unwrap();
    commands
        .sample_counters(&mut resolver, sample(2), true)
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let commands = &recording.segments[0].commands;
    let begin = commands
        .iter()
        .position(|command| matches!(command, Command::BeginRendering(_)))
        .unwrap();
    for query in 0..3 {
        let reset = commands.iter().position(|command| {
            *command
                == Command::ResetQueryPool {
                    pool,
                    first: query,
                    count: 1,
                }
        });
        assert!(reset.is_some_and(|reset| reset < begin), "query {query}");
    }
    assert!(commands.contains(&Command::WriteTimestamp {
        pool,
        query: 2,
        stage: PipelineStages::ALL_COMMANDS,
    }));
    assert!(commands.contains(&Command::WriteTimestamp {
        pool,
        query: 1,
        stage: PipelineStages::FRAGMENT_SHADER,
    }));
}

#[test]
fn blits_resolve_counters_on_the_gpu() {
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    let samples = buffer(9, 128);
    commands
        .sample_counters(
            &mut resolver,
            CounterSample::Statistic(samples.address),
            false,
        )
        .unwrap();
    commands.begin_blit().unwrap();
    let timestamps = CounterRange::Timestamps {
        pool: QueryPool(30),
        first: 1,
        count: 2,
    };
    assert!(
        commands
            .resolve_counters(&mut resolver, timestamps, buffer(5, 64), 4)
            .is_err(),
        "results are 8-byte aligned"
    );
    commands
        .resolve_counters(&mut resolver, timestamps, buffer(5, 64), 8)
        .unwrap();
    commands
        .resolve_counters(
            &mut resolver,
            CounterRange::Statistics(samples),
            buffer(6, 256),
            0,
        )
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let commands = &recording.segments[0].commands;

    let fill = commands
        .iter()
        .position(|command| {
            *command
                == Command::FillBuffer {
                    buffer: Buffer(5),
                    offset: 8,
                    size: 16,
                    data: u32::MAX,
                }
        })
        .expect("untaken samples hold the error value");
    let copy = commands
        .iter()
        .position(|command| {
            matches!(
                command,
                Command::CopyQueryResults {
                    first: 1,
                    count: 2,
                    wait: false,
                    ..
                }
            )
        })
        .unwrap();
    assert!(fill < copy);
    let accumulate = commands
        .iter()
        .position(|command| matches!(command, Command::AccumulateResults { .. }))
        .unwrap();
    let resolved = commands
        .iter()
        .position(|command| matches!(command, Command::CopyBuffer { src: Buffer(9), .. }))
        .unwrap();
    assert!(
        accumulate < resolved,
        "pending statistic samples resolve first"
    );
    assert_eq!(
        count(commands, |c| matches!(c, Command::AccumulateResults { .. })),
        1,
        "commit has nothing left to resolve"
    );
}

fn icb_descriptor(command_types: IndirectCommandType) -> IndirectCommandBufferDescriptor {
    IndirectCommandBufferDescriptor {
        command_types,
        inherit_pipeline_state: false,
        inherit_buffers: false,
        inherit_cull_mode: false,
        inherit_depth_stencil_state: true,
        inherit_depth_bias: true,
        inherit_depth_clip_mode: true,
        inherit_front_facing_winding: true,
        inherit_triangle_fill_mode: true,
        max_vertex_buffer_bind_count: 4,
        max_fragment_buffer_bind_count: 1,
        max_kernel_buffer_bind_count: 1,
        max_kernel_threadgroup_memory_bind_count: 0,
        max_object_buffer_bind_count: 0,
        max_mesh_buffer_bind_count: 0,
        support_ray_tracing: false,
        support_dynamic_attribute_stride: false,
    }
}

/// A resolver knowing the encoder's pipeline (id 0, `Pipeline(42)`), an
/// indirect pipeline (id 1, `Pipeline(43)`) and `buffer` as indirect
/// command buffer 0.
fn icb_resolver(buffer: IndirectCommandBuffer) -> MockResolver {
    let mut other = render_state(1);
    other.id = 1;
    other.pipeline = Some(Pipeline(43));
    MockResolver {
        render_states: alloc::vec![render_state(1), other],
        indirect: alloc::vec![Arc::new(buffer)],
        ..MockResolver::default()
    }
}

fn render_icb(count: u64) -> IndirectCommandBuffer {
    let types = IndirectCommandType::DRAW | IndirectCommandType::DRAW_INDEXED;
    let mut icb =
        IndirectCommandBuffer::new(&capabilities(), &icb_descriptor(types), count).unwrap();
    let mut other = render_state(1);
    other.id = 1;
    for index in 0..count as usize {
        let mut command = icb.render_command(index).unwrap();
        command.set_render_pipeline_state(&other).unwrap();
        command
            .set_buffer(Stage::Vertex, buffer(5, 256), 0, 2)
            .unwrap();
        command.set_cull_mode(CullModeAbi::Back).unwrap();
        command
            .draw_primitives(PrimitiveType::Triangle, 0, 3, 1, 0)
            .unwrap();
    }
    icb
}

fn vertex_buffers(commands: &[Command]) -> Vec<Buffer> {
    commands
        .iter()
        .filter_map(|command| match command {
            Command::BindVertexBuffers { buffers, .. } => Some(buffers[0].buffer),
            _ => None,
        })
        .collect()
}

#[test]
fn indirect_draws_replay_and_restore_the_encoder() {
    let mut icb = render_icb(3);
    icb.render_command(1).unwrap().reset().unwrap();
    let mut indexed = icb.render_command(2).unwrap();
    indexed
        .draw_indexed_primitives(
            PrimitiveType::Triangle,
            6,
            IndexType::UInt16,
            buffer(6, 64),
            0,
            1,
            0,
            0,
        )
        .unwrap();
    let mut resolver = icb_resolver(icb);
    let color = texture(PixelFormat::Rgba8Unorm);
    let mut commands = CommandBuffer::new(FEATURES);
    commands
        .begin_render(
            &mut resolver,
            pass(&color, StoreAction::Store, false),
            None,
            Vec::new(),
        )
        .unwrap();
    commands
        .set_render_pipeline_state(&render_state(1))
        .unwrap();
    commands
        .set_render_buffer(Stage::Vertex, Some(buffer(3, 256)), 0, 2)
        .unwrap();
    commands
        .execute_commands(
            &mut resolver,
            IndirectCommandBufferId(0),
            ExecutionRange::Direct(0..3),
        )
        .unwrap();
    commands
        .draw_primitives(&mut resolver, PrimitiveType::Triangle, 0, 4, 1, 0)
        .unwrap();
    assert!(
        commands
            .execute_commands(
                &mut resolver,
                IndirectCommandBufferId(0),
                ExecutionRange::Direct(2..4)
            )
            .is_err()
    );
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let commands = &recording.segments[0].commands;

    let pipelines: Vec<Pipeline> = commands
        .iter()
        .filter_map(|command| match command {
            Command::BindPipeline { pipeline, .. } => Some(*pipeline),
            _ => None,
        })
        .collect();
    assert_eq!(
        pipelines,
        [Pipeline(42), Pipeline(43), Pipeline(42)],
        "the commands share a pipeline, then the encoder's returns"
    );
    assert_eq!(
        vertex_buffers(commands),
        [Buffer(5), Buffer(3)],
        "the commands' buffers bind once"
    );
    let culls: Vec<&Command> = commands
        .iter()
        .filter(|command| matches!(command, Command::SetCullMode(_)))
        .collect();
    assert_eq!(
        culls[1..],
        [
            &Command::SetCullMode(CullMode::BACK),
            &Command::SetCullMode(CullMode::EMPTY)
        ]
    );
    let draws: Vec<u32> = commands
        .iter()
        .filter_map(|command| match command {
            Command::Draw { vertex_count, .. } => Some(*vertex_count),
            Command::DrawIndexed { index_count, .. } => Some(*index_count),
            _ => None,
        })
        .collect();
    assert_eq!(draws, [3, 6, 4], "the reset command draws nothing");
}

#[test]
fn gpu_ranges_select_commands_outside_the_pass() {
    let mut resolver = icb_resolver(render_icb(2));
    let color = texture(PixelFormat::Rgba8Unorm);
    let mut commands = CommandBuffer::new(FEATURES);
    commands
        .begin_render(
            &mut resolver,
            pass(&color, StoreAction::Store, false),
            None,
            Vec::new(),
        )
        .unwrap();
    let range = |offset| ExecutionRange::Indirect {
        buffer: buffer(9, 64),
        offset,
    };
    let id = IndirectCommandBufferId(0);
    assert!(
        commands
            .execute_commands(&mut resolver, id, range(2))
            .is_err()
    );
    assert!(
        commands
            .execute_commands(&mut resolver, id, range(60))
            .is_err()
    );
    commands
        .execute_commands(&mut resolver, id, range(8))
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let commands = &recording.segments[0].commands;

    let select = commands
        .iter()
        .position(|command| matches!(command, Command::SelectCommands { count: 2, .. }))
        .unwrap();
    assert!(matches!(commands[select - 2], Command::EndRendering));
    let resume = select
        + commands[select..]
            .iter()
            .position(|command| matches!(command, Command::BeginRendering(_)))
            .unwrap();
    assert!(
        commands[select..resume]
            .iter()
            .any(|command| matches!(command, Command::Barrier(barrier)
                if barrier.dst_stages.contains(PipelineStages::CONDITIONAL_RENDERING))),
        "the flags are visible to conditional rendering"
    );
    let Command::SelectCommands { arguments, .. } = commands[select] else {
        unreachable!()
    };
    let arguments = uploaded(&recording, arguments);
    assert_eq!(double(arguments, 0), (9 << 32) + 8);
    assert_eq!(word(arguments, 16), 2);
    let flags = double(arguments, 8);

    let gated: Vec<(usize, u64)> = commands
        .iter()
        .enumerate()
        .filter_map(|(index, command)| match command {
            Command::BeginConditionalRendering { offset, .. } => Some((index, *offset)),
            _ => None,
        })
        .collect();
    assert_eq!(gated.len(), 2);
    let flag_offset = |address: u64| {
        let (chunk, _) = recording
            .uploads
            .iter()
            .find(|(chunk, _)| (chunk.address..chunk.address + chunk.size).contains(&address))
            .unwrap();
        address - chunk.address
    };
    assert_eq!(gated[0].1, flag_offset(flags));
    assert_eq!(gated[1].1, flag_offset(flags) + 4);
    for &(begin, _) in &gated {
        let end = begin
            + commands[begin..]
                .iter()
                .position(|command| matches!(command, Command::EndConditionalRendering))
                .unwrap();
        assert_eq!(
            count(&commands[begin..end], |command| matches!(
                command,
                Command::Draw { .. }
            )),
            1,
            "each command's draw is gated by its flag"
        );
    }
}

#[test]
fn indirect_dispatches_compile_their_variants() {
    let types =
        IndirectCommandType::CONCURRENT_DISPATCH | IndirectCommandType::CONCURRENT_DISPATCH_THREADS;
    let mut icb = IndirectCommandBuffer::new(&capabilities(), &icb_descriptor(types), 2).unwrap();
    let state = kernel_state(true);
    let threads = |width| Size {
        width,
        height: 1,
        depth: 1,
    };
    let mut first = icb.compute_command(0).unwrap();
    first.set_compute_pipeline_state(&state).unwrap();
    first.set_kernel_buffer(buffer(4, 64), 0, 0).unwrap();
    first
        .concurrent_dispatch_threadgroups([2, 1, 1], threads(64))
        .unwrap();
    let mut second = icb.compute_command(1).unwrap();
    second.set_compute_pipeline_state(&state).unwrap();
    second.set_kernel_buffer(buffer(4, 64), 0, 0).unwrap();
    second.set_barrier().unwrap();
    second
        .concurrent_dispatch_threads([100, 1, 1], threads(32))
        .unwrap();
    let mut resolver = MockResolver {
        compute_states: alloc::vec![state],
        indirect: alloc::vec![Arc::new(icb)],
        ..MockResolver::default()
    };
    let mut commands = CommandBuffer::new(FEATURES);
    commands.begin_compute(DispatchType::Concurrent).unwrap();
    commands
        .execute_commands(
            &mut resolver,
            IndirectCommandBufferId(0),
            ExecutionRange::Direct(0..2),
        )
        .unwrap();
    assert_eq!(
        commands.dispatch_threadgroups(&mut resolver, [1, 1, 1], threads(1)),
        Err(Error::Invalid("no compute pipeline state is set")),
        "the encoder's own state returns"
    );
    commands.end_encoding(&mut resolver).unwrap();
    assert_eq!(
        resolver.compiled.len(),
        2,
        "one variant per threadgroup size"
    );
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let commands = &recording.segments[0].commands;
    let dispatches: Vec<usize> = commands
        .iter()
        .enumerate()
        .filter_map(|(index, command)| matches!(command, Command::Dispatch(_)).then_some(index))
        .collect();
    assert_eq!(commands[dispatches[0]], Command::Dispatch([2, 1, 1]));
    assert_eq!(commands[dispatches[1]], Command::Dispatch([4, 1, 1]));
    assert!(
        commands[dispatches[0]..dispatches[1]].contains(&Command::Barrier(FULL)),
        "the second command's barrier"
    );
}

#[test]
fn blits_reset_and_copy_indirect_commands() {
    let types = IndirectCommandType::DRAW;
    let empty = IndirectCommandBuffer::new(&capabilities(), &icb_descriptor(types), 3).unwrap();
    let mut resolver = icb_resolver(render_icb(2));
    resolver.indirect.push(Arc::new(empty));
    let (source, destination) = (IndirectCommandBufferId(0), IndirectCommandBufferId(1));
    let mut commands = CommandBuffer::new(FEATURES);
    assert!(
        commands
            .reset_commands(&mut resolver, source, 0..1)
            .is_err(),
        "outside a blit encoder"
    );
    commands.begin_blit().unwrap();
    commands
        .copy_indirect_commands(&mut resolver, source, 0..2, destination, 1)
        .unwrap();
    assert!(
        commands
            .copy_indirect_commands(&mut resolver, source, 0..2, destination, 2)
            .is_err()
    );
    commands
        .reset_commands(&mut resolver, source, 1..2)
        .unwrap();
    commands
        .optimize_indirect_commands(&mut resolver, destination, 0..3)
        .unwrap();
    assert!(
        commands
            .optimize_indirect_commands(&mut resolver, destination, 2..4)
            .is_err()
    );
    let copied = resolver.indirect[1].commands(0..3).unwrap();
    assert!(copied[0].action.is_none());
    assert!(copied[1].action.is_some() && copied[2].action.is_some());
    let reset = resolver.indirect[0].commands(0..2).unwrap();
    assert!(reset[0].action.is_some() && reset[1].action.is_none());
}

#[test]
fn blits_copy_records_of_resident_buffers_in_order() {
    let descriptor = IndirectCommandBufferDescriptor {
        inherit_pipeline_state: true,
        inherit_cull_mode: true,
        ..icb_descriptor(IndirectCommandType::DRAW)
    };
    let new = || IndirectCommandBuffer::new(&capabilities(), &descriptor, 3).unwrap();
    let mut source = new();
    source
        .render_command(0)
        .unwrap()
        .draw_primitives(PrimitiveType::Point, 0, 3, 1, 0)
        .unwrap();
    let narrow = IndirectCommandBufferDescriptor {
        max_vertex_buffer_bind_count: 1,
        ..descriptor
    };
    let narrow = IndirectCommandBuffer::new(&capabilities(), &narrow, 3).unwrap();
    let mut resolver = MockResolver {
        indirect: [source, new(), new(), narrow].map(Arc::new).to_vec(),
        ..MockResolver::default()
    };
    let id = IndirectCommandBufferId;
    let (layout, records) = resolver.indirect_records(id(1)).unwrap();
    let mut commands = CommandBuffer::new(FEATURES);
    commands.begin_blit().unwrap();
    // Into a resident buffer, the CPU's commands land as records.
    commands
        .copy_indirect_commands(&mut resolver, id(0), 0..2, id(1), 1)
        .unwrap();
    assert!(resolver.indirect[0].records().is_none());
    // From one, the destination becomes resident.
    commands
        .copy_indirect_commands(&mut resolver, id(1), 0..3, id(2), 0)
        .unwrap();
    assert!(resolver.indirect[2].records().is_some());
    assert!(
        commands
            .copy_indirect_commands(&mut resolver, id(1), 0..1, id(3), 0)
            .is_err(),
        "the layouts differ"
    );
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit(&mut resolver, (Semaphore(1), 1)).unwrap();
    let copies: Vec<_> = recording.segments[0]
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::CopyBuffer { src, dst, regions } => Some((*src, *dst, regions[0])),
            _ => None,
        })
        .collect();
    let stride = u64::from(layout.stride);
    assert_eq!(copies.len(), 2);
    assert_eq!(
        (copies[0].1, copies[0].2.dst_offset, copies[0].2.size),
        (records.buffer, layout.record(1), 2 * stride)
    );
    assert_eq!(
        (copies[1].0, copies[1].2.src_offset, copies[1].2.size),
        (records.buffer, layout.record(0), 3 * stride)
    );
}
