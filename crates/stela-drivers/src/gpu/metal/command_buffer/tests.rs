use super::{
    blit::{BlitTexture, BufferLayout, Region},
    render::{PatchSource, Viewport},
    *,
};
use crate::gpu::metal::{
    abi::{
        BarrierScope, BlitOption, CpuCacheMode, DispatchType, HazardTrackingMode, LoadAction,
        PrimitiveTopologyClass, PrimitiveType, RenderStages, ResourceOptions, StorageMode,
        StoreAction, StoreActionOptions, SwizzleChannels, TessellationControlPointIndexType,
        TextureType, TextureUsage, VisibilityResultMode,
    },
    binding::{ArgumentTable, BufferBinding, PushConstants, TessellationArguments},
    capabilities::Size,
    error::Error,
    hazard::FULL,
    nvidia::fixture::capabilities,
    pass::{AttachedTexture, AttachmentDescriptor, RenderPassDescriptor, Target, render_pass},
    pipeline::{
        ColorAttachmentDescriptor, ComputePipelineDescriptor, MAX_COLOR_ATTACHMENTS,
        RenderPipelineDescriptor, RenderTargets, TessellatedVertex, TessellationDescriptor,
        compute_pipeline, render_pipeline, tessellation,
    },
    pixel_format::PixelFormat,
    resource::TextureDescriptor,
    shader::{
        Access as ShaderAccess, BufferUse, CompiledShader, Patch, PatchDomain, Provenance,
        tests::interface,
    },
    vertex::{Attribute, Layout, StepFunction, VertexDescriptor, VertexFormat},
    vulkan::{
        Access, AttachmentLoadOp, AttachmentStoreOp, PipelineStages,
        command::{Barrier, BufferCopy},
        object::{Image, ImageView, ShaderCode},
    },
};
use alloc::vec::Vec;

#[derive(Default)]
struct MockResolver {
    chunks: u64,
    compiled: Vec<Specialization>,
    pools: u64,
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

    fn occlusion_pool(&mut self) -> Result<(QueryPool, u32)> {
        self.pools += 1;
        Ok((QueryPool(self.pools), 2))
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
    }
}

/// A pipeline of a quad post-tessellation function with four control
/// points, indexed by 16-bit control point indices.
fn patch_state() -> RenderPipelineState {
    let evaluation = shader(Stage::Vertex, |interface| {
        interface.patch = Some(Patch {
            domain: PatchDomain::Quad,
            control_points: Some(4),
        });
    });
    let properties = TessellationDescriptor {
        factor_scale_enabled: true,
        control_point_index_type: TessellationControlPointIndexType::UInt16,
        ..TessellationDescriptor::default()
    };
    let tessellation = tessellation(&capabilities(), &evaluation.interface, &properties, None)
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
    }
}

#[test]
fn patch_draws_upload_their_tessellation_arguments() {
    let color = texture(PixelFormat::Rgba8Unorm);
    let mut resolver = MockResolver::default();
    let mut commands = CommandBuffer::new(FEATURES);
    commands
        .begin_render(pass(&color, StoreAction::Store, false), None, Vec::new())
        .unwrap();
    commands.set_render_pipeline_state(&patch_state()).unwrap();
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
    let recording = commands.commit((Semaphore(1), 1)).unwrap();
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
    let arguments = &bytes[(constants.tessellation - chunk.address) as usize..]
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
    };
    assert_eq!(arguments, expected.encode());
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
        .begin_render(pass(&color, StoreAction::Store, false), None, Vec::new())
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
    let recording = commands.commit((Semaphore(1), 5)).unwrap();

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
    assert!(commands.contains(&Command::BindPipeline(Pipeline(42))));
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
        .begin_render(pass(&color, StoreAction::DontCare, false), None, Vec::new())
        .unwrap();
    commands
        .render_memory_barrier(
            BarrierScope::TEXTURES,
            RenderStages::FRAGMENT,
            RenderStages::FRAGMENT,
        )
        .unwrap();
    commands.end_encoding(&mut resolver).unwrap();
    let recording = commands.commit((Semaphore(1), 1)).unwrap();
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
        .begin_render(pass(&color, StoreAction::Unknown, false), None, Vec::new())
        .unwrap();
    assert_eq!(
        commands.end_encoding(&mut resolver),
        Err(Error::Invalid("a store action was never set"))
    );

    let mut commands = CommandBuffer::new(FEATURES);
    commands
        .begin_render(pass(&color, StoreAction::Unknown, false), None, Vec::new())
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
    let recording = commands.commit((Semaphore(1), 1)).unwrap();
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
        [QueryPool(1), QueryPool(2)],
        "a second pool once the first is full"
    );
    let Some(Command::AccumulateResults { sums, dst, .. }) = commands.last() else {
        panic!("{:?}", commands.last())
    };
    assert_eq!(*dst, Buffer(8));
    assert_eq!(sums, &[(0, 2, 0), (2, 1, 8)]);
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
        .begin_render(pass(&color, StoreAction::Store, false), None, Vec::new())
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
    let recording = commands.commit((Semaphore(1), 1)).unwrap();
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
        .begin_render(pass(&color, StoreAction::Store, false), None, Vec::new())
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
        .begin_render(pass(&other, StoreAction::Store, false), None, Vec::new())
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
    };
    let plan = compute_pipeline(&capabilities(), &descriptor).unwrap();
    ComputePipelineState {
        id: 1,
        plan,
        interface: kernel.interface,
    }
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
        (commands.commit((Semaphore(1), 1)).unwrap(), resolver)
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
    let recording = commands.commit((Semaphore(1), 1)).unwrap();
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
    let recording = commands.commit((Semaphore(1), 1)).unwrap();
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
    let recording = commands.commit((Semaphore(1), 1)).unwrap();
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
    commands.encode_wait_for_event(Semaphore(7), 3).unwrap();
    commands.begin_blit().unwrap();
    commands
        .copy_buffer(buffer(4, 64), 0, buffer(5, 64), 0, 64)
        .unwrap();
    assert!(
        commands.encode_signal_event(Semaphore(8), 1).is_err(),
        "events wait for the encoder to end"
    );
    commands.end_encoding(&mut resolver).unwrap();
    commands.encode_signal_event(Semaphore(8), 1).unwrap();
    commands.encode_wait_for_event(Semaphore(7), 4).unwrap();
    let recording = commands.commit((Semaphore(1), 9)).unwrap();
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
