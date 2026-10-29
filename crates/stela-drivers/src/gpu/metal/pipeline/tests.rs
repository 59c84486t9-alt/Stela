use super::*;
use crate::gpu::metal::{
    nvidia::fixture::capabilities,
    shader::{
        AttributeUse, ColorOutput, Patch, PatchDomain, Provenance, ThreadgroupUse, tests::interface,
    },
    vertex::{Attribute, Layout, StepFunction, VertexFormat},
};

fn shader(stage: Stage, code: u64, edit: impl FnOnce(&mut Interface)) -> CompiledShader {
    let mut interface = interface(stage);
    edit(&mut interface);
    CompiledShader {
        code: ShaderCode(code),
        interface,
        provenance: Provenance::default(),
    }
}

fn output(index: u32, numeric: NumericClass) -> ColorOutput {
    ColorOutput {
        index,
        numeric,
        dual_source: false,
    }
}

fn color(format: PixelFormat) -> ColorAttachmentDescriptor {
    ColorAttachmentDescriptor {
        pixel_format: Some(format),
        ..ColorAttachmentDescriptor::default()
    }
}

fn descriptor<'a>(
    vertex: &'a CompiledShader,
    fragment: Option<&'a CompiledShader>,
) -> RenderPipelineDescriptor<'a> {
    RenderPipelineDescriptor {
        vertex_function: vertex,
        fragment_function: fragment,
        vertex_descriptor: None,
        targets: RenderTargets::default(),
        input_primitive_topology: PrimitiveTopologyClass::Unspecified,
        max_vertex_amplification_count: 1,
        tessellation: None,
    }
}

#[test]
fn blend_state_translation() {
    assert_eq!(
        blend_factor(MtlBlendFactor::BlendAlpha),
        BlendFactor::ConstantAlpha
    );
    assert_eq!(
        blend_factor(MtlBlendFactor::OneMinusSource1Alpha),
        BlendFactor::OneMinusSrc1Alpha
    );
    assert_eq!(
        write_mask(ColorWriteMask::RED | ColorWriteMask::ALPHA),
        ColorComponents::R | ColorComponents::A
    );
    assert_eq!(write_mask(ColorWriteMask::KNOWN), ColorComponents::KNOWN);
    assert_eq!(
        class_topology(PrimitiveTopologyClass::Line),
        PrimitiveTopology::LineList
    );
}

#[test]
fn render_pipeline_with_vertex_layout_and_blending() {
    let capabilities = capabilities();
    let vertex = shader(Stage::Vertex, 1, |interface| {
        interface.attributes = alloc::vec![AttributeUse {
            index: 0,
            numeric: NumericClass::Float,
            components: 3
        }];
    });
    let fragment = shader(Stage::Fragment, 2, |interface| {
        interface.color_outputs = alloc::vec![
            output(0, NumericClass::Float),
            output(2, NumericClass::Uint)
        ];
    });
    let layout = VertexDescriptor {
        attributes: alloc::vec![Attribute {
            index: 0,
            format: VertexFormat::Float3,
            offset: 0,
            buffer_index: 0
        }],
        layouts: alloc::vec![Layout {
            buffer_index: 0,
            stride: 12,
            step_function: StepFunction::PerVertex,
            step_rate: 1
        }],
    };
    let mut descriptor = descriptor(&vertex, Some(&fragment));
    descriptor.vertex_descriptor = Some(&layout);
    descriptor.targets.color_attachments[0] = ColorAttachmentDescriptor {
        blending_enabled: true,
        source_rgb_blend_factor: MtlBlendFactor::SourceAlpha,
        destination_rgb_blend_factor: MtlBlendFactor::OneMinusSourceAlpha,
        ..color(PixelFormat::Bgra8UnormSrgb)
    };
    descriptor.targets.color_attachments[2] = color(PixelFormat::R32Uint);
    descriptor.targets.depth_attachment_pixel_format = Some(PixelFormat::Depth32FloatStencil8);
    descriptor.targets.stencil_attachment_pixel_format = Some(PixelFormat::Depth32FloatStencil8);
    descriptor.targets.raster_sample_count = 4;
    descriptor.input_primitive_topology = PrimitiveTopologyClass::Triangle;

    let plan = render_pipeline(&capabilities, &descriptor).unwrap();
    let info = &plan.info;
    assert_eq!(
        info.stages,
        [
            (ShaderStages::VERTEX, ShaderCode(1)),
            (ShaderStages::FRAGMENT, ShaderCode(2))
        ]
    );
    assert_eq!(
        info.color_formats[..4],
        [
            Some(Format::B8G8R8A8Srgb),
            None,
            Some(Format::R32Uint),
            None
        ]
    );
    assert_eq!(
        (info.color_formats.len(), info.color_blend.len()),
        (MAX_COLOR_ATTACHMENTS, MAX_COLOR_ATTACHMENTS)
    );
    assert!(info.color_blend[0].blend_enable && info.color_blend[1].write_mask.is_empty());
    assert_eq!(info.depth_format, Some(Format::D32SfloatS8Uint));
    assert_eq!(info.stencil_format, Some(Format::D32SfloatS8Uint));
    assert_eq!(info.samples, SampleCounts::C4);
    assert!(
        info.dynamic_states
            .contains(&DynamicState::VertexInputBindingStride)
    );
    assert!(info.dynamic_states.contains(&DynamicState::SampleLocations));
    assert!(
        info.dynamic_states
            .contains(&DynamicState::DepthClampEnable)
    );
    let unique = info
        .dynamic_states
        .iter()
        .enumerate()
        .all(|(n, state)| !info.dynamic_states[n + 1..].contains(state));
    assert!(unique, "Vulkan forbids duplicate dynamic states");
    assert_eq!(plan.topology_class, PrimitiveTopologyClass::Triangle);
    assert_eq!(plan.sample_count, 4);
}

#[test]
fn render_pipelines_validate_their_interfaces() {
    let capabilities = capabilities();
    let vertex = shader(Stage::Vertex, 1, |_| {});
    let fragment = shader(Stage::Fragment, 2, |interface| {
        interface.color_outputs = alloc::vec![output(0, NumericClass::Sint)];
    });
    let mut mismatch = descriptor(&vertex, Some(&fragment));
    mismatch.targets.color_attachments[0] = color(PixelFormat::Rgba8Unorm);
    assert_eq!(
        render_pipeline(&capabilities, &mismatch).unwrap_err(),
        Error::Invalid("fragment output type does not match its attachment")
    );

    let mut blend_integer = descriptor(&vertex, None);
    blend_integer.targets.color_attachments[0] = ColorAttachmentDescriptor {
        blending_enabled: true,
        ..color(PixelFormat::Rgba8Uint)
    };
    assert_eq!(
        render_pipeline(&capabilities, &blend_integer).unwrap_err(),
        Error::Invalid("integer attachments cannot blend")
    );

    let mut depth_as_color = descriptor(&vertex, None);
    depth_as_color.targets.color_attachments[0] = color(PixelFormat::Depth32Float);
    assert!(matches!(
        render_pipeline(&capabilities, &depth_as_color),
        Err(Error::Invalid(_))
    ));

    let mut mixed = descriptor(&vertex, None);
    mixed.targets.depth_attachment_pixel_format = Some(PixelFormat::Depth32FloatStencil8);
    mixed.targets.stencil_attachment_pixel_format = Some(PixelFormat::Stencil8);
    assert_eq!(
        render_pipeline(&capabilities, &mixed).unwrap_err(),
        Error::Invalid("depth and stencil attachments share one combined format")
    );

    let stage_in = shader(Stage::Vertex, 1, |interface| {
        interface.attributes = alloc::vec![AttributeUse {
            index: 3,
            numeric: NumericClass::Uint,
            components: 1
        }];
    });
    assert!(render_pipeline(&capabilities, &descriptor(&stage_in, None)).is_err());

    let mut samples = descriptor(&vertex, None);
    samples.targets.raster_sample_count = 3;
    assert_eq!(
        render_pipeline(&capabilities, &samples).unwrap_err(),
        Error::Invalid("raster sample count")
    );
    samples.targets.raster_sample_count = 16;
    assert_eq!(
        render_pipeline(&capabilities, &samples).unwrap_err(),
        Error::Unsupported("raster sample count")
    );

    let patch = shader(Stage::Vertex, 1, |interface| {
        interface.patch = Some(QUAD);
    });
    assert!(matches!(
        render_pipeline(&capabilities, &descriptor(&patch, None)),
        Err(Error::Invalid(_))
    ));

    let wrong_stage = shader(Stage::Fragment, 1, |_| {});
    assert!(render_pipeline(&capabilities, &descriptor(&wrong_stage, None)).is_err());
}

const QUAD: Patch = Patch {
    domain: PatchDomain::Quad,
    control_points: None,
};

#[test]
fn tessellation_properties_follow_metal_rules() {
    fn check(
        function: &Interface,
        properties: TessellationDescriptor,
        layout: Option<&VertexDescriptor>,
    ) -> Result<Option<Tessellation>> {
        tessellation(&capabilities(), function, &properties, layout)
    }
    let vertex = interface(Stage::Vertex);
    assert_eq!(
        check(&vertex, TessellationDescriptor::default(), None),
        Ok(None)
    );

    let mut patch = interface(Stage::Vertex);
    patch.patch = Some(QUAD);
    let scaled = TessellationDescriptor {
        factor_scale_enabled: true,
        ..TessellationDescriptor::default()
    };
    let lowered = check(&patch, scaled, None).unwrap().unwrap();
    assert_eq!(
        (lowered.patch, lowered.max_factor, lowered.factor_scale),
        (QUAD, 16, true)
    );
    let integer = |max_tessellation_factor| TessellationDescriptor {
        partition_mode: TessellationPartitionMode::Integer,
        max_tessellation_factor,
        ..TessellationDescriptor::default()
    };
    assert!(check(&patch, integer(6), None).is_ok());
    let pow2 = TessellationDescriptor {
        max_tessellation_factor: 6,
        ..TessellationDescriptor::default()
    };
    assert!(matches!(check(&patch, pow2, None), Err(Error::Invalid(_))));
    assert!(matches!(
        check(&patch, integer(0), None),
        Err(Error::Invalid(_))
    ));

    patch.attributes = alloc::vec![AttributeUse {
        index: 0,
        numeric: NumericClass::Float,
        components: 4
    }];
    assert!(matches!(
        check(&patch, integer(6), None),
        Err(Error::Invalid(_))
    ));
    let mut layout = VertexDescriptor {
        attributes: alloc::vec![Attribute {
            index: 0,
            format: VertexFormat::Float4,
            offset: 0,
            buffer_index: 0,
        }],
        layouts: alloc::vec![Layout {
            buffer_index: 0,
            stride: 16,
            step_function: StepFunction::PerPatchControlPoint,
            step_rate: 1,
        }],
    };
    let fetched = check(&patch, integer(6), Some(&layout)).unwrap().unwrap();
    assert_eq!(fetched.vertex_descriptor.as_ref(), Some(&layout));
    layout.layouts[0].step_function = StepFunction::PerVertex;
    assert!(matches!(
        check(&patch, integer(6), Some(&layout)),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn dual_source_blending_uses_attachment_zero() {
    let capabilities = capabilities();
    let vertex = shader(Stage::Vertex, 1, |_| {});
    let fragment = shader(Stage::Fragment, 2, |interface| {
        interface.color_outputs = alloc::vec![
            output(0, NumericClass::Float),
            ColorOutput {
                index: 0,
                numeric: NumericClass::Float,
                dual_source: true
            },
        ];
    });
    let mut dual = descriptor(&vertex, Some(&fragment));
    dual.targets.color_attachments[0] = ColorAttachmentDescriptor {
        blending_enabled: true,
        destination_rgb_blend_factor: MtlBlendFactor::OneMinusSource1Color,
        ..color(PixelFormat::Rgba16Float)
    };
    let plan = render_pipeline(&capabilities, &dual).unwrap();
    assert_eq!(
        plan.info.color_blend[0].dst_color,
        BlendFactor::OneMinusSrc1Color
    );

    dual.targets.color_attachments[1] = color(PixelFormat::Rgba16Float);
    assert_eq!(
        render_pipeline(&capabilities, &dual).unwrap_err(),
        Error::Invalid("dual-source blending writes only color attachment 0")
    );
}

#[test]
fn rasterization_disabled_drops_the_fragment_stage() {
    let vertex = shader(Stage::Vertex, 1, |_| {});
    let fragment = shader(Stage::Fragment, 2, |_| {});
    let mut descriptor = descriptor(&vertex, Some(&fragment));
    descriptor.targets.rasterization_enabled = false;
    descriptor.max_vertex_amplification_count = 2;
    let plan = render_pipeline(&capabilities(), &descriptor).unwrap();
    assert_eq!(plan.info.stages, [(ShaderStages::VERTEX, ShaderCode(1))]);
    assert!(!plan.rasterization_enabled);
    assert_eq!(plan.amplification_count, 2);
    descriptor.max_vertex_amplification_count = 3;
    assert!(render_pipeline(&capabilities(), &descriptor).is_err());
}

#[test]
fn mesh_pipelines_keep_the_fragment_for_their_variants() {
    let object = interface(Stage::Object);
    let mesh = interface(Stage::Mesh);
    let fragment = shader(Stage::Fragment, 3, |_| {});
    let mut descriptor = MeshRenderPipelineDescriptor {
        object_function: Some(&object),
        mesh_function: &mesh,
        fragment_function: Some(&fragment),
        targets: RenderTargets::default(),
        max_vertex_amplification_count: 1,
    };
    let plan = mesh_render_pipeline(&capabilities(), &descriptor).unwrap();
    assert!(plan.mesh);
    assert_eq!(plan.info.stages, [(ShaderStages::FRAGMENT, ShaderCode(3))]);
    descriptor.object_function = Some(&mesh);
    assert!(mesh_render_pipeline(&capabilities(), &descriptor).is_err());
}

#[test]
fn compute_variants_validate_dispatch_shape_and_memory() {
    let capabilities = capabilities();
    let kernel = shader(Stage::Kernel, 1, |interface| {
        interface.threadgroup = alloc::vec![ThreadgroupUse {
            index: 1,
            declared_bytes: 32
        }];
        interface.static_threadgroup_bytes = 1024;
        interface.max_total_threads = Some(512);
    });
    let descriptor = ComputePipelineDescriptor {
        compute_function: &kernel.interface,
        threadgroup_size_is_multiple_of_thread_execution_width: true,
        max_total_threads_per_threadgroup: 0,
    };
    let plan = compute_pipeline(&capabilities, &descriptor).unwrap();
    assert_eq!(plan.max_total_threads_per_threadgroup, 512);
    assert_eq!(plan.thread_execution_width, 32);

    let size = |width, height, depth| Size {
        width,
        height,
        depth,
    };
    let variant = compute_variant(
        &plan,
        &kernel.interface,
        size(64, 2, 1),
        &[(0, 4096), (1, 64)],
    )
    .unwrap();
    assert_eq!(variant.workgroup_size, Some([64, 2, 1]));
    assert_eq!(
        variant.threadgroup_lengths,
        [(1, 64)],
        "unused slots are dropped"
    );

    let check = |threads: Size, lengths: &[(u32, u64)]| {
        compute_variant(&plan, &kernel.interface, threads, lengths)
    };
    assert!(
        check(size(16, 1, 1), &[(1, 64)]).is_err(),
        "not a multiple of the SIMD width"
    );
    assert!(
        check(size(1024, 1, 1), &[(1, 64)]).is_err(),
        "exceeds the kernel's declared maximum"
    );
    assert!(check(size(32, 1, 0), &[(1, 64)]).is_err());
    assert!(
        check(size(32, 1, 1), &[]).is_err(),
        "used slot without a length"
    );
    assert!(
        check(size(32, 1, 1), &[(1, 24)]).is_err(),
        "not a multiple of 16"
    );
    assert!(
        check(size(32, 1, 1), &[(1, 16)]).is_err(),
        "smaller than the declared argument"
    );
    assert!(
        check(size(32, 1, 1), &[(1, 48 << 10)]).is_err(),
        "exceeds shared memory with the static part"
    );

    let vertex = shader(Stage::Vertex, 1, |_| {});
    let wrong = ComputePipelineDescriptor {
        compute_function: &vertex.interface,
        ..descriptor
    };
    assert!(compute_pipeline(&capabilities, &wrong).is_err());
}

#[test]
fn depth_stencil_states_set_dynamic_tests() {
    let default = DepthStencilState::default();
    assert!(
        !default.depth_test_enable && !default.depth_write_enable && !default.stencil_test_enable
    );

    let state = depth_stencil(&DepthStencilDescriptor {
        depth_compare_function: CompareFunction::LessEqual,
        depth_write_enabled: true,
        front_face_stencil: StencilDescriptor {
            stencil_compare_function: CompareFunction::Equal,
            depth_stencil_pass_operation: StencilOperation::IncrementWrap,
            read_mask: 0xf,
            ..StencilDescriptor::default()
        },
        back_face_stencil: StencilDescriptor::default(),
    });
    assert!(state.depth_test_enable && state.depth_write_enable && state.stencil_test_enable);
    assert_eq!(state.depth_compare_op, CompareOp::LessOrEqual);
    assert_eq!(state.front.pass_op, StencilOp::IncrementAndWrap);
    assert_eq!(state.front.compare_mask, 0xf);
    assert_eq!(state.back.compare_op, CompareOp::Always);
    assert_eq!(
        stencil_op(StencilOperation::DecrementClamp),
        StencilOp::DecrementAndClamp
    );
}
