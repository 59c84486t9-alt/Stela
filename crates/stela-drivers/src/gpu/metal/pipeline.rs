//! Render, compute and depth-stencil states lowered to Vulkan.
//!
//! A render pipeline state becomes one graphics pipeline for dynamic
//! rendering. Everything Metal sets on a render encoder (viewports, cull
//! mode, winding, depth bias, depth-stencil state, fill mode, depth clip
//! mode, the primitive type within the pipeline's class) is dynamic Vulkan
//! state, so binding them never creates pipelines. A depth-stencil state is
//! therefore not a Vulkan object but the dynamic values it sets.
//!
//! A pipeline whose vertex function is a post-tessellation vertex function
//! is tessellated: [`tessellation`] validates its properties into the
//! [`Tessellation`] the compiler synthesizes the feeding stages from, and
//! the pipeline draws single-point patches (see [`Tessellation`]).
//!
//! A compute pipeline state is compiled per threadgroup size and threadgroup
//! memory lengths, which the compiler specializes on; [`compute_variant`]
//! validates a dispatch's values and names the specialization.
use super::{
    abi::{
        BlendFactor as MtlBlendFactor, BlendOperation, ColorWriteMask, CompareFunction,
        PrimitiveTopologyClass, StencilOperation, TessellationControlPointIndexType,
        TessellationFactorFormat, TessellationFactorStepFunction, TessellationPartitionMode,
        Winding,
    },
    capabilities::{Capabilities, FormatCapabilities, Size},
    error::{Error, Result, ensure, require},
    pixel_format::{Kind, PixelFormat},
    sampler::test_op,
    shader::{CompiledShader, Interface, NumericClass, Specialization, Stage, Tessellation},
    vertex::{VertexDescriptor, patch_input, vertex_input},
    vulkan::{
        BlendFactor, BlendOp, ColorComponents, CompareOp, DynamicState, Format, PrimitiveTopology,
        SampleCounts, ShaderStages, StencilOp,
        object::{ColorBlendAttachment, GraphicsPipelineInfo, ShaderCode, VertexInput},
    },
};
use alloc::vec::Vec;

pub const MAX_COLOR_ATTACHMENTS: usize = 8;

pub const fn blend_factor(factor: MtlBlendFactor) -> BlendFactor {
    use MtlBlendFactor as M;
    match factor {
        M::Zero => BlendFactor::Zero,
        M::One => BlendFactor::One,
        M::SourceColor => BlendFactor::SrcColor,
        M::OneMinusSourceColor => BlendFactor::OneMinusSrcColor,
        M::SourceAlpha => BlendFactor::SrcAlpha,
        M::OneMinusSourceAlpha => BlendFactor::OneMinusSrcAlpha,
        M::DestinationColor => BlendFactor::DstColor,
        M::OneMinusDestinationColor => BlendFactor::OneMinusDstColor,
        M::DestinationAlpha => BlendFactor::DstAlpha,
        M::OneMinusDestinationAlpha => BlendFactor::OneMinusDstAlpha,
        M::SourceAlphaSaturated => BlendFactor::SrcAlphaSaturate,
        M::BlendColor => BlendFactor::ConstantColor,
        M::OneMinusBlendColor => BlendFactor::OneMinusConstantColor,
        M::BlendAlpha => BlendFactor::ConstantAlpha,
        M::OneMinusBlendAlpha => BlendFactor::OneMinusConstantAlpha,
        M::Source1Color => BlendFactor::Src1Color,
        M::OneMinusSource1Color => BlendFactor::OneMinusSrc1Color,
        M::Source1Alpha => BlendFactor::Src1Alpha,
        M::OneMinusSource1Alpha => BlendFactor::OneMinusSrc1Alpha,
    }
}

pub const fn blend_op(operation: BlendOperation) -> BlendOp {
    match operation {
        BlendOperation::Add => BlendOp::Add,
        BlendOperation::Subtract => BlendOp::Subtract,
        BlendOperation::ReverseSubtract => BlendOp::ReverseSubtract,
        BlendOperation::Min => BlendOp::Min,
        BlendOperation::Max => BlendOp::Max,
    }
}

/// Metal numbers the channels from alpha upward; Vulkan from red.
pub const fn write_mask(mask: ColorWriteMask) -> ColorComponents {
    ColorComponents::EMPTY
        .with(ColorComponents::R, mask.contains(ColorWriteMask::RED))
        .with(ColorComponents::G, mask.contains(ColorWriteMask::GREEN))
        .with(ColorComponents::B, mask.contains(ColorWriteMask::BLUE))
        .with(ColorComponents::A, mask.contains(ColorWriteMask::ALPHA))
}

pub const fn stencil_op(operation: StencilOperation) -> StencilOp {
    match operation {
        StencilOperation::Keep => StencilOp::Keep,
        StencilOperation::Zero => StencilOp::Zero,
        StencilOperation::Replace => StencilOp::Replace,
        StencilOperation::IncrementClamp => StencilOp::IncrementAndClamp,
        StencilOperation::DecrementClamp => StencilOp::DecrementAndClamp,
        StencilOperation::Invert => StencilOp::Invert,
        StencilOperation::IncrementWrap => StencilOp::IncrementAndWrap,
        StencilOperation::DecrementWrap => StencilOp::DecrementAndWrap,
    }
}

/// The pipeline topology for a Metal input class; draws set the exact
/// topology dynamically (`dynamicPrimitiveTopologyUnrestricted`).
pub const fn class_topology(class: PrimitiveTopologyClass) -> PrimitiveTopology {
    match class {
        PrimitiveTopologyClass::Point => PrimitiveTopology::PointList,
        PrimitiveTopologyClass::Line => PrimitiveTopology::LineList,
        PrimitiveTopologyClass::Triangle | PrimitiveTopologyClass::Unspecified => {
            PrimitiveTopology::TriangleList
        }
    }
}

/// `MTLRenderPipelineColorAttachmentDescriptor`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColorAttachmentDescriptor {
    pub pixel_format: Option<PixelFormat>,
    pub blending_enabled: bool,
    pub source_rgb_blend_factor: MtlBlendFactor,
    pub destination_rgb_blend_factor: MtlBlendFactor,
    pub rgb_blend_operation: BlendOperation,
    pub source_alpha_blend_factor: MtlBlendFactor,
    pub destination_alpha_blend_factor: MtlBlendFactor,
    pub alpha_blend_operation: BlendOperation,
    pub write_mask: ColorWriteMask,
}

impl Default for ColorAttachmentDescriptor {
    fn default() -> Self {
        Self {
            pixel_format: None,
            blending_enabled: false,
            source_rgb_blend_factor: MtlBlendFactor::One,
            destination_rgb_blend_factor: MtlBlendFactor::Zero,
            rgb_blend_operation: BlendOperation::Add,
            source_alpha_blend_factor: MtlBlendFactor::One,
            destination_alpha_blend_factor: MtlBlendFactor::Zero,
            alpha_blend_operation: BlendOperation::Add,
            write_mask: ColorWriteMask::KNOWN,
        }
    }
}

impl ColorAttachmentDescriptor {
    fn factors(&self) -> [MtlBlendFactor; 4] {
        [
            self.source_rgb_blend_factor,
            self.destination_rgb_blend_factor,
            self.source_alpha_blend_factor,
            self.destination_alpha_blend_factor,
        ]
    }

    fn uses_source1(&self) -> bool {
        self.blending_enabled && self.factors().iter().any(|factor| factor.uses_source1())
    }

    fn vulkan(&self) -> ColorBlendAttachment {
        ColorBlendAttachment {
            blend_enable: self.blending_enabled,
            src_color: blend_factor(self.source_rgb_blend_factor),
            dst_color: blend_factor(self.destination_rgb_blend_factor),
            color_op: blend_op(self.rgb_blend_operation),
            src_alpha: blend_factor(self.source_alpha_blend_factor),
            dst_alpha: blend_factor(self.destination_alpha_blend_factor),
            alpha_op: blend_op(self.alpha_blend_operation),
            write_mask: if self.pixel_format.is_some() {
                write_mask(self.write_mask)
            } else {
                ColorComponents::EMPTY
            },
        }
    }
}

/// The attachment and rasterization half of render pipeline descriptors,
/// shared by vertex and mesh pipelines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenderTargets {
    pub color_attachments: [ColorAttachmentDescriptor; MAX_COLOR_ATTACHMENTS],
    pub depth_attachment_pixel_format: Option<PixelFormat>,
    pub stencil_attachment_pixel_format: Option<PixelFormat>,
    pub raster_sample_count: u64,
    pub alpha_to_coverage_enabled: bool,
    pub alpha_to_one_enabled: bool,
    pub rasterization_enabled: bool,
}

impl Default for RenderTargets {
    fn default() -> Self {
        Self {
            color_attachments: [ColorAttachmentDescriptor::default(); MAX_COLOR_ATTACHMENTS],
            depth_attachment_pixel_format: None,
            stencil_attachment_pixel_format: None,
            raster_sample_count: 1,
            alpha_to_coverage_enabled: false,
            alpha_to_one_enabled: false,
            rasterization_enabled: true,
        }
    }
}

/// The `tessellation*` properties of `MTLRenderPipelineDescriptor`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TessellationDescriptor {
    pub partition_mode: TessellationPartitionMode,
    pub max_tessellation_factor: u64,
    pub factor_scale_enabled: bool,
    pub factor_format: TessellationFactorFormat,
    pub control_point_index_type: TessellationControlPointIndexType,
    pub factor_step_function: TessellationFactorStepFunction,
    pub output_winding_order: Winding,
}

impl Default for TessellationDescriptor {
    /// Metal's defaults.
    fn default() -> Self {
        Self {
            partition_mode: TessellationPartitionMode::Pow2,
            max_tessellation_factor: 16,
            factor_scale_enabled: false,
            factor_format: TessellationFactorFormat::Half,
            control_point_index_type: TessellationControlPointIndexType::None,
            factor_step_function: TessellationFactorStepFunction::Constant,
            output_winding_order: Winding::Clockwise,
        }
    }
}

/// Validates the tessellation of a pipeline whose vertex function is
/// `function`: `None` unless it is a post-tessellation vertex function, in
/// which case `vertex_descriptor` is its patch stage-in.
pub fn tessellation(
    capabilities: &Capabilities,
    function: &Interface,
    descriptor: &TessellationDescriptor,
    vertex_descriptor: Option<&VertexDescriptor>,
) -> Result<Option<Tessellation>> {
    let Some(patch) = function.patch else {
        return Ok(None);
    };
    require(capabilities.supports_tessellation, "tessellation")?;
    let max_factor = descriptor.max_tessellation_factor;
    ensure(
        max_factor >= 2 && max_factor.is_multiple_of(2),
        "the maximum tessellation factor is even",
    )?;
    ensure(
        descriptor.partition_mode != TessellationPartitionMode::Pow2
            || max_factor.is_power_of_two(),
        "power-of-two partitioning needs a power-of-two maximum factor",
    )?;
    require(
        max_factor <= capabilities.limits.max_tessellation_factor,
        "tessellation factor",
    )?;
    match vertex_descriptor {
        Some(layout) => {
            patch_input(capabilities, layout)?;
            stage_in(function, layout)?;
        }
        None => ensure(
            function.attributes.is_empty(),
            "stage-in attributes need a vertex descriptor",
        )?,
    }
    Ok(Some(Tessellation {
        patch,
        partition: descriptor.partition_mode,
        max_factor: max_factor as u32,
        factor_scale: descriptor.factor_scale_enabled,
        step_function: descriptor.factor_step_function,
        control_point_index: descriptor.control_point_index_type,
        winding: descriptor.output_winding_order,
        vertex_descriptor: vertex_descriptor.cloned(),
    }))
}

/// A post-tessellation vertex function's [`Tessellation`] and the stages
/// the compiler synthesized ahead of it.
#[derive(Clone, Copy, Debug)]
pub struct TessellatedVertex<'a> {
    pub tessellation: &'a Tessellation,
    pub vertex: ShaderCode,
    pub control: ShaderCode,
}

/// `MTLRenderPipelineDescriptor`.
#[derive(Clone, Copy, Debug)]
pub struct RenderPipelineDescriptor<'a> {
    /// The vertex function, or the evaluation stage of a tessellated
    /// pipeline.
    pub vertex_function: &'a CompiledShader,
    pub fragment_function: Option<&'a CompiledShader>,
    pub vertex_descriptor: Option<&'a VertexDescriptor>,
    pub targets: RenderTargets,
    pub input_primitive_topology: PrimitiveTopologyClass,
    pub max_vertex_amplification_count: u64,
    /// Present exactly when the vertex function is a post-tessellation
    /// vertex function, from [`tessellation`].
    pub tessellation: Option<TessellatedVertex<'a>>,
}

/// `MTLMeshRenderPipelineDescriptor`. Object and mesh functions compile
/// per threadgroup size at draw time, so only their interfaces are known.
#[derive(Clone, Copy, Debug)]
pub struct MeshRenderPipelineDescriptor<'a> {
    pub object_function: Option<&'a Interface>,
    pub mesh_function: &'a Interface,
    pub fragment_function: Option<&'a CompiledShader>,
    pub targets: RenderTargets,
    pub max_vertex_amplification_count: u64,
}

/// A render pipeline state: its Vulkan pipeline and what encoders check
/// against it.
#[derive(Clone, Debug, PartialEq)]
pub struct RenderPipelinePlan {
    pub info: GraphicsPipelineInfo,
    pub topology_class: PrimitiveTopologyClass,
    pub amplification_count: u32,
    pub rasterization_enabled: bool,
    pub sample_count: u32,
    pub color_formats: [Option<PixelFormat>; MAX_COLOR_ATTACHMENTS],
    pub depth_format: Option<PixelFormat>,
    pub stencil_format: Option<PixelFormat>,
    /// Draws are mesh dispatches (`drawMeshThreadgroups`).
    pub mesh: bool,
    /// Draws are patch draws (`drawPatches`).
    pub tessellation: Option<Tessellation>,
}

pub fn render_pipeline(
    capabilities: &Capabilities,
    descriptor: &RenderPipelineDescriptor,
) -> Result<RenderPipelinePlan> {
    let vertex = &descriptor.vertex_function.interface;
    ensure(
        vertex.stage == Stage::Vertex,
        "the vertex function is not a vertex function",
    )?;
    vertex.validate()?;
    ensure(
        vertex.patch.is_some() == descriptor.tessellation.is_some(),
        "post-tessellation vertex functions draw through tessellation stages",
    )?;
    let code = descriptor.vertex_function.code;
    let mut stages = match descriptor.tessellation {
        Some(tessellated) => alloc::vec![
            (ShaderStages::VERTEX, tessellated.vertex),
            (ShaderStages::TESSELLATION_CONTROL, tessellated.control),
            (ShaderStages::TESSELLATION_EVALUATION, code),
        ],
        None => alloc::vec![(ShaderStages::VERTEX, code)],
    };
    let vertex_input = match (descriptor.tessellation, descriptor.vertex_descriptor) {
        // The evaluation stage fetches its stage-in itself.
        (Some(_), _) => VertexInput::default(),
        (None, Some(layout)) => {
            let input = vertex_input(capabilities, layout)?;
            stage_in(vertex, layout)?;
            input
        }
        (None, None) => {
            ensure(
                vertex.attributes.is_empty(),
                "stage-in attributes need a vertex descriptor",
            )?;
            VertexInput::default()
        }
    };
    let amplification_count =
        amplification(capabilities, descriptor.max_vertex_amplification_count)?;
    let mut plan = targets(
        capabilities,
        &descriptor.targets,
        descriptor.fragment_function,
        &mut stages,
    )?;
    plan.info.stages = stages;
    plan.info.vertex_input = vertex_input;
    match descriptor.tessellation {
        Some(tessellated) => {
            plan.info.topology = PrimitiveTopology::PatchList;
            plan.info.patch_control_points = 1;
            plan.tessellation = Some(tessellated.tessellation.clone());
        }
        None => {
            plan.info.topology = class_topology(descriptor.input_primitive_topology);
            // Strides are always bound with the buffers, which covers
            // Metal's dynamic strides without a second pipeline.
            plan.info
                .dynamic_states
                .push(DynamicState::VertexInputBindingStride);
        }
    }
    plan.topology_class = descriptor.input_primitive_topology;
    plan.amplification_count = amplification_count;
    Ok(plan)
}

/// Checks that the layout declares each stage-in attribute of `function`
/// with a format of the attribute's type.
fn stage_in(function: &Interface, layout: &VertexDescriptor) -> Result<()> {
    for attribute in &function.attributes {
        let declared = layout
            .attributes
            .iter()
            .find(|declared| declared.index == attribute.index)
            .ok_or(Error::Invalid(
                "stage-in attribute missing from the vertex descriptor",
            ))?;
        ensure(
            declared.format.numeric_class() == attribute.numeric,
            "vertex attribute format does not match the shader type",
        )?;
    }
    Ok(())
}

pub fn mesh_render_pipeline(
    capabilities: &Capabilities,
    descriptor: &MeshRenderPipelineDescriptor,
) -> Result<RenderPipelinePlan> {
    require(capabilities.supports_mesh_shaders, "mesh shaders")?;
    let mesh = descriptor.mesh_function;
    ensure(
        mesh.stage == Stage::Mesh,
        "the mesh function is not a mesh function",
    )?;
    mesh.validate()?;
    if let Some(object) = descriptor.object_function {
        ensure(
            object.stage == Stage::Object,
            "the object function is not an object function",
        )?;
        object.validate()?;
    }
    // Variants put their object and mesh stages ahead of the fragment.
    let mut stages = Vec::new();
    let amplification_count =
        amplification(capabilities, descriptor.max_vertex_amplification_count)?;
    let mut plan = targets(
        capabilities,
        &descriptor.targets,
        descriptor.fragment_function,
        &mut stages,
    )?;
    plan.info.stages = stages;
    plan.amplification_count = amplification_count;
    plan.mesh = true;
    Ok(plan)
}

fn amplification(capabilities: &Capabilities, count: u64) -> Result<u32> {
    ensure(count >= 1, "vertex amplification count is at least one")?;
    require(
        capabilities.supports_vertex_amplification_count(count),
        "vertex amplification count",
    )?;
    Ok(count as u32)
}

fn targets(
    capabilities: &Capabilities,
    targets: &RenderTargets,
    fragment: Option<&CompiledShader>,
    stages: &mut Vec<(ShaderStages, ShaderCode)>,
) -> Result<RenderPipelinePlan> {
    let fragment = fragment.filter(|_| targets.rasterization_enabled);
    if let Some(fragment) = fragment {
        ensure(
            fragment.interface.stage == Stage::Fragment,
            "the fragment function is not a fragment function",
        )?;
        fragment.interface.validate()?;
        stages.push((Stage::Fragment.vulkan(), fragment.code));
    }
    let outputs = fragment.map(|fragment| &fragment.interface);

    let samples = u32::try_from(targets.raster_sample_count)
        .map_err(|_| Error::Invalid("raster sample count"))?;
    let sample_flag = SampleCounts::single(samples).ok_or(Error::Invalid("raster sample count"))?;
    require(
        capabilities.supports_texture_sample_count(u64::from(samples)),
        "raster sample count",
    )?;
    let multisampled = samples > 1;

    let dual_source = targets
        .color_attachments
        .iter()
        .any(ColorAttachmentDescriptor::uses_source1);
    if dual_source {
        require(capabilities.dual_source_blending, "dual-source blending")?;
        ensure(
            !targets.color_attachments[1..]
                .iter()
                .any(|attachment| attachment.pixel_format.is_some()),
            "dual-source blending writes only color attachment 0",
        )?;
        ensure(
            outputs.is_some_and(Interface::uses_dual_source),
            "dual-source blending needs an index(1) output",
        )?;
    }

    let mut color_formats = Vec::new();
    let mut color_blend = Vec::new();
    for (index, attachment) in targets.color_attachments.iter().enumerate() {
        let format = match attachment.pixel_format {
            Some(format) => Some(color_format(
                capabilities,
                attachment,
                format,
                multisampled,
            )?),
            None => None,
        };
        if let (Some(format), Some(output)) = (
            attachment.pixel_format,
            outputs.and_then(|outputs| outputs.color_output(index as u32)),
        ) {
            let Kind::Color(numeric) = format.describe().kind else {
                unreachable!("color_format checked the kind")
            };
            ensure(
                NumericClass::of(numeric) == output.numeric,
                "fragment output type does not match its attachment",
            )?;
        }
        color_formats.push(format);
        color_blend.push(attachment.vulkan());
    }

    let depth_format = targets.depth_attachment_pixel_format;
    let stencil_format = targets.stencil_attachment_pixel_format;
    let depth = depth_format
        .map(|format| depth_stencil_format(capabilities, format, true, multisampled))
        .transpose()?;
    let stencil = stencil_format
        .map(|format| depth_stencil_format(capabilities, format, false, multisampled))
        .transpose()?;
    if let (Some(depth), Some(stencil)) = (depth_format, stencil_format) {
        let combined = |format: PixelFormat| format.describe().kind == Kind::DepthStencil;
        ensure(
            depth == stencil || !(combined(depth) || combined(stencil)),
            "depth and stencil attachments share one combined format",
        )?;
    }
    if targets.alpha_to_one_enabled {
        require(capabilities.alpha_to_one, "alpha to one")?;
    }

    let mut dynamic_states = BASE_DYNAMIC_STATES.to_vec();
    if capabilities.programmable_sample_positions {
        dynamic_states.extend([
            DynamicState::SampleLocations,
            DynamicState::SampleLocationsEnable,
        ]);
    }
    if capabilities.depth_clamp {
        dynamic_states.extend([
            DynamicState::DepthClampEnable,
            DynamicState::DepthClipEnable,
        ]);
    }
    if capabilities.wireframe {
        dynamic_states.push(DynamicState::PolygonMode);
    }

    Ok(RenderPipelinePlan {
        info: GraphicsPipelineInfo {
            stages: Vec::new(),
            vertex_input: VertexInput::default(),
            topology: PrimitiveTopology::TriangleList,
            patch_control_points: 0,
            samples: sample_flag,
            alpha_to_coverage: targets.alpha_to_coverage_enabled,
            alpha_to_one: targets.alpha_to_one_enabled,
            color_formats,
            depth_format: depth,
            stencil_format: stencil,
            color_blend,
            dynamic_states,
        },
        topology_class: PrimitiveTopologyClass::Unspecified,
        amplification_count: 1,
        rasterization_enabled: targets.rasterization_enabled,
        sample_count: samples,
        color_formats: targets
            .color_attachments
            .map(|attachment| attachment.pixel_format),
        depth_format,
        stencil_format,
        mesh: false,
        tessellation: None,
    })
}

/// Dynamic states of every graphics pipeline.
const BASE_DYNAMIC_STATES: [DynamicState; 18] = [
    DynamicState::ViewportWithCount,
    DynamicState::ScissorWithCount,
    DynamicState::DepthBias,
    DynamicState::DepthBiasEnable,
    DynamicState::BlendConstants,
    DynamicState::StencilCompareMask,
    DynamicState::StencilWriteMask,
    DynamicState::StencilReference,
    DynamicState::StencilTestEnable,
    DynamicState::StencilOp,
    DynamicState::DepthTestEnable,
    DynamicState::DepthWriteEnable,
    DynamicState::DepthCompareOp,
    DynamicState::CullMode,
    DynamicState::FrontFace,
    DynamicState::PrimitiveTopology,
    DynamicState::PrimitiveRestartEnable,
    DynamicState::RasterizerDiscardEnable,
];

fn color_format(
    capabilities: &Capabilities,
    attachment: &ColorAttachmentDescriptor,
    format: PixelFormat,
    multisampled: bool,
) -> Result<Format> {
    let description = format.describe();
    let Kind::Color(numeric) = description.kind else {
        return Err(Error::Invalid("color attachments need color pixel formats"));
    };
    let caps = capabilities.format(format);
    require(
        caps.contains(FormatCapabilities::COLOR),
        "color attachment pixel format",
    )?;
    if attachment.blending_enabled {
        ensure(!numeric.is_integer(), "integer attachments cannot blend")?;
        require(
            caps.contains(FormatCapabilities::BLEND),
            "blending of the attachment's pixel format",
        )?;
    }
    if multisampled {
        require(
            caps.contains(FormatCapabilities::MSAA),
            "multisampled attachment pixel format",
        )?;
    }
    Ok(description
        .realization
        .map_err(|_| Error::Unsupported("color attachment pixel format"))?
        .format)
}

fn depth_stencil_format(
    capabilities: &Capabilities,
    format: PixelFormat,
    depth: bool,
    multisampled: bool,
) -> Result<Format> {
    let description = format.describe();
    let aspect = if depth {
        description.has_depth()
    } else {
        description.has_stencil()
    };
    ensure(
        aspect,
        if depth {
            "depth attachments need a depth format"
        } else {
            "stencil attachments need a stencil format"
        },
    )?;
    let caps = capabilities.format(format);
    require(
        caps.contains(FormatCapabilities::DEPTH_STENCIL),
        "depth-stencil attachment pixel format",
    )?;
    if multisampled {
        require(
            caps.contains(FormatCapabilities::MSAA),
            "multisampled attachment pixel format",
        )?;
    }
    Ok(description
        .realization
        .map_err(|_| Error::Unsupported("depth-stencil attachment pixel format"))?
        .format)
}

/// `MTLComputePipelineDescriptor`.
#[derive(Clone, Copy, Debug)]
pub struct ComputePipelineDescriptor<'a> {
    /// The kernel's interface; its code compiles per dispatch shape.
    pub compute_function: &'a Interface,
    pub threadgroup_size_is_multiple_of_thread_execution_width: bool,
    /// Zero leaves the device's limit.
    pub max_total_threads_per_threadgroup: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ComputePipelinePlan {
    pub max_total_threads_per_threadgroup: u64,
    pub thread_execution_width: u64,
    pub static_threadgroup_memory_length: u64,
    pub full_subgroups: bool,
    /// The device's per-dimension threadgroup limits.
    pub max_threads_per_threadgroup: Size,
    pub max_threadgroup_memory_length: u64,
}

pub fn compute_pipeline(
    capabilities: &Capabilities,
    descriptor: &ComputePipelineDescriptor,
) -> Result<ComputePipelinePlan> {
    let interface = descriptor.compute_function;
    ensure(
        interface.stage == Stage::Kernel,
        "the compute function is not a kernel",
    )?;
    interface.validate()?;
    let limits = &capabilities.limits;
    let mut max_threads = limits.max_total_threads_per_threadgroup;
    if descriptor.max_total_threads_per_threadgroup != 0 {
        max_threads = max_threads.min(descriptor.max_total_threads_per_threadgroup);
    }
    if let Some(declared) = interface.max_total_threads {
        max_threads = max_threads.min(u64::from(declared));
    }
    ensure(
        interface.static_threadgroup_bytes <= limits.max_threadgroup_memory_length,
        "the kernel's threadgroup memory exceeds the device limit",
    )?;
    Ok(ComputePipelinePlan {
        max_total_threads_per_threadgroup: max_threads,
        thread_execution_width: limits.thread_execution_width,
        static_threadgroup_memory_length: interface.static_threadgroup_bytes,
        full_subgroups: descriptor.threadgroup_size_is_multiple_of_thread_execution_width,
        max_threads_per_threadgroup: limits.max_threads_per_threadgroup,
        max_threadgroup_memory_length: limits.max_threadgroup_memory_length,
    })
}

/// Validates a dispatch's threadgroup size and threadgroup memory lengths
/// against a compute (or object/mesh) function, returning the
/// specialization its Vulkan pipeline is compiled for. Lengths for slots the
/// function does not use are dropped so they do not split the cache.
pub fn compute_variant(
    plan: &ComputePipelinePlan,
    interface: &Interface,
    threads: Size,
    threadgroup_lengths: &[(u32, u64)],
) -> Result<Specialization> {
    let dimensions = [threads.width, threads.height, threads.depth];
    let limit = plan.max_threads_per_threadgroup;
    let maximum = [limit.width, limit.height, limit.depth];
    ensure(
        dimensions.iter().all(|&size| size >= 1),
        "threadgroups have at least one thread",
    )?;
    ensure(
        dimensions
            .iter()
            .zip(maximum)
            .all(|(&size, max)| size <= max),
        "threadgroup dimension exceeds the limit",
    )?;
    let total = dimensions.iter().product::<u64>();
    ensure(
        total <= plan.max_total_threads_per_threadgroup,
        "threadgroup exceeds maxTotalThreadsPerThreadgroup",
    )?;
    if plan.full_subgroups {
        ensure(
            total.is_multiple_of(plan.thread_execution_width),
            "threadgroup is not a multiple of the thread execution width",
        )?;
    }

    let mut lengths = Vec::new();
    let mut bytes = plan.static_threadgroup_memory_length;
    for used in &interface.threadgroup {
        let length = threadgroup_lengths
            .iter()
            .rev()
            .find(|(index, _)| *index == used.index)
            .map(|&(_, length)| length)
            .ok_or(Error::Invalid(
                "threadgroup memory length not set for a used slot",
            ))?;
        ensure(
            length.is_multiple_of(16),
            "threadgroup memory lengths are multiples of 16",
        )?;
        ensure(
            length >= used.declared_bytes,
            "threadgroup memory length is smaller than the argument",
        )?;
        bytes += length;
        lengths.push((used.index, length));
    }
    ensure(
        bytes <= plan.max_threadgroup_memory_length,
        "threadgroup memory exceeds the device limit",
    )?;
    Ok(Specialization {
        workgroup_size: Some(dimensions.map(|size| size as u32)),
        threadgroup_lengths: lengths,
        ..Specialization::default()
    })
}

/// One face's stencil test (`MTLStencilDescriptor`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StencilDescriptor {
    pub stencil_compare_function: CompareFunction,
    pub stencil_failure_operation: StencilOperation,
    pub depth_failure_operation: StencilOperation,
    pub depth_stencil_pass_operation: StencilOperation,
    pub read_mask: u32,
    pub write_mask: u32,
}

impl Default for StencilDescriptor {
    fn default() -> Self {
        Self {
            stencil_compare_function: CompareFunction::Always,
            stencil_failure_operation: StencilOperation::Keep,
            depth_failure_operation: StencilOperation::Keep,
            depth_stencil_pass_operation: StencilOperation::Keep,
            read_mask: u32::MAX,
            write_mask: u32::MAX,
        }
    }
}

/// `MTLDepthStencilDescriptor`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepthStencilDescriptor {
    pub depth_compare_function: CompareFunction,
    pub depth_write_enabled: bool,
    pub front_face_stencil: StencilDescriptor,
    pub back_face_stencil: StencilDescriptor,
}

impl Default for DepthStencilDescriptor {
    fn default() -> Self {
        Self {
            depth_compare_function: CompareFunction::Always,
            depth_write_enabled: false,
            front_face_stencil: StencilDescriptor::default(),
            back_face_stencil: StencilDescriptor::default(),
        }
    }
}

/// `VkStencilOpState` with its masks; the reference is encoder state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StencilFace {
    pub fail_op: StencilOp,
    pub pass_op: StencilOp,
    pub depth_fail_op: StencilOp,
    pub compare_op: CompareOp,
    pub compare_mask: u32,
    pub write_mask: u32,
}

/// The dynamic depth and stencil state a depth-stencil state object sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepthStencilState {
    pub depth_test_enable: bool,
    pub depth_write_enable: bool,
    pub depth_compare_op: CompareOp,
    pub stencil_test_enable: bool,
    pub front: StencilFace,
    pub back: StencilFace,
}

impl Default for DepthStencilState {
    /// The state of an encoder without a depth-stencil state object.
    fn default() -> Self {
        depth_stencil(&DepthStencilDescriptor::default())
    }
}

pub fn depth_stencil(descriptor: &DepthStencilDescriptor) -> DepthStencilState {
    let face = |stencil: &StencilDescriptor| StencilFace {
        fail_op: stencil_op(stencil.stencil_failure_operation),
        pass_op: stencil_op(stencil.depth_stencil_pass_operation),
        depth_fail_op: stencil_op(stencil.depth_failure_operation),
        compare_op: test_op(stencil.stencil_compare_function),
        compare_mask: stencil.read_mask,
        write_mask: stencil.write_mask,
    };
    let inert = |stencil: &StencilDescriptor| {
        stencil.stencil_compare_function == CompareFunction::Always
            && [
                stencil.stencil_failure_operation,
                stencil.depth_failure_operation,
                stencil.depth_stencil_pass_operation,
            ]
            .iter()
            .all(|operation| *operation == StencilOperation::Keep)
    };
    DepthStencilState {
        depth_test_enable: descriptor.depth_compare_function != CompareFunction::Always
            || descriptor.depth_write_enabled,
        depth_write_enable: descriptor.depth_write_enabled,
        depth_compare_op: test_op(descriptor.depth_compare_function),
        stencil_test_enable: !(inert(&descriptor.front_face_stencil)
            && inert(&descriptor.back_face_stencil)),
        front: face(&descriptor.front_face_stencil),
        back: face(&descriptor.back_face_stencil),
    }
}

#[cfg(test)]
mod tests;
