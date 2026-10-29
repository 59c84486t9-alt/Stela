//! Vulkan create infos for the boundary's object descriptions. Each builder
//! assembles the structure and its `pNext` chain on the stack and hands it
//! to `build`, so the chain outlives the Vulkan call that reads it.
use super::handle;
use crate::gpu::metal::{
    binding::HeapArray,
    error::Result,
    vulkan::{
        Format, ImageAspects, MemoryProperties, PipelineStages, PrimitiveTopology, ShaderStages,
        backend::{Descriptor, Requirements},
        command::{BufferImageCopy, Subresource},
        object::{
            BufferInfo, ColorBlendAttachment, ComputePipelineInfo, GraphicsPipelineInfo, ImageInfo,
            ImageViewInfo, MemoryRequest, SamplerInfo, Semaphore, ShaderCode,
        },
        physical::Memory,
    },
};
use alloc::vec::Vec;
use ash::vk;
use core::ffi::c_void;

/// `DRM_FORMAT_MOD_LINEAR`.
const DRM_FORMAT_MOD_LINEAR: u64 = 0;

/// The entry point every compiled stage exports.
pub(super) const ENTRY_POINT: &core::ffi::CStr = c"main";

/// Mesa's `VkPipelineShaderStageNirCreateInfoMESA`
/// (`src/vulkan/util/vk_internal_exts.h`). A stage without a module takes
/// its NIR from this structure in place of SPIR-V; Mesa's runtime clones
/// the NIR, so the compiler keeps ownership.
#[repr(C)]
pub(super) struct NirStage {
    s_type: vk::StructureType,
    p_next: *const c_void,
    nir: *const c_void,
}

impl NirStage {
    /// `VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_NIR_CREATE_INFO_MESA`.
    pub(super) const STRUCTURE_TYPE: vk::StructureType = vk::StructureType::from_raw(1_000_290_001);

    pub(super) fn new(code: ShaderCode) -> Self {
        Self {
            s_type: Self::STRUCTURE_TYPE,
            p_next: core::ptr::null(),
            nir: code.0 as usize as *const c_void,
        }
    }

    #[cfg(test)]
    pub(super) fn nir(&self) -> u64 {
        self.nir as usize as u64
    }
}

pub(super) fn format(format: Format) -> vk::Format {
    vk::Format::from_raw(format.raw() as i32)
}

pub(super) fn aspects(aspects: ImageAspects) -> vk::ImageAspectFlags {
    vk::ImageAspectFlags::from_raw(aspects.bits())
}

pub(super) fn stages(stages: PipelineStages) -> vk::PipelineStageFlags2 {
    vk::PipelineStageFlags2::from_raw(stages.bits())
}

/// Every level and layer of an image with `aspects`.
pub(super) fn whole(aspects: vk::ImageAspectFlags) -> vk::ImageSubresourceRange {
    vk::ImageSubresourceRange {
        aspect_mask: aspects,
        base_mip_level: 0,
        level_count: vk::REMAINING_MIP_LEVELS,
        base_array_layer: 0,
        layer_count: vk::REMAINING_ARRAY_LAYERS,
    }
}

pub(super) fn subresource(subresource: Subresource) -> vk::ImageSubresourceLayers {
    vk::ImageSubresourceLayers {
        aspect_mask: aspects(subresource.aspects),
        mip_level: subresource.mip_level,
        base_array_layer: subresource.base_array_layer,
        layer_count: subresource.layer_count,
    }
}

pub(super) fn offset([x, y, z]: [i32; 3]) -> vk::Offset3D {
    vk::Offset3D { x, y, z }
}

pub(super) fn extent([width, height, depth]: [u32; 3]) -> vk::Extent3D {
    vk::Extent3D {
        width,
        height,
        depth,
    }
}

pub(super) fn requirements(requirements: &vk::MemoryRequirements) -> Requirements {
    Requirements {
        size: requirements.size,
        alignment: requirements.alignment,
        memory_types: requirements.memory_type_bits,
    }
}

/// The memory types among `types` that satisfy `request`, those with its
/// preferred properties first.
pub(super) fn memory_candidates(memory: &Memory, types: u32, request: MemoryRequest) -> Vec<u32> {
    let mut required = request.required;
    if request.mapped {
        required = required.union(MemoryProperties::HOST_VISIBLE);
    }
    let properties = |index: u32| memory.types[index as usize].properties;
    let (preferred, others): (Vec<u32>, Vec<u32>) = (0..memory.types.len() as u32)
        .filter(|&index| types & (1 << index) != 0 && properties(index).contains(required))
        .partition(|&index| properties(index).contains(request.preferred));
    preferred.into_iter().chain(others).collect()
}

/// The heap's bindings, one array per [`HeapArray`] in binding order.
pub(super) fn heap_bindings(counts: &[u32; 5]) -> [vk::DescriptorSetLayoutBinding<'static>; 5] {
    core::array::from_fn(|index| {
        let array = HeapArray::ALL[index];
        vk::DescriptorSetLayoutBinding::default()
            .binding(array.raw())
            .descriptor_type(descriptor_type(array))
            .descriptor_count(counts[array.raw() as usize])
            .stage_flags(vk::ShaderStageFlags::ALL)
    })
}

fn descriptor_type(array: HeapArray) -> vk::DescriptorType {
    match array {
        HeapArray::SampledImages => vk::DescriptorType::SAMPLED_IMAGE,
        HeapArray::StorageImages => vk::DescriptorType::STORAGE_IMAGE,
        HeapArray::Samplers => vk::DescriptorType::SAMPLER,
        HeapArray::UniformTexelBuffers => vk::DescriptorType::UNIFORM_TEXEL_BUFFER,
        HeapArray::StorageTexelBuffers => vk::DescriptorType::STORAGE_TEXEL_BUFFER,
    }
}

/// The write of `descriptor` into slot `index` of its heap array.
pub(super) fn descriptor_write(
    set: vk::DescriptorSet,
    index: u32,
    descriptor: Descriptor,
    write: impl FnOnce(&vk::WriteDescriptorSet<'_>),
) {
    let array = descriptor.array();
    let base = vk::WriteDescriptorSet::default()
        .dst_set(set)
        .dst_binding(array.raw())
        .dst_array_element(index)
        .descriptor_type(descriptor_type(array));
    let image = |view: u64, sampler: u64| {
        [vk::DescriptorImageInfo {
            sampler: handle(sampler),
            image_view: handle(view),
            image_layout: vk::ImageLayout::GENERAL,
        }]
    };
    match descriptor {
        Descriptor::SampledImage(view) | Descriptor::StorageImage(view) => {
            write(&base.image_info(&image(view.0, 0)));
        }
        Descriptor::Sampler(sampler) => write(&base.image_info(&image(0, sampler.0))),
        Descriptor::UniformTexelBuffer(view) | Descriptor::StorageTexelBuffer(view) => {
            write(&base.texel_buffer_view(&[handle(view.0)]));
        }
    }
}

pub(super) fn buffer<T>(
    info: &BufferInfo,
    build: impl FnOnce(&vk::BufferCreateInfo<'_>) -> Result<T>,
) -> Result<T> {
    let mut usage = vk::BufferUsageFlags2CreateInfoKHR::default()
        .usage(vk::BufferUsageFlags2KHR::from_raw(info.usage.bits()));
    let create = vk::BufferCreateInfo::default()
        .size(info.size)
        .flags(vk::BufferCreateFlags::from_raw(info.flags.bits()))
        .sharing_mode(vk::SharingMode::EXCLUSIVE)
        .push_next(&mut usage);
    build(&create)
}

pub(super) fn image<T>(
    info: &ImageInfo,
    build: impl FnOnce(&vk::ImageCreateInfo<'_>) -> Result<T>,
) -> Result<T> {
    let formats: Vec<vk::Format> = info.view_formats.iter().copied().map(format).collect();
    let mut list = vk::ImageFormatListCreateInfo::default().view_formats(&formats);
    let planes = [vk::SubresourceLayout {
        row_pitch: info.linear.map_or(0, |linear| linear.row_pitch),
        ..Default::default()
    }];
    let mut linear = vk::ImageDrmFormatModifierExplicitCreateInfoEXT::default()
        .drm_format_modifier(DRM_FORMAT_MOD_LINEAR)
        .plane_layouts(&planes);
    let mut create = vk::ImageCreateInfo::default()
        .flags(vk::ImageCreateFlags::from_raw(info.flags.bits()))
        .image_type(vk::ImageType::from_raw(info.image_type.raw() as i32))
        .format(format(info.format))
        .extent(extent(info.extent))
        .mip_levels(info.mip_levels)
        .array_layers(info.array_layers)
        .samples(vk::SampleCountFlags::from_raw(info.samples.bits()))
        .tiling(vk::ImageTiling::from_raw(info.tiling.raw() as i32))
        .usage(vk::ImageUsageFlags::from_raw(info.usage.bits()))
        .sharing_mode(vk::SharingMode::EXCLUSIVE)
        .initial_layout(vk::ImageLayout::UNDEFINED);
    if !formats.is_empty() {
        create = create.push_next(&mut list);
    }
    if info.linear.is_some() {
        create = create.push_next(&mut linear);
    }
    build(&create)
}

pub(super) fn image_view<T>(
    image: vk::Image,
    info: &ImageViewInfo,
    build: impl FnOnce(&vk::ImageViewCreateInfo<'_>) -> Result<T>,
) -> Result<T> {
    let swizzle =
        |index: usize| vk::ComponentSwizzle::from_raw(info.components[index].raw() as i32);
    let range = info.range;
    let mut usage = vk::ImageViewUsageCreateInfo::default()
        .usage(vk::ImageUsageFlags::from_raw(info.usage.bits()));
    let create = vk::ImageViewCreateInfo::default()
        .image(image)
        .view_type(vk::ImageViewType::from_raw(info.view_type.raw() as i32))
        .format(format(info.format))
        .components(vk::ComponentMapping {
            r: swizzle(0),
            g: swizzle(1),
            b: swizzle(2),
            a: swizzle(3),
        })
        .subresource_range(vk::ImageSubresourceRange {
            aspect_mask: aspects(range.aspects),
            base_mip_level: range.base_mip_level,
            level_count: range.level_count,
            base_array_layer: range.base_array_layer,
            layer_count: range.layer_count,
        })
        .push_next(&mut usage);
    build(&create)
}

pub(super) fn sampler<T>(
    info: &SamplerInfo,
    build: impl FnOnce(&vk::SamplerCreateInfo<'_>) -> Result<T>,
) -> Result<T> {
    let address =
        |index: usize| vk::SamplerAddressMode::from_raw(info.address_modes[index].raw() as i32);
    let filter =
        |filter: crate::gpu::metal::vulkan::Filter| vk::Filter::from_raw(filter.raw() as i32);
    let mut reduction = vk::SamplerReductionModeCreateInfo::default().reduction_mode(
        vk::SamplerReductionMode::from_raw(info.reduction_mode.raw() as i32),
    );
    let create = vk::SamplerCreateInfo::default()
        .mag_filter(filter(info.mag_filter))
        .min_filter(filter(info.min_filter))
        .mipmap_mode(vk::SamplerMipmapMode::from_raw(
            info.mipmap_mode.raw() as i32
        ))
        .address_mode_u(address(0))
        .address_mode_v(address(1))
        .address_mode_w(address(2))
        .anisotropy_enable(info.anisotropy.is_some())
        .max_anisotropy(info.anisotropy.unwrap_or(1.0))
        .compare_enable(info.compare.is_some())
        .compare_op(info.compare.map_or(vk::CompareOp::NEVER, |op| {
            vk::CompareOp::from_raw(op.raw() as i32)
        }))
        .min_lod(info.min_lod)
        .max_lod(info.max_lod)
        .border_color(vk::BorderColor::from_raw(info.border_color.raw() as i32))
        .unnormalized_coordinates(info.unnormalized_coordinates)
        .push_next(&mut reduction);
    build(&create)
}

fn stage(stage: ShaderStages, nir: &NirStage) -> vk::PipelineShaderStageCreateInfo<'_> {
    let mut info = vk::PipelineShaderStageCreateInfo::default()
        .stage(vk::ShaderStageFlags::from_raw(stage.bits()))
        .name(ENTRY_POINT);
    info.p_next = (nir as *const NirStage).cast();
    info
}

pub(super) fn compute_pipeline<T>(
    info: &ComputePipelineInfo,
    layout: vk::PipelineLayout,
    build: impl FnOnce(&vk::ComputePipelineCreateInfo<'_>) -> Result<T>,
) -> Result<T> {
    let mut subgroup = vk::PipelineShaderStageRequiredSubgroupSizeCreateInfo::default()
        .required_subgroup_size(info.required_subgroup_size);
    let nir = NirStage::new(info.code);
    let mut stage = stage(ShaderStages::COMPUTE, &nir);
    if info.full_subgroups {
        stage = stage.flags(vk::PipelineShaderStageCreateFlags::REQUIRE_FULL_SUBGROUPS);
    }
    if info.required_subgroup_size != 0 {
        stage = stage.push_next(&mut subgroup);
    }
    let create = vk::ComputePipelineCreateInfo::default()
        .stage(stage)
        .layout(layout);
    build(&create)
}

fn blend(attachment: &ColorBlendAttachment) -> vk::PipelineColorBlendAttachmentState {
    let factor = |factor: crate::gpu::metal::vulkan::BlendFactor| {
        vk::BlendFactor::from_raw(factor.raw() as i32)
    };
    let op = |op: crate::gpu::metal::vulkan::BlendOp| vk::BlendOp::from_raw(op.raw() as i32);
    vk::PipelineColorBlendAttachmentState {
        blend_enable: attachment.blend_enable.into(),
        src_color_blend_factor: factor(attachment.src_color),
        dst_color_blend_factor: factor(attachment.dst_color),
        color_blend_op: op(attachment.color_op),
        src_alpha_blend_factor: factor(attachment.src_alpha),
        dst_alpha_blend_factor: factor(attachment.dst_alpha),
        alpha_blend_op: op(attachment.alpha_op),
        color_write_mask: vk::ColorComponentFlags::from_raw(attachment.write_mask.bits()),
    }
}

/// A dynamic-rendering pipeline. Mesh pipelines have no vertex input or
/// input assembly; every state the encoder sets is dynamic, so the static
/// rasterization, viewport and depth-stencil states hold only defaults.
pub(super) fn graphics_pipeline<T>(
    info: &GraphicsPipelineInfo,
    layout: vk::PipelineLayout,
    build: impl FnOnce(&vk::GraphicsPipelineCreateInfo<'_>) -> Result<T>,
) -> Result<T> {
    let nirs: Vec<_> = info
        .stages
        .iter()
        .map(|&(_, code)| NirStage::new(code))
        .collect();
    let stages: Vec<_> = info
        .stages
        .iter()
        .zip(&nirs)
        .map(|(&(shader, _), nir)| stage(shader, nir))
        .collect();
    let mesh = info
        .stages
        .iter()
        .any(|(shader, _)| shader.contains(ShaderStages::MESH));

    let input = &info.vertex_input;
    let bindings: Vec<_> = input
        .bindings
        .iter()
        .map(|binding| vk::VertexInputBindingDescription {
            binding: binding.binding,
            stride: binding.stride.unwrap_or(0),
            input_rate: vk::VertexInputRate::from_raw(binding.input_rate.raw() as i32),
        })
        .collect();
    let divisors: Vec<_> = input
        .bindings
        .iter()
        .filter(|binding| binding.divisor != 1)
        .map(|binding| vk::VertexInputBindingDivisorDescriptionKHR {
            binding: binding.binding,
            divisor: binding.divisor,
        })
        .collect();
    let attributes: Vec<_> = input
        .attributes
        .iter()
        .map(|attribute| vk::VertexInputAttributeDescription {
            location: attribute.location,
            binding: attribute.binding,
            format: format(attribute.format),
            offset: attribute.offset,
        })
        .collect();
    let mut divisor_state = vk::PipelineVertexInputDivisorStateCreateInfoKHR::default()
        .vertex_binding_divisors(&divisors);
    let mut vertex_input = vk::PipelineVertexInputStateCreateInfo::default()
        .vertex_binding_descriptions(&bindings)
        .vertex_attribute_descriptions(&attributes);
    if !divisors.is_empty() {
        vertex_input = vertex_input.push_next(&mut divisor_state);
    }
    let input_assembly = vk::PipelineInputAssemblyStateCreateInfo::default()
        .topology(vk::PrimitiveTopology::from_raw(info.topology.raw() as i32));
    let tessellation = vk::PipelineTessellationStateCreateInfo::default()
        .patch_control_points(info.patch_control_points);

    let viewport = vk::PipelineViewportStateCreateInfo::default();
    let rasterization = vk::PipelineRasterizationStateCreateInfo::default()
        .polygon_mode(vk::PolygonMode::FILL)
        .line_width(1.0);
    let multisample = vk::PipelineMultisampleStateCreateInfo::default()
        .rasterization_samples(vk::SampleCountFlags::from_raw(info.samples.bits()))
        .alpha_to_coverage_enable(info.alpha_to_coverage)
        .alpha_to_one_enable(info.alpha_to_one);
    let depth_stencil = vk::PipelineDepthStencilStateCreateInfo::default();
    let attachments: Vec<_> = info.color_blend.iter().map(blend).collect();
    let color_blend = vk::PipelineColorBlendStateCreateInfo::default().attachments(&attachments);
    let dynamic_states: Vec<_> = info
        .dynamic_states
        .iter()
        .map(|state| vk::DynamicState::from_raw(state.raw() as i32))
        .collect();
    let dynamic = vk::PipelineDynamicStateCreateInfo::default().dynamic_states(&dynamic_states);
    let color_formats: Vec<_> = info
        .color_formats
        .iter()
        .map(|slot| slot.map_or(vk::Format::UNDEFINED, format))
        .collect();
    let mut rendering = vk::PipelineRenderingCreateInfo::default()
        .color_attachment_formats(&color_formats)
        .depth_attachment_format(info.depth_format.map_or(vk::Format::UNDEFINED, format))
        .stencil_attachment_format(info.stencil_format.map_or(vk::Format::UNDEFINED, format));

    let mut create = vk::GraphicsPipelineCreateInfo::default()
        .stages(&stages)
        .viewport_state(&viewport)
        .rasterization_state(&rasterization)
        .multisample_state(&multisample)
        .depth_stencil_state(&depth_stencil)
        .color_blend_state(&color_blend)
        .dynamic_state(&dynamic)
        .layout(layout)
        .push_next(&mut rendering);
    if !mesh {
        create = create
            .vertex_input_state(&vertex_input)
            .input_assembly_state(&input_assembly);
    }
    if info.topology == PrimitiveTopology::PatchList {
        create = create.tessellation_state(&tessellation);
    }
    build(&create)
}

/// `VkMemoryToImageCopyEXT` reading `bytes` from the region's buffer offset.
pub(super) fn memory_to_image(
    region: &BufferImageCopy,
    bytes: &[u8],
) -> vk::MemoryToImageCopyEXT<'static> {
    vk::MemoryToImageCopyEXT::default()
        .host_pointer(bytes[region.buffer_offset as usize..].as_ptr().cast())
        .memory_row_length(region.buffer_row_length)
        .memory_image_height(region.buffer_image_height)
        .image_subresource(subresource(region.subresource))
        .image_offset(offset(region.offset))
        .image_extent(extent(region.extent))
}

/// `VkImageToMemoryCopyEXT` writing `bytes` from the region's buffer offset.
pub(super) fn image_to_memory(
    region: &BufferImageCopy,
    bytes: &mut [u8],
) -> vk::ImageToMemoryCopyEXT<'static> {
    vk::ImageToMemoryCopyEXT::default()
        .host_pointer(bytes[region.buffer_offset as usize..].as_mut_ptr().cast())
        .memory_row_length(region.buffer_row_length)
        .memory_image_height(region.buffer_image_height)
        .image_subresource(subresource(region.subresource))
        .image_offset(offset(region.offset))
        .image_extent(extent(region.extent))
}

/// Timeline waits or signals of a submission, at every stage.
pub(super) fn semaphores(values: &[(Semaphore, u64)]) -> Vec<vk::SemaphoreSubmitInfo<'static>> {
    values
        .iter()
        .map(|&(semaphore, value)| {
            vk::SemaphoreSubmitInfo::default()
                .semaphore(handle(semaphore.0))
                .value(value)
                .stage_mask(vk::PipelineStageFlags2::ALL_COMMANDS)
        })
        .collect()
}
