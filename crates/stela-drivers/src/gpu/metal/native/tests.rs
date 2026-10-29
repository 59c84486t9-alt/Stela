use super::{failure, objects};
use crate::gpu::metal::{
    binding::HeapArray,
    error::Error,
    nvidia::{Chip, fixture::nvk},
    vulkan::{
        Format, ImageCreate, ImageTiling, ImageType, ImageUsage, MemoryProperties as M,
        PrimitiveTopology, SampleCounts, ShaderStages,
        backend::Descriptor,
        object::{
            BufferView, GraphicsPipelineInfo, ImageInfo, ImageView, LinearLayout, MemoryRequest,
            Sampler, ShaderCode,
        },
    },
};
use alloc::vec;
use ash::vk;

fn memory() -> crate::gpu::metal::vulkan::physical::Memory {
    nvk(Chip::find(0x1b3).unwrap(), 16 << 30).memory
}

#[test]
fn memory_candidates_put_preferred_types_first() {
    let shared_cached = MemoryRequest {
        required: M::HOST_VISIBLE | M::HOST_COHERENT,
        preferred: M::HOST_CACHED,
        mapped: true,
    };
    assert_eq!(
        objects::memory_candidates(&memory(), u32::MAX, shared_cached),
        [2, 1, 3]
    );
    let write_combined = MemoryRequest {
        preferred: M::DEVICE_LOCAL,
        ..shared_cached
    };
    assert_eq!(
        objects::memory_candidates(&memory(), u32::MAX, write_combined),
        [3, 1, 2]
    );
    // The resource's memory types restrict the candidates.
    assert_eq!(
        objects::memory_candidates(&memory(), 0b0010, write_combined),
        [1]
    );
}

#[test]
fn mapped_requests_need_host_visible_memory() {
    let private = MemoryRequest {
        required: M::DEVICE_LOCAL,
        preferred: M::EMPTY,
        mapped: false,
    };
    assert_eq!(
        objects::memory_candidates(&memory(), u32::MAX, private),
        [0, 3]
    );
    let mapped = MemoryRequest {
        mapped: true,
        ..private
    };
    assert_eq!(objects::memory_candidates(&memory(), u32::MAX, mapped), [3]);
}

#[test]
fn heap_bindings_follow_the_array_order() {
    let bindings = objects::heap_bindings(&[10, 20, 30, 40, 50]);
    let types = [
        vk::DescriptorType::SAMPLED_IMAGE,
        vk::DescriptorType::STORAGE_IMAGE,
        vk::DescriptorType::SAMPLER,
        vk::DescriptorType::UNIFORM_TEXEL_BUFFER,
        vk::DescriptorType::STORAGE_TEXEL_BUFFER,
    ];
    for ((binding, ty), array) in bindings.iter().zip(types).zip(HeapArray::ALL) {
        assert_eq!(binding.binding, array.raw());
        assert!(binding.descriptor_type == ty);
        assert_eq!(binding.descriptor_count, 10 * (array.raw() + 1));
        assert!(binding.stage_flags == vk::ShaderStageFlags::ALL);
    }
}

#[test]
fn descriptors_write_their_array_slot() {
    let set = vk::Handle::from_raw(7);
    let mut written = None;
    objects::descriptor_write(set, 9, Descriptor::StorageImage(ImageView(5)), |write| {
        // SAFETY: the write points at one image info for this call.
        let image = unsafe { *write.p_image_info };
        written = Some((
            write.dst_binding,
            write.dst_array_element,
            write.descriptor_type,
            image.image_view,
            image.image_layout,
        ));
    });
    // ash's enums implement `Debug` only with its `debug` feature.
    assert!(
        written
            == Some((
                HeapArray::StorageImages.raw(),
                9,
                vk::DescriptorType::STORAGE_IMAGE,
                vk::Handle::from_raw(5),
                vk::ImageLayout::GENERAL,
            ))
    );

    let mut sampler = None;
    objects::descriptor_write(set, 0, Descriptor::Sampler(Sampler(3)), |write| {
        // SAFETY: as above.
        sampler = Some(unsafe { (*write.p_image_info).sampler });
    });
    assert_eq!(sampler, Some(vk::Handle::from_raw(3)));

    let mut texel = None;
    objects::descriptor_write(
        set,
        0,
        Descriptor::UniformTexelBuffer(BufferView(0)),
        |write| {
            // SAFETY: the write points at one texel buffer view.
            texel = Some((write.descriptor_type, unsafe { *write.p_texel_buffer_view }));
        },
    );
    assert!(
        texel
            == Some((
                vk::DescriptorType::UNIFORM_TEXEL_BUFFER,
                vk::BufferView::null()
            ))
    );
}

#[test]
fn linear_images_chain_an_explicit_linear_layout() {
    let info = ImageInfo {
        flags: ImageCreate::MUTABLE_FORMAT,
        image_type: ImageType::D2,
        format: Format::R8G8B8A8Unorm,
        extent: [64, 32, 1],
        mip_levels: 1,
        array_layers: 1,
        samples: SampleCounts::C1,
        tiling: ImageTiling::DrmFormatModifier,
        usage: ImageUsage::SAMPLED,
        view_formats: vec![Format::R8G8B8A8Unorm, Format::R8G8B8A8Srgb],
        linear: Some(LinearLayout { row_pitch: 256 }),
    };
    let chain = objects::image(&info, |create| {
        assert!(create.tiling == vk::ImageTiling::DRM_FORMAT_MODIFIER_EXT);
        assert!(create.initial_layout == vk::ImageLayout::UNDEFINED);
        let mut types = vec![];
        let mut next = create.p_next.cast::<vk::BaseInStructure<'_>>();
        while !next.is_null() {
            // SAFETY: every link is a structure the builder chained.
            let base = unsafe { &*next };
            if base.s_type == vk::StructureType::IMAGE_DRM_FORMAT_MODIFIER_EXPLICIT_CREATE_INFO_EXT
            {
                // SAFETY: the type names the structure.
                let explicit =
                    unsafe { &*next.cast::<vk::ImageDrmFormatModifierExplicitCreateInfoEXT<'_>>() };
                assert_eq!(explicit.drm_format_modifier, 0);
                // SAFETY: one plane layout.
                assert_eq!(unsafe { (*explicit.p_plane_layouts).row_pitch }, 256);
            }
            types.push(base.s_type);
            next = base.p_next;
        }
        Ok(types)
    })
    .unwrap();
    assert!(chain.contains(&vk::StructureType::IMAGE_FORMAT_LIST_CREATE_INFO));
    assert!(chain.contains(&vk::StructureType::IMAGE_DRM_FORMAT_MODIFIER_EXPLICIT_CREATE_INFO_EXT));
}

fn pipeline(
    stages: &[(ShaderStages, ShaderCode)],
    topology: PrimitiveTopology,
) -> GraphicsPipelineInfo {
    GraphicsPipelineInfo {
        stages: stages.to_vec(),
        vertex_input: Default::default(),
        topology,
        patch_control_points: 1,
        samples: SampleCounts::C4,
        alpha_to_coverage: true,
        alpha_to_one: false,
        color_formats: vec![Some(Format::B8G8R8A8Unorm), None],
        depth_format: Some(Format::D32Sfloat),
        stencil_format: None,
        color_blend: vec![],
        dynamic_states: vec![],
    }
}

#[test]
fn mesh_pipelines_have_no_vertex_input() {
    let layout = vk::PipelineLayout::null();
    let code = ShaderCode(1);
    let mesh = pipeline(
        &[(ShaderStages::MESH, code), (ShaderStages::FRAGMENT, code)],
        PrimitiveTopology::TriangleList,
    );
    objects::graphics_pipeline(&mesh, layout, |create| {
        assert!(create.p_vertex_input_state.is_null());
        assert!(create.p_input_assembly_state.is_null());
        assert!(create.p_tessellation_state.is_null());
        assert_eq!(create.stage_count, 2);
        Ok(())
    })
    .unwrap();

    let patches = pipeline(
        &[
            (ShaderStages::VERTEX, code),
            (ShaderStages::TESSELLATION_CONTROL, code),
        ],
        PrimitiveTopology::PatchList,
    );
    objects::graphics_pipeline(&patches, layout, |create| {
        assert!(!create.p_vertex_input_state.is_null());
        assert!(!create.p_tessellation_state.is_null());
        // SAFETY: the builder chained the rendering info first.
        let rendering = unsafe { &*create.p_next.cast::<vk::PipelineRenderingCreateInfo<'_>>() };
        assert_eq!(rendering.color_attachment_count, 2);
        // SAFETY: two formats.
        let second = unsafe { *rendering.p_color_attachment_formats.add(1) };
        assert!(second == vk::Format::UNDEFINED);
        assert!(rendering.depth_attachment_format == vk::Format::D32_SFLOAT);
        // SAFETY: the stage array has two entries.
        let stage = unsafe { &*create.p_stages };
        assert_eq!(stage.p_name, objects::ENTRY_POINT.as_ptr());
        assert_eq!(stage.module, vk::Handle::from_raw(1));
        Ok(())
    })
    .unwrap();
}

#[test]
fn vulkan_failures_map_to_metal_errors() {
    assert_eq!(failure(vk::Result::ERROR_DEVICE_LOST), Error::DeviceLost);
    assert_eq!(
        failure(vk::Result::ERROR_OUT_OF_DEVICE_MEMORY),
        Error::OutOfMemory
    );
    assert_eq!(
        failure(vk::Result::ERROR_FRAGMENTED_POOL),
        Error::OutOfMemory
    );
    assert!(matches!(
        failure(vk::Result::ERROR_INITIALIZATION_FAILED),
        Error::Unsupported(_)
    ));
}
