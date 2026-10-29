//! What the Vulkan driver reports for one physical device.
//!
//! The backend fills a [`PhysicalDevice`] once from
//! `vkGetPhysicalDeviceProperties2`, `vkGetPhysicalDeviceFeatures2`,
//! `vkGetPhysicalDeviceMemoryProperties2` (with `VK_EXT_memory_budget`) and
//! the per-format queries. Field names follow the Vulkan members they copy.
//! Metal capabilities derive from this snapshot; nothing here is inferred
//! from a vendor or chip name.
use super::{
    DriverId, Format, FormatFeatures, MemoryHeapFlags, MemoryProperties, PhysicalDeviceType,
    ResolveModes, SampleCounts, ShaderStages, SubgroupFeatures,
};
use alloc::{string::String, vec::Vec};

#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalDevice {
    pub identity: Identity,
    pub limits: Limits,
    pub features: Features,
    pub memory: Memory,
    pub formats: FormatTable,
}

/// `VkPhysicalDeviceProperties`, `VkPhysicalDeviceDriverProperties` and
/// `VkPhysicalDevicePCIBusInfoPropertiesEXT` identity members.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub api_version: u32,
    pub driver_id: DriverId,
    pub driver_version: u32,
    pub vendor_id: u32,
    pub device_id: u32,
    pub device_type: PhysicalDeviceType,
    pub device_name: String,
    /// `conformanceVersion` as major, minor, subminor, patch; all zero when
    /// the driver does not claim conformance on this device.
    pub conformance_version: [u8; 4],
    pub pci_bus: Option<PciBusInfo>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciBusInfo {
    pub domain: u32,
    pub bus: u32,
    pub device: u32,
    pub function: u32,
}

/// Vulkan 1.0-1.4 limits plus the extension properties Metal needs.
#[derive(Clone, Debug, PartialEq)]
pub struct Limits {
    pub max_image_dimension_1d: u32,
    pub max_image_dimension_2d: u32,
    pub max_image_dimension_3d: u32,
    pub max_image_dimension_cube: u32,
    pub max_image_array_layers: u32,
    pub max_texel_buffer_elements: u32,
    pub max_uniform_buffer_range: u32,
    pub max_storage_buffer_range: u32,
    pub max_push_constants_size: u32,
    pub max_memory_allocation_count: u32,
    pub max_sampler_allocation_count: u32,
    pub buffer_image_granularity: u64,
    pub sparse_address_space_size: u64,
    pub max_per_stage_update_after_bind_samplers: u32,
    pub max_per_stage_update_after_bind_sampled_images: u32,
    pub max_per_stage_update_after_bind_storage_images: u32,
    pub max_per_stage_update_after_bind_storage_buffers: u32,
    pub max_descriptor_set_update_after_bind_samplers: u32,
    pub max_descriptor_set_update_after_bind_sampled_images: u32,
    pub max_descriptor_set_update_after_bind_storage_images: u32,
    pub max_vertex_input_attributes: u32,
    pub max_vertex_input_bindings: u32,
    pub max_vertex_input_attribute_offset: u32,
    pub max_vertex_input_binding_stride: u32,
    pub max_vertex_output_components: u32,
    pub max_tessellation_generation_level: u32,
    pub max_tessellation_patch_size: u32,
    pub max_fragment_input_components: u32,
    pub max_fragment_output_attachments: u32,
    pub max_fragment_dual_src_attachments: u32,
    pub max_compute_shared_memory_size: u32,
    pub max_compute_work_group_count: [u32; 3],
    pub max_compute_work_group_invocations: u32,
    pub max_compute_work_group_size: [u32; 3],
    pub max_sampler_lod_bias: f32,
    pub max_sampler_anisotropy: f32,
    pub max_viewports: u32,
    pub max_viewport_dimensions: [u32; 2],
    pub min_texel_buffer_offset_alignment: u64,
    pub min_uniform_buffer_offset_alignment: u64,
    pub min_storage_buffer_offset_alignment: u64,
    pub max_framebuffer_width: u32,
    pub max_framebuffer_height: u32,
    pub max_framebuffer_layers: u32,
    pub framebuffer_color_sample_counts: SampleCounts,
    pub framebuffer_depth_sample_counts: SampleCounts,
    pub framebuffer_stencil_sample_counts: SampleCounts,
    pub framebuffer_no_attachments_sample_counts: SampleCounts,
    pub max_color_attachments: u32,
    pub sampled_image_color_sample_counts: SampleCounts,
    pub sampled_image_integer_sample_counts: SampleCounts,
    pub sampled_image_depth_sample_counts: SampleCounts,
    pub storage_image_sample_counts: SampleCounts,
    pub max_sample_mask_words: u32,
    pub timestamp_compute_and_graphics: bool,
    /// Nanoseconds per timestamp tick.
    pub timestamp_period: f32,
    pub max_clip_distances: u32,
    pub max_cull_distances: u32,
    pub point_size_range: [f32; 2],
    pub line_width_range: [f32; 2],
    pub non_coherent_atom_size: u64,
    pub subgroup_size: u32,
    pub min_subgroup_size: u32,
    pub max_subgroup_size: u32,
    pub subgroup_supported_stages: ShaderStages,
    pub subgroup_supported_operations: SubgroupFeatures,
    pub subgroup_quad_operations_in_all_stages: bool,
    pub max_multiview_view_count: u32,
    pub max_memory_allocation_size: u64,
    pub max_buffer_size: u64,
    pub storage_texel_buffer_offset_alignment_bytes: u64,
    pub storage_texel_buffer_offset_single_texel_alignment: bool,
    pub uniform_texel_buffer_offset_alignment_bytes: u64,
    pub uniform_texel_buffer_offset_single_texel_alignment: bool,
    pub supported_depth_resolve_modes: ResolveModes,
    pub supported_stencil_resolve_modes: ResolveModes,
    pub independent_resolve_none: bool,
    pub independent_resolve: bool,
    pub max_vertex_attrib_divisor: u32,
    /// `VkPhysicalDeviceSampleLocationsPropertiesEXT`; `None` without the extension.
    pub sample_locations: Option<SampleLocationLimits>,
    /// `VkPhysicalDeviceMeshShaderPropertiesEXT`; `None` without the extension.
    pub mesh: Option<MeshLimits>,
    /// `VkPhysicalDeviceDeviceGeneratedCommandsPropertiesEXT`; `None` unless
    /// the device enables `deviceGeneratedCommands`.
    pub generated_commands: Option<GeneratedCommandsLimits>,
    /// `VkPhysicalDeviceSparseProperties`.
    pub sparse: SparseLimits,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SampleLocationLimits {
    pub sample_counts: SampleCounts,
    pub max_grid_size: [u32; 2],
    pub coordinate_range: [f32; 2],
    pub sub_pixel_bits: u32,
    pub variable_sample_locations: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshLimits {
    pub max_task_work_group_total_count: u32,
    pub max_task_work_group_count: [u32; 3],
    pub max_task_work_group_invocations: u32,
    pub max_task_payload_size: u32,
    pub max_mesh_work_group_total_count: u32,
    pub max_mesh_work_group_count: [u32; 3],
    pub max_mesh_work_group_invocations: u32,
    pub max_mesh_output_vertices: u32,
    pub max_mesh_output_primitives: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeneratedCommandsLimits {
    pub max_pipelines: u32,
    pub max_sequences: u32,
    pub max_tokens: u32,
    pub max_token_offset: u32,
    pub max_stride: u32,
    /// `supportedIndirectCommandsShaderStagesPipelineBinding`: stages an
    /// execution set of pipelines may bind.
    pub pipeline_stages: ShaderStages,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SparseLimits {
    pub residency_standard_2d_block_shape: bool,
    pub residency_standard_2d_multisample_block_shape: bool,
    pub residency_standard_3d_block_shape: bool,
    pub residency_aligned_mip_size: bool,
    pub residency_non_resident_strict: bool,
}

/// Enabled-capable Vulkan features, named as in the Vulkan feature structures.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Features {
    pub image_cube_array: bool,
    pub independent_blend: bool,
    pub geometry_shader: bool,
    pub tessellation_shader: bool,
    pub sample_rate_shading: bool,
    pub dual_src_blend: bool,
    pub alpha_to_one: bool,
    pub multi_draw_indirect: bool,
    pub draw_indirect_first_instance: bool,
    pub depth_clamp: bool,
    pub depth_bias_clamp: bool,
    pub fill_mode_non_solid: bool,
    pub wide_lines: bool,
    pub large_points: bool,
    pub multi_viewport: bool,
    pub sampler_anisotropy: bool,
    pub texture_compression_etc2: bool,
    pub texture_compression_astc_ldr: bool,
    pub texture_compression_astc_hdr: bool,
    pub texture_compression_bc: bool,
    pub texture_compression_pvrtc: bool,
    pub occlusion_query_precise: bool,
    pub pipeline_statistics_query: bool,
    pub vertex_pipeline_stores_and_atomics: bool,
    pub fragment_stores_and_atomics: bool,
    pub shader_image_gather_extended: bool,
    pub shader_storage_image_multisample: bool,
    pub shader_storage_image_read_without_format: bool,
    pub shader_storage_image_write_without_format: bool,
    pub shader_clip_distance: bool,
    pub shader_cull_distance: bool,
    pub shader_float64: bool,
    pub shader_int64: bool,
    pub shader_int16: bool,
    pub shader_float16: bool,
    pub shader_int8: bool,
    pub shader_resource_residency: bool,
    pub shader_resource_min_lod: bool,
    pub sparse_binding: bool,
    pub sparse_residency_buffer: bool,
    pub sparse_residency_image_2d: bool,
    pub sparse_residency_image_3d: bool,
    /// The multisample counts of `sparseResidency{2,4,8,16}Samples`.
    pub sparse_residency_samples: SampleCounts,
    pub sparse_residency_aliased: bool,
    pub storage_buffer_8bit_access: bool,
    pub storage_buffer_16bit_access: bool,
    pub multiview: bool,
    pub sampler_mirror_clamp_to_edge: bool,
    pub sampler_filter_minmax: bool,
    pub descriptor_indexing: bool,
    pub runtime_descriptor_array: bool,
    pub descriptor_binding_partially_bound: bool,
    pub descriptor_binding_update_unused_while_pending: bool,
    pub descriptor_binding_sampled_image_update_after_bind: bool,
    pub descriptor_binding_storage_image_update_after_bind: bool,
    pub descriptor_binding_uniform_texel_buffer_update_after_bind: bool,
    pub descriptor_binding_storage_texel_buffer_update_after_bind: bool,
    pub shader_sampled_image_array_non_uniform_indexing: bool,
    pub shader_storage_image_array_non_uniform_indexing: bool,
    pub buffer_device_address: bool,
    pub timeline_semaphore: bool,
    pub vulkan_memory_model: bool,
    pub vulkan_memory_model_device_scope: bool,
    pub shader_buffer_int64_atomics: bool,
    pub shader_shared_int64_atomics: bool,
    pub shader_image_int64_atomics: bool,
    pub shader_buffer_float32_atomic_add: bool,
    pub shader_shared_float32_atomic_add: bool,
    pub shader_image_float32_atomics: bool,
    pub shader_demote_to_helper_invocation: bool,
    pub subgroup_size_control: bool,
    pub compute_full_subgroups: bool,
    pub synchronization2: bool,
    pub dynamic_rendering: bool,
    pub dynamic_rendering_local_read: bool,
    pub maintenance4: bool,
    pub maintenance5: bool,
    pub host_image_copy: bool,
    pub extended_dynamic_state: bool,
    pub extended_dynamic_state2: bool,
    pub extended_dynamic_state3_polygon_mode: bool,
    pub extended_dynamic_state3_depth_clamp_enable: bool,
    pub extended_dynamic_state3_depth_clip_enable: bool,
    pub vertex_input_dynamic_state: bool,
    pub vertex_attribute_instance_rate_divisor: bool,
    pub vertex_attribute_instance_rate_zero_divisor: bool,
    pub depth_clip_enable: bool,
    pub fragment_shader_barycentric: bool,
    pub task_shader: bool,
    pub mesh_shader: bool,
    pub fragment_shader_pixel_interlock: bool,
    pub unified_image_layouts: bool,
    /// `robustness2` `nullDescriptor`.
    pub null_descriptor: bool,
    pub dynamic_rendering_unused_attachments: bool,
    /// `VkPhysicalDeviceExtendedDynamicState3PropertiesEXT`.
    pub dynamic_primitive_topology_unrestricted: bool,
    pub host_query_reset: bool,
    pub conditional_rendering: bool,
    pub image_drm_format_modifier: bool,
    pub shader_float16_vector_atomics: bool,
    pub memory_budget: bool,
    pub calibrated_timestamps: bool,
    pub cooperative_matrix: bool,
    pub acceleration_structure: bool,
    pub ray_query: bool,
    pub ray_tracing_pipeline: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Memory {
    pub heaps: Vec<MemoryHeap>,
    pub types: Vec<MemoryType>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryHeap {
    pub size: u64,
    pub flags: MemoryHeapFlags,
    /// `VK_EXT_memory_budget` heap budget at snapshot time.
    pub budget: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryType {
    pub properties: MemoryProperties,
    pub heap_index: u32,
}

impl Memory {
    /// Bytes of device-local heap memory, the GPU's own memory.
    pub fn device_local_bytes(&self) -> u64 {
        self.heaps
            .iter()
            .filter(|heap| heap.flags.contains(MemoryHeapFlags::DEVICE_LOCAL))
            .fold(0u64, |total, heap| total.saturating_add(heap.size))
    }

    /// The driver's current budget for device-local heaps, if it reports one.
    pub fn device_local_budget(&self) -> Option<u64> {
        self.heaps
            .iter()
            .filter(|heap| heap.flags.contains(MemoryHeapFlags::DEVICE_LOCAL))
            .try_fold(0u64, |total, heap| Some(total.saturating_add(heap.budget?)))
    }

    /// Index of the first memory type holding every `required` property,
    /// preferring one that also holds `preferred`, among `allowed` type bits.
    pub fn select_type(
        &self,
        allowed: u32,
        required: MemoryProperties,
        preferred: MemoryProperties,
    ) -> Option<u32> {
        let candidates = || {
            self.types
                .iter()
                .enumerate()
                .filter(move |(index, memory)| {
                    *index < 32
                        && allowed & (1 << index) != 0
                        && memory.properties.contains(required)
                })
        };
        candidates()
            .find(|(_, memory)| memory.properties.contains(preferred))
            .or_else(|| candidates().next())
            .map(|(index, _)| index as u32)
    }
}

/// Per-format support, from `vkGetPhysicalDeviceFormatProperties2` with
/// `VkFormatProperties3`, the optimal-tiling 2D image sample counts and
/// the sample counts of its sparse-residency 2D images.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FormatSupport {
    pub optimal: FormatFeatures,
    pub linear: FormatFeatures,
    pub buffer: FormatFeatures,
    pub sample_counts: SampleCounts,
    pub sparse: SampleCounts,
}

/// Format support for every format the Metal layer can request; formats the
/// driver did not report have no features.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FormatTable {
    entries: Vec<(Format, FormatSupport)>,
}

impl FormatTable {
    pub fn insert(&mut self, format: Format, support: FormatSupport) {
        match self.entries.iter_mut().find(|(known, _)| *known == format) {
            Some(entry) => entry.1 = support,
            None => self.entries.push((format, support)),
        }
    }

    pub fn get(&self, format: Format) -> FormatSupport {
        self.entries
            .iter()
            .find(|(known, _)| *known == format)
            .map_or_else(FormatSupport::default, |(_, support)| *support)
    }
}
