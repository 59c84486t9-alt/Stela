//! `VK_EXT_device_generated_commands`, newer than the bindings: its
//! structures and entry points as Mesa 26.2.5's `vulkan_core.h` declares
//! them, and the backend's use of them.
use crate::metal::vulkan::{
    ShaderStages,
    command::GeneratedCommands,
    object::{IndirectCommandsLayoutInfo, IndirectToken},
    physical::GeneratedCommandsLimits,
};
use alloc::vec::Vec;
use ash::vk;
use core::{
    ffi::{CStr, c_void},
    mem, ptr,
};

pub(super) const NAME: &CStr = c"VK_EXT_device_generated_commands";

/// `VK_STRUCTURE_TYPE_*_EXT` of the extension, from 1000572000.
const fn s_type(offset: i32) -> vk::StructureType {
    vk::StructureType::from_raw(1_000_572_000 + offset)
}

/// `VK_PIPELINE_CREATE_2_INDIRECT_BINDABLE_BIT_EXT`.
pub(super) const INDIRECT_BINDABLE: vk::PipelineCreateFlags2KHR =
    vk::PipelineCreateFlags2KHR::from_raw(0x40_0000_0000);

/// `VkIndirectExecutionSetInfoTypeEXT`: pipelines.
const PIPELINES: i32 = 0;
/// `VK_INDIRECT_COMMANDS_INPUT_MODE_VULKAN_INDEX_BUFFER_EXT`.
const VULKAN_INDEX_BUFFER: u32 = 1;

/// `VkPhysicalDeviceDeviceGeneratedCommandsFeaturesEXT`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Features {
    pub(super) s_type: vk::StructureType,
    pub(super) p_next: *mut c_void,
    pub(super) device_generated_commands: vk::Bool32,
    pub(super) dynamic_generated_pipeline_layout: vk::Bool32,
}

impl Default for Features {
    fn default() -> Self {
        Self {
            s_type: s_type(0),
            p_next: ptr::null_mut(),
            device_generated_commands: vk::FALSE,
            dynamic_generated_pipeline_layout: vk::FALSE,
        }
    }
}

/// `VkPhysicalDeviceDeviceGeneratedCommandsPropertiesEXT`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Properties {
    pub(super) s_type: vk::StructureType,
    pub(super) p_next: *mut c_void,
    pub(super) max_indirect_pipeline_count: u32,
    pub(super) max_indirect_shader_object_count: u32,
    pub(super) max_indirect_sequence_count: u32,
    pub(super) max_indirect_commands_token_count: u32,
    pub(super) max_indirect_commands_token_offset: u32,
    pub(super) max_indirect_commands_indirect_stride: u32,
    pub(super) supported_indirect_commands_input_modes: u32,
    pub(super) supported_indirect_commands_shader_stages: vk::ShaderStageFlags,
    pub(super) supported_indirect_commands_shader_stages_pipeline_binding: vk::ShaderStageFlags,
    pub(super) supported_indirect_commands_shader_stages_shader_binding: vk::ShaderStageFlags,
    pub(super) device_generated_commands_transform_feedback: vk::Bool32,
    pub(super) device_generated_commands_multi_draw_indirect_count: vk::Bool32,
}

impl Default for Properties {
    fn default() -> Self {
        Self {
            s_type: s_type(1),
            p_next: ptr::null_mut(),
            max_indirect_pipeline_count: 0,
            max_indirect_shader_object_count: 0,
            max_indirect_sequence_count: 0,
            max_indirect_commands_token_count: 0,
            max_indirect_commands_token_offset: 0,
            max_indirect_commands_indirect_stride: 0,
            supported_indirect_commands_input_modes: 0,
            supported_indirect_commands_shader_stages: vk::ShaderStageFlags::empty(),
            supported_indirect_commands_shader_stages_pipeline_binding: vk::ShaderStageFlags::empty(
            ),
            supported_indirect_commands_shader_stages_shader_binding: vk::ShaderStageFlags::empty(),
            device_generated_commands_transform_feedback: vk::FALSE,
            device_generated_commands_multi_draw_indirect_count: vk::FALSE,
        }
    }
}

/// `VkGeneratedCommandsMemoryRequirementsInfoEXT`.
#[repr(C)]
struct MemoryRequirementsInfo {
    s_type: vk::StructureType,
    p_next: *const c_void,
    execution_set: u64,
    layout: u64,
    max_sequence_count: u32,
    max_draw_count: u32,
}

/// `VkIndirectExecutionSetPipelineInfoEXT`.
#[repr(C)]
struct ExecutionSetPipelineInfo {
    s_type: vk::StructureType,
    p_next: *const c_void,
    initial_pipeline: vk::Pipeline,
    max_pipeline_count: u32,
}

/// `VkIndirectExecutionSetCreateInfoEXT`; `info` is the union's pipeline
/// member.
#[repr(C)]
struct ExecutionSetCreateInfo {
    s_type: vk::StructureType,
    p_next: *const c_void,
    info_type: i32,
    info: *const ExecutionSetPipelineInfo,
}

/// `VkGeneratedCommandsInfoEXT`.
#[repr(C)]
struct GeneratedCommandsInfo {
    s_type: vk::StructureType,
    p_next: *const c_void,
    shader_stages: vk::ShaderStageFlags,
    execution_set: u64,
    layout: u64,
    indirect_address: u64,
    indirect_address_size: u64,
    preprocess_address: u64,
    preprocess_size: u64,
    max_sequence_count: u32,
    sequence_count_address: u64,
    max_draw_count: u32,
}

/// `VkWriteIndirectExecutionSetPipelineEXT`.
#[repr(C)]
struct WriteExecutionSetPipeline {
    s_type: vk::StructureType,
    p_next: *const c_void,
    index: u32,
    pipeline: vk::Pipeline,
}

/// `VkIndirectCommandsLayoutTokenEXT`; `data` is the union's pointer to the
/// token's own structure, or null.
#[repr(C)]
struct LayoutToken {
    s_type: vk::StructureType,
    p_next: *const c_void,
    token_type: i32,
    data: *const c_void,
    offset: u32,
}

/// `VkIndirectCommandsLayoutCreateInfoEXT`.
#[repr(C)]
struct LayoutCreateInfo {
    s_type: vk::StructureType,
    p_next: *const c_void,
    flags: u32,
    shader_stages: vk::ShaderStageFlags,
    indirect_stride: u32,
    pipeline_layout: vk::PipelineLayout,
    token_count: u32,
    tokens: *const LayoutToken,
}

/// The token structures a layout's tokens point to
/// (`VkIndirectCommands*TokenEXT`).
#[derive(Clone, Copy)]
#[repr(C)]
union TokenData {
    push_constant: vk::PushConstantRange,
    vertex_buffer: u32,
    index_buffer: u32,
    execution_set: [u32; 2],
}

type GetMemoryRequirements = unsafe extern "system" fn(
    vk::Device,
    *const MemoryRequirementsInfo,
    *mut vk::MemoryRequirements2<'_>,
);
type CmdExecute =
    unsafe extern "system" fn(vk::CommandBuffer, vk::Bool32, *const GeneratedCommandsInfo);
type CreateLayout = unsafe extern "system" fn(
    vk::Device,
    *const LayoutCreateInfo,
    *const vk::AllocationCallbacks<'_>,
    *mut u64,
) -> vk::Result;
type DestroyLayout = unsafe extern "system" fn(vk::Device, u64, *const vk::AllocationCallbacks<'_>);
type CreateSet = unsafe extern "system" fn(
    vk::Device,
    *const ExecutionSetCreateInfo,
    *const vk::AllocationCallbacks<'_>,
    *mut u64,
) -> vk::Result;
type DestroySet = unsafe extern "system" fn(vk::Device, u64, *const vk::AllocationCallbacks<'_>);
type UpdateSet = unsafe extern "system" fn(vk::Device, u64, u32, *const WriteExecutionSetPipeline);

/// The extension's device-level entry points.
pub(super) struct Fns {
    device: vk::Device,
    get_memory_requirements: GetMemoryRequirements,
    cmd_execute: CmdExecute,
    create_layout: CreateLayout,
    destroy_layout: DestroyLayout,
    create_set: CreateSet,
    destroy_set: DestroySet,
    update_set: UpdateSet,
}

impl Fns {
    /// The entry points of `device`, which enabled the extension; `None`
    /// when the driver lacks one.
    pub(super) fn load(instance: &ash::Instance, device: &ash::Device) -> Option<Self> {
        let handle = device.handle();
        let load = |name: &CStr| {
            // SAFETY: the device is valid and the name is NUL-terminated.
            unsafe { instance.get_device_proc_addr(handle, name.as_ptr()) }
        };
        macro_rules! entry {
            ($name:literal as $type:ty) => {
                // SAFETY: the pointer is the named entry point, whose
                // signature the type declares as `vulkan_core.h` does.
                unsafe { mem::transmute::<unsafe extern "system" fn(), $type>(load($name)?) }
            };
        }
        Some(Self {
            device: handle,
            get_memory_requirements: entry!(
                c"vkGetGeneratedCommandsMemoryRequirementsEXT" as GetMemoryRequirements
            ),
            cmd_execute: entry!(c"vkCmdExecuteGeneratedCommandsEXT" as CmdExecute),
            create_layout: entry!(c"vkCreateIndirectCommandsLayoutEXT" as CreateLayout),
            destroy_layout: entry!(c"vkDestroyIndirectCommandsLayoutEXT" as DestroyLayout),
            create_set: entry!(c"vkCreateIndirectExecutionSetEXT" as CreateSet),
            destroy_set: entry!(c"vkDestroyIndirectExecutionSetEXT" as DestroySet),
            update_set: entry!(c"vkUpdateIndirectExecutionSetPipelineEXT" as UpdateSet),
        })
    }

    /// `vkCreateIndirectCommandsLayoutEXT` over the pipeline layout, whose
    /// push constant range covers every stage.
    pub(super) fn create_layout(
        &self,
        info: &IndirectCommandsLayoutInfo,
        pipeline_layout: vk::PipelineLayout,
    ) -> core::result::Result<u64, vk::Result> {
        let stages = vk::ShaderStageFlags::from_raw(info.stages.bits());
        let data: Vec<Option<TokenData>> = info
            .tokens
            .iter()
            .map(|(_, token)| match *token {
                IndirectToken::ExecutionSet(stages) => Some(TokenData {
                    execution_set: [PIPELINES as u32, stages.bits()],
                }),
                IndirectToken::PushConstants { offset, size } => Some(TokenData {
                    push_constant: vk::PushConstantRange {
                        stage_flags: vk::ShaderStageFlags::ALL,
                        offset,
                        size,
                    },
                }),
                IndirectToken::IndexBuffer => Some(TokenData {
                    index_buffer: VULKAN_INDEX_BUFFER,
                }),
                IndirectToken::VertexBuffer(binding) => Some(TokenData {
                    vertex_buffer: binding,
                }),
                _ => None,
            })
            .collect();
        let tokens: Vec<LayoutToken> = info
            .tokens
            .iter()
            .zip(&data)
            .map(|(&(offset, token), data)| LayoutToken {
                s_type: s_type(7),
                p_next: ptr::null(),
                token_type: token_type(token),
                data: data
                    .as_ref()
                    .map_or(ptr::null(), |data| ptr::from_ref(data).cast()),
                offset,
            })
            .collect();
        let create = LayoutCreateInfo {
            s_type: s_type(6),
            p_next: ptr::null(),
            flags: 0,
            shader_stages: stages,
            indirect_stride: info.stride,
            pipeline_layout,
            token_count: tokens.len() as u32,
            tokens: tokens.as_ptr(),
        };
        let mut layout = 0;
        // SAFETY: the create info, its tokens and their data outlive the
        // call, which writes only the handle.
        let result =
            unsafe { (self.create_layout)(self.device, &create, ptr::null(), &mut layout) };
        result.result_with_success(layout)
    }

    pub(super) fn create_set(
        &self,
        initial: vk::Pipeline,
        capacity: u32,
    ) -> core::result::Result<u64, vk::Result> {
        let pipelines = ExecutionSetPipelineInfo {
            s_type: s_type(10),
            p_next: ptr::null(),
            initial_pipeline: initial,
            max_pipeline_count: capacity,
        };
        let create = ExecutionSetCreateInfo {
            s_type: s_type(3),
            p_next: ptr::null(),
            info_type: PIPELINES,
            info: &pipelines,
        };
        let mut set = 0;
        // SAFETY: the create info and its pipeline info outlive the call,
        // which writes only the handle.
        let result = unsafe { (self.create_set)(self.device, &create, ptr::null(), &mut set) };
        result.result_with_success(set)
    }

    /// # Safety
    ///
    /// No pending submission uses `index` of `set`.
    pub(super) unsafe fn write_set(&self, set: u64, index: u32, pipeline: vk::Pipeline) {
        let write = WriteExecutionSetPipeline {
            s_type: s_type(8),
            p_next: ptr::null(),
            index,
            pipeline,
        };
        // SAFETY: the caller guarantees the index is idle; the write outlives
        // the call.
        unsafe { (self.update_set)(self.device, set, 1, &write) }
    }

    pub(super) fn memory_requirements(
        &self,
        layout: u64,
        set: Option<u64>,
        sequences: u32,
    ) -> vk::MemoryRequirements {
        let info = MemoryRequirementsInfo {
            s_type: s_type(2),
            p_next: ptr::null(),
            execution_set: set.unwrap_or(0),
            layout,
            max_sequence_count: sequences,
            max_draw_count: 0,
        };
        let mut requirements = vk::MemoryRequirements2::default();
        // SAFETY: the info outlives the call, which writes only the
        // requirements.
        unsafe { (self.get_memory_requirements)(self.device, &info, &mut requirements) };
        requirements.memory_requirements
    }

    /// # Safety
    ///
    /// `buffer` is recording, with state valid for the generated commands.
    pub(super) unsafe fn execute(&self, buffer: vk::CommandBuffer, commands: &GeneratedCommands) {
        let info = GeneratedCommandsInfo {
            s_type: s_type(4),
            p_next: ptr::null(),
            shader_stages: vk::ShaderStageFlags::from_raw(commands.stages.bits()),
            execution_set: commands.set.map_or(0, |set| set.0),
            layout: commands.layout.0,
            indirect_address: commands.address,
            indirect_address_size: commands.size,
            preprocess_address: commands.preprocess,
            preprocess_size: commands.preprocess_size,
            max_sequence_count: commands.sequences,
            sequence_count_address: commands.count.unwrap_or(0),
            max_draw_count: 0,
        };
        // SAFETY: the caller guarantees the recording state; the info
        // outlives the call.
        unsafe { (self.cmd_execute)(buffer, vk::FALSE, &info) }
    }

    /// # Safety
    ///
    /// No pending submission uses the layout.
    pub(super) unsafe fn destroy_layout(&self, layout: u64) {
        // SAFETY: as the caller guarantees.
        unsafe { (self.destroy_layout)(self.device, layout, ptr::null()) }
    }

    /// # Safety
    ///
    /// No pending submission uses the set.
    pub(super) unsafe fn destroy_set(&self, set: u64) {
        // SAFETY: as the caller guarantees.
        unsafe { (self.destroy_set)(self.device, set, ptr::null()) }
    }
}

/// `VkIndirectCommandsTokenTypeEXT`.
fn token_type(token: IndirectToken) -> i32 {
    match token {
        IndirectToken::ExecutionSet(_) => 0,
        IndirectToken::PushConstants { .. } => 1,
        IndirectToken::IndexBuffer => 3,
        IndirectToken::VertexBuffer(_) => 4,
        IndirectToken::DrawIndexed => 5,
        IndirectToken::Draw => 6,
        IndirectToken::Dispatch => 9,
        IndirectToken::DrawMeshTasks => 1_000_328_000,
    }
}

/// The limits the snapshot reports when the device enables the feature.
pub(super) fn limits(properties: &Properties) -> GeneratedCommandsLimits {
    GeneratedCommandsLimits {
        max_pipelines: properties.max_indirect_pipeline_count,
        max_sequences: properties.max_indirect_sequence_count,
        max_tokens: properties.max_indirect_commands_token_count,
        max_token_offset: properties.max_indirect_commands_token_offset,
        max_stride: properties.max_indirect_commands_indirect_stride,
        pipeline_stages: ShaderStages::from_bits(
            properties
                .supported_indirect_commands_shader_stages_pipeline_binding
                .as_raw()
                & ShaderStages::KNOWN.bits(),
        )
        .unwrap_or(ShaderStages::EMPTY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    /// The structures keep `vulkan_core.h`'s LP64 layouts.
    #[test]
    fn structures_match_the_c_declarations() {
        assert_eq!(size_of::<Features>(), 24);
        assert_eq!(size_of::<Properties>(), 64);
        assert_eq!(size_of::<MemoryRequirementsInfo>(), 40);
        assert_eq!(size_of::<ExecutionSetPipelineInfo>(), 32);
        assert_eq!(size_of::<ExecutionSetCreateInfo>(), 32);
        assert_eq!(size_of::<GeneratedCommandsInfo>(), 96);
        assert_eq!(offset_of!(GeneratedCommandsInfo, max_sequence_count), 72);
        assert_eq!(offset_of!(GeneratedCommandsInfo, max_draw_count), 88);
        assert_eq!(size_of::<WriteExecutionSetPipeline>(), 32);
        assert_eq!(size_of::<LayoutToken>(), 40);
        assert_eq!(size_of::<LayoutCreateInfo>(), 56);
        assert_eq!(size_of::<TokenData>(), 12);
    }

    #[test]
    fn tokens_take_their_vulkan_types() {
        let types = [
            IndirectToken::ExecutionSet(ShaderStages::VERTEX),
            IndirectToken::PushConstants { offset: 0, size: 4 },
            IndirectToken::IndexBuffer,
            IndirectToken::VertexBuffer(0),
            IndirectToken::DrawIndexed,
            IndirectToken::Draw,
            IndirectToken::Dispatch,
            IndirectToken::DrawMeshTasks,
        ]
        .map(token_type);
        assert_eq!(types, [0, 1, 3, 4, 5, 6, 9, 1_000_328_000]);
    }
}
