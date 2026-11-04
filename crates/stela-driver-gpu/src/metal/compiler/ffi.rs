//! The layouts of `compiler/metal_compiler.h`, which the service fills and
//! reads. Its `STELA_METAL_*_BYTES` sizes are checked against these.
use super::super::capabilities::{MAX_BUFFER_BINDINGS, MAX_SAMPLER_BINDINGS, MAX_TEXTURE_BINDINGS};
use alloc::string::String;
use core::ffi::{c_char, c_void};

/// `stela_metal_visit_function`, whose last argument is a function type.
pub(super) type VisitFunction =
    unsafe extern "C" fn(*mut c_void, *const c_char, usize, u32) -> bool;

pub(super) const ATTRIBUTES: usize = 31;
pub(super) const VARYINGS: usize = 32;
pub(super) const COLOR_OUTPUTS: usize = 9;
pub(super) const FUNCTION_CONSTANTS: usize = 256;
pub(super) const NAME_BYTES: usize = 8192;
pub(super) const SAMPLER_STATES: usize = 256;
pub(super) const BINDINGS: usize = 128;
pub(super) const MEMBERS: usize = 1024;
pub(super) const BINDING_NAME_BYTES: usize = 32768;

/// `enum stela_air_error_kind`.
pub(super) mod kind {
    pub const OK: u32 = 0;
    pub const INPUT: u32 = 1;
    pub const LLVM_VERSION: u32 = 2;
    pub const BITCODE: u32 = 3;
    pub const VERIFY: u32 = 4;
    pub const TARGET: u32 = 5;
    pub const METADATA: u32 = 6;
    pub const ARGUMENT: u32 = 7;
    pub const CONTROL_FLOW: u32 = 8;
    pub const INSTRUCTION: u32 = 9;
    pub const TYPE: u32 = 10;
    pub const MEMORY: u32 = 11;
    pub const LIMIT: u32 = 12;
    pub const ALLOCATION: u32 = 13;
}

/// `enum stela_air_primitive`.
pub(super) mod primitive {
    pub const CHAR: u32 = 1;
    pub const UCHAR: u32 = 2;
    pub const SHORT: u32 = 3;
    pub const USHORT: u32 = 4;
    pub const INT: u32 = 5;
    pub const UINT: u32 = 6;
    pub const FLOAT: u32 = 9;
    pub const HALF: u32 = 10;
}

/// `struct stela_air_error`.
#[repr(C)]
pub struct AirError {
    pub(super) kind: u32,
    pub(super) instruction: u32,
    pub(super) detail: [u8; 256],
}

impl AirError {
    pub(super) const NONE: Self = Self {
        kind: kind::OK,
        instruction: 0,
        detail: [0; 256],
    };

    /// The detail up to its terminator.
    pub(super) fn detail(&self) -> String {
        let end = self.detail.iter().position(|byte| *byte == 0);
        String::from_utf8_lossy(&self.detail[..end.unwrap_or(self.detail.len())]).into_owned()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct BufferUse {
    pub index: u32,
    pub access: u32,
    pub argument_buffer: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct TextureUse {
    pub index: u32,
    pub access: u32,
    pub texture_type: u32,
    pub primitive: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ThreadgroupUse {
    pub index: u32,
    pub bytes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct AttributeUse {
    pub index: u32,
    pub primitive: u32,
    pub components: u32,
    pub patch_control_point: u32,
    pub active: u32,
    pub name: u32,
    pub name_bytes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Varying {
    pub identifier: u32,
    pub identifier_bytes: u32,
    pub primitive: u32,
    pub components: u32,
    pub per_primitive: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ColorOutput {
    pub index: u32,
    pub primitive: u32,
    pub dual_source: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct FunctionConstant {
    pub index: u32,
    pub name: u32,
    pub name_bytes: u32,
    pub type_name: u32,
    pub type_bytes: u32,
    pub required: u32,
}

/// `struct stela_metal_reflection`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Reflection {
    pub(super) stage: u32,
    pub(super) max_total_threads: u32,
    pub(super) threadgroup_bytes: u64,
    pub(super) buffer_count: u32,
    pub(super) texture_count: u32,
    pub(super) sampler_count: u32,
    pub(super) threadgroup_count: u32,
    pub(super) attribute_count: u32,
    pub(super) varying_count: u32,
    pub(super) color_output_count: u32,
    pub(super) writes_depth: u32,
    pub(super) writes_stencil: u32,
    pub(super) writes_sample_mask: u32,
    pub(super) discards: u32,
    pub(super) amplification: u32,
    pub(super) ident: u32,
    pub(super) ident_bytes: u32,
    pub(super) names_bytes: u32,
    pub(super) function_constant_count: u32,
    /// `enum stela_air_patch`.
    pub(super) patch: u32,
    pub(super) patch_control_points: u32,
    pub(super) barycentrics: u32,
    pub(super) interpolants: u32,
    pub(super) function_tables: u32,
    pub(super) commands: u32,
    pub(super) command_barriers: u32,
    pub(super) attachment_reads: u32,
    pub(super) buffers: [BufferUse; MAX_BUFFER_BINDINGS as usize],
    pub(super) textures: [TextureUse; MAX_TEXTURE_BINDINGS as usize],
    pub(super) samplers: [u32; MAX_SAMPLER_BINDINGS as usize],
    pub(super) threadgroup: [ThreadgroupUse; MAX_BUFFER_BINDINGS as usize],
    pub(super) attributes: [AttributeUse; ATTRIBUTES],
    pub(super) varyings: [Varying; VARYINGS],
    pub(super) color_outputs: [ColorOutput; COLOR_OUTPUTS],
    pub(super) function_constants: [FunctionConstant; FUNCTION_CONSTANTS],
    pub(super) names: [u8; NAME_BYTES],
}

impl Reflection {
    #[cfg(test)]
    // SAFETY: every member is an integer or an array of integers.
    pub(super) const ZERO: Self = unsafe { core::mem::zeroed() };

    pub(super) fn zeroed() -> alloc::boxed::Box<Self> {
        // SAFETY: every member is an integer or an array of integers.
        unsafe { alloc::boxed::Box::new_zeroed().assume_init() }
    }
}

/// `enum stela_metal_binding_kind`.
pub(super) mod binding {
    pub const BUFFER: u32 = 0;
    pub const THREADGROUP: u32 = 1;
    pub const TEXTURE: u32 = 2;
    pub const SAMPLER: u32 = 3;
    pub const FUNCTION_TABLE: u32 = 4;
    pub const OBJECT_PAYLOAD: u32 = 5;
}

/// `enum stela_air_field_kind`.
pub(super) mod field {
    pub const DATA: u32 = 0;
    pub const BUFFER: u32 = 1;
    pub const ARGUMENTS: u32 = 2;
    pub const TEXTURE: u32 = 3;
    pub const SAMPLER: u32 = 4;
    pub const COMMANDS: u32 = 5;
    pub const RENDER_PIPELINE: u32 = 6;
    pub const COMPUTE_PIPELINE: u32 = 7;
}

/// `struct stela_metal_binding`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct Binding {
    pub kind: u32,
    pub index: u32,
    pub count: u32,
    pub access: u32,
    pub used: u32,
    pub argument_buffer: u32,
    pub name: u32,
    pub name_bytes: u32,
    pub type_name: u32,
    pub type_bytes: u32,
    pub size: u32,
    pub alignment: u32,
    pub texture_type: u32,
    pub primitive: u32,
    pub depth: u32,
    pub members: u32,
    pub member_count: u32,
}

/// `struct stela_metal_member`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct Member {
    pub offset: u32,
    pub size: u32,
    pub elements: u32,
    pub count: u32,
    pub name: u32,
    pub name_bytes: u32,
    pub type_name: u32,
    pub type_bytes: u32,
    pub members: u32,
    pub member_count: u32,
    pub argument: u32,
    pub kind: u32,
    pub id: u32,
    pub access: u32,
    pub size_pointed: u32,
    pub alignment_pointed: u32,
    pub texture_type: u32,
    pub primitive: u32,
    pub depth: u32,
}

/// `struct stela_metal_bindings`.
#[repr(C)]
pub struct Bindings {
    pub(super) binding_count: u32,
    pub(super) member_count: u32,
    pub(super) names_bytes: u32,
    pub(super) bindings: [Binding; BINDINGS],
    pub(super) members: [Member; MEMBERS],
    pub(super) names: [u8; BINDING_NAME_BYTES],
}

impl Bindings {
    /// Empty bindings, made in place: they are too large for a stack.
    pub(super) fn zeroed() -> alloc::boxed::Box<Self> {
        // SAFETY: every member is an integer or an array of integers.
        unsafe { alloc::boxed::Box::new_zeroed().assume_init() }
    }
}

/// `struct stela_metal_target`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Target {
    pub(super) nir: *const c_void,
    pub(super) max_instructions: u32,
    pub(super) max_threadgroup_bytes: u32,
    pub(super) max_private_bytes: u32,
    pub(super) max_constant_bytes: u32,
    pub(super) max_varying_slots: u32,
    pub(super) max_payload_bytes: u32,
    pub(super) max_mesh_vertices: u32,
    pub(super) max_mesh_primitives: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct ThreadgroupLength {
    pub index: u32,
    pub bytes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct LinkedVarying {
    pub identifier: *const c_char,
    pub identifier_bytes: usize,
    pub per_primitive: u32,
}

/// `struct stela_air_constant_value`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConstantValue {
    pub index: u32,
    pub bytes: *const c_void,
    pub size: usize,
}

/// `struct stela_air_module`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct Module {
    pub bitcode: *const c_void,
    pub size: usize,
    /// Null for a module without values.
    pub constants: *const ConstantValue,
    pub constant_count: u32,
}

/// `stela_air_stitch_source`.
#[repr(C)]
pub struct StitchSource {
    pub(super) bitcode: *const c_void,
    pub(super) size: usize,
    pub(super) name: *const c_char,
}

/// `stela_air_stitch_node`.
#[repr(C)]
pub struct StitchNode {
    pub(super) function: u32,
    pub(super) input: u32,
    pub(super) arguments: *const u32,
    pub(super) argument_count: u32,
}

/// `stela_air_stitch_graph`.
#[repr(C)]
pub struct StitchGraph {
    pub(super) name: *const c_char,
    pub(super) nodes: *const StitchNode,
    pub(super) node_count: u32,
    pub(super) output: u32,
}

/// `stela_air_visit_bytes`.
pub(super) type VisitBytes = unsafe extern "C" fn(*mut c_void, *const c_void, usize);

/// `struct stela_air_linked_function`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct LinkedFunction {
    pub name: *const c_char,
    pub name_bytes: usize,
}

/// `struct stela_air_constexpr_sampler`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct ConstexprSampler {
    pub state: u64,
    pub id: u64,
}

/// `struct stela_metal_specialization`.
#[repr(C)]
#[derive(Debug)]
pub struct Specialization {
    pub(super) workgroup_size: [u32; 3],
    pub(super) threadgroup_length_count: u32,
    pub(super) threadgroup_lengths: *const ThreadgroupLength,
    pub(super) varyings: *const LinkedVarying,
    pub(super) varying_count: u32,
    pub(super) amplified: u32,
    pub(super) launched_by_grid: u32,
    pub(super) dynamic_threadgroups: u32,
    pub(super) constant_count: u32,
    pub(super) constants: *const ConstantValue,
    pub(super) tessellation: *const Tessellation,
    pub(super) stage_in: *const StageIn,
    pub(super) modules: *const Module,
    pub(super) linked_functions: *const LinkedFunction,
    pub(super) module_count: u32,
    pub(super) linked_function_count: u32,
    pub(super) max_call_stack_depth: u32,
    pub(super) sampler_count: u32,
    pub(super) samplers: *const ConstexprSampler,
}

/// `struct stela_metal_tessellation`: the raw values of the pipeline's
/// partition, factor step function and winding.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tessellation {
    pub(super) quad: bool,
    pub(super) partition: u32,
    pub(super) max_factor: u32,
    pub(super) step: u32,
    pub(super) winding: u32,
    pub(super) control_point_index_bytes: u32,
}

/// `struct stela_metal_stage_in_attribute`; a zero format is absent.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct StageInAttribute {
    pub format: u32,
    pub offset: u32,
    pub buffer: u32,
}

/// `struct stela_metal_stage_in_layout`, with the raw `MTLStepFunction`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct StageInLayout {
    pub stride: u32,
    pub step: u32,
    pub rate: u32,
}

/// `STELA_METAL_STRIDE_DYNAMIC`.
pub(super) const STRIDE_DYNAMIC: u32 = u32::MAX;

/// `struct stela_metal_stage_in`, with the bytes and buffer of a kernel's
/// indices.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct StageIn {
    pub(super) attributes: [StageInAttribute; ATTRIBUTES],
    pub(super) layouts: [StageInLayout; MAX_BUFFER_BINDINGS as usize],
    pub(super) index_bytes: u32,
    pub(super) index_buffer: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn layouts_match_the_service_header() {
        let header = include_str!("../../compiler/metal_compiler.h");
        let define = |name: &str| -> usize {
            header
                .lines()
                .find_map(|line| {
                    let value = line.strip_prefix("#define ")?.strip_prefix(name)?;
                    value.strip_prefix(' ')?.strip_suffix('u')?.parse().ok()
                })
                .unwrap_or_else(|| panic!("metal_compiler.h does not define {name}"))
        };
        let expected = [
            ("STELA_METAL_ATTRIBUTES", ATTRIBUTES),
            ("STELA_METAL_VARYINGS", VARYINGS),
            ("STELA_METAL_COLOR_OUTPUTS", COLOR_OUTPUTS),
            ("STELA_METAL_FUNCTION_CONSTANTS", FUNCTION_CONSTANTS),
            ("STELA_METAL_NAME_BYTES", NAME_BYTES),
            ("STELA_METAL_SAMPLER_STATES", SAMPLER_STATES),
            ("STELA_METAL_BINDINGS", BINDINGS),
            ("STELA_METAL_MEMBERS", MEMBERS),
            ("STELA_METAL_BINDING_NAME_BYTES", BINDING_NAME_BYTES),
            ("STELA_METAL_BINDINGS_BYTES", size_of::<Bindings>()),
            ("STELA_METAL_REFLECTION_BYTES", size_of::<Reflection>()),
            ("STELA_METAL_TARGET_BYTES", size_of::<Target>()),
            (
                "STELA_METAL_LINKED_VARYING_BYTES",
                size_of::<LinkedVarying>(),
            ),
            (
                "STELA_METAL_SPECIALIZATION_BYTES",
                size_of::<Specialization>(),
            ),
            (
                "STELA_METAL_CONSTANT_VALUE_BYTES",
                size_of::<ConstantValue>(),
            ),
            (
                "STELA_METAL_PIPELINE_TESSELLATION_BYTES",
                size_of::<Tessellation>(),
            ),
            ("STELA_METAL_STAGE_IN_BYTES", size_of::<StageIn>()),
            ("STELA_METAL_MODULE_BYTES", size_of::<Module>()),
            (
                "STELA_METAL_LINKED_FUNCTION_BYTES",
                size_of::<LinkedFunction>(),
            ),
            (
                "STELA_METAL_CONSTEXPR_SAMPLER_BYTES",
                size_of::<ConstexprSampler>(),
            ),
        ];
        for (name, value) in expected {
            assert_eq!(define(name), value, "{name}");
        }
    }
}
