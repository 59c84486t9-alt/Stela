//! Compiled Metal functions and the interface pipelines need from them.
//!
//! The AIR compiler lowers one function at a time to NIR against the
//! [`binding`](super::binding) ABI and registers the NIR with the Vulkan
//! backend, which receives it as a [`ShaderCode`] handle. The [`Interface`]
//! is the compiler's reflection of the function: the slots it reads and
//! writes, its stage inputs and outputs, and the shader features it needs.
//! [`Provenance`] keeps the input's identity attached to every result.
use super::{
    abi::{
        DataType, FunctionType, TessellationControlPointIndexType, TessellationFactorStepFunction,
        TessellationPartitionMode, TextureType, Winding,
    },
    binding::TableSlot,
    capabilities::{
        MAX_BUFFER_BINDINGS, MAX_SAMPLER_BINDINGS, MAX_TEXTURE_BINDINGS, ShaderFeatures,
    },
    error::{Result, ensure},
    pixel_format::Numeric,
    vertex::{StageInputDescriptor, VertexDescriptor},
    vulkan::{ShaderStages, object::ShaderCode},
};
use alloc::{boxed::Box, string::String, vec::Vec};

raw_enum! {
    /// The Metal function types that become pipeline stages.
    pub enum Stage: u64 {
        Vertex = 1,
        Fragment = 2,
        Kernel = 3,
        Mesh = 7,
        Object = 8,
    }
}

impl Stage {
    pub fn from_function_type(function_type: FunctionType) -> Option<Self> {
        Self::from_raw(function_type.raw())
    }

    pub const fn vulkan(self) -> ShaderStages {
        match self {
            Self::Vertex => ShaderStages::VERTEX,
            Self::Fragment => ShaderStages::FRAGMENT,
            Self::Kernel => ShaderStages::COMPUTE,
            Self::Mesh => ShaderStages::MESH,
            Self::Object => ShaderStages::TASK,
        }
    }

    pub const fn table(self) -> TableSlot {
        match self {
            Self::Vertex | Self::Kernel | Self::Object => TableSlot::Primary,
            Self::Fragment => TableSlot::Fragment,
            Self::Mesh => TableSlot::Mesh,
        }
    }
}

option_set! {
    /// How a function uses a bound resource.
    pub struct Access: u8 {
        const READ = 0x1;
        const WRITE = 0x2;
        /// Filtered sampling through a sampler.
        const SAMPLE = 0x4;
        /// Atomic operations, which also read and write.
        const ATOMIC = 0x8;
    }
}

impl Access {
    pub const fn writes(self) -> bool {
        self.intersects(Self::WRITE.union(Self::ATOMIC))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferUse {
    pub index: u32,
    pub access: Access,
    /// The buffer is an argument buffer; its resources are made resident
    /// with `useResource` rather than through this slot.
    pub argument_buffer: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextureUse {
    pub index: u32,
    pub access: Access,
    pub texture_type: TextureType,
    /// The component type the function reads or writes; a texture bound
    /// here must have a format of the same class.
    pub numeric: NumericClass,
}

/// Shader-visible component classes: Metal `float`/`half` textures accept
/// float, unorm and snorm formats.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NumericClass {
    Float,
    Uint,
    Sint,
}

impl NumericClass {
    pub const fn of(numeric: Numeric) -> Self {
        match numeric {
            Numeric::Uint => Self::Uint,
            Numeric::Sint => Self::Sint,
            Numeric::Unorm | Numeric::Snorm | Numeric::Float => Self::Float,
        }
    }
}

/// A `threadgroup` pointer argument: its slot and the bytes it declares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadgroupUse {
    pub index: u32,
    pub declared_bytes: u64,
}

/// A `[[stage_in]]` attribute of a vertex function. A post-tessellation
/// vertex function's is each control point's (`patchControlPointData`) or
/// its patch's (`patchData`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributeUse {
    pub index: u32,
    pub numeric: NumericClass,
    pub components: u8,
    pub patch_control_point: bool,
}

/// A `[[color(n)]]` output of a fragment function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColorOutput {
    pub index: u32,
    pub numeric: NumericClass,
    /// `[[index(1)]]`: the second source of dual-source blending.
    pub dual_source: bool,
}

/// The scalar type of a varying's components.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Scalar {
    Float,
    Half,
    Int,
    Uint,
    Short,
    Ushort,
    Char,
    Uchar,
}

/// A varying a vertex or mesh function outputs, or a fragment function
/// reads, linked by its `[[user(name)]]` identifier.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Varying {
    pub identifier: String,
    pub scalar: Scalar,
    pub components: u8,
    /// Mesh primitive data, which is constant over its primitive. Fragment
    /// inputs take it from the output they link to.
    pub per_primitive: bool,
}

/// A function constant (`MTLFunctionConstant`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionConstant {
    pub name: String,
    pub data_type: DataType,
    pub index: u32,
    /// The function reads the constant without testing whether it is
    /// defined, so it needs a value.
    pub required: bool,
}

impl FunctionConstant {
    /// Whether `value` is laid out as the constant's type: its lanes packed,
    /// a three-lane vector optionally padded to four.
    pub fn accepts(&self, value: &[u8]) -> bool {
        let (bytes, lanes) = self.data_type.lanes();
        value.len() == bytes * lanes || (lanes == 3 && value.len() == bytes * 4)
    }
}

/// The domain a post-tessellation vertex function evaluates.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PatchDomain {
    Triangle,
    Quad,
}

impl PatchDomain {
    /// Bytes of one `MTL{Triangle,Quad}TessellationFactorsHalf` record:
    /// three or four edge factors and one or two inside factors.
    pub const fn factor_bytes(self) -> u64 {
        match self {
            Self::Triangle => 8,
            Self::Quad => 12,
        }
    }
}

/// `[[patch(domain, count)]]` of a post-tessellation vertex function.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Patch {
    pub domain: PatchDomain,
    /// Control points per patch, when the function declares them; draws
    /// must then pass the same count.
    pub control_points: Option<u32>,
}

/// Metal's limit on control points per patch.
pub const MAX_PATCH_CONTROL_POINTS: u32 = 32;

/// The compiler's reflection of one function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interface {
    pub stage: Stage,
    /// The function is a post-tessellation vertex function.
    pub patch: Option<Patch>,
    pub buffers: Vec<BufferUse>,
    pub textures: Vec<TextureUse>,
    pub samplers: Vec<u32>,
    pub threadgroup: Vec<ThreadgroupUse>,
    pub attributes: Vec<AttributeUse>,
    /// A vertex or mesh function's varying outputs, or a fragment
    /// function's varying inputs.
    pub varyings: Vec<Varying>,
    pub color_outputs: Vec<ColorOutput>,
    pub writes_depth: bool,
    pub writes_stencil: bool,
    pub writes_sample_mask: bool,
    pub discards: bool,
    /// `[[early_fragment_tests]]`.
    pub early_fragment_tests: bool,
    /// Bytes of `threadgroup` variables declared inside the function.
    pub static_threadgroup_bytes: u64,
    /// `[[max_total_threads_per_threadgroup]]`, when declared.
    pub max_total_threads: Option<u32>,
    /// The function reads `[[amplification_id]]`.
    pub amplification: bool,
    /// The function's module may set or copy an indirect command's
    /// barrier.
    pub command_barriers: bool,
    pub constants: Vec<FunctionConstant>,
    pub features: ShaderFeatures,
}

impl Interface {
    /// Checks that every slot fits the argument table and appears once.
    pub fn validate(&self) -> Result<()> {
        fn unique(indices: impl Iterator<Item = u32> + Clone, limit: u32) -> bool {
            indices.clone().all(|index| index < limit)
                && indices
                    .clone()
                    .enumerate()
                    .all(|(n, index)| indices.clone().skip(n + 1).all(|other| other != index))
        }
        ensure(
            unique(
                self.buffers.iter().map(|buffer| buffer.index),
                MAX_BUFFER_BINDINGS,
            ),
            "buffer slots",
        )?;
        ensure(
            unique(
                self.textures.iter().map(|texture| texture.index),
                MAX_TEXTURE_BINDINGS,
            ),
            "texture slots",
        )?;
        ensure(
            unique(self.samplers.iter().copied(), MAX_SAMPLER_BINDINGS),
            "sampler slots",
        )?;
        ensure(
            unique(
                self.threadgroup.iter().map(|threadgroup| threadgroup.index),
                MAX_BUFFER_BINDINGS,
            ),
            "threadgroup slots",
        )?;
        let fragment_only = !self.color_outputs.is_empty() || self.writes_depth || self.discards;
        ensure(
            !fragment_only || self.stage == Stage::Fragment,
            "fragment outputs outside a fragment function",
        )?;
        ensure(
            self.attributes.is_empty() || matches!(self.stage, Stage::Vertex | Stage::Kernel),
            "stage-in outside a vertex or kernel function",
        )?;
        ensure(
            self.varyings.is_empty()
                || matches!(self.stage, Stage::Vertex | Stage::Fragment | Stage::Mesh),
            "varyings outside a vertex, mesh or fragment function",
        )?;
        ensure(
            self.varyings.iter().enumerate().all(|(n, varying)| {
                (1..=4).contains(&varying.components)
                    && (!varying.per_primitive || self.stage == Stage::Mesh)
                    && self.varyings[n + 1..]
                        .iter()
                        .all(|other| other.identifier != varying.identifier)
            }),
            "varyings",
        )?;
        validate_constants(&self.constants)?;
        if let Some(patch) = self.patch {
            ensure(
                self.stage == Stage::Vertex,
                "patch functions are vertex functions",
            )?;
            ensure(
                patch
                    .control_points
                    .is_none_or(|count| (1..=MAX_PATCH_CONTROL_POINTS).contains(&count)),
                "patch control point count",
            )?;
        }
        ensure(
            self.threadgroup.is_empty()
                || matches!(self.stage, Stage::Kernel | Stage::Object | Stage::Mesh),
            "threadgroup arguments outside a compute-like function",
        )
    }

    pub fn color_output(&self, index: u32) -> Option<&ColorOutput> {
        self.color_outputs
            .iter()
            .find(|output| output.index == index && !output.dual_source)
    }

    pub fn uses_dual_source(&self) -> bool {
        self.color_outputs.iter().any(|output| output.dual_source)
    }
}

/// Checks that each constant has its own index and name.
fn validate_constants(constants: &[FunctionConstant]) -> Result<()> {
    ensure(
        constants.iter().enumerate().all(|(n, constant)| {
            constants[n + 1..]
                .iter()
                .all(|other| other.index != constant.index && other.name != constant.name)
        }),
        "function constants",
    )
}

/// The compiler's reflection of a library function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reflection {
    /// A function that becomes a pipeline stage.
    Stage(Box<Interface>),
    /// A `[[visible]]` function, with its module's function constants:
    /// pipelines link it into their stages, which call it directly or
    /// through visible function tables.
    Visible {
        constants: Vec<FunctionConstant>,
        /// As [`Interface::command_barriers`].
        command_barriers: bool,
    },
}

impl Reflection {
    pub fn function_type(&self) -> FunctionType {
        match self {
            Self::Stage(interface) => {
                FunctionType::from_raw(interface.stage.raw()).expect("stages are function types")
            }
            Self::Visible { .. } => FunctionType::Visible,
        }
    }

    pub fn constants(&self) -> &[FunctionConstant] {
        match self {
            Self::Stage(interface) => &interface.constants,
            Self::Visible { constants, .. } => constants,
        }
    }

    /// Whether the function's module may set or copy an indirect command's
    /// barrier.
    pub fn command_barriers(&self) -> bool {
        match self {
            Self::Stage(interface) => interface.command_barriers,
            Self::Visible {
                command_barriers, ..
            } => *command_barriers,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Stage(interface) => interface.validate(),
            Self::Visible { constants, .. } => validate_constants(constants),
        }
    }
}

/// Where a compiled function came from. The compiler fills it from the
/// library's records; it travels with the shader into pipelines and their
/// diagnostics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Provenance {
    /// The library's LLVM build identity.
    pub build_id: Vec<u8>,
    /// SHA-256 of the function's AIR module.
    pub slice_hash: [u8; 32],
    /// The library's source-map section, when present.
    pub source_map: Option<Vec<u8>>,
    pub entry: String,
}

/// A function compiled for a pipeline stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledShader {
    pub code: ShaderCode,
    pub interface: Interface,
    pub provenance: Provenance,
}

/// Facts a compilation is specialized on beyond the function itself.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Specialization {
    /// `MTLFunctionConstantValues`, as (constant index, value bytes).
    pub constants: Vec<(u32, Vec<u8>)>,
    /// Threads per threadgroup of a kernel, object or mesh function.
    pub workgroup_size: Option<[u32; 3]>,
    /// `setThreadgroupMemoryLength:atIndex:` lengths, as (index, bytes).
    pub threadgroup_lengths: Vec<(u32, u64)>,
    /// A kernel's stage-in layout. The region it is fetched over is the
    /// push constants' `arguments`.
    pub stage_in: Option<StageInputDescriptor>,
    /// A vertex function of a pipeline that amplifies vertices: it adds the
    /// push constants' `view_mapping` offsets to the render target array and
    /// viewport indices it writes.
    pub amplified: bool,
    /// A render pipeline's linked varyings, its vertex or mesh function's
    /// outputs; each takes the location of its position, and a fragment
    /// input takes its output's rate.
    pub varyings: Vec<Varying>,
    /// The object function of a mesh pipeline, or its mesh function when it
    /// has none: the stage mesh draws launch, whose threads outside a
    /// `drawMeshThreads` grid skip the function.
    pub launched_by_grid: bool,
    /// A kernel of indirect commands, whose dispatches each shape its
    /// threadgroups and place its threadgroup buffers through their
    /// [`DispatchArguments`]: its `workgroup_size` is `[n, 1, 1]` for the
    /// most threads a threadgroup holds, and it takes no
    /// `threadgroup_lengths`.
    ///
    /// [`DispatchArguments`]: super::binding::DispatchArguments
    pub dynamic_threadgroups: bool,
    /// The functions and libraries the stage links.
    pub linking: Linking,
    /// The sampler of each constexpr sampler state the function and its
    /// linking declare ([`Compiler::sampler_states`]), as (state,
    /// `gpuResourceID`).
    pub samplers: Vec<(u64, u64)>,
}

/// What a pipeline stage links into its function (`MTLLinkedFunctions` and
/// `preloadedLibraries`): visible functions and dynamic libraries. Calls of
/// external functions resolve to any of them.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Linking {
    /// The functions visible function tables call: handle `i + 1` calls
    /// the `i`-th, and handle zero none.
    pub functions: Vec<LinkedFunction>,
    /// Functions only external calls reach (`privateFunctions`).
    pub private_functions: Vec<LinkedFunction>,
    pub libraries: Vec<u64>,
    /// The stage's `maxCallStackDepth`: recursion through function tables
    /// unrolls to this many nested calls, and a call nested deeper calls
    /// none.
    pub max_call_stack_depth: u32,
}

impl Default for Linking {
    fn default() -> Self {
        Self {
            functions: Vec::new(),
            private_functions: Vec::new(),
            libraries: Vec::new(),
            max_call_stack_depth: 1,
        }
    }
}

/// A visible function a stage links: its library, its entry and its
/// function constant values by index, in index order, with which its
/// module compiles.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct LinkedFunction {
    pub library: u64,
    pub entry: String,
    pub constants: Vec<(u32, Vec<u8>)>,
}

impl Linking {
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty() && self.private_functions.is_empty() && self.libraries.is_empty()
    }
}

/// What a post-tessellation vertex function compiles against: its
/// pipeline's tessellation properties and the stage-in layout it fetches.
///
/// Vulkan's tessellator takes its factors from a control stage, so the
/// compiler synthesizes the stages ahead of the function. Each patch is one
/// single-point patch-list vertex: `vertexCount` patches from `firstVertex`,
/// which is the first patch number, as in `MTLDrawPatchIndirectArguments`.
/// The synthesized vertex stage passes the vertex and instance index on; the
/// control stage maps the patch number through the patch index buffer, reads
/// the factors at the [`TessellationArguments`] the push constants name,
/// applies the scale, the step function and the partition's rounding, and
/// emits the patch's factors with the patch ID and instance index
/// (`compiler/metal_abi.h` builds both stages). The function itself becomes
/// the evaluation stage, which fetches control points and per-patch stage-in
/// from the argument table's buffers through the control point index buffer,
/// so the pipeline has no fixed-function vertex input.
///
/// [`TessellationArguments`]: super::binding::TessellationArguments
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Tessellation {
    pub patch: Patch,
    pub partition: TessellationPartitionMode,
    /// Factors are clamped to this (even) value before partitioning.
    pub max_factor: u32,
    /// Factors are multiplied by the encoder's scale before clamping.
    pub factor_scale: bool,
    pub step_function: TessellationFactorStepFunction,
    pub control_point_index: TessellationControlPointIndexType,
    /// The winding of the triangles the tessellator emits.
    pub winding: Winding,
    /// The function's stage-in layout, fetched by the evaluation stage.
    pub vertex_descriptor: Option<VertexDescriptor>,
}

/// The Vulkan stages of a tessellated pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TessellationStages {
    /// The synthesized vertex stage.
    pub vertex: ShaderCode,
    /// The synthesized control stage.
    pub control: ShaderCode,
    /// The post-tessellation vertex function.
    pub evaluation: CompiledShader,
}

/// The compiler as the device sees it.
pub trait Compiler {
    /// Shader constructs this compiler lowers completely.
    fn features(&self) -> ShaderFeatures;

    /// Keeps `data`, a Metal library, until [`remove_library`]; the id it
    /// returns names the library to the other calls and is never reused.
    ///
    /// [`remove_library`]: Self::remove_library
    fn add_library(&mut self, data: Vec<u8>) -> Result<u64>;

    /// Forgets a library; its functions can no longer compile.
    fn remove_library(&mut self, library: u64) -> Result<()>;

    /// Reflects `entry` of `library` without compiling it.
    fn reflect(
        &mut self,
        library: u64,
        entry: &str,
        specialization: &Specialization,
    ) -> Result<Reflection>;

    /// The constexpr sampler states of `entry` of `library` and of the
    /// functions and libraries `specialization` links, each once, which
    /// [`SamplerDescriptor::from_constexpr`] decodes. Compiling the function
    /// takes their samplers.
    ///
    /// [`SamplerDescriptor::from_constexpr`]: super::sampler::SamplerDescriptor::from_constexpr
    fn sampler_states(
        &mut self,
        library: u64,
        entry: &str,
        specialization: &Specialization,
    ) -> Result<Vec<u64>>;

    /// Compiles `entry` of `library`, registering its NIR with the backend.
    fn compile(
        &mut self,
        library: u64,
        entry: &str,
        specialization: &Specialization,
    ) -> Result<CompiledShader>;

    /// Compiles the post-tessellation vertex function `entry` of `library`
    /// with the stages that feed it.
    fn compile_tessellation(
        &mut self,
        library: u64,
        entry: &str,
        specialization: &Specialization,
        tessellation: &Tessellation,
    ) -> Result<TessellationStages>;

    /// Releases a compiled function's NIR.
    fn release(&mut self, code: ShaderCode);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::gpu::metal::error::Error;

    pub(crate) fn interface(stage: Stage) -> Interface {
        Interface {
            stage,
            patch: None,
            buffers: Vec::new(),
            textures: Vec::new(),
            samplers: Vec::new(),
            threadgroup: Vec::new(),
            attributes: Vec::new(),
            varyings: Vec::new(),
            color_outputs: Vec::new(),
            writes_depth: false,
            writes_stencil: false,
            writes_sample_mask: false,
            discards: false,
            early_fragment_tests: false,
            static_threadgroup_bytes: 0,
            max_total_threads: None,
            amplification: false,
            command_barriers: false,
            constants: Vec::new(),
            features: ShaderFeatures::EMPTY,
        }
    }

    #[test]
    fn function_constant_values_take_their_type_s_layout() {
        let constant = |data_type| FunctionConstant {
            name: String::from("c"),
            data_type,
            index: 0,
            required: false,
        };
        assert!(constant(DataType::Bool).accepts(&[1]));
        assert!(constant(DataType::Half2).accepts(&[0; 4]));
        assert!(!constant(DataType::Half2).accepts(&[0; 2]));
        for bytes in [12, 16] {
            assert!(constant(DataType::Float3).accepts(&alloc::vec![0; bytes]));
        }
        assert!(!constant(DataType::Float4).accepts(&[0; 12]));
        assert!(constant(DataType::ULong).accepts(&[0; 8]));
        assert_eq!(DataType::vector(DataType::Char, 3), Some(DataType::Char3));
        assert_eq!(DataType::vector(DataType::Char, 5), None);
    }

    #[test]
    fn varyings_are_validated() {
        let varying = |identifier: &str, per_primitive| Varying {
            identifier: String::from(identifier),
            scalar: Scalar::Float,
            components: 4,
            per_primitive,
        };
        let mut mesh = interface(Stage::Mesh);
        mesh.varyings = alloc::vec![varying("user(a)", false), varying("user(b)", true)];
        assert_eq!(mesh.validate(), Ok(()));
        mesh.varyings[1].identifier = String::from("user(a)");
        assert_eq!(mesh.validate(), Err(Error::Invalid("varyings")));
        mesh.varyings[1].components = 0;
        mesh.varyings[1].identifier = String::from("user(b)");
        assert_eq!(mesh.validate(), Err(Error::Invalid("varyings")));

        let mut vertex = interface(Stage::Vertex);
        vertex.varyings = alloc::vec![varying("user(a)", true)];
        assert_eq!(vertex.validate(), Err(Error::Invalid("varyings")));
        let mut kernel = interface(Stage::Kernel);
        kernel.varyings = alloc::vec![varying("user(a)", false)];
        assert!(kernel.validate().is_err());
    }

    #[test]
    fn stages_map_to_vulkan_and_tables() {
        assert_eq!(
            Stage::from_function_type(FunctionType::Object),
            Some(Stage::Object)
        );
        assert_eq!(Stage::from_function_type(FunctionType::Visible), None);
        assert_eq!(Stage::Object.vulkan(), ShaderStages::TASK);
        assert_eq!(Stage::Fragment.table(), TableSlot::Fragment);
        assert_eq!(Stage::Kernel.table(), TableSlot::Primary);
    }

    #[test]
    fn interfaces_are_validated() {
        let mut kernel = interface(Stage::Kernel);
        kernel.buffers = alloc::vec![
            BufferUse {
                index: 0,
                access: Access::READ,
                argument_buffer: false
            },
            BufferUse {
                index: 30,
                access: Access::WRITE,
                argument_buffer: false
            },
        ];
        kernel.threadgroup = alloc::vec![ThreadgroupUse {
            index: 0,
            declared_bytes: 64
        }];
        assert_eq!(kernel.validate(), Ok(()));

        kernel.buffers[1].index = 0;
        assert_eq!(kernel.validate(), Err(Error::Invalid("buffer slots")));
        kernel.buffers[1].index = 31;
        assert_eq!(kernel.validate(), Err(Error::Invalid("buffer slots")));

        let mut vertex = interface(Stage::Vertex);
        vertex.color_outputs = alloc::vec![ColorOutput {
            index: 0,
            numeric: NumericClass::Float,
            dual_source: false
        }];
        assert!(vertex.validate().is_err());
        let mut fragment = interface(Stage::Fragment);
        fragment.threadgroup = alloc::vec![ThreadgroupUse {
            index: 0,
            declared_bytes: 4
        }];
        assert!(fragment.validate().is_err());
    }

    #[test]
    fn atomics_write() {
        assert!(Access::ATOMIC.writes() && Access::WRITE.writes());
        assert!(!(Access::READ | Access::SAMPLE).writes());
        assert_eq!(NumericClass::of(Numeric::Unorm), NumericClass::Float);
    }
}
