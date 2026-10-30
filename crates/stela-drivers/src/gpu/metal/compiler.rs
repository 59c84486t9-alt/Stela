//! [`Compiler`] over the AIR compiler service, `compiler/metal_compiler.h`.
//!
//! The platform links the service with LLVM and Mesa and supplies its entry
//! points with the Vulkan driver's NIR options. The compiler keeps each
//! library it is given as the original MTLB bytes; reflecting or compiling a
//! function selects it by name and checks its AIR against the library's
//! digest first. A function's [`Interface`] is the service's reflection, and
//! its [`Provenance`] is that digest with the module's `llvm.ident`.
//!
//! The service refuses AIR it does not lower with a typed kind and a detail:
//! the call fails with `Error::Unsupported` naming the kind, and
//! [`AirCompiler::refusal`] keeps the detail for the frontend's `NSError`.
//! Kernel stage-in has no AIR form the frontend lowers, so it is refused
//! before it runs. A post-tessellation vertex function compiles with its
//! pipeline's tessellation and stage-in layout into the evaluation stage,
//! and the service synthesizes the stages ahead of it.
//!
//! A stage's [`Linking`] reaches the service as the AIR modules of its
//! functions, with their function constant values, and of every function
//! of its dynamic libraries, without, each module once and none that is the
//! function's own, with the names of the functions visible function tables
//! call.
pub mod ffi;
#[cfg(test)]
mod tests;

use super::{
    abi::{DataType, FunctionType, IndexType, TessellationControlPointIndexType, TextureType},
    capabilities::ShaderFeatures,
    error::{Error, Result, ensure, require},
    library::{Air, Header, Library},
    shader::{
        Access, AttributeUse, BufferUse, ColorOutput, CompiledShader, Compiler, DeclaredAttribute,
        FunctionConstant, Interface, Linking, MAX_PATCH_CONTROL_POINTS, NumericClass, Patch,
        PatchDomain, Provenance, Reflection, Scalar, Specialization, Stage, Tessellation,
        TessellationStages, TextureUse, ThreadgroupUse, Varying,
    },
    vertex::{Attribute, STRIDE_DYNAMIC, StageInputDescriptor, VertexDescriptor},
    vulkan::{object::ShaderCode, physical::PhysicalDevice},
};
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    ffi::CString,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    ffi::{c_char, c_void},
    ptr::{self, NonNull},
    str,
};

/// The constructs the AIR frontend lowers completely (`metal/README.md`).
const FEATURES: ShaderFeatures = ShaderFeatures::COMPUTE
    .union(ShaderFeatures::VERTEX_FRAGMENT)
    .union(ShaderFeatures::MESH)
    .union(ShaderFeatures::TEXTURE_SAMPLE)
    .union(ShaderFeatures::TEXTURE_READ_WRITE)
    .union(ShaderFeatures::TEXTURE_ATOMICS)
    .union(ShaderFeatures::DEPTH_COMPARE_SAMPLE)
    .union(ShaderFeatures::QUERY_LOD)
    .union(ShaderFeatures::BUFFER_ATOMICS)
    .union(ShaderFeatures::THREADGROUP_MEMORY)
    .union(ShaderFeatures::SIMDGROUP)
    .union(ShaderFeatures::QUADGROUP)
    .union(ShaderFeatures::ARGUMENT_BUFFERS)
    .union(ShaderFeatures::INDIRECT_COMMAND_ENCODING)
    .union(ShaderFeatures::LAYERED_RENDERING)
    .union(ShaderFeatures::VERTEX_AMPLIFICATION)
    .union(ShaderFeatures::TESSELLATION)
    .union(ShaderFeatures::BARYCENTRICS)
    .union(ShaderFeatures::PULL_MODEL_INTERPOLATION)
    .union(ShaderFeatures::SPARSE_FEEDBACK)
    .union(ShaderFeatures::FUNCTION_POINTERS)
    .union(ShaderFeatures::DYNAMIC_LIBRARIES);

/// LLVM instructions one compilation may lower, legalization included. Far
/// beyond the functions Metal compiles, it bounds the work of hostile input.
const MAX_INSTRUCTIONS: u32 = 1 << 20;
/// NVIDIA's local memory per thread, where thread memory lowers to.
const MAX_PRIVATE_BYTES: u32 = 512 << 10;

/// The reflection does not describe a function the frontend lowers.
const MALFORMED: Error = Error::Invalid("the compiler's reflection");

/// The service's entry points and the NIR options it compiles with.
#[derive(Clone, Copy, Debug)]
pub struct Service {
    /// `stela_metal_reflect`.
    pub reflect: unsafe extern "C" fn(
        *const c_void,
        usize,
        *const c_char,
        *const ffi::ConstantValue,
        u32,
        *mut ffi::Reflection,
        *mut ffi::AirError,
    ) -> bool,
    /// `stela_metal_sampler_states`.
    pub sampler_states:
        unsafe extern "C" fn(*const c_void, usize, *mut u64, *mut u32, *mut ffi::AirError) -> bool,
    /// `stela_metal_compile`.
    pub compile: unsafe extern "C" fn(
        *const c_void,
        usize,
        *const c_char,
        *const ffi::Target,
        *const ffi::Specialization,
        *mut ffi::AirError,
    ) -> *mut c_void,
    /// `stela_metal_tessellation_stages`.
    pub tessellation_stages:
        unsafe extern "C" fn(*const ffi::Target, *const ffi::Tessellation, *mut *mut c_void),
    /// `stela_metal_release`.
    pub release: unsafe extern "C" fn(*mut c_void),
    /// The Vulkan driver's `nir_shader_compiler_options`.
    pub nir_options: NonNull<c_void>,
}

/// The service's account of its last refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Refusal {
    pub entry: String,
    /// The zero-based ordinal of the AIR instruction at fault.
    pub instruction: u32,
    pub detail: String,
}

pub struct AirCompiler {
    service: Service,
    target: ffi::Target,
    /// MTLB libraries by id; ids are never reused.
    libraries: BTreeMap<u64, Vec<u8>>,
    next_library: u64,
    refusal: Option<Refusal>,
}

impl AirCompiler {
    /// A compiler for the Vulkan device `device` describes.
    ///
    /// # Safety
    ///
    /// `service` holds the compiler service's entry points and the NIR
    /// options of that device's driver, which outlive the compiler and every
    /// shader it compiles.
    pub unsafe fn new(service: Service, device: &PhysicalDevice) -> Self {
        let limits = &device.limits;
        let mesh = limits.mesh;
        let varying_components = limits
            .max_vertex_output_components
            .min(limits.max_fragment_input_components);
        let target = ffi::Target {
            nir: service.nir_options.as_ptr(),
            max_instructions: MAX_INSTRUCTIONS,
            // NAK sizes shared memory in 16 bits.
            max_threadgroup_bytes: limits.max_compute_shared_memory_size.min(u16::MAX.into()),
            max_private_bytes: MAX_PRIVATE_BYTES,
            // The driver reads constant data through a uniform buffer.
            max_constant_bytes: limits.max_uniform_buffer_range,
            max_varying_slots: (varying_components / 4).min(ffi::VARYINGS as u32),
            max_payload_bytes: mesh.map_or(0, |mesh| mesh.max_task_payload_size),
            max_mesh_vertices: mesh.map_or(0, |mesh| mesh.max_mesh_output_vertices),
            max_mesh_primitives: mesh.map_or(0, |mesh| mesh.max_mesh_output_primitives),
        };
        Self {
            service,
            target,
            libraries: BTreeMap::new(),
            next_library: 0,
            refusal: None,
        }
    }

    /// The detail of the last call the service refused.
    pub fn refusal(&self) -> Option<&Refusal> {
        self.refusal.as_ref()
    }
}

impl Compiler for AirCompiler {
    fn features(&self) -> ShaderFeatures {
        FEATURES
    }

    fn add_library(&mut self, data: Vec<u8>) -> Result<u64> {
        Library::parse(&data).map_err(|_| Error::Invalid("Metal library"))?;
        let id = self.next_library;
        self.next_library += 1;
        self.libraries.insert(id, data);
        Ok(id)
    }

    fn remove_library(&mut self, library: u64) -> Result<()> {
        self.libraries
            .remove(&library)
            .map(drop)
            .ok_or(Error::Invalid("unknown library"))
    }

    fn reflect(
        &mut self,
        library: u64,
        entry: &str,
        specialization: &Specialization,
    ) -> Result<Reflection> {
        let selected = select(&self.libraries, library, entry)?;
        let (reflection, _) = selected.reflect(&self.service, specialization, &mut self.refusal)?;
        Ok(reflection)
    }

    fn sampler_states(
        &mut self,
        library: u64,
        entry: &str,
        specialization: &Specialization,
    ) -> Result<Vec<u64>> {
        let selected = select(&self.libraries, library, entry)?;
        let own = (selected.slice_hash, specialization.constants.as_slice());
        let linked = linked_modules(&self.libraries, &specialization.linking, own)?;
        let mut states = Vec::new();
        for bitcode in
            core::iter::once(selected.air.bitcode).chain(linked.iter().map(|module| module.bitcode))
        {
            let mut listed = [0; ffi::SAMPLER_STATES];
            let mut count = 0;
            let mut error = ffi::AirError::NONE;
            // SAFETY: the bitcode outlives the call, which writes at most
            // SAMPLER_STATES states, the count and the error.
            let valid = unsafe {
                (self.service.sampler_states)(
                    bitcode.as_ptr().cast(),
                    bitcode.len(),
                    listed.as_mut_ptr(),
                    &mut count,
                    &mut error,
                )
            };
            if !valid {
                return Err(refuse(&mut self.refusal, entry, &error));
            }
            states.extend_from_slice(listed.get(..count as usize).ok_or(MALFORMED)?);
        }
        states.sort_unstable();
        states.dedup();
        Ok(states)
    }

    fn compile(
        &mut self,
        library: u64,
        entry: &str,
        specialization: &Specialization,
    ) -> Result<CompiledShader> {
        let stage_in = specialization
            .stage_in
            .as_ref()
            .map(ffi::StageIn::kernel)
            .transpose()?;
        self.compile_function(library, entry, specialization, None, stage_in.as_deref())
    }

    fn compile_tessellation(
        &mut self,
        library: u64,
        entry: &str,
        specialization: &Specialization,
        tessellation: &Tessellation,
    ) -> Result<TessellationStages> {
        if specialization.stage_in.is_some() {
            return Err(Error::Invalid("kernel stage-in of a vertex function"));
        }
        let properties = ffi::Tessellation::new(tessellation);
        let stage_in = tessellation
            .vertex_descriptor
            .as_ref()
            .map(ffi::StageIn::vertex)
            .transpose()?;
        let evaluation = self.compile_function(
            library,
            entry,
            specialization,
            Some(&properties),
            stage_in.as_deref(),
        )?;
        let mut stages = [ptr::null_mut(); 2];
        // SAFETY: the target and tessellation outlive the call, which writes
        // only the two stages.
        unsafe {
            (self.service.tessellation_stages)(&self.target, &properties, stages.as_mut_ptr());
        }
        let [vertex, control] = stages.map(|stage| ShaderCode(stage as usize as u64));
        Ok(TessellationStages {
            vertex,
            control,
            evaluation,
        })
    }

    fn release(&mut self, code: ShaderCode) {
        // SAFETY: the code is NIR this compiler's service compiled, which the
        // device releases once.
        unsafe { (self.service.release)(code.0 as usize as *mut c_void) }
    }
}

impl AirCompiler {
    /// Compiles `entry` of `library`: a post-tessellation vertex function
    /// with its pipeline's tessellation, and a kernel or post-tessellation
    /// vertex function with the stage-in layout it fetches by.
    fn compile_function(
        &mut self,
        library: u64,
        entry: &str,
        specialization: &Specialization,
        tessellation: Option<&ffi::Tessellation>,
        stage_in: Option<&ffi::StageIn>,
    ) -> Result<CompiledShader> {
        let selected = select(&self.libraries, library, entry)?;
        let (reflection, provenance) =
            selected.reflect(&self.service, specialization, &mut self.refusal)?;
        let Reflection::Stage(interface) = reflection else {
            return Err(Error::Invalid("a visible function is not a pipeline stage"));
        };
        let linking = &specialization.linking;
        let own = (selected.slice_hash, specialization.constants.as_slice());
        let linked = linked_modules(&self.libraries, linking, own)?;
        let values: Vec<_> = linked
            .iter()
            .map(|module| module.constants.map(constant_values))
            .collect();
        let modules = linked
            .iter()
            .zip(&values)
            .map(|(module, values)| {
                Ok(ffi::Module {
                    bitcode: module.bitcode.as_ptr().cast(),
                    size: module.bitcode.len(),
                    constants: values
                        .as_ref()
                        .map_or(ptr::null(), |values| values.as_ptr()),
                    constant_count: values.as_ref().map_or(Ok(0), |values| {
                        u32::try_from(values.len()).map_err(|_| MALFORMED)
                    })?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let functions: Vec<_> = linking
            .functions
            .iter()
            .map(|function| ffi::LinkedFunction {
                name: function.entry.as_ptr().cast(),
                name_bytes: function.entry.len(),
            })
            .collect();
        let lengths = specialization
            .threadgroup_lengths
            .iter()
            .map(|&(index, bytes)| {
                let bytes = u32::try_from(bytes)
                    .map_err(|_| Error::Invalid("threadgroup memory length"))?;
                Ok(ffi::ThreadgroupLength { index, bytes })
            })
            .collect::<Result<Vec<_>>>()?;
        let varyings: Vec<_> = specialization
            .varyings
            .iter()
            .map(|varying| ffi::LinkedVarying {
                identifier: varying.identifier.as_ptr().cast(),
                identifier_bytes: varying.identifier.len(),
                per_primitive: varying.per_primitive.into(),
            })
            .collect();
        let constants = constant_values(&specialization.constants);
        let samplers: Vec<_> = specialization
            .samplers
            .iter()
            .map(|&(state, id)| ffi::ConstexprSampler { state, id })
            .collect();
        let count = |len: usize| u32::try_from(len).map_err(|_| MALFORMED);
        let raw = ffi::Specialization {
            workgroup_size: specialization.workgroup_size.unwrap_or_default(),
            threadgroup_length_count: count(lengths.len())?,
            threadgroup_lengths: lengths.as_ptr(),
            varyings: varyings.as_ptr(),
            varying_count: count(varyings.len())?,
            amplified: specialization.amplified.into(),
            launched_by_grid: specialization.launched_by_grid.into(),
            dynamic_threadgroups: specialization.dynamic_threadgroups.into(),
            constant_count: count(constants.len())?,
            constants: constants.as_ptr(),
            tessellation: tessellation.map_or(ptr::null(), ptr::from_ref),
            stage_in: stage_in.map_or(ptr::null(), ptr::from_ref),
            modules: modules.as_ptr(),
            linked_functions: functions.as_ptr(),
            module_count: count(modules.len())?,
            linked_function_count: count(functions.len())?,
            max_call_stack_depth: linking.max_call_stack_depth,
            sampler_count: count(samplers.len())?,
            samplers: samplers.as_ptr(),
        };
        let mut error = ffi::AirError::NONE;
        let air = selected.air.bitcode;
        // SAFETY: the AIR, entry, target and specialization, with the arrays,
        // identifiers, values, layouts, modules and names it points to,
        // outlive the call, which writes only the error.
        let shader = unsafe {
            (self.service.compile)(
                air.as_ptr().cast(),
                air.len(),
                selected.entry.as_ptr(),
                &self.target,
                &raw,
                &mut error,
            )
        };
        if shader.is_null() {
            return Err(refuse(&mut self.refusal, entry, &error));
        }
        Ok(CompiledShader {
            code: ShaderCode(shader as usize as u64),
            interface: *interface,
            provenance,
        })
    }
}

impl ffi::Tessellation {
    fn new(tessellation: &Tessellation) -> Self {
        Self {
            quad: tessellation.patch.domain == PatchDomain::Quad,
            partition: tessellation.partition.raw() as u32,
            max_factor: tessellation.max_factor,
            step: tessellation.step_function.raw() as u32,
            winding: tessellation.winding.raw() as u32,
            control_point_index_bytes: match tessellation.control_point_index {
                TessellationControlPointIndexType::None => 0,
                TessellationControlPointIndexType::UInt16 => 2,
                TessellationControlPointIndexType::UInt32 => 4,
            },
        }
    }
}

impl ffi::StageIn {
    /// The layout of a validated vertex descriptor.
    fn vertex(descriptor: &VertexDescriptor) -> Result<Box<Self>> {
        let layouts = descriptor.layouts.iter().map(|layout| {
            let step = layout.step_function.raw();
            (layout.buffer_index, layout.stride, step, layout.step_rate)
        });
        Self::new(&descriptor.attributes, layouts, 0, 0)
    }

    /// The layout of a validated stage-input descriptor.
    fn kernel(descriptor: &StageInputDescriptor) -> Result<Box<Self>> {
        let layouts = descriptor.layouts.iter().map(|layout| {
            let step = layout.step_function.raw();
            (layout.buffer_index, layout.stride, step, layout.step_rate)
        });
        let index_bytes = match descriptor.index_type {
            IndexType::UInt16 => 2,
            IndexType::UInt32 => 4,
        };
        Self::new(
            &descriptor.attributes,
            layouts,
            index_bytes,
            descriptor.index_buffer_index,
        )
    }

    /// Attributes, and each layout's buffer, stride and raw step function
    /// and rate.
    fn new(
        attributes: &[Attribute],
        layouts: impl Iterator<Item = (u32, u64, u64, u64)>,
        index_bytes: u32,
        index_buffer: u32,
    ) -> Result<Box<Self>> {
        const INVALID: Error = Error::Invalid("stage-in descriptor");
        let mut stage_in = Box::new(Self {
            attributes: [ffi::StageInAttribute::default(); ffi::ATTRIBUTES],
            layouts: Default::default(),
            index_bytes,
            index_buffer,
        });
        for attribute in attributes {
            *stage_in
                .attributes
                .get_mut(attribute.index as usize)
                .ok_or(INVALID)? = ffi::StageInAttribute {
                format: attribute.format.raw() as u32,
                offset: u32::try_from(attribute.offset).map_err(|_| INVALID)?,
                buffer: attribute.buffer_index,
            };
        }
        for (buffer, stride, step, rate) in layouts {
            *stage_in.layouts.get_mut(buffer as usize).ok_or(INVALID)? = ffi::StageInLayout {
                stride: match stride {
                    STRIDE_DYNAMIC => ffi::STRIDE_DYNAMIC,
                    stride => u32::try_from(stride)
                        .ok()
                        .filter(|stride| *stride != ffi::STRIDE_DYNAMIC)
                        .ok_or(INVALID)?,
                },
                step: u32::try_from(step).map_err(|_| INVALID)?,
                rate: u32::try_from(rate).map_err(|_| INVALID)?,
            };
        }
        Ok(stage_in)
    }
}

/// Function constant values as the service takes them, borrowing their
/// bytes.
fn constant_values(constants: &[(u32, Vec<u8>)]) -> Vec<ffi::ConstantValue> {
    constants
        .iter()
        .map(|(index, value)| ffi::ConstantValue {
            index: *index,
            bytes: value.as_ptr().cast(),
            size: value.len(),
        })
        .collect()
}

/// An AIR module a function links, with the function constant values of
/// the functions linked from it, or none for a dynamic library's.
struct LinkedModule<'a> {
    digest: [u8; 32],
    bitcode: &'a [u8],
    constants: Option<&'a [(u32, Vec<u8>)]>,
}

/// Whether two sets of function constant values, each with one value per
/// index, specialize a module alike.
fn same_values(a: Option<&[(u32, Vec<u8>)]>, b: Option<&[(u32, Vec<u8>)]>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.len() == b.len() && a.iter().all(|value| b.contains(value)),
        _ => true,
    }
}

/// The AIR modules `linking` adds to the function whose module has `own`
/// digest and values: each once, by digest. A module links with one set of
/// values; a dynamic library's takes those of a function linked from it.
fn linked_modules<'a>(
    libraries: &'a BTreeMap<u64, Vec<u8>>,
    linking: &'a Linking,
    own: ([u8; 32], &'a [(u32, Vec<u8>)]),
) -> Result<Vec<LinkedModule<'a>>> {
    let mut modules: Vec<LinkedModule<'a>> = Vec::new();
    let mut add = |digest: [u8; 32], air: Air<'a>, constants| {
        if digest == own.0 {
            return require(
                same_values(Some(own.1), constants),
                "linking a function's own module with other function constant values",
            );
        }
        match modules.iter_mut().find(|module| module.digest == digest) {
            Some(module) => {
                require(
                    same_values(module.constants, constants),
                    "linking one module with two sets of function constant values",
                )?;
                module.constants = module.constants.or(constants);
            }
            None => modules.push(LinkedModule {
                digest,
                bitcode: air.bitcode,
                constants,
            }),
        }
        Ok(())
    };
    for function in linking.functions.iter().chain(&linking.private_functions) {
        let selected = select(libraries, function.library, &function.entry)?;
        let constants = Some(function.constants.as_slice());
        add(selected.slice_hash, selected.air, constants)?;
    }
    let invalid = |_| Error::Invalid("Metal library");
    for library in &linking.libraries {
        let data = libraries
            .get(library)
            .ok_or(Error::Invalid("unknown library"))?;
        let parsed = Library::parse(data).map_err(invalid)?;
        ensure(
            parsed.header.kind == Header::DYNAMIC,
            "a preloaded library that is not dynamic",
        )?;
        for function in parsed.functions() {
            add(*function.digest, function.air().map_err(invalid)?, None)?;
        }
    }
    Ok(modules)
}

/// A library function selected for the service.
struct Selected<'a> {
    air: Air<'a>,
    name: &'a str,
    entry: CString,
    slice_hash: [u8; 32],
}

/// Selects `entry` of `library`.
fn select<'a>(
    libraries: &'a BTreeMap<u64, Vec<u8>>,
    library: u64,
    entry: &str,
) -> Result<Selected<'a>> {
    let data = libraries
        .get(&library)
        .ok_or(Error::Invalid("unknown library"))?;
    let invalid = |_| Error::Invalid("Metal library");
    let parsed = Library::parse(data).map_err(invalid)?;
    let function = parsed
        .functions()
        .iter()
        .find(|function| function.name == entry)
        .ok_or(Error::Invalid("no function of that name"))?;
    Ok(Selected {
        air: function.air().map_err(invalid)?,
        name: function.name,
        entry: CString::new(function.name).map_err(|_| Error::Invalid("function name"))?,
        slice_hash: *function.digest,
    })
}

impl Selected<'_> {
    /// The service's reflection of the function specialized with the
    /// function constant values, with the function's provenance.
    fn reflect(
        &self,
        service: &Service,
        specialization: &Specialization,
        refusal: &mut Option<Refusal>,
    ) -> Result<(Reflection, Provenance)> {
        let mut reflection = Box::new(ffi::Reflection::ZERO);
        let mut error = ffi::AirError::NONE;
        let air = self.air.bitcode;
        let values = constant_values(&specialization.constants);
        let count = u32::try_from(values.len()).map_err(|_| MALFORMED)?;
        // SAFETY: the AIR, entry and values outlive the call, which writes
        // only the reflection and the error.
        let reflected = unsafe {
            (service.reflect)(
                air.as_ptr().cast(),
                air.len(),
                self.entry.as_ptr(),
                values.as_ptr(),
                count,
                &mut *reflection,
                &mut error,
            )
        };
        if !reflected {
            return Err(refuse(refusal, self.name, &error));
        }
        let provenance = Provenance {
            build_id: name(&reflection, reflection.ident, reflection.ident_bytes)?.to_vec(),
            slice_hash: self.slice_hash,
            source_map: None,
            entry: self.name.to_string(),
        };
        let reflection = if u64::from(reflection.stage) == FunctionType::Visible.raw() {
            Reflection::Visible {
                constants: constants(&reflection)?,
                command_barriers: reflection.command_barriers != 0,
            }
        } else {
            Reflection::Stage(Box::new(interface(&reflection)?))
        };
        Ok((reflection, provenance))
    }
}

/// Records the service's refusal and names what it refused.
fn refuse(refusal: &mut Option<Refusal>, entry: &str, error: &ffi::AirError) -> Error {
    use ffi::kind;
    *refusal = Some(Refusal {
        entry: entry.to_string(),
        instruction: error.instruction,
        detail: error.detail(),
    });
    match error.kind {
        kind::INPUT => Error::Invalid("compiler request"),
        kind::ALLOCATION => Error::OutOfMemory,
        unsupported => Error::Unsupported(match unsupported {
            kind::LLVM_VERSION => "AIR from a newer LLVM",
            kind::BITCODE => "AIR bitcode",
            kind::VERIFY => "AIR that LLVM rejects",
            kind::TARGET => "AIR target",
            kind::METADATA => "AIR metadata",
            kind::ARGUMENT => "AIR function arguments",
            kind::CONTROL_FLOW => "AIR control flow",
            kind::INSTRUCTION => "AIR instructions",
            kind::TYPE => "AIR types",
            kind::MEMORY => "AIR memory access",
            kind::LIMIT => "AIR beyond the compiler's limits",
            _ => "AIR",
        }),
    }
}

/// The first `count` of a reflection's rows.
fn rows<T>(rows: &[T], count: u32) -> Result<&[T]> {
    rows.get(..count as usize).ok_or(MALFORMED)
}

/// `bytes` of the reflection's names from `offset`.
fn name(reflection: &ffi::Reflection, offset: u32, bytes: u32) -> Result<&[u8]> {
    let end = offset.checked_add(bytes).ok_or(MALFORMED)?;
    if end > reflection.names_bytes {
        return Err(MALFORMED);
    }
    reflection
        .names
        .get(offset as usize..end as usize)
        .ok_or(MALFORMED)
}

fn access(bits: u32) -> Result<Access> {
    u8::try_from(bits)
        .ok()
        .and_then(Access::from_bits)
        .ok_or(MALFORMED)
}

fn scalar(primitive: u32) -> Result<Scalar> {
    use ffi::primitive::*;
    Ok(match primitive {
        CHAR => Scalar::Char,
        UCHAR => Scalar::Uchar,
        SHORT => Scalar::Short,
        USHORT => Scalar::Ushort,
        INT => Scalar::Int,
        UINT => Scalar::Uint,
        FLOAT => Scalar::Float,
        HALF => Scalar::Half,
        _ => return Err(MALFORMED),
    })
}

fn numeric(primitive: u32) -> Result<NumericClass> {
    Ok(match scalar(primitive)? {
        Scalar::Float | Scalar::Half => NumericClass::Float,
        Scalar::Int | Scalar::Short | Scalar::Char => NumericClass::Sint,
        Scalar::Uint | Scalar::Ushort | Scalar::Uchar => NumericClass::Uint,
    })
}

fn components(count: u32) -> Result<u8> {
    u8::try_from(count)
        .ok()
        .filter(|count| (1..=4).contains(count))
        .ok_or(MALFORMED)
}

/// The `MTLDataType` of a function constant's MSL type spelling, as
/// `float`, `uint3` or `bool2`.
fn data_type(spelling: &[u8]) -> Result<DataType> {
    let (scalar, lanes) = match spelling.split_last() {
        Some((lanes @ b'2'..=b'4', scalar)) => (scalar, u64::from(lanes - b'0')),
        _ => (spelling, 1),
    };
    let scalar = match scalar {
        b"float" => DataType::Float,
        b"half" => DataType::Half,
        b"int" => DataType::Int,
        b"uint" => DataType::UInt,
        b"short" => DataType::Short,
        b"ushort" => DataType::UShort,
        b"char" => DataType::Char,
        b"uchar" => DataType::UChar,
        b"bool" => DataType::Bool,
        b"long" => DataType::Long,
        b"ulong" => DataType::ULong,
        _ => return Err(Error::Unsupported("function constant type")),
    };
    DataType::vector(scalar, lanes).ok_or(MALFORMED)
}

/// `enum stela_air_patch` and the control points the function declares.
fn patch(raw: u32, control_points: u32) -> Result<Option<Patch>> {
    let domain = match raw {
        0 => return (control_points == 0).then_some(None).ok_or(MALFORMED),
        1 => PatchDomain::Triangle,
        2 => PatchDomain::Quad,
        _ => return Err(MALFORMED),
    };
    let control_points = match control_points {
        0 => None,
        1..=MAX_PATCH_CONTROL_POINTS => Some(control_points),
        _ => return Err(MALFORMED),
    };
    Ok(Some(Patch {
        domain,
        control_points,
    }))
}

/// `enum stela_air_texture_type`.
fn texture_type(raw: u32) -> Result<TextureType> {
    const TYPES: [TextureType; 10] = [
        TextureType::D1,
        TextureType::D1Array,
        TextureType::D2,
        TextureType::D2Array,
        TextureType::D2Multisample,
        TextureType::D2MultisampleArray,
        TextureType::D3,
        TextureType::Cube,
        TextureType::CubeArray,
        TextureType::TextureBuffer,
    ];
    let index = raw.checked_sub(1).ok_or(MALFORMED)?;
    TYPES.get(index as usize).copied().ok_or(MALFORMED)
}

fn constants(r: &ffi::Reflection) -> Result<Vec<FunctionConstant>> {
    rows(&r.function_constants, r.function_constant_count)?
        .iter()
        .map(|constant| {
            let constant_name = name(r, constant.name, constant.name_bytes)?;
            Ok(FunctionConstant {
                name: String::from(str::from_utf8(constant_name).map_err(|_| MALFORMED)?),
                data_type: data_type(name(r, constant.type_name, constant.type_bytes)?)?,
                index: constant.index,
                required: constant.required != 0,
            })
        })
        .collect()
}

fn interface(reflection: &ffi::Reflection) -> Result<Interface> {
    let r = reflection;
    let stage = Stage::from_raw(r.stage.into()).ok_or(MALFORMED)?;
    let patch = patch(r.patch, r.patch_control_points)?;
    let buffers = rows(&r.buffers, r.buffer_count)?
        .iter()
        .map(|buffer| {
            Ok(BufferUse {
                index: buffer.index,
                access: access(buffer.access)?,
                argument_buffer: buffer.argument_buffer != 0,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let textures = rows(&r.textures, r.texture_count)?
        .iter()
        .map(|texture| {
            Ok(TextureUse {
                index: texture.index,
                access: access(texture.access)?,
                texture_type: texture_type(texture.texture_type)?,
                numeric: numeric(texture.primitive)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let threadgroup = rows(&r.threadgroup, r.threadgroup_count)?
        .iter()
        .map(|threadgroup| ThreadgroupUse {
            index: threadgroup.index,
            declared_bytes: threadgroup.bytes.into(),
        })
        .collect::<Vec<_>>();
    let declared_attributes = rows(&r.attributes, r.attribute_count)?
        .iter()
        .map(|attribute| {
            let name = name(r, attribute.name, attribute.name_bytes)?;
            let scalar = match scalar(attribute.primitive)? {
                Scalar::Float => DataType::Float,
                Scalar::Half => DataType::Half,
                Scalar::Int => DataType::Int,
                Scalar::Uint => DataType::UInt,
                Scalar::Short => DataType::Short,
                Scalar::Ushort => DataType::UShort,
                Scalar::Char => DataType::Char,
                Scalar::Uchar => DataType::UChar,
            };
            let components = components(attribute.components)?;
            Ok(DeclaredAttribute {
                name: String::from(str::from_utf8(name).map_err(|_| MALFORMED)?),
                index: attribute.index,
                data_type: DataType::vector(scalar, components.into()).ok_or(MALFORMED)?,
                active: attribute.active != 0,
                patch_control_point: attribute.patch_control_point != 0,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let attributes = rows(&r.attributes, r.attribute_count)?
        .iter()
        .filter(|attribute| attribute.active != 0)
        .map(|attribute| {
            Ok(AttributeUse {
                index: attribute.index,
                numeric: numeric(attribute.primitive)?,
                components: components(attribute.components)?,
                patch_control_point: attribute.patch_control_point != 0,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let varyings = rows(&r.varyings, r.varying_count)?
        .iter()
        .map(|varying| {
            let identifier = name(r, varying.identifier, varying.identifier_bytes)?;
            Ok(Varying {
                identifier: String::from(str::from_utf8(identifier).map_err(|_| MALFORMED)?),
                scalar: scalar(varying.primitive)?,
                components: components(varying.components)?,
                per_primitive: varying.per_primitive != 0,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let color_outputs = rows(&r.color_outputs, r.color_output_count)?
        .iter()
        .map(|output| {
            Ok(ColorOutput {
                index: output.index,
                numeric: numeric(output.primitive)?,
                dual_source: output.dual_source != 0,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let constants = constants(r)?;
    let features = match stage {
        Stage::Kernel => ShaderFeatures::COMPUTE,
        Stage::Vertex | Stage::Fragment => ShaderFeatures::VERTEX_FRAGMENT,
        Stage::Object | Stage::Mesh => ShaderFeatures::MESH,
    }
    .with(
        ShaderFeatures::TEXTURE_SAMPLE,
        textures
            .iter()
            .any(|texture| texture.access.contains(Access::SAMPLE)),
    )
    .with(
        ShaderFeatures::TEXTURE_READ_WRITE,
        textures.iter().any(|texture| texture.access.writes()),
    )
    .with(
        ShaderFeatures::THREADGROUP_MEMORY,
        !threadgroup.is_empty() || r.threadgroup_bytes != 0,
    )
    .with(
        ShaderFeatures::ARGUMENT_BUFFERS,
        buffers.iter().any(|buffer| buffer.argument_buffer),
    )
    .with(ShaderFeatures::VERTEX_AMPLIFICATION, r.amplification != 0)
    .with(ShaderFeatures::TESSELLATION, patch.is_some())
    .with(ShaderFeatures::BARYCENTRICS, r.barycentrics != 0)
    .with(
        ShaderFeatures::PULL_MODEL_INTERPOLATION,
        r.interpolants != 0,
    )
    .with(ShaderFeatures::FUNCTION_POINTERS, r.function_tables != 0)
    .with(ShaderFeatures::INDIRECT_COMMAND_ENCODING, r.commands != 0);
    let interface = Interface {
        stage,
        patch,
        buffers,
        textures,
        samplers: rows(&r.samplers, r.sampler_count)?.to_vec(),
        threadgroup,
        attributes,
        declared_attributes,
        varyings,
        color_outputs,
        writes_depth: r.writes_depth != 0,
        writes_stencil: r.writes_stencil != 0,
        writes_sample_mask: r.writes_sample_mask != 0,
        discards: r.discards != 0,
        // The frontend refuses metadata it does not lower, this among it.
        early_fragment_tests: false,
        static_threadgroup_bytes: r.threadgroup_bytes,
        max_total_threads: (r.max_total_threads != 0).then_some(r.max_total_threads),
        amplification: r.amplification != 0,
        command_barriers: r.command_barriers != 0,
        constants,
        features,
    };
    interface.validate()?;
    Ok(interface)
}
