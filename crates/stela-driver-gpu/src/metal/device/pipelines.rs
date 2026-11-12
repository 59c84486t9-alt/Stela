//! Libraries, functions and pipeline states, with their compiled variants.
//!
//! A pipeline stage compiles its linked functions into its function
//! ([`Linking`]). A visible function table is a buffer of 64-bit
//! [`FunctionHandle`]s, which the compiler's dispatch reads.
//!
//! As in Metal, a function keeps its library and a pipeline the functions
//! and libraries its descriptor names, whose variants it compiles later:
//! destroying a library or function ends its creator's use, and the object
//! goes once nothing uses it.
use super::{
    ArchiveId, BufferId, ComputePipelineId, Device, FunctionId, LibraryId, RenderPipelineId, Slab,
};
use crate::metal::{
    abi::{ConversionRounding, DataType, FunctionType, PrimitiveTopologyClass},
    command_buffer::{BoundPipeline, ComputePipelineState, IndirectCompute, RenderPipelineState},
    error::{Error, Result, ensure, require},
    library::{self, Function, Header, Library},
    pipeline::{
        self, ComputePipelineDescriptor, MeshRenderPipelineDescriptor, RenderPipelineDescriptor,
        RenderPipelinePlan, RenderTargets, StageThreads, TessellatedVertex, TessellationDescriptor,
        TileTarget,
    },
    reflection::Binding,
    shader::{
        CompiledShader, Compiler, DYNAMIC_BICUBIC, Interface, LinkedFunction, Linking,
        PreparedFunction, Reflection, Specialization, Stage, Tessellation, TessellationStages,
        Varying,
    },
    stitching::StitchedGraph,
    timing::{Detail, Name, Phase, Timed},
    vertex::{self, StageInputDescriptor, VertexDescriptor},
    vulkan::{
        ShaderStages,
        backend::{Backend, Object},
        object::{ComputePipelineInfo, Pipeline, PipelineCache, PipelineSource, ShaderCode},
    },
};
use alloc::{format, string::String, vec::Vec};

/// What a destroyed object's id fails with.
const DESTROYED: &str = "unknown or destroyed object";

/// A function's `TYPE` in a Metal library.
fn mtlb_stage(function_type: FunctionType) -> u8 {
    match function_type {
        FunctionType::Vertex => 0,
        FunctionType::Fragment => 1,
        FunctionType::Kernel => 2,
        FunctionType::Visible => 4,
        FunctionType::Intersection => 6,
        FunctionType::Mesh => 7,
        FunctionType::Object => 8,
    }
}

/// Who uses a library or function: its creator until it destroys the
/// object, and the functions and pipelines made from it.
#[derive(Debug)]
struct Users {
    creator: bool,
    others: u32,
}

impl Users {
    const CREATED: Self = Self {
        creator: true,
        others: 0,
    };

    fn none(&self) -> bool {
        !self.creator && self.others == 0
    }
}

/// `MTLLibrary`: the compiler's library and its functions' names.
#[derive(Debug)]
struct LibraryObject {
    library: u64,
    /// The length and [`library_digest`] of its bytes, which a library of
    /// the same bytes shares ([`Device::share_library`]).
    bytes: (u64, [u8; 32]),
    names: Vec<String>,
    /// Its extern functions' names, which name no function of its own.
    extern_names: Vec<String>,
    dynamic: bool,
    install_name: Option<String>,
    /// The install names of the dynamic libraries its bytes say it links,
    /// which the frontend loads where they are installed.
    linked: Vec<String>,
    /// `MTLCompileOptions.libraries` and a stitched library's functions'
    /// libraries, which it keeps.
    dependencies: Vec<LibraryId>,
    /// The dependencies are `MTLCompileOptions.libraries`, which load with
    /// whatever links the library's functions; a stitched library's only
    /// stay while it does, as `stitched` links their functions.
    preloads: bool,
    /// What a pipeline linking its functions links too: stitched functions'
    /// calls stay declarations.
    stitched: Vec<LinkedFunction>,
    /// Its functions' narrowing floating-point conversions round toward zero.
    round_toward_zero: bool,
    users: Users,
}

/// The SHA-256 of a library's bytes, by which libraries of the same bytes
/// share them.
pub fn library_digest(data: &[u8]) -> [u8; 32] {
    use stela_crypto::{Sha256, digest::Digest};
    Sha256::digest(data).into()
}

/// `MTLBinaryArchive`: the driver's pipeline cache, which holds what its
/// back end compiled. Each pipeline's stages still lower from AIR.
#[derive(Debug)]
struct ArchiveObject {
    cache: PipelineCache,
    users: Users,
}

/// A descriptor's `binaryArchives` and what its request does with them.
#[derive(Clone, Debug, Default)]
pub struct PipelineArchives {
    /// The archives to search, in order.
    pub searched: Vec<ArchiveId>,
    /// `MTLPipelineOptionFailOnBinaryArchiveMiss`.
    pub required: bool,
    /// The archive `add…FunctionsWithDescriptor:` compiles the pipeline
    /// into.
    pub added_to: Option<ArchiveId>,
}

/// Where a pipeline's Vulkan pipelines come from.
#[derive(Clone, Debug, Default)]
struct Sources {
    searched: Vec<PipelineCache>,
    required: bool,
    /// What compiles a pipeline no searched archive holds.
    compiled: PipelineSource,
}

impl Sources {
    /// A pipeline whose stages compile per draw or dispatch shape still
    /// compiles one now, when its creation answers for an archive.
    fn compiles_at_creation(&self) -> bool {
        self.required || self.compiled != PipelineSource::Compiled
    }

    /// The sources of variants compiled after the pipeline's creation: a
    /// draw has no miss to fail with, and since no request names its shapes,
    /// the first archive learns them.
    fn of_variants(&self) -> Self {
        Self {
            searched: self.searched.clone(),
            required: false,
            compiled: match (self.compiled, self.searched.first()) {
                (PipelineSource::Compiled, Some(&cache)) => PipelineSource::Cached(cache),
                (compiled, _) => compiled,
            },
        }
    }
}

/// A function (`newFunctionWithName:constantValues:`).
#[derive(Debug)]
struct FunctionObject {
    library: LibraryId,
    prepared: PreparedFunction,
    users: Users,
    /// Its process has made bicubic samplers
    /// ([`Specialization::bicubic`]).
    bicubic: bool,
    /// The name a visible function's calls reach it by, when its
    /// descriptor's `specializedName` is not its entry.
    alias: Option<String>,
}

impl FunctionObject {
    /// The interface of a function that becomes a pipeline stage.
    fn interface(&self) -> Result<&Interface> {
        self.specialized()?;
        match &self.prepared.reflection {
            Reflection::Stage(interface) => Ok(interface.as_ref()),
            Reflection::Visible { .. } => Err(Error::Invalid("a visible function is not a stage")),
        }
    }

    /// Refuses a function whose required constants have no values: one
    /// made without values, which only reflects.
    fn specialized(&self) -> Result<()> {
        ensure(
            self.prepared.specialized
                || self
                    .prepared
                    .reflection
                    .constants()
                    .iter()
                    .all(|constant| !constant.required),
            "a required function constant has no value",
        )
    }
}

/// `MTLFunctionHandle`: the value a visible function table holds to call a
/// function its stage links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FunctionHandle(pub u64);

/// A stage's linked functions: `functions` are those its handles name, in
/// order, and `linking` what its function compiles with.
#[derive(Debug, Default)]
struct Linked {
    functions: Vec<FunctionId>,
    linking: Linking,
}

impl Linked {
    /// Handle `i + 1` calls the `i`-th function; zero calls none.
    fn handle(&self, function: FunctionId) -> Option<FunctionHandle> {
        let index = self
            .functions
            .iter()
            .position(|&linked| linked == function)?;
        Some(FunctionHandle(index as u64 + 1))
    }
}

/// The functions and libraries an object uses: those a pipeline's
/// descriptor names, or a function's library.
#[derive(Debug, Default)]
struct Kept {
    functions: Vec<FunctionId>,
    libraries: Vec<LibraryId>,
    archives: Vec<ArchiveId>,
}

impl Kept {
    fn new<'a>(
        functions: impl IntoIterator<Item = FunctionId>,
        linked: impl IntoIterator<Item = &'a LinkedFunctions>,
    ) -> Self {
        let mut kept = Self {
            functions: functions.into_iter().collect(),
            ..Self::default()
        };
        for linked in linked {
            kept.functions.extend(&linked.functions);
            kept.functions.extend(&linked.private_functions);
            kept.libraries.extend(&linked.libraries);
        }
        kept
    }

    fn library(library: LibraryId) -> Self {
        Self {
            libraries: alloc::vec![library],
            ..Self::default()
        }
    }

    fn with_archives(mut self, archives: &PipelineArchives) -> Self {
        self.archives.extend(&archives.searched);
        self.archives.extend(archives.added_to);
        self
    }
}

#[derive(Debug)]
struct RenderObject {
    state: RenderPipelineState,
    kept: Kept,
    /// Each stage's linked functions.
    linked: Vec<(Stage, Linked)>,
    sources: Sources,
    /// A mesh pipeline's compiled fragment function, which every variant
    /// links.
    fragment: Option<ShaderCode>,
    mesh: Option<MeshFunctions>,
    /// Mesh variants, and whether their process had made bicubic or
    /// pixel-coordinate samplers when they compiled.
    variants: Vec<(MeshShape, bool, Pipeline)>,
    /// A vertex pipeline's request, which its bicubic variants compile.
    request: Option<RenderPipelineRequest>,
    /// Variants whose vertex and fragment stages filter the samplers at
    /// these indices bicubically ([`RenderPipelineState::bicubic`]), and
    /// whether their process had made such samplers when they compiled.
    bicubic: Vec<([u32; 2], bool, Pipeline)>,
}

/// The object and mesh functions of a mesh pipeline, which its variants
/// compile, and the varyings its mesh function links to its fragment
/// function.
#[derive(Debug)]
struct MeshFunctions {
    object: Option<FunctionId>,
    mesh: FunctionId,
    varyings: Vec<Varying>,
}

/// Threads per object and per mesh threadgroup and the object stage's
/// threadgroup memory lengths, which mesh variants are compiled for.
type MeshShape = ([u32; 3], [u32; 3], Vec<(u32, u64)>);

#[derive(Debug)]
struct ComputeObject {
    state: ComputePipelineState,
    kept: Kept,
    function: FunctionId,
    linked: Linked,
    sources: Sources,
    variants: Vec<(Specialization, Pipeline)>,
    /// A tile pipeline's pass.
    tile: Option<TileTarget>,
}

#[derive(Debug, Default)]
pub(super) struct Pipelines {
    libraries: Slab<LibraryObject>,
    archives: Slab<ArchiveObject>,
    functions: Slab<FunctionObject>,
    render: Slab<RenderObject>,
    compute: Slab<ComputeObject>,
}

impl Pipelines {
    /// The entry points of the functions `pipeline` uses: those its
    /// descriptor names and those it links.
    /// A pipeline's functions by entry point, each with the function
    /// constants it was specialized with as `[index=bytes, ...]`.
    pub(super) fn entries(&self, pipeline: BoundPipeline) -> Result<Vec<String>> {
        let kept = match pipeline {
            BoundPipeline::Render(id) => &self.render.get(id as u32)?.kept,
            BoundPipeline::Compute(id) => &self.compute.get(id as u32)?.kept,
        };
        kept.functions
            .iter()
            .map(|function| {
                let function = self.functions.get(function.0)?;
                let prepared = &function.prepared;
                let mut named = String::from(prepared.entry());
                if !prepared.constants.is_empty() {
                    named.push('[');
                    for (index, (constant, bytes)) in prepared.constants.iter().enumerate() {
                        if index > 0 {
                            named.push(',');
                        }
                        named.push_str(&format!("{constant}="));
                        for byte in bytes {
                            named.push_str(&format!("{byte:02x}"));
                        }
                    }
                    named.push(']');
                }
                Ok(named)
            })
            .collect()
    }

    fn interface(&self, id: FunctionId) -> Result<&Interface> {
        self.functions.get(id.0)?.interface()
    }

    /// The compiler's id of a library.
    fn library(&self, id: LibraryId) -> Result<u64> {
        Ok(self.libraries.get(id.0)?.library)
    }

    /// Refuses a library or function its creator destroyed: what uses it
    /// keeps it, but nothing new may.
    fn ensure_created(&self, kept: &Kept) -> Result<()> {
        for &id in &kept.functions {
            ensure(self.functions.get(id.0)?.users.creator, DESTROYED)?;
        }
        for &id in &kept.libraries {
            ensure(self.libraries.get(id.0)?.users.creator, DESTROYED)?;
        }
        for &id in &kept.archives {
            ensure(self.archives.get(id.0)?.users.creator, DESTROYED)?;
        }
        Ok(())
    }

    fn sources(&self, archives: &PipelineArchives) -> Result<Sources> {
        let cache = |id: ArchiveId| Ok(self.archives.get(id.0)?.cache);
        Ok(Sources {
            searched: archives
                .searched
                .iter()
                .map(|&id| cache(id))
                .collect::<Result<_>>()?,
            required: archives.required,
            compiled: archives
                .added_to
                .map_or(Ok(PipelineSource::Compiled), |id| {
                    cache(id).map(PipelineSource::Cached)
                })?,
        })
    }
}

impl RenderObject {
    fn linked(&self, stage: Stage) -> Option<&Linked> {
        self.linked
            .iter()
            .find(|(linked, _)| *linked == stage)
            .map(|(_, linked)| linked)
    }
}

/// A value of `MTLFunctionConstantValues`: of `data_type`, its lanes
/// packed, for the constant at an index or of a name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstantValue {
    pub key: ConstantKey,
    pub data_type: DataType,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstantKey {
    Index(u32),
    Name(String),
}

impl ConstantValue {
    pub fn at(index: u32, data_type: DataType, value: Vec<u8>) -> Self {
        Self {
            key: ConstantKey::Index(index),
            data_type,
            value,
        }
    }
}

/// `MTLLinkedFunctions`, the `preloadedLibraries` and the call stack depth
/// of a pipeline stage. Every function compiles into the stage, so
/// `binaryFunctions` join `functions`.
#[derive(Clone, Debug)]
pub struct LinkedFunctions {
    /// The visible functions the stage's function tables call.
    pub functions: Vec<FunctionId>,
    /// Visible functions only external calls reach.
    pub private_functions: Vec<FunctionId>,
    /// Dynamic libraries resolving external calls.
    pub libraries: Vec<LibraryId>,
    /// The stage's `maxCallStackDepth` (`maxVertexCallStackDepth`,
    /// `maxFragmentCallStackDepth`, ...).
    pub max_call_stack_depth: u32,
}

impl Default for LinkedFunctions {
    fn default() -> Self {
        Self {
            functions: Vec::new(),
            private_functions: Vec::new(),
            libraries: Vec::new(),
            max_call_stack_depth: Linking::default().max_call_stack_depth,
        }
    }
}

/// `MTLRenderPipelineDescriptor` with the device's function ids.
#[derive(Clone, Debug)]
pub struct RenderPipelineRequest {
    pub vertex_function: FunctionId,
    pub fragment_function: Option<FunctionId>,
    pub vertex_descriptor: Option<VertexDescriptor>,
    pub targets: RenderTargets,
    pub input_primitive_topology: PrimitiveTopologyClass,
    pub max_vertex_amplification_count: u64,
    pub tessellation: TessellationDescriptor,
    pub vertex_linked_functions: LinkedFunctions,
    pub fragment_linked_functions: LinkedFunctions,
    /// `supportIndirectCommandBuffers`: GPU-resident indirect commands can
    /// switch to the pipeline, unless it is tessellated or amplifies
    /// vertices, whose draws only the CPU encodes.
    pub support_indirect_command_buffers: bool,
    pub archives: PipelineArchives,
}

/// `MTLComputePipelineDescriptor` with the device's function id.
#[derive(Clone, Debug)]
pub struct ComputePipelineRequest {
    pub compute_function: FunctionId,
    pub threadgroup_size_is_multiple_of_thread_execution_width: bool,
    /// Zero leaves the device's limit.
    pub max_total_threads_per_threadgroup: u64,
    pub stage_input: Option<StageInputDescriptor>,
    pub linked_functions: LinkedFunctions,
    /// `supportIndirectCommandBuffers`: GPU-resident indirect commands can
    /// switch to the pipeline, whose threadgroup buffers then align to at
    /// most 16 bytes.
    pub support_indirect_command_buffers: bool,
    pub archives: PipelineArchives,
}

/// `MTLMeshRenderPipelineDescriptor` with the device's function ids.
#[derive(Clone, Debug)]
pub struct MeshPipelineRequest {
    pub object_function: Option<FunctionId>,
    pub mesh_function: FunctionId,
    pub fragment_function: Option<FunctionId>,
    pub targets: RenderTargets,
    pub max_vertex_amplification_count: u64,
    pub object_threads: StageThreads,
    pub mesh_threads: StageThreads,
    pub payload_memory_length: u64,
    pub object_linked_functions: LinkedFunctions,
    pub mesh_linked_functions: LinkedFunctions,
    pub fragment_linked_functions: LinkedFunctions,
    pub archives: PipelineArchives,
}

/// The bytes of a `VkPipelineCacheHeaderVersionOne`, which an archive file
/// begins with when it holds this device's pipelines.
pub const ARCHIVE_HEADER_BYTES: u64 = 32;

impl<B: Backend, C: Compiler> Device<B, C> {
    /// `newLibraryWithSource:` of the AIR the source compiled to.
    /// `dependencies` are `MTLCompileOptions.libraries`, which load with the
    /// library for whatever links it.
    pub fn new_source_library(
        &mut self,
        air: &[u8],
        install_name: Option<&str>,
        dependencies: &[LibraryId],
        rounding: ConversionRounding,
    ) -> Result<LibraryId> {
        for &id in dependencies {
            ensure(self.pipelines.libraries.get(id.0)?.users.creator, DESTROYED)?;
        }
        let functions = self.compiler.functions(air)?;
        // A dynamic library lists the definitions it exports, as Metal's
        // compiler does, so pipelines linking it find their modules.
        let exports = match install_name {
            Some(_) => self.compiler.exports(air)?,
            None => Vec::new(),
        };
        let stages: Vec<_> = functions
            .iter()
            .map(|(name, function_type)| (name.as_str(), mtlb_stage(*function_type)))
            .chain(
                exports
                    .iter()
                    .map(|name| (name.as_str(), Function::EXPORTED)),
            )
            .collect();
        let kind = install_name.map_or(0, |_| Header::DYNAMIC);
        let library = self.new_library(library::assemble(air, &stages, kind, install_name))?;
        for &id in dependencies {
            self.pipelines.libraries.get_mut(id.0)?.users.others += 1;
        }
        let held = self.pipelines.libraries.get_mut(library.0)?;
        held.dependencies = dependencies.to_vec();
        held.preloads = true;
        held.round_toward_zero = rounding == ConversionRounding::TowardZero;
        Ok(library)
    }

    /// `newLibraryWithStitchedDescriptor:error:`: a library of `graphs`, whose
    /// calls index `functions`.
    pub fn new_stitched_library(
        &mut self,
        functions: &[FunctionId],
        graphs: &[StitchedGraph],
    ) -> Result<LibraryId> {
        let mut libraries = Vec::with_capacity(functions.len());
        let mut stitched = Vec::with_capacity(functions.len());
        for &id in functions {
            let function = self.pipelines.functions.get(id.0)?;
            ensure(
                matches!(function.prepared.reflection, Reflection::Visible { .. }),
                "stitched functions are visible functions",
            )?;
            function.specialized()?;
            let mut constants = function.prepared.constants.clone();
            constants.sort_unstable_by_key(|&(index, _)| index);
            stitched.push(LinkedFunction {
                library: self.pipelines.library(function.library)?,
                entry: String::from(function.prepared.entry()),
                constants,
                alias: function.alias.clone(),
            });
            libraries.push(function.library);
        }
        let air = self.compiler.stitch(&stitched, graphs)?;
        // A stitched function's own stitched functions link with it.
        for id in &libraries {
            let below = &self.pipelines.libraries.get(id.0)?.stitched;
            stitched.extend_from_slice(below);
        }
        // A stitched library has no compile options of its own.
        let library =
            self.new_source_library(&air, None, &libraries, ConversionRounding::ToNearestEven)?;
        let held = self.pipelines.libraries.get_mut(library.0)?;
        held.stitched = stitched;
        held.preloads = false;
        Ok(library)
    }

    /// `newLibraryWithData:`: keeps a Metal library for its functions.
    pub fn new_library(&mut self, data: Vec<u8>) -> Result<LibraryId> {
        let digest = library_digest(&data);
        self.new_library_digested(data, digest)
    }

    /// [`Self::new_library`] of bytes whose [`library_digest`] the caller
    /// took, as it read them a piece at a time.
    pub fn new_library_digested(&mut self, data: Vec<u8>, digest: [u8; 32]) -> Result<LibraryId> {
        let parsed = Library::parse(&data).map_err(|_| Error::Invalid("Metal library"))?;
        let (externs, functions): (Vec<_>, Vec<_>) = parsed
            .functions()
            .iter()
            .partition(|function| function.kind == Function::EXTERN);
        let names = |functions: Vec<&Function>| {
            functions
                .into_iter()
                .map(|function| String::from(function.name))
                .collect()
        };
        let (names, extern_names) = (names(functions), names(externs));
        let dynamic = parsed.header.kind == Header::DYNAMIC;
        let install_name = parsed.install_name.map(String::from);
        let linked = parsed.linked.iter().copied().map(String::from).collect();
        let length = data.len() as u64;
        let library = self.compiler.add_library(data)?;
        let index = self.pipelines.libraries.insert(LibraryObject {
            library,
            bytes: (length, digest),
            names,
            extern_names,
            dynamic,
            install_name,
            linked,
            dependencies: Vec::new(),
            preloads: false,
            stitched: Vec::new(),
            round_toward_zero: false,
            users: Users::CREATED,
        });
        Ok(LibraryId(index))
    }

    /// `newLibraryWithData:` of `length` bytes of [`library_digest`]
    /// `digest`, which another library already keeps: the two then share
    /// them. System libraries run to hundreds of megabytes and every process
    /// loads them; the digest compares them with no byte read again.
    pub fn share_library(&mut self, length: u64, digest: &[u8; 32]) -> Result<Option<LibraryId>> {
        let found = self
            .pipelines
            .libraries
            .iter()
            .find(|held| held.bytes == (length, *digest));
        let Some(held) = found else {
            return Ok(None);
        };
        let object = LibraryObject {
            library: self.compiler.share_library(held.library)?,
            bytes: held.bytes,
            names: held.names.clone(),
            extern_names: held.extern_names.clone(),
            dynamic: held.dynamic,
            install_name: held.install_name.clone(),
            linked: held.linked.clone(),
            dependencies: Vec::new(),
            preloads: false,
            stitched: Vec::new(),
            // A library of the same bytes, not of the same source options.
            round_toward_zero: false,
            users: Users::CREATED,
        };
        Ok(Some(LibraryId(self.pipelines.libraries.insert(object))))
    }

    /// `functionNames`.
    pub fn library_function_names(&self, id: LibraryId) -> Result<&[String]> {
        Ok(&self.pipelines.libraries.get(id.0)?.names)
    }

    /// `externFunctionNames`.
    pub fn library_extern_function_names(&self, id: LibraryId) -> Result<&[String]> {
        Ok(&self.pipelines.libraries.get(id.0)?.extern_names)
    }

    /// The install names of the dynamic libraries the library links.
    pub fn library_linked_names(&self, id: LibraryId) -> Result<&[String]> {
        Ok(&self.pipelines.libraries.get(id.0)?.linked)
    }

    /// `type` and `installName`.
    pub fn library_identity(&self, id: LibraryId) -> Result<(bool, Option<&str>)> {
        let library = self.pipelines.libraries.get(id.0)?;
        Ok((library.dynamic, library.install_name.as_deref()))
    }

    /// The library's bytes, which `serializeToURL:` writes.
    pub fn library_data(&self, id: LibraryId) -> Result<&[u8]> {
        self.compiler.library_data(self.pipelines.library(id)?)
    }

    /// Whether an archive file beginning with `header` may hold this
    /// device's pipelines: a pipeline cache header of version one naming
    /// its vendor, device and pipeline cache UUID. The driver ignores any
    /// other data, such as another GPU's archive, so it need not be read.
    pub fn archive_header_matches(&self, header: &[u8]) -> bool {
        let identity = &self.backend.physical_device().identity;
        let word = |at: usize| {
            header
                .get(at..at + 4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four bytes")))
        };
        word(0).is_some_and(|size| u64::from(size) >= ARCHIVE_HEADER_BYTES)
            && word(4) == Some(1)
            && word(8) == Some(identity.vendor_id)
            && word(12) == Some(identity.device_id)
            && header.get(16..32) == Some(&identity.pipeline_cache_uuid[..])
    }

    /// `newBinaryArchiveWithDescriptor:error:` of `data`, a file's bytes:
    /// another device's or driver's archive holds nothing of this one's.
    pub fn new_archive(&mut self, data: &[u8]) -> Result<ArchiveId> {
        let cache = self.backend.create_pipeline_cache(data)?;
        let index = self.pipelines.archives.insert(ArchiveObject {
            cache,
            users: Users::CREATED,
        });
        Ok(ArchiveId(index))
    }

    /// The bytes `serializeToURL:error:` writes.
    pub fn archive_data(&mut self, id: ArchiveId) -> Result<Vec<u8>> {
        let cache = self.pipelines.archives.get(id.0)?.cache;
        self.backend.pipeline_cache_data(cache)
    }

    /// Ends the creator's use of an archive, which goes with the last
    /// pipeline reading it.
    pub fn destroy_archive(&mut self, id: ArchiveId) -> Result<()> {
        let users = &mut self.pipelines.archives.get_mut(id.0)?.users;
        ensure(users.creator, DESTROYED)?;
        users.creator = false;
        self.collect_archive(id)
    }

    fn collect_archive(&mut self, id: ArchiveId) -> Result<()> {
        if self.pipelines.archives.get(id.0)?.users.none() {
            let archive = self.pipelines.archives.remove(id.0)?;
            self.defer(Object::PipelineCache(archive.cache));
        }
        Ok(())
    }

    /// A pipeline from the first of `sources` that holds it, else compiled
    /// unless the request wants it from them.
    fn create_from(
        &mut self,
        sources: &Sources,
        mut create: impl FnMut(&mut B, PipelineSource) -> Result<Pipeline>,
    ) -> Result<Pipeline> {
        for &cache in &sources.searched {
            match create(&mut self.backend, PipelineSource::Archived(cache)) {
                Err(Error::NotArchived) => {}
                created => return created,
            }
        }
        if sources.required {
            return Err(Error::NotArchived);
        }
        create(&mut self.backend, sources.compiled)
    }

    /// Ends the creator's use of a library, which goes with the last
    /// function and pipeline using it.
    pub fn destroy_library(&mut self, id: LibraryId) -> Result<()> {
        let users = &mut self.pipelines.libraries.get_mut(id.0)?.users;
        ensure(users.creator, DESTROYED)?;
        users.creator = false;
        self.collect_library(id)
    }

    fn collect_library(&mut self, id: LibraryId) -> Result<()> {
        if self.pipelines.libraries.get(id.0)?.users.none() {
            let library = self.pipelines.libraries.remove(id.0)?;
            self.compiler.remove_library(library.library)?;
            self.release(Kept {
                libraries: library.dependencies,
                ..Kept::default()
            })?;
        }
        Ok(())
    }

    /// `newFunctionWithName:constantValues:`: reflects the function without
    /// compiling it. Values of constants the function does not declare are
    /// ignored, as one set of values often serves several functions.
    /// Without values (`values` is `None`), a function whose constants are
    /// required is the function as its library holds it, which reflects but
    /// becomes no pipeline.
    pub fn new_function(
        &mut self,
        library: LibraryId,
        entry: &str,
        values: Option<&[ConstantValue]>,
    ) -> Result<FunctionId> {
        let kept = Kept::library(library);
        self.pipelines.ensure_created(&kept)?;
        // Metal answers a function of its own kind, which no pipeline
        // takes, for an extern function's name.
        require(
            !self
                .pipelines
                .libraries
                .get(library.0)?
                .extern_names
                .iter()
                .any(|name| name == entry),
            "the function of an extern declaration",
        )?;
        let compiled = self.pipelines.library(library)?;
        // Reflection, from the compiler's cache or the service's.
        let start = self.timing.now();
        let values = match values {
            Some(values) => values,
            None if self
                .compiler
                .constants(compiled, entry)?
                .iter()
                .any(|constant| constant.required) =>
            {
                let prepared = self.compiler.prepare_function(compiled, entry, None)?;
                self.timing.since(Phase::FunctionReflect, start);
                return self.hold_function(library, prepared, &kept);
            }
            None => &[],
        };
        // Values set by name take their constants' indices, which the
        // function's declarations give whatever its values.
        let declared = if values
            .iter()
            .any(|value| matches!(value.key, ConstantKey::Name(_)))
        {
            self.compiler.constants(compiled, entry)?
        } else {
            Vec::new()
        };
        let indexed: Vec<(u32, &ConstantValue)> = values
            .iter()
            .filter_map(|value| match &value.key {
                ConstantKey::Index(index) => Some((*index, value)),
                ConstantKey::Name(name) => declared
                    .iter()
                    .find(|constant| constant.name == *name)
                    .map(|constant| (constant.index, value)),
            })
            .collect();
        ensure(
            indexed
                .iter()
                .enumerate()
                .all(|(n, (index, _))| indexed[n + 1..].iter().all(|(other, _)| other != index)),
            "a function constant has two values",
        )?;
        let constants: Vec<(u32, Vec<u8>)> = indexed
            .iter()
            .map(|&(index, value)| (index, value.value.clone()))
            .collect();
        let prepared = self
            .compiler
            .prepare_function(compiled, entry, Some(constants))?;
        self.timing.since(Phase::FunctionReflect, start);
        for constant in prepared.reflection.constants() {
            match indexed.iter().find(|(index, _)| *index == constant.index) {
                Some((_, value)) => ensure(
                    value.data_type == constant.data_type && constant.accepts(&value.value),
                    "a function constant value of another type",
                )?,
                None => ensure(
                    !constant.required,
                    "a required function constant has no value",
                )?,
            }
        }
        self.hold_function(library, prepared, &kept)
    }

    fn hold_function(
        &mut self,
        library: LibraryId,
        prepared: PreparedFunction,
        kept: &Kept,
    ) -> Result<FunctionId> {
        prepared.reflection.validate()?;
        if prepared.reflection.command_barriers() {
            self.note_command_barriers();
        }
        let function = FunctionObject {
            library,
            prepared,
            users: Users::CREATED,
            bicubic: false,
            alias: None,
        };
        self.keep(kept)?;
        Ok(FunctionId(self.pipelines.functions.insert(function)))
    }

    /// `MTLFunctionDescriptor.specializedName`: the function's name, by
    /// which pipelines linking a visible function resolve its calls.
    pub fn name_function(&mut self, id: FunctionId, name: &str) -> Result<()> {
        let function = self.pipelines.functions.get_mut(id.0)?;
        let visible = matches!(function.prepared.reflection, Reflection::Visible { .. });
        if visible && !name.is_empty() && name != function.prepared.entry() {
            function.alias = Some(String::from(name));
        }
        Ok(())
    }

    /// Lets the samplers `id` takes as arguments filter bicubically, as its
    /// process now makes bicubic samplers: the pipelines made from it next
    /// carry bicubic filtering for them, and for the samplers bound to their
    /// mesh draws and GPU-encoded commands, which run no variants.
    pub fn admit_bicubic(&mut self, id: FunctionId) -> Result<()> {
        self.pipelines.functions.get_mut(id.0)?.bicubic = true;
        Ok(())
    }

    /// Whether `id`'s process has made bicubic or pixel-coordinate
    /// samplers, which the samplers it takes as arguments may then be.
    fn admitted(&self, id: FunctionId) -> Result<bool> {
        Ok(self.pipelines.functions.get(id.0)?.bicubic)
    }

    /// After [`Self::admit_bicubic`] of `functions`: their pipelines made
    /// before compile again on their next use, as variants that read each
    /// argument sampler's flags, so draws and dispatches do not depend on
    /// the order samplers and pipelines were made. GPU-encoded commands and
    /// a mesh pipeline's fragment stage keep what they were compiled with,
    /// which is reported once.
    pub fn outdate_pipelines(&mut self, functions: &[FunctionId]) {
        let mut kept = false;
        for render in self.pipelines.render.iter_mut() {
            let uses = |id: &FunctionId| functions.contains(id);
            if let Some(request) = &render.request {
                if uses(&request.vertex_function)
                    || request.fragment_function.is_some_and(|f| uses(&f))
                {
                    render.state.outdated = true;
                    kept |= render.state.indirect.is_some();
                }
            } else if let Some(mesh) = &render.mesh
                && (uses(&mesh.mesh) || mesh.object.is_some_and(|f| uses(&f)))
            {
                kept |= render.fragment.is_some();
            }
        }
        kept |= self.pipelines.compute.iter().any(|compute| {
            functions.contains(&compute.function) && compute.state.indirect.is_some()
        });
        if kept {
            self.unsupported(
                "bicubic or pixel-coordinate samplers taken as arguments by GPU-encoded \
                 commands or mesh fragment stages of pipelines made before their process's \
                 first one, which filter them linearly with normalized coordinates",
            );
        }
    }

    /// The interface of a function that becomes a pipeline stage.
    pub fn function_interface(&self, id: FunctionId) -> Result<&Interface> {
        self.pipelines.interface(id)
    }

    /// The entry point a function was made from.
    pub fn function_entry(&self, id: FunctionId) -> Result<&str> {
        Ok(self.pipelines.functions.get(id.0)?.prepared.entry())
    }

    /// The name pipelines link a function by: its specialized name, or
    /// its entry.
    pub fn function_name(&self, id: FunctionId) -> Result<&str> {
        let function = self.pipelines.functions.get(id.0)?;
        Ok(function
            .alias
            .as_deref()
            .unwrap_or(function.prepared.entry()))
    }

    /// What the compiler reflects of a function.
    pub fn function_reflection(&self, id: FunctionId) -> Result<&Reflection> {
        Ok(&self.pipelines.functions.get(id.0)?.prepared.reflection)
    }

    /// The SHA-256 of a function's AIR module, its `bitCodeHash`.
    pub fn function_slice_hash(&self, id: FunctionId) -> Result<[u8; 32]> {
        Ok(self
            .pipelines
            .functions
            .get(id.0)?
            .prepared
            .provenance
            .slice_hash)
    }

    /// The bindings of a function specialized with its function constant
    /// values, for `MTLPipelineOptionBindingInfo` and argument encoders.
    pub fn function_bindings(&mut self, id: FunctionId) -> Result<Vec<Binding>> {
        let function = self.pipelines.functions.get(id.0)?;
        let library = self.pipelines.library(function.library)?;
        let specialization = Specialization {
            constants: function.prepared.constants.clone(),
            ..Specialization::default()
        };
        let specialization = function.prepared.specialized.then_some(&specialization);
        self.compiler
            .bindings(library, function.prepared.entry(), specialization)
    }

    pub fn function_type(&self, id: FunctionId) -> Result<FunctionType> {
        Ok(self
            .pipelines
            .functions
            .get(id.0)?
            .prepared
            .reflection
            .function_type())
    }

    /// Ends the creator's use of a function, which goes with the last
    /// pipeline using it.
    pub fn destroy_function(&mut self, id: FunctionId) -> Result<()> {
        let users = &mut self.pipelines.functions.get_mut(id.0)?.users;
        ensure(users.creator, DESTROYED)?;
        users.creator = false;
        self.collect_function(id)
    }

    fn collect_function(&mut self, id: FunctionId) -> Result<()> {
        if self.pipelines.functions.get(id.0)?.users.none() {
            let function = self.pipelines.functions.remove(id.0)?;
            self.release(Kept::library(function.library))?;
        }
        Ok(())
    }

    /// Adds a use of each of `kept`'s functions and libraries.
    fn keep(&mut self, kept: &Kept) -> Result<()> {
        for &id in &kept.functions {
            self.pipelines.functions.get_mut(id.0)?.users.others += 1;
        }
        for &id in &kept.libraries {
            self.pipelines.libraries.get_mut(id.0)?.users.others += 1;
        }
        for &id in &kept.archives {
            self.pipelines.archives.get_mut(id.0)?.users.others += 1;
        }
        Ok(())
    }

    /// Ends a use of each of `kept`'s functions and libraries.
    fn release(&mut self, kept: Kept) -> Result<()> {
        for id in kept.functions {
            self.pipelines.functions.get_mut(id.0)?.users.others -= 1;
            self.collect_function(id)?;
        }
        for id in kept.libraries {
            self.pipelines.libraries.get_mut(id.0)?.users.others -= 1;
            self.collect_library(id)?;
        }
        for id in kept.archives {
            self.pipelines.archives.get_mut(id.0)?.users.others -= 1;
            self.collect_archive(id)?;
        }
        Ok(())
    }

    /// `specialization` of function `id`, with its function constant values
    /// and the samplers of the constexpr sampler states it and its linking
    /// declare.
    fn specialize(
        &mut self,
        id: FunctionId,
        specialization: Specialization,
    ) -> Result<Specialization> {
        let function = self.pipelines.functions.get(id.0)?;
        let library = self.pipelines.library(function.library)?;
        let mut linking = specialization.linking;
        let held = self.pipelines.libraries.get(function.library.0)?;
        let preloaded = if held.preloads {
            held.dependencies.as_slice()
        } else {
            &[]
        };
        for &dependency in preloaded {
            let dependency = self.pipelines.library(dependency)?;
            if !linking.libraries.contains(&dependency) {
                linking.libraries.push(dependency);
            }
        }
        let specialization = Specialization {
            constants: function.prepared.constants.clone(),
            linking,
            round_toward_zero: held.round_toward_zero,
            ..specialization
        };
        let samplers = self
            .compiler
            .sampler_states(library, function.prepared.entry(), &specialization)?
            .into_iter()
            .map(|state| Ok((state, self.constexpr_sampler(state)?.0)))
            .collect::<Result<_>>()?;
        Ok(Specialization {
            samplers,
            ..specialization
        })
    }

    fn compile(
        &mut self,
        id: FunctionId,
        specialization: Specialization,
    ) -> Result<CompiledShader> {
        let stage = self.pipelines.interface(id)?.stage;
        let start = self.timing.now();
        let specialization = self.specialize(id, specialization)?;
        let start = self.timing.since(Phase::PipelineSpecialize, start);
        let function = self.pipelines.functions.get(id.0)?;
        let specialization = Specialization {
            bicubic_arguments: function.bicubic,
            ..specialization
        };
        let compiled = self
            .compiler
            .compile_prepared(&function.prepared, &specialization);
        let phase = match stage {
            Stage::Fragment => Phase::PipelineFragment,
            _ => Phase::PipelineVertex,
        };
        // A variant a commit's replay needs compiles inside the commit.
        let phase = if self.timing.timing(Timed::Commit) {
            Phase::CommitCompile
        } else {
            phase
        };
        self.timing.since(phase, start);
        let compiled = compiled?;
        if compiled.interface.stage != stage {
            self.compiler.release(compiled.code);
            return Err(Error::Invalid("the compiler changed the function's stage"));
        }
        Ok(compiled)
    }

    fn compile_tessellation(
        &mut self,
        id: FunctionId,
        specialization: Specialization,
        tessellation: &Tessellation,
    ) -> Result<TessellationStages> {
        let expected = self
            .pipelines
            .interface(id)
            .map(|interface| (interface.stage, interface.patch))?;
        let start = self.timing.now();
        let specialization = self.specialize(id, specialization)?;
        let start = self.timing.since(Phase::PipelineSpecialize, start);
        let function = self.pipelines.functions.get(id.0)?;
        let specialization = Specialization {
            bicubic_arguments: function.bicubic,
            ..specialization
        };
        let stages = self.compiler.compile_prepared_tessellation(
            &function.prepared,
            &specialization,
            tessellation,
        );
        self.timing.since(Phase::PipelineVertex, start);
        let stages = stages?;
        let interface = &stages.evaluation.interface;
        if (interface.stage, interface.patch) != expected {
            for code in [stages.vertex, stages.control, stages.evaluation.code] {
                self.compiler.release(code);
            }
            return Err(Error::Invalid("the compiler changed the function's patch"));
        }
        Ok(stages)
    }

    /// The device's compiler, for the platform's service to configure.
    pub fn compiler_mut(&mut self) -> &mut C {
        &mut self.compiler
    }

    /// Whether the call deferred a compilation or a pipeline creation, so
    /// that it fails now and runs again once that is done.
    pub fn deferred(&self) -> bool {
        self.compiler.deferred() || self.backend.deferred()
    }

    /// Compiles and creates pipelines in the call from here on: the call
    /// changed what a second run would change again.
    pub fn stop_deferring(&mut self) {
        self.compiler.stop_deferring();
        self.backend.stop_deferring();
    }

    /// `newRenderPipelineStateWithDescriptor:`. A post-tessellation vertex
    /// function compiles with the stages that feed it.
    pub fn new_render_pipeline(
        &mut self,
        request: &RenderPipelineRequest,
    ) -> Result<RenderPipelineId> {
        if self.timing.timing(Timed::NewRenderPipeline) {
            let entry = |id| Name::new(self.function_entry(id).unwrap_or("?"));
            let detail = Detail::Pipeline {
                vertex: entry(request.vertex_function),
                fragment: request.fragment_function.map(entry),
            };
            self.timing.detail(Timed::NewRenderPipeline, detail);
        }
        let kept = Kept::new(
            [request.vertex_function]
                .into_iter()
                .chain(request.fragment_function),
            [
                &request.vertex_linked_functions,
                &request.fragment_linked_functions,
            ],
        )
        .with_archives(&request.archives);
        self.pipelines.ensure_created(&kept)?;
        let sources = self.pipelines.sources(&request.archives)?;
        let vertex_linked = self.link(&request.vertex_linked_functions, true)?;
        let fragment_linked = self.link(&request.fragment_linked_functions, true)?;
        let linkings = [&vertex_linked.linking, &fragment_linked.linking];
        let generated = self.backend.physical_device().limits.generated_commands;
        let indirect_bindable = request.support_indirect_command_buffers && generated.is_some();
        // GPU-encoded commands bind no variants: the pipeline reads each
        // sampler's filter once its process has bicubic samplers.
        let bicubic = if indirect_bindable {
            [
                self.dynamic_bicubic(Some(request.vertex_function))?,
                self.dynamic_bicubic(request.fragment_function)?,
            ]
        } else {
            [0; 2]
        };
        let (vulkan, plan, interfaces) =
            self.create_render(request, linkings, &sources, bicubic, indirect_bindable)?;
        self.tests_fragments |= plan.tests_fragments;
        let indirect = if plan.info.indirect_bindable {
            match self.add_indirect_render(&plan, &interfaces, vulkan) {
                Ok(indirect) => Some(indirect),
                Err(error) => {
                    self.defer(Object::Pipeline(vulkan));
                    return Err(error);
                }
            }
        } else {
            None
        };
        self.keep(&kept)?;
        let index = self.pipelines.render.insert(RenderObject {
            kept,
            state: RenderPipelineState {
                id: 0,
                pipeline: Some(vulkan),
                plan,
                interfaces,
                indirect,
                bicubic,
                outdated: false,
            },
            linked: alloc::vec![
                (Stage::Vertex, vertex_linked),
                (Stage::Fragment, fragment_linked)
            ],
            sources: Sources::default(),
            fragment: None,
            mesh: None,
            variants: Vec::new(),
            request: Some(request.clone()),
            bicubic: Vec::new(),
        });
        self.pipelines.render.get_mut(index)?.state.id = u64::from(index);
        Ok(RenderPipelineId(index))
    }

    /// [`Specialization::bicubic_samplers`] of a pipeline stage whose
    /// commands bind no variants: every sampler, once the function's
    /// process has made bicubic samplers.
    fn dynamic_bicubic(&self, function: Option<FunctionId>) -> Result<u32> {
        Ok(match function {
            Some(id) if self.pipelines.functions.get(id.0)?.bicubic => DYNAMIC_BICUBIC,
            _ => 0,
        })
    }

    /// Compiles a vertex pipeline whose vertex and fragment functions filter
    /// the samplers at `bicubic` bicubically. A post-tessellation vertex
    /// function compiles with the stages that feed it.
    fn create_render(
        &mut self,
        request: &RenderPipelineRequest,
        [vertex_linking, fragment_linking]: [&Linking; 2],
        sources: &Sources,
        [vertex_bicubic, fragment_bicubic]: [u32; 2],
        indirect_bindable: bool,
    ) -> Result<(Pipeline, RenderPipelinePlan, Vec<Interface>)> {
        let pipelines = &self.pipelines;
        let function = pipelines.interface(request.vertex_function)?;
        let fragment_function = request
            .fragment_function
            .map(|id| pipelines.interface(id))
            .transpose()?;
        let varyings = pipeline::link_varyings(function, fragment_function)?;
        let storage_attachments = fragment_function
            .map(|fragment| {
                pipeline::storage_attachments(&self.capabilities, fragment, &request.targets)
            })
            .transpose()?
            .unwrap_or_default();
        let self_tests = storage_attachments.iter().any(Option::is_some)
            && fragment_function
                .is_some_and(|fragment| !pipeline::tests_first(fragment, &request.targets));
        let tessellation = pipeline::tessellation(
            &self.capabilities,
            function,
            &request.tessellation,
            request.vertex_descriptor.as_ref(),
        )?;
        // The evaluation stage of a tessellated pipeline fetches its
        // stage-in itself; a vertex input fetches the rest.
        let vertex_words = match (&tessellation, &request.vertex_descriptor) {
            (None, Some(layout)) => vertex::word_formats(&self.capabilities, layout),
            _ => Default::default(),
        };
        let specialization = Specialization {
            amplified: request.max_vertex_amplification_count > 1,
            varyings: varyings.clone(),
            linking: vertex_linking.clone(),
            vertex_words,
            bicubic_samplers: vertex_bicubic,
            ..Specialization::default()
        };
        let (vertex, feeding) = match &tessellation {
            Some(tessellation) => {
                let stages = self.compile_tessellation(
                    request.vertex_function,
                    specialization,
                    tessellation,
                )?;
                (stages.evaluation, Some([stages.vertex, stages.control]))
            }
            None => (self.compile(request.vertex_function, specialization)?, None),
        };
        let mut codes: Vec<ShaderCode> = feeding.into_iter().flatten().collect();
        codes.push(vertex.code);
        let targets = &request.targets;
        let linked = Specialization {
            varyings,
            linking: fragment_linking.clone(),
            storage_attachments,
            samples: targets.raster_sample_count as u32,
            extended_range: pipeline::extended_range_attachments(targets),
            self_tests,
            alpha_to_coverage: targets.alpha_to_coverage_enabled,
            alpha_to_one: targets.alpha_to_one_enabled,
            bicubic_samplers: fragment_bicubic,
            ..Specialization::default()
        };
        let fragment = match request.fragment_function {
            Some(id) => match self.compile(id, linked) {
                Ok(fragment) => Some(fragment),
                Err(error) => {
                    codes.iter().for_each(|code| self.compiler.release(*code));
                    return Err(error);
                }
            },
            None => None,
        };
        codes.extend(fragment.as_ref().map(|shader| shader.code));
        let descriptor = RenderPipelineDescriptor {
            vertex_function: &vertex,
            fragment_function: fragment.as_ref(),
            vertex_descriptor: request.vertex_descriptor.as_ref(),
            targets: request.targets,
            input_primitive_topology: request.input_primitive_topology,
            max_vertex_amplification_count: request.max_vertex_amplification_count,
            tessellation: tessellation.as_ref().zip(feeding).map(
                |(tessellation, [vertex, control])| TessellatedVertex {
                    tessellation,
                    vertex,
                    control,
                },
            ),
        };
        // The driver compiles the NIR into the pipeline, which outlives it.
        let start = self.timing.now();
        let created =
            pipeline::render_pipeline(&self.capabilities, &descriptor).and_then(|mut plan| {
                let start = self.timing.since(Phase::PipelinePlan, start);
                plan.info.indirect_bindable = indirect_bindable;
                let pipeline = self.create_from(sources, |backend, source| {
                    plan.info.source = source;
                    backend.create_graphics_pipeline(&plan.info)
                });
                self.timing.since(Phase::PipelineCreate, start);
                Ok((pipeline?, plan))
            });
        codes.iter().for_each(|code| self.compiler.release(*code));
        let (vulkan, plan) = created?;
        let interfaces = core::iter::once(vertex.interface)
            .chain(fragment.map(|shader| shader.interface))
            .collect();
        Ok((vulkan, plan, interfaces))
    }

    /// `newRenderPipelineStateWithMeshDescriptor:`; object and mesh stages
    /// compile per threadgroup size when drawn.
    pub fn new_mesh_render_pipeline(
        &mut self,
        request: &MeshPipelineRequest,
    ) -> Result<RenderPipelineId> {
        let kept = Kept::new(
            request
                .object_function
                .into_iter()
                .chain([request.mesh_function])
                .chain(request.fragment_function),
            [
                &request.object_linked_functions,
                &request.mesh_linked_functions,
                &request.fragment_linked_functions,
            ],
        )
        .with_archives(&request.archives);
        self.pipelines.ensure_created(&kept)?;
        let sources = self.pipelines.sources(&request.archives)?;
        let linked = [
            (Stage::Object, &request.object_linked_functions),
            (Stage::Mesh, &request.mesh_linked_functions),
            (Stage::Fragment, &request.fragment_linked_functions),
        ]
        .into_iter()
        .map(|(stage, functions)| Ok((stage, self.link(functions, true)?)))
        .collect::<Result<Vec<_>>>()?;
        let pipelines = &self.pipelines;
        let fragment_function = request
            .fragment_function
            .map(|id| pipelines.interface(id))
            .transpose()?;
        let varyings = pipeline::link_varyings(
            pipelines.interface(request.mesh_function)?,
            fragment_function,
        )?;
        let storage_attachments = fragment_function
            .map(|fragment| {
                pipeline::storage_attachments(&self.capabilities, fragment, &request.targets)
            })
            .transpose()?
            .unwrap_or_default();
        let self_tests = storage_attachments.iter().any(Option::is_some)
            && fragment_function
                .is_some_and(|fragment| !pipeline::tests_first(fragment, &request.targets));
        let fragment = match request.fragment_function {
            Some(id) => {
                let targets = &request.targets;
                let specialization = Specialization {
                    varyings: varyings.clone(),
                    linking: linked[2].1.linking.clone(),
                    storage_attachments,
                    samples: targets.raster_sample_count as u32,
                    extended_range: pipeline::extended_range_attachments(targets),
                    self_tests,
                    alpha_to_coverage: targets.alpha_to_coverage_enabled,
                    alpha_to_one: targets.alpha_to_one_enabled,
                    // Mesh draws bind no bicubic variants.
                    bicubic_samplers: self.dynamic_bicubic(Some(id))?,
                    ..Specialization::default()
                };
                Some(self.compile(id, specialization)?)
            }
            None => None,
        };
        let pipelines = &self.pipelines;
        let object = request
            .object_function
            .map(|id| pipelines.interface(id))
            .transpose()?;
        let mesh = pipelines.interface(request.mesh_function)?;
        let descriptor = MeshRenderPipelineDescriptor {
            object_function: object,
            mesh_function: mesh,
            fragment_function: fragment.as_ref(),
            targets: request.targets,
            max_vertex_amplification_count: request.max_vertex_amplification_count,
            object_threads: request.object_threads,
            mesh_threads: request.mesh_threads,
            payload_memory_length: request.payload_memory_length,
        };
        let interfaces: Vec<Interface> = object
            .into_iter()
            .chain([mesh])
            .cloned()
            .chain(fragment.as_ref().map(|shader| shader.interface.clone()))
            .collect();
        let plan = match pipeline::mesh_render_pipeline(&self.capabilities, &descriptor) {
            Ok(plan) => plan,
            Err(error) => {
                if let Some(fragment) = &fragment {
                    self.compiler.release(fragment.code);
                }
                return Err(error);
            }
        };
        self.tests_fragments |= plan.tests_fragments;
        self.keep(&kept)?;
        let index = self.pipelines.render.insert(RenderObject {
            kept,
            state: RenderPipelineState {
                id: 0,
                pipeline: None,
                plan,
                interfaces,
                indirect: None,
                bicubic: [0; 2],
                outdated: false,
            },
            linked,
            sources: sources.clone(),
            fragment: fragment.map(|shader| shader.code),
            mesh: Some(MeshFunctions {
                object: request.object_function,
                mesh: request.mesh_function,
                varyings,
            }),
            variants: Vec::new(),
            request: None,
            bicubic: Vec::new(),
        });
        let id = RenderPipelineId(index);
        let render = self.pipelines.render.get_mut(index)?;
        render.state.id = u64::from(index);
        let threads = render.state.plan.mesh;
        if let Some(threads) = threads.filter(|_| sources.compiles_at_creation()) {
            let (object, mesh) = threads.smallest();
            if let Err(error) = self.mesh_variant(u64::from(index), object, mesh, &[]) {
                self.destroy_render_pipeline(id)?;
                return Err(error);
            }
        }
        self.pipelines.render.get_mut(index)?.sources = sources.of_variants();
        Ok(id)
    }

    pub fn render_pipeline_state(&self, id: RenderPipelineId) -> Result<&RenderPipelineState> {
        Ok(&self.pipelines.render.get(id.0)?.state)
    }

    /// The vertex pipeline whose vertex and fragment stages filter the
    /// samplers at `bicubic` bicubically, for draws binding bicubic samplers
    /// there; compiled on first use.
    pub(super) fn render_variant(&mut self, id: u64, bicubic: [u32; 2]) -> Result<Pipeline> {
        let index = u32::try_from(id).map_err(|_| Error::Invalid("unknown pipeline"))?;
        let render = self.pipelines.render.get(index)?;
        if bicubic == render.state.bicubic
            && !render.state.outdated
            && let Some(pipeline) = render.state.pipeline
        {
            return Ok(pipeline);
        }
        let request = render
            .request
            .clone()
            .ok_or(Error::Invalid("not a vertex pipeline"))?;
        let arguments = self.admitted(request.vertex_function)?;
        if let Some((_, _, pipeline)) = render
            .bicubic
            .iter()
            .find(|(known, admitted, _)| *known == bicubic && *admitted == arguments)
        {
            return Ok(*pipeline);
        }
        let linking = |stage| {
            render
                .linked(stage)
                .map(|linked| linked.linking.clone())
                .unwrap_or_default()
        };
        let linkings = [linking(Stage::Vertex), linking(Stage::Fragment)];
        let (pipeline, _, _) = self.create_render(
            &request,
            [&linkings[0], &linkings[1]],
            &Sources::default(),
            bicubic,
            false,
        )?;
        self.pipelines
            .render
            .get_mut(index)?
            .bicubic
            .push((bicubic, arguments, pipeline));
        Ok(pipeline)
    }

    /// The mesh pipeline for one draw's threadgroup sizes.
    pub(super) fn mesh_variant(
        &mut self,
        id: u64,
        object_threads: [u32; 3],
        mesh_threads: [u32; 3],
        object_lengths: &[(u32, u64)],
    ) -> Result<Pipeline> {
        let index = u32::try_from(id).map_err(|_| Error::Invalid("unknown pipeline"))?;
        let render = self.pipelines.render.get(index)?;
        let key = (object_threads, mesh_threads, object_lengths.to_vec());
        let functions = render
            .mesh
            .as_ref()
            .ok_or(Error::Invalid("not a mesh pipeline"))?;
        let arguments = self.admitted(functions.mesh)?;
        if let Some((_, _, pipeline)) = render
            .variants
            .iter()
            .find(|(known, admitted, _)| *known == key && *admitted == arguments)
        {
            return Ok(*pipeline);
        }
        let (object, mesh, varyings) =
            (functions.object, functions.mesh, functions.varyings.clone());
        let linking = |stage| {
            render
                .linked(stage)
                .map(|linked| linked.linking.clone())
                .unwrap_or_default()
        };
        let linkings = [linking(Stage::Object), linking(Stage::Mesh)];
        let plan = &render.state.plan;
        plan.mesh
            .ok_or(Error::Invalid("not a mesh pipeline"))?
            .check(object_threads, mesh_threads)?;
        let sources = render.sources.clone();
        let mut info = plan.info.clone();
        let mut stages = Vec::new();
        let mut codes = Vec::new();
        // The first stage is the one mesh draws launch; the mesh function
        // links to the fragment function.
        let [object_linking, mesh_linking] = linkings;
        for (function, threads, stage, varyings, linking, threadgroup_lengths) in [
            (
                object,
                object_threads,
                Stage::Object,
                Vec::new(),
                object_linking,
                object_lengths.to_vec(),
            ),
            (
                Some(mesh),
                mesh_threads,
                Stage::Mesh,
                varyings,
                mesh_linking,
                Vec::new(),
            ),
        ] {
            let Some(function) = function else { continue };
            let specialization = Specialization {
                workgroup_size: Some(threads),
                varyings,
                launched_by_grid: stage == Stage::Object || object.is_none(),
                linking,
                threadgroup_lengths,
                bicubic_samplers: self.dynamic_bicubic(Some(function))?,
                ..Specialization::default()
            };
            match self.compile(function, specialization) {
                Ok(compiled) => {
                    codes.push(compiled.code);
                    stages.push((stage.vulkan(), compiled.code));
                }
                Err(error) => {
                    codes.iter().for_each(|code| self.compiler.release(*code));
                    return Err(error);
                }
            }
        }
        stages.extend(info.stages);
        info.stages = stages;
        let pipeline = self.create_from(&sources, |backend, source| {
            info.source = source;
            backend.create_graphics_pipeline(&info)
        });
        codes
            .into_iter()
            .for_each(|code| self.compiler.release(code));
        let pipeline = pipeline?;
        self.pipelines
            .render
            .get_mut(index)?
            .variants
            .push((key, arguments, pipeline));
        Ok(pipeline)
    }

    /// `gpuResourceID`: the handle GPU-resident indirect commands name the
    /// pipeline by, or zero when they cannot switch to it.
    pub fn render_pipeline_resource_id(&self, id: RenderPipelineId) -> Result<u64> {
        let state = &self.pipelines.render.get(id.0)?.state;
        Ok(state.indirect.map_or(0, |indirect| indirect.handle()))
    }

    pub fn destroy_render_pipeline(&mut self, id: RenderPipelineId) -> Result<()> {
        let render = self.pipelines.render.remove(id.0)?;
        let pipeline = match (render.state.indirect, render.state.pipeline) {
            (Some(indirect), Some(pipeline)) => self.remove_indirect(indirect, pipeline)?,
            (_, pipeline) => pipeline,
        };
        let variants = render.variants.into_iter().map(|(_, _, pipeline)| pipeline);
        let bicubic = render.bicubic.into_iter().map(|(_, _, pipeline)| pipeline);
        for pipeline in pipeline.into_iter().chain(variants).chain(bicubic) {
            self.defer(Object::Pipeline(pipeline));
        }
        if let Some(code) = render.fragment {
            self.compiler.release(code);
        }
        self.release(render.kept)
    }

    /// `newComputePipelineStateWithDescriptor:`; variants compile per
    /// dispatch shape.
    pub fn new_compute_pipeline(
        &mut self,
        request: &ComputePipelineRequest,
    ) -> Result<ComputePipelineId> {
        self.compute_object(request, None)
    }

    /// `newRenderPipelineStateWithTileDescriptor:`: a kernel run on the
    /// tiles of `target`'s passes, whose variants compile per dispatch's
    /// threads per tile.
    pub fn new_tile_pipeline(
        &mut self,
        request: &ComputePipelineRequest,
        target: TileTarget,
    ) -> Result<ComputePipelineId> {
        ensure(
            request.stage_input.is_none() && !request.support_indirect_command_buffers,
            "tile pipelines take no stage input or indirect commands",
        )?;
        self.compute_object(request, Some(target))
    }

    /// A tile pipeline's kernel and pass.
    pub fn tile_pipeline_state(
        &self,
        id: ComputePipelineId,
    ) -> Result<(&ComputePipelineState, TileTarget)> {
        let compute = self.pipelines.compute.get(id.0)?;
        let tile = compute
            .tile
            .ok_or(Error::Invalid("the pipeline state is not a tile pipeline"))?;
        Ok((&compute.state, tile))
    }

    fn compute_object(
        &mut self,
        request: &ComputePipelineRequest,
        tile: Option<TileTarget>,
    ) -> Result<ComputePipelineId> {
        let function = request.compute_function;
        let kept =
            Kept::new([function], [&request.linked_functions]).with_archives(&request.archives);
        self.pipelines.ensure_created(&kept)?;
        let sources = self.pipelines.sources(&request.archives)?;
        let mut linked = self.link(&request.linked_functions, false)?;
        // A stitched kernel's calls link the functions it stitches.
        let library = self.pipelines.functions.get(function.0)?.library;
        let stitched = &self.pipelines.libraries.get(library.0)?.stitched;
        linked.linking.private_functions.extend_from_slice(stitched);
        let interface = self.pipelines.interface(function)?.clone();
        let descriptor = ComputePipelineDescriptor {
            compute_function: &interface,
            threadgroup_size_is_multiple_of_thread_execution_width: request
                .threadgroup_size_is_multiple_of_thread_execution_width,
            max_total_threads_per_threadgroup: request.max_total_threads_per_threadgroup,
            stage_input: request.stage_input.as_ref(),
        };
        let plan = pipeline::compute_pipeline(&self.capabilities, &descriptor)?;
        let generated = self.backend.physical_device().limits.generated_commands;
        let bindable =
            generated.is_some_and(|limits| limits.pipeline_stages.contains(ShaderStages::COMPUTE));
        let subgroups = (plan.thread_execution_width as u32, plan.full_subgroups);
        // A tile pipeline compiles for the largest square of threads its
        // limit holds, when one does.
        let variant = match &tile {
            None => Some(pipeline::indirect_compute_variant(&plan)),
            Some(target) => pipeline::tile_creation_variant(&plan, target),
        };
        let variant = variant.map(|variant| Specialization {
            linking: linked.linking.clone(),
            ..variant
        });
        if let Some(variant) = variant.clone().filter(|_| sources.compiles_at_creation()) {
            let pipeline =
                self.create_compute_variant(function, subgroups, variant, false, &sources)?;
            self.defer(Object::Pipeline(pipeline));
        }
        // Tile pipelines take no indirect commands, so a compute variant is here.
        let indirect = if let Some(variant) =
            variant.filter(|_| request.support_indirect_command_buffers && bindable)
        {
            // GPU-encoded dispatches bind no variants.
            let variant = Specialization {
                bicubic_samplers: self.dynamic_bicubic(Some(function))?,
                ..variant
            };
            let pipeline =
                self.create_compute_variant(function, subgroups, variant, true, &sources)?;
            match self.add_indirect_compute(pipeline) {
                Ok(place) => Some(IndirectCompute { pipeline, place }),
                Err(error) => {
                    self.defer(Object::Pipeline(pipeline));
                    return Err(error);
                }
            }
        } else {
            None
        };
        let state = ComputePipelineState {
            id: 0,
            plan,
            interface,
            indirect,
        };
        self.keep(&kept)?;
        let index = self.pipelines.compute.insert(ComputeObject {
            kept,
            state,
            function,
            linked,
            sources: sources.of_variants(),
            variants: Vec::new(),
            tile,
        });
        self.pipelines.compute.get_mut(index)?.state.id = u64::from(index);
        Ok(ComputePipelineId(index))
    }

    pub fn compute_pipeline_state(&self, id: ComputePipelineId) -> Result<&ComputePipelineState> {
        Ok(&self.pipelines.compute.get(id.0)?.state)
    }

    /// `gpuResourceID`: the handle GPU-resident indirect commands name the
    /// pipeline by, or zero when they cannot switch to it.
    pub fn compute_pipeline_resource_id(&self, id: ComputePipelineId) -> Result<u64> {
        let state = &self.pipelines.compute.get(id.0)?.state;
        Ok(state.indirect.map_or(0, |indirect| indirect.place.handle()))
    }

    /// The compute pipeline for one dispatch's specialization.
    pub(super) fn compute_variant(
        &mut self,
        id: u64,
        specialization: &Specialization,
    ) -> Result<Pipeline> {
        let index = u32::try_from(id).map_err(|_| Error::Invalid("unknown pipeline"))?;
        let compute = self.pipelines.compute.get(index)?;
        // Variants compiled before the process made bicubic or
        // pixel-coordinate samplers read no argument sampler's flags.
        let specialization = &Specialization {
            bicubic_arguments: self.admitted(compute.function)?,
            ..specialization.clone()
        };
        if let Some((_, pipeline)) = compute
            .variants
            .iter()
            .find(|(known, _)| known == specialization)
        {
            return Ok(*pipeline);
        }
        let plan = &compute.state.plan;
        let (function, subgroups) = (
            compute.function,
            (plan.thread_execution_width as u32, plan.full_subgroups),
        );
        let linked = Specialization {
            linking: compute.linked.linking.clone(),
            ..specialization.clone()
        };
        let sources = compute.sources.clone();
        let pipeline = self.create_compute_variant(function, subgroups, linked, false, &sources)?;
        self.pipelines
            .compute
            .get_mut(index)?
            .variants
            .push((specialization.clone(), pipeline));
        Ok(pipeline)
    }

    /// Compiles `function`, linked, into a compute pipeline of its
    /// `(thread execution width, full subgroups)`.
    fn create_compute_variant(
        &mut self,
        function: FunctionId,
        (width, full_subgroups): (u32, bool),
        specialization: Specialization,
        indirect_bindable: bool,
        sources: &Sources,
    ) -> Result<Pipeline> {
        let compiled = self.compile(function, specialization)?;
        let mut info = ComputePipelineInfo {
            code: compiled.code,
            required_subgroup_size: width,
            full_subgroups,
            indirect_bindable,
            source: PipelineSource::Compiled,
        };
        let pipeline = self.create_from(sources, |backend, source| {
            info.source = source;
            backend.create_compute_pipeline(&info)
        });
        self.compiler.release(compiled.code);
        pipeline
    }

    /// `functionHandleWithFunction:` of a compute pipeline: `None` when it
    /// does not link the function.
    pub fn compute_function_handle(
        &self,
        id: ComputePipelineId,
        function: FunctionId,
    ) -> Result<Option<FunctionHandle>> {
        Ok(self.pipelines.compute.get(id.0)?.linked.handle(function))
    }

    /// `functionHandleWithFunction:stage:` of a render pipeline: `None`
    /// when the stage does not link the function.
    pub fn render_function_handle(
        &self,
        id: RenderPipelineId,
        stage: Stage,
        function: FunctionId,
    ) -> Result<Option<FunctionHandle>> {
        let render = self.pipelines.render.get(id.0)?;
        Ok(render
            .linked(stage)
            .and_then(|linked| linked.handle(function)))
    }

    /// `newVisibleFunctionTableWithDescriptor:`: a shared buffer of `count`,
    /// which shaders read as the table's size, then `count` function
    /// handles, each calling no function. It binds as the buffer at a table
    /// argument's index, and its address is its `gpuResourceID`.
    pub fn new_visible_function_table(&mut self, count: u64) -> Result<BufferId> {
        const INVALID: Error = Error::Invalid("visible function table size");
        let bytes = count
            .checked_add(1)
            .and_then(|words| words.checked_mul(8))
            .filter(|_| count != 0)
            .ok_or(INVALID)?;
        let mut contents = alloc::vec![0; usize::try_from(bytes).map_err(|_| INVALID)?];
        contents[..8].copy_from_slice(&count.to_le_bytes());
        self.new_shared_buffer(&contents)
    }

    /// `setFunction:atIndex:` and `setFunctions:withRange:`: writes
    /// `handles` from entry `index` of a table; `None` calls no function.
    pub fn set_visible_functions(
        &mut self,
        table: BufferId,
        index: u64,
        handles: &[Option<FunctionHandle>],
    ) -> Result<()> {
        let (memory, offset, length) = self.buffer_memory(table)?;
        let start = index.checked_add(1).and_then(|word| word.checked_mul(8));
        let end = start.and_then(|start| start.checked_add(handles.len() as u64 * 8));
        ensure(
            end.is_some_and(|end| end <= length),
            "functions past the table's end",
        )?;
        let bytes: Vec<u8> = handles
            .iter()
            .flat_map(|handle| handle.map_or(0, |handle| handle.0).to_le_bytes())
            .collect();
        self.backend
            .write_memory(memory, offset + (index + 1) * 8, &bytes)
    }

    /// Resolves a stage's linked functions, which must be visible
    /// functions; `render` stages are those of render pipelines.
    fn link(&self, linked: &LinkedFunctions, render: bool) -> Result<Linked> {
        let capabilities = &self.capabilities;
        let (function_pointers, dynamic_libraries) = if render {
            (
                capabilities.supports_function_pointers_from_render,
                capabilities.supports_render_dynamic_libraries,
            )
        } else {
            (
                capabilities.supports_function_pointers,
                capabilities.supports_dynamic_libraries,
            )
        };
        let functions = || linked.functions.iter().chain(&linked.private_functions);
        require(
            function_pointers || functions().next().is_none(),
            "function pointers",
        )?;
        require(
            dynamic_libraries || linked.libraries.is_empty(),
            "dynamic libraries",
        )?;
        for &id in functions() {
            let function = self.pipelines.functions.get(id.0)?;
            ensure(
                matches!(function.prepared.reflection, Reflection::Visible { .. }),
                "linked functions are visible functions",
            )?;
            function.specialized()?;
        }
        let entries = |ids: &[FunctionId]| -> Result<Vec<LinkedFunction>> {
            ids.iter()
                .map(|id| {
                    let function = self.pipelines.functions.get(id.0)?;
                    let mut constants = function.prepared.constants.clone();
                    constants.sort_unstable_by_key(|&(index, _)| index);
                    Ok(LinkedFunction {
                        library: self.pipelines.library(function.library)?,
                        entry: String::from(function.prepared.entry()),
                        constants,
                        alias: function.alias.clone(),
                    })
                })
                .collect()
        };
        let mut private_functions = entries(&linked.private_functions)?;
        for &id in functions() {
            let library = self.pipelines.functions.get(id.0)?.library;
            let stitched = &self.pipelines.libraries.get(library.0)?.stitched;
            private_functions.extend_from_slice(stitched);
        }
        Ok(Linked {
            functions: linked.functions.clone(),
            linking: Linking {
                functions: entries(&linked.functions)?,
                private_functions,
                libraries: linked
                    .libraries
                    .iter()
                    .map(|&id| self.pipelines.library(id))
                    .collect::<Result<_>>()?,
                max_call_stack_depth: linked.max_call_stack_depth,
            },
        })
    }

    pub fn destroy_compute_pipeline(&mut self, id: ComputePipelineId) -> Result<()> {
        let compute = self.pipelines.compute.remove(id.0)?;
        let indirect = match compute.state.indirect {
            Some(indirect) => self.remove_indirect(indirect.place, indirect.pipeline)?,
            None => None,
        };
        let variants = compute.variants.into_iter().map(|(_, pipeline)| pipeline);
        for pipeline in indirect.into_iter().chain(variants) {
            self.defer(Object::Pipeline(pipeline));
        }
        self.release(compute.kept)
    }
}
