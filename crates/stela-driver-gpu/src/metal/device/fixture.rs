//! A device over a recording Vulkan backend and a compiler that reflects
//! functions by name, for the tests of the device and the layers above it.

use super::{Device, LibraryId};
use crate::metal::{
    abi::{DataType, FunctionType, TextureType},
    capabilities::ShaderFeatures,
    command_buffer::Segment,
    error::{Error, Result},
    library::tests::fixture,
    nvidia::{CHIPS, Chip, PcieLink, fixture::nvk},
    reflection::{
        ArrayType, Binding, BindingAccess, BindingKind, PointerType, StructMember, StructType,
        TextureReferenceType, Type,
    },
    shader::{
        Access, BufferUse, CompiledShader, Compiler, FunctionConstant, Interface, Patch,
        PatchDomain, Provenance, Reflection, Scalar, Specialization, Stage, Tessellation,
        TessellationStages, Varying, tests::interface,
    },
    stitching::StitchedGraph,
    vulkan::{
        backend::{Backend, BufferAllocation, Descriptor, Object, Requirements},
        command::BufferImageCopy,
        object::{
            Buffer, BufferInfo, BufferView, BufferViewInfo, ComputePipelineInfo, ExecutionSet,
            GraphicsPipelineInfo, Image, ImageInfo, ImageView, ImageViewInfo,
            IndirectCommandsLayout, IndirectCommandsLayoutInfo, Memory, MemoryRequest, Pipeline,
            PipelineCache, PipelineSource, QueryPool, QueryPoolInfo, Sampler, SamplerInfo,
            Semaphore, ShaderCode, SparseImageRequirements,
        },
        physical::PhysicalDevice,
    },
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    string::String,
    vec::Vec,
};
use core::num::NonZeroU64;
use stela_contracts::gate::MemoryRange;

#[derive(Default)]
pub(crate) struct MockBackend {
    pub(crate) idle_calls: usize,
    pub(crate) idle_error: Option<Error>,
    pub(crate) semaphore_error: Option<Error>,
    pub(crate) physical: Option<PhysicalDevice>,
    pub(crate) next: u64,
    pub(crate) destroyed: Vec<Object>,
    pub(crate) descriptors: Vec<(u32, Descriptor)>,
    pub(crate) graphics: Vec<GraphicsPipelineInfo>,
    pub(crate) compute: Vec<ComputePipelineInfo>,
    /// The pipelines each pipeline cache holds.
    pub(crate) caches: BTreeMap<u64, u8>,
    pub(crate) submissions: Vec<Vec<Segment>>,
    pub(crate) writes: Vec<(Memory, u64, Vec<u8>)>,
    pub(crate) invalidated: Vec<(Memory, u64, u64)>,
    /// Host memory each imported memory is, by memory.
    pub(crate) imports: BTreeMap<u64, (Vec<MemoryRange>, NonZeroU64)>,
    pub(crate) retired: VecDeque<NonZeroU64>,
    pub(crate) semaphores: BTreeMap<u64, u64>,
    pub(crate) queries_ready: bool,
    pub(crate) layouts: Vec<IndirectCommandsLayoutInfo>,
    /// Each execution set's pipelines by index.
    pub(crate) execution_sets: BTreeMap<u64, BTreeMap<u32, Pipeline>>,
}

impl MockBackend {
    pub(crate) fn new() -> Self {
        Self {
            physical: Some(nvk(&CHIPS[0], 8 << 30)),
            ..Self::default()
        }
    }

    fn id(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    /// Finds or keeps a pipeline in the cache of `source`.
    fn source(&mut self, source: PipelineSource) -> Result<()> {
        match source {
            PipelineSource::Compiled => {}
            PipelineSource::Cached(cache) => *self.caches.get_mut(&cache.0).unwrap() += 1,
            PipelineSource::Archived(cache) if self.caches[&cache.0] == 0 => {
                return Err(Error::NotArchived);
            }
            PipelineSource::Archived(_) => {}
        }
        Ok(())
    }

    /// Completes everything submitted so far.
    pub(crate) fn complete(&mut self, timeline: Semaphore, serial: u64) {
        self.semaphores.insert(timeline.0, serial);
    }
}

impl Backend for MockBackend {
    fn acknowledge_idle(&mut self) -> Result<()> {
        self.idle_calls += 1;
        self.idle_error.map_or(Ok(()), Err)
    }

    fn physical_device(&self) -> &PhysicalDevice {
        self.physical.as_ref().unwrap()
    }
    fn allocate_memory(&mut self, _: u64, _: MemoryRequest, _: u32) -> Result<Memory> {
        Ok(Memory(self.id()))
    }
    fn buffer_requirements(&mut self, info: &BufferInfo) -> Result<Requirements> {
        Ok(Requirements {
            size: info.size,
            alignment: 256,
            memory_types: u32::MAX,
        })
    }
    fn image_requirements(&mut self, info: &ImageInfo) -> Result<Requirements> {
        let size = u64::from(info.extent[0]) * u64::from(info.extent[1]) * 4;
        Ok(Requirements {
            size,
            alignment: 65536,
            memory_types: u32::MAX,
        })
    }
    fn create_buffer(&mut self, info: &BufferInfo, _: MemoryRequest) -> Result<BufferAllocation> {
        let id = self.id();
        Ok(BufferAllocation {
            buffer: Buffer(id),
            memory: Memory(id),
            address: id << 32,
            allocated: info.size,
        })
    }
    fn import_memory(&mut self, ranges: &[MemoryRange], token: NonZeroU64) -> Result<Memory> {
        let id = self.id();
        self.imports.insert(id, (ranges.to_vec(), token));
        Ok(Memory(id))
    }
    fn retired(&mut self) -> Option<NonZeroU64> {
        self.retired.pop_front()
    }
    fn retiring(&self) -> bool {
        !self.retired.is_empty()
    }
    fn create_placed_buffer(
        &mut self,
        _: &BufferInfo,
        _: Memory,
        offset: u64,
    ) -> Result<(Buffer, u64)> {
        let id = self.id();
        Ok((Buffer(id), (id << 32) + offset))
    }
    fn create_image(
        &mut self,
        info: &ImageInfo,
        request: MemoryRequest,
    ) -> Result<(Image, Memory, u64)> {
        let requirements = self.image_requirements(info)?;
        let memory = self.allocate_memory(requirements.size, request, u32::MAX)?;
        Ok((Image(self.id()), memory, requirements.size))
    }
    fn create_placed_image(&mut self, _: &ImageInfo, _: Memory, _: u64) -> Result<Image> {
        Ok(Image(self.id()))
    }
    /// RGBA8's standard block at the image's sample count, with each
    /// layer's tail of one block from level 2.
    fn create_sparse_image(
        &mut self,
        info: &ImageInfo,
    ) -> Result<(Image, SparseImageRequirements)> {
        let halvings = info.samples.bits().trailing_zeros();
        let requirements = SparseImageRequirements {
            memory_types: u32::MAX,
            granularity: [128 >> halvings.div_ceil(2), 128 >> (halvings / 2), 1],
            mip_tail_first_lod: 2,
            mip_tail_size: 64 << 10,
            mip_tail_offset: 1 << 20,
            mip_tail_stride: 64 << 10,
            single_mip_tail: false,
        };
        Ok((Image(self.id()), requirements))
    }
    fn create_image_view(&mut self, _: Image, _: &ImageViewInfo) -> Result<ImageView> {
        Ok(ImageView(self.id()))
    }
    fn create_buffer_view(&mut self, _: Buffer, _: &BufferViewInfo) -> Result<BufferView> {
        Ok(BufferView(self.id()))
    }
    fn create_sampler(&mut self, _: &SamplerInfo) -> Result<Sampler> {
        Ok(Sampler(self.id()))
    }
    fn create_pipeline_cache(&mut self, data: &[u8]) -> Result<PipelineCache> {
        let id = self.id();
        self.caches.insert(id, data.first().copied().unwrap_or(0));
        Ok(PipelineCache(id))
    }
    fn pipeline_cache_data(&mut self, cache: PipelineCache) -> Result<Vec<u8>> {
        Ok(alloc::vec![self.caches[&cache.0]])
    }
    fn create_graphics_pipeline(&mut self, info: &GraphicsPipelineInfo) -> Result<Pipeline> {
        self.source(info.source)?;
        self.graphics.push(info.clone());
        Ok(Pipeline(self.id()))
    }
    fn create_compute_pipeline(&mut self, info: &ComputePipelineInfo) -> Result<Pipeline> {
        self.source(info.source)?;
        self.compute.push(*info);
        Ok(Pipeline(self.id()))
    }
    fn create_query_pool(&mut self, _: &QueryPoolInfo) -> Result<QueryPool> {
        Ok(QueryPool(self.id()))
    }
    fn create_semaphore(&mut self, initial: u64) -> Result<Semaphore> {
        let id = self.id();
        self.semaphores.insert(id, initial);
        Ok(Semaphore(id))
    }
    fn create_indirect_commands_layout(
        &mut self,
        info: &IndirectCommandsLayoutInfo,
    ) -> Result<IndirectCommandsLayout> {
        self.layouts.push(info.clone());
        Ok(IndirectCommandsLayout(self.id()))
    }
    fn create_execution_set(&mut self, initial: Pipeline, _: u32) -> Result<ExecutionSet> {
        let id = self.id();
        self.execution_sets
            .insert(id, BTreeMap::from([(0, initial)]));
        Ok(ExecutionSet(id))
    }
    fn write_execution_set(&mut self, set: ExecutionSet, index: u32, pipeline: Pipeline) {
        self.execution_sets
            .get_mut(&set.0)
            .unwrap()
            .insert(index, pipeline);
    }
    fn generated_commands_requirements(
        &mut self,
        _: IndirectCommandsLayout,
        _: Option<ExecutionSet>,
        sequences: u32,
        _: MemoryRequest,
    ) -> Result<Requirements> {
        Ok(Requirements {
            size: u64::from(sequences) * 64,
            alignment: 256,
            memory_types: u32::MAX,
        })
    }
    fn destroy(&mut self, object: Object) {
        if let Object::Memory(Memory(id)) = object
            && let Some((_, token)) = self.imports.remove(&id)
        {
            self.retired.push_back(token);
        }
        self.destroyed.push(object);
    }
    fn write_descriptor(&mut self, index: u32, descriptor: Descriptor) {
        self.descriptors.push((index, descriptor));
    }
    fn write_memory(&mut self, memory: Memory, offset: u64, bytes: &[u8]) -> Result<()> {
        self.writes.push((memory, offset, bytes.to_vec()));
        Ok(())
    }
    /// Reads back the latest write to each byte.
    fn read_memory(&mut self, memory: Memory, offset: u64, bytes: &mut [u8]) -> Result<()> {
        for (written, at, data) in &self.writes {
            for (index, byte) in bytes.iter_mut().enumerate() {
                let address = offset + index as u64;
                if *written == memory && (*at..*at + data.len() as u64).contains(&address) {
                    *byte = data[(address - at) as usize];
                }
            }
        }
        Ok(())
    }
    fn flush_memory(&mut self, _: Memory, _: u64, _: u64) -> Result<()> {
        Ok(())
    }
    fn invalidate_memory(&mut self, memory: Memory, offset: u64, size: u64) -> Result<()> {
        self.invalidated.push((memory, offset, size));
        Ok(())
    }
    fn copy_to_image(&mut self, _: Image, _: &BufferImageCopy, _: &[u8]) -> Result<()> {
        Ok(())
    }
    fn copy_from_image(&mut self, _: Image, _: &BufferImageCopy, _: &mut [u8]) -> Result<()> {
        Ok(())
    }
    fn reset_queries(&mut self, _: QueryPool, _: u32, _: u32) {}
    fn query_results(&mut self, _: QueryPool, _: u32, results: &mut [u64]) -> Result<bool> {
        results
            .iter_mut()
            .enumerate()
            .for_each(|(index, result)| *result = index as u64 * 10);
        Ok(self.queries_ready)
    }
    fn semaphore_value(&mut self, semaphore: Semaphore) -> Result<u64> {
        if let Some(error) = self.semaphore_error.take() {
            return Err(error);
        }
        Ok(self.semaphores[&semaphore.0])
    }
    fn signal_semaphore(&mut self, semaphore: Semaphore, value: u64) -> Result<()> {
        self.semaphores.insert(semaphore.0, value);
        Ok(())
    }
    fn wait_semaphore(&mut self, semaphore: Semaphore, value: u64, _: u64) -> Result<bool> {
        Ok(self.semaphores[&semaphore.0] >= value)
    }
    fn submit(&mut self, segments: &[Segment]) -> Result<()> {
        self.submissions.push(segments.to_vec());
        Ok(())
    }
    fn calibrated_timestamps(&mut self) -> Result<(u64, u64)> {
        Ok((1, 2))
    }
}

/// Reflects functions by name: `"kernel"`, `"vertex"`, `"fragment"`,
/// `"object"`, `"mesh"`, the post-tessellation `"patch"`, `"unlinked"`, a
/// fragment function reading a varying nothing outputs, `"constants"`, a
/// kernel with a required and an optional function constant, and the
/// visible functions `"visible"`, `"barriers"`, whose module sets indirect
/// commands' barriers, and `"tinted"`, whose module has a function
/// constant. Library `n` is the `n`-th added, `None` once removed.
#[derive(Default)]
pub(crate) struct MockCompiler {
    pub(crate) libraries: Vec<Option<Vec<u8>>>,
    pub(crate) compiled: Vec<Specialization>,
    pub(crate) tessellations: Vec<Tessellation>,
    pub(crate) released: Vec<ShaderCode>,
}

/// Every function's bindings: uniforms holding a matrix and an array of
/// structures, an argument buffer of a texture and a buffer, and a sampler.
pub(crate) fn bound() -> Vec<Binding> {
    let member = |name: &str, offset, ty, argument_index| StructMember {
        name: String::from(name),
        offset,
        ty,
        argument_index,
    };
    let inner = StructType {
        members: alloc::vec![
            member("uv", 0, Type::Data(DataType::Float2), 0),
            member("h", 8, Type::Data(DataType::Half), 0),
        ],
    };
    let uniforms = StructType {
        members: alloc::vec![
            member("mvp", 0, Type::Data(DataType::Float4x4), 0),
            member(
                "inner",
                64,
                Type::Array(ArrayType {
                    element: Box::new(Type::Struct(inner)),
                    length: 2,
                    stride: 16,
                    argument_index_stride: 0,
                }),
                0,
            ),
        ],
    };
    let texture = TextureReferenceType {
        data_type: DataType::Float,
        texture_type: TextureType::D2,
        access: BindingAccess::ReadOnly,
        depth: false,
    };
    let arguments = StructType {
        members: alloc::vec![
            member("t", 0, Type::Texture(texture), 0),
            member(
                "d",
                8,
                Type::Pointer(PointerType {
                    element: Box::new(Type::Data(DataType::Float)),
                    access: BindingAccess::ReadWrite,
                    alignment: 4,
                    data_size: 4,
                    element_is_argument_buffer: false,
                }),
                1,
            ),
        ],
    };
    let buffer = |name: &str, index, element, alignment, data_size, argument_buffer| Binding {
        name: String::from(name),
        index,
        access: BindingAccess::ReadOnly,
        used: true,
        kind: BindingKind::Buffer(PointerType {
            element: Box::new(element),
            access: BindingAccess::ReadOnly,
            alignment,
            data_size,
            element_is_argument_buffer: argument_buffer,
        }),
    };
    alloc::vec![
        buffer("u", 0, Type::Struct(uniforms), 16, 96, false),
        buffer("args", 1, Type::Struct(arguments), 8, 16, true),
        Binding {
            name: String::from("s"),
            index: 0,
            access: BindingAccess::ReadOnly,
            used: false,
            kind: BindingKind::Sampler { array_length: 1 },
        },
    ]
}

fn reflected(entry: &str) -> Result<Interface> {
    let stage = match entry {
        "kernel" => Stage::Kernel,
        "vertex" | "patch" => Stage::Vertex,
        "fragment" | "unlinked" => Stage::Fragment,
        "object" => Stage::Object,
        "mesh" => Stage::Mesh,
        "constants" | "sampling" => Stage::Kernel,
        _ => return Err(Error::Invalid("no such function")),
    };
    let mut interface = interface(stage);
    if entry == "patch" {
        interface.patch = Some(Patch {
            domain: PatchDomain::Quad,
            control_points: Some(4),
        });
    }
    let varying = |identifier: &str, per_primitive| Varying {
        identifier: String::from(identifier),
        scalar: Scalar::Float,
        components: 4,
        per_primitive,
    };
    interface.varyings = match entry {
        "vertex" | "patch" | "fragment" => alloc::vec![varying("user(color)", false)],
        "mesh" => alloc::vec![varying("user(color)", false), varying("user(normal)", true)],
        "unlinked" => alloc::vec![varying("user(missing)", false)],
        _ => Vec::new(),
    };
    if entry == "constants" {
        let constant = |name: &str, data_type, index, required| FunctionConstant {
            name: String::from(name),
            data_type,
            index,
            required,
        };
        interface.constants = alloc::vec![
            constant("scale", DataType::UInt, 0, true),
            constant("tint", DataType::Half3, 1, false),
        ];
    }
    if stage == Stage::Kernel {
        interface.buffers = alloc::vec![BufferUse {
            index: 0,
            access: Access::READ | Access::WRITE,
            argument_buffer: false
        }];
    }
    Ok(interface)
}

impl Compiler for MockCompiler {
    fn features(&self) -> ShaderFeatures {
        ShaderFeatures::KNOWN
    }
    fn add_library(&mut self, data: Vec<u8>) -> Result<u64> {
        self.libraries.push(Some(data));
        Ok(self.libraries.len() as u64 - 1)
    }
    fn functions(&mut self, _: &[u8]) -> Result<Vec<(String, FunctionType)>> {
        Ok(alloc::vec![
            (String::from("kernel"), FunctionType::Kernel),
            (String::from("visible"), FunctionType::Visible),
        ])
    }
    fn stitch(&mut self, _: &[(u64, &str)], _: &[StitchedGraph]) -> Result<Vec<u8>> {
        Ok(b"BC\xc0\xde\0\0\0\0".to_vec())
    }
    fn library_data(&self, library: u64) -> Result<&[u8]> {
        self.libraries[library as usize]
            .as_deref()
            .ok_or(Error::Invalid("unknown library"))
    }
    fn remove_library(&mut self, library: u64) -> Result<()> {
        self.libraries[library as usize]
            .take()
            .map(drop)
            .ok_or(Error::Invalid("unknown library"))
    }
    fn reflect(&mut self, _: u64, entry: &str, _: &Specialization) -> Result<Reflection> {
        match entry {
            "visible" => Ok(Reflection::Visible {
                constants: Vec::new(),
                command_barriers: false,
            }),
            "barriers" => Ok(Reflection::Visible {
                constants: Vec::new(),
                command_barriers: true,
            }),
            "tinted" => Ok(Reflection::Visible {
                constants: alloc::vec![FunctionConstant {
                    name: String::from("tint"),
                    data_type: DataType::Float,
                    index: 0,
                    required: false,
                }],
                command_barriers: false,
            }),
            _ => reflected(entry).map(|interface| Reflection::Stage(Box::new(interface))),
        }
    }
    fn bindings(&mut self, _: u64, entry: &str, _: &Specialization) -> Result<Vec<Binding>> {
        reflected(entry).map(|_| bound())
    }
    fn sampler_states(&mut self, _: u64, entry: &str, _: &Specialization) -> Result<Vec<u64>> {
        // The default state, and filter::linear with the default's state.
        Ok(match entry {
            "sampling" => alloc::vec![0x007b_ff00_0008_0049, 0x007b_ff00_0008_0a49],
            _ => Vec::new(),
        })
    }
    fn compile(
        &mut self,
        _: u64,
        entry: &str,
        specialization: &Specialization,
    ) -> Result<CompiledShader> {
        self.compiled.push(specialization.clone());
        Ok(CompiledShader {
            code: ShaderCode(self.compiled.len() as u64),
            interface: reflected(entry)?,
            provenance: Provenance::default(),
        })
    }
    fn compile_tessellation(
        &mut self,
        library: u64,
        entry: &str,
        specialization: &Specialization,
        tessellation: &Tessellation,
    ) -> Result<TessellationStages> {
        self.tessellations.push(tessellation.clone());
        let evaluation = self.compile(library, entry, specialization)?;
        let base = evaluation.code.0;
        Ok(TessellationStages {
            vertex: ShaderCode(base + 100),
            control: ShaderCode(base + 200),
            evaluation,
        })
    }
    fn release(&mut self, code: ShaderCode) {
        self.released.push(code);
    }
}

pub(crate) type TestDevice = Device<MockBackend, MockCompiler>;

/// The library [`device`] opens with, whose functions [`MockCompiler`]
/// reflects.
pub(crate) const LIBRARY: LibraryId = LibraryId(0);

/// A device of the first chip, holding [`LIBRARY`].
pub(crate) fn device() -> TestDevice {
    device_on(MockBackend::new())
}

/// A device of the first chip over `backend`, holding [`LIBRARY`].
pub(crate) fn device_on(backend: MockBackend) -> TestDevice {
    let chip: &Chip = &CHIPS[0];
    let platform = chip.platform(crate::metal::nvidia::Attachment {
        link: PcieLink {
            speed: 4,
            width: 16,
        },
        external: false,
        location_number: 0,
    });
    let mut device = Device::new(backend, MockCompiler::default(), &platform).unwrap();
    assert_eq!(device.new_library(fixture(false)), Ok(LIBRARY));
    device
}
