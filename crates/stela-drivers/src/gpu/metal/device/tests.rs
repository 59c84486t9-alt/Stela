use super::{
    pipelines::{ComputePipelineRequest, MeshPipelineRequest, RenderPipelineRequest},
    queue::{AttachmentRequest, CounterSet, RenderPassRequest},
    *,
};
use crate::gpu::metal::{
    abi::{
        CpuCacheMode, DataType, DispatchType, HazardTrackingMode, HeapType, IndirectCommandType,
        LoadAction, MultisampleDepthResolveFilter, MultisampleStencilResolveFilter,
        PrimitiveTopologyClass, PrimitiveType, ResourceOptions, SparsePageSize,
        SparseTextureMappingMode, StorageMode, StoreAction, StoreActionOptions, SwizzleChannels,
        TessellationPartitionMode, TextureType, TextureUsage,
    },
    capabilities::{ShaderFeatures, Size},
    command_buffer::{
        BufferRef, Segment,
        counters::{COUNTER_ERROR_VALUE, CounterSample},
        indirect::ExecutionRange,
    },
    heap::HeapDescriptor,
    indirect::IndirectCommandBufferDescriptor,
    nvidia::{CHIPS, Chip, PcieLink, fixture::nvk},
    pipeline::{
        ColorAttachmentDescriptor, MAX_COLOR_ATTACHMENTS, RenderTargets, TessellationDescriptor,
    },
    pixel_format::PixelFormat,
    resource::TextureDescriptor,
    sampler::SamplerDescriptor,
    shader::{
        Access, BufferUse, CompiledShader, FunctionConstant, Interface, Patch, PatchDomain,
        Provenance, Scalar, Specialization, Stage, Tessellation, TessellationStages, Varying,
        tests::interface,
    },
    sparse::{MappingUpdate, SparseRegion},
    vulkan::{
        ImageAspects, PrimitiveTopology, ShaderStages,
        backend::{BufferAllocation, Descriptor, Requirements},
        command::{BufferImageCopy, Command, Subresource},
        object::{
            Buffer, BufferInfo, BufferView, BufferViewInfo, ComputePipelineInfo,
            GraphicsPipelineInfo, Image, ImageInfo, ImageView, ImageViewInfo, MemoryRequest,
            Pipeline, QueryPool, QueryPoolInfo, Sampler, SamplerInfo, ShaderCode,
            SparseImageRequirements,
        },
        physical::PhysicalDevice,
    },
};
use alloc::{collections::BTreeMap, string::String, vec::Vec};

#[derive(Default)]
struct MockBackend {
    physical: Option<PhysicalDevice>,
    next: u64,
    destroyed: Vec<Object>,
    descriptors: Vec<(u32, Descriptor)>,
    graphics: Vec<GraphicsPipelineInfo>,
    compute: Vec<ComputePipelineInfo>,
    submissions: Vec<Vec<Segment>>,
    writes: Vec<(Memory, u64, Vec<u8>)>,
    semaphores: BTreeMap<u64, u64>,
    queries_ready: bool,
}

impl MockBackend {
    fn new() -> Self {
        Self {
            physical: Some(nvk(&CHIPS[0], 8 << 30)),
            ..Self::default()
        }
    }

    fn id(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    /// Completes everything submitted so far.
    fn complete(&mut self, timeline: Semaphore, serial: u64) {
        self.semaphores.insert(timeline.0, serial);
    }
}

impl Backend for MockBackend {
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
    /// RGBA8's standard block, with each layer's tail of one block from
    /// level 2.
    fn create_sparse_image(&mut self, _: &ImageInfo) -> Result<(Image, SparseImageRequirements)> {
        let requirements = SparseImageRequirements {
            memory_types: u32::MAX,
            granularity: [128, 128, 1],
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
    fn create_graphics_pipeline(&mut self, info: &GraphicsPipelineInfo) -> Result<Pipeline> {
        self.graphics.push(info.clone());
        Ok(Pipeline(self.id()))
    }
    fn create_compute_pipeline(&mut self, info: &ComputePipelineInfo) -> Result<Pipeline> {
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
    fn destroy(&mut self, object: Object) {
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
    fn invalidate_memory(&mut self, _: Memory, _: u64, _: u64) -> Result<()> {
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
/// fragment function reading a varying nothing outputs, and `"constants"`, a
/// kernel with a required and an optional function constant.
#[derive(Default)]
struct MockCompiler {
    compiled: Vec<Specialization>,
    tessellations: Vec<Tessellation>,
    released: Vec<ShaderCode>,
}

fn reflected(entry: &str) -> Result<Interface> {
    let stage = match entry {
        "kernel" => Stage::Kernel,
        "vertex" | "patch" => Stage::Vertex,
        "fragment" | "unlinked" => Stage::Fragment,
        "object" => Stage::Object,
        "mesh" => Stage::Mesh,
        "constants" => Stage::Kernel,
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
    fn reflect(&mut self, _: u64, entry: &str, _: &Specialization) -> Result<Interface> {
        reflected(entry)
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

type TestDevice = Device<MockBackend, MockCompiler>;

fn device() -> TestDevice {
    let chip: &Chip = &CHIPS[0];
    let platform = chip.platform(crate::gpu::metal::nvidia::Attachment {
        link: PcieLink {
            speed: 4,
            width: 16,
        },
        external: false,
        location_number: 0,
    });
    Device::new(MockBackend::new(), MockCompiler::default(), &platform).unwrap()
}

fn options(storage_mode: StorageMode) -> ResourceOptions {
    ResourceOptions {
        cpu_cache_mode: CpuCacheMode::DefaultCache,
        storage_mode,
        hazard_tracking_mode: HazardTrackingMode::Default,
    }
}

fn texture(pixel_format: PixelFormat, usage: TextureUsage) -> TextureDescriptor {
    TextureDescriptor {
        texture_type: TextureType::D2,
        pixel_format,
        width: 128,
        height: 128,
        depth: 1,
        mipmap_level_count: 1,
        sample_count: 1,
        array_length: 1,
        options: options(StorageMode::Private),
        usage,
        swizzle: SwizzleChannels::IDENTITY,
    }
}

/// Submits an empty command buffer and returns its serial.
fn submit(device: &mut TestDevice) -> u64 {
    let commands = device.new_command_buffer();
    device.commit(commands).unwrap()
}

fn complete(device: &mut TestDevice, serial: u64) {
    let timeline = device.timeline;
    device.backend().complete(timeline, serial);
    assert_eq!(device.poll(), Ok(serial));
}

#[test]
fn devices_missing_a_required_feature_are_refused() {
    let mut backend = MockBackend::new();
    backend.physical.as_mut().unwrap().features.null_descriptor = false;
    let platform = CHIPS[0].platform(crate::gpu::metal::nvidia::Attachment {
        link: PcieLink {
            speed: 4,
            width: 16,
        },
        external: false,
        location_number: 0,
    });
    let device = Device::new(backend, MockCompiler::default(), &platform);
    assert!(matches!(device, Err(Error::Unsupported("nullDescriptor"))));
}

#[test]
fn destruction_waits_for_submitted_work() {
    let mut device = device();
    let buffer = device
        .new_buffer(4096, options(StorageMode::Shared))
        .unwrap();
    assert_eq!(device.current_allocated_size(), 4096);
    let reference = device.buffer(buffer).unwrap();
    assert_eq!(reference.length, 4096);
    let serial = submit(&mut device);
    device.destroy_buffer(buffer).unwrap();
    assert_eq!(device.current_allocated_size(), 0);
    assert!(
        device.backend().destroyed.is_empty(),
        "the GPU may still read it"
    );
    complete(&mut device, serial);
    assert!(
        device
            .backend()
            .destroyed
            .contains(&Object::Buffer(reference.buffer))
    );
    assert!(device.buffer(buffer).is_err());

    let idle = device
        .new_buffer(16, options(StorageMode::Private))
        .unwrap();
    let idle_buffer = device.buffer(idle).unwrap().buffer;
    device.destroy_buffer(idle).unwrap();
    assert!(
        device
            .backend()
            .destroyed
            .contains(&Object::Buffer(idle_buffer)),
        "nothing pending: destroyed at once"
    );
    assert!(device.buffer_memory(idle).is_err());
}

#[test]
fn textures_publish_descriptors_and_release_them() {
    let mut device = device();
    let usage = TextureUsage::SHADER_READ | TextureUsage::SHADER_WRITE;
    let id = device
        .new_texture(&texture(PixelFormat::Rgba8Unorm, usage))
        .unwrap();
    let resource = device.texture_resource_id(id).unwrap();
    assert!(resource.low() != 0 && resource.high() != 0);
    let written: Vec<_> = device
        .backend()
        .descriptors
        .iter()
        .map(|(index, descriptor)| (*index, descriptor.array()))
        .collect();
    assert!(written.contains(&(resource.low(), HeapArray::SampledImages)));
    assert!(written.contains(&(resource.high(), HeapArray::StorageImages)));

    let view = device
        .new_texture_view(
            id,
            &crate::gpu::metal::resource::TextureViewDescriptor {
                pixel_format: PixelFormat::Rgba8UnormSrgb,
                texture_type: TextureType::D2,
                levels: 0..1,
                slices: 0..1,
                swizzle: SwizzleChannels::IDENTITY,
            },
        )
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(
        device.destroy_texture(id),
        Err(Error::Invalid("views of the texture are still alive"))
    );
    device.destroy_texture(view).unwrap();
    device.destroy_texture(id).unwrap();
    let images = device
        .backend()
        .destroyed
        .iter()
        .filter(|object| matches!(object, Object::Image(_)))
        .count();
    assert_eq!(images, 1, "views share their parent's image");
    // Released indices are reused once the (absent) work completes.
    let again = device
        .new_texture(&texture(PixelFormat::Rgba8Unorm, TextureUsage::SHADER_READ))
        .unwrap();
    assert!(device.texture_resource_id(again).unwrap().low() != 0);
}

#[test]
fn storage_textures_have_a_descriptor_per_level() {
    let mut device = device();
    let mut descriptor = texture(PixelFormat::Rgba8Unorm, TextureUsage::SHADER_WRITE);
    descriptor.mipmap_level_count = 8;
    let id = device.new_texture(&descriptor).unwrap();
    let resource = device.texture_resource_id(id).unwrap();
    assert_eq!(resource.low(), 0, "write-only textures are not sampled");
    assert_eq!(resource.high_count(), 8);
    let storage: Vec<_> = device
        .backend()
        .descriptors
        .iter()
        .filter(|(_, descriptor)| descriptor.array() == HeapArray::StorageImages)
        .map(|(index, _)| *index)
        .collect();
    let first = resource.high_index();
    assert_eq!(storage, (first..first + 8).collect::<Vec<_>>());
    assert_eq!(device.descriptors.in_use(HeapArray::StorageImages), 8);
    let serial = submit(&mut device);
    device.destroy_texture(id).unwrap();
    complete(&mut device, serial);
    assert_eq!(device.descriptors.in_use(HeapArray::StorageImages), 0);
    let views = device
        .backend()
        .destroyed
        .iter()
        .filter(|object| matches!(object, Object::ImageView(_)))
        .count();
    assert_eq!(views, 8, "each level's view is destroyed");
}

#[test]
fn texture_buffers_and_linear_textures_alias_their_buffer() {
    let mut device = device();
    let buffer = device
        .new_buffer(1 << 16, options(StorageMode::Shared))
        .unwrap();
    let mut descriptor = texture(
        PixelFormat::R32Float,
        TextureUsage::SHADER_READ | TextureUsage::SHADER_WRITE,
    );
    descriptor.texture_type = TextureType::TextureBuffer;
    descriptor.width = 1024;
    descriptor.height = 1;
    descriptor.options = options(StorageMode::Shared);
    let texel = device
        .new_texture_from_buffer(buffer, &descriptor, 0, 4096)
        .unwrap();
    let id = device.texture_resource_id(texel).unwrap();
    let arrays: Vec<_> = device
        .backend()
        .descriptors
        .iter()
        .map(|(_, descriptor)| descriptor.array())
        .collect();
    assert!(
        arrays.contains(&HeapArray::UniformTexelBuffers)
            && arrays.contains(&HeapArray::StorageTexelBuffers)
    );
    assert!(id.low() != 0 && id.high() != 0);
    assert_eq!(
        device.destroy_buffer(buffer),
        Err(Error::Invalid("textures still alias the buffer"))
    );
    device.destroy_texture(texel).unwrap();
    device.destroy_buffer(buffer).unwrap();
}

#[test]
fn samplers_are_shared_and_clamped_variants_cached() {
    let mut device = device();
    let descriptor = SamplerDescriptor::default();
    let first = device.new_sampler(&descriptor).unwrap();
    let second = device.new_sampler(&descriptor).unwrap();
    assert_eq!(first, second);
    let id = device.sampler_resource_id(first).unwrap();
    assert_eq!(
        id.low(),
        id.high(),
        "no border: the float sampler serves integer textures"
    );
    let mut resolver = device.resolver();
    let clamped =
        crate::gpu::metal::command_buffer::Resolver::clamped_sampler(&mut resolver, id, 1.0, 4.0)
            .unwrap();
    let again =
        crate::gpu::metal::command_buffer::Resolver::clamped_sampler(&mut resolver, id, 1.0, 4.0)
            .unwrap();
    assert_eq!(clamped, again);
    assert_ne!(clamped, id);
    device.destroy_sampler(first).unwrap();
    assert!(
        device.backend().destroyed.is_empty(),
        "one reference remains"
    );
    device.destroy_sampler(second).unwrap();
    let samplers = device
        .backend()
        .destroyed
        .iter()
        .filter(|object| matches!(object, Object::Sampler(_)))
        .count();
    assert_eq!(samplers, 2, "the sampler and its clamped variant");
}

#[test]
fn automatic_heaps_place_and_alias_resources() {
    let mut device = device();
    let heap = device
        .new_heap(&HeapDescriptor {
            size: 1 << 20,
            options: options(StorageMode::Private),
            heap_type: HeapType::Automatic,
            sparse_page_size: SparsePageSize::Size64,
        })
        .unwrap();
    let a = device
        .new_heap_buffer(heap, 1000, options(StorageMode::Private), None)
        .unwrap();
    let b = device
        .new_heap_buffer(heap, 1000, options(StorageMode::Private), None)
        .unwrap();
    assert_eq!(device.heap_usage(heap, 1).unwrap().0, 2048);
    assert!(
        device
            .new_heap_buffer(heap, 64, options(StorageMode::Shared), None)
            .is_err(),
        "storage mode differs"
    );
    assert!(
        device
            .new_heap_buffer(heap, 64, options(StorageMode::Private), Some(0))
            .is_err(),
        "automatic heaps place"
    );
    device.make_buffer_aliasable(a).unwrap();
    assert_eq!(device.heap_usage(heap, 1).unwrap().0, 1024);
    assert!(device.make_buffer_aliasable(a).is_err());
    let c = device
        .new_heap_buffer(heap, 1000, options(StorageMode::Private), None)
        .unwrap();
    assert_eq!(
        device.buffer(c).unwrap().address & 0xffff_ffff,
        0,
        "c reuses a's range"
    );
    let texture = device
        .new_heap_texture(
            heap,
            &texture(PixelFormat::Rgba8Unorm, TextureUsage::SHADER_READ),
            None,
        )
        .unwrap();
    assert_eq!(
        device.destroy_heap(heap),
        Err(Error::Invalid("resources still live in the heap"))
    );
    for buffer in [a, b, c] {
        device.destroy_buffer(buffer).unwrap();
    }
    device.destroy_texture(texture).unwrap();
    assert_eq!(device.heap_usage(heap, 1).unwrap().0, 0);
    device.destroy_heap(heap).unwrap();
    assert_eq!(device.current_allocated_size(), 0);
}

fn color_targets() -> RenderTargets {
    let mut targets = RenderTargets::default();
    targets.color_attachments[0] = ColorAttachmentDescriptor {
        pixel_format: Some(PixelFormat::Rgba8Unorm),
        ..ColorAttachmentDescriptor::default()
    };
    targets
}

#[test]
fn amplified_pipelines_compile_amplified_vertex_functions() {
    let mut device = device();
    let vertex = device.new_function(1, "vertex", Vec::new()).unwrap();
    let fragment = device.new_function(1, "fragment", Vec::new()).unwrap();
    let request = RenderPipelineRequest {
        vertex_function: vertex,
        fragment_function: Some(fragment),
        vertex_descriptor: None,
        targets: color_targets(),
        input_primitive_topology: PrimitiveTopologyClass::Triangle,
        max_vertex_amplification_count: 2,
        tessellation: Default::default(),
    };
    device.new_render_pipeline(&request).unwrap();
    let amplified: Vec<bool> = device
        .compiler
        .compiled
        .iter()
        .map(|specialization| specialization.amplified)
        .collect();
    assert_eq!(amplified, [true, false]);
}

#[test]
fn functions_take_values_for_their_function_constants() {
    let mut device = device();
    let scale = (0, alloc::vec![2, 0, 0, 0]);
    let refused = [
        (Vec::new(), "a required function constant has no value"),
        (
            alloc::vec![(0, alloc::vec![2, 0])],
            "a function constant value of another type",
        ),
        (
            alloc::vec![scale.clone(), scale.clone()],
            "a function constant has two values",
        ),
    ];
    for (constants, reason) in refused {
        assert_eq!(
            device.new_function(1, "constants", constants),
            Err(Error::Invalid(reason))
        );
    }
    // tint is optional; values of constants the function lacks are ignored.
    for constants in [
        alloc::vec![scale.clone()],
        alloc::vec![scale.clone(), (1, alloc::vec![0; 8]), (9, alloc::vec![1])],
    ] {
        assert!(device.new_function(1, "constants", constants).is_ok());
    }
}

#[test]
fn render_pipelines_compile_their_functions_once() {
    let mut device = device();
    let vertex = device
        .new_function(1, "vertex", alloc::vec![(0, alloc::vec![1, 0, 0, 0])])
        .unwrap();
    let fragment = device.new_function(1, "fragment", Vec::new()).unwrap();
    assert!(device.new_function(1, "missing", Vec::new()).is_err());
    let request = RenderPipelineRequest {
        vertex_function: vertex,
        fragment_function: Some(fragment),
        vertex_descriptor: None,
        targets: color_targets(),
        input_primitive_topology: PrimitiveTopologyClass::Triangle,
        max_vertex_amplification_count: 1,
        tessellation: Default::default(),
    };
    let pipeline = device.new_render_pipeline(&request).unwrap();
    assert_eq!(
        device.compiler.compiled[0].constants,
        [(0, alloc::vec![1, 0, 0, 0])]
    );
    for specialization in &device.compiler.compiled {
        let linked: Vec<_> = specialization
            .varyings
            .iter()
            .map(|varying| varying.identifier.as_str())
            .collect();
        assert_eq!(linked, ["user(color)"], "both stages link");
    }
    assert_eq!(
        device.compiler.released.len(),
        2,
        "NIR is released once the pipeline exists"
    );
    let state = device.render_pipeline_state(pipeline).unwrap().clone();
    assert!(state.pipeline.is_some());
    device.destroy_render_pipeline(pipeline).unwrap();
    assert!(
        device
            .backend()
            .destroyed
            .contains(&Object::Pipeline(state.pipeline.unwrap()))
    );

    let bad = RenderPipelineRequest {
        vertex_function: fragment,
        ..request.clone()
    };
    assert!(device.new_render_pipeline(&bad).is_err());
    assert_eq!(
        device.compiler.released.len(),
        4,
        "failed pipelines release their NIR"
    );

    let unlinked = device.new_function(1, "unlinked", Vec::new()).unwrap();
    let unlinked = RenderPipelineRequest {
        fragment_function: Some(unlinked),
        ..request
    };
    let compiled = device.compiler.compiled.len();
    assert!(device.new_render_pipeline(&unlinked).is_err());
    assert_eq!(
        device.compiler.compiled.len(),
        compiled,
        "unlinked functions compile nothing"
    );
}

#[test]
fn managed_textures_keep_a_cpu_copy_without_host_image_copy() {
    let mut backend = MockBackend::new();
    backend.physical.as_mut().unwrap().features.host_image_copy = false;
    let chip: &Chip = &CHIPS[0];
    let platform = chip.platform(crate::gpu::metal::nvidia::Attachment {
        link: PcieLink {
            speed: 4,
            width: 16,
        },
        external: false,
        location_number: 0,
    });
    let mut device = Device::new(backend, MockCompiler::default(), &platform).unwrap();
    let descriptor = TextureDescriptor {
        width: 8,
        height: 4,
        mipmap_level_count: 2,
        options: options(StorageMode::Managed),
        ..texture(PixelFormat::Rgba8Unorm, TextureUsage::SHADER_READ)
    };
    let texture = device.new_texture(&descriptor).unwrap();
    let region = BufferImageCopy {
        buffer_offset: 0,
        buffer_row_length: 0,
        buffer_image_height: 0,
        subresource: Subresource {
            aspects: ImageAspects::COLOR,
            mip_level: 0,
            base_array_layer: 0,
            layer_count: 1,
        },
        offset: [2, 1, 0],
        extent: [2, 2, 1],
    };
    let written: Vec<u8> = (0..16).collect();
    device.replace_region(texture, &region, &written).unwrap();
    let mut read = [0; 16];
    device.get_bytes(texture, &region, &mut read).unwrap();
    assert_eq!(read[..], written[..], "reads come from the CPU copy");
    assert!(
        device
            .replace_region(texture, &region, &written[..12])
            .is_err()
    );

    let level1 = device.texture_cpu_copy(texture, 1, 0).unwrap().unwrap();
    assert_eq!((level1.offset, level1.bytes_per_row), (8 * 4 * 4, 4 * 4));

    submit(&mut device);
    let segment = &device.backend().submissions.last().unwrap()[0];
    let Command::CopyBufferToImage { src, regions, .. } = &segment.commands[1] else {
        panic!("{:?}", segment.commands[1]);
    };
    assert_eq!(*src, level1.buffer.buffer);
    assert_eq!(
        (
            regions[0].buffer_offset,
            regions[0].buffer_row_length,
            regions[0].offset
        ),
        ((8 * 4) + 2 * 4, 8, [2, 1, 0])
    );
    assert!(matches!(segment.commands[2], Command::Barrier(_)));
    submit(&mut device);
    let segment = &device.backend().submissions.last().unwrap()[0];
    assert!(
        !segment
            .commands
            .iter()
            .any(|command| matches!(command, Command::CopyBufferToImage { .. })),
        "each write uploads once"
    );
}

#[test]
fn post_tessellation_functions_compile_with_their_feeding_stages() {
    let mut device = device();
    let patch = device.new_function(1, "patch", Vec::new()).unwrap();
    let fragment = device.new_function(1, "fragment", Vec::new()).unwrap();
    let request = RenderPipelineRequest {
        vertex_function: patch,
        fragment_function: Some(fragment),
        vertex_descriptor: None,
        targets: color_targets(),
        input_primitive_topology: PrimitiveTopologyClass::Unspecified,
        max_vertex_amplification_count: 1,
        tessellation: TessellationDescriptor {
            partition_mode: TessellationPartitionMode::FractionalOdd,
            max_tessellation_factor: 64,
            ..TessellationDescriptor::default()
        },
    };
    let pipeline = device.new_render_pipeline(&request).unwrap();
    let tessellation = &device.compiler.tessellations[0];
    assert_eq!(
        (tessellation.partition, tessellation.max_factor),
        (TessellationPartitionMode::FractionalOdd, 64)
    );
    let state = device.render_pipeline_state(pipeline).unwrap();
    let stages: Vec<_> = state
        .plan
        .info
        .stages
        .iter()
        .map(|(stage, _)| *stage)
        .collect();
    assert_eq!(
        stages,
        [
            ShaderStages::VERTEX,
            ShaderStages::TESSELLATION_CONTROL,
            ShaderStages::TESSELLATION_EVALUATION,
            ShaderStages::FRAGMENT
        ]
    );
    assert_eq!(state.plan.info.topology, PrimitiveTopology::PatchList);
    assert_eq!(
        device.compiler.released.len(),
        4,
        "every stage's NIR is released"
    );

    let odd = RenderPipelineRequest {
        tessellation: TessellationDescriptor {
            max_tessellation_factor: 15,
            ..TessellationDescriptor::default()
        },
        ..request.clone()
    };
    assert!(matches!(
        device.new_render_pipeline(&odd),
        Err(Error::Invalid(_))
    ));
    let too_large = RenderPipelineRequest {
        tessellation: TessellationDescriptor {
            max_tessellation_factor: 128,
            ..TessellationDescriptor::default()
        },
        ..request
    };
    assert_eq!(
        device.new_render_pipeline(&too_large),
        Err(Error::Unsupported("tessellation factor"))
    );
    assert_eq!(
        device.compiler.compiled.len(),
        2,
        "invalid tessellation compiles nothing"
    );
}

#[test]
fn compute_and_mesh_variants_compile_per_shape() {
    let mut device = device();
    let kernel = device.new_function(1, "kernel", Vec::new()).unwrap();
    let pipeline = device
        .new_compute_pipeline(&ComputePipelineRequest {
            compute_function: kernel,
            threadgroup_size_is_multiple_of_thread_execution_width: false,
            max_total_threads_per_threadgroup: 0,
            stage_input: None,
        })
        .unwrap();
    let state = device.compute_pipeline_state(pipeline).unwrap().clone();
    let buffer = device
        .new_buffer(4096, options(StorageMode::Private))
        .unwrap();
    let buffer = device.buffer(buffer).unwrap();

    let mut commands = device.new_command_buffer();
    commands.begin_compute(DispatchType::Serial).unwrap();
    commands.set_compute_pipeline_state(&state).unwrap();
    commands.set_compute_buffer(Some(buffer), 0, 0).unwrap();
    let size = |width| Size {
        width,
        height: 1,
        depth: 1,
    };
    for threads in [64, 64, 128] {
        commands
            .dispatch_threadgroups(&mut device.resolver(), [1, 1, 1], size(threads))
            .unwrap();
    }
    commands.end_encoding(&mut device.resolver()).unwrap();
    let serial = device.commit(commands).unwrap();
    assert_eq!(
        device.backend().compute.len(),
        2,
        "one variant per threadgroup size"
    );
    assert_eq!(device.backend().compute[0].required_subgroup_size, 32);
    let submission = device.backend().submissions.last().unwrap().clone();
    let signals = &submission.last().unwrap().signals;
    assert_eq!(signals, &[(device.timeline, serial)]);
    assert!(
        !device.backend().writes.is_empty(),
        "argument tables reach the upload chunk"
    );

    let object = device.new_function(1, "object", Vec::new()).unwrap();
    let mesh = device.new_function(1, "mesh", Vec::new()).unwrap();
    let fragment = device.new_function(1, "fragment", Vec::new()).unwrap();
    let request = MeshPipelineRequest {
        object_function: Some(object),
        mesh_function: mesh,
        fragment_function: Some(fragment),
        targets: color_targets(),
        max_vertex_amplification_count: 1,
    };
    let compiled = device.compiler.compiled.len();
    let id = device.new_mesh_render_pipeline(&request).unwrap();
    let first = device
        .mesh_variant(u64::from(id.0), [32, 1, 1], [64, 1, 1])
        .unwrap();
    let linked = [("user(color)", false), ("user(normal)", true)];
    let stages: Vec<_> = device.compiler.compiled[compiled..]
        .iter()
        .map(|specialization| {
            let varyings: Vec<_> = specialization
                .varyings
                .iter()
                .map(|varying| (varying.identifier.as_str(), varying.per_primitive))
                .collect();
            (varyings, specialization.launched_by_grid)
        })
        .collect();
    assert_eq!(
        stages,
        [
            (linked.to_vec(), false),
            (Vec::new(), true),
            (linked.to_vec(), false),
        ],
        "the fragment, then the object function the draw launches and the mesh function"
    );
    let again = device
        .mesh_variant(u64::from(id.0), [32, 1, 1], [64, 1, 1])
        .unwrap();
    assert_eq!(first, again);
    let stages: Vec<_> = device
        .backend()
        .graphics
        .last()
        .unwrap()
        .stages
        .iter()
        .map(|(stage, _)| *stage)
        .collect();
    use crate::gpu::metal::vulkan::ShaderStages as S;
    assert_eq!(stages, [S::TASK, S::MESH, S::FRAGMENT]);
    assert!(
        device
            .mesh_variant(u64::from(id.0), [32, 1, 1], [4096, 1, 1])
            .is_err(),
        "beyond the mesh limit"
    );
    device.destroy_render_pipeline(id).unwrap();
    complete(&mut device, serial);
}

#[test]
fn render_passes_resolve_cached_attachment_views() {
    let mut device = device();
    let target = device
        .new_texture(&texture(
            PixelFormat::Rgba8Unorm,
            TextureUsage::RENDER_TARGET,
        ))
        .unwrap();
    let request = RenderPassRequest {
        color_attachments: {
            let mut colors = [None; MAX_COLOR_ATTACHMENTS];
            colors[0] = Some(AttachmentRequest {
                texture: target,
                level: 0,
                slice: 0,
                depth_plane: 0,
                resolve: None,
                load_action: LoadAction::Clear,
                store_action: StoreAction::Store,
                store_action_options: StoreActionOptions::EMPTY,
                clear: [1.0, 0.0, 0.0, 1.0],
            });
            colors
        },
        depth_attachment: None,
        depth_resolve_filter: MultisampleDepthResolveFilter::Sample0,
        stencil_attachment: None,
        stencil_resolve_filter: MultisampleStencilResolveFilter::Sample0,
        visibility_result_buffer: None,
        render_target_array_length: 0,
        render_target_width: 0,
        render_target_height: 0,
        default_raster_sample_count: 0,
        tile_memory: false,
        sample_positions: Vec::new(),
        rasterization_rate_map: false,
        counter_samples: Vec::new(),
    };
    let mut views = Vec::new();
    for _ in 0..2 {
        let mut commands = device.new_command_buffer();
        device.begin_render(&mut commands, &request).unwrap();
        commands.end_encoding(&mut device.resolver()).unwrap();
        device.commit(commands).unwrap();
        let segment = &device.backend().submissions.last().unwrap()[0];
        let view = segment.commands.iter().find_map(|command| match command {
            Command::BeginRendering(rendering) => rendering.color[0].map(|color| color.view),
            _ => None,
        });
        views.push(view.unwrap());
    }
    assert_eq!(views[0], views[1], "the attachment view is created once");
    let _ = PrimitiveType::Triangle;
}

#[test]
fn completion_recycles_upload_chunks() {
    let mut device = device();
    let record = |device: &mut TestDevice| {
        let mut commands = device.new_command_buffer();
        commands.begin_compute(DispatchType::Serial).unwrap();
        commands
            .set_compute_bytes(&mut device.resolver(), &[7; 64], 0)
            .unwrap();
        commands.end_encoding(&mut device.resolver()).unwrap();
        device.commit(commands).unwrap()
    };
    let first = record(&mut device);
    complete(&mut device, first);
    let created = device.backend().next;
    let second = record(&mut device);
    assert_eq!(
        device.backend().next,
        created,
        "the completed chunk is reused"
    );
    assert!(device.wait(second, 0).is_ok());
    assert!(device.wait(second + 1, 0).is_err(), "never committed");
}

#[test]
fn shared_events_and_counters() {
    let mut device = device();
    let event = device.new_event().unwrap();
    device.set_signaled_value(event, 5).unwrap();
    device.set_signaled_value(event, 3).unwrap();
    assert_eq!(
        device.signaled_value(event),
        Ok(5),
        "timeline values never decrease"
    );
    assert_eq!(device.wait_event(event, 5, 0), Ok(true));
    assert_eq!(device.wait_event(event, 6, 0), Ok(false));

    let counters = device
        .new_counter_sample_buffer(CounterSet::Timestamp, 4)
        .unwrap();
    assert_eq!(device.resolve_counters(counters, 0, 4), Ok(None));
    device.backend().queries_ready = true;
    assert_eq!(
        device.resolve_counters(counters, 1, 2),
        Ok(Some(alloc::vec![0, 10]))
    );
    assert!(device.resolve_counters(counters, 3, 2).is_err());
    let sample = device.counter_sample(counters, 0).unwrap();
    assert!(matches!(sample, CounterSample::Timestamp { query: 0, .. }));
    assert!(device.counter_sample(counters, 4).is_err());
    let mut commands = device.new_command_buffer();
    commands
        .sample_counters(&mut device.resolver(), sample, true)
        .unwrap();
    device.commit(commands).unwrap();
    device.destroy_counter_sample_buffer(counters).unwrap();
    device.destroy_event(event).unwrap();
}

#[test]
fn statistic_samples_start_as_error_values() {
    let mut device = device();
    let counters = device
        .new_counter_sample_buffer(CounterSet::Statistic, 2)
        .unwrap();
    let values = device.resolve_counters(counters, 1, 1).unwrap().unwrap();
    assert_eq!(
        values, [COUNTER_ERROR_VALUE; 8],
        "one MTLCounterResultStatistic"
    );
    let CounterSample::Statistic(first) = device.counter_sample(counters, 0).unwrap() else {
        panic!("statistic buffers hold statistic samples")
    };
    assert_eq!(
        device.counter_sample(counters, 1),
        Ok(CounterSample::Statistic(first + 64))
    );
    let mut commands = device.new_command_buffer();
    commands
        .sample_counters(
            &mut device.resolver(),
            CounterSample::Statistic(first),
            false,
        )
        .unwrap();
    device.commit(commands).unwrap();
    let segment = &device.backend().submissions.last().unwrap()[0];
    assert!(
        segment
            .commands
            .iter()
            .any(|command| matches!(command, Command::AccumulateResults { runs: 7, .. })),
        "commit resolves the sample's seven counted members"
    );
    device.destroy_counter_sample_buffer(counters).unwrap();
}

#[test]
fn sparse_textures_map_heap_pages_at_commit() {
    let mut device = device();
    let heap = device
        .new_heap(&HeapDescriptor {
            size: 4 << 16,
            options: options(StorageMode::Private),
            heap_type: HeapType::Sparse,
            sparse_page_size: SparsePageSize::Size64,
        })
        .unwrap();
    let descriptor = TextureDescriptor {
        width: 256,
        height: 256,
        mipmap_level_count: 4,
        ..texture(PixelFormat::Rgba8Unorm, TextureUsage::SHADER_READ)
    };
    assert!(
        device.new_heap_texture(heap, &descriptor, Some(0)).is_err(),
        "sparse heaps place textures themselves"
    );
    let sparse = device.new_heap_texture(heap, &descriptor, None).unwrap();
    assert_eq!(device.sparse_tail(sparse), Ok(Some((2, 64 << 10))));
    let image = device.sparse_image(sparse).unwrap();
    let plain = device
        .new_texture(&texture(PixelFormat::Rgba8Unorm, TextureUsage::SHADER_READ))
        .unwrap();
    assert_eq!(device.sparse_tail(plain), Ok(None));
    assert!(device.sparse_image(plain).is_err());

    let mut commands = device.new_command_buffer();
    commands.begin_blit().unwrap();
    let scratch = BufferRef {
        buffer: Buffer(99),
        offset: 0,
        address: 99 << 32,
        length: 64,
    };
    commands.copy_buffer(scratch, 0, scratch, 32, 32).unwrap();
    commands.end_encoding(&mut device.resolver()).unwrap();
    commands
        .begin_resource_state(&mut device.resolver())
        .unwrap();
    let tiles = |level, origin, size| MappingUpdate {
        level,
        slice: 0,
        region: SparseRegion { origin, size },
    };
    commands
        .update_texture_mappings(
            image,
            SparseTextureMappingMode::Map,
            alloc::vec![tiles(0, [0; 3], [2, 1, 1]), tiles(3, [0; 3], [1; 3])],
        )
        .unwrap();
    assert_eq!(
        commands.update_texture_mapping_indirect(),
        Err(Error::Unsupported("indirect sparse mapping updates"))
    );
    commands.end_encoding(&mut device.resolver()).unwrap();
    device.commit(commands).unwrap();
    let segments = device.backend().submissions.last().unwrap().clone();
    assert_eq!(
        segments.len(),
        2,
        "the encoder's updates bind between segments"
    );
    assert!(segments[0].binds.is_empty());
    assert_eq!(segments[1].binds.len(), 3, "two blocks and the tail");
    assert_eq!(device.heap_usage(heap, 1), Ok((3 << 16, 1 << 16)));

    // A bad region fails the commit before any mapping changes.
    let mut commands = device.new_command_buffer();
    commands
        .begin_resource_state(&mut device.resolver())
        .unwrap();
    commands
        .update_texture_mappings(
            image,
            SparseTextureMappingMode::Unmap,
            alloc::vec![tiles(0, [0; 3], [1; 3]), tiles(0, [2, 0, 0], [1; 3])],
        )
        .unwrap();
    commands.end_encoding(&mut device.resolver()).unwrap();
    assert!(device.commit(commands).is_err());
    assert_eq!(device.heap_usage(heap, 1), Ok((3 << 16, 1 << 16)));

    assert!(
        device.destroy_heap(heap).is_err(),
        "the texture lives in it"
    );
    device.destroy_texture(sparse).unwrap();
    assert_eq!(device.heap_usage(heap, 1), Ok((0, 4 << 16)));
    device.destroy_heap(heap).unwrap();
}

#[test]
fn indirect_commands_execute_snapshots_of_their_buffer() {
    let mut device = device();
    let kernel = device.new_function(1, "kernel", Vec::new()).unwrap();
    let pipeline = device
        .new_compute_pipeline(&ComputePipelineRequest {
            compute_function: kernel,
            threadgroup_size_is_multiple_of_thread_execution_width: false,
            max_total_threads_per_threadgroup: 0,
            stage_input: None,
        })
        .unwrap();
    let state = device.compute_pipeline_state(pipeline).unwrap().clone();
    let buffer = device
        .new_buffer(4096, options(StorageMode::Private))
        .unwrap();
    let buffer = device.buffer(buffer).unwrap();
    let descriptor = IndirectCommandBufferDescriptor {
        command_types: IndirectCommandType::CONCURRENT_DISPATCH,
        inherit_pipeline_state: false,
        inherit_buffers: false,
        inherit_cull_mode: true,
        inherit_depth_stencil_state: true,
        inherit_depth_bias: true,
        inherit_depth_clip_mode: true,
        inherit_front_facing_winding: true,
        inherit_triangle_fill_mode: true,
        max_vertex_buffer_bind_count: 0,
        max_fragment_buffer_bind_count: 0,
        max_kernel_buffer_bind_count: 1,
        max_kernel_threadgroup_memory_bind_count: 0,
        max_object_buffer_bind_count: 0,
        max_mesh_buffer_bind_count: 0,
        support_ray_tracing: false,
        support_dynamic_attribute_stride: false,
    };
    let icb = device.new_indirect_command_buffer(&descriptor, 2).unwrap();
    let threads = Size {
        width: 64,
        height: 1,
        depth: 1,
    };
    let contents = device.indirect_command_buffer_mut(icb).unwrap();
    let mut command = contents.compute_command(0).unwrap();
    command.set_compute_pipeline_state(&state).unwrap();
    command.set_kernel_buffer(buffer, 0, 0).unwrap();
    command
        .concurrent_dispatch_threadgroups([3, 1, 1], threads)
        .unwrap();

    let mut commands = device.new_command_buffer();
    commands.begin_compute(DispatchType::Serial).unwrap();
    commands
        .execute_commands(&mut device.resolver(), icb, ExecutionRange::Direct(0..2))
        .unwrap();
    // Encoding after the execution changes later executions only.
    device
        .indirect_command_buffer_mut(icb)
        .unwrap()
        .reset(0..1)
        .unwrap();
    commands
        .execute_commands(&mut device.resolver(), icb, ExecutionRange::Direct(0..2))
        .unwrap();
    commands.end_encoding(&mut device.resolver()).unwrap();
    device.commit(commands).unwrap();
    let segments = device.backend().submissions.last().unwrap().clone();
    let dispatches = segments[0]
        .commands
        .iter()
        .filter(|command| **command == Command::Dispatch([3, 1, 1]))
        .count();
    assert_eq!(dispatches, 1);
    assert_eq!(device.indirect_command_buffer(icb).unwrap().size(), 2);
    device.destroy_indirect_command_buffer(icb).unwrap();
    assert!(device.indirect_command_buffer(icb).is_err());
}
