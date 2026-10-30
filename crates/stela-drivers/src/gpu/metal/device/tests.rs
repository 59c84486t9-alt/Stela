use super::{
    pipelines::{
        ComputePipelineRequest, ConstantKey, ConstantValue, FunctionHandle, LinkedFunctions,
        MeshPipelineRequest, RenderPipelineRequest,
    },
    queue::{AttachmentRequest, CounterSet, RenderPassRequest},
    resources::Strides,
    *,
};
use crate::gpu::metal::{
    abi::{
        CpuCacheMode, DataType, DispatchType, FunctionType, HazardTrackingMode, HeapType,
        IndirectCommandType, LoadAction, MultisampleDepthResolveFilter,
        MultisampleStencilResolveFilter, PrimitiveTopologyClass, PrimitiveType, ResourceOptions,
        SparsePageSize, SparseTextureMappingMode, StorageMode, StoreAction, StoreActionOptions,
        SwizzleChannels, TessellationPartitionMode, TextureType, TextureUsage,
    },
    capabilities::Size,
    command_buffer::{
        BufferRef,
        blit::Region,
        counters::{COUNTER_ERROR_VALUE, CounterSample},
        generated::{GeneratedLayoutKey, GeneratedWork},
        indirect::ExecutionRange,
    },
    heap::HeapDescriptor,
    indirect::{IndirectCommandBufferDescriptor, RecordLayout},
    nvidia::{CHIPS, PcieLink},
    pipeline::{
        ColorAttachmentDescriptor, MAX_COLOR_ATTACHMENTS, RenderTargets, StageThreads,
        TessellationDescriptor,
    },
    pixel_format::PixelFormat,
    resource::TextureDescriptor,
    sampler::SamplerDescriptor,
    shader::{LinkedFunction, Linking, Specialization, Stage},
    sparse::{MappingUpdate, SparseRegion},
    vulkan::{
        MemoryProperties, PrimitiveTopology, ShaderStages,
        backend::Descriptor,
        command::Command,
        object::{Buffer, MemoryRequest, Pipeline},
    },
};
use alloc::{string::String, vec::Vec};

use super::fixture::{LIBRARY, MockBackend, MockCompiler, TestDevice, device, device_on};
use crate::gpu::metal::library::tests::fixture;

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
fn sampled_cubes_are_followed_by_their_faces() {
    let mut device = device();
    let cube = TextureDescriptor {
        texture_type: TextureType::Cube,
        ..texture(PixelFormat::Rgba8Unorm, TextureUsage::SHADER_READ)
    };
    let id = device.new_texture(&cube).unwrap();
    let low = device.texture_resource_id(id).unwrap().low();
    let sampled: Vec<_> = device
        .backend()
        .descriptors
        .iter()
        .filter(|(_, descriptor)| descriptor.array() == HeapArray::SampledImages)
        .map(|(index, _)| *index)
        .collect();
    assert_eq!(sampled, [low, low + 1]);
    assert_eq!(device.descriptors.in_use(HeapArray::SampledImages), 2);
    let serial = submit(&mut device);
    device.destroy_texture(id).unwrap();
    complete(&mut device, serial);
    assert_eq!(device.descriptors.in_use(HeapArray::SampledImages), 0);
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
fn constexpr_samplers_are_created_once_and_reach_compilation() {
    let mut device = device();
    let kernel = device.new_function(LIBRARY, "sampling", &[]).unwrap();
    // Indirect command support compiles the pipeline's function at once.
    let request = ComputePipelineRequest {
        compute_function: kernel,
        threadgroup_size_is_multiple_of_thread_execution_width: false,
        max_total_threads_per_threadgroup: 64,
        stage_input: None,
        linked_functions: LinkedFunctions::default(),
        support_indirect_command_buffers: true,
    };
    let created = |device: &mut TestDevice| {
        let descriptors = &device.backend().descriptors;
        descriptors
            .iter()
            .filter(|(_, descriptor)| matches!(descriptor, Descriptor::Sampler(_)))
            .count()
    };
    device.new_compute_pipeline(&request).unwrap();
    let samplers = device.compiler.compiled.last().unwrap().samplers.clone();
    assert_eq!(created(&mut device), 2);
    // Each is the sampler of the descriptor its state encodes.
    let (default, linear) = (0x007b_ff00_0008_0049, 0x007b_ff00_0008_0a49);
    let mut id = |state| {
        let sampler = device
            .new_sampler(&SamplerDescriptor::from_constexpr(state).unwrap())
            .unwrap();
        device.sampler_resource_id(sampler).unwrap().0
    };
    assert_eq!(samplers, [(default, id(default)), (linear, id(linear))]);
    device.new_compute_pipeline(&request).unwrap();
    assert_eq!(device.compiler.compiled.len(), 2);
    assert_eq!(device.compiler.compiled[1].samplers, samplers);
    assert_eq!(
        created(&mut device),
        2,
        "later pipelines reuse the samplers"
    );
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
fn indirect_pipelines_share_execution_sets_by_state() {
    let mut device = device();
    let vertex = device.new_function(LIBRARY, "vertex", &[]).unwrap();
    let fragment = device.new_function(LIBRARY, "fragment", &[]).unwrap();
    let request = RenderPipelineRequest {
        vertex_function: vertex,
        fragment_function: Some(fragment),
        vertex_descriptor: None,
        targets: color_targets(),
        input_primitive_topology: PrimitiveTopologyClass::Triangle,
        max_vertex_amplification_count: 1,
        tessellation: Default::default(),
        vertex_linked_functions: LinkedFunctions::default(),
        fragment_linked_functions: LinkedFunctions::default(),
        support_indirect_command_buffers: true,
    };
    let first = device.new_render_pipeline(&request).unwrap();
    let second = device.new_render_pipeline(&request).unwrap();
    let mut blended = request.clone();
    blended.targets.color_attachments[0].blending_enabled = true;
    let other = device.new_render_pipeline(&blended).unwrap();
    let plain = device
        .new_render_pipeline(&RenderPipelineRequest {
            support_indirect_command_buffers: false,
            ..request.clone()
        })
        .unwrap();

    let handle = |device: &TestDevice, id| device.render_pipeline_resource_id(id).unwrap();
    assert_eq!(handle(&device, first), 1 << 32 | 1);
    assert_eq!(
        handle(&device, second),
        1 << 32 | 2,
        "the same state shares a set"
    );
    assert_eq!(
        handle(&device, other),
        2 << 32 | 1,
        "other state has its own"
    );
    assert_eq!(handle(&device, plain), 0);
    let graphics = &device.backend().graphics;
    let bindable: Vec<bool> = graphics.iter().map(|info| info.indirect_bindable).collect();
    assert_eq!(bindable, [true, true, true, false]);
    let sets = &device.backend().execution_sets;
    assert_eq!(sets.len(), 2);
    let first_set = sets.values().next().unwrap();
    assert_eq!(first_set.len(), 3, "index 0 repeats the initial pipeline");
    assert_eq!(first_set[&0], first_set[&1]);

    device.destroy_render_pipeline(other).unwrap();
    assert!(
        device
            .backend()
            .destroyed
            .iter()
            .any(|object| matches!(object, Object::ExecutionSet(_))),
        "the set goes with its last pipeline"
    );
    device.destroy_render_pipeline(second).unwrap();
    let third = device.new_render_pipeline(&request).unwrap();
    assert_eq!(
        handle(&device, third),
        1 << 32 | 3,
        "indices return only once idle"
    );

    let vulkan = |device: &TestDevice, id| device.render_pipeline_state(id).unwrap().pipeline;
    let (initial, kept) = (vulkan(&device, first), vulkan(&device, third));
    let classes = device.indirect_render_classes();
    assert_eq!(classes.len(), 1);
    assert_eq!(
        (classes[0].index, classes[0].pipeline),
        (0, initial.unwrap())
    );
    assert_eq!(classes[0].topology, PrimitiveTopologyClass::Triangle);
    let destroyed = |device: &mut TestDevice, pipeline: Option<Pipeline>| {
        let pipeline = Object::Pipeline(pipeline.unwrap());
        device.backend().destroyed.contains(&pipeline)
    };
    device.destroy_render_pipeline(first).unwrap();
    assert!(
        !destroyed(&mut device, initial),
        "the class keeps its initial pipeline"
    );
    assert_eq!(
        device.indirect_render_classes()[0].pipeline,
        kept.unwrap(),
        "executions bind a live pipeline"
    );
    device.destroy_render_pipeline(third).unwrap();
    assert!(destroyed(&mut device, initial) && destroyed(&mut device, kept));
    assert!(device.indirect_render_classes().is_empty());
}

#[test]
fn indirect_compute_pipelines_share_the_compute_execution_set() {
    let mut device = device();
    let kernel = device.new_function(LIBRARY, "kernel", &[]).unwrap();
    let request = ComputePipelineRequest {
        compute_function: kernel,
        threadgroup_size_is_multiple_of_thread_execution_width: false,
        max_total_threads_per_threadgroup: 40,
        stage_input: None,
        linked_functions: LinkedFunctions::default(),
        support_indirect_command_buffers: true,
    };
    let first = device.new_compute_pipeline(&request).unwrap();
    let specialization = device.compiler.compiled.last().unwrap().clone();
    assert!(specialization.dynamic_threadgroups);
    assert_eq!(
        specialization.workgroup_size,
        Some([64, 1, 1]),
        "the most threads, in whole SIMD-groups"
    );
    assert!(device.backend().compute.last().unwrap().indirect_bindable);
    let second = device.new_compute_pipeline(&request).unwrap();
    let plain = device
        .new_compute_pipeline(&ComputePipelineRequest {
            support_indirect_command_buffers: false,
            ..request.clone()
        })
        .unwrap();

    let handle = |device: &TestDevice, id| device.compute_pipeline_resource_id(id).unwrap();
    assert_eq!(handle(&device, first), u64::from(u32::MAX) << 32 | 1);
    assert_eq!(handle(&device, second), u64::from(u32::MAX) << 32 | 2);
    assert_eq!(handle(&device, plain), 0);
    assert_eq!(device.backend().execution_sets.len(), 1);

    let variant = |device: &TestDevice, id| {
        let state = device.compute_pipeline_state(id).unwrap();
        state.indirect.unwrap().pipeline
    };
    let (initial, kept) = (variant(&device, first), variant(&device, second));
    assert_eq!(device.indirect_compute_set().unwrap().1, initial);
    let destroyed = |device: &mut TestDevice, pipeline| {
        let destroyed = &device.backend().destroyed;
        destroyed.contains(&Object::Pipeline(pipeline))
    };
    device.destroy_compute_pipeline(first).unwrap();
    assert!(
        !destroyed(&mut device, initial),
        "the set keeps its initial pipeline"
    );
    assert_eq!(
        device.indirect_compute_set().unwrap().1,
        kept,
        "executions bind a live pipeline"
    );
    device.destroy_compute_pipeline(second).unwrap();
    assert!(destroyed(&mut device, initial) && destroyed(&mut device, kept));
    assert!(
        device
            .backend()
            .destroyed
            .iter()
            .any(|object| matches!(object, Object::ExecutionSet(_))),
        "the set goes with its last pipeline"
    );
    assert!(device.indirect_compute_set().is_none());
}

#[test]
fn generated_layouts_are_created_once_per_key() {
    let mut device = device();
    let key = GeneratedLayoutKey {
        stages: ShaderStages::VERTEX | ShaderStages::FRAGMENT,
        execution_set: false,
        work: GeneratedWork::Draw {
            indexed: true,
            vertex_buffers: alloc::vec![0],
        },
    };
    let request = MemoryRequest {
        required: MemoryProperties::HOST_VISIBLE,
        preferred: MemoryProperties::EMPTY,
        mapped: true,
    };
    let (layout, requirements) = device.generated_layout(&key, None, 1, request).unwrap();
    assert_eq!((requirements.size, requirements.alignment), (64, 256));
    assert_eq!(
        device.generated_layout(&key, None, 1, request).unwrap().0,
        layout
    );
    let wide = GeneratedLayoutKey {
        work: GeneratedWork::Draw {
            indexed: true,
            vertex_buffers: (0..31).collect(),
        },
        ..key.clone()
    };
    assert!(
        matches!(
            device.generated_layout(&wide, None, 1, request),
            Err(Error::Unsupported(_))
        ),
        "more tokens than the device takes"
    );
    let limit = device.backend().physical_device().limits.generated_commands;
    let beyond = limit.unwrap().max_sequences + 1;
    assert!(
        matches!(
            device.generated_layout(&key, None, beyond, request),
            Err(Error::Unsupported(_))
        ),
        "more sequences than one execution runs"
    );
    assert_eq!(device.backend().layouts, [key.info()]);
}

#[test]
fn amplified_pipelines_compile_amplified_vertex_functions() {
    let mut device = device();
    let vertex = device.new_function(LIBRARY, "vertex", &[]).unwrap();
    let fragment = device.new_function(LIBRARY, "fragment", &[]).unwrap();
    let request = RenderPipelineRequest {
        vertex_function: vertex,
        fragment_function: Some(fragment),
        vertex_descriptor: None,
        targets: color_targets(),
        input_primitive_topology: PrimitiveTopologyClass::Triangle,
        max_vertex_amplification_count: 2,
        tessellation: Default::default(),
        vertex_linked_functions: LinkedFunctions::default(),
        fragment_linked_functions: LinkedFunctions::default(),
        support_indirect_command_buffers: false,
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
    let scale = ConstantValue::at(0, DataType::UInt, alloc::vec![2, 0, 0, 0]);
    let named = |name: &str, data_type, value| ConstantValue {
        key: ConstantKey::Name(String::from(name)),
        data_type,
        value,
    };
    let refused = [
        (Vec::new(), "a required function constant has no value"),
        (
            alloc::vec![ConstantValue::at(0, DataType::UInt, alloc::vec![2, 0])],
            "a function constant value of another type",
        ),
        (
            alloc::vec![ConstantValue::at(0, DataType::Int, alloc::vec![2, 0, 0, 0])],
            "a function constant value of another type",
        ),
        (
            alloc::vec![scale.clone(), scale.clone()],
            "a function constant has two values",
        ),
        (
            alloc::vec![
                scale.clone(),
                named("scale", DataType::UInt, alloc::vec![0; 4])
            ],
            "a function constant has two values",
        ),
    ];
    for (constants, reason) in refused {
        assert_eq!(
            device.new_function(LIBRARY, "constants", &constants),
            Err(Error::Invalid(reason))
        );
    }
    // tint is optional; values of constants the function lacks are ignored.
    for constants in [
        alloc::vec![scale.clone()],
        alloc::vec![named("scale", DataType::UInt, alloc::vec![2, 0, 0, 0])],
        alloc::vec![
            scale.clone(),
            ConstantValue::at(1, DataType::Half3, alloc::vec![0; 8]),
            ConstantValue::at(9, DataType::Bool, alloc::vec![1]),
            named("missing", DataType::Bool, alloc::vec![1]),
        ],
    ] {
        assert!(
            device
                .new_function(LIBRARY, "constants", &constants)
                .is_ok()
        );
    }
}

#[test]
fn stages_link_visible_functions_and_name_them_by_handle() {
    let mut device = device();
    let kernel = device.new_function(LIBRARY, "kernel", &[]).unwrap();
    let visible = device.new_function(LIBRARY, "visible", &[]).unwrap();
    let tint = 1.0f32.to_le_bytes().to_vec();
    let tinted = device
        .new_function(
            LIBRARY,
            "tinted",
            &[ConstantValue::at(0, DataType::Float, tint.clone())],
        )
        .unwrap();
    let dynamic = device.new_library(fixture(false)).unwrap();
    assert_eq!(device.function_type(visible), Ok(FunctionType::Visible));
    assert_eq!(device.function_type(kernel), Ok(FunctionType::Kernel));
    assert!(device.function_interface(visible).is_err());

    let request = |functions: Vec<FunctionId>| ComputePipelineRequest {
        compute_function: kernel,
        threadgroup_size_is_multiple_of_thread_execution_width: false,
        max_total_threads_per_threadgroup: 0,
        stage_input: None,
        linked_functions: LinkedFunctions {
            functions,
            libraries: alloc::vec![dynamic],
            max_call_stack_depth: 4,
            ..LinkedFunctions::default()
        },
        support_indirect_command_buffers: false,
    };
    let pipeline = device
        .new_compute_pipeline(&request(alloc::vec![visible]))
        .unwrap();
    assert_eq!(
        device.compute_function_handle(pipeline, visible),
        Ok(Some(FunctionHandle(1)))
    );
    assert_eq!(device.compute_function_handle(pipeline, kernel), Ok(None));
    let dispatch = Specialization {
        workgroup_size: Some([64, 1, 1]),
        ..Specialization::default()
    };
    device
        .compute_variant(u64::from(pipeline.0), &dispatch)
        .unwrap();
    assert_eq!(
        device.compiler.compiled.last().unwrap().linking,
        Linking {
            functions: alloc::vec![LinkedFunction {
                library: 0,
                entry: String::from("visible"),
                constants: Vec::new(),
            }],
            private_functions: Vec::new(),
            libraries: alloc::vec![1],
            max_call_stack_depth: 4,
        }
    );
    assert_eq!(
        device.new_compute_pipeline(&request(alloc::vec![kernel])),
        Err(Error::Invalid("linked functions are visible functions"))
    );
    // A specialized function links with its values.
    let pipeline = device
        .new_compute_pipeline(&request(alloc::vec![tinted]))
        .unwrap();
    device
        .compute_variant(u64::from(pipeline.0), &dispatch)
        .unwrap();
    assert_eq!(
        device.compiler.compiled.last().unwrap().linking.functions,
        [LinkedFunction {
            library: 0,
            entry: String::from("tinted"),
            constants: alloc::vec![(0, tint)],
        }]
    );

    let vertex = device.new_function(LIBRARY, "vertex", &[]).unwrap();
    let fragment = device.new_function(LIBRARY, "fragment", &[]).unwrap();
    let render = RenderPipelineRequest {
        vertex_function: vertex,
        fragment_function: Some(fragment),
        vertex_descriptor: None,
        targets: color_targets(),
        input_primitive_topology: PrimitiveTopologyClass::Triangle,
        max_vertex_amplification_count: 1,
        tessellation: Default::default(),
        vertex_linked_functions: LinkedFunctions::default(),
        fragment_linked_functions: LinkedFunctions {
            functions: alloc::vec![visible],
            ..LinkedFunctions::default()
        },
        support_indirect_command_buffers: false,
    };
    let pipeline = device.new_render_pipeline(&render).unwrap();
    let handle =
        |device: &TestDevice, stage| device.render_function_handle(pipeline, stage, visible);
    assert_eq!(
        handle(&device, Stage::Fragment),
        Ok(Some(FunctionHandle(1)))
    );
    assert_eq!(handle(&device, Stage::Vertex), Ok(None));
    let linked: Vec<_> = device.compiler.compiled[device.compiler.compiled.len() - 2..]
        .iter()
        .map(|specialization| specialization.linking.functions.len())
        .collect();
    assert_eq!(linked, [0, 1], "only the fragment stage links");
}

#[test]
fn visible_function_tables_hold_handles() {
    let mut device = device();
    assert!(device.new_visible_function_table(0).is_err());
    let table = device.new_visible_function_table(4).unwrap();
    let (memory, offset, length) = device.buffer_memory(table).unwrap();
    assert_eq!(length, 32);
    device
        .set_visible_functions(table, 2, &[Some(FunctionHandle(3)), None])
        .unwrap();
    assert_eq!(
        device.set_visible_functions(table, 3, &[None, None]),
        Err(Error::Invalid("functions past the table's end"))
    );
    let mut bytes = [0xff; 32];
    device
        .backend()
        .read_memory(memory, offset, &mut bytes)
        .unwrap();
    let handles: Vec<u64> = bytes
        .chunks(8)
        .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
        .collect();
    assert_eq!(handles, [0, 0, 3, 0], "tables start with no functions");
}

#[test]
fn pipelines_keep_their_functions_and_libraries() {
    let mut device = device();
    let library = device.new_library(fixture(false)).unwrap();
    assert_eq!(
        device.library_function_names(library),
        Ok(&[String::from("kernel")][..])
    );
    assert_eq!(
        device.new_library(alloc::vec![0; 16]),
        Err(Error::Invalid("Metal library"))
    );
    let kernel = device.new_function(library, "kernel", &[]).unwrap();
    let visible = device.new_function(library, "visible", &[]).unwrap();
    let pipeline = device
        .new_compute_pipeline(&ComputePipelineRequest {
            compute_function: kernel,
            threadgroup_size_is_multiple_of_thread_execution_width: false,
            max_total_threads_per_threadgroup: 0,
            stage_input: None,
            linked_functions: LinkedFunctions {
                functions: alloc::vec![visible],
                ..LinkedFunctions::default()
            },
            support_indirect_command_buffers: false,
        })
        .unwrap();
    device.destroy_function(kernel).unwrap();
    device.destroy_function(visible).unwrap();
    device.destroy_library(library).unwrap();
    // Nothing new may use them, nor destroy them twice...
    let destroyed = Error::Invalid("unknown or destroyed object");
    assert_eq!(device.new_function(library, "kernel", &[]), Err(destroyed));
    assert_eq!(device.destroy_function(kernel), Err(destroyed));
    assert_eq!(device.destroy_library(library), Err(destroyed));
    // ...but the pipeline still compiles from them and names its functions.
    let dispatch = Specialization {
        workgroup_size: Some([64, 1, 1]),
        ..Specialization::default()
    };
    device
        .compute_variant(u64::from(pipeline.0), &dispatch)
        .unwrap();
    assert_eq!(
        device.compute_function_handle(pipeline, visible),
        Ok(Some(FunctionHandle(1)))
    );
    assert!(device.compiler.libraries[1].is_some());
    device.destroy_compute_pipeline(pipeline).unwrap();
    assert!(device.compiler.libraries[1].is_none());
    assert_eq!(device.function_type(kernel), Err(destroyed));
}

#[test]
fn render_pipelines_compile_their_functions_once() {
    let mut device = device();
    let vertex = device
        .new_function(
            LIBRARY,
            "vertex",
            &[ConstantValue::at(
                0,
                DataType::UInt,
                alloc::vec![1, 0, 0, 0],
            )],
        )
        .unwrap();
    let fragment = device.new_function(LIBRARY, "fragment", &[]).unwrap();
    assert!(device.new_function(LIBRARY, "missing", &[]).is_err());
    let request = RenderPipelineRequest {
        vertex_function: vertex,
        fragment_function: Some(fragment),
        vertex_descriptor: None,
        targets: color_targets(),
        input_primitive_topology: PrimitiveTopologyClass::Triangle,
        max_vertex_amplification_count: 1,
        tessellation: Default::default(),
        vertex_linked_functions: LinkedFunctions::default(),
        fragment_linked_functions: LinkedFunctions::default(),
        support_indirect_command_buffers: false,
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

    let unlinked = device.new_function(LIBRARY, "unlinked", &[]).unwrap();
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
    let mut device = device_on(backend);
    let descriptor = TextureDescriptor {
        width: 8,
        height: 4,
        mipmap_level_count: 2,
        options: options(StorageMode::Managed),
        ..texture(PixelFormat::Rgba8Unorm, TextureUsage::SHADER_READ)
    };
    let texture = device.new_texture(&descriptor).unwrap();
    let region = Region {
        slice: 0,
        level: 0,
        origin: [2, 1, 0],
        size: [2, 2, 1],
    };
    let tight = Strides {
        bytes_per_row: 8,
        bytes_per_image: 0,
    };
    let written: Vec<u8> = (0..16).collect();
    device
        .replace_region(texture, &region, &written, tight)
        .unwrap();
    let mut read = [0; 16];
    device
        .get_bytes(texture, &region, &mut read, tight)
        .unwrap();
    assert_eq!(read[..], written[..], "reads come from the CPU copy");
    // Rows of 8 bytes, 12 apart: the 4 between them are left alone.
    let strided = Strides {
        bytes_per_row: 12,
        ..tight
    };
    let mut read = [0xee; 20];
    device
        .get_bytes(texture, &region, &mut read, strided)
        .unwrap();
    assert_eq!(read[..8], written[..8]);
    assert_eq!(read[8..12], [0xee; 4]);
    assert_eq!(read[12..], written[8..]);
    let refused = [
        (&written[..12], tight, "the bytes end before the region"),
        (
            &written[..],
            Strides {
                bytes_per_row: 4,
                ..tight
            },
            "bytesPerRow is smaller than a row",
        ),
    ];
    for (bytes, strides, reason) in refused {
        assert_eq!(
            device.replace_region(texture, &region, bytes, strides),
            Err(Error::Invalid(reason))
        );
    }

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
    let patch = device.new_function(LIBRARY, "patch", &[]).unwrap();
    let fragment = device.new_function(LIBRARY, "fragment", &[]).unwrap();
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
        vertex_linked_functions: LinkedFunctions::default(),
        fragment_linked_functions: LinkedFunctions::default(),
        support_indirect_command_buffers: false,
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
    let kernel = device.new_function(LIBRARY, "kernel", &[]).unwrap();
    let pipeline = device
        .new_compute_pipeline(&ComputePipelineRequest {
            compute_function: kernel,
            threadgroup_size_is_multiple_of_thread_execution_width: false,
            max_total_threads_per_threadgroup: 0,
            stage_input: None,
            linked_functions: LinkedFunctions::default(),
            support_indirect_command_buffers: false,
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

    let object = device.new_function(LIBRARY, "object", &[]).unwrap();
    let mesh = device.new_function(LIBRARY, "mesh", &[]).unwrap();
    let fragment = device.new_function(LIBRARY, "fragment", &[]).unwrap();
    let request = MeshPipelineRequest {
        object_function: Some(object),
        mesh_function: mesh,
        fragment_function: Some(fragment),
        targets: color_targets(),
        max_vertex_amplification_count: 1,
        object_threads: StageThreads::default(),
        mesh_threads: StageThreads::default(),
        payload_memory_length: 0,
        object_linked_functions: LinkedFunctions::default(),
        mesh_linked_functions: LinkedFunctions::default(),
        fragment_linked_functions: LinkedFunctions::default(),
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
fn multisample_sparse_textures_map_msaa_blocks() {
    let mut device = device();
    let heap = device
        .new_heap(&HeapDescriptor {
            size: 4 << 16,
            options: options(StorageMode::Private),
            heap_type: HeapType::Sparse,
            sparse_page_size: SparsePageSize::Size64,
        })
        .unwrap();
    // Four-sample RGBA8 blocks are 64 by 64 texels.
    let descriptor = TextureDescriptor {
        texture_type: TextureType::D2Multisample,
        sample_count: 4,
        width: 128,
        height: 128,
        ..texture(PixelFormat::Rgba8Unorm, TextureUsage::RENDER_TARGET)
    };
    let sparse = device.new_heap_texture(heap, &descriptor, None).unwrap();
    assert_eq!(device.sparse_tail(sparse), Ok(Some((1, 0))), "no mip tail");
    let image = device.sparse_image(sparse).unwrap();

    let mut commands = device.new_command_buffer();
    commands
        .begin_resource_state(&mut device.resolver())
        .unwrap();
    commands
        .update_texture_mappings(
            image,
            SparseTextureMappingMode::Map,
            alloc::vec![MappingUpdate {
                level: 0,
                slice: 0,
                region: SparseRegion {
                    origin: [0; 3],
                    size: [2, 2, 1],
                },
            }],
        )
        .unwrap();
    commands.end_encoding(&mut device.resolver()).unwrap();
    device.commit(commands).unwrap();
    let segments = device.backend().submissions.last().unwrap().clone();
    assert_eq!(segments.last().unwrap().binds.len(), 4);
    assert_eq!(device.heap_usage(heap, 1), Ok((4 << 16, 0)));
    device.destroy_texture(sparse).unwrap();
    device.destroy_heap(heap).unwrap();
}

#[test]
fn indirect_mapping_updates_bind_once_their_arguments_are_read() {
    let mut device = device();
    let heap = device
        .new_heap(&HeapDescriptor {
            size: 4 << 16,
            options: options(StorageMode::Private),
            heap_type: HeapType::Sparse,
            sparse_page_size: SparsePageSize::Size64,
        })
        .unwrap();
    // Two by two tiles and no mip tail.
    let descriptor = TextureDescriptor {
        width: 256,
        height: 256,
        ..texture(PixelFormat::Rgba8Unorm, TextureUsage::SHADER_READ)
    };
    let sparse = device.new_heap_texture(heap, &descriptor, None).unwrap();
    let image = device.sparse_image(sparse).unwrap();
    let indirect = BufferRef {
        buffer: Buffer(99),
        offset: 0,
        address: 99 << 32,
        length: 64,
    };
    let encode = |device: &mut TestDevice, offset| {
        let mut commands = device.new_command_buffer();
        commands
            .begin_resource_state(&mut device.resolver())
            .unwrap();
        let encoded = commands.update_texture_mapping_indirect(
            &mut device.resolver(),
            image,
            SparseTextureMappingMode::Map,
            indirect,
            offset,
        );
        commands.end_encoding(&mut device.resolver()).unwrap();
        encoded.map(|()| commands)
    };
    assert!(
        encode(&mut device, 2).is_err(),
        "offsets are 4-byte aligned"
    );
    assert!(
        encode(&mut device, 40).is_err(),
        "the arguments are in the buffer"
    );

    // Commits an update and plays the GPU: its copy of the arguments lands
    // and signals its step.
    let copied = |device: &mut TestDevice, words: [u32; 8]| {
        let submitted = device.backend().submissions.len();
        let copy = device.backend().submissions.last().unwrap().clone();
        assert_eq!(copy.len(), 1, "the segments from the update's on are held");
        let at = copy[0]
            .commands
            .iter()
            .find_map(|command| match command {
                Command::CopyBuffer { src, regions, .. } if *src == Buffer(99) => {
                    Some(regions[0].dst_offset)
                }
                _ => None,
            })
            .unwrap();
        let (steps, step) = *copy[0].signals.last().unwrap();
        let backend = device.backend();
        let memory = backend.writes.last().unwrap().0;
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        backend.write_memory(memory, at, &bytes).unwrap();
        (submitted, steps, step)
    };

    let commands = encode(&mut device, 32).unwrap();
    device.commit(commands).unwrap();
    let later = submit(&mut device);
    // Origin (1, 0, 0), size (1, 2, 1), level 0, slice 0: the right column.
    let (submitted, steps, step) = copied(&mut device, [1, 0, 0, 1, 2, 1, 0, 0]);
    assert_eq!(
        device.wait(later, 0),
        Ok(false),
        "later command buffers wait"
    );
    assert_eq!(device.backend().submissions.len(), submitted);
    device.backend().signal_semaphore(steps, step).unwrap();
    assert_eq!(device.poll(), Ok(0));
    let submissions = &device.backend().submissions;
    assert_eq!(submissions.len(), submitted + 2);
    assert_eq!(submissions[submitted][0].binds.len(), 2);
    assert!(submissions[submitted + 1][0].binds.is_empty());
    assert_eq!(device.heap_usage(heap, 1), Ok((2 << 16, 2 << 16)));

    // Arguments naming no region of the texture map nothing.
    let commands = encode(&mut device, 0).unwrap();
    let serial = device.commit(commands).unwrap();
    let (_, steps, step) = copied(&mut device, [0, 0, 0, 1, 1, 1, 5, 0]);
    device.backend().signal_semaphore(steps, step).unwrap();
    assert_eq!(device.poll(), Ok(0));
    assert!(
        device.backend().submissions.last().unwrap()[0]
            .binds
            .is_empty()
    );
    assert_eq!(device.heap_usage(heap, 1), Ok((2 << 16, 2 << 16)));
    complete(&mut device, serial);
    device.destroy_texture(sparse).unwrap();
    device.destroy_heap(heap).unwrap();
}

#[test]
fn indirect_commands_execute_snapshots_of_their_buffer() {
    let mut device = device();
    let kernel = device.new_function(LIBRARY, "kernel", &[]).unwrap();
    let pipeline = device
        .new_compute_pipeline(&ComputePipelineRequest {
            compute_function: kernel,
            threadgroup_size_is_multiple_of_thread_execution_width: false,
            max_total_threads_per_threadgroup: 0,
            stage_input: None,
            linked_functions: LinkedFunctions::default(),
            support_indirect_command_buffers: false,
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

/// Draws under inherited state with one vertex buffer.
fn draws() -> IndirectCommandBufferDescriptor {
    IndirectCommandBufferDescriptor {
        command_types: IndirectCommandType::DRAW,
        inherit_pipeline_state: true,
        inherit_buffers: false,
        inherit_cull_mode: true,
        inherit_depth_stencil_state: true,
        inherit_depth_bias: true,
        inherit_depth_clip_mode: true,
        inherit_front_facing_winding: true,
        inherit_triangle_fill_mode: true,
        max_vertex_buffer_bind_count: 1,
        max_fragment_buffer_bind_count: 0,
        max_kernel_buffer_bind_count: 0,
        max_kernel_threadgroup_memory_bind_count: 0,
        max_object_buffer_bind_count: 0,
        max_mesh_buffer_bind_count: 0,
        support_ray_tracing: false,
        support_dynamic_attribute_stride: false,
    }
}

#[test]
fn functions_that_set_command_barriers_order_resident_buffers() {
    let mut device = device();
    let resident = device.new_indirect_command_buffer(&draws(), 1).unwrap();
    device
        .indirect_command_buffer_resource_id(resident)
        .unwrap();
    let later = device.new_indirect_command_buffer(&draws(), 1).unwrap();
    let barriers =
        |device: &Device<_, _>, id| device.indirect_command_buffer(id).unwrap().has_barriers();
    device.new_function(LIBRARY, "visible", &[]).unwrap();
    assert!(!barriers(&device, resident));
    device.new_function(LIBRARY, "barriers", &[]).unwrap();
    assert!(barriers(&device, resident));
    device.indirect_command_buffer_resource_id(later).unwrap();
    assert!(barriers(&device, later));
}

#[test]
fn handing_out_an_indirect_address_keeps_commands_as_records() {
    let mut device = device();
    let icb = device.new_indirect_command_buffer(&draws(), 2).unwrap();
    device
        .indirect_command_buffer_mut(icb)
        .unwrap()
        .render_command(1)
        .unwrap()
        .draw_primitives(PrimitiveType::Point, 0, 5, 1, 0)
        .unwrap();
    let address = device.indirect_command_buffer_resource_id(icb).unwrap();
    assert_eq!(device.indirect_command_buffer_resource_id(icb), Ok(address));
    let layout = *device
        .indirect_command_buffer(icb)
        .unwrap()
        .records()
        .unwrap();
    let (memory, base, image) = device.backend().writes.last().unwrap().clone();
    assert_eq!(image.len() as u64, layout.bytes());
    let record = layout.record(1) as usize;
    assert_eq!(image[record], RecordLayout::DRAW as u8);

    // CPU encoding reaches the records when the next command buffer commits.
    device
        .indirect_command_buffer_mut(icb)
        .unwrap()
        .render_command(1)
        .unwrap()
        .reset()
        .unwrap();
    let written = device.backend().writes.len();
    let commands = device.new_command_buffer();
    device.commit(commands).unwrap();
    let mut action = [0xff; 4];
    device
        .backend()
        .read_memory(memory, base + layout.record(1), &mut action)
        .unwrap();
    assert_eq!(action, [0; 4]);
    assert_eq!(device.backend().writes.len(), written + 1);

    let mut commands = device.new_command_buffer();
    commands.begin_blit().unwrap();
    commands
        .reset_commands(&mut device.resolver(), icb, 0..2)
        .unwrap();
    commands.end_encoding(&mut device.resolver()).unwrap();
    device.commit(commands).unwrap();
    let segments = device.backend().submissions.last().unwrap().clone();
    let fill = segments[0]
        .commands
        .iter()
        .find_map(|command| match command {
            Command::FillBuffer { offset, size, .. } => Some((*offset, *size)),
            _ => None,
        });
    assert_eq!(fill, Some((layout.record(0), 2 * u64::from(layout.stride))));
    device.destroy_indirect_command_buffer(icb).unwrap();
}

#[test]
fn synchronized_managed_buffers_are_invalidated_on_completion() {
    let mut device = device();
    let managed = device
        .new_buffer(256, options(StorageMode::Managed))
        .unwrap();
    let shared = device
        .new_buffer(256, options(StorageMode::Shared))
        .unwrap();
    assert_eq!(
        device.managed_range(shared),
        Err(Error::Invalid(
            "synchronizeResource: is for managed resources"
        ))
    );
    let range = device.managed_range(managed).unwrap();
    let mut commands = device.new_command_buffer();
    commands.begin_blit().unwrap();
    commands.synchronize_buffer(range).unwrap();
    commands.end_encoding(&mut device.resolver()).unwrap();
    let serial = device.commit(commands).unwrap();
    // The managed buffer outlives its handle until the work completes.
    device.destroy_buffer(managed).unwrap();
    assert!(device.backend().invalidated.is_empty());
    complete(&mut device, serial);
    let invalidated = (range.memory, range.offset, range.length);
    assert_eq!(device.backend().invalidated, [invalidated]);
}

#[test]
fn uncommitted_command_buffers_return_their_upload_memory() {
    let mut device = device();
    let encode = |device: &mut TestDevice| {
        let mut commands = device.new_command_buffer();
        commands.begin_compute(DispatchType::Serial).unwrap();
        commands
            .set_compute_bytes(&mut device.resolver(), &[7; 64], 0)
            .unwrap();
        commands
    };
    let commands = encode(&mut device);
    let created = device.backend().next;
    assert_eq!(
        device.commit(commands),
        Err(Error::Invalid("another encoder is still encoding"))
    );
    let commands = encode(&mut device);
    device.discard(commands);
    let mut commands = encode(&mut device);
    commands.end_encoding(&mut device.resolver()).unwrap();
    device.commit(commands).unwrap();
    assert_eq!(
        device.backend().next,
        created,
        "each command buffer reused the first one's chunk"
    );
}
