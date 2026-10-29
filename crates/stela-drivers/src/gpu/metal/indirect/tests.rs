use super::*;
use crate::gpu::metal::{nvidia::fixture::capabilities, vulkan::object::Buffer};

fn descriptor(command_types: IndirectCommandType) -> IndirectCommandBufferDescriptor {
    IndirectCommandBufferDescriptor {
        command_types,
        inherit_pipeline_state: false,
        inherit_buffers: false,
        inherit_cull_mode: true,
        inherit_depth_stencil_state: true,
        inherit_depth_bias: true,
        inherit_depth_clip_mode: true,
        inherit_front_facing_winding: true,
        inherit_triangle_fill_mode: true,
        max_vertex_buffer_bind_count: 4,
        max_fragment_buffer_bind_count: 2,
        max_kernel_buffer_bind_count: 4,
        max_kernel_threadgroup_memory_bind_count: 1,
        max_object_buffer_bind_count: 0,
        max_mesh_buffer_bind_count: 0,
        support_ray_tracing: false,
        support_dynamic_attribute_stride: false,
    }
}

fn buffer_ref(id: u64) -> BufferRef {
    BufferRef {
        buffer: Buffer(id),
        offset: 0,
        address: id << 32,
        length: 256,
    }
}

#[test]
fn descriptors_hold_one_kind_of_command() {
    let caps = capabilities();
    let mixed = descriptor(IndirectCommandType::DRAW | IndirectCommandType::CONCURRENT_DISPATCH);
    assert!(IndirectCommandBuffer::new(&caps, &mixed, 4).is_err());
    assert!(IndirectCommandBuffer::new(&caps, &descriptor(IndirectCommandType::EMPTY), 4).is_err());
    let draws = descriptor(IndirectCommandType::DRAW);
    assert!(IndirectCommandBuffer::new(&caps, &draws, 0).is_err());
    let ray_tracing = IndirectCommandBufferDescriptor {
        support_ray_tracing: true,
        ..draws
    };
    assert_eq!(
        IndirectCommandBuffer::new(&caps, &ray_tracing, 4),
        Err(Error::Unsupported("ray tracing in indirect commands"))
    );
    let wide = IndirectCommandBufferDescriptor {
        max_vertex_buffer_bind_count: 32,
        ..draws
    };
    assert!(IndirectCommandBuffer::new(&caps, &wide, 4).is_err());
    let buffer = IndirectCommandBuffer::new(&caps, &draws, 4).unwrap();
    assert_eq!(buffer.size(), 4);
    assert!(buffer.descriptor().renders());
    assert!(
        buffer
            .commands(0..4)
            .unwrap()
            .iter()
            .all(|command| command.action.is_none())
    );
}

#[test]
fn render_commands_follow_the_descriptor() {
    let mut buffer =
        IndirectCommandBuffer::new(&capabilities(), &descriptor(IndirectCommandType::DRAW), 2)
            .unwrap();
    assert!(buffer.compute_command(0).is_err());
    assert!(buffer.render_command(2).is_err());
    let mut command = buffer.render_command(1).unwrap();
    command
        .set_buffer(Stage::Vertex, buffer_ref(1), 16, 3)
        .unwrap();
    command
        .set_buffer(Stage::Vertex, buffer_ref(2), 0, 3)
        .unwrap();
    assert!(
        command
            .set_buffer(Stage::Vertex, buffer_ref(1), 0, 4)
            .is_err(),
        "four vertex buffers"
    );
    assert!(
        command
            .set_buffer(Stage::Fragment, buffer_ref(1), 512, 0)
            .is_err()
    );
    assert!(
        command
            .set_buffer(Stage::Kernel, buffer_ref(1), 0, 0)
            .is_err()
    );
    assert!(
        command
            .set_vertex_buffer_with_stride(buffer_ref(1), 0, 16, 0)
            .is_err(),
        "no dynamic strides"
    );
    assert!(command.set_cull_mode(CullMode::Back).is_err(), "inherited");
    assert!(
        command
            .draw_indexed_primitives(
                PrimitiveType::Triangle,
                3,
                IndexType::UInt16,
                buffer_ref(4),
                0,
                1,
                0,
                0
            )
            .is_err(),
        "indexed draws are not among the types"
    );
    command
        .draw_primitives(PrimitiveType::Triangle, 0, 3, 1, 0)
        .unwrap();
    command.set_barrier().unwrap();
    let encoded = &buffer.commands(1..2).unwrap()[0];
    assert_eq!(
        encoded.buffers.len(),
        1,
        "the second bind replaced the first"
    );
    assert_eq!(encoded.buffers[0].buffer, buffer_ref(2));
    assert!(encoded.barrier);
    assert!(matches!(
        encoded.action,
        Some(IndirectAction::Draw {
            vertex_count: 3,
            ..
        })
    ));

    buffer.render_command(1).unwrap().reset().unwrap();
    assert_eq!(
        buffer.commands(1..2).unwrap()[0],
        IndirectCommand::default()
    );
}

#[test]
fn inherited_state_cannot_be_set() {
    let inheriting = IndirectCommandBufferDescriptor {
        inherit_pipeline_state: true,
        inherit_buffers: true,
        inherit_cull_mode: false,
        ..descriptor(IndirectCommandType::CONCURRENT_DISPATCH)
    };
    let mut buffer = IndirectCommandBuffer::new(&capabilities(), &inheriting, 1).unwrap();
    let mut command = buffer.compute_command(0).unwrap();
    assert!(command.set_kernel_buffer(buffer_ref(1), 0, 0).is_err());
    assert!(command.set_threadgroup_memory_length(64, 1).is_err());
    command.set_threadgroup_memory_length(64, 0).unwrap();
    command.set_threadgroup_memory_length(128, 0).unwrap();
    let threads = Size {
        width: 64,
        height: 1,
        depth: 1,
    };
    assert!(
        command
            .concurrent_dispatch_threads([64, 1, 1], threads)
            .is_err()
    );
    command
        .concurrent_dispatch_threadgroups([2, 1, 1], threads)
        .unwrap();
    assert_eq!(
        buffer.commands(0..1).unwrap()[0].threadgroup_lengths,
        [(0, 128)]
    );
}

#[test]
fn copies_check_the_destination_and_resets_clear() {
    let caps = capabilities();
    let mut source =
        IndirectCommandBuffer::new(&caps, &descriptor(IndirectCommandType::DRAW), 3).unwrap();
    for index in 0..3 {
        let mut command = source.render_command(index).unwrap();
        command
            .set_buffer(Stage::Vertex, buffer_ref(1), 0, 3)
            .unwrap();
        command
            .draw_primitives(PrimitiveType::Point, index as u32, 1, 1, 0)
            .unwrap();
    }
    let narrow = IndirectCommandBufferDescriptor {
        max_vertex_buffer_bind_count: 2,
        ..descriptor(IndirectCommandType::DRAW)
    };
    let mut destination = IndirectCommandBuffer::new(&caps, &narrow, 4).unwrap();
    assert!(
        destination.copy_from(&source, 0..2, 0).is_err(),
        "the destination binds two vertex buffers"
    );
    let mut destination =
        IndirectCommandBuffer::new(&caps, &descriptor(IndirectCommandType::DRAW), 4).unwrap();
    assert!(
        destination.copy_from(&source, 1..3, 3).is_err(),
        "past the end"
    );
    destination.copy_from(&source, 1..3, 2).unwrap();
    assert_eq!(
        destination.commands(2..4).unwrap(),
        source.commands(1..3).unwrap()
    );
    assert_eq!(
        destination.commands(0..1).unwrap()[0],
        IndirectCommand::default()
    );

    destination.reset(2..3).unwrap();
    assert!(destination.commands(2..3).unwrap()[0].action.is_none());
    assert!(destination.commands(3..4).unwrap()[0].action.is_some());
    assert!(destination.reset(3..5).is_err());
}

fn word(bytes: &[u8], offset: u32) -> u32 {
    let offset = offset as usize;
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn double(bytes: &[u8], offset: u32) -> u64 {
    let offset = offset as usize;
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn resident_images_hold_each_command_as_a_record() {
    let descriptor = IndirectCommandBufferDescriptor {
        support_dynamic_attribute_stride: true,
        ..descriptor(IndirectCommandType::DRAW | IndirectCommandType::DRAW_INDEXED)
    };
    let mut buffer = IndirectCommandBuffer::new(&capabilities(), &descriptor, 3).unwrap();
    let mut command = buffer.render_command(1).unwrap();
    command
        .set_vertex_buffer_with_stride(buffer_ref(1), 16, 12, 2)
        .unwrap();
    command
        .set_buffer(Stage::Fragment, buffer_ref(2), 0, 1)
        .unwrap();
    command.set_barrier().unwrap();
    command
        .draw_indexed_primitives(
            PrimitiveType::TriangleStrip,
            6,
            IndexType::UInt32,
            buffer_ref(3),
            8,
            2,
            -1,
            4,
        )
        .unwrap();
    let handle = IndirectPipeline { class: 0, index: 3 }.handle();
    buffer.commands[1].pipeline = Some(CommandPipeline { id: 7, handle });

    let (layout, image) = buffer.resident_image().unwrap();
    assert_eq!(layout.tables, [80, 144]);
    assert_eq!(layout.table_slots, [4, 2]);
    assert_eq!(
        (layout.words, layout.word_count, layout.stride),
        (176, 4, 192)
    );
    assert_eq!(image.len() as u64, layout.bytes());
    assert_eq!(&image[..64], &layout.header());
    assert_eq!(word(&image, RecordLayout::HEADER_STRIDE), 192);
    let start = layout.record(1) as usize;
    assert!(image[64..start].iter().all(|&byte| byte == 0), "reset");
    let record = &image[start..start + 192];
    assert_eq!(
        word(record, RecordLayout::ACTION),
        RecordLayout::DRAW_INDEXED
    );
    assert_eq!(word(record, RecordLayout::BARRIER), 1);
    assert_eq!(double(record, RecordLayout::PIPELINE), handle);
    let arguments: Vec<u32> = (0..6)
        .map(|index| word(record, RecordLayout::VERTICES + 4 * index))
        .collect();
    assert_eq!(arguments, [6, 2, 0, u32::MAX, 4, 4]);
    assert_eq!(double(record, RecordLayout::INDEX_ADDRESS), (3 << 32) + 8);
    assert_eq!(word(record, RecordLayout::INDEX_LENGTH), 248);
    assert_eq!(word(record, RecordLayout::INDEX_TYPE), 1);
    assert_eq!(double(record, 80 + 16), (1 << 32) + 16);
    assert_eq!(double(record, 80 + 8 * 6), 240);
    assert_eq!(word(record, 176 + 8), 12);
    assert_eq!(double(record, 144 + 8), 2 << 32);
    assert_eq!(double(record, 144 + 8 * 3), 256);
}

#[test]
fn resident_buffers_write_what_cpu_encoding_changes() {
    let types = IndirectCommandType::DRAW | IndirectCommandType::DRAW_INDEXED;
    let mut buffer = IndirectCommandBuffer::new(&capabilities(), &descriptor(types), 2).unwrap();
    let (layout, _) = buffer.resident_image().unwrap();
    buffer.make_resident(layout);
    assert!(buffer.commands(0..1).is_err(), "records are the contents");
    let base = layout.record(1);
    let mut command = buffer.render_command(1).unwrap();
    command
        .set_buffer(Stage::Vertex, buffer_ref(1), 0, 1)
        .unwrap();
    command
        .draw_primitives(PrimitiveType::Line, 2, 3, 1, 0)
        .unwrap();
    assert!(
        command
            .draw_indexed_primitives(
                PrimitiveType::Line,
                3,
                IndexType::UInt32,
                buffer_ref(3),
                2,
                1,
                0,
                0,
            )
            .is_err(),
        "misaligned index offset"
    );
    assert!(command.set_depth_bias(1.0, 0.0, 0.0).is_err());
    let draw: Vec<u8> = [3u32, 1, 2, 0, 0, 1]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    assert!(buffer.has_writes());
    assert_eq!(
        buffer.take_writes(),
        [
            (base + 88, (1u64 << 32).to_le_bytes().to_vec()),
            (base + 80 + 8 * 5, 256u64.to_le_bytes().to_vec()),
            (base, RecordLayout::DRAW.to_le_bytes().to_vec()),
            (base + 16, draw),
        ]
    );
    assert!(matches!(
        buffer.commands[1].action,
        Some(IndirectAction::Draw { .. })
    ));
    assert!(!buffer.has_writes());

    buffer.reset(0..2).unwrap();
    assert_eq!(
        buffer.take_writes(),
        [(layout.record(0), alloc::vec![0; 2 * layout.stride as usize])]
    );
}

#[test]
fn records_hold_only_what_the_gpu_executes() {
    let caps = capabilities();
    let refused = |descriptor: &IndirectCommandBufferDescriptor| {
        let buffer = IndirectCommandBuffer::new(&caps, descriptor, 1).unwrap();
        matches!(buffer.resident_image(), Err(Error::Unsupported(_)))
    };
    assert!(refused(&descriptor(IndirectCommandType::DRAW_PATCHES)));
    assert!(refused(&IndirectCommandBufferDescriptor {
        inherit_cull_mode: false,
        ..descriptor(IndirectCommandType::DRAW)
    }));

    let compute = descriptor(IndirectCommandType::CONCURRENT_DISPATCH);
    let mut buffer = IndirectCommandBuffer::new(&caps, &compute, 1).unwrap();
    let mut command = buffer.compute_command(0).unwrap();
    command.set_threadgroup_memory_length(64, 0).unwrap();
    command.set_stage_in_region([1, 2, 3], [4, 5, 6]).unwrap();
    let threads = Size {
        width: 8,
        height: 4,
        depth: 1,
    };
    command
        .concurrent_dispatch_threadgroups([2, 3, 1], threads)
        .unwrap();
    let (layout, image) = buffer.resident_image().unwrap();
    assert_eq!((layout.tables, layout.table_slots), ([80, 144], [4, 0]));
    assert_eq!(
        (layout.words, layout.word_count, layout.stride),
        (144, 1, 160)
    );
    let record = &image[64..];
    assert_eq!(word(record, RecordLayout::ACTION), RecordLayout::DISPATCH);
    let words = |at: u32, count: u32| -> Vec<u32> {
        (0..count)
            .map(|index| word(record, at + 4 * index))
            .collect()
    };
    assert_eq!(words(RecordLayout::GRID, 6), [2, 3, 1, 8, 4, 1]);
    assert_eq!(
        words(RecordLayout::STAGE_IN_ORIGIN, 7),
        [1, 2, 3, 4, 5, 6, 1]
    );
    assert_eq!(word(record, 144), 64);

    buffer.commands[0].pipeline = Some(CommandPipeline { id: 1, handle: 0 });
    assert!(
        matches!(buffer.resident_image(), Err(Error::Invalid(_))),
        "the pipeline has no handle"
    );
}
