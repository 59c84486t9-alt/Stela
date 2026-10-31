use super::{
    IDENTITY, Memory, TestService, call, connect, cpu_buffer, imported, options, service_on,
    status, texture,
};
use crate::metal::{
    abi::{
        CompareFunction, HeapType, SamplerAddressMode, SamplerBorderColor, SamplerMinMagFilter,
        SamplerMipFilter, SamplerReductionMode, SparsePageSize, StorageMode, TextureType,
    },
    device::fixture::MockBackend,
    pixel_format::PixelFormat,
    service::{
        GuestMemory, Outcome,
        wire::{
            AUTOMATIC, BufferRangeRequest, BufferResponse, Empty, FormatAlignmentsResponse, Handle,
            HeapBufferSizeRequest, HeapDescriptorRecord, HeapUsageRequest, HeapUsageResponse,
            NewBufferRequest, NewHeapBufferRequest, NewImportedBufferRequest,
            NewTextureViewRequest, Operation, PixelFormatRequest, RegionRecord,
            SamplerDescriptorRecord, SamplerResponse, SizeAndAlignRecord, SparseTileRequest,
            SparseTileResponse, Status, TextureBytesRequest, TextureResponse,
        },
    },
};
use core::num::NonZeroU64;
use stela_contracts::gate::MemoryRange;

mod imports;

fn release(service: &mut TestService, connection: NonZeroU64, handle: u64) -> Status {
    status(call::<_, Empty>(
        service,
        connection,
        Operation::Release,
        &Handle { handle },
        &mut Memory::default(),
    ))
}

#[test]
fn buffers_answer_their_addresses() {
    let mut service = service_on(MockBackend::new());
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let mut buffer = |storage_mode| {
        let request = NewBufferRequest {
            length: 4096,
            options: options(storage_mode),
        };
        call::<_, BufferResponse>(
            &mut service,
            connection,
            Operation::NewBuffer,
            &request,
            memory,
        )
    };
    let private = buffer(StorageMode::Private).unwrap();
    assert_ne!(private.gpu_address, 0);
    assert_eq!((private.allocated_size, private.heap_offset), (4096, 0));
    assert_eq!(status(buffer(StorageMode::Shared)), Status::Invalid);
    let shared = cpu_buffer(&mut service, connection, 4096, StorageMode::Shared);
    assert_eq!(
        call::<_, BufferResponse>(
            &mut service,
            connection,
            Operation::NewBuffer,
            &NewBufferRequest {
                length: 4096,
                options: 1 << 20,
            },
            memory,
        ),
        Err(Outcome {
            status: Status::Malformed,
            reason: "resource options",
        })
    );
    let modified = BufferRangeRequest {
        buffer: shared.handle,
        offset: 0,
        length: 16,
    };
    assert_eq!(
        call::<_, Empty>(
            &mut service,
            connection,
            Operation::BufferDidModifyRange,
            &modified,
            memory,
        ),
        Err(Outcome {
            status: Status::Invalid,
            reason: "didModifyRange: is for managed buffers",
        })
    );
}

#[test]
fn textures_trade_regions_with_guest_memory() {
    let mut backend = MockBackend::new();
    backend.physical.as_mut().unwrap().features.host_image_copy = false;
    let mut service = service_on(backend);
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let texture: TextureResponse = call(
        &mut service,
        connection,
        Operation::NewTexture,
        &texture(StorageMode::Managed),
        memory,
    )
    .unwrap();
    assert_ne!(texture.resource_id, 0);
    assert_eq!(texture.sparse, 0);

    // Two rows of two texels, 12 bytes apart, in and tightly packed out.
    let region = RegionRecord {
        slice: 0,
        level: 0,
        origin: [2, 1, 0],
        size: [2, 2, 1],
    };
    let mut written = [0xee; 20];
    written[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    written[12..].copy_from_slice(&[9, 10, 11, 12, 13, 14, 15, 16]);
    let replace = TextureBytesRequest {
        texture: texture.handle,
        region,
        bytes: memory.put(&written),
        bytes_per_row: 12,
        bytes_per_image: 0,
    };
    call::<_, Empty>(
        &mut service,
        connection,
        Operation::ReplaceRegion,
        &replace,
        memory,
    )
    .unwrap();
    let read = TextureBytesRequest {
        bytes: memory.put(&[0; 16]),
        bytes_per_row: 8,
        ..replace
    };
    call::<_, Empty>(&mut service, connection, Operation::GetBytes, &read, memory).unwrap();
    assert_eq!(
        memory.read(read.bytes).unwrap(),
        (1..=16).collect::<alloc::vec::Vec<u8>>()
    );

    // A view keeps its texture until it is released.
    let view_request = NewTextureViewRequest {
        texture: texture.handle,
        pixel_format: PixelFormat::Rgba8UnormSrgb.raw(),
        texture_type: TextureType::D2.raw(),
        levels: [0, 1],
        slices: [0, 1],
        swizzle: IDENTITY,
        reserved: 0,
    };
    let view: Result<TextureResponse, _> = call(
        &mut service,
        connection,
        Operation::NewTextureView,
        &view_request,
        memory,
    );
    let view = view.unwrap();
    assert_eq!(
        release(&mut service, connection, texture.handle),
        Status::Invalid
    );
    assert_eq!(release(&mut service, connection, view.handle), Status::Ok);
    assert_eq!(
        release(&mut service, connection, texture.handle),
        Status::Ok
    );
}

#[test]
fn heaps_place_resources_and_report_their_usage() {
    let mut service = service_on(MockBackend::new());
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let heap = HeapDescriptorRecord {
        memory: 0,
        size: 1 << 20,
        options: options(StorageMode::Private),
        heap_type: HeapType::Automatic.raw(),
        sparse_page_size: SparsePageSize::Size16.raw(),
    };
    let heap: Handle = call(&mut service, connection, Operation::NewHeap, &heap, memory).unwrap();
    let size_request = HeapBufferSizeRequest {
        length: 1000,
        options: options(StorageMode::Private),
    };
    let size: SizeAndAlignRecord = call(
        &mut service,
        connection,
        Operation::HeapBufferSizeAndAlign,
        &size_request,
        memory,
    )
    .unwrap();
    assert_eq!(size.align, 256);
    let placed = NewHeapBufferRequest {
        heap: heap.handle,
        length: 1000,
        options: options(StorageMode::Private),
        offset: AUTOMATIC,
    };
    let buffer: BufferResponse = call(
        &mut service,
        connection,
        Operation::NewHeapBuffer,
        &placed,
        memory,
    )
    .unwrap();
    assert_eq!(buffer.allocated_size, size.size);
    let usage: HeapUsageResponse = call(
        &mut service,
        connection,
        Operation::HeapUsage,
        &HeapUsageRequest {
            heap: heap.handle,
            alignment: 256,
        },
        memory,
    )
    .unwrap();
    assert_eq!(usage.used_size, size.size);
    assert_eq!(usage.max_available_size, (1 << 20) - size.size);

    let aliasable = |service: &mut TestService, handle| {
        status(call::<_, Empty>(
            service,
            connection,
            Operation::MakeAliasable,
            &Handle { handle },
            &mut Memory::default(),
        ))
    };
    assert_eq!(aliasable(&mut service, heap.handle), Status::StaleHandle);
    assert_eq!(aliasable(&mut service, buffer.handle), Status::Ok);
    assert_eq!(
        release(&mut service, connection, heap.handle),
        Status::Invalid
    );
    assert_eq!(release(&mut service, connection, buffer.handle), Status::Ok);
    assert_eq!(release(&mut service, connection, heap.handle), Status::Ok);
}

#[test]
fn pixel_formats_answer_their_alignments_and_tiles() {
    let mut service = service_on(MockBackend::new());
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let format = PixelFormat::Rgba8Unorm.raw();
    let request = PixelFormatRequest {
        pixel_format: format,
    };
    let alignments: FormatAlignmentsResponse = call(
        &mut service,
        connection,
        Operation::FormatAlignments,
        &request,
        memory,
    )
    .unwrap();
    assert!(alignments.linear_texture.is_power_of_two());
    let request = SparseTileRequest {
        texture_type: TextureType::D1.raw(),
        pixel_format: format,
        sample_count: 1,
    };
    let tile: SparseTileResponse = call(
        &mut service,
        connection,
        Operation::SparseTileSize,
        &request,
        memory,
    )
    .unwrap();
    assert_eq!(tile.size, [0; 3], "a 1D texture is never sparse");
}

#[test]
fn samplers_decode_their_descriptors() {
    let mut service = service_on(MockBackend::new());
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let descriptor = SamplerDescriptorRecord {
        min_filter: SamplerMinMagFilter::Linear.raw(),
        mag_filter: SamplerMinMagFilter::Linear.raw(),
        mip_filter: SamplerMipFilter::NotMipmapped.raw(),
        max_anisotropy: 1,
        address_modes: [SamplerAddressMode::Repeat.raw(); 3],
        border_color: SamplerBorderColor::TransparentBlack.raw(),
        reduction_mode: SamplerReductionMode::WeightedAverage.raw(),
        compare_function: CompareFunction::Never.raw(),
        lod_min_clamp: 0.0,
        lod_max_clamp: f32::MAX,
        normalized_coordinates: 1,
        reserved: 0,
    };
    let sampler: SamplerResponse = call(
        &mut service,
        connection,
        Operation::NewSampler,
        &descriptor,
        memory,
    )
    .unwrap();
    assert_ne!(sampler.resource_id, 0);
    let malformed = SamplerDescriptorRecord {
        normalized_coordinates: 2,
        ..descriptor
    };
    assert_eq!(
        status(call::<_, SamplerResponse>(
            &mut service,
            connection,
            Operation::NewSampler,
            &malformed,
            memory,
        )),
        Status::Malformed
    );
    assert_eq!(
        release(&mut service, connection, sampler.handle),
        Status::Ok
    );
}

#[test]
fn a_cpu_reaches_buffers_of_imported_memory() {
    let mut service = service_on(MockBackend::new());
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let shared = cpu_buffer(&mut service, connection, 8192, StorageMode::Shared);
    assert_eq!(shared.allocated_size, 8192);

    // The buffer took the memory's handle, as it does the memory.
    let handle = imported(&mut service, connection, 8192);
    let request = NewImportedBufferRequest {
        memory: handle,
        length: 8192,
        options: options(StorageMode::Managed),
    };
    let new = |service: &mut TestService, memory: &mut Memory, request| {
        status(call::<_, BufferResponse>(
            service,
            connection,
            Operation::NewImportedBuffer,
            &request,
            memory,
        ))
    };
    let private = NewImportedBufferRequest {
        options: options(StorageMode::Private),
        ..request
    };
    let long = NewImportedBufferRequest {
        length: 8193,
        ..request
    };
    assert_eq!(new(&mut service, memory, private), Status::Invalid);
    assert_eq!(new(&mut service, memory, long), Status::Invalid);
    assert_eq!(new(&mut service, memory, request), Status::Ok);
    assert_eq!(new(&mut service, memory, request), Status::StaleHandle);
}

#[test]
fn imported_memory_retires_once_the_gpu_is_done_with_it() {
    let mut service = service_on(MockBackend::new());
    let connection = connect(&mut service);
    let token = NonZeroU64::new(7).unwrap();
    let range = MemoryRange {
        address: 0x8_0000_0000,
        bytes: 4096,
    };
    let memory = service.import(connection, &[range], token).unwrap();
    assert_eq!(service.retired(), None);
    assert_eq!(release(&mut service, connection, memory.get()), Status::Ok);
    assert_eq!(service.retired(), Some(token));
    assert_eq!(service.retired(), None);
}
