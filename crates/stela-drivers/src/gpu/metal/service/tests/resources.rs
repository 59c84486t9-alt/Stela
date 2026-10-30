use super::{Memory, TestService, call, connect, service_on, status};
use crate::gpu::metal::{
    abi::{
        CompareFunction, CpuCacheMode, HazardTrackingMode, HeapType, ResourceOptions,
        SamplerAddressMode, SamplerBorderColor, SamplerMinMagFilter, SamplerMipFilter,
        SamplerReductionMode, SparsePageSize, StorageMode, SwizzleChannels, TextureType,
        TextureUsage,
    },
    device::fixture::MockBackend,
    pixel_format::PixelFormat,
    service::{
        GuestMemory, Outcome,
        wire::{
            AUTOMATIC, BufferRangeRequest, BufferResponse, Empty, Handle, HeapBufferSizeRequest,
            HeapDescriptorRecord, HeapUsageRequest, HeapUsageResponse, NewBufferRequest,
            NewHeapBufferRequest, NewTextureViewRequest, Operation, RegionRecord,
            SamplerDescriptorRecord, SamplerResponse, SizeAndAlignRecord, Status,
            TextureBytesRequest, TextureDescriptorRecord, TextureResponse,
        },
    },
};
use core::num::NonZeroU64;

fn options(storage_mode: StorageMode) -> u64 {
    ResourceOptions {
        cpu_cache_mode: CpuCacheMode::DefaultCache,
        storage_mode,
        hazard_tracking_mode: HazardTrackingMode::Default,
    }
    .raw()
}

const IDENTITY: [u8; 4] = [2, 3, 4, 5];

fn texture(storage_mode: StorageMode) -> TextureDescriptorRecord {
    assert_eq!(
        SwizzleChannels::IDENTITY.0.map(|swizzle| swizzle.raw()),
        IDENTITY
    );
    TextureDescriptorRecord {
        texture_type: TextureType::D2.raw(),
        pixel_format: PixelFormat::Rgba8Unorm.raw(),
        width: 8,
        height: 4,
        depth: 1,
        mipmap_level_count: 1,
        sample_count: 1,
        array_length: 1,
        options: options(storage_mode),
        usage: TextureUsage::SHADER_READ.bits(),
        swizzle: IDENTITY,
        reserved: 0,
    }
}

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
fn buffers_answer_their_addresses_and_contents() {
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
    let shared = buffer(StorageMode::Shared).unwrap();
    assert_ne!(shared.gpu_address, 0);
    assert_ne!(shared.contents, 0);
    assert_eq!((shared.allocated_size, shared.heap_offset), (4096, 0));
    let private = buffer(StorageMode::Private).unwrap();
    assert_eq!(private.contents, 0);
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
