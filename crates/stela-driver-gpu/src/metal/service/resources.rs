//! Buffers, textures, samplers and heaps.
use super::{
    Call, Object, Service, boolean, known, region,
    wire::{
        AUTOMATIC, BufferRangeRequest, BufferResponse, Empty, Fault, FormatAlignmentsResponse,
        Handle, HeapBufferSizeRequest, HeapDescriptorRecord, HeapUsageRequest, HeapUsageResponse,
        NewBufferRequest, NewBufferTextureRequest, NewHeapBufferRequest, NewHeapTextureRequest,
        NewImportedBufferRequest, NewTextureViewRequest, PixelFormatRequest,
        SamplerDescriptorRecord, SamplerResponse, SizeAndAlignRecord, SparseTileRequest,
        SparseTileResponse, Status, TextureBytesRequest, TextureDescriptorRecord, TextureResponse,
    },
};
use crate::metal::{
    abi::{
        CompareFunction, HeapType, ResourceOptions, SamplerAddressMode, SamplerBorderColor,
        SamplerMinMagFilter, SamplerMipFilter, SamplerReductionMode, SparsePageSize, StorageMode,
        SwizzleChannels, TextureSwizzle, TextureType, TextureUsage,
    },
    device::{BufferId, Device, HeapId, MemoryId, TextureId, resources::Strides},
    error::Error,
    heap::{HeapDescriptor, SizeAndAlign},
    pixel_format::PixelFormat,
    resource::{TextureDescriptor, TextureViewDescriptor},
    sampler::SamplerDescriptor,
    shader::Compiler,
    vulkan::backend::Backend,
};
use core::num::NonZeroU64;

impl<B: Backend, C: Compiler> Service<B, C> {
    pub(super) fn new_buffer(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewBufferRequest = call.request()?;
        let options = options(request.options)?;
        // A guest task reaches only its own memory.
        if options.storage_mode != StorageMode::Private {
            return Err(Fault::new(
                Status::Invalid,
                "the CPU's buffers are imported",
            ));
        }
        let buffer = self.device.new_buffer(request.length, options)?;
        let response = self.adopt_buffer(call.connection, buffer)?;
        call.reply(&response)
    }

    pub(super) fn new_imported_buffer(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewImportedBufferRequest = call.request()?;
        let options = options(request.options)?;
        let memory = self.object::<MemoryId>(call.connection, request.memory)?;
        let buffer = self
            .device
            .new_imported_buffer(memory, request.length, options)?;
        self.take_memory(call.connection, request.memory)?;
        let response = self.adopt_buffer(call.connection, buffer)?;
        call.reply(&response)
    }

    pub(super) fn format_alignments(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: PixelFormatRequest = call.request()?;
        let format = pixel_format(request.pixel_format)?;
        let capabilities = self.device.capabilities();
        call.reply(&FormatAlignmentsResponse {
            linear_texture: capabilities.minimum_linear_texture_alignment(format),
            texture_buffer: capabilities.minimum_texture_buffer_alignment(format),
        })
    }

    pub(super) fn sparse_tile_size(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: SparseTileRequest = call.request()?;
        let size = self.device.capabilities().sparse_tile_size(
            texture_type(request.texture_type)?,
            pixel_format(request.pixel_format)?,
            request.sample_count,
        );
        call.reply(&SparseTileResponse {
            size: size.map_or([0; 3], |size| [size.width, size.height, size.depth]),
        })
    }

    pub(super) fn buffer_did_modify_range(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: BufferRangeRequest = call.request()?;
        let buffer = self.object::<BufferId>(call.connection, request.buffer)?;
        self.device
            .did_modify_range(buffer, request.offset, request.length)?;
        call.reply(&Empty {})
    }

    pub(super) fn new_texture(&mut self, call: &mut Call) -> Result<(), Fault> {
        let descriptor = texture_descriptor(&call.request()?)?;
        let texture = self.device.new_texture(&descriptor)?;
        let response = self.adopt_texture(call.connection, texture)?;
        call.reply(&response)
    }

    pub(super) fn new_texture_view(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewTextureViewRequest = call.request()?;
        let parent = self.object::<TextureId>(call.connection, request.texture)?;
        let view = TextureViewDescriptor {
            pixel_format: pixel_format(request.pixel_format)?,
            texture_type: texture_type(request.texture_type)?,
            levels: range(request.levels)?,
            slices: range(request.slices)?,
            swizzle: swizzle(request.swizzle)?,
        };
        let texture = self.device.new_texture_view(parent, &view)?;
        let response = self.adopt_texture(call.connection, texture)?;
        call.reply(&response)
    }

    pub(super) fn new_buffer_texture(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewBufferTextureRequest = call.request()?;
        let buffer = self.object::<BufferId>(call.connection, request.buffer)?;
        let descriptor = texture_descriptor(&request.descriptor)?;
        let texture = self.device.new_texture_from_buffer(
            buffer,
            &descriptor,
            request.offset,
            request.bytes_per_row,
        )?;
        let response = self.adopt_texture(call.connection, texture)?;
        call.reply(&response)
    }

    pub(super) fn replace_region(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: TextureBytesRequest = call.request()?;
        let texture = self.object::<TextureId>(call.connection, request.texture)?;
        let bytes = call.memory.read(request.bytes)?;
        self.device
            .replace_region(texture, &region(&request.region), &bytes, strides(&request))?;
        call.reply(&Empty {})
    }

    pub(super) fn get_bytes(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: TextureBytesRequest = call.request()?;
        let texture = self.object::<TextureId>(call.connection, request.texture)?;
        let mut bytes = call.memory.read(request.bytes)?;
        self.device.get_bytes(
            texture,
            &region(&request.region),
            &mut bytes,
            strides(&request),
        )?;
        call.memory.write(request.bytes, &bytes)?;
        call.reply(&Empty {})
    }

    pub(super) fn new_sampler(&mut self, call: &mut Call) -> Result<(), Fault> {
        let descriptor = sampler_descriptor(&call.request()?)?;
        let sampler = self.device.new_sampler(&descriptor)?;
        let (handle, resource_id) =
            self.adopt(call.connection, Object::Sampler(sampler), |device| {
                device.sampler_resource_id(sampler)
            })?;
        call.reply(&SamplerResponse {
            handle: handle.handle,
            resource_id: resource_id.0,
        })
    }

    pub(super) fn new_heap(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: HeapDescriptorRecord = call.request()?;
        let descriptor = HeapDescriptor {
            size: request.size,
            options: options(request.options)?,
            heap_type: known(HeapType::from_raw(request.heap_type), "heap type")?,
            sparse_page_size: known(
                SparsePageSize::from_raw(request.sparse_page_size),
                "sparse page size",
            )?,
        };
        let heap = if request.memory == 0 {
            // A guest task reaches only its own memory.
            if descriptor.options.storage_mode != StorageMode::Private {
                return Err(Fault::new(Status::Invalid, "the CPU's heaps are imported"));
            }
            self.device.new_heap(&descriptor)?
        } else {
            let memory = self.object::<MemoryId>(call.connection, request.memory)?;
            let heap = self.device.new_imported_heap(memory, &descriptor)?;
            self.take_memory(call.connection, request.memory)?;
            heap
        };
        let handle = self.hold(call.connection, Object::Heap(heap))?;
        call.reply(&handle)
    }

    pub(super) fn heap_buffer_size_and_align(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: HeapBufferSizeRequest = call.request()?;
        let options = options(request.options)?;
        let size = self
            .device
            .heap_buffer_size_and_align(request.length, options)?;
        call.reply(&size_and_align(size))
    }

    pub(super) fn heap_texture_size_and_align(&mut self, call: &mut Call) -> Result<(), Fault> {
        let descriptor = texture_descriptor(&call.request()?)?;
        let size = self.device.heap_texture_size_and_align(&descriptor)?;
        call.reply(&size_and_align(size))
    }

    pub(super) fn new_heap_buffer(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewHeapBufferRequest = call.request()?;
        let heap = self.object::<HeapId>(call.connection, request.heap)?;
        let options = options(request.options)?;
        let buffer =
            self.device
                .new_heap_buffer(heap, request.length, options, offset(request.offset))?;
        let response = self.adopt_buffer(call.connection, buffer)?;
        call.reply(&response)
    }

    pub(super) fn new_heap_texture(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewHeapTextureRequest = call.request()?;
        let heap = self.object::<HeapId>(call.connection, request.heap)?;
        let descriptor = texture_descriptor(&request.descriptor)?;
        let texture = self
            .device
            .new_heap_texture(heap, &descriptor, offset(request.offset))?;
        let response = self.adopt_texture(call.connection, texture)?;
        call.reply(&response)
    }

    pub(super) fn heap_usage(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: HeapUsageRequest = call.request()?;
        let heap = self.object::<HeapId>(call.connection, request.heap)?;
        let (used_size, max_available_size) = self.device.heap_usage(heap, request.alignment)?;
        call.reply(&HeapUsageResponse {
            used_size,
            max_available_size,
        })
    }

    pub(super) fn make_aliasable(&mut self, call: &mut Call) -> Result<(), Fault> {
        let Handle { handle } = call.request()?;
        match self.entry(call.connection, handle)? {
            Object::Buffer(buffer) => self.device.make_buffer_aliasable(buffer)?,
            Object::Texture(texture) => self.device.make_texture_aliasable(texture)?,
            _ => return Err(Fault::STALE),
        }
        call.reply(&Empty {})
    }

    pub(super) fn adopt_buffer(
        &mut self,
        connection: NonZeroU64,
        buffer: BufferId,
    ) -> Result<BufferResponse, Fault> {
        let (handle, response) = self.adopt(connection, Object::Buffer(buffer), |device| {
            let placement = device.buffer_placement(buffer)?;
            Ok(BufferResponse {
                handle: 0,
                gpu_address: device.buffer(buffer)?.address,
                allocated_size: placement.allocated_size,
                heap_offset: placement.heap_offset,
            })
        })?;
        Ok(BufferResponse {
            handle: handle.handle,
            ..response
        })
    }

    pub(super) fn adopt_texture(
        &mut self,
        connection: NonZeroU64,
        texture: TextureId,
    ) -> Result<TextureResponse, Fault> {
        let (handle, response) = self.adopt(connection, Object::Texture(texture), |device| {
            texture_response(device, texture)
        })?;
        Ok(TextureResponse {
            handle: handle.handle,
            ..response
        })
    }
}

fn texture_response<B: Backend, C: Compiler>(
    device: &Device<B, C>,
    texture: TextureId,
) -> Result<TextureResponse, Error> {
    let placement = device.texture_placement(texture)?;
    let tail = device.sparse_tail(texture)?;
    let (first_mipmap_in_tail, tail_size) = tail.unwrap_or_default();
    Ok(TextureResponse {
        handle: 0,
        resource_id: device.texture_resource_id(texture)?.0,
        allocated_size: placement.allocated_size,
        heap_offset: placement.heap_offset,
        first_mipmap_in_tail,
        tail_size,
        sparse: tail.is_some().into(),
        reserved: 0,
    })
}

fn options(raw: u64) -> Result<ResourceOptions, Fault> {
    known(ResourceOptions::from_raw(raw), "resource options")
}

pub(super) fn pixel_format(raw: u64) -> Result<PixelFormat, Fault> {
    known(PixelFormat::from_raw(raw), "pixel format")
}

fn texture_type(raw: u64) -> Result<TextureType, Fault> {
    known(TextureType::from_raw(raw), "texture type")
}

fn swizzle(raw: [u8; 4]) -> Result<SwizzleChannels, Fault> {
    let mut channels = SwizzleChannels::IDENTITY;
    for (channel, raw) in channels.0.iter_mut().zip(raw) {
        *channel = known(TextureSwizzle::from_raw(raw), "texture swizzle")?;
    }
    Ok(channels)
}

/// An `NSRange` of a location and a length.
fn range([location, length]: [u64; 2]) -> Result<core::ops::Range<u64>, Fault> {
    let end = location
        .checked_add(length)
        .ok_or(Fault::malformed("range"))?;
    Ok(location..end)
}

fn offset(raw: u64) -> Option<u64> {
    (raw != AUTOMATIC).then_some(raw)
}

fn texture_descriptor(record: &TextureDescriptorRecord) -> Result<TextureDescriptor, Fault> {
    Ok(TextureDescriptor {
        texture_type: texture_type(record.texture_type)?,
        pixel_format: pixel_format(record.pixel_format)?,
        width: record.width,
        height: record.height,
        depth: record.depth,
        mipmap_level_count: record.mipmap_level_count,
        sample_count: record.sample_count,
        array_length: record.array_length,
        options: options(record.options)?,
        usage: known(TextureUsage::from_bits(record.usage), "texture usage")?,
        swizzle: swizzle(record.swizzle)?,
    })
}

fn sampler_descriptor(record: &SamplerDescriptorRecord) -> Result<SamplerDescriptor, Fault> {
    let filter = |raw| known(SamplerMinMagFilter::from_raw(raw), "sampler filter");
    let mut address_modes = [SamplerAddressMode::ClampToEdge; 3];
    for (mode, raw) in address_modes.iter_mut().zip(record.address_modes) {
        *mode = known(SamplerAddressMode::from_raw(raw), "sampler address mode")?;
    }
    Ok(SamplerDescriptor {
        min_filter: filter(record.min_filter)?,
        mag_filter: filter(record.mag_filter)?,
        mip_filter: known(
            SamplerMipFilter::from_raw(record.mip_filter),
            "sampler mip filter",
        )?,
        max_anisotropy: record.max_anisotropy,
        address_modes,
        border_color: known(
            SamplerBorderColor::from_raw(record.border_color),
            "sampler border color",
        )?,
        reduction_mode: known(
            SamplerReductionMode::from_raw(record.reduction_mode),
            "sampler reduction mode",
        )?,
        normalized_coordinates: boolean(record.normalized_coordinates)?,
        lod_min_clamp: record.lod_min_clamp,
        lod_max_clamp: record.lod_max_clamp,
        compare_function: known(
            CompareFunction::from_raw(record.compare_function),
            "compare function",
        )?,
    })
}

fn strides(request: &TextureBytesRequest) -> Strides {
    Strides {
        bytes_per_row: request.bytes_per_row,
        bytes_per_image: request.bytes_per_image,
    }
}

fn size_and_align(size: SizeAndAlign) -> SizeAndAlignRecord {
    SizeAndAlignRecord {
        size: size.size,
        align: size.align,
    }
}
