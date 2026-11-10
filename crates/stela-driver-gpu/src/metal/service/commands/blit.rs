//! Commands of `MTLBlitCommandEncoder`.
use super::Payload;
use crate::metal::{
    abi::{BlitOption, StorageMode},
    binding::ResourceId,
    capabilities::FormatCapabilities,
    command_buffer::{
        BufferRef, CommandBuffer,
        blit::{BlitTexture, Region},
    },
    device::TextureId,
    error::ensure,
    resource::TextureDescriptor,
    service::{
        Object, Service, decode_bits, region,
        wire::{
            Empty, Fault,
            commands::{
                BlitCode, CopyBuffer, CopyBufferToTexture, CopyTexture, CopyTextureSlices,
                CopyTextureToBuffer, FillBuffer, ResolveCounters, Resource, SynchronizeTexture,
            },
        },
    },
    shader::Compiler,
    vulkan::{backend::Backend, object::Image},
};
use core::{num::NonZeroU64, ops::Range};

impl<B: Backend, C: Compiler> Service<B, C> {
    pub(super) fn blit(
        &mut self,
        connection: NonZeroU64,
        commands: &mut CommandBuffer,
        code: BlitCode,
        payload: Payload,
    ) -> Result<(), Fault> {
        match code {
            BlitCode::Begin => {
                payload.record::<Empty>()?;
                commands.begin_blit()?;
            }
            BlitCode::CopyBuffer => {
                let request: CopyBuffer = payload.record()?;
                let source = self.buffer_ref(connection, request.source)?;
                let destination = self.buffer_ref(connection, request.destination)?;
                commands.copy_buffer(
                    source,
                    request.source_offset,
                    destination,
                    request.destination_offset,
                    request.size,
                )?;
            }
            BlitCode::CopyBufferToTexture => {
                let request: CopyBufferToTexture = payload.record()?;
                let source = self.buffer_layout(connection, request.source)?;
                let region = region(&request.region);
                let (image, descriptor, storage, blocks) =
                    self.copied_texture(connection, request.texture, &region)?;
                let options = blit_options(request.options)?;
                let texture = BlitTexture {
                    image,
                    descriptor: &descriptor,
                    storage,
                    blocks,
                };
                commands.copy_buffer_to_texture(
                    &mut self.device.resolver(),
                    source,
                    texture,
                    region,
                    options,
                )?;
            }
            BlitCode::CopyTextureToBuffer => {
                let request: CopyTextureToBuffer = payload.record()?;
                let region = region(&request.region);
                let (image, descriptor, storage, blocks) =
                    self.copied_texture(connection, request.texture, &region)?;
                let destination = self.buffer_layout(connection, request.destination)?;
                let options = blit_options(request.options)?;
                let texture = BlitTexture {
                    image,
                    descriptor: &descriptor,
                    storage,
                    blocks,
                };
                commands.copy_texture_to_buffer(
                    &mut self.device.resolver(),
                    texture,
                    region,
                    destination,
                    options,
                )?;
            }
            BlitCode::CopyTexture => {
                let request: CopyTexture = payload.record()?;
                commands.copy_texture(
                    self.blit_texture(connection, request.source)?,
                    region(&request.region),
                    self.blit_texture(connection, request.destination)?,
                    request.destination_slice,
                    request.destination_level,
                    request.destination_origin,
                )?;
            }
            BlitCode::CopyTextureSlices => {
                let request: CopyTextureSlices = payload.record()?;
                commands.copy_texture_slices(
                    self.blit_texture(connection, request.source)?,
                    request.source_slice,
                    request.source_level,
                    self.blit_texture(connection, request.destination)?,
                    request.destination_slice,
                    request.destination_level,
                    request.slice_count,
                    request.level_count,
                )?;
            }
            BlitCode::FillBuffer => {
                let request: FillBuffer = payload.record()?;
                let buffer = self.buffer_ref(connection, request.buffer)?;
                let value = u8::try_from(request.value)
                    .map_err(|_| Fault::malformed("fill value").value(request.value))?;
                let resolver = &mut self.device.resolver();
                commands.fill_buffer(resolver, buffer, request.start, request.length, value)?;
            }
            BlitCode::GenerateMipmaps => {
                let Resource { resource } = payload.record()?;
                let texture = self.blit_texture(connection, resource)?;
                let format = self
                    .device
                    .capabilities()
                    .format(texture.descriptor.pixel_format);
                commands.generate_mipmaps(texture, format.contains(FormatCapabilities::FILTER))?;
            }
            BlitCode::Synchronize => {
                let Resource { resource } = payload.record()?;
                match self.entry(connection, resource)? {
                    Object::Buffer(id) => {
                        commands.synchronize_buffer(self.device.managed_range(id)?)?;
                    }
                    Object::Texture(id) => {
                        let descriptor = self.device.texture_descriptor(id)?;
                        let (slices, levels) = (
                            0..descriptor.slice_count(),
                            0..descriptor.mipmap_level_count,
                        );
                        self.synchronize_texture(commands, id, slices, levels)?;
                    }
                    _ => return Err(Fault::STALE),
                }
            }
            BlitCode::ResolveCounters => {
                let request: ResolveCounters = payload.record()?;
                let range = |value| {
                    u32::try_from(value).map_err(|_| Fault::malformed("sample range").value(value))
                };
                let counters = self.object(connection, request.buffer)?;
                let range = self.device.counter_range(
                    counters,
                    range(request.first)?,
                    range(request.count)?,
                )?;
                let destination = self.buffer_ref(connection, request.destination)?;
                let resolver = &mut self.device.resolver();
                commands.resolve_counters(resolver, range, destination, request.offset)?;
            }
            BlitCode::SynchronizeTexture => {
                let SynchronizeTexture {
                    texture,
                    slice,
                    level,
                } = payload.record()?;
                let id = self.object::<TextureId>(connection, texture)?;
                let (slices, levels) = (
                    slice..slice.saturating_add(1),
                    level..level.saturating_add(1),
                );
                self.synchronize_texture(commands, id, slices, levels)?;
            }
        }
        Ok(())
    }

    /// A texture a buffer copy of `region` reads or writes: its image, its
    /// descriptor and, when its image stores another encoding than its
    /// format's bytes, the raw storage view of the region's level and slice
    /// that the texel kernels convert through, and a decoded format's blocks.
    fn copied_texture(
        &mut self,
        connection: NonZeroU64,
        handle: u64,
        region: &Region,
    ) -> Result<CopiedTexture, Fault> {
        let id = self.object::<TextureId>(connection, handle)?;
        let descriptor = *self.device.texture_descriptor(id)?;
        let storage = self.device.texel_storage(id, region.level, region.slice)?;
        let blocks = self.device.texture_blocks(id)?;
        Ok((self.device.texture_image(id)?, descriptor, storage, blocks))
    }

    /// Synchronizes subresources of a managed texture: each is copied to
    /// the texture's CPU copy, or, without one, host image copies read the
    /// texture once the command buffer completes.
    fn synchronize_texture(
        &mut self,
        commands: &mut CommandBuffer,
        id: TextureId,
        slices: Range<u64>,
        levels: Range<u64>,
    ) -> Result<(), Fault> {
        let descriptor = *self.device.texture_descriptor(id)?;
        ensure(
            descriptor.options.storage_mode == StorageMode::Managed,
            "synchronizeResource: is for managed resources",
        )?;
        ensure(
            levels.end <= descriptor.mipmap_level_count && slices.end <= descriptor.slice_count(),
            "subresource outside the texture",
        )?;
        // Only an exact encoding keeps a CPU copy, which a transfer fills.
        let image = self.device.texture_image(id)?;
        for level in levels {
            for slice in slices.clone() {
                let Some(staging) = self.device.texture_cpu_copy(id, level, slice)? else {
                    return Ok(commands.synchronize()?);
                };
                let region = Region {
                    slice,
                    level,
                    origin: [0; 3],
                    size: descriptor.level_extent(level),
                };
                let texture = BlitTexture {
                    image,
                    descriptor: &descriptor,
                    storage: ResourceId::NULL,
                    blocks: None,
                };
                commands.synchronize_texture(
                    &mut self.device.resolver(),
                    texture,
                    staging,
                    region,
                )?;
            }
        }
        Ok(())
    }
}

/// A copied texture's image, descriptor, raw storage view and blocks.
type CopiedTexture = (Image, TextureDescriptor, ResourceId, Option<BufferRef>);

fn blit_options(raw: u64) -> Result<BlitOption, Fault> {
    decode_bits(BlitOption::from_bits, raw, "blit options")
}
