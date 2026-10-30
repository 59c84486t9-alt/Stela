//! Commands of `MTLBlitCommandEncoder`.
use super::Payload;
use crate::gpu::metal::{
    abi::{BlitOption, StorageMode},
    capabilities::FormatCapabilities,
    command_buffer::{
        CommandBuffer,
        blit::{BlitTexture, Region},
    },
    device::TextureId,
    error::ensure,
    service::{
        Object, Service, known, region,
        wire::{
            Empty, Fault,
            commands::{
                BlitCode, CopyBuffer, CopyBufferToTexture, CopyTexture, CopyTextureSlices,
                CopyTextureToBuffer, FillBuffer, ResolveCounters, Resource, SynchronizeTexture,
            },
        },
    },
    shader::Compiler,
    vulkan::backend::Backend,
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
                let texture = self.blit_texture(connection, request.texture)?;
                let options = blit_options(request.options)?;
                commands.copy_buffer_to_texture(
                    source,
                    texture,
                    region(&request.region),
                    options,
                )?;
            }
            BlitCode::CopyTextureToBuffer => {
                let request: CopyTextureToBuffer = payload.record()?;
                let texture = self.blit_texture(connection, request.texture)?;
                let destination = self.buffer_layout(connection, request.destination)?;
                let options = blit_options(request.options)?;
                commands.copy_texture_to_buffer(
                    texture,
                    region(&request.region),
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
                let value =
                    u8::try_from(request.value).map_err(|_| Fault::malformed("fill value"))?;
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
                let range =
                    |value| u32::try_from(value).map_err(|_| Fault::malformed("sample range"));
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

    /// Synchronizes subresources of a managed texture: each is copied to
    /// the texture's CPU copy, or, without one, host image copies read the
    /// texture once the command buffer completes.
    fn synchronize_texture(
        &self,
        commands: &mut CommandBuffer,
        id: TextureId,
        slices: Range<u64>,
        levels: Range<u64>,
    ) -> Result<(), Fault> {
        let descriptor = self.device.texture_descriptor(id)?;
        ensure(
            descriptor.options.storage_mode == StorageMode::Managed,
            "synchronizeResource: is for managed resources",
        )?;
        ensure(
            levels.end <= descriptor.mipmap_level_count && slices.end <= descriptor.slice_count(),
            "subresource outside the texture",
        )?;
        let texture = BlitTexture {
            image: self.device.texture_image(id)?,
            descriptor,
        };
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
                commands.synchronize_texture(texture, staging, region)?;
            }
        }
        Ok(())
    }
}

fn blit_options(raw: u64) -> Result<BlitOption, Fault> {
    known(BlitOption::from_bits(raw), "blit options")
}
