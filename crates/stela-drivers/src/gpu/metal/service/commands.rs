//! `Commit`: replays a connection's command stream into a command buffer
//! and submits it. A command the encoders refuse discards the command
//! buffer, as Metal's validation would, and the commit answers why.
use super::{
    Call, Service,
    wire::{
        self, Empty, Fault, Record, Status, Value,
        commands::{
            BufferLayoutRecord, CommandBufferCode, CommandCode, CommandHeader, CommitRequest,
            EventCommand, RegionRecord,
        },
    },
};
use crate::gpu::metal::{
    binding::ResourceId,
    capabilities::Size,
    command_buffer::{
        BufferRef, CommandBuffer,
        blit::{BlitTexture, BufferLayout, Region},
    },
    device::{BufferId, EventId, SamplerId, TextureId},
    shader::Compiler,
    vulkan::backend::Backend,
};
use core::num::NonZeroU64;

mod blit;
mod compute;

/// The entries of a command stream.
struct Stream<'a>(&'a [u8]);

impl<'a> Iterator for Stream<'a> {
    type Item = Result<(CommandCode, Payload<'a>), Fault>;

    fn next(&mut self) -> Option<Self::Item> {
        (!self.0.is_empty()).then(|| self.entry())
    }
}

impl<'a> Stream<'a> {
    fn entry(&mut self) -> Result<(CommandCode, Payload<'a>), Fault> {
        const HEADER: usize = core::mem::size_of::<CommandHeader>();
        let header: CommandHeader = wire::read(self.0.get(..HEADER).ok_or(Fault::MALFORMED)?)?;
        let end = HEADER + header.length as usize;
        let entry = self
            .0
            .get(..end.next_multiple_of(8))
            .ok_or(Fault::MALFORMED)?;
        self.0 = &self.0[entry.len()..];
        let code = CommandCode::from_raw(header.code)
            .ok_or(Fault::new(Status::UnknownOperation, "unknown command"))?;
        Ok((code, Payload(&entry[HEADER..end])))
    }
}

/// A command's record and the variable data after it.
#[derive(Clone, Copy)]
struct Payload<'a>(&'a [u8]);

impl<'a> Payload<'a> {
    /// The command's record, with no data after it.
    fn record<T: Record>(self) -> Result<T, Fault> {
        wire::read(self.0)
    }

    /// The command's record and the data after it.
    fn split<T: Record>(self) -> Result<(T, &'a [u8]), Fault> {
        let (record, data) = self
            .0
            .split_at_checked(core::mem::size_of::<T>())
            .ok_or(Fault::MALFORMED)?;
        Ok((wire::read(record)?, data))
    }
}

impl<B: Backend, C: Compiler> Service<B, C> {
    pub(super) fn commit(&mut self, call: &mut Call) -> Result<(), Fault> {
        let CommitRequest { commands: stream } = call.request()?;
        let connection = call.connection;
        let mut commands = self.device.new_command_buffer();
        let replayed = Stream(call.memory.read(stream)?).try_for_each(|entry| {
            let (code, payload) = entry?;
            self.replay(connection, &mut commands, code, payload)
        });
        if let Err(fault) = replayed {
            self.device.discard(commands);
            return Err(fault);
        }
        let value = self.device.commit(commands)?;
        call.reply(&Value { value })
    }

    fn replay(
        &mut self,
        connection: NonZeroU64,
        commands: &mut CommandBuffer,
        code: CommandCode,
        payload: Payload,
    ) -> Result<(), Fault> {
        match code {
            CommandCode::CommandBuffer(code) => {
                self.command_buffer(connection, commands, code, payload)
            }
            CommandCode::Compute(code) => self.compute(connection, commands, code, payload),
            CommandCode::Blit(code) => self.blit(connection, commands, code, payload),
        }
    }

    fn command_buffer(
        &mut self,
        connection: NonZeroU64,
        commands: &mut CommandBuffer,
        code: CommandBufferCode,
        payload: Payload,
    ) -> Result<(), Fault> {
        if code == CommandBufferCode::EndEncoding {
            payload.record::<Empty>()?;
            return Ok(commands.end_encoding(&mut self.device.resolver())?);
        }
        let EventCommand { event, value } = payload.record()?;
        let event = self
            .device
            .event_semaphore(self.object::<EventId>(connection, event)?)?;
        let resolver = &mut self.device.resolver();
        Ok(match code {
            CommandBufferCode::SignalEvent => commands.encode_signal_event(resolver, event, value),
            _ => commands.encode_wait_for_event(resolver, event, value),
        }?)
    }

    fn buffer_ref(&self, connection: NonZeroU64, handle: u64) -> Result<BufferRef, Fault> {
        Ok(self
            .device
            .buffer(self.object::<BufferId>(connection, handle)?)?)
    }

    /// The buffer `handle` names, or none for nil.
    fn optional_buffer(
        &self,
        connection: NonZeroU64,
        handle: u64,
    ) -> Result<Option<BufferRef>, Fault> {
        (handle != 0)
            .then(|| self.buffer_ref(connection, handle))
            .transpose()
    }

    fn buffer_layout(
        &self,
        connection: NonZeroU64,
        record: BufferLayoutRecord,
    ) -> Result<BufferLayout, Fault> {
        Ok(BufferLayout {
            buffer: self.buffer_ref(connection, record.buffer)?,
            offset: record.offset,
            bytes_per_row: record.bytes_per_row,
            bytes_per_image: record.bytes_per_image,
        })
    }

    /// The `gpuResourceID` of the texture `handle` names, null for nil.
    fn texture_id(&self, connection: NonZeroU64, handle: u64) -> Result<ResourceId, Fault> {
        if handle == 0 {
            return Ok(ResourceId::NULL);
        }
        Ok(self
            .device
            .texture_resource_id(self.object::<TextureId>(connection, handle)?)?)
    }

    /// The `gpuResourceID` of the sampler `handle` names, null for nil.
    fn sampler_id(&self, connection: NonZeroU64, handle: u64) -> Result<ResourceId, Fault> {
        if handle == 0 {
            return Ok(ResourceId::NULL);
        }
        Ok(self
            .device
            .sampler_resource_id(self.object::<SamplerId>(connection, handle)?)?)
    }

    fn blit_texture(&self, connection: NonZeroU64, handle: u64) -> Result<BlitTexture<'_>, Fault> {
        let id = self.object::<TextureId>(connection, handle)?;
        Ok(BlitTexture {
            image: self.device.texture_image(id)?,
            descriptor: self.device.texture_descriptor(id)?,
        })
    }
}

/// An argument table index.
fn binding(index: u64) -> Result<u32, Fault> {
    u32::try_from(index).map_err(|_| Fault::malformed("binding index"))
}

/// An `MTLSize` of threads in a threadgroup.
fn size([width, height, depth]: [u64; 3]) -> Size {
    Size {
        width,
        height,
        depth,
    }
}

/// An `MTLSize` of a grid, whose dimensions the GPU counts in 32 bits.
fn grid(size: [u64; 3]) -> Result<[u32; 3], Fault> {
    let mut grid = [0; 3];
    for (out, size) in grid.iter_mut().zip(size) {
        *out = u32::try_from(size)
            .map_err(|_| Fault::new(Status::Invalid, "a grid dimension exceeds 32 bits"))?;
    }
    Ok(grid)
}

fn region(record: RegionRecord) -> Region {
    Region {
        slice: record.slice,
        level: record.level,
        origin: record.origin,
        size: record.size,
    }
}
