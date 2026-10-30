//! `Commit`: replays a connection's command stream into a command buffer
//! and submits it. A command the encoders refuse discards the command
//! buffer, as Metal's validation would, and the commit answers why.
use super::{
    Call, Service, boolean, known,
    wire::{
        self, Empty, Fault, Record, Status, Value,
        commands::{
            BufferLayoutRecord, CommandBufferCode, CommandCode, CommandHeader, CommitRequest,
            DepthStencilRecord, EventCommand, PatchSourceRecord, SampleCounters, StencilRecord,
        },
    },
};
use crate::metal::{
    abi::{CompareFunction, IndexType, PrimitiveType, StencilOperation},
    binding::ResourceId,
    capabilities::Size,
    command_buffer::{
        BufferRef, CommandBuffer,
        blit::{BlitTexture, BufferLayout},
        render::PatchSource,
    },
    device::{BufferId, SamplerId, TextureId},
    pipeline::{DepthStencilDescriptor, DepthStencilState, StencilDescriptor, depth_stencil},
    shader::Compiler,
    vulkan::backend::Backend,
};
use alloc::vec::Vec;
use core::num::NonZeroU64;

mod blit;
mod compute;
mod encode;
mod indirect;
mod render;
mod resource_state;

/// The entries of a stream: of commands a command buffer replays, or of
/// encoding calls for an indirect command buffer. `decode` names their
/// codes.
pub(super) struct Stream<'a, Code> {
    bytes: &'a [u8],
    decode: fn(u32) -> Option<Code>,
}

impl<'a, Code> Stream<'a, Code> {
    pub(super) fn new(bytes: &'a [u8], decode: fn(u32) -> Option<Code>) -> Self {
        Self { bytes, decode }
    }

    fn entry(&mut self) -> Result<(Code, Payload<'a>), Fault> {
        const HEADER: usize = core::mem::size_of::<CommandHeader>();
        let header: CommandHeader = wire::read(self.bytes.get(..HEADER).ok_or(Fault::MALFORMED)?)?;
        let end = HEADER + header.length as usize;
        let entry = self
            .bytes
            .get(..end.next_multiple_of(8))
            .ok_or(Fault::MALFORMED)?;
        self.bytes = &self.bytes[entry.len()..];
        let code = (self.decode)(header.code)
            .ok_or(Fault::new(Status::UnknownOperation, "unknown command"))?;
        Ok((code, Payload(&entry[HEADER..end])))
    }
}

impl<'a, Code> Iterator for Stream<'a, Code> {
    type Item = Result<(Code, Payload<'a>), Fault>;

    fn next(&mut self) -> Option<Self::Item> {
        (!self.bytes.is_empty()).then(|| self.entry())
    }
}

/// An entry's record and the variable data after it.
#[derive(Clone, Copy)]
pub(super) struct Payload<'a>(&'a [u8]);

impl<'a> Payload<'a> {
    /// The entry's record, with no data after it.
    pub(super) fn record<T: Record>(self) -> Result<T, Fault> {
        wire::read(self.0)
    }

    /// The records filling the command's data, which has no record of its
    /// own.
    pub(super) fn list<T: Record>(self) -> Result<Vec<T>, Fault> {
        wire::read_array(self.0)
    }

    /// The entry's record and the data after it.
    pub(super) fn split<T: Record>(self) -> Result<(T, Payload<'a>), Fault> {
        let (record, data) = self
            .0
            .split_at_checked(core::mem::size_of::<T>())
            .ok_or(Fault::MALFORMED)?;
        Ok((wire::read(record)?, Payload(data)))
    }

    pub(super) fn bytes(self) -> &'a [u8] {
        self.0
    }
}

impl<B: Backend, C: Compiler> Service<B, C> {
    pub(super) fn commit(&mut self, call: &mut Call) -> Result<(), Fault> {
        let CommitRequest { commands: span } = call.request()?;
        let connection = call.connection;
        let mut commands = self.device.new_command_buffer();
        let stream_bytes = call.memory.read(span)?;
        let mut stream = Stream::new(&stream_bytes, CommandCode::from_raw);
        let replayed = stream.try_for_each(|entry| {
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
            CommandCode::Render(code) => self.render(connection, commands, code, payload),
            CommandCode::ResourceState(code) => {
                self.resource_state(connection, commands, code, payload)
            }
            CommandCode::Indirect(code) => self.indirect(connection, commands, code, payload),
        }
    }

    fn command_buffer(
        &mut self,
        connection: NonZeroU64,
        commands: &mut CommandBuffer,
        code: CommandBufferCode,
        payload: Payload,
    ) -> Result<(), Fault> {
        match code {
            CommandBufferCode::EndEncoding => {
                payload.record::<Empty>()?;
                commands.end_encoding(&mut self.device.resolver())?;
            }
            CommandBufferCode::SignalEvent | CommandBufferCode::WaitForEvent => {
                let EventCommand { event, value } = payload.record()?;
                let event = self
                    .device
                    .event_semaphore(self.object(connection, event)?)?;
                let resolver = &mut self.device.resolver();
                match code {
                    CommandBufferCode::SignalEvent => {
                        commands.encode_signal_event(resolver, event, value)
                    }
                    _ => commands.encode_wait_for_event(resolver, event, value),
                }?;
            }
            CommandBufferCode::SampleCounters => {
                let SampleCounters {
                    buffer,
                    index,
                    barrier,
                    reserved: _,
                } = payload.record()?;
                let index = u32::try_from(index).map_err(|_| Fault::malformed("sample index"))?;
                let sample = self
                    .device
                    .counter_sample(self.object(connection, buffer)?, index)?;
                let barrier = boolean(barrier)?;
                commands.sample_counters(&mut self.device.resolver(), sample, barrier)?;
            }
        }
        Ok(())
    }

    fn patch_source(
        &self,
        connection: NonZeroU64,
        record: &PatchSourceRecord,
    ) -> Result<PatchSource, Fault> {
        let indices = |buffer, offset| {
            Ok::<_, Fault>(
                self.optional_buffer(connection, buffer)?
                    .map(|buffer| (buffer, offset)),
            )
        };
        Ok(PatchSource {
            control_points: u32::try_from(record.control_points)
                .map_err(|_| Fault::malformed("patch control points"))?,
            patch_indices: indices(record.patch_index_buffer, record.patch_index_offset)?,
            control_point_indices: indices(
                record.control_point_index_buffer,
                record.control_point_index_offset,
            )?,
        })
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

/// A draw's count, start or base, which the GPU takes in 32 bits.
fn count(value: u64) -> Result<u32, Fault> {
    u32::try_from(value).map_err(|_| Fault::new(Status::Invalid, "a draw argument exceeds 32 bits"))
}

fn primitive(raw: u64) -> Result<PrimitiveType, Fault> {
    known(PrimitiveType::from_raw(raw), "primitive type")
}

fn index_type(raw: u64) -> Result<IndexType, Fault> {
    known(IndexType::from_raw(raw), "index type")
}

/// The state of a depth-stencil state object made from `record`.
fn depth_stencil_state(record: &DepthStencilRecord) -> Result<DepthStencilState, Fault> {
    Ok(depth_stencil(&DepthStencilDescriptor {
        depth_compare_function: compare_function(record.depth_compare_function)?,
        depth_write_enabled: boolean(record.depth_write_enabled)?,
        front_face_stencil: stencil(&record.front_face_stencil)?,
        back_face_stencil: stencil(&record.back_face_stencil)?,
    }))
}

fn stencil(record: &StencilRecord) -> Result<StencilDescriptor, Fault> {
    let operation = |raw| known(StencilOperation::from_raw(raw), "stencil operation");
    Ok(StencilDescriptor {
        stencil_compare_function: compare_function(record.compare_function)?,
        stencil_failure_operation: operation(record.stencil_failure_operation)?,
        depth_failure_operation: operation(record.depth_failure_operation)?,
        depth_stencil_pass_operation: operation(record.depth_stencil_pass_operation)?,
        read_mask: record.read_mask,
        write_mask: record.write_mask,
    })
}

fn compare_function(raw: u64) -> Result<CompareFunction, Fault> {
    known(CompareFunction::from_raw(raw), "compare function")
}
