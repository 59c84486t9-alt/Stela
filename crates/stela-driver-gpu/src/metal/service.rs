//! The Metal service: the boundary the guest frontend crosses into the
//! device.
//!
//! `StelaGPU.bundle` reaches native code through the process call gate,
//! whose doorbell names a [`GateCall`](wire::GateCall) that
//! [`Service::serve`] completes in the caller's memory, with one entry,
//! [`Service::call`]: a connection, an [`Operation`] and its fixed-width
//! request and response records ([`wire`]). Variable data (names, library
//! bytes, texel data, command streams) stays in guest memory as [`Span`]s
//! that the gate copies through [`GuestMemory`]; the service never
//! dereferences a guest address itself. Each connection names device
//! objects by its own generation-checked handles ([`identity`]), so a handle
//! of another connection, of a destroyed object or of another kind of object
//! is refused, and closing a connection releases what it still holds, newest
//! first, so views and aliases go before the resources under them.
use super::{
    command_buffer::blit::Region,
    device::{
        ArchiveId, BufferId, ComputePipelineId, CounterBufferId, Device, EventId, FunctionId,
        HeapId, LibraryId, MemoryId, RenderPipelineId, SamplerId, TextureId,
    },
    error::Error,
    indirect::IndirectCommandBufferId,
    shader::Compiler,
    vulkan::backend::Backend,
};
use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    num::{NonZeroU32, NonZeroU64},
    ops::Range,
};
use identity::{DeviceEpoch, ObjectHandle, ObjectTable};
pub use shared::{ServiceHost, SharedService};
use stela_contracts::gate::MemoryRange;
use wire::{Fault, Handle, NegotiateRequest, NegotiateResponse, Operation, Record, Span, Status};

mod commands;
mod gate;
pub mod identity;
mod indirect;
mod libraries;
mod pipelines;
mod queue;
mod reflection;
mod resources;
mod shared;
mod sharing;
#[cfg(test)]
mod tests;
pub mod wire;

/// A decoded value, or the value's name when it is not one.
fn known<T>(value: Option<T>, name: &'static str) -> Result<T, Fault> {
    value.ok_or(Fault::malformed(name))
}

/// `MTLRegion` of one slice and level.
fn region(record: &wire::RegionRecord) -> Region {
    Region {
        slice: record.slice,
        level: record.level,
        origin: record.origin,
        size: record.size,
    }
}

/// `first..first + count` of an indirect command buffer's commands.
fn command_range(first: u64, count: u64) -> Result<Range<usize>, Fault> {
    let index = |value| usize::try_from(value).map_err(|_| Fault::malformed("command range"));
    let first = index(first)?;
    let end = first
        .checked_add(index(count)?)
        .ok_or(Fault::malformed("command range"))?;
    Ok(first..end)
}

fn boolean(raw: u32) -> Result<bool, Fault> {
    match raw {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Fault::malformed("boolean")),
    }
}

/// The objects one connection may hold.
const MAX_OBJECTS: NonZeroU32 = NonZeroU32::new(1 << 20).unwrap();

/// Guest memory the call gate resolves for one call: spans of the calling
/// task's address space, checked against its mappings. An empty span is no
/// bytes wherever it points. A read is a copy, so the task's other threads
/// cannot change what the service validated.
pub trait GuestMemory {
    fn read(&mut self, span: Span) -> Result<Vec<u8>, Fault>;
    fn write(&mut self, span: Span, bytes: &[u8]) -> Result<(), Fault>;
}

/// A device object a connection holds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Object {
    Memory(MemoryId),
    Buffer(BufferId),
    Texture(TextureId),
    Sampler(SamplerId),
    Heap(HeapId),
    Library(LibraryId),
    Archive(ArchiveId),
    Function(FunctionId),
    RenderPipeline(RenderPipelineId),
    ComputePipeline(ComputePipelineId),
    Event(EventId),
    CounterBuffer(CounterBufferId),
    IndirectCommandBuffer(IndirectCommandBufferId),
}

/// A kind of object a handle may name.
trait Kind: Sized {
    fn of(object: Object) -> Option<Self>;
}

macro_rules! kinds {
    ($($variant:ident($id:ty);)*) => {$(
        impl Kind for $id {
            fn of(object: Object) -> Option<Self> {
                match object {
                    Object::$variant(id) => Some(id),
                    _ => None,
                }
            }
        }
    )*};
}

kinds! {
    Memory(MemoryId);
    Buffer(BufferId);
    Texture(TextureId);
    Sampler(SamplerId);
    Heap(HeapId);
    Library(LibraryId);
    Archive(ArchiveId);
    Function(FunctionId);
    RenderPipeline(RenderPipelineId);
    ComputePipeline(ComputePipelineId);
    Event(EventId);
    CounterBuffer(CounterBufferId);
    IndirectCommandBuffer(IndirectCommandBufferId);
}

/// An object and when its connection made it.
struct Entry {
    object: Object,
    made: u64,
}

struct Connection {
    objects: ObjectTable<Entry>,
    /// Objects made so far, which orders them.
    made: u64,
    negotiated: bool,
}

/// How a call ended: its status and, unless it succeeded, why.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Outcome {
    pub status: Status,
    pub reason: &'static str,
}

impl From<Result<(), Fault>> for Outcome {
    fn from(result: Result<(), Fault>) -> Self {
        match result {
            Ok(()) => Self {
                status: Status::Ok,
                reason: "",
            },
            Err(fault) => Self {
                status: fault.status,
                reason: fault.reason,
            },
        }
    }
}

/// One call's records and memory.
struct Call<'a> {
    connection: NonZeroU64,
    request: &'a [u8],
    response: &'a mut [u8],
    memory: &'a mut dyn GuestMemory,
}

impl Call<'_> {
    fn request<T: Record>(&self) -> Result<T, Fault> {
        wire::read(self.request)
    }

    fn reply<T: Record>(&mut self, value: &T) -> Result<(), Fault> {
        wire::write(value, self.response)
    }

    /// Writes variable data to `out` when it fits; its response answers
    /// its length either way, so a frontend with too short a span asks
    /// again.
    fn write_fitting(&mut self, out: Span, data: &[u8]) -> Result<(), Fault> {
        let length = data.len() as u64;
        if length > out.length {
            return Ok(());
        }
        let span = Span {
            address: out.address,
            length,
        };
        self.memory.write(span, data)
    }

    /// Writes variable data as [`write_fitting`](Self::write_fitting) does
    /// and replies its length.
    fn reply_data(&mut self, out: Span, data: &[u8]) -> Result<(), Fault> {
        self.write_fitting(out, data)?;
        self.reply(&wire::Length {
            length: data.len() as u64,
        })
    }
}

pub struct Service<B: Backend, C: Compiler> {
    device: Device<B, C>,
    epoch: DeviceEpoch,
    connections: BTreeMap<NonZeroU64, Connection>,
    next_connection: NonZeroU64,
    shares: sharing::Shares,
    /// The completed serial the gate last signaled; `u64::MAX` once it
    /// signaled the device's loss.
    signaled: u64,
}

impl<B: Backend, C: Compiler> Service<B, C> {
    /// Serves `device` in its `epoch`, which a device the gate registers
    /// again after a loss advances.
    pub fn new(device: Device<B, C>, epoch: DeviceEpoch) -> Self {
        Self {
            device,
            epoch,
            connections: BTreeMap::new(),
            next_connection: NonZeroU64::MIN,
            shares: sharing::Shares::default(),
            signaled: 0,
        }
    }

    pub fn device(&mut self) -> &mut Device<B, C> {
        &mut self.device
    }

    /// Opens a connection for the task the gate authenticated; it must
    /// negotiate before any other operation.
    pub fn connect(&mut self) -> Result<NonZeroU64, Fault> {
        let id = self.next_connection;
        self.next_connection = id.checked_add(1).ok_or(Fault::new(
            Status::OutOfMemory,
            "connection identifiers are exhausted",
        ))?;
        self.connections.insert(
            id,
            Connection {
                objects: ObjectTable::new(id, self.epoch, MAX_OBJECTS),
                made: 0,
                negotiated: false,
            },
        );
        Ok(id)
    }

    /// Closes a connection and releases its objects, newest first. The
    /// device keeps what in-flight work uses until that work completes.
    pub fn disconnect(&mut self, connection: NonZeroU64) -> Result<(), Fault> {
        let mut closed = self.connections.remove(&connection).ok_or(Fault::CLOSED)?;
        closed.objects.close();
        let mut entries: Vec<Entry> = closed.objects.into_objects().collect();
        entries.sort_unstable_by_key(|entry| core::cmp::Reverse(entry.made));
        // Every object is released even when an earlier one fails; the
        // first failure is reported.
        let mut released = Ok(());
        for entry in entries {
            if let Err(error) = self.destroy(entry.object) {
                released = released.and(Err(Fault::from(error)));
            }
        }
        released
    }

    /// Gives `connection` the wired guest RAM of `ranges`; the handle goes to
    /// a buffer or heap of that memory, or to `Release`.
    pub fn import(
        &mut self,
        connection: NonZeroU64,
        ranges: &[MemoryRange],
        token: NonZeroU64,
    ) -> Result<NonZeroU64, Fault> {
        self.connection(connection)?;
        let memory = self.device.import_memory(ranges, token)?;
        let handle = self.hold(connection, Object::Memory(memory))?;
        NonZeroU64::new(handle.handle).ok_or(Fault::STALE)
    }

    /// The token of imported memory the GPU no longer reaches.
    pub fn retired(&mut self) -> Option<NonZeroU64> {
        self.device.retired()
    }

    /// Whether [`Self::retired`] has an answer.
    pub(super) fn retiring(&self) -> bool {
        self.device.retiring()
    }

    /// Takes the imported memory `handle` names from the connection, for an
    /// object that keeps it.
    fn take_memory(&mut self, connection: NonZeroU64, handle: u64) -> Result<MemoryId, Fault> {
        let memory = self.object::<MemoryId>(connection, handle)?;
        let epoch = self.epoch;
        let handle = ObjectHandle::decode(handle).ok_or(Fault::STALE)?;
        self.connection(connection)?
            .objects
            .remove(connection, epoch, handle)?;
        Ok(memory)
    }

    /// Runs `operation` for `connection` on its request record, writing its
    /// response record.
    pub fn call(
        &mut self,
        connection: u64,
        operation: u32,
        request: &[u8],
        response: &mut [u8],
        memory: &mut dyn GuestMemory,
    ) -> Outcome {
        self.dispatch(connection, operation, request, response, memory)
            .into()
    }

    fn dispatch(
        &mut self,
        connection: u64,
        operation: u32,
        request: &[u8],
        response: &mut [u8],
        memory: &mut dyn GuestMemory,
    ) -> Result<(), Fault> {
        let connection = NonZeroU64::new(connection)
            .filter(|id| self.connections.contains_key(id))
            .ok_or(Fault::CLOSED)?;
        let operation = Operation::from_raw(operation)
            .ok_or(Fault::new(Status::UnknownOperation, "unknown operation"))?;
        let (request_bytes, response_bytes) = operation.sizes();
        if request.len() != request_bytes || response.len() != response_bytes {
            return Err(Fault::MALFORMED);
        }
        if !self.connections[&connection].negotiated && operation != Operation::Negotiate {
            return Err(Fault::new(
                Status::Invalid,
                "the connection has not negotiated",
            ));
        }
        let mut call = Call {
            connection,
            request,
            response,
            memory,
        };
        match operation {
            Operation::Negotiate => self.negotiate(&mut call),
            Operation::Capabilities => {
                let block = self.device.capabilities().block()?;
                call.reply(&*block)
            }
            Operation::Release => {
                let Handle { handle } = call.request()?;
                self.release(connection, handle)?;
                call.reply(&wire::Empty {})
            }
            Operation::NewLibrary => self.new_library(&mut call),
            Operation::LibraryFunctionNames => self.library_function_names(&mut call),
            Operation::LibraryIdentity => self.library_identity(&mut call),
            Operation::LibraryData => self.library_data(&mut call),
            Operation::NewSourceLibrary => self.new_source_library(&mut call),
            Operation::NewArchive => self.new_archive(&mut call),
            Operation::ArchiveData => self.archive_data(&mut call),
            Operation::NewFunction => self.new_function(&mut call),
            Operation::FunctionReflection => self.function_reflection(&mut call),
            Operation::FunctionBindings => self.function_bindings(&mut call),
            Operation::ArgumentLayout => reflection::argument_layout(&mut call),
            Operation::NewBuffer => self.new_buffer(&mut call),
            Operation::NewImportedBuffer => self.new_imported_buffer(&mut call),
            Operation::FormatAlignments => self.format_alignments(&mut call),
            Operation::SparseTileSize => self.sparse_tile_size(&mut call),
            Operation::BufferDidModifyRange => self.buffer_did_modify_range(&mut call),
            Operation::NewTexture => self.new_texture(&mut call),
            Operation::NewTextureView => self.new_texture_view(&mut call),
            Operation::NewBufferTexture => self.new_buffer_texture(&mut call),
            Operation::ReplaceRegion => self.replace_region(&mut call),
            Operation::GetBytes => self.get_bytes(&mut call),
            Operation::NewSampler => self.new_sampler(&mut call),
            Operation::NewHeap => self.new_heap(&mut call),
            Operation::HeapBufferSizeAndAlign => self.heap_buffer_size_and_align(&mut call),
            Operation::HeapTextureSizeAndAlign => self.heap_texture_size_and_align(&mut call),
            Operation::NewHeapBuffer => self.new_heap_buffer(&mut call),
            Operation::NewHeapTexture => self.new_heap_texture(&mut call),
            Operation::HeapUsage => self.heap_usage(&mut call),
            Operation::MakeAliasable => self.make_aliasable(&mut call),
            Operation::NewRenderPipeline => self.new_render_pipeline(&mut call),
            Operation::NewMeshPipeline => self.new_mesh_pipeline(&mut call),
            Operation::NewComputePipeline => self.new_compute_pipeline(&mut call),
            Operation::FunctionHandle => self.function_handle(&mut call),
            Operation::NewFunctionTable => self.new_function_table(&mut call),
            Operation::SetFunctions => self.set_functions(&mut call),
            Operation::NewEvent => {
                let event = self.device.new_event()?;
                let handle = self.hold(connection, Object::Event(event))?;
                call.reply(&handle)
            }
            Operation::EventSignaledValue => self.event_signaled_value(&mut call),
            Operation::SetEventSignaledValue => self.set_event_signaled_value(&mut call),
            Operation::WaitEvent => self.wait_event(&mut call),
            Operation::ShareObject => self.share_object(&mut call),
            Operation::OpenSharedEvent => self.open_shared_event(&mut call),
            Operation::OpenSharedTexture => self.open_shared_texture(&mut call),
            Operation::NewCounterBuffer => self.new_counter_buffer(&mut call),
            Operation::ResolveCounters => self.resolve_counters(&mut call),
            Operation::SampleTimestamps => {
                let (cpu, gpu) = self.device.sample_timestamps()?;
                call.reply(&wire::TimestampsResponse { cpu, gpu })
            }
            Operation::AllocatedSize => call.reply(&wire::Value {
                value: self.device.current_allocated_size(),
            }),
            Operation::Poll => {
                let value = self.device.poll()?;
                call.reply(&wire::Value { value })
            }
            Operation::Commit => self.commit(&mut call),
            Operation::CommandBufferTimes => {
                let wire::Value { value } = call.request()?;
                let [start, end] = self.device.command_buffer_times(value)?;
                call.reply(&wire::CommandBufferTimesResponse { start, end })
            }
            Operation::NewIndirectCommandBuffer => self.new_indirect_command_buffer(&mut call),
            Operation::IndirectResourceId => self.indirect_resource_id(&mut call),
            Operation::EncodeIndirect => self.encode_indirect(&mut call),
            Operation::ResetIndirect => self.reset_indirect(&mut call),
        }
    }

    fn negotiate(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NegotiateRequest = call.request()?;
        if request.major != wire::MAJOR {
            return Err(Fault::new(Status::Unsupported, "protocol major version"));
        }
        self.connection(call.connection)?.negotiated = true;
        call.reply(&NegotiateResponse {
            major: wire::MAJOR,
            minor: wire::MINOR,
            capability_bytes: core::mem::size_of::<super::capabilities::block::Block>() as u32,
            reserved: 0,
        })
    }

    fn connection(&mut self, id: NonZeroU64) -> Result<&mut Connection, Fault> {
        self.connections.get_mut(&id).ok_or(Fault::CLOSED)
    }

    /// Gives the connection a handle to a new object with what `describe`
    /// answers of it, releasing the object again if either fails.
    fn adopt<T>(
        &mut self,
        connection: NonZeroU64,
        object: Object,
        describe: impl FnOnce(&Device<B, C>) -> Result<T, Error>,
    ) -> Result<(Handle, T), Fault> {
        match describe(&self.device) {
            Ok(description) => Ok((self.hold(connection, object)?, description)),
            Err(error) => {
                self.destroy(object)?;
                Err(error.into())
            }
        }
    }

    /// Gives the connection a handle to a new object, releasing the object
    /// again if the connection cannot hold it.
    fn hold(&mut self, connection: NonZeroU64, object: Object) -> Result<Handle, Fault> {
        let epoch = self.epoch;
        let held = self.connection(connection).and_then(|held| {
            held.made += 1;
            let entry = Entry {
                object,
                made: held.made,
            };
            held.objects
                .insert(connection, epoch, entry)
                .map_err(|refused| Fault::from(refused.error))
        });
        match held {
            Ok(handle) => Ok(Handle {
                handle: handle.encode(),
            }),
            Err(fault) => {
                // Nothing uses the new object yet, so releasing it cannot fail.
                self.destroy(object)?;
                Err(fault)
            }
        }
    }

    /// The object `handle` names.
    fn entry(&self, connection: NonZeroU64, handle: u64) -> Result<Object, Fault> {
        let held = self.connections.get(&connection).ok_or(Fault::CLOSED)?;
        let handle = ObjectHandle::decode(handle).ok_or(Fault::STALE)?;
        Ok(held.objects.get(connection, self.epoch, handle)?.object)
    }

    /// The object of kind `T` that `handle` names.
    fn object<T: Kind>(&self, connection: NonZeroU64, handle: u64) -> Result<T, Fault> {
        T::of(self.entry(connection, handle)?).ok_or(Fault::STALE)
    }

    /// Releases the object `handle` names. When the device refuses, for an
    /// object others still depend on, the handle stays valid.
    fn release(&mut self, connection: NonZeroU64, handle: u64) -> Result<(), Fault> {
        let epoch = self.epoch;
        let handle = ObjectHandle::decode(handle).ok_or(Fault::STALE)?;
        let held = self.connection(connection)?;
        let object = held.objects.get(connection, epoch, handle)?.object;
        self.destroy(object)?;
        self.connection(connection)?
            .objects
            .remove(connection, epoch, handle)?;
        Ok(())
    }

    /// Gives up a handle's hold of `object`, destroying it with the last.
    fn destroy(&mut self, object: Object) -> Result<(), Error> {
        if self.shares.release(object) {
            return Ok(());
        }
        let device = &mut self.device;
        match object {
            Object::Memory(id) => device.release_import(id),
            Object::Buffer(id) => device.destroy_buffer(id),
            Object::Texture(id) => device.destroy_texture(id),
            Object::Sampler(id) => device.destroy_sampler(id),
            Object::Heap(id) => device.destroy_heap(id),
            Object::Library(id) => device.destroy_library(id),
            Object::Archive(id) => device.destroy_archive(id),
            Object::Function(id) => device.destroy_function(id),
            Object::RenderPipeline(id) => device.destroy_render_pipeline(id),
            Object::ComputePipeline(id) => device.destroy_compute_pipeline(id),
            Object::Event(id) => device.destroy_event(id),
            Object::CounterBuffer(id) => device.destroy_counter_sample_buffer(id),
            Object::IndirectCommandBuffer(id) => device.destroy_indirect_command_buffer(id),
        }?;
        self.shares.forget(object);
        Ok(())
    }
}
