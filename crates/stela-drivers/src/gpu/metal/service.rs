//! The Metal service: the boundary the guest frontend crosses into the
//! device.
//!
//! `StelaGPU.bundle` reaches native code through the process call gate with
//! one entry, [`Service::call`]: a connection, an [`Operation`] and its
//! fixed-width request and response records ([`wire`]). Variable data
//! (names, library bytes, texel data, command streams) stays in guest memory
//! as [`Span`]s that the gate resolves through [`GuestMemory`]; the service
//! never dereferences a guest address itself. Each connection names device
//! objects by its own generation-checked handles
//! ([`identity`](crate::gpu::protocol::identity)), so a handle of another
//! connection, of a destroyed object or of another kind of object is
//! refused, and closing a connection releases what it still holds, newest
//! first, so views and aliases go before the resources under them.
use super::{
    device::{Device, FunctionId, LibraryId},
    error::Error,
    shader::Compiler,
    vulkan::backend::Backend,
};
use crate::gpu::protocol::identity::{DeviceEpoch, ObjectHandle, ObjectTable};
use alloc::{collections::BTreeMap, vec::Vec};
use core::num::{NonZeroU32, NonZeroU64};
use wire::{Fault, Handle, NegotiateRequest, NegotiateResponse, Operation, Record, Span, Status};

mod libraries;
#[cfg(test)]
mod tests;
pub mod wire;

/// The objects one connection may hold.
const MAX_OBJECTS: NonZeroU32 = NonZeroU32::new(1 << 20).unwrap();

/// Guest memory the call gate resolves for one call: spans of the calling
/// task's address space, checked against its mappings.
pub trait GuestMemory {
    fn read(&self, span: Span) -> Result<&[u8], Fault>;
    fn write(&mut self, span: Span, bytes: &[u8]) -> Result<(), Fault>;
}

/// A device object a connection holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Object {
    Library(LibraryId),
    Function(FunctionId),
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
    Library(LibraryId);
    Function(FunctionId);
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

    /// Writes variable data to `out` when it fits, replying its length
    /// either way, so a frontend with too short a span asks again.
    fn reply_data(&mut self, out: Span, data: &[u8]) -> Result<(), Fault> {
        let length = data.len() as u64;
        if length <= out.length {
            let span = Span {
                address: out.address,
                length,
            };
            self.memory.write(span, data)?;
        }
        self.reply(&wire::Length { length })
    }
}

pub struct Service<B: Backend, C: Compiler> {
    device: Device<B, C>,
    epoch: DeviceEpoch,
    connections: BTreeMap<NonZeroU64, Connection>,
    next_connection: NonZeroU64,
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
            Operation::NewFunction => self.new_function(&mut call),
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

    /// The object of kind `T` that `handle` names.
    fn object<T: Kind>(&self, connection: NonZeroU64, handle: u64) -> Result<T, Fault> {
        let held = self.connections.get(&connection).ok_or(Fault::CLOSED)?;
        let handle = ObjectHandle::decode(handle).ok_or(Fault::STALE)?;
        let entry = held.objects.get(connection, self.epoch, handle)?;
        T::of(entry.object).ok_or(Fault::STALE)
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

    fn destroy(&mut self, object: Object) -> Result<(), Error> {
        let device = &mut self.device;
        match object {
            Object::Library(id) => device.destroy_library(id),
            Object::Function(id) => device.destroy_function(id),
        }
    }
}
