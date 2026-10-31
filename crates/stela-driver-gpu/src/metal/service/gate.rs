//! The call gate's entry: a doorbell names a [`GateCall`] in the calling
//! thread's memory, which [`Service::serve`] reads, dispatches and
//! completes in place. Every byte crosses as a copy through
//! [`CallerMemory`], with the thread's own permissions, so nothing the
//! service validated can change under it.
use super::{
    GuestMemory, Service,
    wire::{self, Fault, GateCall, Span, Status},
};
use crate::metal::{capabilities::block::Block, shader::Compiler, vulkan::backend::Backend};
use alloc::{vec, vec::Vec};
use core::num::NonZeroU64;
use stela_contracts::gate::{CallerFault, CallerMemory};

/// Request and response records are fixed-width, the capability block the
/// largest; variable data travels in spans the operation names.
const MAX_RECORD_BYTES: u64 = size_of::<Block>() as u64;

/// The calling thread's memory, as the service reads and writes spans.
struct Caller<'a>(&'a mut dyn CallerMemory);

impl GuestMemory for Caller<'_> {
    fn read(&mut self, span: Span) -> Result<Vec<u8>, Fault> {
        let length = usize::try_from(span.length).map_err(|_| Fault::malformed("span length"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Fault::new(Status::OutOfMemory, "out of memory"))?;
        bytes.resize(length, 0);
        self.0.read(span.address, &mut bytes).map_err(fault)?;
        Ok(bytes)
    }

    fn write(&mut self, span: Span, bytes: &[u8]) -> Result<(), Fault> {
        if bytes.len() as u64 != span.length {
            return Err(Fault::MALFORMED);
        }
        self.0.write(span.address, bytes).map_err(fault)
    }
}

fn fault(error: CallerFault) -> Fault {
    match error {
        CallerFault::Denied { .. } => {
            Fault::new(Status::Unmapped, "a span the caller cannot access")
        }
        CallerFault::NotRam { .. } => Fault::malformed("a span that is not memory"),
        CallerFault::Unsupported(reason) => Fault::new(Status::Unsupported, reason),
    }
}

impl<B: Backend, C: Compiler> Service<B, C> {
    /// Serves the call `connection`'s gate rang for, whose [`GateCall`] is
    /// at `record`. Fails only when the record itself is out of the
    /// caller's reach; every other failure is the call's status.
    pub fn serve(
        &mut self,
        connection: NonZeroU64,
        record: u64,
        caller: &mut dyn CallerMemory,
    ) -> Result<(), CallerFault> {
        let mut raw = [0; size_of::<GateCall>()];
        caller.read(record, &mut raw)?;
        let mut call: GateCall = wire::read(&raw).expect("a record of its own size");
        let mut caller = Caller(caller);
        let outcome = self.dispatch_gate(connection, &call, &mut caller);
        let (status, reason) = match outcome {
            Ok(()) => (Status::Ok, ""),
            Err(fault) => (fault.status, fault.reason),
        };
        call.status = status.raw();
        call.reason_length = reason.len() as u64;
        if !reason.is_empty() && call.reason.length >= call.reason_length {
            let span = Span {
                address: call.reason.address,
                length: call.reason_length,
            };
            // The status still reports a reason the caller cannot take.
            let _ = caller.write(span, reason.as_bytes());
        }
        wire::write(&call, &mut raw).expect("a record of its own size");
        caller.0.write(record, &raw)
    }

    /// Command buffers completed, or the device was lost, since this last
    /// answered true; either wakes the frontend's waiters.
    pub fn signaled(&mut self) -> bool {
        let reached = match self.device.poll() {
            Ok(completed) => completed,
            Err(_) => {
                // A completion query that cannot be trusted must fail every
                // waiter consistently, rather than merely waking it once.
                self.device.mark_lost();
                u64::MAX
            }
        };
        let signaled = reached > self.signaled;
        self.signaled = self.signaled.max(reached);
        signaled
    }

    fn dispatch_gate(
        &mut self,
        connection: NonZeroU64,
        call: &GateCall,
        caller: &mut Caller,
    ) -> Result<(), Fault> {
        if call.request.length > MAX_RECORD_BYTES || call.response.length > MAX_RECORD_BYTES {
            return Err(Fault::malformed("record length"));
        }
        let request = caller.read(call.request)?;
        let mut response = vec![0; call.response.length as usize];
        let outcome = self.call(
            connection.get(),
            call.operation,
            &request,
            &mut response,
            caller,
        );
        if outcome.status != Status::Ok {
            return Err(Fault::new(outcome.status, outcome.reason));
        }
        caller.write(call.response, &response)
    }
}
