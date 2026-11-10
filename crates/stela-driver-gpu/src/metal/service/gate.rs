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
use alloc::{format, vec, vec::Vec};
use core::num::NonZeroU64;
use stela_contracts::gate::{CallerFault, CallerMemory};

/// Request and response records are fixed-width, the capability block the
/// largest; variable data travels in spans the operation names.
const MAX_RECORD_BYTES: u64 = size_of::<Block>() as u64;

/// The bytes [`Caller::matches`] reads at once.
const COMPARED_BYTES: usize = 1 << 16;

/// The calling thread's memory, as the service reads and writes spans.
struct Caller<'a>(&'a mut dyn CallerMemory);

impl GuestMemory for Caller<'_> {
    fn read(&mut self, span: Span) -> Result<Vec<u8>, Fault> {
        let length = usize::try_from(span.length)
            .map_err(|_| Fault::malformed("span length").value(span.length))?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| {
            Fault::new(Status::OutOfMemory, "out of memory for a span of bytes").value(span.length)
        })?;
        bytes.resize(length, 0);
        self.0.read(span.address, &mut bytes).map_err(fault)?;
        Ok(bytes)
    }

    /// Compares a chunk at a time, never holding the span whole.
    fn matches(&mut self, span: Span, bytes: &[u8]) -> Result<bool, Fault> {
        if span.length != bytes.len() as u64 {
            return Ok(false);
        }
        let mut chunk = vec![0; COMPARED_BYTES.min(bytes.len())];
        for (index, expected) in bytes.chunks(COMPARED_BYTES).enumerate() {
            let address = span
                .address
                .checked_add((index * COMPARED_BYTES) as u64)
                .ok_or(Fault::malformed("span address").bits(span.address))?;
            let chunk = &mut chunk[..expected.len()];
            self.0.read(address, chunk).map_err(fault)?;
            if chunk != expected {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn write(&mut self, span: Span, bytes: &[u8]) -> Result<(), Fault> {
        if bytes.len() as u64 != span.length {
            return Err(Fault::malformed("response span").length(span.length, bytes.len() as u64));
        }
        self.0.write(span.address, bytes).map_err(fault)
    }
}

fn fault(error: CallerFault) -> Fault {
    match error {
        CallerFault::Denied { address } => {
            Fault::new(Status::Unmapped, "a span the caller cannot access").bits(address)
        }
        CallerFault::NotRam { address } => {
            Fault::malformed("a span that is not memory").bits(address)
        }
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
        // A record out of reach names no operation.
        self.served = (0, Status::Closed);
        let mut raw = [0; size_of::<GateCall>()];
        caller.read(record, &mut raw)?;
        let mut call: GateCall = wire::read(&raw).expect("a record of its own size");
        let mut caller = Caller(caller);
        let outcome = self.dispatch_gate(connection, &call, &mut caller);
        while let Some(what) = self.device.take_unsupported() {
            self.refused.push(format!(
                "{what}: unsupported, left undone, in operation {}",
                call.operation
            ));
        }
        // The reason the caller reads names the raw value it refused too.
        let detailed;
        let (status, reason) = match outcome {
            Ok(()) => {
                // A refusal the call recovered from, such as a form it then
                // compiled another way, must not name a later failure.
                if let Some(refusal) = self.device.take_refusal() {
                    self.refused.push(format!(
                        "operation {} succeeded after the compiler refused {} at {}: {}",
                        call.operation, refusal.entry, refusal.instruction, refusal.detail
                    ));
                }
                (Status::Ok, "")
            }
            // The frontend answers `Unmapped` by mapping the span and retrying.
            Err(fault) if fault.status == Status::Unmapped => (fault.status, fault.reason),
            // Metal's own nil answer is a note, not a refusal; a note the
            // call made itself says more.
            Err(fault) if fault.status == Status::Declined => {
                if self.noted.is_none() {
                    self.noted = Some(format!("{fault} in operation {}", call.operation));
                }
                (fault.status, fault.reason)
            }
            Err(fault) => {
                self.refused.push(match self.device.take_refusal() {
                    Some(refusal) => format!(
                        "{fault} in operation {} in {} at {}: {}",
                        call.operation, refusal.entry, refusal.instruction, refusal.detail
                    ),
                    None if fault.status == Status::DeviceLost && !self.loss_described => {
                        self.loss_described = true;
                        format!(
                            "{fault} in operation {} running {}",
                            call.operation,
                            self.device.work_in_flight()
                        )
                    }
                    // How much the device and the connection hold, which
                    // says whether the memory ran out or the request is huge.
                    None if fault.status == Status::OutOfMemory => {
                        let device = self.device.memory();
                        let [sampled, storage, samplers, uniform, texel] = device.descriptors;
                        format!(
                            "{fault} in operation {} with device allocated={}M deferred={}M \
                             in_flight={} connection={}M descriptors sampled={sampled} \
                             storage={storage} samplers={samplers} uniform_texel={uniform} \
                             storage_texel={texel}",
                            call.operation,
                            device.allocated >> 20,
                            device.deferred_bytes >> 20,
                            device.in_flight,
                            self.connections
                                .get(&connection)
                                .map_or(0, |held| held.allocated >> 20),
                        )
                    }
                    None => format!("{fault} in operation {}", call.operation),
                });
                match fault.raw {
                    Some(_) => {
                        detailed = format!("{fault}");
                        (fault.status, detailed.as_str())
                    }
                    None => (fault.status, fault.reason),
                }
            }
        };
        self.served = (call.operation, status);
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
        // Any connection's work completing counts, in whatever order: held
        // work of another delays no connection's waiters.
        let reached = match self.device.poll() {
            Ok(_) => self.device.completions(),
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
        if call.request.length > MAX_RECORD_BYTES {
            return Err(Fault::malformed("record length").value(call.request.length));
        }
        if call.response.length > MAX_RECORD_BYTES {
            return Err(Fault::malformed("record length").value(call.response.length));
        }
        // Common records such as Commit and Poll fit on the service stack.
        // Keep independent copies even when the guest supplies aliased spans.
        const INLINE_RECORD_BYTES: usize = 128;
        let mut inline_request = [0; INLINE_RECORD_BYTES];
        let heap_request;
        let request = if let Some(bytes) = inline_request.get_mut(..call.request.length as usize) {
            caller.0.read(call.request.address, bytes).map_err(fault)?;
            &*bytes
        } else {
            heap_request = caller.read(call.request)?;
            &heap_request
        };
        let mut inline_response = [0; INLINE_RECORD_BYTES];
        let mut heap_response;
        let response = if let Some(bytes) = inline_response.get_mut(..call.response.length as usize)
        {
            bytes
        } else {
            heap_response = vec![0; call.response.length as usize];
            &mut heap_response
        };
        let outcome = self.call(connection.get(), call.operation, request, response, caller);
        if outcome.status != Status::Ok {
            return Err(outcome.into());
        }
        caller.write(call.response, response)
    }
}
