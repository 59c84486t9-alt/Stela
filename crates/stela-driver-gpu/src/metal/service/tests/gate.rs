use super::{Memory, Stream, commit, connect, service};
use crate::metal::service::{
    GuestMemory,
    wire::{self, GateCall, NegotiateRequest, NegotiateResponse, Operation, Span, Status},
};
use core::mem::size_of;
use stela_contracts::gate::{CallerFault, CallerMemory, GateService};

impl CallerMemory for Memory {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), CallerFault> {
        let span = Span {
            address,
            length: buffer.len() as u64,
        };
        let bytes = GuestMemory::read(self, span).map_err(|_| CallerFault::Denied { address })?;
        buffer.copy_from_slice(&bytes);
        Ok(())
    }

    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), CallerFault> {
        let span = Span {
            address,
            length: data.len() as u64,
        };
        GuestMemory::write(self, span, data).map_err(|_| CallerFault::Denied { address })
    }
}

/// Maps a [`GateCall`] for `operation` with `request`, room for a
/// response of `response` bytes and a 64-byte reason.
fn gate_call(memory: &mut Memory, operation: Operation, request: &[u8], response: usize) -> u64 {
    let call = GateCall {
        operation: operation.raw(),
        status: u32::MAX,
        request: memory.put(request),
        response: memory.put(&alloc::vec![0; response]),
        reason: memory.put(&[0; 64]),
        reason_length: 0,
    };
    memory.records(&[call]).address
}

fn completed(memory: &mut Memory, record: u64) -> GateCall {
    let span = Span {
        address: record,
        length: size_of::<GateCall>() as u64,
    };
    wire::read(&GuestMemory::read(memory, span).unwrap()).unwrap()
}

#[test]
fn a_gate_call_completes_in_the_callers_memory() {
    let mut service = service();
    let connection = service.connect().unwrap();
    let mut memory = Memory::default();
    let mut request = [0; size_of::<NegotiateRequest>()];
    let negotiate = NegotiateRequest {
        major: wire::MAJOR,
        minor: wire::MINOR,
    };
    wire::write(&negotiate, &mut request).unwrap();
    let record = gate_call(
        &mut memory,
        Operation::Negotiate,
        &request,
        size_of::<NegotiateResponse>(),
    );
    service.serve(connection, record, &mut memory).unwrap();
    let call = completed(&mut memory, record);
    assert_eq!((call.status, call.reason_length), (Status::Ok.raw(), 0));
    let response: NegotiateResponse =
        wire::read(&GuestMemory::read(&mut memory, call.response).unwrap()).unwrap();
    assert_eq!(response.major, wire::MAJOR);
}

#[test]
fn a_failed_gate_call_reports_its_status_and_reason() {
    let mut service = service();
    let connection = service.connect().unwrap();
    let mut memory = Memory::default();
    let oversized = gate_call(&mut memory, Operation::Negotiate, &[0; 8192], 16);
    service.serve(connection, oversized, &mut memory).unwrap();
    let call = completed(&mut memory, oversized);
    assert_eq!(call.status, Status::Malformed.raw());
    let reason = GuestMemory::read(&mut memory, call.reason).unwrap();
    assert_eq!(
        &reason[..call.reason_length as usize],
        b"record length".as_slice()
    );
    assert_eq!(
        service.serve(connection, 0x10, &mut memory),
        Err(CallerFault::Denied { address: 0x10 })
    );
}

#[test]
fn the_gate_signals_completed_work_once() {
    let mut service = service();
    let connection = connect(&mut service);
    assert!(!GateService::signaled(&mut service));
    commit(&mut service, connection, &Stream::default()).unwrap();
    assert!(!GateService::signaled(&mut service));
    let backend = service.device().backend();
    let timeline = *backend.semaphores.keys().next().unwrap();
    backend.semaphores.insert(timeline, 1);
    assert!(GateService::signaled(&mut service));
    assert!(!GateService::signaled(&mut service));
}
