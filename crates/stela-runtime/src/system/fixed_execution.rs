//! Fixed EL1 register/exception execution over immutable owned code/controls.
//!
//! This concrete adapter admits no guest data, tag, control, cache, TLBI,
//! device, trace/error or IRQ producer. It uses actual memory/event owners for
//! exception return, and requires the runtime's post-return code scope.

use super::{
    access::ExceptionLevel,
    events::EventEndpoint,
    exception::{self, Completion, EffectFailure, EntryEvent, ExceptionServices, ServiceRequest},
    execution::{Boundary, Dispatcher, EntryBoundary, Failure},
    fixed_controls::FixedEl1Controls,
    state::SystemState,
};
use crate::{
    blocks::CodePublicationScope,
    memory::domain::{DataPolicy, MemoryThread},
};
#[cfg(not(feature = "std"))]
use alloc::string::String;
use stela_compiler::{
    GuestAddress, GuestState, Lifter,
    aarch64::{Decoder, Operation, system::exception::Operation as ExceptionOperation},
    block::{BlockProfile, SuccessorKind, analyze_with_profile, system::SystemOperation},
};

const INSTRUCTION_BYTES: usize = core::mem::size_of::<u32>();
const NOP_WORD: u32 = 0xd503_201f;
const CONDITIONAL_BRANCH_MASK: u32 = 0xff00_0000;
const CONDITIONAL_BRANCH_CLASS: u32 = 0x5400_0000;
const CONSISTENT_BRANCH_HINT: u32 = 1 << 4;

/// Exclusive state and monitor borrows plus the actual immutable control owner.
/// The endpoint is the same per-PE event register used by WFx/SEVL services.
pub struct FixedEl1Dispatcher<'a, P> {
    address_space: u64,
    system: &'a mut SystemState,
    controls: &'a FixedEl1Controls,
    memory: &'a mut MemoryThread<P>,
    event: &'a EventEndpoint,
}

impl<'a, P: DataPolicy> FixedEl1Dispatcher<'a, P> {
    pub fn new(
        address_space: u64,
        system: &'a mut SystemState,
        controls: &'a FixedEl1Controls,
        memory: &'a mut MemoryThread<P>,
        event: &'a EventEndpoint,
    ) -> Result<Self, Failure> {
        if memory.address_space() != Some(address_space) {
            return Err(Failure::WrongAddressSpace);
        }
        check_pe_binding(memory, event).map_err(Failure::Backend)?;
        Ok(Self {
            address_space,
            system,
            controls,
            memory,
            event,
        })
    }
}

impl<P: DataPolicy> Dispatcher for FixedEl1Dispatcher<'_, P> {
    fn address_space(&self) -> u64 {
        self.address_space
    }

    fn validate_entry(
        &mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        registers: &GuestState,
    ) -> Result<(), Failure> {
        if boundary.address_space() != self.address_space {
            return Err(Failure::WrongAddressSpace);
        }
        self.controls
            .entry_snapshot(self.system, registers)
            .map_err(|error| Failure::Backend(format!("fixed controls: {error:?}")))?;
        self.memory
            .validate_execution(0)
            .map_err(|error| Failure::Backend(format!("memory owner: {error:?}")))?;
        validate_source(boundary, source)
    }

    fn complete(
        &mut self,
        _boundary: Boundary,
        _registers: &mut GuestState,
    ) -> Result<GuestAddress, Failure> {
        Err(Failure::Unsupported(
            "fixed EL1 completion requires runtime code scope",
        ))
    }

    fn complete_with_code_scope(
        &mut self,
        boundary: Boundary,
        registers: &mut GuestState,
        code: &mut CodePublicationScope<'_>,
    ) -> Result<GuestAddress, Failure> {
        if boundary.source().address_space() != self.address_space {
            return Err(Failure::WrongAddressSpace);
        }
        code.check_boundary(&boundary).map_err(Failure::Backend)?;
        let snapshot = self
            .controls
            .entry_snapshot(self.system, registers)
            .map_err(|error| Failure::Backend(format!("fixed controls: {error:?}")))?;
        let instruction = boundary.instruction();
        let event = match instruction.operation {
            SystemOperation::Exception(ExceptionOperation::Undefined { .. }) => {
                Some(EntryEvent::Undefined {
                    instruction_pc: instruction.instruction_pc.0,
                })
            }
            SystemOperation::Exception(ExceptionOperation::SupervisorCall { immediate }) => {
                Some(EntryEvent::SupervisorCall {
                    instruction_pc: instruction.instruction_pc.0,
                    immediate,
                })
            }
            SystemOperation::Exception(ExceptionOperation::ExceptionReturn { key: None }) => {
                self.controls
                    .validate_return(self.system)
                    .map_err(|error| Failure::Backend(format!("fixed return: {error:?}")))?;
                None
            }
            _ => {
                return Err(Failure::Unsupported(
                    "operation outside fixed EL1 exceptions",
                ));
            }
        };
        let mut services = FixedServices {
            address_space: self.address_space,
            code,
            controls: self.controls,
            memory: self.memory,
            event: self.event,
        };
        let next = if let Some(event) = event {
            exception::prepare_entry(
                &snapshot.features,
                snapshot.profile,
                snapshot.controls,
                self.system,
                registers,
                event,
            )
            .map_err(Failure::ExceptionPrepare)?
            .execute(self.system, registers, &mut services)
        } else {
            exception::prepare_return(
                instruction.instruction_pc.0,
                &snapshot.features,
                snapshot.profile,
                snapshot.controls,
                self.system,
                registers,
            )
            .map_err(Failure::ExceptionPrepare)?
            .execute(self.system, registers, &mut services)
        };
        next.map(GuestAddress).map_err(Failure::ExceptionExecute)
    }
}

pub(crate) fn validate_source(boundary: &EntryBoundary, source: &[u8]) -> Result<(), Failure> {
    if source
        .first_chunk::<INSTRUCTION_BYTES>()
        .map(|bytes| u32::from_le_bytes(*bytes))
        != Some(boundary.word())
    {
        return Err(Failure::Unsupported("fixed entry word differs from source"));
    }
    let analysis = analyze_with_profile(source, boundary.entry(), BlockProfile::SystemV1)
        .map_err(|error| Failure::Backend(format!("fixed source: {error:?}")))?;
    if analysis.trap.is_some()
        || analysis.pointer_authentication.is_some()
        || analysis.clock_instruction.is_some()
        || analysis.thread_register_instruction.is_some()
    {
        return Err(Failure::Unsupported(
            "terminal outside fixed EL1 source contract",
        ));
    }
    let consumed = source
        .get(..analysis.source_bytes)
        .ok_or(Failure::Unsupported("invalid fixed EL1 source extent"))?;
    for (index, bytes) in consumed
        .as_chunks::<INSTRUCTION_BYTES>()
        .0
        .iter()
        .enumerate()
    {
        let pc = GuestAddress(boundary.entry().0 + (index * INSTRUCTION_BYTES) as u64);
        let word = u32::from_le_bytes(*bytes);
        let is_last = (index + 1) * INSTRUCTION_BYTES == consumed.len();
        if is_last && let Some(instruction) = analysis.system_instruction {
            if !instruction.matches_source(pc, word)
                || !matches!(
                    instruction.operation,
                    SystemOperation::Exception(
                        ExceptionOperation::Undefined { .. }
                            | ExceptionOperation::SupervisorCall { .. }
                            | ExceptionOperation::ExceptionReturn { key: None }
                    )
                )
            {
                return Err(Failure::Unsupported(
                    "terminal outside fixed EL1 exceptions",
                ));
            }
            continue;
        }
        // The shared parser alone constructs these plain BR/BLR/RET and BL
        // boundaries. Other special terminal families were rejected above.
        if is_last
            && (analysis.dynamic_edge.is_some()
                || analysis
                    .static_successors
                    .iter()
                    .any(|edge| edge.kind == SuccessorKind::CallTarget))
        {
            continue;
        }
        let instruction = Decoder
            .lift(pc, word)
            .map_err(|error| Failure::Backend(format!("fixed prefix: {error:?}")))?;
        if !baseline_register_operation(word, &instruction.operation) {
            return Err(Failure::Unsupported(
                "instruction outside fixed EL1 baseline registers",
            ));
        }
    }
    Ok(())
}

fn baseline_register_operation(word: u32, operation: &Operation) -> bool {
    // The shared decoder intentionally selects some constrained memory NOPs
    // and erases BC's HBC origin. This fixed profile authorizes neither those
    // memory/FP assumptions nor HBC, so retain the original-word distinction.
    match operation {
        Operation::Nop => return word == NOP_WORD,
        Operation::BranchCondition { .. } => {
            return word & CONDITIONAL_BRANCH_MASK == CONDITIONAL_BRANCH_CLASS
                && word & CONSISTENT_BRANCH_HINT == 0;
        }
        _ => {}
    }
    matches!(
        operation,
        Operation::Bitfield(_)
            | Operation::PcRelative(_)
            | Operation::ConditionalSelect(_)
            | Operation::ConditionalCompare(_)
            | Operation::IntegerMath(_)
            | Operation::AddSubRegister { .. }
            | Operation::AddSubCarry { .. }
            | Operation::AddSubExtended { .. }
            | Operation::LogicalRegister { .. }
            | Operation::LogicalImmediate { .. }
            | Operation::Branch { .. }
            | Operation::BranchZero { .. }
            | Operation::BranchBit { .. }
            | Operation::MoveWide { .. }
            | Operation::AddSub { .. }
            | Operation::Return
    )
}

struct FixedServices<'a, 'run, P> {
    address_space: u64,
    code: &'a mut CodePublicationScope<'run>,
    controls: &'a FixedEl1Controls,
    memory: &'a mut MemoryThread<P>,
    event: &'a EventEndpoint,
}

impl<P: DataPolicy> ExceptionServices for FixedServices<'_, '_, P> {
    type Permit = ServiceRequest;
    type Error = String;

    fn preflight(&mut self, request: ServiceRequest) -> Result<ServiceRequest, String> {
        self.code.check_exception_request(self.controls, &request)?;
        if self.memory.address_space() != Some(self.address_space) {
            return Err("fixed exception monitor belongs to another address space".into());
        }
        check_pe_binding(self.memory, self.event)?;
        // This common health/control check has no fault settlement or monitor
        // cleanup. Later domain failure remains a committed-prefix error.
        self.memory
            .validate_execution(0)
            .map_err(|error| format!("memory preflight: {error:?}"))?;
        Ok(request)
    }

    fn synchronize_context(
        &mut self,
        permit: &mut ServiceRequest,
        source_el: ExceptionLevel,
    ) -> Result<(), EffectFailure<String>> {
        if permit.source_el != source_el {
            return Err(no_effect("fixed synchronization source EL changed".into()));
        }
        self.code.synchronize_fixed_el1(self.controls, permit)
    }

    fn clear_exclusive_local(
        &mut self,
        _permit: &mut ServiceRequest,
    ) -> Result<(), EffectFailure<String>> {
        self.memory
            .clear_reservation()
            .map_err(|error| EffectFailure {
                error: format!("exclusive owner: {error:?}"),
                // This owner also checks sticky failure after local cleanup.
                // Its Result cannot distinguish that from a pre-clear decline.
                completion: Completion::Unknown,
            })
    }

    fn send_event_local(
        &mut self,
        _permit: &mut ServiceRequest,
    ) -> Result<(), EffectFailure<String>> {
        self.event.signal_local();
        Ok(())
    }

    fn branch_address(
        &mut self,
        _permit: &mut ServiceRequest,
        target: u64,
        destination_el: ExceptionLevel,
    ) -> Result<u64, EffectFailure<String>> {
        self.controls
            .branch_address(target, destination_el)
            .map_err(|error| no_effect(format!("fixed branch: {error:?}")))
    }
}

fn no_effect(error: String) -> EffectFailure<String> {
    EffectFailure {
        error,
        completion: Completion::None,
    }
}

// The memory owner retains the non-cloneable binding for this actual monitor.
// Matching address spaces alone cannot authorize independently supplied PEs.
fn check_pe_binding<P: DataPolicy>(
    memory: &MemoryThread<P>,
    event: &EventEndpoint,
) -> Result<(), String> {
    memory
        .check_event_endpoint(event)
        .map_err(|error| format!("memory/event PE binding: {error:?}"))
}

#[cfg(test)]
#[path = "fixed_execution/tests.rs"]
mod tests;
