//! EL1 register and exception execution over fixed code and controls.

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

/// Exclusive state and monitor borrows, plus the control owner. The endpoint is
/// the PE's event register used by WFx and SEVL.
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
    // The shared decoder turns some constrained memory forms into NOPs and
    // erases BC's HBC origin. This profile supports neither, so the original
    // word is kept.
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

// The memory owner keeps the PE's monitor binding; matching address spaces
// alone do not admit another PE.
fn check_pe_binding<P: DataPolicy>(
    memory: &MemoryThread<P>,
    event: &EventEndpoint,
) -> Result<(), String> {
    memory
        .check_event_endpoint(event)
        .map_err(|error| format!("memory/event PE binding: {error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blocks::{BlockRuntime, StopReason, ThreadState},
        memory::domain::{DataAccess, MemoryDomain, MemorySystem},
        system::{
            debug::DebugControls,
            events::EventDomain,
            exception::EntryControls,
            profile::{EntryProfile, ScalableEntryAbsence, SystemEntryFeatures},
            state::{El1Registers, PSTATE_EL0T, PSTATE_EL1H, PSTATE_EL1T},
        },
    };
    use stela_compiler::{
        TargetCpu, block::system::decode_system_instruction, context::memory::MemoryStatus,
    };

    const ADDRESS_SPACE: u64 = 7;
    const SOURCE_PC: GuestAddress = GuestAddress(0x1000);
    const VECTOR_BASE: u64 = 0x8000;
    const TARGET_PC: u64 = 0x2000;
    const INACTIVE_SP: u64 = 0x3000;
    const ACTIVE_SP: u64 = 0x4000;
    const SAVED_NZCV: u32 = 0xa000_0000;
    const SAVED_DAIF: u64 = 0x140;
    const ENTRY_DAIF: u64 = 0x3c0;
    const VECTOR_SPX: u64 = 0x200;
    const ESR_SVC: u64 = 0x5600_0000;
    const ESR_UNDEFINED: u64 = 0x0200_0000;
    const ERG_BYTES: u64 = 16;
    const MONITOR_STRIPES: usize = 4;
    const SVC: u32 = 0xd400_0001;
    const UDF: u32 = 0;
    const ERET: u32 = 0xd69f_03e0;
    const ADD_X0: u32 = 0x9100_0400;
    const B_EQ: u32 = 0x5400_0020;
    const BC_EQ: u32 = B_EQ | CONSISTENT_BRANCH_HINT;
    const CONSTRAINED_FP_PAIR: u32 = 0xad40_0000;

    struct Policy;
    impl DataPolicy for Policy {
        fn validate_execution(&self, _: u32) -> Result<(), MemoryStatus> {
            Ok(())
        }
        fn translate(&self, address: u64) -> Result<u64, MemoryStatus> {
            Ok(address)
        }
        fn check(&mut self, _: DataAccess<'_>) -> Result<(), MemoryStatus> {
            Ok(())
        }
    }

    fn memory() -> MemoryThread<Policy> {
        MemoryDomain::new_for_address_space(
            ADDRESS_SPACE,
            MemorySystem::new(ERG_BYTES, MONITOR_STRIPES).unwrap(),
            Vec::new(),
            TargetCpu::detect(),
        )
        .unwrap()
        .thread(Policy)
    }

    fn controls() -> FixedEl1Controls {
        FixedEl1Controls::new(
            EntryProfile::base(
                SystemEntryFeatures::declared_absent(),
                ScalableEntryAbsence::from_id_registers(0, 0).unwrap(),
            )
            .unwrap(),
            crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
            0,
            EntryControls {
                tcr_el1: 0,
                mdscr_el1: 0,
                debug: DebugControls::default(),
            },
        )
        .unwrap()
    }

    fn state(mode: u64, saved_mode: u64) -> SystemState {
        SystemState::new(
            mode,
            INACTIVE_SP,
            El1Registers::new(
                TARGET_PC,
                saved_mode | SAVED_DAIF | u64::from(SAVED_NZCV),
                0x5555,
                0x6666,
                VECTOR_BASE,
            ),
        )
        .unwrap()
    }

    fn registers() -> GuestState {
        let mut registers = GuestState {
            sp: ACTIVE_SP,
            nzcv: 0x5000_0000,
            reserved: 0x1234_5678,
            fpcr: 0x0100_0000,
            fpsr: 0x0800_009f,
            ..GuestState::default()
        };
        for (index, value) in registers.x.iter_mut().enumerate() {
            *value = 0x1020_3040_5060_7080 ^ index as u64;
        }
        for (index, value) in registers.v.iter_mut().enumerate() {
            *value = [index as u64 * 17 + 3, !(index as u64 * 17 + 3)];
        }
        registers
    }

    fn source(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn entry(words: &[u32]) -> EntryBoundary {
        EntryBoundary::new(
            ADDRESS_SPACE,
            1,
            SOURCE_PC,
            SOURCE_PC,
            words.len() * INSTRUCTION_BYTES,
            words[0],
        )
    }

    #[test]
    fn fixed_source_uses_shared_boundaries_and_declines_all_external_producers() {
        for words in [
            vec![ADD_X0, SVC],
            vec![ADD_X0, UDF],
            vec![ERET],
            vec![NOP_WORD, SVC],
            vec![B_EQ],
            vec![0x1400_0001],
            vec![0xd61f_0000],
            vec![0x9400_0001],
        ] {
            assert_eq!(validate_source(&entry(&words), &source(&words)), Ok(()));
        }
        const CRC: u32 = 0x1ac0_4000;
        const CSSC_ABS: u32 = 0x5ac0_2000;
        const SSBB: u32 = 0xd503_309f;
        const MSR_NZCV: u32 = 0xd51b_4200;
        const LOAD: u32 = 0xf940_0000;
        const IRG: u32 = 0x9ac0_1000;
        const ERETAA: u32 = 0xd69f_0bff;
        const BRK: u32 = 0xd420_0000;
        for word in [CRC, CSSC_ABS, SSBB, MSR_NZCV, LOAD, IRG, ERETAA, BRK] {
            let words = [ADD_X0, word, SVC];
            assert!(
                validate_source(&entry(&words), &source(&words)).is_err(),
                "{word:#x}"
            );
        }
        assert!(validate_source(&entry(&[SVC]), &source(&[UDF])).is_err());
    }

    #[test]
    fn fixed_legacy_completion_never_grants_synchronization() {
        let controls = controls();
        let mut system = state(PSTATE_EL1H, PSTATE_EL1H);
        let original_system = system.clone();
        let mut registers = registers();
        let original_registers = registers.clone();
        let domain = EventDomain::new();
        let event = domain.register(false, None).unwrap();
        let mut memory = memory();
        memory.bind_events(&event.producer()).unwrap();
        let mut dispatcher =
            FixedEl1Dispatcher::new(ADDRESS_SPACE, &mut system, &controls, &mut memory, &event)
                .unwrap();
        let boundary = Boundary::new(
            entry(&[SVC]),
            INSTRUCTION_BYTES,
            decode_system_instruction(SOURCE_PC, SVC).unwrap().unwrap(),
        );
        assert!(matches!(
            dispatcher.complete(boundary, &mut registers),
            Err(Failure::Unsupported(_))
        ));
        assert_eq!(registers, original_registers);
        assert_eq!(system, original_system);
        assert!(!event.is_set());
    }

    #[test]
    fn fixed_constructor_requires_the_actual_retained_pe_binding() {
        let controls = controls();
        let mut system = state(PSTATE_EL1H, PSTATE_EL1H);
        let domain = EventDomain::new();
        let first = domain.register(false, None).unwrap();
        let other = domain.register(false, None).unwrap();
        let mut memory = memory();
        assert!(matches!(
            FixedEl1Dispatcher::new(ADDRESS_SPACE, &mut system, &controls, &mut memory, &first),
            Err(Failure::Backend(_))
        ));
        memory.bind_events(&first.producer()).unwrap();
        assert!(matches!(
            FixedEl1Dispatcher::new(ADDRESS_SPACE, &mut system, &controls, &mut memory, &other),
            Err(Failure::Backend(_))
        ));
        assert!(
            FixedEl1Dispatcher::new(ADDRESS_SPACE, &mut system, &controls, &mut memory, &first)
                .is_ok()
        );
        assert!(!first.is_set());
        assert!(!other.is_set());
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn fixed_native_entry_preserves_full_state_and_uses_old_stack_vector() -> anyhow::Result<()> {
        for mode in [PSTATE_EL1T, PSTATE_EL1H] {
            for terminal in [UDF, SVC] {
                let cache = tempfile::tempdir()?;
                let mut runtime = BlockRuntime::new_for_target(
                    ADDRESS_SPACE,
                    cache.path().into(),
                    BlockProfile::SystemV1,
                    TargetCpu::Baseline,
                );
                runtime.register_code(SOURCE_PC, source(&[ADD_X0, terminal]))?;
                let controls = controls();
                let mut system = state(mode, PSTATE_EL1H);
                let mut thread = ThreadState {
                    registers: registers(),
                    pc: SOURCE_PC,
                };
                let mut expected = thread.registers.clone();
                expected.x[0] += 1;
                if mode == PSTATE_EL1T {
                    expected.sp = INACTIVE_SP;
                }
                let old_psr = system.pstate(&thread.registers);
                let domain = EventDomain::new();
                let event = domain.register(false, None).unwrap();
                let mut memory = memory();
                memory.bind_events(&event.producer()).unwrap();
                let mut dispatcher = FixedEl1Dispatcher::new(
                    ADDRESS_SPACE,
                    &mut system,
                    &controls,
                    &mut memory,
                    &event,
                )
                .unwrap();
                // SAFETY: validated baseline register prefix, immutable source and
                // scoped fixed exception completion; no guest data is executed.
                let outcome =
                    unsafe { runtime.run_with_system(&mut thread, None, 1, &mut dispatcher)? };
                assert_eq!(outcome.reason, StopReason::BudgetExhausted);
                assert_eq!(outcome.blocks_executed, 1);
                assert_eq!(thread.registers, expected);
                assert_eq!(
                    thread.pc.0,
                    VECTOR_BASE + if mode == PSTATE_EL1H { VECTOR_SPX } else { 0 }
                );
                assert_eq!(
                    system.pstate(&thread.registers),
                    u64::from(expected.nzcv) | ENTRY_DAIF | PSTATE_EL1H
                );
                assert_eq!(system.el1_registers().spsr(), old_psr);
                assert_eq!(
                    system.el1_registers().elr(),
                    SOURCE_PC.0
                        + INSTRUCTION_BYTES as u64
                        + if terminal == SVC {
                            INSTRUCTION_BYTES as u64
                        } else {
                            0
                        }
                );
                assert_eq!(
                    system.el1_registers().esr(),
                    if terminal == SVC {
                        ESR_SVC
                    } else {
                        ESR_UNDEFINED
                    }
                );
                assert_eq!(system.el1_registers().far(), 0x6666);
                assert!(!event.is_set());
            }
        }
        Ok(())
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn fixed_native_return_uses_real_local_event_and_preserves_full_state() -> anyhow::Result<()> {
        for mode in [PSTATE_EL1T, PSTATE_EL1H] {
            for saved_mode in [PSTATE_EL1T, PSTATE_EL1H] {
                let cache = tempfile::tempdir()?;
                let mut runtime = BlockRuntime::new_for_target(
                    ADDRESS_SPACE,
                    cache.path().into(),
                    BlockProfile::SystemV1,
                    TargetCpu::Baseline,
                );
                runtime.register_code(SOURCE_PC, source(&[ADD_X0, ERET]))?;
                let controls = controls();
                let mut system = state(mode, saved_mode);
                let saved = *system.el1_registers();
                let mut thread = ThreadState {
                    registers: registers(),
                    pc: SOURCE_PC,
                };
                let mut expected = thread.registers.clone();
                expected.x[0] += 1;
                expected.nzcv = SAVED_NZCV;
                if mode != saved_mode {
                    expected.sp = INACTIVE_SP;
                }
                let domain = EventDomain::new();
                let event = domain.register(false, None).unwrap();
                let mut memory = memory();
                memory.bind_events(&event.producer()).unwrap();
                let mut dispatcher = FixedEl1Dispatcher::new(
                    ADDRESS_SPACE,
                    &mut system,
                    &controls,
                    &mut memory,
                    &event,
                )
                .unwrap();
                // SAFETY: validated register-only source and real scoped return owners.
                let outcome =
                    unsafe { runtime.run_with_system(&mut thread, None, 1, &mut dispatcher)? };
                assert_eq!(outcome.reason, StopReason::BudgetExhausted);
                assert_eq!(thread.pc.0, TARGET_PC);
                assert_eq!(thread.registers, expected);
                assert_eq!(
                    system.pstate(&thread.registers),
                    saved_mode | SAVED_DAIF | u64::from(SAVED_NZCV)
                );
                assert_eq!(system.el1_registers(), &saved);
                assert!(event.is_set());
            }
        }
        Ok(())
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn fixed_return_decline_keeps_native_prefix_without_exception_effects() -> anyhow::Result<()> {
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new_for_target(
            ADDRESS_SPACE,
            cache.path().into(),
            BlockProfile::SystemV1,
            TargetCpu::Baseline,
        );
        runtime.register_code(SOURCE_PC, source(&[ADD_X0, ERET]))?;
        let controls = controls();
        let mut system = state(PSTATE_EL1H, PSTATE_EL0T);
        let original_system = system.clone();
        let mut thread = ThreadState {
            registers: registers(),
            pc: SOURCE_PC,
        };
        let mut expected = thread.registers.clone();
        expected.x[0] += 1;
        let domain = EventDomain::new();
        let event = domain.register(false, None).unwrap();
        let mut memory = memory();
        memory.bind_events(&event.producer()).unwrap();
        let mut dispatcher =
            FixedEl1Dispatcher::new(ADDRESS_SPACE, &mut system, &controls, &mut memory, &event)
                .unwrap();
        // SAFETY: register-only source; unsupported destination declines after native prefix.
        let outcome = unsafe { runtime.run_with_system(&mut thread, None, 1, &mut dispatcher)? };
        assert!(matches!(outcome.reason, StopReason::SystemFailure { .. }));
        assert_eq!(thread.pc.0, SOURCE_PC.0 + INSTRUCTION_BYTES as u64);
        assert_eq!(thread.registers, expected);
        assert_eq!(system, original_system);
        assert!(!event.is_set());
        Ok(())
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn fixed_forbidden_control_is_denied_before_any_native_prefix() -> anyhow::Result<()> {
        const MSR_NZCV: u32 = 0xd51b_4200;
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new_for_target(
            ADDRESS_SPACE,
            cache.path().into(),
            BlockProfile::SystemV1,
            TargetCpu::Baseline,
        );
        runtime.register_code(SOURCE_PC, source(&[ADD_X0, MSR_NZCV, SVC]))?;
        let controls = controls();
        let mut system = state(PSTATE_EL1H, PSTATE_EL1H);
        let original_system = system.clone();
        let mut thread = ThreadState {
            registers: registers(),
            pc: SOURCE_PC,
        };
        let original_registers = thread.registers.clone();
        let domain = EventDomain::new();
        let event = domain.register(false, None).unwrap();
        let mut memory = memory();
        memory.bind_events(&event.producer()).unwrap();
        let mut dispatcher =
            FixedEl1Dispatcher::new(ADDRESS_SPACE, &mut system, &controls, &mut memory, &event)
                .unwrap();
        // SAFETY: pre-entry source validation declines unsupported control producer.
        let outcome = unsafe { runtime.run_with_system(&mut thread, None, 1, &mut dispatcher)? };
        assert!(matches!(
            outcome.reason,
            StopReason::SystemEntryFailure { .. }
        ));
        assert_eq!(outcome.blocks_executed, 0);
        assert_eq!(outcome.compiled_blocks, 0);
        assert_eq!(thread.pc, SOURCE_PC);
        assert_eq!(thread.registers, original_registers);
        assert_eq!(system, original_system);
        assert!(!event.is_set());
        Ok(())
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn fixed_erased_optional_origins_decline_before_any_native_prefix() -> anyhow::Result<()> {
        assert!(matches!(
            Decoder.lift(SOURCE_PC, BC_EQ).unwrap().operation,
            Operation::BranchCondition { .. }
        ));
        assert!(matches!(
            Decoder
                .lift(SOURCE_PC, CONSTRAINED_FP_PAIR)
                .unwrap()
                .operation,
            Operation::Nop
        ));
        for forbidden in [BC_EQ, CONSTRAINED_FP_PAIR] {
            let cache = tempfile::tempdir()?;
            let mut runtime = BlockRuntime::new_for_target(
                ADDRESS_SPACE,
                cache.path().into(),
                BlockProfile::SystemV1,
                TargetCpu::Baseline,
            );
            runtime.register_code(SOURCE_PC, source(&[ADD_X0, forbidden, SVC]))?;
            let controls = controls();
            let mut system = state(PSTATE_EL1H, PSTATE_EL1H);
            let original_system = system.clone();
            let mut thread = ThreadState {
                registers: registers(),
                pc: SOURCE_PC,
            };
            let original_registers = thread.registers.clone();
            let domain = EventDomain::new();
            let event = domain.register(false, None).unwrap();
            let mut memory = memory();
            memory.bind_events(&event.producer()).unwrap();
            let mut dispatcher =
                FixedEl1Dispatcher::new(ADDRESS_SPACE, &mut system, &controls, &mut memory, &event)
                    .unwrap();
            // SAFETY: pre-entry source validation declines unsupported control producer.
            let outcome =
                unsafe { runtime.run_with_system(&mut thread, None, 1, &mut dispatcher)? };
            assert!(matches!(
                outcome.reason,
                StopReason::SystemEntryFailure { .. }
            ));
            assert_eq!(outcome.blocks_executed, 0);
            assert_eq!(outcome.compiled_blocks, 0);
            assert_eq!(thread.pc, SOURCE_PC);
            assert_eq!(thread.registers, original_registers);
            assert_eq!(system, original_system);
            assert!(!event.is_set());
        }
        Ok(())
    }
}
