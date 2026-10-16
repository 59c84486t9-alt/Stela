//! The software system backend of a privileged PE: controls, system-register
//! effects and memory resources. Thread state and PC stay with the retiring owner.
use super::super::software_async::{CtiRoute, DebugSources};
use super::{
    NativeObservation, provider,
    source::{BoundSource, Helper},
};
use crate::{
    memory::{
        domain::{MemoryDomain, MemoryExecutionLoan, MemoryThread},
        policy::MemoryControls,
    },
    system::{
        access::{ExceptionLevel, SecurityState},
        debug::{halted::DebugMachine, halting},
        exception::higher_el::{self, Call, CallPrefix, Selection},
        execution::Boundary,
        identification_snapshot::Snapshot,
        pstate::{DAIF_MASK, NZCV_MASK},
        state::{PSTATE_EL1H, PSTATE_EL2H, PSTATE_EL3H, PSTATE_IL_MASK, SystemState},
    },
};
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::sync::Arc;
use stela_compiler::{
    GuestAddress, GuestState,
    aarch64::system::exception::Operation,
    block::{BlockProfile, system::SystemOperation},
    context::memory::MemoryStatus,
};

const HCR_HCD: u64 = 1 << 29;
const HCR_TSC: u64 = 1 << 19;
const HCR_RW: u64 = 1 << 31;
const SCR_NS: u64 = 1;
const SCR_SMD: u64 = 1 << 7;
const SCR_HCE: u64 = 1 << 8;
const SCR_RW: u64 = 1 << 10;
const VECTOR_ALIGNMENT_MASK: u64 = 0x7ff;
const VECTOR_LOWER_A64: u64 = 0x400;
const ONE_SOURCE_WORD_BYTES: usize = size_of::<u32>();

/// Lower-EL control storage. MDSCR and the debug view come from the debug
/// lifecycle instead.
pub(super) struct LowerElControls {
    pub snapshot: Arc<Snapshot>,
    pub sctlr_el1: u64,
    pub tcr_el1: u64,
    pub call_implementation: higher_el::Implementation,
}

pub(crate) struct PrivilegedOwner<'pe> {
    pub(super) address_space: u64,
    pub(super) lower: LowerElControls,
    pub(super) memory: &'pe mut MemoryThread<MemoryControls>,
    pub(super) domain: Arc<MemoryDomain>,
    pub(super) producers: DebugSources<'pe>,
    pub(super) cti: CtiRoute,
    pub(super) scalable: Option<super::privileged_debug::DebugScalable<'pe>>,
    last_cti_receipt: Option<(u64, usize)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Committed {
    None,
    HypervisorStep,
    SoftwareStep,
    ContextSynchronized,
    DebugInitialized,
    PstateWritten,
    ExceptionBankWritten,
    HaltPublished,
    FieldsUpdated,
}
/// Created only by this backend and consumed by the consumer into PC and phase.
pub(crate) enum SystemOutcome {
    NoEffect(anyhow::Error),
    Indeterminate {
        committed: Committed,
        error: anyhow::Error,
    },
    Entry {
        target: GuestAddress,
    },
    Halted {
        source_pc: GuestAddress,
    },
}

impl<'pe> PrivilegedOwner<'pe> {
    /// The last CTI output recorded, for diagnostics.
    pub(crate) fn last_cti_receipt(&self) -> Option<(u64, usize)> {
        self.last_cti_receipt
    }

    pub(crate) fn enqueue_editr(&mut self, slot: usize, word: u32) -> anyhow::Result<()> {
        self.producers
            .enqueue_editr_slot(slot, word)
            .map_err(|e| anyhow::anyhow!("actual software-debug input: {e:?}"))
    }

    /// # Safety
    /// For a new software PE only. `memory`, `domain` and `producers` are that
    /// PE's exclusive resources and its complete set of event producers;
    /// `lower` owns its lower-EL controls and identification snapshot. Keep the
    /// backend for the PE's whole lifetime, with no other native entry, control
    /// copies, producer writers, adoption or reset.
    pub(super) unsafe fn fresh_software(
        address_space: u64,
        lower: LowerElControls,
        memory: &'pe mut MemoryThread<MemoryControls>,
        domain: Arc<MemoryDomain>,
        producers: DebugSources<'pe>,
        cti: CtiRoute,
        scalable: Option<super::privileged_debug::DebugScalable<'pe>>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            memory.address_space() == Some(address_space) && memory.has_domain(&domain),
            "privileged producer memory domain differs"
        );
        anyhow::ensure!(
            lower.call_implementation.without_el3_security
                == higher_el::WithoutEl3Security::NonSecureOnly,
            "first privileged producer requires explicit NonSecure lower ELs"
        );
        lower
            .snapshot
            .check_base_optional_entry_effects()
            .map_err(|e| anyhow::anyhow!("privileged optional state: {e:?}"))?;
        producers
            .check_registry()
            .map_err(|e| anyhow::anyhow!("privileged complete producer registry: {e:?}"))?;
        Ok(Self {
            address_space,
            lower,
            memory,
            domain,
            producers,
            cti,
            scalable,
            last_cti_receipt: None,
        })
    }
    pub(crate) fn qualify_lifecycle(
        &self,
        debug: &DebugMachine,
        system: &SystemState,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.lower.snapshot.same_snapshot(debug.snapshot()),
            "debug/control Snapshot differs"
        );
        if let Some(higher) = system.higher_el() {
            anyhow::ensure!(
                higher.same_snapshot(&self.lower.snapshot),
                "higher/control Snapshot differs"
            );
        } else {
            self.lower
                .snapshot
                .check_el10_regime()
                .map_err(|e| anyhow::anyhow!("EL regime: {e:?}"))?;
        }
        anyhow::ensure!(
            debug.qualifier_step_disabled(),
            "enabled monitor/halting step outside first producer"
        );
        self.check_current_controls(system)?;
        Ok(())
    }
    pub(super) fn qualify_debug_resources(
        &self,
        system: &SystemState,
        debug: &DebugMachine,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        self.qualify_lifecycle(debug, system)?;
        anyhow::ensure!(
            self.memory.address_space() == Some(self.address_space)
                && self.memory.has_domain(&self.domain)
                && outer.belongs_to(&self.domain),
            "actual halted outer/domain differs"
        );
        self.domain
            .check_execution()
            .map_err(|e| anyhow::anyhow!("actual privileged memory health: {e:?}"))?;
        self.check_current_controls(system)?;
        self.producers
            .check_registry()
            .map_err(|e| anyhow::anyhow!("actual halted producer universe: {e:?}"))
    }
    pub(super) fn update_debug_fields(
        &self,
        system: &SystemState,
        debug: &mut DebugMachine,
    ) -> anyhow::Result<()> {
        self.producers
            .check_registry()
            .map_err(|e| anyhow::anyhow!("actual SError universe: {e:?}"))?;
        // Only the debug producer exists, and the controls exclude virtual and
        // delegated SError routing.
        let context = self.halting_context(system, debug);
        match halting::pending_serror_source(context) {
            halting::PendingSError::Physical => {}
            selected => anyhow::bail!("actual {selected:?} SError source unavailable"),
        }
        debug.write_edscr_fields(halting::edscr_fields(debug.edscr(), context, false));
        Ok(())
    }
    fn check_resources(
        &self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            bound.runtime.profile() == BlockProfile::SystemV1,
            "privileged source ABI differs"
        );
        anyhow::ensure!(
            bound.source.len() == ONE_SOURCE_WORD_BYTES && bound.system_instruction().is_ok(),
            "first System producer accepts one no-memory source word"
        );
        anyhow::ensure!(
            bound.entry.address_space() == self.address_space
                && self.memory.address_space() == Some(self.address_space)
                && self.memory.has_domain(&self.domain)
                && outer.belongs_to(&self.domain),
            "actual outer/source domain differs"
        );
        self.domain
            .check_execution()
            .map_err(|e| anyhow::anyhow!("actual privileged memory health: {e:?}"))?;
        self.check_current_controls(system)?;
        self.producers
            .check_registry()
            .map_err(|e| anyhow::anyhow!("actual producer registry: {e:?}"))?;
        Ok(())
    }

    fn check_current_controls(&self, system: &SystemState) -> anyhow::Result<()> {
        anyhow::ensure!(
            system.pacm_state_feature() == crate::system::state::PacmStateFeature::Absent,
            "privileged lifecycle excludes Full PACM storage"
        );
        anyhow::ensure!(
            system.pstate_misc() & PSTATE_IL_MASK == 0,
            "illegal source execution state"
        );
        anyhow::ensure!(
            self.lower.sctlr_el1 == 0 && self.lower.tcr_el1 == 0,
            "first producer requires actual base EL1 controls"
        );
        if let Some(higher) = system.higher_el() {
            anyhow::ensure!(
                higher.same_snapshot(&self.lower.snapshot),
                "actual higher Snapshot differs"
            );
            if let Some(hcr) = higher.hcr() {
                anyhow::ensure!(
                    *hcr & !(HCR_HCD | HCR_TSC | HCR_RW) == 0,
                    "unsupported actual HCR field"
                );
            }
            if let Some(scr) = higher.scr() {
                anyhow::ensure!(
                    *scr & !(SCR_NS | SCR_SMD | SCR_HCE | SCR_RW) == 0,
                    "unsupported actual SCR field"
                );
            }
            for el in [ExceptionLevel::El2, ExceptionLevel::El3] {
                if higher.present(el) {
                    anyhow::ensure!(
                        higher.sctlr(el).map_err(|e| anyhow::anyhow!("{e:?}"))? == 0
                            && higher.tcr(el).map_err(|e| anyhow::anyhow!("{e:?}"))? == 0,
                        "unsupported actual target address controls"
                    );
                }
            }
        }
        Ok(())
    }

    /// Every preparation and check precedes the first architectural effect. The
    /// method never sees PC.
    pub(super) fn complete_system(
        &mut self,
        bound: &BoundSource<'_>,
        boundary: &Boundary,
        system: &mut SystemState,
        registers: &mut GuestState,
        debug: &mut DebugMachine,
        outer: &MemoryExecutionLoan,
    ) -> SystemOutcome {
        let prepared = (|| -> anyhow::Result<()> {
            self.check_resources(bound, system, outer)?;
            self.qualify_lifecycle(debug, system)?;
            bound.check_descriptor(boundary.source())?;
            anyhow::ensure!(
                boundary.instruction().instruction_pc == bound.entry.entry()
                    && boundary.instruction().word == bound.entry.word(),
                "System terminal differs from original word"
            );
            debug
                .qualify_normal_entry()
                .map_err(|e| anyhow::anyhow!("actual debug gate: {e:?}"))?;
            self.producers
                .qualify_normal_boundary()
                .map_err(|e| anyhow::anyhow!("actual pending source: {e:?}"))?;
            Ok(())
        })();
        if let Err(error) = prepared {
            return SystemOutcome::NoEffect(error);
        }
        let SystemOperation::Exception(operation) = boundary.instruction().operation else {
            return SystemOutcome::NoEffect(anyhow::anyhow!(
                "System family outside privileged producer"
            ));
        };
        match operation {
            Operation::HypervisorCall { immediate } => self.call(
                bound,
                boundary,
                system,
                registers,
                debug,
                Call::Hypervisor { immediate },
            ),
            Operation::SecureMonitorCall { immediate } => self.call(
                bound,
                boundary,
                system,
                registers,
                debug,
                Call::SecureMonitor { immediate },
            ),
            Operation::Halt { .. } => self.halt(boundary, system, registers, debug),
            _ => SystemOutcome::NoEffect(anyhow::anyhow!(
                "architectural System family requires its original guest exception owner"
            )),
        }
    }
    fn call(
        &mut self,
        bound: &BoundSource<'_>,
        boundary: &Boundary,
        system: &mut SystemState,
        registers: &mut GuestState,
        debug: &mut DebugMachine,
        call: Call,
    ) -> SystemOutcome {
        // Copy the selector inputs into locals before mutating the system
        // state. SPSR is read after the prefix.
        let selected = (|| -> anyhow::Result<_> {
            let higher = system
                .higher_el()
                .ok_or_else(|| anyhow::anyhow!("higher-EL bank owner unavailable"))?;
            let selection = higher_el::select(
                &self.lower.snapshot,
                higher_el::ControlReadbacks {
                    hcr_el2: higher.hcr(),
                    scr_el3: higher.scr(),
                },
                self.lower.call_implementation,
                system,
                registers,
                boundary.instruction().instruction_pc.0,
                call,
            )
            .map_err(|e| anyhow::anyhow!("call selection: {e:?}"))?;
            let request = match selection {
                Selection::Entry(request) => request,
                Selection::Undefined(reason) => anyhow::bail!(
                    "call {reason:?} needs generalized original guest exception route"
                ),
            };
            anyhow::ensure!(
                request.snapshot.same_snapshot(&self.lower.snapshot)
                    && core::ptr::eq(request.source_system, system)
                    && core::ptr::eq(request.source_registers, registers)
                    && request.source_pc == boundary.instruction().instruction_pc.0
                    && request.controls.hcr_el2.map(core::ptr::from_ref)
                        == higher.hcr().map(core::ptr::from_ref)
                    && request.controls.scr_el3.map(core::ptr::from_ref)
                        == higher.scr().map(core::ptr::from_ref)
                    && request.target_security == higher.security(request.target_el),
                "higher-EL intent does not belong to actual source/control/state owners"
            );
            let bank = system
                .exception_registers(request.target_el)
                .map_err(|e| anyhow::anyhow!("target bank: {e:?}"))?;
            let target = (bank.vbar() & !VECTOR_ALIGNMENT_MASK).wrapping_add(VECTOR_LOWER_A64);
            let target_source = BoundSource::new(bound.runtime, GuestAddress(target))?;
            anyhow::ensure!(
                matches!(
                    target_source.system_instruction()?.operation,
                    SystemOperation::Exception(Operation::Halt { .. })
                ),
                "first higher-EL consumer requires actual loaded HLT handler source"
            );
            Ok((
                request.target_el,
                request.preferred_pc,
                request.esr,
                request.call_prefix,
                target,
                target_source,
            ))
        })();
        let (target_el, preferred, esr, prefix, target, _target_source) = match selected {
            Ok(v) => v,
            Err(e) => return SystemOutcome::NoEffect(e),
        };
        let mut committed = Committed::None;
        let result = (|| -> anyhow::Result<()> {
            match prefix {
                CallPrefix::SecureMonitor => {
                    debug.hs_advance(SecurityState::NonSecure);
                    committed = Committed::HypervisorStep;
                    debug
                        .ss_advance(system, registers)
                        .map_err(|e| anyhow::anyhow!("actual SSAdvance: {e:?}"))?;
                    committed = Committed::SoftwareStep;
                }
                CallPrefix::Hypervisor => {
                    debug
                        .ss_advance(system, registers)
                        .map_err(|e| anyhow::anyhow!("actual SSAdvance: {e:?}"))?;
                    committed = Committed::SoftwareStep;
                }
                CallPrefix::TrappedSecureMonitor => {}
            }
            super::super::super::serialize_instruction_execution()?;
            committed = Committed::ContextSynchronized;
            let saved = system.pstate(registers);
            let mode = match target_el {
                ExceptionLevel::El1 => PSTATE_EL1H,
                ExceptionLevel::El2 => PSTATE_EL2H,
                ExceptionLevel::El3 => PSTATE_EL3H,
                ExceptionLevel::El0 => anyhow::bail!("invalid exception target"),
            };
            system
                .transition_pstate(registers, (saved & NZCV_MASK) | DAIF_MASK | mode)
                .map_err(|e| anyhow::anyhow!("actual target state: {e:?}"))?;
            committed = Committed::PstateWritten;
            let bank = system
                .exception_registers_mut(target_el)
                .map_err(|e| anyhow::anyhow!("actual target bank: {e:?}"))?;
            bank.set_esr(esr);
            bank.set_spsr(saved);
            bank.set_elr(preferred);
            // FAR/HPFAR are UNKNOWN for these calls, so keep the old values.
            committed = Committed::ExceptionBankWritten;
            // The consumer stores the target PC before the finalizers run. A
            // late failure must keep the entry bank, SP and target PC; it is
            // not a refusal.
            Ok(())
        })();
        match result {
            Ok(()) => SystemOutcome::Entry {
                target: GuestAddress(target),
            },
            Err(error) => SystemOutcome::Indeterminate { committed, error },
        }
    }
    fn halt(
        &mut self,
        boundary: &Boundary,
        system: &mut SystemState,
        registers: &mut GuestState,
        debug: &mut DebugMachine,
    ) -> SystemOutcome {
        let context = self.halting_context(system, debug);
        let prepared = (|| -> anyhow::Result<_> {
            let instruction = halting::Instruction::prepare(boundary.instruction().word)
                .ok_or_else(|| anyhow::anyhow!("not compiler-owned HLT"))?;
            let plan = halting::prepare(instruction, context, debug.status(), debug.edscr())
                .map_err(|e| anyhow::anyhow!("HLT preparation: {e:?}"))?;
            let halting::Preparation::Plan(plan) = plan else {
                anyhow::bail!("HLT Undefined needs original guest exception route");
            };
            anyhow::ensure!(
                plan.word() == boundary.instruction().word,
                "HLT plan/source association differs"
            );
            self.producers
                .prepare_cross_halt(&self.cti)
                .map_err(|e| anyhow::anyhow!("actual CTI preflight: {e:?}"))
        })();
        let cross = match prepared {
            Ok(v) => v,
            Err(error) => return SystemOutcome::NoEffect(error),
        };
        let mut committed = Committed::None;
        let result = (|| -> anyhow::Result<()> {
            // The CTI output ledger is domain state and survives any later
            // failure.
            let cti = self
                .producers
                .publish_cross_halt(cross)
                .map_err(|e| anyhow::anyhow!("actual CTI signal: {e:?}"))?;
            self.last_cti_receipt = Some((cti.sequence, cti.delivered_targets));
            debug.save_halt_state(
                boundary.instruction().instruction_pc.0,
                system.pstate(registers),
            );
            debug.write_edscr_fields(halting::halt_edscr(debug.edscr(), context));
            committed = Committed::DebugInitialized;
            system
                .transition_pstate(
                    registers,
                    halting::halt_pstate(system.pstate(registers), context.features),
                )
                .map_err(|e| anyhow::anyhow!("actual Halt PSTATE: {e:?}"))?;
            committed = Committed::PstateWritten;
            debug.stop_prefetch_enable_itr();
            debug
                .publish_halt_instruction()
                .map_err(|e| anyhow::anyhow!("actual halt publication: {e:?}"))?;
            committed = Committed::HaltPublished;
            // Only debug producers are registered; HCR virtual-pending/AMO and
            // SCR delegated-SError controls were refused.
            self.producers
                .check_registry()
                .map_err(|e| anyhow::anyhow!("actual SError universe: {e:?}"))?;
            debug.write_edscr_fields(halting::edscr_fields(
                debug.edscr(),
                self.halting_context(system, debug),
                false,
            ));
            committed = Committed::FieldsUpdated;
            self.domain
                .check_execution()
                .map_err(|e| anyhow::anyhow!("actual halted domain finalization: {e:?}"))?;
            Ok(())
        })();
        match result {
            Ok(()) => SystemOutcome::Halted {
                source_pc: boundary.instruction().instruction_pc,
            },
            Err(error) => SystemOutcome::Indeterminate { committed, error },
        }
    }
    pub(super) fn halting_context(
        &self,
        system: &SystemState,
        debug: &DebugMachine,
    ) -> halting::Context {
        let higher = system.higher_el();
        let present = |el| higher.is_some_and(|state| state.present(el));
        let security = higher.map_or(SecurityState::NonSecure, |state| {
            state.security(system.current_el())
        });
        halting::Context {
            features: debug.halting_features(),
            current_el: system.current_el(),
            security,
            aarch64_at_all_present_els: true,
            el2_present: present(ExceptionLevel::El2),
            el2_enabled: present(ExceptionLevel::El2),
            el3_present: present(ExceptionLevel::El3),
            secure_el2_enabled: false,
            host_at_el0: false,
            hcr_el2: higher.and_then(|state| state.hcr()).copied(),
            sctlr_el1: self.lower.sctlr_el1,
            sctlr_el2: higher.and_then(|state| state.sctlr(ExceptionLevel::El2).ok()),
            double_lock: debug.double_locked(),
            external_invasive_enabled: debug.nonsecure_invasive(),
            external_secure_invasive_enabled: debug.secure_invasive(),
            delegated_serror_enabled: false,
        }
    }
}

impl provider::sealed::Concrete for PrivilegedOwner<'_> {}
impl provider::Owner for PrivilegedOwner<'_> {
    fn supports_profile(&self, profile: BlockProfile) -> bool {
        profile == BlockProfile::SystemV1
    }
    fn prepare_source(
        &mut self,
        runtime: &mut crate::blocks::BlockRuntime,
        system: &SystemState,
        pc: GuestAddress,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            outer.belongs_to(&self.domain),
            "actual source outer differs"
        );
        self.domain
            .check_execution()
            .map_err(|e| anyhow::anyhow!("actual source domain health: {e:?}"))?;
        let (_, region) = runtime
            .region(pc)
            .ok_or_else(|| anyhow::anyhow!("actual System source absent"))?;
        let base = runtime
            .region(pc)
            .ok_or_else(|| anyhow::anyhow!("actual System source absent"))?
            .0;
        let offset = usize::try_from(
            pc.0.checked_sub(base)
                .ok_or_else(|| anyhow::anyhow!("source underflow"))?,
        )?;
        let end = offset
            .checked_add(ONE_SOURCE_WORD_BYTES)
            .ok_or_else(|| anyhow::anyhow!("source slice overflow"))?;
        let word = u32::from_le_bytes(
            region
                .source
                .get(offset..end)
                .ok_or_else(|| anyhow::anyhow!("source word absent"))?
                .try_into()?,
        );
        let target_el = match stela_compiler::aarch64::system::exception::decode(word) {
            Some(Operation::HypervisorCall { .. }) => Some(ExceptionLevel::El2),
            Some(Operation::SecureMonitorCall { .. }) => Some(
                if system
                    .higher_el()
                    .and_then(|h| h.hcr())
                    .is_some_and(|hcr| hcr & HCR_TSC != 0)
                {
                    ExceptionLevel::El2
                } else {
                    ExceptionLevel::El3
                },
            ),
            _ => None,
        };
        if let Some(el) = target_el {
            // Cache preparation only. The selection, target bank, controls and
            // loaded source are re-checked against the GPRs after the native
            // block, before any architectural effect.
            if let Ok(bank) = system.exception_registers(el) {
                let target = GuestAddress(
                    (bank.vbar() & !VECTOR_ALIGNMENT_MASK).wrapping_add(VECTOR_LOWER_A64),
                );
                runtime.load(target, &mut super::empty_accounting())?;
            }
        }
        Ok(())
    }
    fn qualify_debug_lifecycle(
        &self,
        debug: Option<&DebugMachine>,
        system: &SystemState,
    ) -> anyhow::Result<()> {
        let debug = debug.ok_or_else(|| anyhow::anyhow!("actual debug lifecycle unavailable"))?;
        self.qualify_lifecycle(debug, system)?;
        debug
            .qualify_normal_entry()
            .map_err(|e| anyhow::anyhow!("actual normal instruction gate: {e:?}"))
    }
    fn execution_loan(&mut self) -> anyhow::Result<MemoryExecutionLoan> {
        self.memory
            .execution_loan()
            .map_err(|e| anyhow::anyhow!("actual privileged exclusion: {e:?}"))
    }
    fn qualify(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        _registers: &mut GuestState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        self.check_resources(bound, system, outer)?;
        self.producers
            .qualify_normal_boundary()
            .map_err(|e| anyhow::anyhow!("actual pending source: {e:?}"))
    }
    fn invoke(
        &mut self,
        bound: &BoundSource<'_>,
        _system: &mut SystemState,
        registers: &mut GuestState,
    ) -> anyhow::Result<NativeObservation> {
        self.domain
            .check_execution()
            .map_err(|e| anyhow::anyhow!("actual immediate native domain: {e:?}"))?;
        // The one-word mapping returns only the terminal; this ABI uses no
        // guest RAM, execution context or memory callback.
        let exit = match unsafe { bound.block.mapping.call_block(registers) } {
            Ok(exit) => exit,
            Err(error) => {
                return Ok(NativeObservation::InvocationFailed {
                    detail: error.to_string(),
                    native_invoked: true,
                    native_executed: false,
                    original_fault: None,
                    raw_memory: None,
                    completed_bytes: 0,
                    observed_exit: None,
                    raw_returned_carrier: None,
                });
            }
        };
        // Keep the native result even if finalization cannot validate it.
        let finalized = self
            .domain
            .check_execution()
            .map_err(|e| anyhow::anyhow!("actual native domain finalization: {e:?}"))
            .and_then(|()| {
                self.producers
                    .check_registry()
                    .map_err(|e| anyhow::anyhow!("actual native producer finalization: {e:?}"))
            });
        if let Err(error) = finalized {
            return Ok(NativeObservation::FinalizationFailed {
                status: MemoryStatus::Unsupported,
                native_executed: true,
                original_fault: None,
                completed_bytes: 0,
                observed_exit: Some((exit.next_pc, exit.kind)),
                native_invoked: Some(true),
                callback_failure: Some(error.to_string()),
                raw_memory: None,
                raw_returned_carrier: Some((exit.next_pc, exit.kind)),
            });
        }
        Ok(NativeObservation::Returned {
            next_pc: exit.next_pc,
            kind: exit.kind,
        })
    }
    fn complete_system(
        &mut self,
        bound: &BoundSource<'_>,
        boundary: &Boundary,
        system: &mut SystemState,
        registers: &mut GuestState,
        debug: Option<&mut DebugMachine>,
        outer: &MemoryExecutionLoan,
    ) -> SystemOutcome {
        let Some(debug) = debug else {
            return SystemOutcome::NoEffect(anyhow::anyhow!("actual debug lifecycle unavailable"));
        };
        PrivilegedOwner::complete_system(self, bound, boundary, system, registers, debug, outer)
    }
    fn complete_helper(
        &mut self,
        _helper: &Helper,
        _system: &SystemState,
        _registers: &mut GuestState,
        _outer: Option<&MemoryExecutionLoan>,
    ) -> provider::HelperOutcome {
        provider::HelperOutcome::NoEffect(anyhow::anyhow!("helper outside privileged producer"))
    }
    fn complete_trap(
        &mut self,
        _trap: &stela_compiler::block::SynchronousTrap,
        _system: &SystemState,
        _registers: &mut GuestState,
        _events: &mut super::darwin_services::TrapServiceEvents,
    ) -> super::darwin_services::Outcome {
        // A SystemV1 source cannot qualify this carrier. Guest EL1 exceptions
        // must use the architectural guest bank owner, never the Darwin adapter.
        super::darwin_services::Outcome::NoEffect
    }
    fn post_retirement(
        &mut self,
        bound: &BoundSource<'_>,
        system: &SystemState,
        _registers: &mut GuestState,
        outer: &MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        self.check_resources(bound, system, outer)?;
        self.producers
            .qualify_normal_boundary()
            .map_err(|e| anyhow::anyhow!("actual retirement producers: {e:?}"))
    }
}

#[cfg(test)]
pub(super) mod tests;
