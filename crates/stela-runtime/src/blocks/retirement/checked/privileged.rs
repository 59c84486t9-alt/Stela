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
            .map_err(|e| anyhow::anyhow!("software-debug input: {e:?}"))
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
            "halted outer/domain differs"
        );
        self.domain
            .check_execution()
            .map_err(|e| anyhow::anyhow!("privileged memory health: {e:?}"))?;
        self.check_current_controls(system)?;
        self.producers
            .check_registry()
            .map_err(|e| anyhow::anyhow!("halted producer universe: {e:?}"))
    }
    pub(super) fn update_debug_fields(
        &self,
        system: &SystemState,
        debug: &mut DebugMachine,
    ) -> anyhow::Result<()> {
        self.producers
            .check_registry()
            .map_err(|e| anyhow::anyhow!("SError universe: {e:?}"))?;
        // Only the debug producer exists, and the controls exclude virtual and
        // delegated SError routing.
        let context = self.halting_context(system, debug);
        match halting::pending_serror_source(context) {
            halting::PendingSError::Physical => {}
            selected => anyhow::bail!("{selected:?} SError source unavailable"),
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
            "outer/source domain differs"
        );
        self.domain
            .check_execution()
            .map_err(|e| anyhow::anyhow!("privileged memory health: {e:?}"))?;
        self.check_current_controls(system)?;
        self.producers
            .check_registry()
            .map_err(|e| anyhow::anyhow!("producer registry: {e:?}"))?;
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
            "first producer requires base EL1 controls"
        );
        if let Some(higher) = system.higher_el() {
            anyhow::ensure!(
                higher.same_snapshot(&self.lower.snapshot),
                "higher Snapshot differs"
            );
            if let Some(hcr) = higher.hcr() {
                anyhow::ensure!(
                    *hcr & !(HCR_HCD | HCR_TSC | HCR_RW) == 0,
                    "unsupported HCR field"
                );
            }
            if let Some(scr) = higher.scr() {
                anyhow::ensure!(
                    *scr & !(SCR_NS | SCR_SMD | SCR_HCE | SCR_RW) == 0,
                    "unsupported SCR field"
                );
            }
            for el in [ExceptionLevel::El2, ExceptionLevel::El3] {
                if higher.present(el) {
                    anyhow::ensure!(
                        higher.sctlr(el).map_err(|e| anyhow::anyhow!("{e:?}"))? == 0
                            && higher.tcr(el).map_err(|e| anyhow::anyhow!("{e:?}"))? == 0,
                        "unsupported target address controls"
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
                .map_err(|e| anyhow::anyhow!("debug gate: {e:?}"))?;
            self.producers
                .qualify_normal_boundary()
                .map_err(|e| anyhow::anyhow!("pending source: {e:?}"))?;
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
                "higher-EL intent does not belong to source/control/state owners"
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
                "first higher-EL consumer requires loaded HLT handler source"
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
                        .map_err(|e| anyhow::anyhow!("SSAdvance: {e:?}"))?;
                    committed = Committed::SoftwareStep;
                }
                CallPrefix::Hypervisor => {
                    debug
                        .ss_advance(system, registers)
                        .map_err(|e| anyhow::anyhow!("SSAdvance: {e:?}"))?;
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
                .map_err(|e| anyhow::anyhow!("target state: {e:?}"))?;
            committed = Committed::PstateWritten;
            let bank = system
                .exception_registers_mut(target_el)
                .map_err(|e| anyhow::anyhow!("target bank: {e:?}"))?;
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
                .map_err(|e| anyhow::anyhow!("CTI preflight: {e:?}"))
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
                .map_err(|e| anyhow::anyhow!("CTI signal: {e:?}"))?;
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
                .map_err(|e| anyhow::anyhow!("Halt PSTATE: {e:?}"))?;
            committed = Committed::PstateWritten;
            debug.stop_prefetch_enable_itr();
            debug
                .publish_halt_instruction()
                .map_err(|e| anyhow::anyhow!("halt publication: {e:?}"))?;
            committed = Committed::HaltPublished;
            // Only debug producers are registered; HCR virtual-pending/AMO and
            // SCR delegated-SError controls were refused.
            self.producers
                .check_registry()
                .map_err(|e| anyhow::anyhow!("SError universe: {e:?}"))?;
            debug.write_edscr_fields(halting::edscr_fields(
                debug.edscr(),
                self.halting_context(system, debug),
                false,
            ));
            committed = Committed::FieldsUpdated;
            self.domain
                .check_execution()
                .map_err(|e| anyhow::anyhow!("halted domain finalization: {e:?}"))?;
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
        anyhow::ensure!(outer.belongs_to(&self.domain), "source outer differs");
        self.domain
            .check_execution()
            .map_err(|e| anyhow::anyhow!("source domain health: {e:?}"))?;
        let (_, region) = runtime
            .region(pc)
            .ok_or_else(|| anyhow::anyhow!("System source absent"))?;
        let base = runtime
            .region(pc)
            .ok_or_else(|| anyhow::anyhow!("System source absent"))?
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
        let debug = debug.ok_or_else(|| anyhow::anyhow!("debug lifecycle unavailable"))?;
        self.qualify_lifecycle(debug, system)?;
        debug
            .qualify_normal_entry()
            .map_err(|e| anyhow::anyhow!("normal instruction gate: {e:?}"))
    }
    fn execution_loan(&mut self) -> anyhow::Result<MemoryExecutionLoan> {
        self.memory
            .execution_loan()
            .map_err(|e| anyhow::anyhow!("privileged exclusion: {e:?}"))
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
            .map_err(|e| anyhow::anyhow!("pending source: {e:?}"))
    }
    fn invoke(
        &mut self,
        bound: &BoundSource<'_>,
        _system: &mut SystemState,
        registers: &mut GuestState,
    ) -> anyhow::Result<NativeObservation> {
        self.domain
            .check_execution()
            .map_err(|e| anyhow::anyhow!("immediate native domain: {e:?}"))?;
        // The one-word mapping returns only the terminal; this ABI uses no
        // guest RAM, execution context or memory callback.
        let exit = match unsafe { bound.block.mapping.call_block(registers) } {
            Ok(exit) => exit,
            Err(error) => {
                return Ok(NativeObservation::InvocationFailed(error.to_string()));
            }
        };
        // Keep the native result even if finalization cannot validate it.
        let finalized = self
            .domain
            .check_execution()
            .map_err(|e| anyhow::anyhow!("native domain finalization: {e:?}"))
            .and_then(|()| {
                self.producers
                    .check_registry()
                    .map_err(|e| anyhow::anyhow!("native producer finalization: {e:?}"))
            });
        if let Err(error) = finalized {
            return Ok(NativeObservation::FinalizationFailed {
                status: MemoryStatus::Unsupported,
                fault: None,
                detail: format!("{error}; returned={:?}", (exit.next_pc, exit.kind)),
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
            return SystemOutcome::NoEffect(anyhow::anyhow!("debug lifecycle unavailable"));
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
            .map_err(|e| anyhow::anyhow!("retirement producers: {e:?}"))
    }
}

#[cfg(test)]
pub(super) mod tests {
    // Tests of the software privileged PE.
    use super::*;
    use crate::{
        blocks::{
            ThreadState,
            retirement::{
                checked::{OwnedRunRequest, OwnedStop, accept_retained_loan},
                software_async::SoftwareAsyncDomain,
            },
        },
        memory::{
            domain::{MemorySystem, MemoryThread},
            policy::{LowerAddressProfile, TagCheckFaultMode},
        },
        system::{
            debug::halted::{
                ExtendedHaltSyndrome, ExternalControls, Initialization as DebugInitialization,
                Status,
            },
            execution::owner::SystemExecutionOwner,
            identification::Register,
            state::{
                El1Registers, PSTATE_EL1T, StackBank,
                higher_el::{El2Initialization, El3Initialization, Initialization},
            },
        },
    };
    use stela_compiler::TargetCpu;
    const PC: GuestAddress = GuestAddress(0x1000);
    const ITE: u32 = 1 << 24;
    const HDE: u32 = 1 << 14;
    fn ids(higher: bool) -> Arc<Snapshot> {
        Arc::new(
            Snapshot::declared(
                "privileged-actual-owner-software-model",
                &[
                    (Register::IdAa64Pfr0El1, if higher { 0x1111 } else { 0x11 }),
                    (Register::IdAa64Pfr1El1, 0),
                    (Register::IdAa64Pfr2El1, 0),
                    (Register::IdAa64Dfr0El1, 9),
                    (Register::IdAa64Dfr1El1, 0),
                    (Register::IdAa64Mmfr0El1, 0),
                    (Register::IdAa64Mmfr1El1, 0),
                    (Register::IdAa64Mmfr2El1, 0),
                    (Register::IdAa64Mmfr4El1, 0),
                    (Register::IdAa64Isar1El1, 0),
                    (Register::IdAa64Isar2El1, 0),
                ],
            )
            .unwrap(),
        )
    }
    fn system(ids: Arc<Snapshot>, higher: bool, saved: u64) -> SystemState {
        let el1 = El1Registers::new(1, saved, 3, 4, 0x6000);
        if !higher {
            return SystemState::new(PSTATE_EL1H, 0x1110, el1).unwrap();
        }
        SystemState::new_with_higher_el(
            PSTATE_EL1H,
            0x1110,
            el1,
            ids,
            Initialization {
                el2: Some(El2Initialization {
                    exception: El1Registers::new(21, 22, 23, 24, 0x8000),
                    stack_pointer: 0x3330,
                    hcr: 0,
                    sctlr: 0,
                    tcr: 0,
                    hpfar: 26,
                }),
                el3: Some(El3Initialization {
                    exception: El1Registers::new(31, 32, 33, 34, 0xa000),
                    stack_pointer: 0x4440,
                    scr: SCR_NS | SCR_HCE,
                    sctlr: 0,
                    tcr: 0,
                }),
            },
        )
        .unwrap()
    }
    fn debug(ids: Arc<Snapshot>, status: Status) -> DebugMachine {
        DebugMachine::fresh_declared(
            ids,
            DebugInitialization {
                edscr: status as u32 | ITE | HDE,
                edprsr: if status.halted() { 1 << 4 } else { 0 },
                dlr: 0x7770,
                dspsr: 0x8880,
                edesr: 0,
                edecr: 0,
                mdscr_el1: 0,
                should_advance_ss: true,
                should_advance_hs: true,
                external: ExternalControls {
                    powered: true,
                    double_locked: false,
                    software_locked: false,
                    nonsecure_invasive: true,
                    secure_invasive: true,
                },
                extended_halt_syndrome: ExtendedHaltSyndrome::DeclaredAbsent,
            },
        )
        .unwrap()
    }
    fn memory() -> (Arc<MemoryDomain>, MemoryThread<MemoryControls>) {
        let domain = MemoryDomain::new_for_address_space(
            7,
            MemorySystem::new(16, 8).unwrap(),
            vec![],
            TargetCpu::Baseline,
        )
        .unwrap();
        let thread = domain.thread(MemoryControls::new(
            LowerAddressProfile::new(48, false).unwrap(),
            true,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        ));
        (domain, thread)
    }
    macro_rules! machine {
        ($ids:ident, $system:ident, $thread:ident, $status:expr, |$pe:ident| $body:block) => {{
            let (domain, mut memory) = memory();
            let mut producers = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
            let keys = [producers.register_debug().unwrap()];
            let lease = producers.lease_debug_sources(&keys).unwrap();
            let mut backend = unsafe {
                PrivilegedOwner::fresh_software(
                    7,
                    LowerElControls {
                        snapshot: Arc::clone(&$ids),
                        sctlr_el1: 0,
                        tcr_el1: 0,
                        call_implementation: higher_el::Implementation {
                            without_el3_security: higher_el::WithoutEl3Security::NonSecureOnly,
                            trap_smc_without_el3: higher_el::TrapSmcWithoutEl3::Enabled,
                        },
                    },
                    &mut memory,
                    domain,
                    lease,
                    CtiRoute {
                        output_slot: 0,
                        target_slots: vec![],
                    },
                    None,
                )
                .unwrap()
            };
            let mut $pe = unsafe {
                SystemExecutionOwner::new_pe_with_debug(
                    &mut $thread,
                    &mut $system,
                    &mut backend,
                    debug(Arc::clone(&$ids), $status),
                )
                .unwrap()
            };
            $body
        }};
    }
    fn thread() -> ThreadState {
        let mut registers = GuestState {
            sp: 0x2220,
            nzcv: 0xa0000000,
            fpcr: 1 << 22,
            fpsr: (1 << 27) | 0x1f,
            ..GuestState::default()
        };
        for (i, x) in registers.x.iter_mut().enumerate() {
            *x = 0x0123456789abcdefu64 ^ ((i as u64) << 48);
        }
        for (i, v) in registers.v.iter_mut().enumerate() {
            *v = [
                0x8877665544332211u64 ^ (i as u64),
                0xffeeddccbbaa9988u64 ^ ((i as u64) << 32),
            ];
        }
        ThreadState { registers, pc: PC }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn actual_hvc_smc_enter_original_banks_and_sp_once() {
        for (word, target, mode, sp, esr) in [
            (
                0xd4000002u32 | (0x1234 << 5),
                0x8400,
                PSTATE_EL2H,
                0x3330,
                (0x16 << 26) | (1 << 25) | 0x1234,
            ),
            (
                0xd4000003u32 | (0x5678 << 5),
                0xa400,
                PSTATE_EL3H,
                0x4440,
                (0x17 << 26) | (1 << 25) | 0x5678,
            ),
        ] {
            let ids = ids(true);
            let mut system = system(Arc::clone(&ids), true, 0);
            let mut thread = thread();
            let cache = tempfile::tempdir().unwrap();
            let mut runtime = crate::blocks::BlockRuntime::new_for_target(
                7,
                cache.path().to_owned(),
                BlockProfile::SystemV1,
                TargetCpu::Baseline,
            );
            runtime
                .register_code(PC, word.to_le_bytes().to_vec())
                .unwrap();
            runtime
                .register_code(GuestAddress(target), 0xd4400000u32.to_le_bytes().to_vec())
                .unwrap();
            machine!(ids, system, thread, Status::NonDebug, |pe| {
                let outcome = runtime.run_owned(
                    pe.loan(),
                    OwnedRunRequest {
                        stop_pc: Some(GuestAddress(target)),
                        block_budget: 1,
                    },
                );
                assert!(matches!(outcome.stop, OwnedStop::StopAddress));
                assert_eq!(outcome.accounting.blocks_executed, 1);
                assert_eq!(pe.pc(), GuestAddress(target));
            });
            assert_eq!(system.pstate_misc(), mode | DAIF_MASK);
            assert_eq!(thread.registers.sp, sp);
            assert_eq!(thread.registers.nzcv, 0xa0000000);
            let bank = system.exception_registers(system.current_el()).unwrap();
            assert_eq!(bank.elr(), PC.0 + 4);
            assert_eq!(bank.spsr(), PSTATE_EL1H | 0xa0000000);
            assert_eq!(bank.esr(), esr);
            assert_eq!(
                system.read_stack_pointer(crate::system::state::StackBank::El1, &thread.registers),
                Ok(0x2220)
            );
        }
    }
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn actual_hlt_stops_native_and_keeps_restart_pc() {
        let ids = ids(false);
        let mut system = system(Arc::clone(&ids), false, 0);
        let mut thread = thread();
        let cache = tempfile::tempdir().unwrap();
        let mut runtime = crate::blocks::BlockRuntime::new_for_target(
            7,
            cache.path().to_owned(),
            BlockProfile::SystemV1,
            TargetCpu::Baseline,
        );
        runtime
            .register_code(PC, 0xd4400000u32.to_le_bytes().to_vec())
            .unwrap();
        machine!(ids, system, thread, Status::NonDebug, |pe| {
            let outcome = runtime.run_owned(
                pe.loan(),
                OwnedRunRequest {
                    stop_pc: None,
                    block_budget: 1,
                },
            );
            assert!(matches!(
                outcome.stop,
                OwnedStop::Halted { instruction_pc: PC }
            ));
            assert_eq!(pe.pc(), PC);
            {
                let resources = accept_retained_loan(pe.loan());
                assert!(resources.authority.halted());
                assert!(!resources.authority.ready());
                let debug = resources.debug.as_ref().unwrap();
                assert_eq!(debug.status(), Status::HaltInstruction);
                assert_eq!(debug.dlr(), PC.0);
                assert_eq!(debug.dspsr(), PSTATE_EL1H | 0xa0000000);
            }
            let denied = runtime.run_owned(
                pe.loan(),
                OwnedRunRequest {
                    stop_pc: None,
                    block_budget: 1,
                },
            );
            assert!(matches!(denied.stop, OwnedStop::EntryDeclined(_)));
            assert_eq!(denied.accounting.blocks_executed, 0);
        });
    }
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn actual_dcps_all_targets_stay_halted_and_preserve_pc() {
        for (word, el, sp) in [
            (0xd4a00001u32, ExceptionLevel::El1, 0x2220),
            (0xd4a00002, ExceptionLevel::El2, 0x3330),
            (0xd4a00003, ExceptionLevel::El3, 0x4440),
        ] {
            let ids = ids(true);
            let mut system = system(Arc::clone(&ids), true, 0);
            let mut thread = thread();
            machine!(ids, system, thread, Status::ResetCatch, |pe| {
                pe.queue_editr(0, word).unwrap();
                let outcome = pe.run_editr();
                assert!(matches!(
                    outcome.stop,
                    super::super::halted::DebugStop::Complete
                ));
                assert_eq!(outcome.actual_pc, PC);
                let resources = accept_retained_loan(pe.loan());
                assert!(resources.authority.halted());
                let debug = resources.debug.as_ref().unwrap();
                assert_eq!(debug.status(), Status::ResetCatch);
                assert_ne!(debug.edscr() & ITE, 0);
                assert_eq!(debug.dlr(), 0);
                assert_eq!(debug.dspsr(), 0);
            });
            assert_eq!(system.current_el(), el);
            assert_eq!(thread.registers.sp, sp);
            let bank = system.exception_registers(el).unwrap();
            assert_eq!((bank.elr(), bank.spsr(), bank.esr()), (0, 0, 0));
        }
    }
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn actual_drps_restores_saved_sp_without_branch_or_resume() {
        let ids = ids(false);
        let mut system = system(Arc::clone(&ids), false, PSTATE_EL1T | NZCV_MASK | DAIF_MASK);
        let mut thread = thread();
        machine!(ids, system, thread, Status::ResetCatch, |pe| {
            pe.queue_editr(0, 0xd6bf03e0).unwrap();
            let outcome = pe.run_editr();
            assert!(matches!(
                outcome.stop,
                super::super::halted::DebugStop::Complete
            ));
            assert_eq!(outcome.actual_pc, PC);
            let resources = accept_retained_loan(pe.loan());
            assert!(resources.authority.halted());
            assert!(!resources.authority.ready());
        });
        assert_eq!(system.pstate_misc(), PSTATE_EL1T);
        assert_eq!(thread.registers.nzcv, 0);
        assert_eq!(thread.registers.sp, 0x1110);
        assert_eq!(
            system.read_stack_pointer(StackBank::El1, &thread.registers),
            Ok(0x2220)
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn refused_debug_input_stays_queued_and_dropped_active_poison_stays_terminal() {
        let ids = ids(false);
        let mut system = system(Arc::clone(&ids), false, 0);
        let mut thread = thread();
        machine!(ids, system, thread, Status::ResetCatch, |pe| {
            pe.queue_editr(0, 0xd4a00002).unwrap(); // No original EL2 bank, so no fake DCPS2 success.
            let refused = pe.run_editr();
            assert!(matches!(
                refused.stop,
                super::super::halted::DebugStop::EntryDeclined(_)
            ));
            {
                let mut resources = accept_retained_loan(pe.loan());
                assert!(resources.backend.producers.next_editr().unwrap().is_some());
                assert!(resources.authority.halted());
                let outer = resources.backend.memory.execution_loan().unwrap();
                let attempt = resources
                    .authority
                    .begin_debug(&super::super::ConsumerKey(()))
                    .unwrap();
                let active = super::super::Active {
                    pe: &mut resources,
                    outer: Some(outer),
                    source_pin: None,
                    attempt,
                    closed: false,
                };
                drop(active);
                assert!(!resources.authority.halted());
                assert!(!resources.authority.ready());
            }
            assert!(matches!(
                pe.run_editr().stop,
                super::super::halted::DebugStop::EntryDeclined(_)
            ));
            assert_eq!(pe.pc(), PC);
        });
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn actual_halted_movt_480_literal_model_outputs_and_full_bank_preservation() {
        use crate::{
            scalable::ScalableState,
            system::scalable_controls::{Implementation, Readbacks, ScalableControlOwner},
        };
        use stela_compiler::{
            aarch64::scalable::{
                ScalableMode, VectorLength,
                features::{ScalableFeature, ScalableFeatures},
                profile::ScalableControls,
            },
            context::{ExecutionContext, memory::MemoryImplementationProfile},
            extended::ScalableProfile,
        };
        fn hex(value: &str) -> Vec<u8> {
            value
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
                .collect()
        }
        fn banks(state: &ScalableState, registers: &GuestState, sm: bool) -> Vec<u8> {
            let mut out = Vec::new();
            let mut za = vec![0; state.vector_length().bytes().pow(2)];
            state.read_za(0, &mut za).unwrap();
            out.extend(za);
            if sm {
                for r in 0..32 {
                    let mut z = vec![0; state.vector_length().bytes()];
                    state.read_z(registers, r, &mut z).unwrap();
                    out.extend(z);
                }
                for r in 0..16 {
                    let mut p = vec![0; state.vector_length().predicate_bytes()];
                    state.read_predicate(r, &mut p).unwrap();
                    out.extend(p);
                }
                let mut ffr = vec![0; state.vector_length().predicate_bytes()];
                state.read_ffr(&mut ffr).unwrap();
                out.extend(ffr);
            }
            out.extend(state.tpidr2_el0().to_le_bytes());
            out.extend(state.fpmr().to_le_bytes());
            out
        }
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/movement_model.json"
        )))
        .unwrap();
        let before = &fixture["before"];
        let lengths: Vec<_> = [16, 32, 64, 128, 256]
            .into_iter()
            .map(|b| VectorLength::from_bytes(b).unwrap())
            .collect();
        let mut comparisons = 0;
        for length in &lengths {
            for sm in [false, true] {
                for case in fixture["cases"].as_array().unwrap() {
                    let ids = Arc::new(
                        Snapshot::declared(
                            "actual-halted-movt-independent-model-probe",
                            &[
                                (Register::IdAa64Pfr0El1, 0x11),
                                (Register::IdAa64Pfr1El1, 2 << 24),
                                (Register::IdAa64Pfr2El1, 0),
                                (Register::IdAa64Smfr0El1, 1 << 56),
                                (Register::IdAa64Zfr0El1, 0),
                                (Register::IdAa64Isar3El1, 0),
                                (Register::IdAa64Dfr0El1, 9),
                                (Register::IdAa64Dfr1El1, 0),
                                (Register::IdAa64Mmfr0El1, 0),
                                (Register::IdAa64Mmfr1El1, 0),
                                (Register::IdAa64Mmfr2El1, 0),
                                (Register::IdAa64Mmfr3El1, 0),
                                (Register::IdAa64Mmfr4El1, 0),
                                (Register::IdAa64Isar1El1, 0),
                                (Register::IdAa64Isar2El1, 0),
                            ],
                        )
                        .unwrap(),
                    );
                    let controls = ScalableControlOwner::new_declared_el10(
                        &ids,
                        Readbacks {
                            cpacr_el1: (3 << 20) | (3 << 24),
                            smcr_el1: ((length.bytes() / 16 - 1) as u64) | (1 << 30),
                        },
                        Implementation::declared(
                            &lengths,
                            MemoryImplementationProfile::ScalableTagChecks,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    let mut system = system(Arc::clone(&ids), false, 0);
                    let mut thread = thread();
                    for (x, v) in thread
                        .registers
                        .x
                        .iter_mut()
                        .zip(before["x"].as_array().unwrap())
                    {
                        *x = v.as_u64().unwrap();
                    }
                    thread.registers.sp = before["sp"].as_u64().unwrap();
                    thread.registers.nzcv =
                        u32::try_from(before["nzcv"].as_u64().unwrap()).unwrap();
                    thread.registers.fpcr =
                        u32::try_from(before["fpcr"].as_u64().unwrap()).unwrap();
                    thread.registers.fpsr =
                        u32::try_from(before["fpsr"].as_u64().unwrap()).unwrap();
                    let mut scalable = ScalableState::new(*length, true);
                    scalable
                        .apply_mode(&mut thread.registers, ScalableMode::new(sm, true))
                        .unwrap();
                    let za: Vec<_> = (0..length.bytes().pow(2))
                        .map(|i| (i.wrapping_mul(37) + 11) as u8)
                        .collect();
                    scalable.write_za(0, &za).unwrap();
                    scalable
                        .write_zt0(0, &hex(before["zt0"].as_str().unwrap()))
                        .unwrap();
                    if sm {
                        for reg in 0..32 {
                            let z: Vec<_> = (0..length.bytes())
                                .map(|i| (i * 17 + usize::from(reg) * 29 + 7) as u8)
                                .collect();
                            scalable.write_z(&mut thread.registers, reg, &z).unwrap();
                        }
                        for reg in 0..16 {
                            let p: Vec<_> = (0..length.predicate_bytes())
                                .map(|i| (i * 3 + usize::from(reg) * 11 + 5) as u8)
                                .collect();
                            scalable.write_predicate(reg, &p).unwrap();
                        }
                        scalable
                            .write_ffr(&vec![0x5a; length.predicate_bytes()])
                            .unwrap();
                    }
                    let expected_banks = banks(&scalable, &thread.registers, sm);
                    let mut expected_registers = thread.registers.clone();
                    for change in case["x_changes"].as_array().unwrap() {
                        expected_registers.x[change[0].as_u64().unwrap() as usize] =
                            change[1].as_u64().unwrap();
                    }
                    let mut context = ExecutionContext::default();
                    let profile = ScalableProfile::new_with_features(
                        *length,
                        ScalableMode::new(sm, true),
                        ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2),
                        ScalableControls::new(lengths[4], true),
                    )
                    .unwrap();
                    let (domain, mut memory) = memory();
                    let mut producers = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
                    let keys = [producers.register_debug().unwrap()];
                    let lease = producers.lease_debug_sources(&keys).unwrap();
                    let mut backend = unsafe {
                        PrivilegedOwner::fresh_software(
                            7,
                            LowerElControls {
                                snapshot: Arc::clone(&ids),
                                sctlr_el1: 0,
                                tcr_el1: 0,
                                call_implementation: higher_el::Implementation {
                                    without_el3_security:
                                        higher_el::WithoutEl3Security::NonSecureOnly,
                                    trap_smc_without_el3: higher_el::TrapSmcWithoutEl3::Enabled,
                                },
                            },
                            &mut memory,
                            domain,
                            lease,
                            CtiRoute {
                                output_slot: 0,
                                target_slots: vec![],
                            },
                            Some(super::super::privileged_debug::DebugScalable {
                                controls: &controls,
                                state: &mut scalable,
                                context: &mut context,
                                specialization: profile,
                            }),
                        )
                        .unwrap()
                    };
                    {
                        let mut pe = unsafe {
                            SystemExecutionOwner::new_pe_with_debug(
                                &mut thread,
                                &mut system,
                                &mut backend,
                                debug(Arc::clone(&ids), Status::ResetCatch),
                            )
                            .unwrap()
                        };
                        pe.queue_editr(
                            0,
                            u32::from_str_radix(case["word"].as_str().unwrap(), 16).unwrap(),
                        )
                        .unwrap();
                        let outcome = pe.run_editr();
                        assert!(
                            matches!(outcome.stop, super::super::halted::DebugStop::Complete),
                            "{outcome:?}"
                        );
                        assert_eq!(outcome.actual_pc, PC);
                        let record = outcome.record.unwrap();
                        assert!(
                            record.native_invoked
                                && record.native_returned
                                && record.native_finalized
                        );
                        let resources = accept_retained_loan(pe.loan());
                        assert!(resources.authority.halted());
                        assert!(!resources.authority.ready());
                    }
                    drop(backend);
                    assert_eq!(thread.registers, expected_registers);
                    assert_eq!(banks(&scalable, &thread.registers, sm), expected_banks);
                    let mut actual_zt0 = [0; 64];
                    scalable.read_zt0(0, &mut actual_zt0).unwrap();
                    assert_eq!(actual_zt0.as_slice(), hex(case["zt0"].as_str().unwrap()));
                    assert!(
                        context.memory.is_null()
                            && context.scalable.is_null()
                            && context.system.is_null()
                    );
                    assert!(context.has_supported_header());
                    comparisons += 1;
                }
            }
        }
        assert_eq!(comparisons, 480);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn raw_editr_err_ignores_unallocated_word_before_decode() {
        let ids = ids(false);
        let mut system = system(Arc::clone(&ids), false, 0);
        let mut thread = thread();
        let before = thread.registers.clone();
        machine!(ids, system, thread, Status::ResetCatch, |pe| {
            {
                let resources = accept_retained_loan(pe.loan());
                resources.debug.as_mut().unwrap().set_overrun();
            }
            pe.queue_editr(0, u32::MAX).unwrap();
            let outcome = pe.run_editr();
            assert!(matches!(
                outcome.stop,
                super::super::halted::DebugStop::Complete
            ));
            assert_eq!(
                outcome.record.unwrap().disposition,
                crate::system::debug::halted::EditrDisposition::Ignored
            );
            assert_eq!(pe.pc(), PC);
            assert_eq!(pe.registers(), &before);
        });
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn absent_actual_exception_target_refuses_before_native_or_source_effects() {
        let ids = ids(true);
        let mut system = system(Arc::clone(&ids), true, 0);
        let mut thread = thread();
        let before = thread.registers.clone();
        let original_system = system.clone();
        let cache = tempfile::tempdir().unwrap();
        let mut runtime = crate::blocks::BlockRuntime::new_for_target(
            7,
            cache.path().to_owned(),
            BlockProfile::SystemV1,
            TargetCpu::Baseline,
        );
        runtime
            .register_code(PC, 0xd4000002u32.to_le_bytes().to_vec())
            .unwrap();
        machine!(ids, system, thread, Status::NonDebug, |pe| {
            let outcome = runtime.run_owned(
                pe.loan(),
                OwnedRunRequest {
                    stop_pc: None,
                    block_budget: 1,
                },
            );
            assert!(matches!(outcome.stop, OwnedStop::EntryDeclined(_)));
            assert!(outcome.last_native_observation.is_none());
            assert_eq!(outcome.accounting.blocks_executed, 0);
            assert_eq!(pe.pc(), PC);
            assert_eq!(pe.registers(), &before);
        });
        assert_eq!(system, original_system);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn actual_fresh_factory_hvc_hlt_dcps_lifetime() {
        use super::super::software_privileged::*;
        let ids = ids(true);
        let initial_system = system(Arc::clone(&ids), true, 0);
        // Initialization values only.
        let initial_debug = DebugInitialization {
            edscr: Status::NonDebug as u32 | ITE | HDE,
            edprsr: 0,
            dlr: 0x7770,
            dspsr: 0x8880,
            edesr: 0,
            edecr: 0,
            mdscr_el1: 0,
            should_advance_ss: true,
            should_advance_hs: true,
            external: ExternalControls {
                powered: true,
                double_locked: false,
                software_locked: false,
                nonsecure_invasive: true,
                secure_invasive: true,
            },
            extended_halt_syndrome: ExtendedHaltSyndrome::DeclaredAbsent,
        };
        let cache = tempfile::tempdir().unwrap();
        let config = DeclaredPrivilegedConfig {
            identification: [
                Register::IdAa64Pfr0El1,
                Register::IdAa64Pfr1El1,
                Register::IdAa64Pfr2El1,
                Register::IdAa64Dfr0El1,
                Register::IdAa64Dfr1El1,
                Register::IdAa64Mmfr0El1,
                Register::IdAa64Mmfr1El1,
                Register::IdAa64Mmfr2El1,
                Register::IdAa64Mmfr4El1,
                Register::IdAa64Isar1El1,
                Register::IdAa64Isar2El1,
            ]
            .into_iter()
            .map(|register| (register, ids.read(register).unwrap()))
            .collect(),
            thread: thread(),
            pstate_misc: PSTATE_EL1H,
            inactive_stack_pointer: 0x1110,
            el1: *initial_system
                .exception_registers(ExceptionLevel::El1)
                .unwrap(),
            higher: Some(Initialization {
                el2: Some(El2Initialization {
                    exception: El1Registers::new(21, 22, 23, 24, 0x8000),
                    stack_pointer: 0x3330,
                    hcr: 0,
                    sctlr: 0,
                    tcr: 0,
                    hpfar: 26,
                }),
                el3: Some(El3Initialization {
                    exception: El1Registers::new(31, 32, 33, 34, 0xa000),
                    stack_pointer: 0x4440,
                    scr: SCR_NS | SCR_HCE,
                    sctlr: 0,
                    tcr: 0,
                }),
            }),
            sctlr_el1: 0,
            tcr_el1: 0,
            debug: initial_debug,
            scalable: None,
            trap_smc_without_el3: TrapSmcWithoutEl3::Enabled,
            address_space: 7,
            cache_directory: cache.path().into(),
            code: vec![
                DeclaredPrivilegedCode {
                    base: PC,
                    bytes: 0xd4000002u32.to_le_bytes().to_vec(),
                },
                DeclaredPrivilegedCode {
                    base: GuestAddress(0x8400),
                    bytes: 0xd4400000u32.to_le_bytes().to_vec(),
                },
            ],
            debug_producer_count: 1,
            cti_output_slot: 0,
            cti_target_slots: vec![],
        };
        let report = run_declared_privileged(
            config,
            vec![
                DeclaredPrivilegedRequest::Run {
                    stop_pc: Some(GuestAddress(0x8400)),
                    block_budget: 1,
                },
                DeclaredPrivilegedRequest::Run {
                    stop_pc: None,
                    block_budget: 1,
                },
                DeclaredPrivilegedRequest::Editr {
                    route_slot: 0,
                    word: 0xd4a00001,
                },
            ],
        )
        .unwrap();
        assert_eq!(report.receipts.len(), 3);
        assert_eq!(report.thread.pc, GuestAddress(0x8400));
        assert!(report.receipts[0].stop.contains("StopAddress"));
        assert!(report.receipts[1].stop.contains("Halted"));
        assert_eq!(report.receipts[2].stop, "Complete");
        // DCPS1 retains a higher source EL; this lifetime already entered EL2.
        assert_eq!(report.system.current_el(), ExceptionLevel::El2);
        assert_eq!(report.thread.registers.sp, 0x3330);
        let actual_el2 = report
            .system
            .exception_registers(ExceptionLevel::El2)
            .unwrap();
        assert_eq!(
            (actual_el2.elr(), actual_el2.spsr(), actual_el2.esr()),
            (0, 0, 0)
        );
        assert!(report.receipts[2].lifecycle.contains("phase: Halted"));
        assert!(
            report
                .asynchronous
                .contains("cross_halt_outputs=[(1, 1, [])]")
        );
        assert!(report.receipts[0].source_receipts[0].contains("source_sha256"));
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn actual_fresh_factory_sme2_movt_owns_original_storage() {
        use super::super::software_privileged::*;
        use crate::scalable::ScalableState;
        use crate::system::scalable_controls::Readbacks;
        use stela_compiler::aarch64::scalable::{
            ScalableMode, VectorLength,
            features::{ScalableFeature, ScalableFeatures},
            profile::ScalableControls,
        };
        use stela_compiler::extended::ScalableProfile;
        let length = VectorLength::from_bytes(16).unwrap();
        let mut original_thread = thread();
        let mut original_scalable = ScalableState::new(length, true);
        original_scalable
            .apply_mode(
                &mut original_thread.registers,
                ScalableMode::new(false, true),
            )
            .unwrap();
        let zt0: Vec<_> = (0..64u8)
            .map(|i| i.wrapping_mul(19).wrapping_add(3))
            .collect();
        original_scalable.write_zt0(0, &zt0).unwrap();
        let expected_x0 = u64::from_le_bytes(zt0[..8].try_into().unwrap());
        let initial_debug = DebugInitialization {
            edscr: Status::ResetCatch as u32 | ITE | HDE,
            edprsr: 1 << 4,
            dlr: 0x7770,
            dspsr: 0x8880,
            edesr: 0,
            edecr: 0,
            mdscr_el1: 0,
            should_advance_ss: true,
            should_advance_hs: true,
            external: ExternalControls {
                powered: true,
                double_locked: false,
                software_locked: false,
                nonsecure_invasive: true,
                secure_invasive: true,
            },
            extended_halt_syndrome: ExtendedHaltSyndrome::DeclaredAbsent,
        };
        let cache = tempfile::tempdir().unwrap();
        let report = run_declared_privileged(
            DeclaredPrivilegedConfig {
                identification: vec![
                    (Register::IdAa64Pfr0El1, 0x11),
                    (Register::IdAa64Pfr1El1, 2 << 24),
                    (Register::IdAa64Pfr2El1, 0),
                    (Register::IdAa64Smfr0El1, 1 << 56),
                    (Register::IdAa64Zfr0El1, 0),
                    (Register::IdAa64Isar3El1, 0),
                    (Register::IdAa64Dfr0El1, 9),
                    (Register::IdAa64Dfr1El1, 0),
                    (Register::IdAa64Mmfr0El1, 0),
                    (Register::IdAa64Mmfr1El1, 0),
                    (Register::IdAa64Mmfr2El1, 0),
                    (Register::IdAa64Mmfr3El1, 0),
                    (Register::IdAa64Mmfr4El1, 0),
                    (Register::IdAa64Isar1El1, 0),
                    (Register::IdAa64Isar2El1, 0),
                ],
                thread: original_thread,
                pstate_misc: PSTATE_EL1H,
                inactive_stack_pointer: 0x1110,
                el1: El1Registers::new(1, 2, 3, 4, 0x6000),
                higher: None,
                sctlr_el1: 0,
                tcr_el1: 0,
                debug: initial_debug,
                scalable: Some(DeclaredPrivilegedScalable {
                    state: original_scalable,
                    readbacks: Readbacks {
                        cpacr_el1: (3 << 20) | (3 << 24),
                        smcr_el1: 1 << 30,
                    },
                    supported_lengths: vec![length],
                    specialization: ScalableProfile::new_with_features(
                        length,
                        ScalableMode::new(false, true),
                        ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2),
                        ScalableControls::new(length, true),
                    )
                    .unwrap(),
                }),
                trap_smc_without_el3: TrapSmcWithoutEl3::Enabled,
                address_space: 7,
                cache_directory: cache.path().into(),
                code: vec![],
                debug_producer_count: 1,
                cti_output_slot: 0,
                cti_target_slots: vec![],
            },
            vec![DeclaredPrivilegedRequest::Editr {
                route_slot: 0,
                word: 0xc04c03e0,
            }],
        )
        .unwrap();
        assert_eq!(report.thread.registers.x[0], expected_x0);
        assert_eq!(report.thread.pc, PC);
        assert_eq!(report.receipts[0].stop, "Complete");
        assert!(
            report.receipts[0]
                .debug_record
                .as_ref()
                .unwrap()
                .contains("native_finalized: true")
        );
        let mut actual_zt0 = [0; 64];
        report
            .scalable
            .unwrap()
            .read_zt0(0, &mut actual_zt0)
            .unwrap();
        assert_eq!(actual_zt0.as_slice(), zt0);
    }
}
