//! Halted-debug instruction bodies for the privileged PE.
use super::super::software_async::EditrSource;
use super::privileged::PrivilegedOwner;
use crate::{
    execution::{context::ContextLoan, platform::Mapping},
    scalable::ScalableState,
    system::{
        debug::{
            drps,
            halted::{DebugMachine, EditrDisposition},
            halting,
        },
        scalable_controls::ScalableControlOwner,
        state::SystemState,
    },
};
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, string::String, vec::Vec};
use stela_compiler::{
    GuestState,
    context::ExecutionContext,
    extended::{
        ScalableProfile,
        debug_movement::{self, PreparedDebugMovement, Recipe},
    },
};

/// Original scalable controls, backing and context, borrowed once by the same
/// concrete PE producer. None is unavailable; it is never a feature-absence fact.
pub(super) struct DebugScalable<'pe> {
    pub controls: &'pe ScalableControlOwner<'pe>,
    pub state: &'pe mut ScalableState,
    pub context: &'pe mut ExecutionContext,
    pub specialization: ScalableProfile,
}

pub(super) enum Body {
    Dcps(Vec<halting::Step>),
    Drps(drps::Plan),
    Movement {
        prepared: PreparedDebugMovement,
        mapping: Mapping,
    },
}
pub(super) struct PreparedDebug {
    pub source: EditrSource,
    pub disposition: EditrDisposition,
    pub body: Option<Body>,
    pub record: DebugRecord,
}
#[derive(Debug)]
pub(crate) struct DebugRecord {
    pub source: u64,
    pub sequence: u64,
    pub word: u32,
    pub disposition: EditrDisposition,
    pub last_effect: &'static str,
    pub native_invoked: bool,
    pub native_returned: bool,
    pub native_finalized: bool,
    pub compiler_source_sha256: Option<String>,
    pub native_sha256: Option<String>,
    pub word_to_native: Option<[(usize, usize); 1]>,
}

impl PrivilegedOwner<'_> {
    pub(super) fn prepare_debug(
        &mut self,
        system: &SystemState,
        registers: &mut GuestState,
        debug: &DebugMachine,
        outer: &crate::memory::domain::MemoryExecutionLoan,
    ) -> anyhow::Result<Option<PreparedDebug>> {
        self.qualify_debug_resources(system, debug, outer)?;
        debug
            .qualify_halted_boundary()
            .map_err(|e| anyhow::anyhow!("halted boundary: {e:?}"))?;
        let Some(source) = self
            .producers
            .next_editr()
            .map_err(|e| anyhow::anyhow!("queued EDITR: {e:?}"))?
        else {
            return Ok(None);
        };
        let disposition = debug.editr_disposition();
        let mut record = DebugRecord {
            source: source.source(),
            sequence: source.sequence(),
            word: source.word(),
            disposition,
            last_effect: "none",
            native_invoked: false,
            native_returned: false,
            native_finalized: false,
            compiler_source_sha256: None,
            native_sha256: None,
            word_to_native: None,
        };
        // Raw ERR/not-Halted/ITE/MA priority precedes decoding ignored input.
        let body = if disposition != EditrDisposition::Execute {
            None
        } else if let Some(instruction) = halting::Instruction::prepare(source.word()) {
            let context = self.halting_context(system, debug);
            // DCPS's MaybeZeroSVEUppers has no effect only when the ID
            // registers show SVE and SME absent.
            self.lower
                .snapshot
                .base_entry_effect_profile()
                .map_err(|e| anyhow::anyhow!("DCPS optional state: {e:?}"))?;
            let halting::Preparation::Plan(plan) =
                halting::prepare(instruction, context, debug.status(), debug.edscr())
                    .map_err(|e| anyhow::anyhow!("DCPS source preparation: {e:?}"))?
            else {
                anyhow::bail!("debug Undefined owner unavailable");
            };
            anyhow::ensure!(
                plan.word() == source.word(),
                "DCPS plan/source association differs"
            );
            let steps = plan.steps();
            anyhow::ensure!(
                steps.iter().all(|step| matches!(
                    step,
                    halting::Step::SynchronizeContext
                        | halting::Step::MaybeZeroSveUppers { .. }
                        | halting::Step::SelectHandlerPstate { .. }
                        | halting::Step::WriteHandlerArbitrary { .. }
                        | halting::Step::WriteDlrDspsrArbitrary
                        | halting::Step::SetDcpsOptionalPstate
                        | halting::Step::UpdateEdscrFields
                        | halting::Step::CompleteHaltedInjection
                )),
                "debug Undefined/HLT injection requires its original exception owner"
            );
            Some(Body::Dcps(steps))
        } else if stela_compiler::aarch64::system::exception::decode(source.word())
            == Some(stela_compiler::aarch64::system::exception::Operation::DebugReturn)
        {
            self.lower
                .snapshot
                .check_el10_regime()
                .map_err(|e| anyhow::anyhow!("DRPS EL regime: {e:?}"))?;
            self.lower
                .snapshot
                .base_entry_effect_profile()
                .map_err(|e| anyhow::anyhow!("DRPS optional state: {e:?}"))?;
            let saved = system
                .exception_registers(system.current_el())
                .map_err(|e| anyhow::anyhow!("SPSR: {e:?}"))?
                .spsr();
            let drps::Preparation::Plan(plan) =
                drps::prepare(source.word(), debug.status(), system.current_el(), saved)
                    .map_err(|e| anyhow::anyhow!("DRPS state: {e:?}"))?
            else {
                anyhow::bail!("DRPS debug Undefined owner unavailable");
            };
            Some(Body::Drps(plan))
        } else {
            let scalable = self
                .scalable
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("scalable owner unavailable"))?;
            anyhow::ensure!(
                self.lower
                    .snapshot
                    .same_snapshot(scalable.controls.identification_snapshot()),
                "scalable/control Snapshot differs"
            );
            anyhow::ensure!(
                scalable.context.has_supported_header(),
                "scalable context header"
            );
            let prepared =
                debug_movement::prepare(source.word(), scalable.specialization, Recipe::Scalar)?;
            scalable
                .controls
                .with_checked_execution(
                    prepared.execution_requirements(),
                    prepared.profile(),
                    system,
                    registers,
                    scalable.state,
                    |_, _, _| (),
                )
                .map_err(|e| anyhow::anyhow!("MOVT access before EDITR consumption: {e:?}"))?;
            // W^X mapping and all metadata allocation precede source consumption,
            // ITE clear and first architectural instruction effect.
            let mapping = Mapping::new(prepared.code())?;
            record.compiler_source_sha256 = Some(crate::compiler_source_sha256().to_owned());
            record.native_sha256 = Some(stela_core::sha256(prepared.code()));
            record.word_to_native = Some(*prepared.word_to_native());
            Some(Body::Movement { prepared, mapping })
        };
        Ok(Some(PreparedDebug {
            source,
            disposition,
            body,
            record,
        }))
    }
    pub(super) fn execute_debug(
        &mut self,
        prepared: &mut PreparedDebug,
        system: &mut SystemState,
        registers: &mut GuestState,
        debug: &mut DebugMachine,
        outer: &crate::memory::domain::MemoryExecutionLoan,
    ) -> anyhow::Result<()> {
        self.qualify_debug_resources(system, debug, outer)?;
        anyhow::ensure!(
            debug.editr_disposition() == prepared.disposition,
            "EDITR disposition changed"
        );
        if let Some(Body::Drps(plan)) = &prepared.body {
            anyhow::ensure!(
                plan.word() == prepared.source.word(),
                "DRPS plan/source association changed"
            );
        }
        self.producers
            .consume_editr(&prepared.source)
            .map_err(|e| anyhow::anyhow!("EDITR source: {e:?}"))?;
        prepared.record.last_effect = "EDITR consumed";
        match prepared.disposition {
            EditrDisposition::Ignored => return Ok(()),
            EditrDisposition::Overrun => {
                debug.set_overrun();
                prepared.record.last_effect = "ERR/ITO written";
                return Ok(());
            }
            EditrDisposition::Execute => {}
        }
        debug
            .begin_itr()
            .map_err(|e| anyhow::anyhow!("ITR begin: {e:?}"))?;
        prepared.record.last_effect = "ITE cleared";
        match prepared
            .body
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("prepared debug body absent"))?
        {
            Body::Dcps(steps) => {
                for step in steps {
                    match *step {
                        halting::Step::SynchronizeContext => {
                            super::super::super::serialize_instruction_execution()?
                        }
                        halting::Step::MaybeZeroSveUppers { .. } => {
                            // Actual immutable absence established before consuming
                            // input; no SVE/SME bank exists in this DCPS profile.
                            self.lower
                                .snapshot
                                .base_entry_effect_profile()
                                .map_err(|e| anyhow::anyhow!("absent uppers: {e:?}"))?;
                        }
                        halting::Step::SelectHandlerPstate { handler } => {
                            let context = self.halting_context(system, debug);
                            system
                                .transition_pstate(
                                    registers,
                                    halting::dcps_pstate(
                                        system.pstate(registers),
                                        handler,
                                        context,
                                    ),
                                )
                                .map_err(|e| anyhow::anyhow!("DCPS handler/SP: {e:?}"))?;
                        }
                        halting::Step::WriteHandlerArbitrary { handler } => {
                            let bank = system
                                .exception_registers_mut(handler)
                                .map_err(|e| anyhow::anyhow!("DCPS bank: {e:?}"))?;
                            bank.set_elr(halting::ARBITRARY_REGISTER_ZERO);
                            bank.set_spsr(halting::ARBITRARY_REGISTER_ZERO);
                            bank.set_esr(halting::ARBITRARY_REGISTER_ZERO);
                        }
                        halting::Step::WriteDlrDspsrArbitrary => debug.write_debug_arbitrary(),
                        halting::Step::SetDcpsOptionalPstate => {
                            system
                                .transition_pstate(
                                    registers,
                                    halting::dcps_optional_pstate(
                                        system.pstate(registers),
                                        debug.halting_features(),
                                    ),
                                )
                                .map_err(|e| anyhow::anyhow!("DCPS optional state: {e:?}"))?;
                        }
                        halting::Step::UpdateEdscrFields => {
                            self.update_debug_fields(system, debug)?
                        }
                        halting::Step::CompleteHaltedInjection => { /* canonical completion below */
                        }
                        _ => anyhow::bail!("unprepared debug step"),
                    }
                    prepared.record.last_effect = match step {
                        halting::Step::SynchronizeContext => "context synchronized",
                        halting::Step::SelectHandlerPstate { .. } => "handler PSTATE/SP written",
                        halting::Step::WriteHandlerArbitrary { .. } => {
                            "handler ELR/SPSR/ESR written"
                        }
                        halting::Step::WriteDlrDspsrArbitrary => "DLR/DSPSR written",
                        halting::Step::SetDcpsOptionalPstate => "optional PSTATE written",
                        halting::Step::UpdateEdscrFields => "EDSCR fields written",
                        _ => prepared.record.last_effect,
                    };
                }
            }
            Body::Drps(plan) => {
                for step in plan.steps() {
                    match step {
                        drps::Step::SynchronizeContext => {
                            super::super::super::serialize_instruction_execution()?;
                            prepared.record.last_effect = "context synchronized";
                        }
                        drps::Step::RestoreActualSavedPstate => {
                            // Actual SPSR is read at its source step after sync;
                            // the unapplied plan's earlier diagnostic is not restored.
                            let saved = system
                                .exception_registers(system.current_el())
                                .map_err(|e| anyhow::anyhow!("synchronized SPSR: {e:?}"))?
                                .spsr();
                            system
                                .transition_pstate(registers, saved)
                                .map_err(|e| anyhow::anyhow!("DRPS restored SP/PSTATE: {e:?}"))?;
                            prepared.record.last_effect = "SPSR restored";
                        }
                        drps::Step::ClearShouldAdvanceSs => {
                            debug.clear_should_advance_ss();
                            prepared.record.last_effect = "ShouldAdvanceSS cleared";
                        }
                        drps::Step::WriteArbitraryPstate => {
                            system
                                .transition_pstate(
                                    registers,
                                    drps::arbitrary_pstate(system.pstate(registers)),
                                )
                                .map_err(|e| anyhow::anyhow!("DRPS arbitrary PSTATE: {e:?}"))?;
                            prepared.record.last_effect = "DRPS arbitrary PSTATE written";
                        }
                        drps::Step::WriteDlrDspsrArbitrary => {
                            debug.write_debug_arbitrary();
                            prepared.record.last_effect = "DRPS arbitrary fields written";
                        }
                        drps::Step::UpdateEdscrFields => {
                            self.update_debug_fields(system, debug)?;
                            prepared.record.last_effect = "EDSCR fields written";
                        }
                        drps::Step::CompleteHaltedInjection => { /* canonical completion below */ }
                    }
                }
            }
            Body::Movement {
                prepared: movement,
                mapping,
            } => {
                let scalable = self
                    .scalable
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("scalable resource lost"))?;
                anyhow::ensure!(
                    movement.word() == prepared.source.word()
                        && prepared
                            .record
                            .compiler_source_sha256
                            .as_deref()
                            .is_some_and(|actual| actual == crate::compiler_source_sha256())
                        && prepared.record.native_sha256.as_deref()
                            == Some(stela_core::sha256(movement.code()).as_str()),
                    "native capsule association changed"
                );
                let context = &mut *scalable.context;
                let original_memory = context.memory;
                let original_scalable = context.scalable;
                let original_system = context.system;
                let original_header = (context.version, context.bytes);
                let result = scalable
                    .controls
                    .with_checked_execution(
                        movement.execution_requirements(),
                        movement.profile(),
                        system,
                        registers,
                        scalable.state,
                        |_, registers, state| unsafe {
                            state.with_view(|view| {
                                let original = (
                                    view.svl_bytes,
                                    view.reserved,
                                    view.svcr,
                                    view.tpidr2_el0,
                                    view.fpmr,
                                    view.z_upper,
                                    view.predicates,
                                    view.ffr,
                                    view.za,
                                    view.zt0,
                                );
                                let mut loan = ContextLoan::scalable(context, view);
                                prepared.record.native_invoked = true;
                                let result = mapping.call_context(registers, loan.context());
                                prepared.record.native_returned = result.is_ok();
                                drop(loan);
                                result?;
                                anyhow::ensure!(
                                    original
                                        == (
                                            view.svl_bytes,
                                            view.reserved,
                                            view.svcr,
                                            view.tpidr2_el0,
                                            view.fpmr,
                                            view.z_upper,
                                            view.predicates,
                                            view.ffr,
                                            view.za,
                                            view.zt0
                                        ),
                                    "MOVT scalable view finalization failed"
                                );
                                Ok::<(), anyhow::Error>(())
                            })
                        },
                    )
                    .map_err(|e| anyhow::anyhow!("MOVT requalification: {e:?}"))?;
                prepared.record.last_effect = if result.is_ok() {
                    "MOVT native returned"
                } else {
                    "MOVT native/view finalization failed"
                };
                result?;
                // The context borrow restored the original pointers; a
                // finalization failure keeps the register effects and marks the
                // PE failed.
                anyhow::ensure!(
                    context.memory == original_memory
                        && context.scalable == original_scalable
                        && context.system == original_system
                        && (context.version, context.bytes) == original_header
                        && context.has_supported_header(),
                    "MOVT context finalization failed"
                );
                prepared.record.native_finalized = true;
            }
        }
        debug
            .complete_itr()
            .map_err(|e| anyhow::anyhow!("ITR completion: {e:?}"))?;
        prepared.record.last_effect = "ITE restored";
        self.qualify_debug_resources(system, debug, outer)?;
        debug
            .qualify_halted_boundary()
            .map_err(|e| anyhow::anyhow!("final halted gate: {e:?}"))?;
        Ok(())
    }
}
