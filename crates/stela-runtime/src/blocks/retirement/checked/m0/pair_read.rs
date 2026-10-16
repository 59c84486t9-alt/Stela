//! Canonical actual Active pair-read consumer. No alternate dispatcher/PE.
use super::super::source::{BoundSource, ReturnedTerminal};
use super::{
    Active, ConsumerKey, INSTRUCTION_BYTES, M0PairReadSourceInput, M0Step, PreparedM0Commit,
    RetainedM0Session, SettledPrefix, provider,
};
use crate::{
    blocks::RunOutcome,
    memory::domain::m0_read::{M0RamPairReadPlatformError, pair::M0ReadPairSource},
    system::translation_controls::m0_data::M0ControlError,
};
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, string::ToString, vec::Vec};
use stela_compiler::{GuestAddress, Lifter, aarch64::Decoder, block::ExitKind};
mod callback;
mod session;
use session::{M0PairReadNativeReport, M0PairReadSessionFailure, NativeM0PairReadSession};

pub(crate) enum M0PairReadObservation {
    SourceResourceFailure {
        source_pc: GuestAddress,
        source_word: u32,
        detail: String,
    },
    SourceControlFailure {
        source_pc: GuestAddress,
        source_word: u32,
        error: M0ControlError,
    },
    PreparationFailure {
        source_pc: GuestAddress,
        source_word: u32,
        error: M0RamPairReadPlatformError,
    },
    Native {
        source_pc: GuestAddress,
        source_word: u32,
        report: Box<M0PairReadNativeReport>,
        precommit_failure: Option<M0PairReadSessionFailure>,
        settlement_failure: Option<String>,
    },
}
impl M0PairReadObservation {
    fn retain_settlement_failure(observation: &mut Option<Self>, error: &anyhow::Error) {
        if let Some(Self::Native {
            settlement_failure, ..
        }) = observation
        {
            *settlement_failure = Some(error.to_string());
        }
    }
}

impl<B: provider::Owner> Active<'_, '_, B> {
    pub(in crate::blocks::retirement::checked) fn execute_m0_read64_pair(
        mut self,
        bound: &BoundSource<'_>,
        accounting: &mut RunOutcome,
        observation: &mut Option<M0PairReadObservation>,
        prefixes: &mut Vec<SettledPrefix>,
    ) -> anyhow::Result<M0Step> {
        *observation = None;
        self.require_native()?;
        let outer = self
            .outer
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("M0 outer loan absent"))?;
        bound.recheck()?;
        anyhow::ensure!(
            bound.source.len() == INSTRUCTION_BYTES,
            "M0 source extent differs"
        );
        anyhow::ensure!(
            self.pe.thread.pc == bound.entry.entry(),
            "M0 actual source PC differs"
        );
        let word = u32::from_le_bytes(bound.source.try_into()?);
        let instruction = Decoder
            .lift(bound.entry.entry(), word)
            .map_err(|reason| anyhow::anyhow!("M0 source decode: {reason:?}"))?;
        let stela_compiler::block::el1_platform::Intent::Read64Pair(descriptor) =
            bound.el1_platform_intent()?
        else {
            anyhow::bail!("actual EL1 source is not a canonical M0 pair read");
        };
        let source = M0ReadPairSource::from_source(&instruction, word)
            .map_err(|failure| anyhow::anyhow!("M0 pair read source shape: {failure:?}"))?;
        anyhow::ensure!(
            descriptor.source_pc() == instruction.pc
                && descriptor.requirements() == source.requirements(),
            "actual M0 pair read descriptor/requirements differ"
        );
        anyhow::ensure!(
            bound.memory_requirements()? == source.requirements(),
            "M0 requirements differ"
        );
        let intent = source.intent(&self.pe.thread.registers);
        // The whole-B loan is split ONCE. Never access B again while any of
        // these original field loans is live. Outer Active stays armed through
        // all opaque producer/session teardown, including after Ready.
        let result = {
            let provider::M0ExecutionResources {
                sources,
                platform,
                controls,
                memory,
                context,
                checks,
            } = match self.pe.backend.split_m0_resources() {
                Ok(resources) => resources,
                Err(error) => {
                    *observation = Some(M0PairReadObservation::SourceResourceFailure {
                        source_pc: intent.source_pc,
                        source_word: intent.source_word,
                        detail: error.to_string(),
                    });
                    return Ok(M0Step::SourceResourcesBlocked);
                }
            };
            checks.check(outer)?;
            let installed = sources.source_scope().map_err(anyhow::Error::msg)?;
            let platform = platform.ok_or_else(|| {
                anyhow::anyhow!("actual pair-read platform identification absent")
            })?;
            let input = M0PairReadSourceInput::new(
                &ConsumerKey(()),
                bound,
                &*self.pe.system,
                outer,
                memory,
                &installed,
                platform,
                &self.pe.thread.registers,
            )?;

            // Real source/control witness, stable BEFORE the RAM session borrows
            // it. All M0/EE0/current-source qualification precedes target read.
            let control = match controls.loan_m0_read8_pair(&input) {
                Ok(control) => control,
                Err(error) => {
                    *observation = Some(M0PairReadObservation::SourceControlFailure {
                        source_pc: intent.source_pc,
                        source_word: intent.source_word,
                        error,
                    });
                    return Ok(M0Step::SourceControlBlocked);
                }
            };
            let mut candidate = self.pe.thread.registers.clone();
            let session = match NativeM0PairReadSession::prepare(bound, outer, &control, context) {
                Ok(session) => session,
                Err(error) => {
                    *observation = Some(M0PairReadObservation::PreparationFailure {
                        source_pc: intent.source_pc,
                        source_word: intent.source_word,
                        error,
                    });
                    return Ok(M0Step::PreparationBlocked);
                }
            };
            // Own the NO-READ session under ORIGINAL authority BEFORE invoke.
            // Errors and panic poison before physical pin/order resources drop.
            let mut retained = RetainedM0Session {
                authority: &mut *self.pe.authority,
                session,
                closed: false,
            };
            let report = retained.session.invoke(&mut candidate);
            let exit = report.returned_exit();
            let valid_report = report.invoked
                && report.progress.attempted
                && report.progress.uncertain_member.is_none()
                && report.completed_bytes == intent.bytes()
                && report.callback_failure.is_none()
                && report.failure.is_none();
            *observation = Some(M0PairReadObservation::Native {
                source_pc: intent.source_pc,
                source_word: intent.source_word,
                report: Box::new(report),
                precommit_failure: None,
                settlement_failure: None,
            });
            if !valid_report {
                // The genuine report is already owned by output. Diagnostic
                // formatting may allocate or panic; it cannot erase the report.
                let detail = match observation.as_ref() {
                    Some(M0PairReadObservation::Native { report, .. }) => format!(
                        "M0 pair read native report incomplete: invoked={}; completed={}; callback={:?}; failure={:?}; carrier={:?}",
                        report.invoked,
                        report.completed_bytes,
                        report.callback_failure,
                        report.failure,
                        report.raw_carrier,
                    ),
                    _ => unreachable!("same invocation retained its native report"),
                };
                return Ok(M0Step::Indeterminate(detail));
            }
            let qualified = (|| -> anyhow::Result<_> {
                let exit = exit.ok_or_else(|| anyhow::anyhow!("M0 reached carrier absent"))?;
                anyhow::ensure!(
                    ExitKind::try_from(exit.kind) == Ok(ExitKind::Fallthrough),
                    "M0 carrier differs"
                );
                let ReturnedTerminal::Ordinary(next_pc) =
                    bound.validate_return(&exit, &candidate)?
                else {
                    anyhow::bail!("M0 helper/trap carrier is not admitted");
                };
                anyhow::ensure!(next_pc == intent.next_pc, "M0 continuation differs");
                anyhow::ensure!(
                    self.pe.thread.pc == bound.entry.entry(),
                    "M0 actual PC changed before settlement"
                );
                let mut permitted = self.pe.thread.registers.clone();
                let values = retained
                    .session
                    .completed_values()
                    .ok_or_else(|| anyhow::anyhow!("M0 actual pair results absent"))?;
                for (destination, value) in intent.destinations.into_iter().zip(values) {
                    match destination {
                        stela_compiler::aarch64::Register::X(index) => {
                            permitted.x[usize::from(index)] = value
                        }
                        stela_compiler::aarch64::Register::Zero => {}
                        _ => unreachable!("source validated GPR/ZR destination"),
                    }
                }
                if let Some((base, value)) = source.writeback(&self.pe.thread.registers) {
                    permitted.x[usize::from(base)] = value;
                }
                anyhow::ensure!(candidate == permitted, "M0 changed unrelated state");
                // Allocate diagnostics BEFORE infallible state/PC/Ready commit.
                let prefix = bound.prefix(None, intent.bytes())?;
                prefixes.try_reserve(1)?;
                Ok((next_pc, exit, prefix))
            })();
            let (next_pc, exit, prefix) = match qualified {
                Ok(value) => value,
                Err(error) => {
                    M0PairReadObservation::retain_settlement_failure(observation, &error);
                    return Err(error);
                }
            };
            if let Err(failure) = retained.session.precommit() {
                // Move the actual typed error into retained output BEFORE any
                // fallible diagnostic formatting, without Clone or conversion.
                let detail = match observation {
                    Some(M0PairReadObservation::Native {
                        precommit_failure, ..
                    }) => {
                        *precommit_failure = Some(failure);
                        format!("M0 actual session precommit: {precommit_failure:?}")
                    }
                    _ => unreachable!("same invocation retained its native report"),
                };
                return Err(anyhow::anyhow!(detail));
            }
            let checked = (|| -> anyhow::Result<()> {
                checks.check(outer)?;
                bound.recheck()?;
                retained.require_native(self.attempt)
            })();
            if let Err(error) = checked {
                M0PairReadObservation::retain_settlement_failure(observation, &error);
                return Err(error);
            }
            // Mint the borrowed authority token directly, never return it from
            // a closure that also captures the retained mutable authority loan.
            let authority = match retained
                .authority
                .prepare_native_commit(&ConsumerKey(()), self.attempt)
            {
                Ok(authority) => authority,
                Err(()) => {
                    let error = anyhow::anyhow!("M0 commit authority failed");
                    M0PairReadObservation::retain_settlement_failure(observation, &error);
                    return Err(error);
                }
            };
            PreparedM0Commit {
                authority,
                actual_thread: &mut *self.pe.thread,
                _system: &*self.pe.system,
                _checks: &checks,
                _session: &retained.session,
                _source: bound,
                _outer: outer,
                candidate,
                next_pc,
            }
            .commit();
            // Capacity was reserved above; this cannot allocate or invoke a
            // producer. Both guards remain armed until bookkeeping completes.
            prefixes.push(prefix);
            accounting.blocks_executed += 1;
            accounting.last_exit = Some((exit.next_pc, exit.kind));
            retained.closed = true;
            Ok(M0Step::Committed)
        }; // Session, control, input, scope and split resource borrows end here.
        if matches!(&result, Ok(M0Step::Committed)) {
            self.closed = true;
        }
        result
    }
}

impl core::fmt::Debug for M0PairReadObservation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SourceResourceFailure {
                source_pc,
                source_word,
                detail,
            } => f
                .debug_struct("SourceResourceFailure")
                .field("source_pc", source_pc)
                .field("source_word", source_word)
                .field("detail", detail)
                .finish(),
            Self::SourceControlFailure {
                source_pc,
                source_word,
                error,
            } => f
                .debug_struct("SourceControlFailure")
                .field("source_pc", source_pc)
                .field("source_word", source_word)
                .field("error", error)
                .finish(),
            Self::PreparationFailure {
                source_pc,
                source_word,
                error,
            } => f
                .debug_struct("PreparationFailure")
                .field("source_pc", source_pc)
                .field("source_word", source_word)
                .field("error", error)
                .field("progress", &error.progress())
                .finish(),
            Self::Native {
                source_pc,
                source_word,
                report,
                precommit_failure,
                settlement_failure,
            } => f
                .debug_struct("Native")
                .field("source_pc", source_pc)
                .field("source_word", source_word)
                .field("report", report)
                .field("precommit_failure", precommit_failure)
                .field("settlement_failure", settlement_failure)
                .finish(),
        }
    }
}
