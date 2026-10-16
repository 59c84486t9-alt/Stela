//! Private canonical M0 staged consumer. Type/native/production gates pending.
//! Actual source/control/RAM loans and original PE authority remain live through
//! one native session and infallible register/PC settlement. No saved observation
//! is accepted as access or commit authority. Typed exception delivery is absent.

use super::{
    Active, ConsumerKey, SettledPrefix, provider,
    source::{BoundSource, ReturnedTerminal},
};
use crate::{
    blocks::{InstalledM0SourceScope, RunOutcome, ThreadState},
    memory::domain::{
        DataPolicy, MemoryExecutionLoan, MemoryThread,
        m0_read::{M0RamReadPlatformError, M0Read64Intent, M0Read64Source},
        m0_write::{M0WriteIntent, M0WriteSource},
        physical::BoundPhysicalInstruction,
    },
    system::{
        execution::authority::{NativeRetirementCommit, PeExecutionAuthority},
        state::SystemState,
        translation_controls::{PhysicalFetch, m0_data::M0ControlError},
    },
};
use stela_compiler::{
    GuestAddress, GuestState, Lifter,
    aarch64::{Decoder, Register},
    block::ExitKind,
};

mod callback;
mod write;
pub(super) use write::M0WriteObservation;
mod session;
use session::{M0NativeReport, M0SessionFailure, NativeM0Session};

const INSTRUCTION_BYTES: usize = size_of::<u32>();
const READ_BYTES: u64 = size_of::<u64>() as u64;

mod thread_sealed {
    pub(in crate::blocks::retirement::checked) trait ActualMemoryThread {}
    impl<P: crate::memory::domain::DataPolicy> ActualMemoryThread
        for crate::memory::domain::MemoryThread<P>
    {
    }
}

/// Readonly currency for the ORIGINAL backend MemoryThread, never a caller
/// implementation, copied ASID or identity label. The object borrows the actual
/// MemoryThread<P> and erases only its policy type; no policy callback is invoked.
pub(super) trait M0ThreadCurrency: thread_sealed::ActualMemoryThread {
    fn validate_outer(&self, outer: &MemoryExecutionLoan) -> anyhow::Result<()>;
    fn actual_address_space(&self) -> Option<u64>;
}
impl<P: DataPolicy> M0ThreadCurrency for MemoryThread<P> {
    fn validate_outer(&self, outer: &MemoryExecutionLoan) -> anyhow::Result<()> {
        outer
            .check_thread_domain(self)
            .map_err(|status| anyhow::anyhow!("M0 original thread/outer currency: {status:?}"))
    }
    fn actual_address_space(&self) -> Option<u64> {
        self.address_space()
    }
}

/// Opaque source input minted only by the actual NativeActive path below.
/// This retains the original immutable System/source and SAME outer loan, but
/// no GuestState, actual-PC, PeAuthority or mutable-backend borrow. Copied intent
/// and PSTATE describe the actual pre-read registers sampled under that loan.
/// Installed CPU/context/physical currency is a separate mandatory producer
/// check; validate_source_current does not establish it.
pub(crate) struct M0SourceInput<'source, 'native> {
    bound: &'source BoundSource<'source>,
    system: &'native SystemState,
    outer: &'native MemoryExecutionLoan,
    thread: &'native dyn M0ThreadCurrency,
    installed: &'native InstalledM0SourceScope<'native>,
    intent: M0SourceIntent,
    pstate: u64,
}

#[derive(Clone, Copy)]
enum M0SourceIntent {
    Read(M0Read64Intent),
    Write(M0WriteIntent),
}

/// Same original source/currency input, restricted to an actual write descriptor.
/// Only checked Active may construct this with the sealed ConsumerKey. No CPU,
/// source, outer or thread reference is replaced by copied metadata.
pub(crate) struct M0WriteSourceInput<'source, 'native> {
    original: M0SourceInput<'source, 'native>,
}
impl<'source, 'native> M0WriteSourceInput<'source, 'native> {
    pub(in crate::blocks::retirement::checked) fn new(
        _: &ConsumerKey,
        bound: &'source BoundSource<'source>,
        system: &'native SystemState,
        outer: &'native MemoryExecutionLoan,
        thread: &'native dyn M0ThreadCurrency,
        installed: &'native InstalledM0SourceScope<'native>,
        actual_registers: &GuestState,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bound.source.len() == INSTRUCTION_BYTES,
            "M0 write input source extent differs"
        );
        let word = u32::from_le_bytes(bound.source.try_into()?);
        let instruction = Decoder
            .lift(bound.entry.entry(), word)
            .map_err(|error| anyhow::anyhow!("M0 write canonical decode: {error:?}"))?;
        let source = M0WriteSource::from_source(&instruction, word)
            .map_err(|error| anyhow::anyhow!("M0 write canonical shape: {error:?}"))?;
        let original = M0SourceInput {
            bound,
            system,
            outer,
            thread,
            installed,
            intent: M0SourceIntent::Write(source.intent(actual_registers)),
            pstate: system.pstate(actual_registers),
        };
        original.validate_source_current()?;
        Ok(Self { original })
    }
    pub(crate) fn original(&self) -> &M0SourceInput<'source, 'native> {
        &self.original
    }
    pub(crate) fn intent(&self) -> M0WriteIntent {
        match self.original.intent {
            M0SourceIntent::Write(intent) => intent,
            M0SourceIntent::Read(_) => unreachable!("private write-only constructor"),
        }
    }
}

impl M0SourceInput<'_, '_> {
    pub(crate) fn actual_system(&self) -> &SystemState {
        self.system
    }
    pub(crate) fn outer_execution(&self) -> &MemoryExecutionLoan {
        self.outer
    }
    #[cfg(test)]
    pub(crate) fn source_generation(&self) -> u64 {
        self.bound.entry.generation()
    }
    #[cfg(test)]
    pub(crate) fn actual_address_space(&self) -> Option<u64> {
        self.thread.actual_address_space()
    }
    pub(crate) fn read_intent(&self) -> Option<M0Read64Intent> {
        match self.intent {
            M0SourceIntent::Read(intent) => Some(intent),
            M0SourceIntent::Write(_) => None,
        }
    }
    pub(crate) fn source_pc(&self) -> GuestAddress {
        match self.intent {
            M0SourceIntent::Read(intent) => intent.source_pc,
            M0SourceIntent::Write(intent) => intent.source_pc,
        }
    }
    pub(crate) fn source_word(&self) -> u32 {
        match self.intent {
            M0SourceIntent::Read(intent) => intent.source_word,
            M0SourceIntent::Write(intent) => intent.source_word,
        }
    }
    fn next_pc(&self) -> GuestAddress {
        match self.intent {
            M0SourceIntent::Read(intent) => intent.next_pc,
            M0SourceIntent::Write(intent) => intent.next_pc,
        }
    }
    pub(crate) fn installed_source_scope(&self) -> &InstalledM0SourceScope<'_> {
        self.installed
    }
    pub(crate) fn actual_pstate(&self) -> u64 {
        self.pstate
    }
    pub(crate) fn source_bytes(&self) -> &[u8] {
        self.bound.source
    }

    /// Authority/platform currency only, not an architectural data fault.
    /// SAME-domain membership is checked on the actual immutable thread object
    /// retained from the sealed backend's original field at the sole mint below.
    /// No external caller can substitute another same-domain MemoryThread.
    pub(crate) fn validate_thread_current(&self) -> anyhow::Result<()> {
        self.thread.validate_outer(self.outer)?;
        anyhow::ensure!(
            self.thread.actual_address_space() == Some(self.bound.entry.address_space()),
            "M0 original thread/source address space differs"
        );
        Ok(())
    }

    /// Compare a genuine fresh installed-context fetch to the SINGLE original
    /// CodeRegion physical registration. No copied source registry or snapshot.
    /// Same-domain/System/ASID qualification remains the source/control/PA
    /// producer's mandatory check against actual outer and actual MemoryThread.
    pub(crate) fn validate_installed_fetch(
        &self,
        scope: &InstalledM0SourceScope<'_>,
        reached: &BoundPhysicalInstruction,
    ) -> anyhow::Result<()> {
        self.validate_source_current()?;
        anyhow::ensure!(
            std::ptr::eq(scope, self.installed),
            "M0 installed scope is not the original input borrow"
        );
        anyhow::ensure!(
            reached.raw_pc() == self.source_pc().0
                && reached.word() == self.source_word()
                && self.bound.source == reached.word().to_le_bytes(),
            "M0 reached original source differs"
        );
        self.bound
            .runtime
            .check_physical_source(
                scope.installed_snapshot(),
                PhysicalFetch {
                    pc: reached.raw_pc(),
                    word: reached.word(),
                    physical_address: reached.physical_address(),
                    source_generation: self.bound.entry.generation(),
                },
                reached,
            )
            .map_err(|reason| anyhow::anyhow!(reason))
    }

    /// Recheck the retained logical source/RX/plan association. This never
    /// substitutes for genuine installed-context instruction re-fetch or an
    /// actual CPU/control/physical-space witness. No metadata grants access.
    pub(crate) fn validate_source_current(&self) -> anyhow::Result<()> {
        self.validate_thread_current()?;
        self.bound.recheck()?;
        anyhow::ensure!(
            self.bound.source.len() == INSTRUCTION_BYTES,
            "M0 source input extent differs"
        );
        let word = u32::from_le_bytes(self.bound.source.try_into()?);
        anyhow::ensure!(
            word == self.source_word() && self.bound.entry.entry() == self.source_pc(),
            "M0 source input identity differs"
        );
        let instruction = Decoder
            .lift(self.source_pc(), word)
            .map_err(|reason| anyhow::anyhow!("M0 source decode: {reason:?}"))?;
        let requirements = match self.intent {
            M0SourceIntent::Read(_) => {
                let source = if matches!(
                    self.bound.runtime.profile(),
                    stela_compiler::block::BlockProfile::El1M0IntegerV1
                        | stela_compiler::block::BlockProfile::El1PlatformV1
                ) {
                    M0Read64Source::from_el1_integer_source(&instruction, word)
                } else {
                    M0Read64Source::from_source(&instruction, word)
                }
                .map_err(|failure| anyhow::anyhow!("M0 read source shape: {failure:?}"))?;
                source.requirements()
            }
            M0SourceIntent::Write(_) => {
                anyhow::ensure!(
                    self.bound.runtime.profile()
                        == stela_compiler::block::BlockProfile::El1PlatformV1,
                    "M0 write source requires the immutable platform cohort"
                );
                M0WriteSource::from_source(&instruction, word)
                    .map_err(|failure| anyhow::anyhow!("M0 write source shape: {failure:?}"))?
                    .requirements()
            }
        };
        anyhow::ensure!(
            self.bound.memory_requirements()? == requirements,
            "M0 source requirements differ"
        );
        anyhow::ensure!(
            self.next_pc().0
                == self
                    .source_pc()
                    .0
                    .checked_add(INSTRUCTION_BYTES as u64)
                    .ok_or_else(|| anyhow::anyhow!("M0 source input PC overflow"))?,
            "M0 source input continuation differs"
        );
        Ok(())
    }
}

/// Drop order is architectural: poison the ORIGINAL PE in Drop's body BEFORE
/// releasing the owned session fields (Device mutex/pins). This covers invoke
/// panic, typed fault, validation/precommit error and every early return. No
/// replacement authority or ready-on-drop behavior is introduced.
struct RetainedM0Session<'active, S> {
    authority: &'active mut PeExecutionAuthority,
    session: S,
    closed: bool,
}
impl<S> RetainedM0Session<'_, S> {
    fn require_native(&self, attempt: u64) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.authority.native_attempt(attempt),
            "M0 retained NativeActive attempt lost"
        );
        Ok(())
    }
}
impl<S> Drop for RetainedM0Session<'_, S> {
    fn drop(&mut self) {
        if !self.closed {
            self.authority.poison();
        }
        // session fields release only after this body's actual failstop store.
    }
}

pub(super) enum M0Step {
    Committed,
    SourceResourcesBlocked,
    SourceControlBlocked,
    PreparationBlocked,
    Indeterminate(String),
}

/// Owned output only. Preserve the genuine report before fallible validation;
/// it never supplies a source, exception-delivery, retry or commit capability.
pub(crate) enum M0Observation {
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
        error: M0RamReadPlatformError,
    },
    Native {
        source_pc: GuestAddress,
        source_word: u32,
        report: Box<M0NativeReport>,
        precommit_failure: Option<M0SessionFailure>,
        settlement_failure: Option<String>,
    },
}
impl M0Observation {
    fn retain_settlement_failure(observation: &mut Option<Self>, error: &anyhow::Error) {
        if let Some(Self::Native {
            settlement_failure, ..
        }) = observation
        {
            *settlement_failure = Some(error.to_string());
        }
    }
}

/// Only this actual Active path creates the paired commit. Session borrows
/// retain the genuine control/input/scope and physical pins; checks retain the
/// original execution/closed-producer/thread resources. No whole-B reborrow.
struct PreparedM0Commit<'commit, 'code, C, S> {
    authority: NativeRetirementCommit<'commit>,
    actual_thread: &'commit mut ThreadState,
    _system: &'commit SystemState,
    _checks: &'commit C,
    _session: &'commit S,
    _source: &'commit BoundSource<'code>,
    _outer: &'commit MemoryExecutionLoan,
    candidate: GuestState,
    next_pc: GuestAddress,
}
impl<C, S> PreparedM0Commit<'_, '_, C, S> {
    /// No caller inputs, callbacks, allocation, failure or target access.
    fn commit(self) {
        self.actual_thread.registers = self.candidate;
        self.actual_thread.pc = self.next_pc;
        self.authority.finish(&ConsumerKey(()));
    }
}

impl<B: provider::Owner> Active<'_, '_, B> {
    pub(super) fn execute_m0_read64(
        mut self,
        bound: &BoundSource<'_>,
        accounting: &mut RunOutcome,
        observation: &mut Option<M0Observation>,
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
        let source = if matches!(
            bound.runtime.profile(),
            stela_compiler::block::BlockProfile::El1M0IntegerV1
                | stela_compiler::block::BlockProfile::El1PlatformV1
        ) {
            M0Read64Source::from_el1_integer_source(&instruction, word)
        } else {
            M0Read64Source::from_source(&instruction, word)
        }
        .map_err(|failure| anyhow::anyhow!("M0 source shape: {failure:?}"))?;
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
                platform: _,
                controls,
                memory,
                context,
                checks,
            } = match self.pe.backend.split_m0_resources() {
                Ok(resources) => resources,
                Err(error) => {
                    *observation = Some(M0Observation::SourceResourceFailure {
                        source_pc: intent.source_pc,
                        source_word: intent.source_word,
                        detail: error.to_string(),
                    });
                    return Ok(M0Step::SourceResourcesBlocked);
                }
            };
            checks.check(outer)?;
            let installed = sources.source_scope().map_err(anyhow::Error::msg)?;
            let input = M0SourceInput {
                bound,
                system: &*self.pe.system,
                outer,
                thread: memory,
                installed: &installed,
                intent: M0SourceIntent::Read(intent),
                pstate: self.pe.system.pstate(&self.pe.thread.registers),
            };
            input.validate_source_current()?;
            // Real source/control witness, stable BEFORE the RAM session borrows
            // it. All M0/EE0/current-source qualification precedes target read.
            let control = match controls.loan_m0_read8(&input) {
                Ok(control) => control,
                Err(error) => {
                    *observation = Some(M0Observation::SourceControlFailure {
                        source_pc: intent.source_pc,
                        source_word: intent.source_word,
                        error,
                    });
                    return Ok(M0Step::SourceControlBlocked);
                }
            };
            let mut candidate = self.pe.thread.registers.clone();
            let session = match NativeM0Session::prepare(bound, outer, &control, context) {
                Ok(session) => session,
                Err(error) => {
                    *observation = Some(M0Observation::PreparationFailure {
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
                && report.completed_bytes == READ_BYTES
                && report.callback_failure.is_none()
                && report.failure.is_none();
            *observation = Some(M0Observation::Native {
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
                    Some(M0Observation::Native { report, .. }) => format!(
                        "M0 native report incomplete: invoked={}; completed={}; callback={:?}; failure={:?}; carrier={:?}",
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
                match intent.destination {
                    Register::X(index) => {
                        permitted.x[usize::from(index)] = candidate.x[usize::from(index)]
                    }
                    Register::Zero => {}
                    _ => anyhow::bail!("M0 destination differs"),
                }
                anyhow::ensure!(candidate == permitted, "M0 changed unrelated state");
                // Allocate diagnostics BEFORE infallible state/PC/Ready commit.
                let prefix = bound.prefix(None, READ_BYTES)?;
                prefixes.try_reserve(1)?;
                Ok((next_pc, exit, prefix))
            })();
            let (next_pc, exit, prefix) = match qualified {
                Ok(value) => value,
                Err(error) => {
                    M0Observation::retain_settlement_failure(observation, &error);
                    return Err(error);
                }
            };
            if let Err(failure) = retained.session.precommit() {
                // Move the actual typed error into retained output BEFORE any
                // fallible diagnostic formatting, without Clone or conversion.
                let detail = match observation {
                    Some(M0Observation::Native {
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
                M0Observation::retain_settlement_failure(observation, &error);
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
                    M0Observation::retain_settlement_failure(observation, &error);
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

#[cfg(test)]
#[path = "m0/fixture.rs"]
mod fixture;

impl core::fmt::Debug for M0Observation {
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
