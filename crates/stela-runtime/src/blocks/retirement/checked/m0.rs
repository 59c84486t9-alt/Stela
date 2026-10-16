//! Execution of MMU-off ("M0") EL1 blocks that perform one staged RAM read.

use super::{
    Active, ConsumerKey, SettledPrefix, provider,
    source::{BoundSource, ReturnedTerminal},
};
use crate::{
    blocks::{InstalledM0SourceScope, RunOutcome, ThreadState},
    memory::domain::{
        DataPolicy, MemoryExecutionLoan, MemoryThread,
        m0_read::pair::{M0ReadPairIntent, M0ReadPairSource},
        m0_read::{M0RamReadPlatformError, M0ScalarReadIntent, M0ScalarReadSource},
        m0_write::{M0WriteIntent, M0WriteSource},
        physical::BoundPhysicalInstruction,
    },
    system::{
        execution::authority::{NativeRetirementCommit, PeExecutionAuthority},
        state::SystemState,
        translation_controls::{PhysicalFetch, m0_data::M0ControlError},
    },
};
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, string::ToString, vec::Vec};
use stela_compiler::{
    GuestAddress, GuestState, Lifter,
    aarch64::{Decoder, Register},
    block::ExitKind,
};

mod callback;
mod pair_read;
mod write;
pub(super) use pair_read::M0PairReadObservation;
pub(super) use write::M0WriteObservation;
mod session;
use session::{M0NativeReport, M0SessionFailure, NativeM0Session};

const INSTRUCTION_BYTES: usize = size_of::<u32>();

mod thread_sealed {
    pub(in crate::blocks::retirement::checked) trait ActualMemoryThread {}
    impl<P: crate::memory::domain::DataPolicy> ActualMemoryThread
        for crate::memory::domain::MemoryThread<P>
    {
    }
}

/// Read-only access to the backend's memory thread, with its policy type
/// erased.
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

/// Source input created only by the native-session path below. It holds the
/// system state, source and outer borrow, but no guest state or mutable
/// backend. The copied intent and PSTATE are the pre-read registers sampled
/// under that borrow. The installed context must be checked separately;
/// `validate_source_current` does not do it.
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
    Read(M0ScalarReadIntent),
    Write(M0WriteIntent),
    PairRead(M0ReadPairIntent),
}

/// The same input, for a write descriptor. Only the checked consumer constructs
/// it.
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
            M0SourceIntent::Read(_) | M0SourceIntent::PairRead(_) => {
                unreachable!("private write-only constructor")
            }
        }
    }
}

/// Input for a pair read; the consumer lends the platform identification.
pub(crate) struct M0PairReadSourceInput<'source, 'native> {
    original: M0SourceInput<'source, 'native>,
    platform: &'native super::el1_system::El1PlatformControls,
}
impl<'source, 'native> M0PairReadSourceInput<'source, 'native> {
    // The resources are split borrows of one PE.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::blocks::retirement::checked) fn new(
        _: &ConsumerKey,
        bound: &'source BoundSource<'source>,
        system: &'native SystemState,
        outer: &'native MemoryExecutionLoan,
        thread: &'native dyn M0ThreadCurrency,
        installed: &'native InstalledM0SourceScope<'native>,
        platform: &'native super::el1_system::El1PlatformControls,
        actual_registers: &GuestState,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bound.source.len() == INSTRUCTION_BYTES,
            "M0 pair source extent differs"
        );
        let word = u32::from_le_bytes(bound.source.try_into()?);
        let instruction = Decoder
            .lift(bound.entry.entry(), word)
            .map_err(|error| anyhow::anyhow!("M0 pair canonical decode: {error:?}"))?;
        let source = M0ReadPairSource::from_source(&instruction, word)
            .map_err(|error| anyhow::anyhow!("M0 pair canonical shape: {error:?}"))?;
        let result = Self {
            original: M0SourceInput {
                bound,
                system,
                outer,
                thread,
                installed,
                intent: M0SourceIntent::PairRead(source.intent(actual_registers)),
                pstate: system.pstate(actual_registers),
            },
            platform,
        };
        result.original.validate_source_current()?;
        result.validate_pair_profile()?;
        Ok(result)
    }
    pub(crate) fn original(&self) -> &M0SourceInput<'source, 'native> {
        &self.original
    }
    pub(crate) fn intent(&self) -> M0ReadPairIntent {
        match self.original.intent {
            M0SourceIntent::PairRead(intent) => intent,
            M0SourceIntent::Read(_) | M0SourceIntent::Write(_) => {
                unreachable!("private pair-only constructor")
            }
        }
    }
    pub(crate) fn validate_pair_profile(&self) -> anyhow::Result<()> {
        self.platform
            .check_pair_read_profile(self.original.actual_system())
    }
}

impl M0SourceInput<'_, '_> {
    pub(crate) fn actual_system(&self) -> &SystemState {
        self.system
    }
    pub(crate) fn outer_execution(&self) -> &MemoryExecutionLoan {
        self.outer
    }
    pub(crate) fn read_intent(&self) -> Option<M0ScalarReadIntent> {
        match self.intent {
            M0SourceIntent::Read(intent) => Some(intent),
            M0SourceIntent::Write(_) | M0SourceIntent::PairRead(_) => None,
        }
    }
    pub(crate) fn source_pc(&self) -> GuestAddress {
        match self.intent {
            M0SourceIntent::Read(intent) => intent.source_pc,
            M0SourceIntent::Write(intent) => intent.source_pc,
            M0SourceIntent::PairRead(intent) => intent.source_pc,
        }
    }
    pub(crate) fn source_word(&self) -> u32 {
        match self.intent {
            M0SourceIntent::Read(intent) => intent.source_word,
            M0SourceIntent::Write(intent) => intent.source_word,
            M0SourceIntent::PairRead(intent) => intent.source_word,
        }
    }
    fn next_pc(&self) -> GuestAddress {
        match self.intent {
            M0SourceIntent::Read(intent) => intent.next_pc,
            M0SourceIntent::Write(intent) => intent.next_pc,
            M0SourceIntent::PairRead(intent) => intent.next_pc,
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

    /// Check that the thread is still the PE's own memory thread (not an
    /// architectural fault).
    pub(crate) fn validate_thread_current(&self) -> anyhow::Result<()> {
        self.thread.validate_outer(self.outer)?;
        anyhow::ensure!(
            self.thread.actual_address_space() == Some(self.bound.entry.address_space()),
            "M0 original thread/source address space differs"
        );
        Ok(())
    }

    /// Compare a fresh fetch from the installed context with the code region's
    /// physical registration.
    pub(crate) fn validate_installed_fetch(
        &self,
        scope: &InstalledM0SourceScope<'_>,
        reached: &BoundPhysicalInstruction,
    ) -> anyhow::Result<()> {
        self.validate_source_current()?;
        anyhow::ensure!(
            core::ptr::eq(scope, self.installed),
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

    /// Re-check the logical source, native-code and plan association. This does
    /// not replace re-fetching the instruction.
    pub(crate) fn validate_source_current(&self) -> anyhow::Result<()> {
        self.validate_thread_current()?;
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
                let source = M0ScalarReadSource::from_profile(
                    self.bound.runtime.profile(),
                    &instruction,
                    word,
                )
                .map_err(|failure| anyhow::anyhow!("M0 read source shape: {failure:?}"))?;
                source.requirements()
            }
            M0SourceIntent::PairRead(_) => {
                anyhow::ensure!(
                    self.bound.runtime.profile()
                        == stela_compiler::block::BlockProfile::El1PlatformV1,
                    "M0 pair read requires immutable platform cohort"
                );
                M0ReadPairSource::from_source(&instruction, word)
                    .map_err(|failure| anyhow::anyhow!("M0 pair read source shape: {failure:?}"))?
                    .requirements()
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

/// Drop marks the PE failed before releasing the session's fields (the Device
/// mutex and pins), covering panics, faults, validation errors and early
/// returns.
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
        // The session fields are released only after the PE is marked failed.
    }
}

pub(super) enum M0Step {
    Committed,
    SourceResourcesBlocked,
    SourceControlBlocked,
    PreparationBlocked,
    Indeterminate(String),
}

/// Owned output, recorded before any fallible validation.
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

/// Created only by the consumer. The session borrows its controls, input, scope
/// and physical pins; the checks borrow the execution, producer and thread
/// resources.
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
    pub(super) fn execute_m0_scalar_load(
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
        anyhow::ensure!(
            bound.source.len() == INSTRUCTION_BYTES,
            "M0 source extent differs"
        );
        anyhow::ensure!(
            self.pe.thread.pc == bound.entry.entry(),
            "M0 source PC differs"
        );
        let word = u32::from_le_bytes(bound.source.try_into()?);
        let instruction = Decoder
            .lift(bound.entry.entry(), word)
            .map_err(|reason| anyhow::anyhow!("M0 source decode: {reason:?}"))?;
        let source = M0ScalarReadSource::from_profile(bound.runtime.profile(), &instruction, word)
            .map_err(|failure| anyhow::anyhow!("M0 source shape: {failure:?}"))?;
        anyhow::ensure!(
            bound.memory_requirements()? == source.requirements(),
            "M0 requirements differ"
        );
        let intent = source.intent(&self.pe.thread.registers);
        // Split the backend once and do not touch `B` again while these borrows
        // are live. The outer consumer stays active through teardown, even
        // after a ready result.
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
            let control = match controls.loan_m0_scalar_read(&input) {
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
            // Hold the session in the failure guard before the call, so an
            // error or panic marks the PE failed before the pins are released.
            let mut retained = RetainedM0Session {
                authority: &mut *self.pe.authority,
                session,
                closed: false,
            };
            let report = retained.session.invoke(&mut candidate);
            let exit = report.returned_exit();
            let valid_report = report.invoked
                && report.completed_bytes == u64::from(intent.bytes)
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
                // The report is already in the output; formatting may allocate
                // or panic without losing it.
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
                    "M0 PC changed before settlement"
                );
                let mut permitted = self.pe.thread.registers.clone();
                match intent.destination {
                    Register::X(index) => {
                        permitted.x[usize::from(index)] = candidate.x[usize::from(index)]
                    }
                    Register::Zero => {}
                    _ => anyhow::bail!("M0 destination differs"),
                }
                if let Some((base, value)) = intent.writeback {
                    match base {
                        Register::X(index) => permitted.x[usize::from(index)] = value,
                        Register::Sp => permitted.sp = value,
                        Register::Zero => anyhow::bail!("M0 writeback cannot target ZR"),
                    }
                }
                anyhow::ensure!(
                    candidate == permitted,
                    "M0 changed unrelated state or writeback"
                );
                // Allocate diagnostics BEFORE infallible state/PC/Ready commit.
                let prefix = bound.prefix(None, u64::from(intent.bytes))?;
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
                // Move the typed error into the output before any fallible
                // formatting.
                let detail = match observation {
                    Some(M0Observation::Native {
                        precommit_failure, ..
                    }) => {
                        *precommit_failure = Some(failure);
                        format!("M0 session precommit: {precommit_failure:?}")
                    }
                    _ => unreachable!("same invocation retained its native report"),
                };
                return Err(anyhow::anyhow!(detail));
            }
            let checked = (|| -> anyhow::Result<()> {
                checks.check(outer)?;
                retained.require_native(self.attempt)
            })();
            if let Err(error) = checked {
                M0Observation::retain_settlement_failure(observation, &error);
                return Err(error);
            }
            // Create the borrowed token directly rather than returning it from
            // a closure that also captures the mutable borrow.
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
