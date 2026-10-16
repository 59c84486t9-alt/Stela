//! Checked DSB/DSBnXS/ISB requests and ordered owner-service execution.
//!
//! This leaf supplies no production completion/publication implementation.
//! A host fence covers only the selected synchronous Normal-WB data profile;
//! guest maintenance and instruction/context publication need their owners.

use super::access::{ExceptionLevel, Profile, Resolution};
use super::exception::EffectFailure;
use stela_compiler::aarch64::system::synchronization::{self, Operation, Requirement, Scope};

const HCRX_FNXS_MASK: u64 = 1 << 3;
const A64_INSTRUCTION_BYTES: u64 = 4;

/// Access is derived by the authoritative control owner using FEAT_HCX,
/// EL2's execution state, SCR_EL3.HXEn and EL2Enabled, not host detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HcrxAccess {
    /// No effective-control readback was supplied. Irrelevant to ISB/nXS.
    Unreported,
    Disabled,
    Enabled {
        effective_value: u64,
    },
}

/// BRBE feature absence differs from an implemented policy that records no ISB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrbeIsb {
    /// No authoritative feature/policy readback was supplied. ISB must stop.
    Unreported,
    Absent,
    DoesNotRecord,
    Records,
}

/// An unavailable readback must never become an architectural feature absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Xs {
    Unreported,
    Absent,
    Present,
}

/// Dispatch snapshot, not a second mutable machine or feature bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub profile: Profile,
    pub xs: Xs,
    pub hcrx: HcrxAccess,
    pub brbe_isb: BrbeIsb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataCompletion {
    option: u8,
    scope: Scope,
    requirement: Requirement,
    nxs: bool,
}

impl DataCompletion {
    pub const fn option(self) -> u8 {
        self.option
    }
    /// June MBMaintenanceScope, not the legacy memory request domain.
    pub const fn scope(self) -> Scope {
        self.scope
    }
    pub const fn requirement(self) -> Requirement {
        self.requirement
    }
    /// Effective nXS includes execution-controlled FnXS on ordinary DSB.
    pub const fn nxs(self) -> bool {
        self.nxs
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Data(DataCompletion),
    Instruction { option: u8, record_brbe: bool },
}

/// Canonical source descriptor and its validated execution-control snapshot.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    word: u32,
    context: Context,
    kind: RequestKind,
}

impl Request {
    pub const fn original_word(&self) -> u32 {
        self.word
    }
    pub const fn context(&self) -> Context {
        self.context
    }
    pub const fn kind(&self) -> RequestKind {
        self.kind
    }
}

/// Resolve only this service family. Aliases remain with their existing owners.
pub fn resolve(word: u32, context: Context) -> Resolution<Request> {
    let Some(operation) = synchronization::decode(word) else {
        return Resolution::NotHandled;
    };
    if !matches!(
        operation,
        Operation::DataCompletion { .. } | Operation::InstructionSynchronization { .. }
    ) {
        return Resolution::NotHandled;
    }
    let kind = match operation {
        Operation::DataCompletion {
            option,
            scope,
            requirement,
            nxs,
        } => {
            if nxs {
                match context.xs {
                    Xs::Absent => return Resolution::Undefined,
                    Xs::Unreported => {
                        return Resolution::Unsupported("explicit nXS requires actual XS readback");
                    }
                    Xs::Present => {}
                }
            }
            if !nxs
                && context.xs != Xs::Absent
                && matches!(
                    context.profile.current_el,
                    ExceptionLevel::El0 | ExceptionLevel::El1
                )
                && matches!(context.hcrx, HcrxAccess::Enabled { .. })
                && !context.profile.el2_enabled
            {
                return Resolution::Unsupported("enabled HCRX requires enabled EL2");
            }
            if !nxs
                && context.xs != Xs::Absent
                && matches!(
                    context.profile.current_el,
                    ExceptionLevel::El0 | ExceptionLevel::El1
                )
                && context.profile.el2_enabled
                && context.hcrx == HcrxAccess::Unreported
            {
                return Resolution::Unsupported(
                    "effective nXS requires actual HCRX access readback",
                );
            }
            let forcing_control = matches!(
                context.profile.current_el,
                ExceptionLevel::El0 | ExceptionLevel::El1
            ) && matches!(context.hcrx,
                    HcrxAccess::Enabled { effective_value } if effective_value & HCRX_FNXS_MASK != 0);
            if !nxs && forcing_control && context.xs == Xs::Unreported {
                return Resolution::Unsupported("effective nXS requires actual XS readback");
            }
            let forced_nxs = context.xs == Xs::Present && forcing_control;
            RequestKind::Data(DataCompletion {
                option,
                scope,
                requirement,
                nxs: nxs || forced_nxs,
            })
        }
        Operation::InstructionSynchronization { option } => {
            if context.brbe_isb == BrbeIsb::Unreported {
                return Resolution::Unsupported("ISB requires actual BRBE feature/policy readback");
            }
            RequestKind::Instruction {
                option,
                record_brbe: context.brbe_isb == BrbeIsb::Records,
            }
        }
        _ => unreachable!("operation filtered to this service family"),
    };
    Resolution::BackendRequired(Request {
        word,
        context,
        kind,
    })
}

/// Resolve EL0/EL1 ordinary DSB when the authoritative profile disables EL2.
///
/// June IsHCRXEL2Enabled ends with EL2Enabled, so effective HCRX is disabled
/// independently of XS/HCX availability. Preserve those unavailable readbacks
/// instead of inventing feature absence. The caller must derive Profile from
/// its actual PE/control owner; this pure decoder confers no execution permit,
/// source authority, mapped history or completion/publication implementation.
/// Explicit nXS, ISB and bypass aliases remain with the complete dispatcher.
pub fn resolve_ordinary_el2_disabled(word: u32, profile: Profile) -> Resolution<Request> {
    if !matches!(
        synchronization::decode(word),
        Some(Operation::DataCompletion { nxs: false, .. })
    ) {
        return Resolution::NotHandled;
    }
    if profile.el2_enabled {
        return Resolution::Unsupported("ordinary no-EL2 route requires actual disabled EL2");
    }
    if !matches!(
        profile.current_el,
        ExceptionLevel::El0 | ExceptionLevel::El1
    ) {
        return Resolution::Unsupported("ordinary no-EL2 route requires actual EL0/EL1");
    }
    resolve(
        word,
        Context {
            profile,
            xs: Xs::Unreported,
            hcrx: HcrxAccess::Disabled,
            brbe_isb: BrbeIsb::Unreported,
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceRequest {
    pub original_word: u32,
    pub source_pc: u64,
    pub context: Context,
    pub kind: RequestKind,
}

/// A permit binds actual source/control provenance and the owning PE, machine
/// and address space throughout this one execution. Preflight has no guest or
/// barrier effect. It reserves every required service before any completion.
///
/// Data completion combines real synchronous data completion with every
/// maintenance obligation required by the raw option/scope/effective nXS.
/// Unsupported-before-issue or immutable-code/fixed-control eligibility must
/// come from the source-generation/runtime exclusion contract. Zero counters
/// and absent host queues do not establish global architectural absence.
///
/// Instruction synchronization publishes the actual guest instruction stream
/// and relevant control/translation changes before the next guest instruction.
/// CPUID or another host serialization recipe alone does not establish this.
/// Do not clear unrelated trace/error work: the DSB/ISB source calls no blanket
/// TraceUnitFlush or SynchronizeErrors. Any unavailable requirement stops here.
/// Every callback `Ok(())` certifies its complete architectural effect, not
/// issuance or queued work. Failure completion describes that current stage;
/// CommittedPrefix describes earlier stages that already completed.
pub trait BarrierServices {
    type Permit;
    type Error;

    fn preflight(&mut self, request: ServiceRequest) -> Result<Self::Permit, Self::Error>;
    fn complete_data_and_maintenance(
        &mut self,
        permit: &mut Self::Permit,
        request: DataCompletion,
    ) -> Result<(), EffectFailure<Self::Error>>;
    fn synchronize_instructions(
        &mut self,
        permit: &mut Self::Permit,
    ) -> Result<(), EffectFailure<Self::Error>>;
    fn record_brbe_isb(
        &mut self,
        permit: &mut Self::Permit,
        next_pc: u64,
    ) -> Result<(), EffectFailure<Self::Error>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectStage {
    DataCompletion,
    InstructionSynchronization,
    BrbeRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommittedPrefix {
    None,
    InstructionsSynchronized,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecuteError<E> {
    Preflight(E),
    Effect {
        stage: EffectStage,
        committed: CommittedPrefix,
        failure: EffectFailure<E>,
    },
}

impl Request {
    /// On failure preserve earlier instructions, memory and completed owner
    /// effects. A consumed request is not a whole-operation retry token.
    /// The caller commits the returned PC only after successful completion.
    /// On every failure the caller must settle the actual reached terminal PC
    /// under the PE lease, including NoEffect after a native prefix. Failure
    /// never authorizes replay from block entry or rollback of prior effects.
    pub fn execute<S: BarrierServices>(
        self,
        source_pc: u64,
        services: &mut S,
    ) -> Result<u64, ExecuteError<S::Error>> {
        let permit = services
            .preflight(self.service_request(source_pc))
            .map_err(ExecuteError::Preflight)?;
        self.execute_preflighted(source_pc, services, permit)
    }

    /// Pure request for reservation before the canonical Retiring transition.
    pub(crate) const fn service_request(&self, source_pc: u64) -> ServiceRequest {
        ServiceRequest {
            original_word: self.word,
            source_pc,
            context: self.context,
            kind: self.kind,
        }
    }

    /// Consume the exact original prepared service permit once. No second
    /// preflight, authority transition or PC commit occurs in the semantic leaf.
    pub(crate) fn execute_preflighted<S: BarrierServices>(
        self,
        source_pc: u64,
        services: &mut S,
        mut permit: S::Permit,
    ) -> Result<u64, ExecuteError<S::Error>> {
        let next_pc = source_pc.wrapping_add(A64_INSTRUCTION_BYTES);
        match self.kind {
            RequestKind::Data(request) => services
                .complete_data_and_maintenance(&mut permit, request)
                .map_err(|failure| ExecuteError::Effect {
                    stage: EffectStage::DataCompletion,
                    committed: CommittedPrefix::None,
                    failure,
                })?,
            RequestKind::Instruction { record_brbe, .. } => {
                services
                    .synchronize_instructions(&mut permit)
                    .map_err(|failure| ExecuteError::Effect {
                        stage: EffectStage::InstructionSynchronization,
                        committed: CommittedPrefix::None,
                        failure,
                    })?;
                if record_brbe {
                    services
                        .record_brbe_isb(&mut permit, next_pc)
                        .map_err(|failure| ExecuteError::Effect {
                            stage: EffectStage::BrbeRecord,
                            committed: CommittedPrefix::InstructionsSynchronized,
                            failure,
                        })?;
                }
            }
        }
        Ok(next_pc)
    }
}

#[cfg(test)]
mod tests;
