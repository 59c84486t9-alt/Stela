//! DSB, DSBnXS and ISB. A host fence covers synchronous write-back data only.

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
                        return Resolution::Unsupported("explicit nXS requires XS readback");
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
                return Resolution::Unsupported("effective nXS requires HCRX access readback");
            }
            let forcing_control = matches!(
                context.profile.current_el,
                ExceptionLevel::El0 | ExceptionLevel::El1
            ) && matches!(context.hcrx,
                    HcrxAccess::Enabled { effective_value } if effective_value & HCRX_FNXS_MASK != 0);
            if !nxs && forcing_control && context.xs == Xs::Unreported {
                return Resolution::Unsupported("effective nXS requires XS readback");
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
                return Resolution::Unsupported("ISB requires BRBE feature/policy readback");
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

/// Resolve an EL0/EL1 DSB when the profile has EL2 disabled.
///
/// IsHCRXEL2Enabled ends with EL2Enabled, so HCRX is disabled whether or not XS
/// and HCX exist; those readbacks stay unknown rather than absent. The caller
/// derives `Profile` from its PE. nXS, ISB and bypass aliases are handled by
/// the full dispatcher.
pub fn resolve_ordinary_el2_disabled(word: u32, profile: Profile) -> Resolution<Request> {
    if !matches!(
        synchronization::decode(word),
        Some(Operation::DataCompletion { nxs: false, .. })
    ) {
        return Resolution::NotHandled;
    }
    if profile.el2_enabled {
        return Resolution::Unsupported("ordinary no-EL2 route requires disabled EL2");
    }
    if !matches!(
        profile.current_el,
        ExceptionLevel::El0 | ExceptionLevel::El1
    ) {
        return Resolution::Unsupported("ordinary no-EL2 route requires EL0/EL1");
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

/// Services that complete barriers for one execution, bound to the PE, machine
/// and address space.
///
/// Preflight has no effect and reserves every service needed. Data completion
/// covers the synchronous data accesses and every maintenance obligation of the
/// option, scope and nXS. Zero counters or empty host queues do not prove there
/// is no outstanding work. Instruction synchronization publishes the
/// instruction stream and any control or translation changes before the next
/// instruction; host serialization alone is not enough. Unrelated trace and
/// error work is not flushed. Any unavailable requirement stops execution. A
/// callback's `Ok(())` means its whole architectural effect is complete; on
/// failure, CommittedPrefix lists the stages already completed.
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
    /// On failure, earlier instructions, memory and completed effects stand;
    /// the request cannot be retried as a whole. The caller commits the
    /// returned PC only on success, and on failure settles the reached PC
    /// (including NoEffect after a native prefix). Failure never permits replay
    /// from block entry or rollback.
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

    /// The service request, for reservation before retiring.
    pub(crate) const fn service_request(&self, source_pc: u64) -> ServiceRequest {
        ServiceRequest {
            original_word: self.word,
            source_pc,
            context: self.context,
            kind: self.kind,
        }
    }

    /// Consume the prepared service reservation once.
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
