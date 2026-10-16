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
mod tests {
    use super::super::access::SecurityState;
    use super::super::exception::Completion;
    use super::*;

    const DSB_BASE: u32 = 0xd503_309f;
    const DSB_NXS_BASE: u32 = 0xd503_323f;
    const ISB_BASE: u32 = 0xd503_30df;
    const OPTION_SHIFT: u32 = 8;
    const NXS_SCOPE_SHIFT: u32 = 10;
    const SOURCE_PC: u64 = 0x1234;

    fn context() -> Context {
        Context {
            profile: Profile {
                current_el: ExceptionLevel::El1,
                security: SecurityState::NonSecure,
                el2_enabled: false,
                el3_present: false,
            },
            xs: Xs::Absent,
            hcrx: HcrxAccess::Disabled,
            brbe_isb: BrbeIsb::Absent,
        }
    }

    fn request(word: u32, context: Context) -> Request {
        match resolve(word, context) {
            Resolution::BackendRequired(request) => request,
            other => panic!("expected checked backend request, got {other:?}"),
        }
    }

    #[test]
    fn dsb_table_retains_raw_operand_and_june_maintenance_scope() {
        use Requirement::{All, Reads, Writes};
        use Scope::{InnerShareable, Nonshareable, OuterShareable};
        let expected = [
            (1, Scope::None, Reads),
            (2, Scope::None, Writes),
            (3, OuterShareable, All),
            (5, Scope::None, Reads),
            (6, Scope::None, Writes),
            (7, Nonshareable, All),
            (8, OuterShareable, All),
            (9, Scope::None, Reads),
            (10, Scope::None, Writes),
            (11, InnerShareable, All),
            (12, OuterShareable, All),
            (13, Scope::None, Reads),
            (14, Scope::None, Writes),
            (15, OuterShareable, All),
        ];
        for (option, scope, requirement) in expected {
            let word = DSB_BASE | u32::from(option) << OPTION_SHIFT;
            let request = request(word, context());
            assert_eq!(request.original_word(), word);
            assert_eq!(
                request.kind(),
                RequestKind::Data(DataCompletion {
                    option,
                    scope,
                    requirement,
                    nxs: false
                })
            );
        }
        for option in [0, 4] {
            assert!(matches!(
                resolve(DSB_BASE | option << OPTION_SHIFT, context()),
                Resolution::NotHandled
            ));
        }
    }

    #[test]
    fn explicit_nxs_requires_xs_and_retains_every_scope() {
        for (option, scope) in [
            Scope::OuterShareable,
            Scope::Nonshareable,
            Scope::InnerShareable,
            Scope::OuterShareable,
        ]
        .into_iter()
        .enumerate()
        {
            let word = DSB_NXS_BASE | (option as u32) << NXS_SCOPE_SHIFT;
            // Irrelevant inconsistent control cannot override the decode UNDEF.
            let context = Context {
                hcrx: HcrxAccess::Enabled {
                    effective_value: HCRX_FNXS_MASK,
                },
                ..context()
            };
            assert!(matches!(resolve(word, context), Resolution::Undefined));
            assert_eq!(
                request(
                    word,
                    Context {
                        xs: Xs::Present,
                        ..context
                    }
                )
                .kind(),
                RequestKind::Data(DataCompletion {
                    option: option as u8,
                    scope,
                    requirement: Requirement::All,
                    nxs: true
                })
            );
        }
    }

    #[test]
    fn ordinary_nxs_forcing_uses_actual_source_el_and_effective_control() {
        for current_el in [
            ExceptionLevel::El0,
            ExceptionLevel::El1,
            ExceptionLevel::El2,
            ExceptionLevel::El3,
        ] {
            for xs in [false, true] {
                for enabled in [false, true] {
                    for fnxs in [false, true] {
                        let base = context();
                        let context = Context {
                            xs: if xs { Xs::Present } else { Xs::Absent },
                            profile: Profile {
                                current_el,
                                el2_enabled: true,
                                ..base.profile
                            },
                            hcrx: if enabled {
                                HcrxAccess::Enabled {
                                    effective_value: if fnxs { HCRX_FNXS_MASK } else { 0 },
                                }
                            } else {
                                HcrxAccess::Disabled
                            },
                            ..base
                        };
                        let RequestKind::Data(data) =
                            request(DSB_BASE | 15 << OPTION_SHIFT, context).kind()
                        else {
                            unreachable!()
                        };
                        assert_eq!(
                            data.nxs(),
                            xs && enabled
                                && fnxs
                                && matches!(current_el, ExceptionLevel::El0 | ExceptionLevel::El1)
                        );
                    }
                }
            }
        }
    }

    #[derive(Default)]
    struct Services {
        preflight: Vec<ServiceRequest>,
        calls: Vec<EffectStage>,
        data: Vec<DataCompletion>,
        brbe_pc: Option<u64>,
        unavailable: bool,
        fail: Option<EffectStage>,
        completion: Option<Completion>,
    }

    impl Services {
        fn step(&mut self, stage: EffectStage) -> Result<(), EffectFailure<&'static str>> {
            self.calls.push(stage);
            if self.fail == Some(stage) {
                Err(EffectFailure {
                    error: "injected",
                    completion: self.completion.unwrap_or(Completion::Partial),
                })
            } else {
                Ok(())
            }
        }
    }

    impl BarrierServices for Services {
        type Permit = ();
        type Error = &'static str;
        fn preflight(&mut self, request: ServiceRequest) -> Result<(), Self::Error> {
            self.preflight.push(request);
            if self.unavailable {
                Err("required publication owner unavailable")
            } else {
                Ok(())
            }
        }
        fn complete_data_and_maintenance(
            &mut self,
            _: &mut (),
            request: DataCompletion,
        ) -> Result<(), EffectFailure<Self::Error>> {
            self.step(EffectStage::DataCompletion)?;
            self.data.push(request);
            Ok(())
        }
        fn synchronize_instructions(
            &mut self,
            _: &mut (),
        ) -> Result<(), EffectFailure<Self::Error>> {
            self.step(EffectStage::InstructionSynchronization)
        }
        fn record_brbe_isb(
            &mut self,
            _: &mut (),
            next_pc: u64,
        ) -> Result<(), EffectFailure<Self::Error>> {
            self.step(EffectStage::BrbeRecord)?;
            self.brbe_pc = Some(next_pc);
            Ok(())
        }
    }

    #[test]
    fn all_isb_options_require_publication_before_optional_brbe() {
        for option in 0..=15 {
            for policy in [BrbeIsb::Absent, BrbeIsb::DoesNotRecord, BrbeIsb::Records] {
                let context = Context {
                    brbe_isb: policy,
                    ..context()
                };
                let word = ISB_BASE | option << OPTION_SHIFT;
                let request = request(word, context);
                assert_eq!(
                    request.kind(),
                    RequestKind::Instruction {
                        option: option as u8,
                        record_brbe: policy == BrbeIsb::Records
                    }
                );
                let mut services = Services::default();
                assert_eq!(request.execute(SOURCE_PC, &mut services), Ok(SOURCE_PC + 4));
                assert_eq!(services.preflight[0].original_word, word);
                assert_eq!(services.preflight[0].context, context);
                assert_eq!(services.preflight[0].source_pc, SOURCE_PC);
                if policy == BrbeIsb::Records {
                    assert_eq!(
                        services.calls,
                        [
                            EffectStage::InstructionSynchronization,
                            EffectStage::BrbeRecord
                        ]
                    );
                    assert_eq!(services.brbe_pc, Some(SOURCE_PC + 4));
                } else {
                    assert_eq!(services.calls, [EffectStage::InstructionSynchronization]);
                    assert_eq!(services.brbe_pc, None);
                }
            }
        }
    }

    #[test]
    fn unavailable_owner_declines_before_any_host_or_guest_completion() {
        for word in [DSB_BASE | 15 << OPTION_SHIFT, ISB_BASE | 15 << OPTION_SHIFT] {
            let mut services = Services {
                unavailable: true,
                ..Services::default()
            };
            assert_eq!(
                request(word, context()).execute(SOURCE_PC, &mut services),
                Err(ExecuteError::Preflight(
                    "required publication owner unavailable"
                ))
            );
            assert!(services.calls.is_empty());
        }
    }

    #[test]
    fn data_service_receives_effective_nxs_and_failure_does_not_retire() {
        let base = context();
        let context = Context {
            xs: Xs::Present,
            profile: Profile {
                el2_enabled: true,
                ..base.profile
            },
            hcrx: HcrxAccess::Enabled {
                effective_value: HCRX_FNXS_MASK,
            },
            ..base
        };
        let word = DSB_BASE | 15 << OPTION_SHIFT;
        let mut services = Services::default();
        assert_eq!(
            request(word, context).execute(u64::MAX - 3, &mut services),
            Ok(0)
        );
        assert_eq!(services.calls, [EffectStage::DataCompletion]);
        assert_eq!(
            services.data,
            [DataCompletion {
                option: 15,
                scope: Scope::OuterShareable,
                requirement: Requirement::All,
                nxs: true
            }]
        );
        assert_eq!(services.brbe_pc, None);
        let mut services = Services {
            fail: Some(EffectStage::DataCompletion),
            ..Services::default()
        };
        assert_eq!(
            request(word, context).execute(SOURCE_PC, &mut services),
            Err(ExecuteError::Effect {
                stage: EffectStage::DataCompletion,
                committed: CommittedPrefix::None,
                failure: EffectFailure {
                    error: "injected",
                    completion: Completion::Partial
                }
            })
        );
        assert_eq!(services.calls, [EffectStage::DataCompletion]);
    }

    #[test]
    fn failed_brbe_retains_completed_isb_and_its_own_failure_completion() {
        let context = Context {
            brbe_isb: BrbeIsb::Records,
            ..context()
        };
        for (stage, prefix) in [
            (
                EffectStage::InstructionSynchronization,
                CommittedPrefix::None,
            ),
            (
                EffectStage::BrbeRecord,
                CommittedPrefix::InstructionsSynchronized,
            ),
        ] {
            let mut services = Services {
                fail: Some(stage),
                ..Services::default()
            };
            assert_eq!(
                request(ISB_BASE | 15 << OPTION_SHIFT, context).execute(SOURCE_PC, &mut services),
                Err(ExecuteError::Effect {
                    stage,
                    committed: prefix,
                    failure: EffectFailure {
                        error: "injected",
                        completion: Completion::Partial
                    }
                })
            );
            assert_eq!(
                services.calls.len(),
                if stage == EffectStage::BrbeRecord {
                    2
                } else {
                    1
                }
            );
        }
    }

    #[test]
    fn ordinary_no_el2_route_preserves_unreported_features_for_every_option() {
        for option in 0..=15 {
            let word = DSB_BASE | option << OPTION_SHIFT;
            let resolution = resolve_ordinary_el2_disabled(word, context().profile);
            if matches!(option, 0 | 4) {
                assert_eq!(resolution, Resolution::NotHandled);
                continue;
            }
            let Resolution::BackendRequired(request) = resolution else {
                panic!("ordinary DSB requires real backend, got {resolution:?}");
            };
            assert_eq!(request.context().xs, Xs::Unreported);
            assert_eq!(request.context().brbe_isb, BrbeIsb::Unreported);
            let RequestKind::Data(data) = request.kind() else {
                unreachable!()
            };
            assert!(!data.nxs());
            assert_eq!(data.option(), option as u8);
            let mut services = Services::default();
            assert_eq!(request.execute(SOURCE_PC, &mut services), Ok(SOURCE_PC + 4));
            assert_eq!(services.calls, [EffectStage::DataCompletion]);
            assert_eq!(services.data, [data]);
            let enabled = Profile {
                el2_enabled: true,
                ..context().profile
            };
            assert!(matches!(
                resolve_ordinary_el2_disabled(word, enabled),
                Resolution::Unsupported(_)
            ));
        }
        for word in [DSB_NXS_BASE, ISB_BASE, 0xd503_209f] {
            assert_eq!(
                resolve_ordinary_el2_disabled(word, context().profile),
                Resolution::NotHandled
            );
        }
        for current_el in [ExceptionLevel::El2, ExceptionLevel::El3] {
            assert!(matches!(
                resolve_ordinary_el2_disabled(
                    DSB_BASE | 15 << OPTION_SHIFT,
                    Profile {
                        current_el,
                        ..context().profile
                    }
                ),
                Resolution::Unsupported(_)
            ));
        }
    }

    #[test]
    fn unreported_features_never_silently_disable_required_effects() {
        let base = context();
        for encoded_scope in 0..4 {
            let word = DSB_NXS_BASE | encoded_scope << NXS_SCOPE_SHIFT;
            assert!(matches!(
                resolve(
                    word,
                    Context {
                        xs: Xs::Unreported,
                        ..base
                    }
                ),
                Resolution::Unsupported(_)
            ));
            assert_eq!(resolve(word, base), Resolution::Undefined);
        }
        for option in 0..16 {
            assert!(matches!(
                resolve(
                    ISB_BASE | option << OPTION_SHIFT,
                    Context {
                        brbe_isb: BrbeIsb::Unreported,
                        ..base
                    }
                ),
                Resolution::Unsupported(_)
            ));
            if matches!(option, 0 | 4) {
                continue;
            }
            assert!(matches!(
                resolve(
                    DSB_BASE | option << OPTION_SHIFT,
                    Context {
                        xs: Xs::Unreported,
                        profile: Profile {
                            el2_enabled: true,
                            ..base.profile
                        },
                        hcrx: HcrxAccess::Enabled {
                            effective_value: HCRX_FNXS_MASK
                        },
                        ..base
                    }
                ),
                Resolution::Unsupported(_)
            ));
        }
    }

    #[test]
    fn every_data_option_reaches_service_with_its_effective_nxs() {
        let base = context();
        let forced = Context {
            xs: Xs::Present,
            profile: Profile {
                el2_enabled: true,
                ..base.profile
            },
            hcrx: HcrxAccess::Enabled {
                effective_value: HCRX_FNXS_MASK,
            },
            ..base
        };
        let ordinary = (0..16)
            .filter(|&option| !matches!(option, 0 | 4))
            .map(|option| DSB_BASE | option << OPTION_SHIFT);
        let explicit = (0..4).map(|scope| DSB_NXS_BASE | scope << NXS_SCOPE_SHIFT);
        for word in ordinary.chain(explicit) {
            let request = request(word, forced);
            let RequestKind::Data(data) = request.kind() else {
                unreachable!()
            };
            assert!(data.nxs());
            let mut services = Services::default();
            assert_eq!(request.execute(SOURCE_PC, &mut services), Ok(SOURCE_PC + 4));
            assert_eq!(services.data, [data]);
            assert_eq!(services.calls, [EffectStage::DataCompletion]);
            assert_eq!(services.preflight[0].original_word, word);
        }
    }

    #[test]
    fn unreported_hcrx_is_allowed_only_when_irrelevant_or_proven_disabled() {
        for current_el in [
            ExceptionLevel::El0,
            ExceptionLevel::El1,
            ExceptionLevel::El2,
            ExceptionLevel::El3,
        ] {
            for el2_enabled in [false, true] {
                for xs in [Xs::Unreported, Xs::Absent, Xs::Present] {
                    let context = Context {
                        profile: Profile {
                            current_el,
                            el2_enabled,
                            ..context().profile
                        },
                        xs,
                        hcrx: HcrxAccess::Unreported,
                        brbe_isb: BrbeIsb::Absent,
                    };
                    let ordinary = resolve(DSB_BASE | 15 << OPTION_SHIFT, context);
                    let requires_hcrx = el2_enabled
                        && xs != Xs::Absent
                        && matches!(current_el, ExceptionLevel::El0 | ExceptionLevel::El1);
                    if requires_hcrx {
                        assert!(matches!(ordinary, Resolution::Unsupported(_)));
                    } else {
                        let Resolution::BackendRequired(request) = ordinary else {
                            panic!("irrelevant/unavailable HCRX was not preserved: {ordinary:?}");
                        };
                        let RequestKind::Data(data) = request.kind() else {
                            unreachable!()
                        };
                        assert!(!data.nxs());
                    }
                    assert!(matches!(
                        resolve(ISB_BASE, context),
                        Resolution::BackendRequired(_)
                    ));
                    assert!(matches!(
                        resolve(
                            DSB_NXS_BASE,
                            Context {
                                xs: Xs::Present,
                                ..context
                            }
                        ),
                        Resolution::BackendRequired(_)
                    ));
                }
            }
        }
    }

    #[test]
    fn every_failure_completion_preserves_current_stage_and_completed_prefix() {
        for completion in [
            Completion::None,
            Completion::Partial,
            Completion::Complete,
            Completion::Unknown,
        ] {
            for (stage, word, committed, calls) in [
                (
                    EffectStage::DataCompletion,
                    DSB_BASE | 15 << OPTION_SHIFT,
                    CommittedPrefix::None,
                    1,
                ),
                (
                    EffectStage::InstructionSynchronization,
                    ISB_BASE | 15 << OPTION_SHIFT,
                    CommittedPrefix::None,
                    1,
                ),
                (
                    EffectStage::BrbeRecord,
                    ISB_BASE | 15 << OPTION_SHIFT,
                    CommittedPrefix::InstructionsSynchronized,
                    2,
                ),
            ] {
                let mut services = Services {
                    fail: Some(stage),
                    completion: Some(completion),
                    ..Services::default()
                };
                let context = Context {
                    brbe_isb: BrbeIsb::Records,
                    ..context()
                };
                assert_eq!(
                    request(word, context).execute(SOURCE_PC, &mut services),
                    Err(ExecuteError::Effect {
                        stage,
                        committed,
                        failure: EffectFailure {
                            error: "injected",
                            completion
                        }
                    })
                );
                assert_eq!(services.calls.len(), calls);
                assert_eq!(services.brbe_pc, None);
            }
        }
    }

    #[test]
    fn prepared_permit_is_consumed_without_repeating_preflight() {
        let mut services = Services::default();
        let request = request(DSB_BASE | 15 << OPTION_SHIFT, context());
        services
            .preflight(request.service_request(SOURCE_PC))
            .unwrap();
        assert!(services.calls.is_empty());
        assert_eq!(
            request.execute_preflighted(SOURCE_PC, &mut services, ()),
            Ok(SOURCE_PC + 4)
        );
        assert_eq!(services.preflight.len(), 1);
        assert_eq!(services.calls, [EffectStage::DataCompletion]);
    }
}
