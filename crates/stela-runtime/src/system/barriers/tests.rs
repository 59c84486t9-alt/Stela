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
    fn synchronize_instructions(&mut self, _: &mut ()) -> Result<(), EffectFailure<Self::Error>> {
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
