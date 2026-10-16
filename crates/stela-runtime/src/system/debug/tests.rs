use super::*;

fn context(el: ExceptionLevel) -> Context {
    Context {
        profile: Profile {
            current_el: el,
            security: SecurityState::NonSecure,
            el2_enabled: false,
            el3_present: false,
        },
        features: Features {
            aa64: true,
            ..Features::default()
        },
        traps: TrapControls::default(),
        debug: DebugControls {
            breakpoint_count: BANK_SIZE,
            watchpoint_count: BANK_SIZE,
            ..DebugControls::default()
        },
    }
}

fn bank(op2: u8, index: u8) -> Encoding {
    Encoding::new(DEBUG_OP0, DEBUG_EL1_OP1, 0, index, op2)
}

fn is_backend(result: Resolution<BackendRequest>) -> bool {
    matches!(result, Resolution::BackendRequired(_))
}

#[test]
fn selector_space_has_exact_direction_sensitive_allocations() {
    let mut reads = 0;
    let mut writes = 0;
    for op0 in 0..4 {
        for op1 in 0..8 {
            for crn in 0..16 {
                for crm in 0..16 {
                    for op2 in 0..8 {
                        let encoding = Encoding::new(op0, op1, crn, crm, op2);
                        reads += u32::from(decode(encoding, AccessKind::Read).is_some());
                        writes +=
                            u32::from(decode(encoding, AccessKind::Write { value: 0 }).is_some());
                    }
                }
            }
        }
    }
    assert_eq!((reads, writes), (72, 71));
    assert_eq!(decode(OSLAR_EL1, AccessKind::Read), None);
    let ctx = context(ExceptionLevel::El1);
    for request in [
        Request::read(OSLAR_EL1, 0),
        Request::write(OSLSR_EL1, 0, 0),
        Request::write(MDCCSR_EL0, 0, 0),
        Request::read(Encoding::new(3, 7, 15, 15, 7), 0),
    ] {
        assert_eq!(resolve(request, &ctx), Resolution::NotHandled);
    }
    assert_eq!(decode(OSLSR_EL1, AccessKind::Write { value: 0 }), None);
    assert_eq!(decode(MDCCSR_EL0, AccessKind::Write { value: 0 }), None);
    assert_eq!(
        decode(DBGDTR_RX_TX_EL0, AccessKind::Read),
        Some(Register::DbgdtrrxEl0)
    );
    assert_eq!(
        decode(DBGDTR_RX_TX_EL0, AccessKind::Write { value: 0 }),
        Some(Register::DbgdtrtxEl0)
    );
}

#[test]
fn descriptor_selectors_preserve_request_identity() {
    for index in 0..BANK_SIZE * BANK_COUNT {
        for register in [
            Register::DbgbvrEl1(index),
            Register::DbgbcrEl1(index),
            Register::DbgwvrEl1(index),
            Register::DbgwcrEl1(index),
        ] {
            assert_eq!(register.encoding().crm(), index % BANK_SIZE);
        }
    }
    for encoding in [
        MDSCR_EL1,
        MDCCINT_EL1,
        OSLSR_EL1,
        DBGPRCR_EL1,
        MDCCSR_EL0,
        DBGDTR_RX_TX_EL0,
        DBGDTR_EL0,
        MDSELR_EL1,
    ] {
        assert_eq!(
            decode(encoding, AccessKind::Read).unwrap().encoding(),
            encoding
        );
    }
    assert_eq!(
        decode(OSLAR_EL1, AccessKind::Write { value: 0 })
            .unwrap()
            .encoding(),
        OSLAR_EL1
    );
}

#[test]
fn all_indexed_members_obey_count_and_feature_priority() {
    let mut ctx = context(ExceptionLevel::El1);
    for op2 in BREAKPOINT_VALUE_OP2..=WATCHPOINT_CONTROL_OP2 {
        for index in 0..BANK_SIZE {
            for count in 0..=BANK_SIZE {
                ctx.debug.breakpoint_count = count;
                ctx.debug.watchpoint_count = count;
                for kind in [AccessKind::Read, AccessKind::Write { value: u64::MAX }] {
                    let request = Request {
                        encoding: bank(op2, index),
                        kind,
                        rt: 0,
                    };
                    assert_eq!(
                        resolve(request, &ctx) == Resolution::Undefined,
                        index >= count
                    );
                }
            }
        }
    }
    ctx.features.aa64 = false;
    ctx.profile.el2_enabled = true;
    ctx.traps.mdcr_el2_tde = true;
    assert_eq!(
        resolve(Request::read(bank(BREAKPOINT_VALUE_OP2, 0), 0), &ctx),
        Resolution::Undefined
    );
}

#[test]
fn bank_selection_preserves_raw_watchpoint_guard_and_effective_index() {
    let mut ctx = context(ExceptionLevel::El1);
    ctx.features.debug_v8p9 = true;
    ctx.debug.breakpoint_count = BANK_SIZE * BANK_COUNT;
    ctx.debug.watchpoint_count = BANK_SIZE * BANK_COUNT;
    for raw in 0..BANK_COUNT {
        for effective in 0..BANK_COUNT {
            ctx.debug.raw_bank = raw;
            ctx.debug.effective_bank = effective;
            for index in 0..BANK_SIZE {
                for op2 in BREAKPOINT_VALUE_OP2..=WATCHPOINT_CONTROL_OP2 {
                    for count in 0..=BANK_SIZE * BANK_COUNT {
                        ctx.debug.breakpoint_count = count;
                        ctx.debug.watchpoint_count = count;
                        let encoded = bank(op2, index);
                        let request = Request::read(encoded, 0);
                        let range_bank = if op2 < WATCHPOINT_VALUE_OP2 {
                            effective
                        } else {
                            raw
                        };
                        let result = resolve(request, &ctx);
                        if index + range_bank * BANK_SIZE >= count {
                            assert_eq!(result, Resolution::Undefined);
                        } else {
                            let register = match op2 {
                                BREAKPOINT_VALUE_OP2 => {
                                    Register::DbgbvrEl1(index + effective * BANK_SIZE)
                                }
                                BREAKPOINT_CONTROL_OP2 => {
                                    Register::DbgbcrEl1(index + effective * BANK_SIZE)
                                }
                                WATCHPOINT_VALUE_OP2 => {
                                    Register::DbgwvrEl1(index + effective * BANK_SIZE)
                                }
                                WATCHPOINT_CONTROL_OP2 => {
                                    Register::DbgwcrEl1(index + effective * BANK_SIZE)
                                }
                                _ => unreachable!(),
                            };
                            assert_eq!(
                                result,
                                Resolution::BackendRequired(register_request(register, request))
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn el0_privilege_and_halted_dcc_priority_are_distinct() {
    let mut ctx = context(ExceptionLevel::El0);
    ctx.features.debug_v8p9 = true;
    ctx.debug.halted = true;
    ctx.debug.ignore_traps_in_debug = true;
    ctx.traps.mdscr_el1_tdcc = true;
    for encoding in [
        MDSCR_EL1,
        MDCCINT_EL1,
        OSLSR_EL1,
        DBGPRCR_EL1,
        MDSELR_EL1,
        bank(BREAKPOINT_VALUE_OP2, 0),
    ] {
        assert_eq!(
            resolve(Request::read(encoding, 0), &ctx),
            Resolution::Undefined
        );
    }
    assert!(is_backend(resolve(
        Request::write(OSLAR_EL1, 0, 1),
        &context(ExceptionLevel::El1)
    )));
    assert_eq!(
        resolve(Request::write(OSLAR_EL1, 0, 1), &ctx),
        Resolution::Undefined
    );
    for encoding in [MDCCSR_EL0, DBGDTR_RX_TX_EL0, DBGDTR_EL0] {
        assert!(is_backend(resolve(Request::read(encoding, 31), &ctx)));
    }
    ctx.debug.ignore_traps_in_debug = false;
    assert!(matches!(
        resolve(Request::read(MDCCSR_EL0, 0), &ctx),
        Resolution::Trap(_)
    ));
    assert!(is_backend(resolve(Request::read(DBGDTR_EL0, 0), &ctx)));
}

#[test]
fn dcc_el0_trap_routing_uses_raw_tge_before_later_effective_tge() {
    let mut ctx = context(ExceptionLevel::El0);
    ctx.profile.el2_enabled = true;
    ctx.traps.mdscr_el1_tdcc = true;
    ctx.traps.effective_tge = true;
    let request = Request::read(MDCCSR_EL0, 7);
    assert_eq!(
        resolve(request, &ctx),
        Resolution::Trap(Trap::system_access(ExceptionLevel::El1))
    );
    ctx.traps.hcr_el2_tge = true;
    assert_eq!(
        resolve(request, &ctx),
        Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
    );
    ctx.traps.mdscr_el1_tdcc = false;
    ctx.traps.hcr_el2_tge = false;
    assert_eq!(
        resolve(request, &ctx),
        Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
    );
    ctx.profile.el2_enabled = false;
    assert!(is_backend(resolve(request, &ctx)));
}

#[test]
fn dcc_tdcc_requires_fgt_but_tda_and_tde_do_not() {
    let mut ctx = context(ExceptionLevel::El1);
    ctx.profile.el2_enabled = true;
    let request = Request::read(MDCCINT_EL1, 0);
    ctx.traps.mdcr_el2_tdcc = true;
    assert!(is_backend(resolve(request, &ctx)));
    ctx.features.fgt = true;
    assert_eq!(
        resolve(request, &ctx),
        Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
    );
    ctx.features.fgt = false;
    ctx.traps.mdcr_el2_tdcc = false;
    ctx.traps.mdcr_el2_tda = true;
    assert!(matches!(resolve(request, &ctx), Resolution::Trap(_)));
    ctx.traps.mdcr_el2_tda = false;
    ctx.traps.mdcr_el2_tde = true;
    assert!(matches!(resolve(request, &ctx), Resolution::Trap(_)));
    ctx.debug.halted = true;
    ctx.debug.ignore_traps_in_debug = true;
    assert!(is_backend(resolve(request, &ctx)));
}

#[test]
fn os_control_uses_tdosa_and_ignores_tda() {
    let mut ctx = context(ExceptionLevel::El1);
    ctx.profile.el2_enabled = true;
    ctx.traps.mdcr_el2_tda = true;
    for request in [
        Request::write(OSLAR_EL1, 0, 1),
        Request::read(OSLSR_EL1, 0),
        Request::read(DBGPRCR_EL1, 0),
    ] {
        assert!(is_backend(resolve(request, &ctx)));
        let mut trapped = ctx;
        trapped.traps.mdcr_el2_tdosa = true;
        assert_eq!(
            resolve(request, &trapped),
            Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
        );
    }
}

#[test]
fn fine_grained_read_write_traps_are_independent() {
    let mut ctx = context(ExceptionLevel::El1);
    ctx.profile.el2_enabled = true;
    ctx.features.fgt = true;
    for encoding in [
        bank(BREAKPOINT_VALUE_OP2, 0),
        bank(BREAKPOINT_CONTROL_OP2, 0),
        bank(WATCHPOINT_VALUE_OP2, 0),
        bank(WATCHPOINT_CONTROL_OP2, 0),
        MDSCR_EL1,
        DBGPRCR_EL1,
    ] {
        let bit = decode(encoding, AccessKind::Read)
            .unwrap()
            .fine_grained_bit();
        ctx.traps.fine_grained_read_traps = bit;
        ctx.traps.fine_grained_write_traps = 0;
        assert!(matches!(
            resolve(Request::read(encoding, 0), &ctx),
            Resolution::Trap(_)
        ));
        assert!(is_backend(resolve(Request::write(encoding, 0, 0), &ctx)));
        ctx.traps.fine_grained_read_traps = 0;
        ctx.traps.fine_grained_write_traps = bit;
        assert!(is_backend(resolve(Request::read(encoding, 0), &ctx)));
        assert!(matches!(
            resolve(Request::write(encoding, 0, 0), &ctx),
            Resolution::Trap(_)
        ));
    }
}

#[test]
fn software_access_halt_requires_unlocked_enabled_bank_and_loses_to_trap() {
    let mut ctx = context(ExceptionLevel::El1);
    ctx.debug.halting_allowed = true;
    ctx.debug.edscr_tda = true;
    let request = Request::read(bank(BREAKPOINT_VALUE_OP2, 0), 0);
    assert!(matches!(
        resolve(request, &ctx),
        Resolution::BackendRequired(BackendRequest::HaltSoftwareAccess { .. })
    ));
    for changed in [
        DebugControls {
            os_locked: true,
            ..ctx.debug
        },
        DebugControls {
            halting_allowed: false,
            ..ctx.debug
        },
        DebugControls {
            edscr_tda: false,
            ..ctx.debug
        },
    ] {
        let no_halt = Context {
            debug: changed,
            ..ctx
        };
        assert!(matches!(
            resolve(request, &no_halt),
            Resolution::BackendRequired(BackendRequest::Register { .. })
        ));
    }
    assert!(matches!(
        resolve(Request::read(MDSCR_EL1, 0), &ctx),
        Resolution::BackendRequired(BackendRequest::Register { .. })
    ));
    ctx.profile.el2_enabled = true;
    ctx.traps.mdcr_el2_tda = true;
    assert!(matches!(resolve(request, &ctx), Resolution::Trap(_)));
}

#[test]
fn nested_monitor_redirect_and_bank_select_have_exact_gate() {
    let mut ctx = context(ExceptionLevel::El1);
    for nvx in 0..8 {
        ctx.traps.effective_nvx = nvx;
        assert_eq!(
            matches!(
                resolve(Request::read(MDSCR_EL1, 0), &ctx),
                Resolution::BackendRequired(BackendRequest::NestedMonitorControl {
                    offset: MDSCR_NV_OFFSET,
                    ..
                })
            ),
            nvx == 5 || nvx == 7
        );
    }
    assert_eq!(
        resolve(Request::read(MDSELR_EL1, 0), &ctx),
        Resolution::Undefined
    );
    ctx.features.debug_v8p9 = true;
    ctx.features.fgt2 = true;
    ctx.profile.el2_enabled = true;
    ctx.traps.mdselr_read_allowed = true;
    assert!(is_backend(resolve(Request::read(MDSELR_EL1, 0), &ctx)));
    assert!(matches!(
        resolve(Request::write(MDSELR_EL1, 0, 0), &ctx),
        Resolution::Trap(_)
    ));
}

#[test]
fn dcc_width_and_xzr_keep_side_effecting_requests() {
    let ctx = context(ExceptionLevel::El0);
    let request = Request::write(DBGDTR_RX_TX_EL0, 5, 0xaabb_ccdd_1122_3344);
    let Resolution::BackendRequired(BackendRequest::Register { request, width, .. }) =
        resolve(request, &ctx)
    else {
        panic!("DCC transmit request expected")
    };
    assert_eq!(width, TransferWidth::Word);
    assert_eq!(request.write_value(), Some(0x1122_3344));
    for encoding in [DBGDTR_RX_TX_EL0, DBGDTR_EL0] {
        let raw = Request {
            encoding,
            kind: AccessKind::Write { value: u64::MAX },
            rt: 31,
        };
        let Resolution::BackendRequired(BackendRequest::Register { request, .. }) =
            resolve(raw, &ctx)
        else {
            panic!("DCC XZR transmit request expected")
        };
        assert_eq!(request.write_value(), Some(0));
        assert!(is_backend(resolve(Request::read(encoding, 31), &ctx)));
    }
}

#[test]
fn out_of_profile_states_are_explicit_and_resolution_is_pure() {
    let ctx = context(ExceptionLevel::El1);
    let request = Request::read(MDSCR_EL1, 0);
    for profile in [
        Profile {
            security: SecurityState::Secure,
            ..ctx.profile
        },
        Profile {
            security: SecurityState::Realm,
            ..ctx.profile
        },
        Profile {
            el3_present: true,
            ..ctx.profile
        },
        Profile {
            current_el: ExceptionLevel::El2,
            ..ctx.profile
        },
        Profile {
            current_el: ExceptionLevel::El3,
            ..ctx.profile
        },
    ] {
        assert!(matches!(
            resolve(request, &Context { profile, ..ctx }),
            Resolution::Unsupported(_)
        ));
    }
    let before = ctx;
    assert!(is_backend(resolve(request, &ctx)));
    assert_eq!(ctx, before);
}
