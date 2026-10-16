use super::super::access::SecurityState;
use super::*;
fn context(level: ExceptionLevel) -> Context {
    let no_traps = ThreadIdTrapBits {
        el0: false,
        read_only_el0: false,
        el1: false,
    };
    Context {
        profile: Profile {
            current_el: level,
            security: SecurityState::NonSecure,
            el2_enabled: false,
            el3_present: false,
        },
        features: Features {
            aa64: true,
            pan: true,
            uao: true,
            dit: true,
            ssbs: SsbsFeature::ReadWrite,
            mte: MteFeature::TwoOrLater,
            fine_grained_traps: true,
        },
        controls: Controls {
            el0_in_host: false,
            sctlr_el1_uma: true,
            hcr_el2_tge: false,
            effective_hcr_el2_nvx: 0,
            scr_el3_fgt_enable: false,
            thread_id_read_traps: no_traps,
            thread_id_write_traps: no_traps,
        },
    }
}
fn snapshot(pstate: u64) -> Snapshot {
    Snapshot {
        pstate: Some(pstate),
        thread_id_el0: Some(0x0123456789abcdef),
        thread_id_read_only_el0: Some(0xfedcba9876543210),
        thread_id_el1: Some(0x55aa55aa55aa55aa),
        stack_pointer_el0: Some(0x89abcdef01234567),
    }
}
fn immediate(op1: u8, op2: u8, operand: u8) -> Request {
    Request::write(Encoding::new(0, op1, 4, operand, op2), 31, 0)
}
fn pstate_update(field: PstateField, mask: u64, value: u64) -> Resolution<BackendRequest> {
    Resolution::BackendRequired(BackendRequest::Pstate { field, mask, value })
}

#[test]
fn nzcv_reads_and_writes_preserve_unselected_bits_and_xzr_source() {
    for level in [ExceptionLevel::El0, ExceptionLevel::El1] {
        let context = context(level);
        for bits in 0..16 {
            let input = (bits << 28) | !NZCV_MASK;
            let state = snapshot(input);
            let before = state;
            for rt in 0..=31 {
                assert_eq!(
                    resolve(Request::read(NZCV, rt), &context, &state),
                    Resolution::Read(bits << 28)
                );
                let write = Request::write(NZCV, rt, input);
                assert_eq!(
                    resolve(write, &context, &state),
                    Resolution::Write(StateWrite {
                        encoding: NZCV,
                        value: if rt == 31 { 0 } else { bits << 28 }
                    })
                );
            }
            assert_eq!(state, before);
        }
    }
}

#[test]
fn every_register_masks_readback_and_returns_unapplied_external_effect() {
    let context = context(ExceptionLevel::El1);
    let state = snapshot(u64::MAX);
    for (register, field, mask) in [
        (DAIF, PstateField::Daif, DAIF_MASK),
        (SPSEL, PstateField::SpSelect, SP_SELECT_MASK),
        (PAN, PstateField::Pan, PAN_MASK),
        (UAO, PstateField::Uao, UAO_MASK),
        (DIT, PstateField::Dit, DIT_MASK),
        (SSBS, PstateField::Ssbs, SSBS_MASK),
        (TCO, PstateField::Tco, TCO_MASK),
    ] {
        for rt in 0..=31 {
            assert_eq!(
                resolve(Request::read(register, rt), &context, &state),
                Resolution::Read(mask)
            );
            assert_eq!(
                resolve(Request::write(register, rt, u64::MAX), &context, &state),
                pstate_update(field, mask, if rt == 31 { 0 } else { mask })
            );
            assert_eq!(
                resolve(Request::write(register, rt, !mask), &context, &state),
                pstate_update(field, mask, 0)
            );
        }
    }
}

#[test]
fn immediate_one_bit_fields_accept_every_crm_and_use_only_low_bit() {
    let context = context(ExceptionLevel::El1);
    let state = snapshot(u64::MAX);
    for (op1, op2, field, mask) in [
        (0, 3, PstateField::Uao, UAO_MASK),
        (0, 4, PstateField::Pan, PAN_MASK),
        (0, 5, PstateField::SpSelect, SP_SELECT_MASK),
        (3, 1, PstateField::Ssbs, SSBS_MASK),
        (3, 2, PstateField::Dit, DIT_MASK),
        (3, 4, PstateField::Tco, TCO_MASK),
    ] {
        for operand in 0..16 {
            assert_eq!(
                resolve(immediate(op1, op2, operand), &context, &state),
                pstate_update(field, mask, if operand & 1 != 0 { mask } else { 0 })
            );
        }
    }
}

#[test]
fn daif_immediate_mask_and_trap_precedence_cover_all_control_combinations() {
    for level in [ExceptionLevel::El0, ExceptionLevel::El1] {
        for in_host in [false, true] {
            for uma in [false, true] {
                for el2 in [false, true] {
                    for tge in [false, true] {
                        let mut context = context(level);
                        context.controls.el0_in_host = in_host;
                        context.controls.sctlr_el1_uma = uma;
                        context.profile.el2_enabled = el2;
                        context.controls.hcr_el2_tge = tge;
                        let trap = level == ExceptionLevel::El0 && (in_host || !uma);
                        let target = if el2 && tge {
                            ExceptionLevel::El2
                        } else {
                            ExceptionLevel::El1
                        };
                        for operand in 0..16 {
                            let mask = u64::from(operand) << DAIF_SHIFT;
                            for (op2, value) in [(6, mask), (7, 0)] {
                                let expected = if trap {
                                    Resolution::Trap(Trap::system_access(target))
                                } else {
                                    pstate_update(PstateField::Daif, mask, value)
                                };
                                assert_eq!(
                                    resolve(
                                        immediate(3, op2, operand),
                                        &context,
                                        &snapshot(u64::MAX)
                                    ),
                                    expected
                                );
                            }
                        }
                        for rt in [0, 31] {
                            let read =
                                resolve(Request::read(DAIF, rt), &context, &snapshot(u64::MAX));
                            assert_eq!(
                                read,
                                if trap {
                                    Resolution::Trap(Trap::system_access(target))
                                } else {
                                    Resolution::Read(DAIF_MASK)
                                }
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn privilege_checks_apply_even_for_xzr_and_zero_immediates() {
    let context = context(ExceptionLevel::El0);
    for register in [CURRENT_EL, SPSEL, PAN, UAO, SP_EL0, TPIDR_EL1] {
        assert_eq!(
            resolve(Request::read(register, 31), &context, &snapshot(u64::MAX)),
            Resolution::Undefined
        );
    }
    for register in [SPSEL, PAN, UAO, SP_EL0, TPIDR_EL1, TPIDRRO_EL0] {
        assert_eq!(
            resolve(
                Request::write(register, 31, u64::MAX),
                &context,
                &snapshot(u64::MAX)
            ),
            Resolution::Undefined
        );
    }
    for op2 in [3, 4, 5] {
        assert_eq!(
            resolve(immediate(0, op2, 0), &context, &snapshot(0)),
            Resolution::Undefined
        );
    }
    assert_eq!(
        resolve(Request::write(CURRENT_EL, 0, 0), &context, &snapshot(0)),
        Resolution::NotHandled
    );
}

#[test]
fn missing_features_and_ssbs_versions_have_distinct_allocation_contracts() {
    let mut context = context(ExceptionLevel::El1);
    context.features.pan = false;
    context.features.uao = false;
    context.features.dit = false;
    context.features.ssbs = SsbsFeature::Absent;
    context.features.mte = MteFeature::Absent;
    for register in [PAN, UAO, DIT, SSBS, TCO] {
        for request in [Request::read(register, 31), Request::write(register, 31, 0)] {
            assert_eq!(
                resolve(request, &context, &snapshot(0)),
                Resolution::Undefined
            );
        }
    }
    for (op1, op2) in [(0, 3), (0, 4), (3, 1), (3, 2), (3, 4)] {
        assert_eq!(
            resolve(immediate(op1, op2, 0), &context, &snapshot(0)),
            Resolution::Undefined
        );
    }
    context.features.ssbs = SsbsFeature::ImmediateOnly;
    assert_eq!(
        resolve(immediate(3, 1, 1), &context, &snapshot(0)),
        pstate_update(PstateField::Ssbs, SSBS_MASK, SSBS_MASK)
    );
    assert_eq!(
        resolve(Request::read(SSBS, 0), &context, &snapshot(0)),
        Resolution::Undefined
    );
}

#[test]
fn mte1_implementation_defined_choices_are_independent() {
    for raz_wi in [false, true] {
        for ignored in [false, true] {
            let mut context = context(ExceptionLevel::El0);
            context.features.mte = MteFeature::One {
                register_raz_wi: raz_wi,
                immediate_ignored: ignored,
            };
            assert_eq!(
                resolve(Request::read(TCO, 0), &context, &snapshot(u64::MAX)),
                Resolution::Read(if raz_wi { 0 } else { TCO_MASK })
            );
            assert_eq!(
                resolve(Request::write(TCO, 0, u64::MAX), &context, &snapshot(0)),
                if raz_wi {
                    Resolution::BackendRequired(BackendRequest::IgnoreTcoWrite)
                } else {
                    pstate_update(PstateField::Tco, TCO_MASK, TCO_MASK)
                }
            );
            assert_eq!(
                resolve(immediate(3, 4, 15), &context, &snapshot(0)),
                if ignored {
                    Resolution::BackendRequired(BackendRequest::IgnoreTcoWrite)
                } else {
                    pstate_update(PstateField::Tco, TCO_MASK, TCO_MASK)
                }
            );
        }
    }
}

#[test]
fn current_el_uses_effective_nv_low_bit_and_sp_el0_rejects_active_alias() {
    let mut context = context(ExceptionLevel::El1);
    for nvx in 0..8 {
        context.controls.effective_hcr_el2_nvx = nvx;
        assert_eq!(
            resolve(Request::read(CURRENT_EL, 31), &context, &snapshot(0)),
            Resolution::Read(if nvx & 1 != 0 { 8 } else { 4 })
        );
    }
    for rt in 0..=31 {
        for access in [
            Request::read(SP_EL0, rt),
            Request::write(SP_EL0, rt, u64::MAX),
        ] {
            assert_eq!(
                resolve(access, &context, &snapshot(0)),
                Resolution::Undefined
            );
        }
        assert_eq!(
            resolve(Request::read(SP_EL0, rt), &context, &snapshot(1)),
            Resolution::Read(snapshot(1).stack_pointer_el0.unwrap())
        );
        assert_eq!(
            resolve(Request::write(SP_EL0, rt, u64::MAX), &context, &snapshot(1)),
            Resolution::Write(StateWrite {
                encoding: SP_EL0,
                value: if rt == 31 { 0 } else { u64::MAX }
            })
        );
    }
}

#[test]
fn thread_id_traps_cover_features_security_gate_host_and_direction() {
    for level in [ExceptionLevel::El0, ExceptionLevel::El1] {
        for el2 in [false, true] {
            for fgt in [false, true] {
                for el3 in [false, true] {
                    for gate in [false, true] {
                        for host in [false, true] {
                            let mut context = context(level);
                            context.profile.el2_enabled = el2;
                            context.features.fine_grained_traps = fgt;
                            context.profile.el3_present = el3;
                            context.controls.scr_el3_fgt_enable = gate;
                            context.controls.el0_in_host = host;
                            context.controls.thread_id_read_traps = ThreadIdTrapBits {
                                el0: true,
                                read_only_el0: true,
                                el1: true,
                            };
                            let expected_trap = el2
                                && fgt
                                && (!el3 || gate)
                                && (level != ExceptionLevel::El0 || !host);
                            for register in [TPIDR_EL0, TPIDRRO_EL0, TPIDR_EL1] {
                                let read =
                                    resolve(Request::read(register, 31), &context, &snapshot(0));
                                let expected = if level == ExceptionLevel::El0
                                    && register == TPIDR_EL1
                                {
                                    Resolution::Undefined
                                } else if expected_trap {
                                    Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
                                } else {
                                    Resolution::Read(match register {
                                        TPIDR_EL0 => snapshot(0).thread_id_el0.unwrap(),
                                        TPIDRRO_EL0 => snapshot(0).thread_id_read_only_el0.unwrap(),
                                        _ => snapshot(0).thread_id_el1.unwrap(),
                                    })
                                };
                                assert_eq!(read, expected);
                                // Read control must never act as write control.
                                let write = resolve(
                                    Request::write(register, 31, u64::MAX),
                                    &context,
                                    &snapshot(0),
                                );
                                let expected =
                                    if level == ExceptionLevel::El0 && register != TPIDR_EL0 {
                                        Resolution::Undefined
                                    } else {
                                        Resolution::Write(StateWrite {
                                            encoding: register,
                                            value: 0,
                                        })
                                    };
                                assert_eq!(write, expected);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn unrelated_encodings_and_unsupported_levels_do_not_succeed() {
    let mut context = context(ExceptionLevel::El1);
    assert_eq!(
        resolve(
            Request::read(Encoding::new(3, 7, 15, 15, 7), 0),
            &context,
            &snapshot(0)
        ),
        Resolution::NotHandled
    );
    assert_eq!(
        resolve(immediate(0, 0, 0), &context, &snapshot(0)),
        Resolution::NotHandled
    );
    assert_eq!(
        resolve(immediate(3, 3, 6), &context, &snapshot(0)),
        Resolution::NotHandled
    );
    for level in [ExceptionLevel::El2, ExceptionLevel::El3] {
        context.profile.current_el = level;
        assert!(matches!(
            resolve(Request::read(NZCV, 0), &context, &snapshot(0)),
            Resolution::Unsupported(_)
        ));
    }
}

#[test]
fn thread_id_write_traps_are_checked_after_privilege_and_xzr_normalization() {
    for level in [ExceptionLevel::El0, ExceptionLevel::El1] {
        for security in [
            SecurityState::NonSecure,
            SecurityState::Secure,
            SecurityState::Realm,
        ] {
            let mut context = context(level);
            context.profile.security = security;
            context.profile.el2_enabled = true;
            context.controls.thread_id_write_traps = ThreadIdTrapBits {
                el0: true,
                read_only_el0: true,
                el1: true,
            };
            for register in [TPIDR_EL0, TPIDRRO_EL0, TPIDR_EL1] {
                for rt in [0, 31] {
                    let expected = if level == ExceptionLevel::El0 && register != TPIDR_EL0 {
                        Resolution::Undefined
                    } else {
                        Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
                    };
                    assert_eq!(
                        resolve(
                            Request::write(register, rt, u64::MAX),
                            &context,
                            &snapshot(0)
                        ),
                        expected
                    );
                }
            }
        }
    }
}

#[test]
fn unavailable_storage_never_fabricates_readback_or_masks_a_prior_fault() {
    let mut context = context(ExceptionLevel::El0);
    let state = Snapshot {
        pstate: None,
        thread_id_el0: None,
        thread_id_read_only_el0: None,
        thread_id_el1: None,
        stack_pointer_el0: None,
    };
    for register in [NZCV, DAIF, DIT, SSBS, TCO, TPIDR_EL0, TPIDRRO_EL0] {
        assert!(matches!(
            resolve(Request::read(register, 31), &context, &state),
            Resolution::Unsupported(_)
        ));
    }
    assert_eq!(
        resolve(Request::write(NZCV, 0, u64::MAX), &context, &state),
        Resolution::Write(StateWrite {
            encoding: NZCV,
            value: NZCV_MASK
        })
    );
    assert_eq!(
        resolve(Request::write(DIT, 0, u64::MAX), &context, &state),
        pstate_update(PstateField::Dit, DIT_MASK, DIT_MASK)
    );
    assert_eq!(
        resolve(Request::read(SP_EL0, 0), &context, &state),
        Resolution::Undefined
    );
    context.controls.sctlr_el1_uma = false;
    assert_eq!(
        resolve(Request::read(DAIF, 31), &context, &state),
        Resolution::Trap(Trap::system_access(ExceptionLevel::El1))
    );
    context.profile.el2_enabled = true;
    context.controls.thread_id_read_traps.el0 = true;
    assert_eq!(
        resolve(Request::read(TPIDR_EL0, 31), &context, &state),
        Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
    );
    context.profile.current_el = ExceptionLevel::El1;
    assert!(matches!(
        resolve(Request::write(SP_EL0, 0, 0), &context, &state),
        Resolution::Unsupported(_)
    ));
    context.features.dit = false;
    assert_eq!(
        resolve(Request::read(DIT, 31), &context, &state),
        Resolution::Undefined
    );
}
