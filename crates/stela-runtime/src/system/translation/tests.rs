use super::super::access::*;
use super::*;

fn context() -> Context {
    Context {
        profile: Profile {
            current_el: ExceptionLevel::El1,
            security: SecurityState::NonSecure,
            el2_enabled: false,
            el3_present: false,
        },
        aa64: true,
        readbacks: Readbacks {
            sctlr_el1: Some(0x3060_0981),
            tcr_el1: Some(0x5008_03519),
            ttbr0_el1: Some(0x4001_0000),
            ttbr1_el1: Some(0xabcd_0000_4010_0000),
            mair_el1: Some(0xff),
            amair_el1: Some(0x0123_4567_89ab_cdef),
            par_el1: Some(0x800),
            contextidr_el1: Some(0xfedc_ba98),
            vbar_el1: Some(0x4008_1000),
        },
    }
}

#[test]
fn exact_selectors_match_official_pages_and_do_not_alias() {
    let official = [
        (3, 0, 1, 0, 0),
        (3, 0, 2, 0, 2),
        (3, 0, 2, 0, 0),
        (3, 0, 2, 0, 1),
        (3, 0, 10, 2, 0),
        (3, 0, 10, 3, 0),
        (3, 0, 7, 4, 0),
        (3, 0, 13, 0, 1),
        (3, 0, 12, 0, 0),
    ];
    for (register, (op0, op1, crn, crm, op2)) in Register::ALL.into_iter().zip(official) {
        let encoding = Encoding::new(op0, op1, crn, crm, op2);
        assert_eq!(register.encoding(), encoding);
        assert_eq!(Register::decode(encoding), Some(register));
    }
    let mut recognized = 0;
    for op0 in 0..4 {
        for op1 in 0..8 {
            for crn in 0..16 {
                for crm in 0..16 {
                    for op2 in 0..8 {
                        let encoding = Encoding::new(op0, op1, crn, crm, op2);
                        if Register::decode(encoding).is_some() {
                            recognized += 1;
                        } else {
                            assert_eq!(
                                resolve(Request::read(encoding, 0), &context()),
                                Resolution::NotHandled
                            );
                        }
                    }
                }
            }
        }
    }
    assert_eq!(recognized, Register::ALL.len());
}

#[test]
fn reads_preserve_explicit_values_for_every_destination_including_xzr() {
    let original = context();
    for register in Register::ALL {
        for rt in 0..32 {
            assert_eq!(
                resolve(Request::read(register.encoding(), rt), &original),
                Resolution::Read(original.readbacks.get(register).unwrap())
            );
        }
    }
    assert_eq!(original, context());
}

#[test]
fn every_write_requires_backend_without_mutation_or_reserved_bit_masking() {
    let context = context();
    let before = context;
    for register in Register::ALL {
        for rt in 0..32 {
            for value in [0, 1, u64::MAX, 0x0123_4567_89ab_cdef] {
                let expected = if rt == 31 { 0 } else { value };
                assert_eq!(
                    resolve(Request::write(register.encoding(), rt, value), &context),
                    Resolution::BackendRequired(BackendRequest {
                        register,
                        operation: Operation::Write { value: expected },
                        effect: register.effect(),
                    })
                );
            }
        }
    }
    assert_eq!(context, before);
}

#[test]
fn absent_readbacks_request_real_backend_even_for_xzr() {
    let mut context = context();
    context.readbacks = Readbacks {
        sctlr_el1: None,
        tcr_el1: None,
        ttbr0_el1: None,
        ttbr1_el1: None,
        mair_el1: None,
        amair_el1: None,
        par_el1: None,
        contextidr_el1: None,
        vbar_el1: None,
    };
    for register in Register::ALL {
        for rt in [0, 31] {
            assert_eq!(
                resolve(Request::read(register.encoding(), rt), &context),
                Resolution::BackendRequired(BackendRequest {
                    register,
                    operation: Operation::Read,
                    effect: register.effect(),
                })
            );
        }
    }
}

#[test]
fn el0_is_undefined_before_hypervisor_controls_for_both_directions() {
    for register in Register::ALL {
        for el2_enabled in [false, true] {
            for el3_present in [false, true] {
                let mut context = context();
                context.profile.current_el = ExceptionLevel::El0;
                context.profile.el2_enabled = el2_enabled;
                context.profile.el3_present = el3_present;
                for rt in 0..32 {
                    assert_eq!(
                        resolve(Request::read(register.encoding(), rt), &context),
                        Resolution::Undefined
                    );
                    assert_eq!(
                        resolve(Request::write(register.encoding(), rt, u64::MAX), &context),
                        Resolution::Undefined
                    );
                }
            }
        }
    }
}

#[test]
fn missing_aa64_is_architectural_undefined() {
    let mut context = context();
    context.aa64 = false;
    for register in Register::ALL {
        for el in [
            ExceptionLevel::El0,
            ExceptionLevel::El1,
            ExceptionLevel::El2,
            ExceptionLevel::El3,
        ] {
            context.profile.current_el = el;
            assert_eq!(
                resolve(Request::read(register.encoding(), 0), &context),
                Resolution::Undefined
            );
            assert_eq!(
                resolve(Request::write(register.encoding(), 0, 1), &context),
                Resolution::Undefined
            );
        }
    }
}

#[test]
fn unmodeled_control_paths_are_not_architectural_undefined_or_success() {
    for register in Register::ALL {
        for mode in 0..6 {
            let mut context = context();
            match mode {
                0 => context.profile.el2_enabled = true,
                1 => context.profile.el3_present = true,
                2 => context.profile.security = SecurityState::Secure,
                3 => context.profile.security = SecurityState::Realm,
                4 => context.profile.current_el = ExceptionLevel::El2,
                5 => context.profile.current_el = ExceptionLevel::El3,
                _ => unreachable!(),
            }
            assert!(matches!(
                resolve(Request::read(register.encoding(), 0), &context),
                Resolution::Unsupported(_)
            ));
            assert!(matches!(
                resolve(Request::write(register.encoding(), 0, 0), &context),
                Resolution::Unsupported(_)
            ));
        }
    }
}

#[test]
fn forged_public_write_request_cannot_make_xzr_nonzero() {
    for register in Register::ALL {
        let request = Request {
            encoding: register.encoding(),
            kind: AccessKind::Write { value: u64::MAX },
            rt: 31,
        };
        assert!(matches!(
            resolve(request, &context()),
            Resolution::BackendRequired(BackendRequest {
                operation: Operation::Write { value: 0 },
                ..
            })
        ));
    }
}
