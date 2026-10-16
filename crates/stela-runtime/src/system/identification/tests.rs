use super::*;

struct Inputs {
    value: Option<u64>,
    choice: Option<bool>,
}
impl Readbacks for Inputs {
    fn readback(&self, key: Readback) -> Option<u64> {
        self.value.map(|value| match key {
            Readback::VirtualMidr => value ^ 0x1000,
            Readback::VirtualMpidr => value ^ 0x2000,
            Readback::DynamicDczid => value ^ 0x3000,
            _ => value,
        })
    }
    fn conditional_tid3(&self, _: Register) -> Option<bool> {
        self.choice
    }
}
fn context(el: ExceptionLevel) -> Context {
    Context {
        profile: Profile {
            current_el: el,
            security: super::super::access::SecurityState::NonSecure,
            el2_enabled: false,
            el3_present: false,
        },
        features: Features {
            aa64: true,
            idst: false,
            idte3: false,
            fgt: false,
            evt: false,
            ccidx: true,
            mte2: false,
        },
        el0_in_host: false,
        hcr_tge: false,
        hcr_tid1: false,
        hcr_tid2: false,
        hcr_tid3: false,
        hcr_tid4: false,
        scr_tid3: false,
        scr_fgt_enabled: false,
        el3_sdd_undef_priority: false,
        el3_sdd_undef: false,
        sctlr_el1_uct: true,
        sctlr_el2_uct: true,
        fgt_read: false,
        fgt_write: false,
    }
}
fn run(register: Register, c: &Context) -> Resolution<BackendRequest> {
    resolve_kind(
        register.encoding(),
        AccessKind::Read,
        c,
        &Inputs {
            value: Some(0x1234),
            choice: Some(false),
        },
    )
}

#[test]
fn selectors_are_unique_and_direction_allocation_is_exact() {
    for (i, r) in ALL_REGISTERS.iter().enumerate() {
        assert_eq!(Register::decode(r.encoding()), Some(*r));
        for other in &ALL_REGISTERS[i + 1..] {
            assert_ne!(r.encoding(), other.encoding());
        }
        let result = resolve_kind(
            r.encoding(),
            AccessKind::Write { value: u64::MAX },
            &context(ExceptionLevel::El1),
            &Inputs {
                value: Some(0),
                choice: None,
            },
        );
        assert_eq!(
            result,
            if *r == Register::CsselrEl1 {
                Resolution::Write(StateWrite {
                    encoding: Register::CsselrEl1.encoding(),
                    value: CACHE_SELECTOR_BASE_MASK,
                })
            } else {
                Resolution::NotHandled
            }
        );
    }
    assert_eq!(
        resolve_kind(
            Encoding::new(3, 7, 15, 15, 7),
            AccessKind::Read,
            &context(ExceptionLevel::El1),
            &Inputs {
                value: None,
                choice: None
            }
        ),
        Resolution::NotHandled
    );
}
#[test]
fn all_privileged_identification_registers_obey_idst_el0_routing() {
    for r in ALL_REGISTERS {
        if matches!(r, Register::CtrEl0 | Register::DczidEl0) {
            continue;
        }
        for idst in [false, true] {
            for el2 in [false, true] {
                for tge in [false, true] {
                    let mut c = context(ExceptionLevel::El0);
                    c.features.idst = idst;
                    c.profile.el2_enabled = el2;
                    c.hcr_tge = tge;
                    assert_eq!(
                        run(r, &c),
                        if !idst || r == Register::CsselrEl1 {
                            Resolution::Undefined
                        } else {
                            trap(if el2 && tge {
                                ExceptionLevel::El2
                            } else {
                                ExceptionLevel::El1
                            })
                        }
                    );
                }
            }
        }
    }
}
#[test]
fn virtual_identity_is_el1_only_and_fgt_precedes_virtual_readback() {
    for (r, virtual_value) in [(Register::MidrEl1, 0x0234), (Register::MpidrEl1, 0x3234)] {
        for el in [
            ExceptionLevel::El1,
            ExceptionLevel::El2,
            ExceptionLevel::El3,
        ] {
            let mut c = context(el);
            c.profile.el2_enabled = true;
            c.features.fgt = true;
            assert_eq!(
                run(r, &c),
                Resolution::Read(if el == ExceptionLevel::El1 {
                    virtual_value
                } else {
                    0x1234
                })
            );
            c.fgt_read = true;
            assert_eq!(
                run(r, &c),
                if el == ExceptionLevel::El1 {
                    trap(ExceptionLevel::El2)
                } else {
                    Resolution::Read(0x1234)
                }
            );
            c.profile.el3_present = true;
            assert_eq!(
                run(r, &c),
                Resolution::Read(if el == ExceptionLevel::El1 {
                    virtual_value
                } else {
                    0x1234
                })
            );
        }
    }
}
#[test]
fn idte3_undefined_priority_precedes_el2_tid3_and_normal_el3_trap_follows_it() {
    for r in ALL_REGISTERS.into_iter().filter(|r| r.is_aa64_feature()) {
        let mut c = context(ExceptionLevel::El1);
        c.profile.el2_enabled = true;
        c.profile.el3_present = true;
        c.features.idte3 = true;
        c.scr_tid3 = true;
        c.hcr_tid3 = true;
        c.el3_sdd_undef = true;
        assert_eq!(run(r, &c), trap(ExceptionLevel::El2));
        c.el3_sdd_undef_priority = true;
        assert_eq!(run(r, &c), Resolution::Undefined);
        c.el3_sdd_undef_priority = false;
        c.hcr_tid3 = false;
        assert_eq!(run(r, &c), Resolution::Undefined);
        c.el3_sdd_undef = false;
        assert_eq!(run(r, &c), trap(ExceptionLevel::El3));
        c.profile.current_el = ExceptionLevel::El3;
        assert_eq!(run(r, &c), Resolution::Read(0x1234));
    }
}
#[test]
fn late_tid3_requires_explicit_zero_register_implementation_choice() {
    for r in ALL_REGISTERS
        .into_iter()
        .filter(|r| r.has_conditional_tid3())
    {
        let mut c = context(ExceptionLevel::El1);
        c.profile.el2_enabled = true;
        c.hcr_tid3 = true;
        for value in [None, Some(0), Some(1)] {
            for choice in [None, Some(false), Some(true)] {
                let actual = resolve_kind(
                    r.encoding(),
                    AccessKind::Read,
                    &c,
                    &Inputs { value, choice },
                );
                let expected = match (value, choice) {
                    (None, _) => {
                        Resolution::BackendRequired(BackendRequest::Readback(Readback::Register(r)))
                    }
                    (Some(0), None) => {
                        Resolution::BackendRequired(BackendRequest::ConditionalTid3(r))
                    }
                    (Some(0), Some(false)) => Resolution::Read(0),
                    _ => trap(ExceptionLevel::El2),
                };
                assert_eq!(actual, expected);
            }
        }
        c.features.fgt = true;
        assert_eq!(
            resolve_kind(
                r.encoding(),
                AccessKind::Read,
                &c,
                &Inputs {
                    value: None,
                    choice: None
                }
            ),
            trap(ExceptionLevel::El2)
        );
    }
}
#[test]
fn ctr_host_and_nonhost_uct_priority_is_distinct() {
    let mut c = context(ExceptionLevel::El0);
    c.profile.el2_enabled = true;
    c.hcr_tid2 = true;
    c.sctlr_el1_uct = false;
    assert_eq!(run(Register::CtrEl0, &c), trap(ExceptionLevel::El1));
    c.hcr_tge = true;
    assert_eq!(run(Register::CtrEl0, &c), trap(ExceptionLevel::El2));
    c.el0_in_host = true;
    assert_eq!(run(Register::CtrEl0, &c), Resolution::Read(0x1234));
    c.sctlr_el2_uct = false;
    assert_eq!(run(Register::CtrEl0, &c), trap(ExceptionLevel::El2));
}
#[test]
fn cache_geometry_tid2_evt_and_fgt_rules_are_register_specific() {
    for r in [
        Register::ClidrEl1,
        Register::CcsidrEl1,
        Register::Ccsidr2El1,
        Register::CsselrEl1,
    ] {
        let mut c = context(ExceptionLevel::El1);
        c.profile.el2_enabled = true;
        c.hcr_tid4 = true;
        assert_eq!(run(r, &c), Resolution::Read(0x1234));
        c.features.evt = true;
        assert_eq!(run(r, &c), trap(ExceptionLevel::El2));
        c.features.evt = false;
        c.features.fgt = true;
        c.fgt_read = true;
        assert_eq!(
            run(r, &c),
            if r == Register::Ccsidr2El1 {
                Resolution::Read(0x1234)
            } else {
                trap(ExceptionLevel::El2)
            }
        );
        c.features.fgt = false;
        c.hcr_tid2 = true;
        assert_eq!(run(r, &c), trap(ExceptionLevel::El2));
    }
}
#[test]
fn cache_selector_writes_preserve_only_implemented_fields_and_correct_fgt_direction() {
    let mut c = context(ExceptionLevel::El1);
    for value in 0..64 {
        for mte2 in [false, true] {
            c.features.mte2 = mte2;
            let mask = CACHE_SELECTOR_BASE_MASK
                | if mte2 && value & 1 == 0 {
                    CACHE_SELECTOR_TAG_BIT
                } else {
                    0
                };
            assert_eq!(
                resolve_kind(
                    Register::CsselrEl1.encoding(),
                    AccessKind::Write { value },
                    &c,
                    &Inputs {
                        value: None,
                        choice: None
                    }
                ),
                Resolution::Write(StateWrite {
                    encoding: Register::CsselrEl1.encoding(),
                    value: value & mask
                })
            );
        }
    }
    c.profile.el2_enabled = true;
    c.features.fgt = true;
    c.fgt_read = true;
    assert_eq!(
        resolve_kind(
            Register::CsselrEl1.encoding(),
            AccessKind::Write { value: 0 },
            &c,
            &Inputs {
                value: None,
                choice: None
            }
        ),
        Resolution::Write(StateWrite {
            encoding: Register::CsselrEl1.encoding(),
            value: 0
        })
    );
    c.fgt_write = true;
    assert_eq!(
        resolve_kind(
            Register::CsselrEl1.encoding(),
            AccessKind::Write { value: 0 },
            &c,
            &Inputs {
                value: None,
                choice: None
            }
        ),
        trap(ExceptionLevel::El2)
    );
}
#[test]
fn absence_routes_unimplemented_id_and_never_creates_fake_values() {
    for r in ALL_REGISTERS {
        let mut c = context(ExceptionLevel::El1);
        c.features.aa64 = false;
        if matches!(r, Register::IdAa64Smfr0El1 | Register::IdAa64Zfr0El1) {
            assert_eq!(run(r, &c), Resolution::Read(0x1234));
            continue;
        }
        assert_eq!(run(r, &c), Resolution::Undefined);
        c.features.idst = true;
        assert_eq!(
            run(r, &c),
            if r == Register::CsselrEl1 {
                Resolution::Undefined
            } else {
                trap(ExceptionLevel::El1)
            }
        );
    }
    let c = context(ExceptionLevel::El1);
    for r in ALL_REGISTERS {
        assert!(matches!(
            resolve_kind(
                r.encoding(),
                AccessKind::Read,
                &c,
                &Inputs {
                    value: None,
                    choice: None
                }
            ),
            Resolution::BackendRequired(_)
        ));
    }
}
#[test]
fn dczid_requires_resolved_dynamic_dzp_and_host_el0_ignores_nonhost_fgt() {
    let mut c = context(ExceptionLevel::El0);
    c.profile.el2_enabled = true;
    c.features.fgt = true;
    c.fgt_read = true;
    assert_eq!(run(Register::DczidEl0, &c), trap(ExceptionLevel::El2));
    c.el0_in_host = true;
    assert_eq!(run(Register::DczidEl0, &c), Resolution::Read(0x2234));
    assert_eq!(
        resolve_kind(
            Register::DczidEl0.encoding(),
            AccessKind::Read,
            &c,
            &Inputs {
                value: None,
                choice: None
            }
        ),
        Resolution::BackendRequired(BackendRequest::Readback(Readback::DynamicDczid))
    );
}
#[test]
fn request_xzr_writes_zero_but_reads_still_perform_access_checks() {
    let c = context(ExceptionLevel::El1);
    let inputs = Inputs {
        value: None,
        choice: None,
    };
    let request = Request {
        encoding: Register::CsselrEl1.encoding(),
        kind: AccessKind::Write { value: u64::MAX },
        rt: 31,
    };
    assert_eq!(
        resolve(request, &c, &inputs),
        Resolution::Write(StateWrite {
            encoding: Register::CsselrEl1.encoding(),
            value: 0
        })
    );
    let c = context(ExceptionLevel::El0);
    assert_eq!(
        resolve(Request::read(Register::MidrEl1.encoding(), 31), &c, &inputs),
        Resolution::Undefined
    );
}
