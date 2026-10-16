use super::*;
fn context(el: ExceptionLevel) -> Context {
    Context {
        aa64: true,
        ecv: true,
        ecv_physical_offset: true,
        secure_el2: false,
        profile: Profile {
            current_el: el,
            security: SecurityState::NonSecure,
            el2_enabled: false,
            el3_present: false,
        },
        highest_el: ExceptionLevel::El1,
        have_el2: false,
        el2_aarch64: true,
        el2_in_host: false,
        el0_in_host: false,
        effective_tge: false,
        scr_ecv_enable: false,
        nested_all: false,
        kernel: KernelControl {
            el0_physical_count: true,
            el0_virtual_count: true,
            el0_physical_timer: true,
            el0_virtual_timer: true,
        },
        hypervisor: HypervisorControl {
            el0_physical_count: true,
            el0_virtual_count: true,
            el1_physical_count: true,
            el1_physical_timer: true,
            el1_physical_timer_host: true,
            el0_physical_timer: true,
            el0_virtual_timer: true,
            ..Default::default()
        },
    }
}
fn denied(outcome: Outcome, level: ExceptionLevel, reason: TrapReason) {
    assert_eq!(outcome, trap(level, reason));
}
fn timer_register(kind: TimerKind, field: TimerField) -> Register {
    Register::TimerEl0 { kind, field }
}
#[test]
fn canonical_selectors_and_xzr_are_not_access_bypasses() {
    let mut allocated = 0;
    for op0 in 0..4 {
        for op1 in 0..8 {
            for crn in 0..16 {
                for crm in 0..16 {
                    for op2 in 0..8 {
                        let encoding = Encoding::new(op0, op1, crn, crm, op2);
                        if let Some(register) = decode(encoding) {
                            assert_eq!(register.encoding(), encoding);
                            allocated += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(allocated, 12);
    let frequency = Encoding::new(
        TIMER_OP0,
        EL0_TIMER_OP1,
        TIMER_CRN,
        COUNTER_CRM,
        FREQUENCY_OP2,
    );
    let mut c = context(ExceptionLevel::El1);
    let request = Request::write(frequency, 31, u64::MAX);
    assert_eq!(
        resolve(request, &c),
        Resolution::BackendRequired(BackendRequest::Frequency(AccessKind::Write { value: 0 }))
    );
    c.profile.current_el = ExceptionLevel::El0;
    c.kernel.el0_physical_count = false;
    c.kernel.el0_virtual_count = false;
    assert!(matches!(
        resolve(Request::read(frequency, 31), &c),
        Resolution::Trap(_)
    ));
    c.kernel.el0_virtual_count = true;
    assert_eq!(
        resolve(Request::read(frequency, 31), &c),
        Resolution::BackendRequired(BackendRequest::Frequency(AccessKind::Read))
    );
    let unowned = Encoding::new(0, 0, 0, 0, 0);
    assert_eq!(
        resolve(Request::read(unowned, 0), &c),
        Resolution::NotHandled
    );
}
#[test]
fn read_only_counter_write_directions_belong_to_allocation_owner() {
    let mut c = context(ExceptionLevel::El0);
    c.aa64 = false;
    c.ecv = false;
    for op2 in [
        PHYSICAL_COUNT_OP2,
        VIRTUAL_COUNT_OP2,
        PHYSICAL_COUNT_SS_OP2,
        VIRTUAL_COUNT_SS_OP2,
    ] {
        let encoding = Encoding::new(TIMER_OP0, EL0_TIMER_OP1, TIMER_CRN, COUNTER_CRM, op2);
        for rt in [0, 31] {
            let request = Request::write(encoding, rt, u64::MAX);
            assert_eq!(resolve(request, &c), Resolution::NotHandled);
        }
    }
}
#[test]
fn feature_and_direction_checks_precede_access_controls() {
    let mut c = context(ExceptionLevel::El0);
    c.aa64 = false;
    c.kernel.el0_physical_count = false;
    assert_eq!(
        plan(Register::CntpctEl0, AccessKind::Read, &c),
        Outcome::Fault(Fault::Undefined)
    );
    c.aa64 = true;
    c.ecv = false;
    for r in [Register::CntpctssEl0, Register::CntvctssEl0] {
        assert_eq!(
            plan(r, AccessKind::Read, &c),
            Outcome::Fault(Fault::Undefined)
        );
    }
    for r in [
        Register::CntpctEl0,
        Register::CntvctEl0,
        Register::CntpctssEl0,
        Register::CntvctssEl0,
    ] {
        assert_eq!(
            plan(r, AccessKind::Write { value: u64::MAX }, &c),
            Outcome::Fault(Fault::Undefined)
        );
    }
}
#[test]
fn frequency_read_gate_is_either_counter_enable_not_both() {
    for p in [false, true] {
        for v in [false, true] {
            for host in [false, true] {
                let mut c = context(ExceptionLevel::El0);
                c.el0_in_host = host;
                c.kernel.el0_physical_count = p;
                c.kernel.el0_virtual_count = v;
                c.hypervisor.el0_physical_count = p;
                c.hypervisor.el0_virtual_count = v;
                let result = plan(Register::CntfrqEl0, AccessKind::Read, &c);
                if p || v {
                    assert_eq!(
                        result,
                        Outcome::Backend(BackendRequest::Frequency(AccessKind::Read))
                    );
                } else {
                    denied(
                        result,
                        if host {
                            ExceptionLevel::El2
                        } else {
                            ExceptionLevel::El1
                        },
                        TrapReason::El0Frequency,
                    );
                }
            }
        }
    }
}
#[test]
fn frequency_writes_require_highest_implemented_el() {
    let mut c = context(ExceptionLevel::El1);
    assert_eq!(
        plan(
            Register::CntfrqEl0,
            AccessKind::Write { value: 24_000_000 },
            &c
        ),
        Outcome::Backend(BackendRequest::Frequency(AccessKind::Write {
            value: 24_000_000
        }))
    );
    c.highest_el = ExceptionLevel::El2;
    assert_eq!(
        plan(Register::CntfrqEl0, AccessKind::Write { value: 1 }, &c),
        Outcome::Fault(Fault::Undefined)
    );
    c.profile.current_el = ExceptionLevel::El0;
    assert_eq!(
        plan(Register::CntkctlEl1, AccessKind::Write { value: 0 }, &c),
        Outcome::Fault(Fault::Undefined)
    );
}
#[test]
fn physical_count_trap_priority_and_tge_routing() {
    for tge in [false, true] {
        for k in [false, true] {
            for h in [false, true] {
                let mut c = context(ExceptionLevel::El0);
                c.profile.el2_enabled = true;
                c.effective_tge = tge;
                c.kernel.el0_physical_count = k;
                c.hypervisor.el1_physical_count = h;
                let actual = plan(Register::CntpctEl0, AccessKind::Read, &c);
                if !k {
                    denied(
                        actual,
                        if tge {
                            ExceptionLevel::El2
                        } else {
                            ExceptionLevel::El1
                        },
                        TrapReason::El0PhysicalCount,
                    );
                } else if !h {
                    denied(actual, ExceptionLevel::El2, TrapReason::El1PhysicalCount);
                } else {
                    assert!(matches!(
                        actual,
                        Outcome::Backend(BackendRequest::Counter { .. })
                    ));
                }
            }
        }
    }
    let mut c = context(ExceptionLevel::El0);
    c.el2_in_host = true;
    c.el0_in_host = true;
    c.hypervisor.el1_physical_count = false;
    c.hypervisor.el0_physical_count = false;
    denied(
        plan(Register::CntpctEl0, AccessKind::Read, &c),
        ExceptionLevel::El2,
        TrapReason::El1PhysicalCount,
    );
    c.effective_tge = true;
    denied(
        plan(Register::CntpctEl0, AccessKind::Read, &c),
        ExceptionLevel::El2,
        TrapReason::El0HostPhysicalCount,
    );
}
#[test]
fn virtual_count_host_and_nonhost_gates_are_distinct() {
    let mut c = context(ExceptionLevel::El0);
    c.profile.el2_enabled = true;
    c.kernel.el0_virtual_count = false;
    c.hypervisor.el1_virtual_count_trap = true;
    denied(
        plan(Register::CntvctEl0, AccessKind::Read, &c),
        ExceptionLevel::El1,
        TrapReason::El0VirtualCount,
    );
    c.kernel.el0_virtual_count = true;
    denied(
        plan(Register::CntvctEl0, AccessKind::Read, &c),
        ExceptionLevel::El2,
        TrapReason::El1VirtualCount,
    );
    c.el0_in_host = true;
    c.hypervisor.el0_virtual_count = false;
    denied(
        plan(Register::CntvctEl0, AccessKind::Read, &c),
        ExceptionLevel::El2,
        TrapReason::El0HostVirtualCount,
    );
    c.hypervisor.el0_virtual_count = true;
    assert_eq!(
        plan(Register::CntvctEl0, AccessKind::Read, &c),
        Outcome::Backend(BackendRequest::Counter {
            kind: TimerKind::Virtual,
            offset: CounterOffset::None,
            ordering: CounterOrdering::CounterReads
        })
    );
}
#[test]
fn virtual_offset_survives_el2_disabled_but_present() {
    let mut c = context(ExceptionLevel::El0);
    c.have_el2 = true;
    assert_eq!(
        plan(Register::CntvctssEl0, AccessKind::Read, &c),
        Outcome::Backend(BackendRequest::Counter {
            kind: TimerKind::Virtual,
            offset: CounterOffset::VirtualEl2,
            ordering: CounterOrdering::SelfSynchronized
        })
    );
    c.el2_aarch64 = false;
    assert_eq!(
        plan(Register::CntvctEl0, AccessKind::Read, &c),
        Outcome::Unsupported(Requirement::Aarch32El2CounterOffset)
    );
}
#[test]
fn physical_offset_requires_every_feature_and_enable() {
    for bits in 0u8..32 {
        let mut c = context(ExceptionLevel::El1);
        c.ecv_physical_offset = bits & 1 != 0;
        c.profile.el2_enabled = bits & 2 != 0;
        c.profile.el3_present = bits & 4 != 0;
        c.scr_ecv_enable = bits & 8 != 0;
        c.hypervisor.ecv = bits & 16 != 0;
        let expected = c.ecv_physical_offset
            && c.profile.el2_enabled
            && (!c.profile.el3_present || c.scr_ecv_enable)
            && c.hypervisor.ecv;
        assert_eq!(
            physical_offset(&c),
            if expected {
                CounterOffset::PhysicalEl2
            } else {
                CounterOffset::None
            }
        );
    }
}
#[test]
fn all_physical_timer_fields_and_directions_share_ordered_gates() {
    for field in [
        TimerField::Control,
        TimerField::CompareValue,
        TimerField::TimerValue,
    ] {
        for access in [AccessKind::Read, AccessKind::Write { value: u64::MAX }] {
            let mut c = context(ExceptionLevel::El0);
            c.profile.el2_enabled = true;
            c.kernel.el0_physical_timer = false;
            c.hypervisor.el1_physical_timer = false;
            denied(
                plan(timer_register(TimerKind::Physical, field), access, &c),
                ExceptionLevel::El1,
                TrapReason::El0PhysicalTimer,
            );
            c.kernel.el0_physical_timer = true;
            denied(
                plan(timer_register(TimerKind::Physical, field), access, &c),
                ExceptionLevel::El2,
                TrapReason::El1PhysicalTimer,
            );
            c.profile.current_el = ExceptionLevel::El1;
            c.nested_all = true;
            denied(
                plan(timer_register(TimerKind::Physical, field), access, &c),
                ExceptionLevel::El2,
                TrapReason::El1PhysicalTimer,
            );
        }
    }
}
#[test]
fn virtual_timer_trap_requires_ecv_and_precedes_nested_memory() {
    let mut c = context(ExceptionLevel::El1);
    c.nested_all = true;
    c.profile.el2_enabled = true;
    c.hypervisor.el1_virtual_timer_trap = true;
    let r = timer_register(TimerKind::Virtual, TimerField::Control);
    denied(
        plan(r, AccessKind::Read, &c),
        ExceptionLevel::El2,
        TrapReason::El1VirtualTimer,
    );
    c.ecv = false;
    assert_eq!(
        plan(r, AccessKind::Read, &c),
        Outcome::Backend(BackendRequest::NestedMemory {
            offset: CNTV_NVMEM_CTL,
            access: AccessKind::Read
        })
    );
}
#[test]
fn nested_all_redirects_only_control_and_compare() {
    let mut c = context(ExceptionLevel::El1);
    c.nested_all = true;
    for (kind, field, offset) in [
        (TimerKind::Physical, TimerField::Control, CNTP_NVMEM_CTL),
        (
            TimerKind::Physical,
            TimerField::CompareValue,
            CNTP_NVMEM_CVAL,
        ),
        (TimerKind::Virtual, TimerField::Control, CNTV_NVMEM_CTL),
        (
            TimerKind::Virtual,
            TimerField::CompareValue,
            CNTV_NVMEM_CVAL,
        ),
    ] {
        assert_eq!(
            plan(
                timer_register(kind, field),
                AccessKind::Write { value: 99 },
                &c
            ),
            Outcome::Backend(BackendRequest::NestedMemory {
                offset,
                access: AccessKind::Write { value: 99 }
            })
        );
    }
    for kind in [TimerKind::Physical, TimerKind::Virtual] {
        assert!(matches!(
            plan(
                timer_register(kind, TimerField::TimerValue),
                AccessKind::Read,
                &c
            ),
            Outcome::Backend(BackendRequest::Timer {
                field: TimerField::TimerValue,
                ..
            })
        ));
    }
}
#[test]
fn host_bank_aliases_match_security_rules() {
    let mut c = context(ExceptionLevel::El0);
    c.el0_in_host = true;
    for (secure, sel2, physical, virtual_bank) in [
        (
            false,
            false,
            TimerBank::HostPhysical,
            TimerBank::HostVirtual,
        ),
        (
            true,
            true,
            TimerBank::HostSecurePhysical,
            TimerBank::HostSecureVirtual,
        ),
        (
            true,
            false,
            TimerBank::PhysicalEl1,
            TimerBank::HostSecureVirtual,
        ),
    ] {
        c.profile.security = if secure {
            SecurityState::Secure
        } else {
            SecurityState::NonSecure
        };
        c.secure_el2 = sel2;
        for (kind, bank) in [
            (TimerKind::Physical, physical),
            (TimerKind::Virtual, virtual_bank),
        ] {
            assert!(
                matches!(plan(timer_register(kind, TimerField::TimerValue), AccessKind::Read, &c), Outcome::Backend(BackendRequest::Timer { bank: b, .. }) if b == bank)
            );
        }
    }
}
#[test]
fn timer_value_signed_low_word_and_modular_arithmetic() {
    let values = [
        0,
        1,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x1234_5678_8000_0001,
        u64::MAX,
    ];
    for input in values {
        for count in [0, 1, u64::MAX] {
            for offset in [0, 7, u64::MAX] {
                let compare = compare_from_timer_value(input, count, offset);
                assert_eq!(
                    timer_value(compare, count, offset, true),
                    Some(u64::from(input as u32))
                );
                assert_eq!(timer_value(compare, count, offset, false), None);
            }
        }
    }
}
#[test]
fn control_read_known_bits_and_interrupt_mask_are_independent() {
    for control in 0..16 {
        for condition in [false, true] {
            let (value, known) = control_value(control, condition);
            assert_eq!(value & TIMER_WRITABLE_MASK, control & TIMER_WRITABLE_MASK);
            assert_eq!(value & !(TIMER_WRITABLE_MASK | TIMER_ISTATUS), 0);
            if control & TIMER_ENABLE != 0 {
                assert_eq!(known, u64::MAX);
                assert_eq!(value & TIMER_ISTATUS != 0, condition);
            } else {
                assert_eq!(known, !TIMER_ISTATUS);
            }
            assert_eq!(
                interrupt_asserted(control, condition),
                control & TIMER_ENABLE != 0 && control & TIMER_IMASK == 0 && condition
            );
        }
    }
}
#[test]
fn current_el2_or_el3_never_falls_through_to_success() {
    for el in [ExceptionLevel::El2, ExceptionLevel::El3] {
        let c = context(el);
        assert_eq!(
            plan(Register::CntfrqEl0, AccessKind::Read, &c),
            Outcome::Unsupported(Requirement::CurrentEl2OrEl3)
        );
    }
}
