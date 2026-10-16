use super::*;

#[test]
fn every_isb_option_retains_its_raw_option() {
    for option in 0..=OPTION_MASK {
        assert_eq!(
            decode(ISB_CLASS | option << OPTION_SHIFT),
            Some(Operation::InstructionSynchronization {
                option: option as u8
            })
        );
    }
}

#[test]
fn every_sb_crm_selects_execute_as_zero_policy() {
    for option in 0..=OPTION_MASK {
        assert_eq!(
            decode(SB_CLASS | option << OPTION_SHIFT),
            Some(Operation::SpeculationBarrier)
        );
    }
}

#[test]
fn dsb_aliases_do_not_become_completion_fences() {
    for (option, physical) in [(SSBB_OPTION, false), (PSSBB_OPTION, true)] {
        assert_eq!(
            decode(DSB_CLASS | u32::from(option) << OPTION_SHIFT),
            Some(Operation::StoreBypassBarrier { physical })
        );
    }
    for option in [8, 12] {
        assert_eq!(
            decode(DSB_CLASS | option << OPTION_SHIFT),
            Some(Operation::DataCompletion {
                option: option as u8,
                scope: Scope::OuterShareable,
                requirement: Requirement::All,
                nxs: false
            })
        );
    }
}

#[test]
fn ordinary_dsb_options_match_the_source_table() {
    use Requirement::{All, Reads, Writes};
    use Scope::{InnerShareable, Nonshareable, OuterShareable};
    // Options0/4 are the separately tested SSBB/PSSBB aliases.
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
        assert_eq!(
            decode(DSB_CLASS | u32::from(option) << OPTION_SHIFT),
            Some(Operation::DataCompletion {
                option,
                scope,
                requirement,
                nxs: false
            })
        );
    }
}

#[test]
fn every_nxs_scope_retains_nxs() {
    for encoded_scope in 0..=SCOPE_MASK {
        assert_eq!(
            decode(DSB_NXS_CLASS | encoded_scope << NXS_SCOPE_SHIFT),
            Some(Operation::DataCompletion {
                option: encoded_scope as u8,
                scope: scope(encoded_scope),
                requirement: Requirement::All,
                nxs: true
            })
        );
    }
}

#[test]
fn bti_retains_every_target_kind() {
    for targets in 0..=BTI_TARGET_MASK {
        assert_eq!(
            decode(BTI_CLASS | targets << BTI_TARGET_SHIFT),
            Some(Operation::BranchTarget {
                targets: targets as u8
            })
        );
    }
}

#[test]
fn timed_waits_retain_all_registers_including_zero() {
    for (class, kind) in [
        (WFET_CLASS, WaitKind::Event),
        (WFIT_CLASS, WaitKind::Interrupt),
    ] {
        for register in 0..=REGISTER_MASK {
            assert_eq!(
                decode(class | register),
                Some(Operation::Wait {
                    kind,
                    timeout_register: Some(register as u8)
                })
            );
        }
    }
}

#[test]
fn other_hint_slots_require_delegation_and_never_become_nop() {
    for immediate in [0, 7, 8, 19, 22, 39, 40, 48, 127] {
        assert_eq!(
            decode(HINT_CLASS | immediate << HINT_IMMEDIATE_SHIFT),
            Some(Operation::OtherHint {
                immediate: immediate as u8
            })
        );
    }
    // Adjacent DMB and CLREX remain owned by their existing/forthcoming families.
    for word in [
        0xd503_3fbf,
        0xd503_3f5f,
        0xd503_203e,
        0xd503_103f ^ (1 << 8),
    ] {
        assert_eq!(decode(word), None);
    }
}
