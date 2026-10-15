//! Synchronization, event and architectural hint descriptors.
//! Execution profiles own system effects; recognition does not imply a native NOP.

const BARRIER_MASK: u32 = 0xffff_f0ff;
const DSB_CLASS: u32 = 0xd503_309f;
const DSB_NXS_MASK: u32 = 0xffff_f3ff;
const DSB_NXS_CLASS: u32 = 0xd503_323f;
const ISB_CLASS: u32 = 0xd503_30df;
const SB_CLASS: u32 = 0xd503_30ff;
const OPTION_SHIFT: u32 = 8;
const OPTION_MASK: u32 = 15;
const NXS_SCOPE_SHIFT: u32 = 10;
const SCOPE_MASK: u32 = 3;
const SCOPE_SHIFT: u32 = 2;
const NONSHAREABLE_SCOPE: u32 = 1;
const INNER_SHAREABLE_SCOPE: u32 = 2;
const REQUIREMENT_MASK: u8 = 3;
const READS_OPTION: u8 = 1;
const WRITES_OPTION: u8 = 2;
const SSBB_OPTION: u8 = 0;
const PSSBB_OPTION: u8 = 4;
const BTI_MASK: u32 = 0xffff_ff3f;
const BTI_CLASS: u32 = 0xd503_241f;
const BTI_TARGET_SHIFT: u32 = 6;
const BTI_TARGET_MASK: u32 = 3;
const WFXT_MASK: u32 = 0xffff_ffe0;
const WFET_CLASS: u32 = 0xd503_1000;
const WFIT_CLASS: u32 = 0xd503_1020;
const REGISTER_MASK: u32 = 31;
const HINT_MASK: u32 = 0xffff_f01f;
const HINT_CLASS: u32 = 0xd503_201f;
const HINT_IMMEDIATE_SHIFT: u32 = 5;
const HINT_IMMEDIATE_MASK: u32 = 127;
const YIELD: u32 = 0xd503_203f;
const WFE: u32 = 0xd503_205f;
const WFI: u32 = 0xd503_207f;
const SEV: u32 = 0xd503_209f;
const SEVL: u32 = 0xd503_20bf;
const ESB: u32 = 0xd503_221f;
const TSB: u32 = 0xd503_225f;
const CSDB: u32 = 0xd503_229f;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    All,
    Reads,
    Writes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    OuterShareable,
    Nonshareable,
    InnerShareable,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitKind {
    Event,
    Interrupt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    DataCompletion {
        option: u8,
        scope: Scope,
        requirement: Requirement,
        nxs: bool,
    },
    StoreBypassBarrier {
        physical: bool,
    },
    InstructionSynchronization {
        option: u8,
    },
    SpeculationBarrier,
    ConsumptionBarrier,
    Yield,
    BranchTarget {
        targets: u8,
    },
    SendEvent {
        local: bool,
    },
    Wait {
        kind: WaitKind,
        timeout_register: Option<u8>,
    },
    ErrorSynchronization,
    TraceSynchronization,
    // Delegated to the complete hint dispatcher, never emitted as generic NOP.
    OtherHint {
        immediate: u8,
    },
}

pub fn decode(word: u32) -> Option<Operation> {
    if word & BARRIER_MASK == DSB_CLASS {
        let option = ((word >> OPTION_SHIFT) & OPTION_MASK) as u8;
        if option == SSBB_OPTION || option == PSSBB_OPTION {
            return Some(Operation::StoreBypassBarrier {
                physical: option == PSSBB_OPTION,
            });
        }
        let requirement = match option & REQUIREMENT_MASK {
            READS_OPTION => Requirement::Reads,
            WRITES_OPTION => Requirement::Writes,
            _ => Requirement::All,
        };
        let scope = match option & REQUIREMENT_MASK {
            READS_OPTION | WRITES_OPTION => Scope::None,
            0 => Scope::OuterShareable,
            _ => scope((u32::from(option) >> SCOPE_SHIFT) & SCOPE_MASK),
        };
        return Some(Operation::DataCompletion {
            option,
            scope,
            requirement,
            nxs: false,
        });
    }
    if word & DSB_NXS_MASK == DSB_NXS_CLASS {
        let encoded_scope = (word >> NXS_SCOPE_SHIFT) & SCOPE_MASK;
        return Some(Operation::DataCompletion {
            option: encoded_scope as u8,
            scope: scope(encoded_scope),
            requirement: Requirement::All,
            nxs: true,
        });
    }
    if word & BARRIER_MASK == ISB_CLASS {
        return Some(Operation::InstructionSynchronization {
            option: ((word >> OPTION_SHIFT) & OPTION_MASK) as u8,
        });
    }
    if word & BARRIER_MASK == SB_CLASS {
        // CRm is should-be-zero, not an architectural operand. This profile
        // selects the permitted execute-as-zero outcome for nonzero bits.
        return Some(Operation::SpeculationBarrier);
    }
    if word & BTI_MASK == BTI_CLASS {
        return Some(Operation::BranchTarget {
            targets: ((word >> BTI_TARGET_SHIFT) & BTI_TARGET_MASK) as u8,
        });
    }
    let timed_wait = match word & WFXT_MASK {
        WFET_CLASS => Some(WaitKind::Event),
        WFIT_CLASS => Some(WaitKind::Interrupt),
        _ => None,
    };
    if let Some(kind) = timed_wait {
        return Some(Operation::Wait {
            kind,
            timeout_register: Some((word & REGISTER_MASK) as u8),
        });
    }
    Some(match word {
        YIELD => Operation::Yield,
        WFE => Operation::Wait {
            kind: WaitKind::Event,
            timeout_register: None,
        },
        WFI => Operation::Wait {
            kind: WaitKind::Interrupt,
            timeout_register: None,
        },
        SEV => Operation::SendEvent { local: false },
        SEVL => Operation::SendEvent { local: true },
        ESB => Operation::ErrorSynchronization,
        TSB => Operation::TraceSynchronization,
        CSDB => Operation::ConsumptionBarrier,
        _ if word & HINT_MASK == HINT_CLASS => Operation::OtherHint {
            immediate: ((word >> HINT_IMMEDIATE_SHIFT) & HINT_IMMEDIATE_MASK) as u8,
        },
        _ => return None,
    })
}

fn scope(encoded: u32) -> Scope {
    match encoded {
        NONSHAREABLE_SCOPE => Scope::Nonshareable,
        INNER_SHAREABLE_SCOPE => Scope::InnerShareable,
        _ => Scope::OuterShareable,
    }
}

#[cfg(test)]
mod tests {
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
}
