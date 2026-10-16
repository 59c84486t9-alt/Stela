//! Barriers, events and hints: DSB, ISB, SB, WFE/WFI, SEV, YIELD, NOP and others.

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
mod tests;
