//! Stage-2 data aborts carry the faulting instruction's syndrome where Arm
//! defines one.
use super::*;
use crate::machine::mmu::{Fault, FaultKind, SecondStage};

const ISV: u64 = 1 << 24;

fn stage2(walk: bool) -> Fault {
    Fault {
        kind: FaultKind::Translation,
        level: 3,
        second_stage: Some(SecondStage {
            ipa: 0x8000_0000,
            walk,
        }),
    }
}

fn syndrome(word: u32, fault: Fault, write: bool) -> u64 {
    let mut machine = machine(&[word]);
    machine.cpu.set_pstate(Pstate::reset(1));
    machine.cpu.pc = BASE;
    machine
        .data_abort_exception(0x8000_0000, fault, write, false)
        .syndrome
}

#[test]
fn a_stage2_fault_of_a_single_register_access_reports_its_instruction() {
    // ldrsh w3, [x1]: SAS 01, SSE, SRT 3, SF 0, AR 0.
    let iss = syndrome(0x79c0_0023, stage2(false), false);
    assert_eq!(iss & 0x01ff_c000, ISV | 1 << 22 | 1 << 21 | 3 << 16);
    // stlr x5, [x1]: SAS 11, SRT 5, SF, AR and WnR.
    let iss = syndrome(0xc89f_fc25, stage2(false), true);
    assert_eq!(
        iss & 0x01ff_c040,
        ISV | 3 << 22 | 5 << 16 | 1 << 15 | 1 << 14 | 1 << 6
    );
}

#[test]
fn writeback_forms_walks_and_stage1_faults_have_no_instruction_syndrome() {
    // ldr x3, [x1], #8.
    assert_eq!(syndrome(0xf840_8423, stage2(false), false) & ISV, 0);
    // ldr x3, [x1] on a stage-1 walk's stage-2 translation.
    assert_eq!(syndrome(0xf940_0023, stage2(true), false) & ISV, 0);
    assert_eq!(
        syndrome(0xf940_0023, Fault::stage1(FaultKind::Translation, 3), false) & ISV,
        0
    );
}
