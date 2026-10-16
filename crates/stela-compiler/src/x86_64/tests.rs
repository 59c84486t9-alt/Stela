use super::*;
use crate::aarch64::system::synchronization::{
    Operation as Synchronization, Requirement, Scope, WaitKind,
};

#[test]
fn constructed_context_operations_return_an_explicit_error() {
    const BARRIER_OPTION_OSH: u8 = 3;
    const BARRIER_OPTION_SY: u8 = 15;
    const BTI_JC_TARGETS: u8 = 3;
    const RESERVED_HINT_IMMEDIATE: u8 = 127;
    let pc = GuestAddress(0x1000);
    for operation in [
        Synchronization::DataCompletion {
            option: BARRIER_OPTION_OSH,
            scope: Scope::OuterShareable,
            requirement: Requirement::All,
            nxs: false,
        },
        Synchronization::InstructionSynchronization {
            option: BARRIER_OPTION_SY,
        },
        Synchronization::StoreBypassBarrier { physical: false },
        Synchronization::StoreBypassBarrier { physical: true },
        Synchronization::BranchTarget {
            targets: BTI_JC_TARGETS,
        },
        Synchronization::Wait {
            kind: WaitKind::Event,
            timeout_register: None,
        },
        Synchronization::SendEvent { local: false },
        Synchronization::ErrorSynchronization,
        Synchronization::TraceSynchronization,
        Synchronization::OtherHint {
            immediate: RESERVED_HINT_IMMEDIATE,
        },
    ] {
        let instructions = [
            Instruction {
                pc,
                operation: Operation::Nop,
            },
            Instruction {
                pc: GuestAddress(pc.0 + size_of::<u32>() as u64),
                operation: Operation::Synchronization(operation),
            },
        ];
        assert!(
            matches!(Emitter.emit_for_target(&instructions, crate::TargetCpu::Baseline),
            Err(UnsupportedReason::PrivilegedOperation { address }) if address == instructions[1].pc)
        );
    }
}
