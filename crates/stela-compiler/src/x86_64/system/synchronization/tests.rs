use super::*;
use crate::aarch64::system::synchronization::{Requirement, Scope, WaitKind};
use alloc::vec;
use alloc::vec::Vec;

#[test]
fn baseline_barriers_share_real_serialization() {
    let expected: Vec<_> = [MOV_R8_RBX, XOR_EAX_EAX, CPUID, MOV_RBX_R8].concat();
    assert_eq!(expected.len(), 10);
    for operation in [
        Operation::ConsumptionBarrier,
        Operation::SpeculationBarrier,
        Operation::StoreBypassBarrier { physical: false },
        Operation::StoreBypassBarrier { physical: true },
    ] {
        let mut code = vec![];
        assert_eq!(emit(&mut code, &operation), Ok(()));
        assert_eq!(code, expected);
    }
}

#[test]
fn yield_uses_pause() {
    let mut code = vec![];
    assert_eq!(emit(&mut code, &Operation::Yield), Ok(()));
    assert_eq!(code, PAUSE);
}

#[test]
fn context_operations_decline_without_partial_output() {
    let sentinel = vec![0xcc];
    for operation in [
        Operation::DataCompletion {
            option: 15,
            scope: Scope::OuterShareable,
            requirement: Requirement::All,
            nxs: false,
        },
        Operation::InstructionSynchronization { option: 15 },
        Operation::BranchTarget { targets: 3 },
        Operation::SendEvent { local: false },
        Operation::SendEvent { local: true },
        Operation::Wait {
            kind: WaitKind::Event,
            timeout_register: None,
        },
        Operation::Wait {
            kind: WaitKind::Interrupt,
            timeout_register: Some(31),
        },
        Operation::ErrorSynchronization,
        Operation::TraceSynchronization,
        Operation::OtherHint { immediate: 127 },
    ] {
        let mut code = sentinel.clone();
        assert_eq!(emit(&mut code, &operation), Err(EmitError::ContextRequired));
        assert_eq!(code, sentinel);
    }
}
