//! Barriers and hints (ISB, SB, NOP, YIELD, ...).
use crate::aarch64::system::synchronization::Operation;
use crate::x86_64::asm::{
    Alu, Code,
    Gpr::{R8, Rax, Rbx},
    Size,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitError {
    ContextRequired,
}

/// Emit the barriers and hints that need no system context. R8 is scratch.
/// CPUID leaf 0 serializes; RBX is saved around it. Other operations go to the
/// runtime.
pub fn emit(code: &mut Code, operation: &Operation) -> Result<(), EmitError> {
    match operation {
        Operation::Yield => code.asm().pause(),
        Operation::ConsumptionBarrier
        | Operation::SpeculationBarrier
        | Operation::StoreBypassBarrier { .. } => {
            let mut asm = code.asm();
            asm.mov(Size::Qword, R8, Rbx);
            asm.alu(Alu::Xor, Size::Dword, Rax, Rax);
            asm.cpuid();
            asm.mov(Size::Qword, Rbx, R8);
        }
        _ => return Err(EmitError::ContextRequired),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::system::synchronization::{Requirement, Scope, WaitKind};
    use alloc::vec;

    /// `mov r8,rbx; xor eax,eax; cpuid; mov rbx,r8`.
    const SERIALIZATION: [u8; 10] = [0x49, 0x89, 0xd8, 0x31, 0xc0, 0x0f, 0xa2, 0x4c, 0x89, 0xc3];

    #[test]
    fn baseline_barriers_share_real_serialization() {
        let expected = SERIALIZATION;
        for operation in [
            Operation::ConsumptionBarrier,
            Operation::SpeculationBarrier,
            Operation::StoreBypassBarrier { physical: false },
            Operation::StoreBypassBarrier { physical: true },
        ] {
            let mut code = Code::new();
            assert_eq!(emit(&mut code, &operation), Ok(()));
            assert_eq!(code, expected);
            assert_eq!(code.instructions(), 4);
        }
    }

    #[test]
    fn yield_uses_pause() {
        let mut code = Code::new();
        assert_eq!(emit(&mut code, &Operation::Yield), Ok(()));
        assert_eq!(code, [0xf3, 0x90]);
        assert_eq!(code.instructions(), 1);
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
            let mut code = Code::from(sentinel.clone());
            assert_eq!(emit(&mut code, &operation), Err(EmitError::ContextRequired));
            assert_eq!(code, sentinel);
        }
    }
}
