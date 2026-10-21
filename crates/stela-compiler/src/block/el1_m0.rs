//! EL1 blocks with the MMU off, planned one RAM read per attempt.
use super::{ExitKind, ParsedBlock, Terminator};
use crate::{
    CompileError, GuestAddress, NativeBlock, TargetCpu,
    aarch64::{Instruction, Operation, Register, Width, literal},
    context::memory::{MemoryRequirements, SpAlignmentRequirement, profile_requirements},
};
use alloc::vec::Vec;

/// A decoded access of the plan that emits its callback request. The runtime
/// re-validates source, controls and physical RAM before reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiteralRead64 {
    pub source_pc: GuestAddress,
    pub address: u64,
    pub destination: Register,
}

/// Present only for this typed profile; None at the CompilationPlan accessor
/// means a different profile, never permission for a no-memory native call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    Registers,
    LiteralRead64(LiteralRead64),
}

pub(super) fn validate_operation(operation: &Operation) -> Result<(), CompileError> {
    match operation {
        Operation::PcRelative(_)
        | Operation::AddSub {
            flags: false,
            destination: Register::X(_) | Register::Zero,
            source: Register::X(_) | Register::Zero,
            ..
        }
        | Operation::Branch { .. }
        | Operation::Literal(literal::Operand {
            transfer:
                literal::Transfer::Integer {
                    width: Width::X64,
                    signed: false,
                    ..
                },
            ..
        }) => Ok(()),
        _ => Err(CompileError("operation outside EL1 M0 integer plan".into())),
    }
}

pub(super) fn validate_terminal(terminal: &Terminator) -> Result<(), CompileError> {
    match terminal {
        Terminator::DirectCall(_)
        | Terminator::Register {
            kind: ExitKind::Return,
            ..
        }
        | Terminator::Branch(Operation::Branch { .. }) => Ok(()),
        _ => Err(CompileError("terminal outside EL1 M0 integer plan".into())),
    }
}

pub(super) struct Plan {
    instructions: Vec<Instruction>,
    terminal: Option<(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    read: Option<LiteralRead64>,
}
impl Plan {
    pub(super) fn new(parsed: &ParsedBlock) -> Result<Self, CompileError> {
        let mut read = None;
        for instruction in &parsed.instructions {
            validate_operation(&instruction.operation)?;
            if let Operation::Literal(operand) = instruction.operation {
                let literal::Transfer::Integer {
                    destination,
                    width: Width::X64,
                    signed: false,
                } = operand.transfer
                else {
                    return Err(CompileError("literal is not an unsigned doubleword".into()));
                };
                if parsed.instructions.len() != 1 || parsed.terminal.is_some() {
                    return Err(CompileError(
                        "RAM read must be a separate complete attempt".into(),
                    ));
                }
                read = Some(LiteralRead64 {
                    source_pc: instruction.pc,
                    address: operand.address,
                    destination,
                });
            }
        }
        if let Some((_, terminal)) = &parsed.terminal {
            validate_terminal(terminal)?;
        }
        Ok(Self {
            instructions: parsed.instructions.clone(),
            terminal: parsed.terminal.clone(),
            fallthrough: parsed.next_pc,
            read,
        })
    }
    pub(super) fn intent(&self) -> Intent {
        self.read.map_or(Intent::Registers, Intent::LiteralRead64)
    }
    pub(super) fn requirements(&self) -> Option<MemoryRequirements> {
        self.read.map(|_| MemoryRequirements {
            required_address_checks: Default::default(),
            required_pointer_arithmetic: None,
            // June LDR literal: tagchecked=false; no register base or SP.
            required_flags: 0,
            required_host_caps: 0,
            required_profile: profile_requirements::M0_DEVICE_RAM_READ64,
            required_sp_alignment: SpAlignmentRequirement::Any,
            ..MemoryRequirements::default()
        })
    }
    pub(super) fn emit(self, target: TargetCpu) -> Result<NativeBlock, CompileError> {
        crate::x86_64::block::el1_m0::emit(
            &self.instructions,
            self.terminal.as_ref(),
            self.fallthrough,
            self.read,
            target,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockProfile, CompilationPlan, EL1_M0_INTEGER_BLOCK_ABI};
    use alloc::vec::Vec;
    const ADRP_X0: u32 = 0x9000_0000;
    const ADD_X0: u32 = 0x9100_0000;
    const LDR_X1: u32 = 0x5800_1bc1;
    const BL: u32 = 0x9400_139f;
    const RET: u32 = 0xd65f_03c0;
    fn bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }
    #[test]
    fn generic_entry_plan_splits_before_ram_and_preserves_call_return() {
        for base in [0x100000, 0x200000, 0x4020000000] {
            let profile = BlockProfile::El1M0IntegerV1;
            assert_eq!(profile.abi(), EL1_M0_INTEGER_BLOCK_ABI);
            let plan = CompilationPlan::new(
                &bytes(&[ADRP_X0, ADD_X0, LDR_X1, BL]),
                GuestAddress(base),
                profile,
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(plan.source_bytes(), 8);
            assert!(
                plan.memory_requirements().is_none()
                    && plan.el1_m0_intent() == Some(Intent::Registers)
            );
            assert_eq!(plan.compile().unwrap().native.source_map.len(), 2);
            let plan = CompilationPlan::new(
                &bytes(&[LDR_X1, BL]),
                GuestAddress(base + 8),
                profile,
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(plan.source_bytes(), 4);
            assert_eq!(
                plan.el1_m0_intent(),
                Some(Intent::LiteralRead64(LiteralRead64 {
                    source_pc: GuestAddress(base + 8),
                    address: base + 0x380,
                    destination: Register::X(1)
                }))
            );
            let requirements = plan.memory_requirements().unwrap();
            assert_eq!(
                requirements.required_profile,
                profile_requirements::M0_DEVICE_RAM_READ64
            );
            assert_eq!(requirements.required_flags, 0);
            assert_eq!(requirements.required_host_caps, 0);
            assert_eq!(plan.compile().unwrap().native.source_map.len(), 1);
            for (word, pc) in [(BL, base + 12), (RET, base + 0x4e88)] {
                let plan = CompilationPlan::new(
                    &word.to_le_bytes(),
                    GuestAddress(pc),
                    profile,
                    TargetCpu::Baseline,
                )
                .unwrap();
                assert_eq!(plan.source_bytes(), 4);
                assert!(plan.memory_requirements().is_none());
                assert_eq!(plan.compile().unwrap().native.source_map.len(), 1);
            }
        }
    }
    #[test]
    fn unadmitted_effects_decline_instead_of_using_direct_memory_or_services() {
        for word in [
            0xd5034fdf_u32,
            0xf9400020,
            0xf9000020,
            0x18000000,
            0x98000000,
            0x5c000000,
            0x54000000,
            0xd61f0000,
            0xd63f0000,
            0xd4000001,
            0x910003e0,
            0xb1000000,
        ] {
            assert!(
                CompilationPlan::new(
                    &word.to_le_bytes(),
                    GuestAddress(0x100000),
                    BlockProfile::El1M0IntegerV1,
                    TargetCpu::Baseline
                )
                .is_err(),
                "{word:08x}"
            );
        }
        let plan = CompilationPlan::new(
            &bytes(&[LDR_X1, 0xd5034fdf]),
            GuestAddress(0x100008),
            BlockProfile::El1M0IntegerV1,
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(plan.source_bytes(), 4);
    }
}
