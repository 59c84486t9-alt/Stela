//! Generic EL1 MMU-off integer plans, with a separate attempt per RAM read.
//! No metadata here grants CPU, translation, physical RAM or native entry.
use super::{ExitKind, ParsedBlock, Terminator};
use crate::{
    CompileError, GuestAddress, NativeBlock, TargetCpu,
    aarch64::{Instruction, Operation, Register, Width, literal},
    context::memory::{MemoryRequirements, SpAlignmentRequirement, profile_requirements},
};
use alloc::vec::Vec;

/// Exact decoded access, owned by the plan that emits its callback request.
/// The actual runtime must revalidate source, controls, physical RAM and outer
/// exclusion before reading; a copied intent is never a memory permission.
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
mod tests;
