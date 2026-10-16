//! EL1 platform blocks: integer code, RAM accesses and system instructions.
use super::{ExitKind, ParsedBlock, Terminator, el1_m0, system};
use crate::{
    CompileError, GuestAddress, Lifter, NativeBlock, TargetCpu,
    aarch64::{
        AddressMode, Decoder, Instruction, MemoryTransfer, Operation, Register, Width,
        register_offset::IndexExtend,
    },
    context::memory::MemoryRequirements,
};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    Registers,
    LiteralRead64(el1_m0::LiteralRead64),
    ScalarLoad(ScalarLoad),
    System(system::SystemInstruction),
    Write64Pair(Write64Pair),
    Read64Pair(Read64Pair),
}

/// Addressing derived from the source instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarLoadAddress {
    Literal {
        address: u64,
    },
    Immediate {
        base: Register,
        displacement: i32,
        mode: AddressMode,
    },
    RegisterOffset {
        base: Register,
        index: Register,
        extend: IndexExtend,
        shift: u8,
    },
}

/// A scalar load. One checked operand drives analysis, runtime metadata and
/// emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarLoad {
    source_pc: GuestAddress,
    operand: crate::x86_64::memory_store::checked_scalar::Operand,
}
impl ScalarLoad {
    pub fn from_instruction(instruction: &Instruction) -> Option<Self> {
        Some(Self {
            source_pc: instruction.pc,
            operand: crate::x86_64::memory_store::checked_scalar::Operand::from_m0_scalar_load(
                &instruction.operation,
            )?,
        })
    }
    pub fn source_pc(self) -> GuestAddress {
        self.source_pc
    }
    pub fn bytes(self) -> u8 {
        self.operand.bytes()
    }
    pub fn destination(self) -> Register {
        self.operand.data()
    }
    pub fn result_width(self) -> Width {
        let MemoryTransfer::Load { width, .. } = self.operand.transfer() else {
            unreachable!("private canonical load operand")
        };
        width
    }
    pub fn signed(self) -> bool {
        let MemoryTransfer::Load { signed, .. } = self.operand.transfer() else {
            unreachable!("private canonical load operand")
        };
        signed
    }
    pub fn address(self) -> ScalarLoadAddress {
        use crate::x86_64::memory_store::checked_scalar::Address;
        match self.operand.address() {
            Address::Literal { address } => ScalarLoadAddress::Literal { address },
            Address::Immediate { displacement, mode } => ScalarLoadAddress::Immediate {
                base: self.operand.base(),
                displacement,
                mode,
            },
            Address::RegisterOffset {
                index,
                extend,
                shift,
            } => ScalarLoadAddress::RegisterOffset {
                base: self.operand.base(),
                index,
                extend,
                shift,
            },
        }
    }
    pub fn writeback_base(self) -> Option<Register> {
        match self.address() {
            ScalarLoadAddress::Immediate { base, mode, .. } if mode != AddressMode::Offset => {
                Some(base)
            }
            _ => None,
        }
    }
    pub fn requirements(self) -> MemoryRequirements {
        crate::x86_64::memory_store::checked_scalar::requirements(&self.operand)
    }
    pub fn matches_instruction(self, instruction: &Instruction) -> bool {
        Self::from_instruction(instruction) == Some(self)
    }
    pub fn matches_source(self, pc: GuestAddress, word: u32) -> bool {
        Decoder
            .lift(pc, word)
            .is_ok_and(|instruction| self.matches_instruction(&instruction))
    }
    pub(crate) fn operand(self) -> crate::x86_64::memory_store::checked_scalar::Operand {
        self.operand
    }
}

/// Canonical pair metadata. This descriptor never grants a writable pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Write64Pair {
    source_pc: GuestAddress,
    data: [Register; 2],
    base: Register,
    displacement: i32,
    mode: AddressMode,
}
impl Write64Pair {
    pub fn source_pc(self) -> GuestAddress {
        self.source_pc
    }
    pub fn from_instruction(instruction: &Instruction) -> Option<Self> {
        crate::x86_64::memory_store::checked_pair::Operand::from_m0_write_pair(
            &instruction.operation,
        )?;
        let Operation::MemoryPair {
            data,
            base,
            displacement,
            mode,
            ..
        } = instruction.operation
        else {
            unreachable!("validated shared pair operand")
        };
        Some(Self {
            source_pc: instruction.pc,
            data,
            base,
            displacement,
            mode,
        })
    }
    fn operation(self) -> Operation {
        Operation::MemoryPair {
            transfer: crate::aarch64::MemoryTransfer::Store,
            bytes: size_of::<u64>() as u8,
            data: self.data,
            base: self.base,
            displacement: self.displacement,
            mode: self.mode,
        }
    }
    pub fn requirements(self) -> MemoryRequirements {
        let operand = crate::x86_64::memory_store::checked_pair::Operand::from_m0_write_pair(
            &self.operation(),
        )
        .expect("private plan retained a canonical pair");
        crate::x86_64::memory_store::checked_pair::requirements(&operand)
    }
}

/// Canonical pair metadata. This descriptor never grants a readable pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Read64Pair {
    source_pc: GuestAddress,
    data: [Register; 2],
    base: Register,
    displacement: i32,
    mode: AddressMode,
}
impl Read64Pair {
    pub fn source_pc(self) -> GuestAddress {
        self.source_pc
    }
    pub fn from_instruction(instruction: &Instruction) -> Option<Self> {
        crate::x86_64::memory_store::checked_pair::Operand::from_m0_read_pair(
            &instruction.operation,
        )?;
        let Operation::MemoryPair {
            data,
            base,
            displacement,
            mode,
            ..
        } = instruction.operation
        else {
            unreachable!("validated shared pair operand")
        };
        Some(Self {
            source_pc: instruction.pc,
            data,
            base,
            displacement,
            mode,
        })
    }
    fn operation(self) -> Operation {
        Operation::MemoryPair {
            transfer: crate::aarch64::MemoryTransfer::Load {
                signed: false,
                width: Width::X64,
            },
            bytes: size_of::<u64>() as u8,
            data: self.data,
            base: self.base,
            displacement: self.displacement,
            mode: self.mode,
        }
    }
    pub fn requirements(self) -> MemoryRequirements {
        let operand = crate::x86_64::memory_store::checked_pair::Operand::from_m0_read_pair(
            &self.operation(),
        )
        .expect("private plan retained a canonical pair");
        crate::x86_64::memory_store::checked_pair::requirements(&operand)
    }
}

pub(super) fn validate_operation(operation: &Operation) -> Result<(), CompileError> {
    if crate::x86_64::memory_store::checked_pair::Operand::from_m0_write_pair(operation).is_some()
        || crate::x86_64::memory_store::checked_pair::Operand::from_m0_read_pair(operation)
            .is_some()
    {
        return Ok(());
    }
    if crate::x86_64::memory_store::checked_scalar::Operand::from_m0_scalar_load(operation)
        .is_some()
    {
        return Ok(());
    }
    match operation {
        Operation::Bitfield(_)
        | Operation::Branch { .. }
        | Operation::BranchCondition { .. }
        | Operation::BranchZero { .. }
        | Operation::BranchBit { .. }
        | Operation::PcRelative(_)
        | Operation::ConditionalSelect(_)
        | Operation::ConditionalCompare(_)
        | Operation::IntegerMath(_)
        | Operation::AddSubRegister { .. }
        | Operation::AddSubCarry { .. }
        | Operation::AddSubExtended { .. }
        | Operation::LogicalRegister { .. }
        | Operation::LogicalImmediate { .. }
        | Operation::MoveWide { .. }
        | Operation::AddSub { .. }
        | Operation::Nop => Ok(()),
        _ => Err(CompileError(
            "operation requires another EL1 effect owner".into(),
        )),
    }
}

pub(super) fn validate_terminal(terminal: &Terminator) -> Result<(), CompileError> {
    match terminal {
        Terminator::DirectCall(_)
        | Terminator::Register {
            kind: ExitKind::Indirect | ExitKind::Call | ExitKind::Return,
            ..
        }
        | Terminator::Branch(
            Operation::Branch { .. }
            | Operation::BranchCondition { .. }
            | Operation::BranchZero { .. }
            | Operation::BranchBit { .. },
        ) => Ok(()),
        Terminator::System(instruction) => validate_system(*instruction),
        _ => Err(CompileError(
            "terminal requires another EL1 effect owner".into(),
        )),
    }
}

pub(super) fn validate_system(instruction: system::SystemInstruction) -> Result<(), CompileError> {
    if instruction.is_el1_context_operation() || instruction.is_el1_ram_completion() {
        return Ok(());
    }
    match instruction.operation {
        system::SystemOperation::Register(_) | system::SystemOperation::PstateImmediate(_) => {
            Ok(())
        }
        _ => Err(CompileError(
            "EL1 platform System carrier requires a retained register effect owner".into(),
        )),
    }
}

enum Body {
    Registers {
        instructions: Vec<Instruction>,
        terminal: Option<(GuestAddress, Terminator)>,
        fallthrough: GuestAddress,
    },
    Scalar(Instruction, ScalarLoad),
    Write(Instruction, Write64Pair),
    Read(Instruction, Read64Pair),
    System(system::SystemInstruction),
}

pub(super) struct Plan {
    body: Body,
}
impl Plan {
    pub(super) fn new(parsed: &ParsedBlock) -> Result<Self, CompileError> {
        for instruction in &parsed.instructions {
            validate_operation(&instruction.operation)?;
        }
        if let Some((_, terminal)) = &parsed.terminal {
            validate_terminal(terminal)?;
        }
        let body = if let Some((_, Terminator::System(instruction))) = &parsed.terminal {
            if !parsed.instructions.is_empty() {
                return Err(CompileError(
                    "System effects require a separate source attempt".into(),
                ));
            }
            Body::System(*instruction)
        } else if let Some(instruction) = parsed.instructions.first()
            && let Some(write) = Write64Pair::from_instruction(instruction)
        {
            if parsed.instructions.len() != 1 || parsed.terminal.is_some() {
                return Err(CompileError(
                    "M0 write requires one separate complete attempt".into(),
                ));
            }
            Body::Write(instruction.clone(), write)
        } else if let Some(instruction) = parsed.instructions.first()
            && let Some(read) = Read64Pair::from_instruction(instruction)
        {
            if parsed.instructions.len() != 1 || parsed.terminal.is_some() {
                return Err(CompileError(
                    "M0 pair read requires one separate complete attempt".into(),
                ));
            }
            Body::Read(instruction.clone(), read)
        } else if let Some(instruction) = parsed.instructions.first()
            && let Some(load) = ScalarLoad::from_instruction(instruction)
        {
            if parsed.instructions.len() != 1 || parsed.terminal.is_some() {
                return Err(CompileError(
                    "M0 scalar load requires one separate complete attempt".into(),
                ));
            }
            Body::Scalar(instruction.clone(), load)
        } else {
            Body::Registers {
                instructions: parsed.instructions.clone(),
                terminal: parsed.terminal.clone(),
                fallthrough: parsed.next_pc,
            }
        };
        Ok(Self { body })
    }
    pub(super) fn intent(&self) -> Intent {
        match &self.body {
            Body::Registers { .. } => Intent::Registers,
            Body::Scalar(_, load) => Intent::ScalarLoad(*load),
            Body::System(instruction) => Intent::System(*instruction),
            Body::Write(_, write) => Intent::Write64Pair(*write),
            Body::Read(_, read) => Intent::Read64Pair(*read),
        }
    }
    pub(super) fn requirements(&self) -> Option<MemoryRequirements> {
        match &self.body {
            Body::Scalar(_, load) => Some(load.requirements()),
            Body::Write(_, write) => Some(write.requirements()),
            Body::Read(_, read) => Some(read.requirements()),
            Body::Registers { .. } | Body::System(_) => None,
        }
    }
    pub(super) fn emit(self, target: TargetCpu) -> Result<NativeBlock, CompileError> {
        match self.body {
            Body::Scalar(instruction, load) => {
                crate::x86_64::block::el1_m0::emit_scalar_load(&instruction, load, target)
            }
            Body::Write(instruction, _) => {
                crate::x86_64::block::el1_m0::emit_write_pair(&instruction, target)
            }
            Body::Read(instruction, _) => {
                crate::x86_64::block::el1_m0::emit_read_pair(&instruction, target)
            }
            Body::Registers {
                instructions,
                terminal,
                fallthrough,
            } => Ok(crate::x86_64::block::emit_for_target(
                &instructions,
                terminal.as_ref(),
                fallthrough,
                target,
            )),
            Body::System(instruction) => Ok(crate::x86_64::block::emit_for_target(
                &[],
                Some(&(instruction.instruction_pc, Terminator::System(instruction))),
                instruction.next_pc,
                target,
            )),
        }
    }
}

#[cfg(test)]
mod tests;
