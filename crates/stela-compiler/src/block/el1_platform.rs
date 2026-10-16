//! One immutable EL1 cohort for base integer, qualified RAM and System carriers.
//! These plans describe effects; the actual retained source/CPU owners admit them.
use super::{ExitKind, ParsedBlock, Terminator, el1_m0, system};
use crate::{
    CompileError, GuestAddress, NativeBlock, TargetCpu,
    aarch64::{AddressMode, Instruction, Operation, Register, Width, literal},
    context::memory::MemoryRequirements,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    Registers,
    LiteralRead64(el1_m0::LiteralRead64),
    System(system::SystemInstruction),
    Write64Pair(Write64Pair),
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

pub(super) fn validate_operation(operation: &Operation) -> Result<(), CompileError> {
    if crate::x86_64::memory_store::checked_pair::Operand::from_m0_write_pair(operation).is_some() {
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
        | Operation::Nop
        | Operation::Literal(literal::Operand {
            transfer:
                literal::Transfer::Integer {
                    width: Width::X64,
                    signed: false,
                    ..
                },
            ..
        }) => Ok(()),
        _ => Err(CompileError(
            "operation requires another actual EL1 effect owner".into(),
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
            "terminal requires another actual EL1 effect owner".into(),
        )),
    }
}

pub(super) fn validate_system(instruction: system::SystemInstruction) -> Result<(), CompileError> {
    if instruction.is_el1_context_operation() {
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
    Literal(el1_m0::Plan),
    Write(Instruction, Write64Pair),
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
        } else if parsed
            .instructions
            .iter()
            .any(|instruction| matches!(instruction.operation, Operation::Literal(_)))
        {
            Body::Literal(el1_m0::Plan::new(parsed)?)
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
            Body::Literal(plan) => match plan.intent() {
                el1_m0::Intent::LiteralRead64(read) => Intent::LiteralRead64(read),
                el1_m0::Intent::Registers => {
                    unreachable!("literal body is constructed only from a literal source")
                }
            },
            Body::System(instruction) => Intent::System(*instruction),
            Body::Write(_, write) => Intent::Write64Pair(*write),
        }
    }
    pub(super) fn requirements(&self) -> Option<MemoryRequirements> {
        match &self.body {
            Body::Literal(plan) => plan.requirements(),
            Body::Write(_, write) => Some(write.requirements()),
            Body::Registers { .. } | Body::System(_) => None,
        }
    }
    pub(super) fn emit(self, target: TargetCpu) -> Result<NativeBlock, CompileError> {
        match self.body {
            Body::Literal(plan) => plan.emit(target),
            Body::Write(instruction, _) => {
                crate::x86_64::block::el1_m0::emit_write_pair(&instruction, target)
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
mod tests {
    use super::*;
    use crate::block::{BlockProfile, CompilationPlan};
    const BASE: GuestAddress = GuestAddress(0x100000);
    const ADD_X0: u32 = 0x91000000;
    const CMP_X10_X11: u32 = 0xeb0b015f;
    const DAIFSET: u32 = 0xd5034fdf;
    const MSR_VBAR_X10: u32 = 0xd518c00a;
    fn bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }
    #[test]
    fn base_integer_and_each_system_effect_keep_separate_consumed_attempts() {
        let source = bytes(&[ADD_X0, DAIFSET, MSR_VBAR_X10]);
        let prefix = CompilationPlan::new(
            &source,
            BASE,
            BlockProfile::El1PlatformV1,
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(prefix.source_bytes(), 4);
        assert_eq!(prefix.el1_platform_intent(), Some(Intent::Registers));
        assert!(prefix.memory_requirements().is_none());
        for word in [DAIFSET, MSR_VBAR_X10] {
            let plan = CompilationPlan::new(
                &word.to_le_bytes(),
                BASE,
                BlockProfile::El1PlatformV1,
                TargetCpu::Baseline,
            )
            .unwrap();
            let Some(Intent::System(instruction)) = plan.el1_platform_intent() else {
                panic!("source-bound System intent absent")
            };
            assert!(instruction.matches_source(BASE, word));
            assert_eq!(plan.source_bytes(), 4);
            assert!(plan.memory_requirements().is_none());
            assert_eq!(plan.compile().unwrap().native.source_map.len(), 1);
        }
        let compare = CompilationPlan::new(
            &CMP_X10_X11.to_le_bytes(),
            BASE,
            BlockProfile::El1PlatformV1,
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(compare.el1_platform_intent(), Some(Intent::Registers));
    }
    #[test]
    fn canonical_branch_operations_reach_existing_terminal_plan() {
        for word in [0x14000002u32, 0x54000040, 0x34000040, 0x36000040] {
            let source = bytes(&[word]);
            let plan = CompilationPlan::new(
                &source,
                BASE,
                BlockProfile::El1PlatformV1,
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(plan.source_bytes(), size_of::<u32>());
            assert_eq!(plan.el1_platform_intent(), Some(Intent::Registers));
            assert!(plan.memory_requirements().is_none());
            assert_eq!(plan.compile().unwrap().native.source_map.len(), 1);
        }
    }
    #[test]
    fn every_declared_platform_route_reaches_plan_and_shared_emitter() {
        // One authored canonical row per permitted operation family and terminal.
        // These check integration/admission; differential ISA evidence is separate.
        for (name, word, lane) in [
            ("bitfield", 0xd341fc20, 0),
            ("pc_relative", 0x90000000, 0),
            ("conditional_select", 0x9a820020, 0),
            ("conditional_compare", 0xfa410000, 0),
            ("integer_math", 0x9b027c20, 0),
            ("add_sub_register", 0x8b020020, 0),
            ("add_sub_carry", 0x9a020020, 0),
            ("add_sub_extended", 0x8b224020, 0),
            ("logical_register", 0x8a020020, 0),
            ("logical_immediate", 0x92400020, 0),
            ("move_wide", 0xd2800000, 0),
            ("add_sub_immediate", 0x91000420, 0),
            ("nop", 0xd503201f, 0),
            ("branch", 0x14000002, 0),
            ("branch_condition", 0x54000040, 0),
            ("branch_zero", 0x34000040, 0),
            ("branch_bit", 0x36000040, 0),
            ("direct_call", 0x94000002, 0),
            ("indirect_branch", 0xd61f0000, 0),
            ("indirect_call", 0xd63f0000, 0),
            ("return", 0xd65f03c0, 0),
            ("literal_read64", 0x58000040, 1),
            ("pair_offset", 0xa9000440, 2),
            ("pair_preindex", 0xa9800440, 2),
            ("pair_postindex", 0xa8800440, 2),
            ("daif", DAIFSET, 3),
            ("vbar_write", MSR_VBAR_X10, 3),
            ("vbar_read", 0xd538c00b, 3),
        ] {
            let plan = CompilationPlan::new(
                &bytes(&[word]),
                BASE,
                BlockProfile::El1PlatformV1,
                TargetCpu::Baseline,
            )
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            let actual_lane = match plan.el1_platform_intent().expect(name) {
                Intent::Registers => 0,
                Intent::LiteralRead64(_) => 1,
                Intent::Write64Pair(_) => 2,
                Intent::System(_) => 3,
            };
            assert_eq!(actual_lane, lane, "{name}");
            assert_eq!(plan.source_bytes(), size_of::<u32>(), "{name}");
            assert_eq!(
                plan.memory_requirements().is_some(),
                lane == 1 || lane == 2,
                "{name}"
            );
            let block = plan
                .compile()
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            assert_eq!(block.native.source_map.len(), 1, "{name}");
        }
        for word in [
            0xf9000040u32,
            0xa90007e0,
            0xa8000440,
            0x29000440,
            0xa9400440,
            0x18000040,
            0x98000040,
            0x1c000040,
            0xd4000002, // HVC remains unsupported.
            0xd69f0bff, // ERETAA: authenticated owner remains unmounted.
            0xd69f0fff, // ERETAB likewise.
            0xd503207f,
            0xa9800420,
            0xffffffff,
        ] {
            assert!(
                CompilationPlan::new(
                    &bytes(&[word]),
                    BASE,
                    BlockProfile::El1PlatformV1,
                    TargetCpu::Baseline
                )
                .is_err(),
                "unowned {word:08x}"
            );
        }
    }
    #[test]
    fn unowned_memory_atomic_fp_and_exception_effects_never_use_direct_ram_or_services() {
        for word in [
            0xf9000000u32,
            0xd69f0bff, // ERETAA still needs its actual feature-present owner.
            0xd69f0fff, // ERETAB likewise remains outside this base profile.
            0x1e602800,
            0x5ac02000,
        ] {
            assert!(
                CompilationPlan::new(
                    &word.to_le_bytes(),
                    BASE,
                    BlockProfile::El1PlatformV1,
                    TargetCpu::Baseline
                )
                .is_err(),
                "{word:08x}"
            );
        }
    }
    #[test]
    fn device_pair_is_one_source_attempt_with_distinct_reached_member_requirements() {
        const STP_XZR_XZR_POST_X10_16: u32 = 0xa8817d5f;
        let source = bytes(&[ADD_X0, STP_XZR_XZR_POST_X10_16, ADD_X0]);
        let prefix = CompilationPlan::new(
            &source,
            BASE,
            BlockProfile::El1PlatformV1,
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(prefix.source_bytes(), size_of::<u32>());
        let store = CompilationPlan::new(
            &source[size_of::<u32>()..],
            GuestAddress(BASE.0 + 4),
            BlockProfile::El1PlatformV1,
            TargetCpu::Baseline,
        )
        .unwrap();
        let Some(Intent::Write64Pair(write)) = store.el1_platform_intent() else {
            panic!("typed write missing")
        };
        assert_eq!(write.base, Register::X(10));
        assert_eq!(write.data, [Register::Zero; 2]);
        assert_eq!(write.mode, AddressMode::PostIndex);
        assert_eq!(write.displacement, 16);
        assert_eq!(store.source_bytes(), size_of::<u32>());
        let requirements = store.memory_requirements().unwrap();
        assert_eq!(
            requirements.required_profile,
            crate::context::memory::profile_requirements::M0_DEVICE_RAM_WRITE8_OR_PAIR
        );
        assert_eq!(requirements.required_host_caps, 0);
        assert_eq!(
            requirements.required_flags,
            crate::context::memory::flags::WRITE
                | crate::context::memory::flags::PAIR
                | crate::context::memory::flags::TAG_CHECKED
        );
        assert_eq!(store.compile().unwrap().native.source_map.len(), 1);
    }
}
