//! Decoded instructions and the state, memory and prefix requirements they carry.
use alloc::{boxed::Box, format, vec::Vec};

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        Instruction, Operation,
        scalable::execution::{
            GuestMemoryQuantity, ScalableAccessCheck, ScalableAccessRequirements,
        },
        sme::{
            integer_dots, integer_matrix, integer_vector, length, lut_v2, memory as sme_memory,
            movement, tables,
        },
        sve::{
            address, dot, floating_copy, integer_arithmetic, integer_bits, integer_comparison,
            integer_logic, integer_predicate_move, integer_products, integer_saturation,
            memory_load, memory_multi, memory_store, memory_structure, predicate_generation,
            predicate_logic, rearrange, rearrange_extract, rearrange_widen, reductions, shifts,
            shifts_narrow, sign, tables as sve_tables,
        },
    },
    x86_64,
};

pub(crate) enum Decoded {
    Exclusive(crate::x86_64::exclusive::CheckedOperand),
    MemoryScalar(crate::x86_64::memory_store::checked_scalar::Operand),
    MemoryPair(crate::x86_64::memory_store::checked_pair::Operand),
    MemoryFixed(crate::x86_64::CheckedFixedMemoryOperand),
    Ordinary(Instruction),
    Address(address::Operand),
    IntegerDot(dot::Operand),
    IntegerBits(integer_bits::Operand),
    IntegerLogic(integer_logic::Operand),
    IntegerPredicateMove(integer_predicate_move::Operand),
    IntegerProducts(integer_products::Operand),
    IntegerSaturation(integer_saturation::Operand),
    Rearrange(rearrange::Operand),
    RearrangeExtract(rearrange_extract::Operand),
    RearrangeWiden(rearrange_widen::Operand),
    Reductions(reductions::Operand),
    Shifts(shifts::Operand),
    ShiftsNarrow(shifts_narrow::Operand),
    Sign(sign::Operand),
    FloatingCopy(floating_copy::Operand),
    IntegerArithmetic(integer_arithmetic::Operand),
    IntegerComparison(integer_comparison::Operand),
    PredicateGeneration(predicate_generation::Operand),
    PredicateLogic(predicate_logic::Operand),
    Length(length::Operand),
    MemoryLoad(memory_load::Operand),
    SmeMemory(sme_memory::Operand),
    MemoryMulti(memory_multi::Operand),
    MemoryStore(memory_store::Operand),
    MemoryStructure(memory_structure::Operand),
    SmeTables(tables::Operand),
    SveTables(sve_tables::Operand),
    SmeLutV2(lut_v2::Operand),
    SmeMovement(movement::Operand),
    SmeIntegerVector(integer_vector::Operand),
    SmeIntegerDots(integer_dots::Operand),
    SmeIntegerMatrix(integer_matrix::Operand),
}

impl Decoded {
    pub(super) fn execution_access_requirements(&self) -> ScalableAccessRequirements {
        match self {
            Self::Exclusive(_) => ScalableAccessRequirements::Unqualified,
            Self::MemoryScalar(_) | Self::MemoryPair(_) | Self::MemoryFixed(_) => {
                ScalableAccessRequirements::Unqualified
            }
            Self::MemoryLoad(_) => {
                ScalableAccessRequirements::Known(Box::new([ScalableAccessCheck::SveEnabled]))
            }
            Self::MemoryMulti(operand) => memory_multi::execution_access_requirements(operand),
            Self::MemoryStore(operand) => memory_store::execution_access_requirements(operand),
            Self::MemoryStructure(operand) => {
                memory_structure::execution_access_requirements(operand)
            }
            Self::SmeMemory(operand) => operand.execution_access_requirements(),
            Self::Ordinary(instruction) => match instruction.operation {
                Operation::MoveWide { .. }
                | Operation::AddSub { .. }
                | Operation::Return
                | Operation::Nop => ScalableAccessRequirements::Known(Box::new([])),
                _ => ScalableAccessRequirements::Unqualified,
            },
            Self::Address(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerDot(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerBits(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerLogic(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerPredicateMove(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerProducts(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerSaturation(_) => ScalableAccessRequirements::Unqualified,
            Self::Rearrange(_) => ScalableAccessRequirements::Unqualified,
            Self::RearrangeExtract(_) => ScalableAccessRequirements::Unqualified,
            Self::RearrangeWiden(_) => ScalableAccessRequirements::Unqualified,
            Self::Reductions(_) => ScalableAccessRequirements::Unqualified,
            Self::Shifts(_) => ScalableAccessRequirements::Unqualified,
            Self::ShiftsNarrow(_) => ScalableAccessRequirements::Unqualified,
            Self::Sign(_) => ScalableAccessRequirements::Unqualified,
            Self::FloatingCopy(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerArithmetic(_) => ScalableAccessRequirements::Unqualified,
            Self::IntegerComparison(_) => ScalableAccessRequirements::Unqualified,
            Self::PredicateGeneration(_) => ScalableAccessRequirements::Unqualified,
            Self::PredicateLogic(_) => ScalableAccessRequirements::Unqualified,
            Self::Length(_) => ScalableAccessRequirements::Unqualified,
            Self::SmeLutV2(_) => ScalableAccessRequirements::Known(Box::new([
                ScalableAccessCheck::StreamingSveEnabled,
                ScalableAccessCheck::SmeZt0Enabled,
            ])),
            Self::SmeTables(_) => ScalableAccessRequirements::Unqualified,
            Self::SveTables(_) => ScalableAccessRequirements::Unqualified,
            Self::SmeMovement(_) => ScalableAccessRequirements::Unqualified,
            Self::SmeIntegerVector(_) => ScalableAccessRequirements::Unqualified,
            Self::SmeIntegerDots(_) => ScalableAccessRequirements::Unqualified,
            Self::SmeIntegerMatrix(_) => ScalableAccessRequirements::Unqualified,
        }
    }

    pub(super) const fn guest_memory_quantity(&self) -> GuestMemoryQuantity {
        match self {
            Self::Exclusive(_) => GuestMemoryQuantity::Unqualified,
            Self::MemoryScalar(_) | Self::MemoryPair(_) | Self::MemoryFixed(_) => {
                GuestMemoryQuantity::Unqualified
            }
            Self::MemoryLoad(operand) => GuestMemoryQuantity::Maximum(operand.memory_element),
            Self::MemoryMulti(operand) => memory_multi::guest_memory_quantity(operand),
            Self::MemoryStore(operand) => memory_store::guest_memory_quantity(operand),
            Self::MemoryStructure(operand) => memory_structure::guest_memory_quantity(operand),
            Self::SmeMemory(operand) => operand.guest_memory_quantity(),
            Self::Ordinary(instruction) => match instruction.operation {
                Operation::MoveWide { .. }
                | Operation::AddSub { .. }
                | Operation::Return
                | Operation::Nop => GuestMemoryQuantity::None,
                _ => GuestMemoryQuantity::Unqualified,
            },
            Self::Address(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerDot(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerBits(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerLogic(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerPredicateMove(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerProducts(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerSaturation(_) => GuestMemoryQuantity::Unqualified,
            Self::Rearrange(_) => GuestMemoryQuantity::Unqualified,
            Self::RearrangeExtract(_) => GuestMemoryQuantity::Unqualified,
            Self::RearrangeWiden(_) => GuestMemoryQuantity::Unqualified,
            Self::Reductions(_) => GuestMemoryQuantity::Unqualified,
            Self::Shifts(_) => GuestMemoryQuantity::Unqualified,
            Self::ShiftsNarrow(_) => GuestMemoryQuantity::Unqualified,
            Self::Sign(_) => GuestMemoryQuantity::Unqualified,
            Self::FloatingCopy(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerArithmetic(_) => GuestMemoryQuantity::Unqualified,
            Self::IntegerComparison(_) => GuestMemoryQuantity::Unqualified,
            Self::PredicateGeneration(_) => GuestMemoryQuantity::Unqualified,
            Self::PredicateLogic(_) => GuestMemoryQuantity::Unqualified,
            Self::Length(_) => GuestMemoryQuantity::Unqualified,
            Self::SmeLutV2(_) => GuestMemoryQuantity::None,
            Self::SmeTables(_) => GuestMemoryQuantity::Unqualified,
            Self::SveTables(_) => GuestMemoryQuantity::None,
            Self::SmeMovement(_) => GuestMemoryQuantity::Unqualified,
            Self::SmeIntegerVector(_) => GuestMemoryQuantity::Unqualified,
            Self::SmeIntegerDots(_) => GuestMemoryQuantity::Unqualified,
            Self::SmeIntegerMatrix(_) => GuestMemoryQuantity::Unqualified,
        }
    }

    pub(crate) fn memory_requirements(&self) -> crate::context::memory::MemoryRequirements {
        match self {
            Self::MemoryScalar(operand) => {
                crate::x86_64::memory_store::checked_scalar::requirements(operand)
            }
            Self::MemoryPair(operand) => {
                crate::x86_64::memory_store::checked_pair::requirements(operand)
            }
            Self::MemoryFixed(operand) => operand.requirements(),
            Self::Exclusive(operand) => crate::x86_64::exclusive::requirements(operand),
            Self::MemoryLoad(operand) => x86_64::sve::memory_load::requirements(*operand),
            Self::SmeMemory(operand) => x86_64::sme::memory::requirements(operand),
            Self::MemoryMulti(operand) => x86_64::sve::memory_multi::requirements(operand),
            Self::MemoryStore(operand) => x86_64::sve::memory_store::requirements(operand),
            Self::MemoryStructure(operand) => x86_64::sve::memory_structure::requirements(*operand),
            Self::Ordinary(_) => Default::default(),
            Self::Address(_) => Default::default(),
            Self::IntegerDot(_) => Default::default(),
            Self::IntegerBits(_) => Default::default(),
            Self::IntegerLogic(_) => Default::default(),
            Self::IntegerPredicateMove(_) => Default::default(),
            Self::IntegerProducts(_) => Default::default(),
            Self::IntegerSaturation(_) => Default::default(),
            Self::Rearrange(_) => Default::default(),
            Self::RearrangeExtract(_) => Default::default(),
            Self::RearrangeWiden(_) => Default::default(),
            Self::Reductions(_) => Default::default(),
            Self::Shifts(_) => Default::default(),
            Self::ShiftsNarrow(_) => Default::default(),
            Self::Sign(_) => Default::default(),
            Self::FloatingCopy(_) => Default::default(),
            Self::IntegerArithmetic(_) => Default::default(),
            Self::IntegerComparison(_) => Default::default(),
            Self::PredicateGeneration(_) => Default::default(),
            Self::PredicateLogic(_) => Default::default(),
            Self::Length(_) => Default::default(),
            Self::SmeLutV2(_) => Default::default(),
            Self::SmeTables(_) => Default::default(),
            Self::SveTables(_) => Default::default(),
            Self::SmeMovement(_) => Default::default(),
            Self::SmeIntegerVector(_) => Default::default(),
            Self::SmeIntegerDots(_) => Default::default(),
            Self::SmeIntegerMatrix(_) => Default::default(),
        }
    }

    /// Each family adapter re-checks the original word. Encodings without a
    /// policy are refused.
    pub(super) fn prefix_requirement(
        &self,
        original_word: u32,
    ) -> Result<Option<crate::aarch64::sve::prefix::PrefixRequirement>, ()> {
        match self {
            Self::Exclusive(_)
            | Self::MemoryScalar(_)
            | Self::MemoryPair(_)
            | Self::MemoryFixed(_) => Ok(None),
            Self::MemoryLoad(_)
            | Self::MemoryMulti(_)
            | Self::MemoryStore(_)
            | Self::MemoryStructure(_)
            | Self::SmeMemory(_) => Ok(None),
            Self::Ordinary(_) => Ok(None),
            Self::Address(_) => Ok(None),
            Self::IntegerDot(_) => Ok(None),
            Self::IntegerBits(_) => Ok(None),
            Self::IntegerLogic(operand) => operand.prefix_requirement(original_word),
            Self::IntegerPredicateMove(_) => Ok(None),
            Self::IntegerProducts(operand) => operand.prefix_requirement(original_word),
            Self::IntegerSaturation(operand) => operand.prefix_requirement(original_word),
            Self::Rearrange(operand) => operand.prefix_requirement(original_word),
            Self::RearrangeExtract(operand) => operand.prefix_requirement(original_word),
            Self::RearrangeWiden(operand) => operand.prefix_requirement(original_word),
            Self::Reductions(operand) => operand.prefix_requirement(original_word),
            Self::Shifts(_) => Ok(None),
            Self::ShiftsNarrow(_) => Ok(None),
            Self::Sign(_) => Ok(None),
            Self::FloatingCopy(_) => Ok(None),
            Self::IntegerArithmetic(operand) => operand.prefix_requirement(original_word),
            Self::IntegerComparison(_) => Ok(None),
            Self::PredicateGeneration(_) => Ok(None),
            Self::PredicateLogic(_) => Ok(None),
            Self::Length(_) => Ok(None),
            Self::SmeLutV2(_) => Ok(None),
            Self::SmeTables(_) => Ok(None),
            Self::SveTables(_) => Ok(None),
            Self::SmeMovement(_) => Ok(None),
            Self::SmeIntegerVector(_) => Ok(None),
            Self::SmeIntegerDots(_) => Ok(None),
            Self::SmeIntegerMatrix(_) => Ok(None),
        }
    }

    /// Pairs may currently use only register-only followers that compile
    /// completely inline. A service, numerical or memory exit would need
    /// restart support.
    pub(super) fn require_total_inline_prefix(&self, pc: GuestAddress) -> Result<(), CompileError> {
        match self {
            Self::IntegerLogic(_)
            | Self::IntegerProducts(_)
            | Self::IntegerSaturation(_)
            | Self::Rearrange(_)
            | Self::RearrangeExtract(_)
            | Self::RearrangeWiden(_)
            | Self::Reductions(_)
            | Self::IntegerArithmetic(_) => Ok(()),
            Self::Exclusive(_)
            | Self::MemoryScalar(_)
            | Self::MemoryPair(_)
            | Self::MemoryFixed(_)
            | Self::MemoryLoad(_)
            | Self::MemoryMulti(_)
            | Self::MemoryStore(_)
            | Self::MemoryStructure(_)
            | Self::SmeMemory(_)
            | Self::Ordinary(_)
            | Self::Address(_)
            | Self::IntegerDot(_)
            | Self::IntegerBits(_)
            | Self::IntegerPredicateMove(_)
            | Self::Shifts(_)
            | Self::ShiftsNarrow(_)
            | Self::Sign(_)
            | Self::FloatingCopy(_)
            | Self::IntegerComparison(_)
            | Self::PredicateGeneration(_)
            | Self::PredicateLogic(_)
            | Self::Length(_)
            | Self::SmeLutV2(_)
            | Self::SmeTables(_)
            | Self::SveTables(_)
            | Self::SmeMovement(_)
            | Self::SmeIntegerVector(_)
            | Self::SmeIntegerDots(_)
            | Self::SmeIntegerMatrix(_) => Err(CompileError(format!(
                "MOVPRFX pair validation: follower pair/effect requirements are not reviewed at {:#x}",
                pc.0
            ))),
        }
    }
}

impl Decoded {
    /// Reuse the already decoded ordinary block instruction. Effects receive a
    /// typed checked variant; unmigrated writers never fall back to direct RAM.
    pub(crate) fn checked_ordinary(
        instruction: Instruction,
        profile: crate::block::CheckedMemoryProfile,
    ) -> Result<Self, CompileError> {
        if profile == crate::block::CheckedMemoryProfile::M0DeviceRamRead64Staged
            && !matches!(&instruction.operation, Operation::Memory { .. })
        {
            return Err(CompileError(format!(
                "operation outside staged M0 ordinary read64 profile at {:#x}",
                instruction.pc.0
            )));
        }
        if let Operation::Exclusive(operand) = instruction.operation {
            // The existing typed adapter validates every decoded exclusive shape,
            // including constrained register roles, and derives its exact checked
            // quantity, ordering and host requirements. No raw memory fallback.
            return Ok(Self::Exclusive(
                crate::x86_64::exclusive::CheckedOperand::new(operand, profile)?,
            ));
        }
        if let Some(operand) = crate::x86_64::memory_store::checked_scalar::Operand::from_operation(
            &instruction.operation,
            profile,
        ) {
            return Ok(Self::MemoryScalar(operand));
        }
        if let Some(operand) = crate::x86_64::memory_store::checked_pair::Operand::from_operation(
            &instruction.operation,
            profile,
        ) {
            return Ok(Self::MemoryPair(operand));
        }
        if let Some(operand) = crate::x86_64::CheckedFixedMemoryOperand::from_operation(
            &instruction.operation,
            profile,
        ) {
            return Ok(Self::MemoryFixed(operand));
        }
        if !ordinary_permitted(&instruction.operation) {
            return Err(CompileError(format!(
                "operation outside checked GPR memory profile at {:#x}",
                instruction.pc.0
            )));
        }
        Ok(Self::Ordinary(instruction))
    }
    pub(crate) fn emit_checked_ordinary(
        &self,
        code: &mut Vec<u8>,
        pc: GuestAddress,
        target: TargetCpu,
        fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
    ) -> Result<(), CompileError> {
        match self {
            Self::Ordinary(instruction) => {
                if instruction.pc != pc {
                    return Err(CompileError("checked instruction PC differs".into()));
                }
                x86_64::emit_instruction(
                    code,
                    instruction,
                    fixups,
                    target,
                    x86_64::MemoryChecks::DEFAULT,
                );
            }
            Self::MemoryScalar(operand) => {
                crate::x86_64::memory_store::checked_scalar::emit_context(code, operand, pc.0)
            }
            Self::MemoryPair(operand) => {
                crate::x86_64::memory_store::checked_pair::emit_context(code, operand, pc.0)
            }
            Self::MemoryFixed(operand) => operand.emit_context(code, pc.0),
            Self::Exclusive(operand) => {
                crate::x86_64::exclusive::emit_context(code, operand, pc.0)?
            }
            Self::MemoryLoad(_)
            | Self::SmeMemory(_)
            | Self::MemoryMulti(_)
            | Self::MemoryStore(_)
            | Self::MemoryStructure(_)
            | Self::Address(_)
            | Self::SmeLutV2(_)
            | Self::SmeTables(_)
            | Self::SveTables(_)
            | Self::SmeMovement(_)
            | Self::IntegerBits(_)
            | Self::IntegerPredicateMove(_)
            | Self::Rearrange(_)
            | Self::Reductions(_)
            | Self::Shifts(_)
            | Self::ShiftsNarrow(_)
            | Self::IntegerComparison(_)
            | Self::PredicateGeneration(_)
            | Self::PredicateLogic(_)
            | Self::SmeIntegerVector(_)
            | Self::IntegerDot(_)
            | Self::IntegerLogic(_)
            | Self::IntegerProducts(_)
            | Self::IntegerSaturation(_)
            | Self::RearrangeExtract(_)
            | Self::RearrangeWiden(_)
            | Self::Sign(_)
            | Self::FloatingCopy(_)
            | Self::IntegerArithmetic(_)
            | Self::Length(_)
            | Self::SmeIntegerDots(_)
            | Self::SmeIntegerMatrix(_) => {
                return Err(CompileError(
                    "unrequested scalable operation in checked GPR memory profile".into(),
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn ordinary_permitted(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::Bitfield(_)
            | Operation::PcRelative(_)
            | Operation::ConditionalSelect(_)
            | Operation::ConditionalCompare(_)
            | Operation::Crc(_)
            | Operation::Flags(_)
            | Operation::IntegerMath(_)
            | Operation::IntegerMinMax(_)
            | Operation::IntegerUnary(_)
            | Operation::AddSubRegister { .. }
            | Operation::AddSubCarry { .. }
            | Operation::AddSubExtended { .. }
            | Operation::LogicalRegister { .. }
            | Operation::LogicalImmediate { .. }
            | Operation::Branch { .. }
            | Operation::BranchCondition { .. }
            | Operation::BranchZero { .. }
            | Operation::BranchBit { .. }
            | Operation::MoveWide { .. }
            | Operation::AddSub { .. }
            | Operation::Synchronization(_)
            | Operation::Nop
            | Operation::Return
    )
}
