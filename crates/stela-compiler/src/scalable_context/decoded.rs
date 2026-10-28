//! Decoded instructions and the state, memory and prefix requirements they carry.
use crate::aarch64::Unsupported;
use crate::x86_64::asm::Code;
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
    SharedMemory(crate::x86_64::shared_memory::CheckedOperand),
    Exclusive(crate::x86_64::exclusive::CheckedOperand),
    MemoryScalar(crate::x86_64::memory_store::checked_scalar::Operand),
    MemoryPair(crate::x86_64::memory_store::checked_pair::Operand),
    MemoryFixed(crate::x86_64::CheckedFixedMemoryOperand),
    /// The architecturally permitted no-action hint, without lending an
    /// untranslated guest address to the host's cache or memory system.
    PrefetchHint,
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
            Self::PrefetchHint => ScalableAccessRequirements::Known(Box::new([])),
            Self::Exclusive(_) | Self::SharedMemory(_) => ScalableAccessRequirements::Unqualified,
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
            Self::PrefetchHint => GuestMemoryQuantity::None,
            Self::Exclusive(_) | Self::SharedMemory(_) => GuestMemoryQuantity::Unqualified,
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
            Self::PrefetchHint => Default::default(),
            Self::MemoryScalar(operand) => {
                crate::x86_64::memory_store::checked_scalar::requirements(operand)
            }
            Self::MemoryPair(operand) => {
                crate::x86_64::memory_store::checked_pair::requirements(operand)
            }
            Self::MemoryFixed(operand) => operand.requirements(),
            Self::Exclusive(operand) => crate::x86_64::exclusive::requirements(operand),
            Self::SharedMemory(operand) => operand.requirements(),
            Self::MemoryLoad(operand) => x86_64::sve::memory_load::requirements(*operand),
            Self::SmeMemory(operand) => x86_64::sme::memory::requirements(operand),
            Self::MemoryMulti(operand) => x86_64::sve::memory_multi::requirements(operand),
            Self::MemoryStore(operand) => x86_64::sve::memory_store::requirements(operand),
            Self::MemoryStructure(operand) => x86_64::sve::memory_structure::requirements(*operand),
            Self::Ordinary(instruction) if checked_register_asimd(&instruction.operation) => {
                crate::context::memory::MemoryRequirements {
                    required_flags: crate::context::memory::flags::ASIMD,
                    ..Default::default()
                }
            }
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
    ) -> Result<Option<crate::aarch64::sve::prefix::PrefixRequirement>, Unsupported> {
        match self {
            Self::PrefetchHint => Ok(None),
            Self::SharedMemory(_)
            | Self::Exclusive(_)
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
            Self::SharedMemory(_)
            | Self::PrefetchHint
            | Self::Exclusive(_)
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
        if matches!(instruction.operation, Operation::Prefetch(_)) {
            // The ignored hint has no consumer for its address/descriptor.
            // AddressAdd/PointerAddCheckAtEL only change that dead temporary;
            // neither raises a fault or writes architectural state, even with
            // CPA2 enabled. Do not require controls for an unobserved result.
            return Ok(Self::PrefetchHint);
        }
        if let Some(operand) = crate::x86_64::shared_memory::CheckedOperand::from_operation(
            &instruction.operation,
            profile,
        )? {
            return Ok(Self::SharedMemory(operand));
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
        if !ordinary_permitted(&instruction.operation)
            && !checked_register_asimd(&instruction.operation)
        {
            return Err(CompileError(format!(
                "operation outside checked GPR memory profile at {:#x}",
                instruction.pc.0
            )));
        }
        Ok(Self::Ordinary(instruction))
    }
    pub(crate) fn emit_checked_ordinary(
        &self,
        code: &mut Code,
        pc: GuestAddress,
        target: TargetCpu,
        fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
    ) -> Result<(), CompileError> {
        match self {
            // Arm June 2026 Hint_Prefetch permits any hint to be ignored and
            // forbids synchronous translation/alignment faults and Device
            // accesses. A host prefetch using a raw guest VA would not preserve
            // the guest translation/permission boundary. Keep a source interval.
            Self::PrefetchHint => code.asm().nop(),
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
            Self::MemoryFixed(operand) => operand.emit_context(code, pc.0, target),
            Self::SharedMemory(operand) => operand.emit(code, pc.0),
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

/// Existing register-only AdvSIMD recipes can share checked blocks without
/// borrowing guest RAM. Memory variants must retain their typed adapters;
/// numerical FP remains on its separately recovered block/service path. Keep
/// this exhaustive by variant so a future SIMD family needs explicit review.
fn checked_register_asimd(operation: &Operation) -> bool {
    use crate::aarch64::simd::Operand;
    matches!(
        operation,
        Operation::Simd(
            Operand::Aes(_)
                | Operand::I8mm(_)
                | Operand::Sha1(_)
                | Operand::Sha256(_)
                | Operand::Sha3(_)
                | Operand::Sha512(_)
                | Operand::Floating(_)
                | Operand::Immediate(_)
                | Operand::Halving(_)
                | Operand::Product(_)
                | Operand::Saturate(_)
                | Operand::Reduce(_)
                | Operand::Shift(_)
                | Operand::Rearrange(_)
                | Operand::Lut(_)
                | Operand::Compare { .. }
                | Operand::Integer { .. }
                | Operand::MoveImmediate { .. }
        )
    )
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

#[cfg(test)]
mod checked_register_tests {
    use super::*;
    use crate::context::memory::flags;
    use crate::{
        Lifter,
        aarch64::Decoder,
        block::{BlockProfile, CheckedMemoryProfile, CompilationPlan, Features},
    };
    use alloc::vec;

    #[test]
    fn checked_prefetch_uses_ignored_hint_for_every_address_form_and_hint() {
        use crate::context::memory::address::{AccessEl, AddressAddChecks, EffectiveAddressChecks};
        let pc = GuestAddress(0x4000);
        for hint in 0..32 {
            let mut words = vec![
                0xf980_0190 & !31 | hint,
                0xf9bf_ffe0 | hint,
                0xf890_03e0 | hint,
                0xd8ff_ffe0 | hint,
            ];
            if hint < 24 {
                for option in [2, 3, 6, 7] {
                    for shift in [0, 1 << 12] {
                        words.push(0xf8a0_0be0 | (2 << 16) | (option << 13) | shift | hint);
                    }
                }
            }
            for word in words {
                let instruction = Decoder.lift(pc, word).unwrap();
                assert!(matches!(instruction.operation, Operation::Prefetch(_)));
                let plain = CheckedMemoryProfile::SpAlignmentDisabled;
                let mut profiles = vec![CheckedMemoryProfile::SpAlignmentEnabled, plain];
                for access_el in [AccessEl::El0, AccessEl::El1] {
                    for el0 in [AddressAddChecks::Disabled, AddressAddChecks::Enabled] {
                        for el1 in [AddressAddChecks::Disabled, AddressAddChecks::Enabled] {
                            profiles.push(plain.with_address_checks(
                                access_el,
                                AccessEl::El0,
                                EffectiveAddressChecks::new(el0, el1),
                            ));
                        }
                    }
                }
                for profile in profiles {
                    let decoded = Decoded::checked_ordinary(instruction.clone(), profile).unwrap();
                    assert!(matches!(decoded, Decoded::PrefetchHint));
                    assert_eq!(decoded.memory_requirements(), Default::default());
                    let mut code = Code::new();
                    let mut recovery = Vec::new();
                    decoded
                        .emit_checked_ordinary(&mut code, pc, TargetCpu::Baseline, &mut recovery)
                        .unwrap();
                    assert_eq!(code, [0x90]); // nop
                    assert!(recovery.is_empty());
                }
            }
        }
    }

    #[test]
    fn checked_prefetch_keeps_source_intervals_and_rejects_unqualified_neighbors() {
        use crate::context::memory::address::{AccessEl, AddressAddChecks, EffectiveAddressChecks};
        let pc = GuestAddress(0x4000);
        let source: Vec<_> = [0x5280_0000u32, 0xf980_0190, 0xd65f_03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let compiled = CompilationPlan::new(
            &source,
            pc,
            &crate::Options::new(
                BlockProfile::new(Features::SYSTEM_MODE)
                    .with_checked_memory(CheckedMemoryProfile::SpAlignmentDisabled),
                TargetCpu::Baseline,
            ),
        )
        .unwrap()
        .compile()
        .unwrap();
        assert_eq!(compiled.source_bytes, source.len());
        let map = &compiled.native.source_map;
        assert_eq!(
            map.iter().map(|(address, _)| address.0).collect::<Vec<_>>(),
            [pc.0, pc.0 + 4, pc.0 + 8]
        );
        assert_eq!(
            &compiled.native.x86_64_code[map[1].1..map[2].1],
            &[0x90] // nop
        );
        assert!(compiled.fault_recovery.is_empty());
        let checked = CheckedMemoryProfile::SpAlignmentDisabled.with_address_checks(
            AccessEl::El0,
            AccessEl::El1,
            EffectiveAddressChecks::new(AddressAddChecks::Enabled, AddressAddChecks::Disabled),
        );
        for word in [0xf980_0190, 0xf890_03e0, 0xf8a2_6bf0] {
            let instruction = Decoder.lift(pc, word).unwrap();
            let admitted = Decoded::checked_ordinary(instruction.clone(), checked).unwrap();
            assert_eq!(admitted.memory_requirements(), Default::default());
        }
        let literal =
            Decoded::checked_ordinary(Decoder.lift(pc, 0xd800_0000).unwrap(), checked).unwrap();
        assert!(
            literal
                .memory_requirements()
                .required_address_checks
                .is_empty()
        );
        for word in [0xf8a2_6bf8, 0xf8a2_0be0] {
            assert!(
                Decoder.lift(pc, word).is_err(),
                "RPRFM or reserved extend {word:08x}"
            );
        }
    }

    #[test]
    fn checked_vector_logic_requires_asimd_for_both_widths_and_all_alias_roles() {
        let base = GuestAddress(0x4000);
        for class in [
            0x0e201c00, 0x0e601c00, 0x0ea01c00, 0x0ee01c00, 0x2e201c00, 0x2e601c00, 0x2ea01c00,
            0x2ee01c00,
        ] {
            for q in [0, 1 << 30] {
                for (destination, left, right) in [(0, 0, 0), (31, 0, 31), (7, 31, 7), (0, 1, 2)] {
                    let word: u32 = class | q | destination | (left << 5) | (right << 16);
                    let instruction = Decoder.lift(base, word).unwrap();
                    assert!(checked_register_asimd(&instruction.operation));
                    assert!(!ordinary_permitted(&instruction.operation));
                    for specialization in [
                        CheckedMemoryProfile::SpAlignmentEnabled,
                        CheckedMemoryProfile::SpAlignmentDisabled,
                    ] {
                        let decoded =
                            Decoded::checked_ordinary(instruction.clone(), specialization).unwrap();
                        assert!(matches!(decoded, Decoded::Ordinary(_)));
                        assert_eq!(decoded.memory_requirements().required_flags, flags::ASIMD);
                    }
                }
            }
        }
    }
    #[test]
    fn shared_register_simd_prefix_retains_real_branch_extent_and_source_map() {
        // Generic move/vector-zero/integer-zero/compare/conditional-branch
        // prefix. A following unallocated word is outside its consumed block.
        let words: [u32; 7] = [
            0xaa0103e2, 0x6e201c00, 0xca010021, 0xaa0003e3, 0xf101005f, 0x54000883, 0,
        ];
        let source: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let base = GuestAddress(0x8000);
        for specialization in [
            CheckedMemoryProfile::SpAlignmentEnabled,
            CheckedMemoryProfile::SpAlignmentDisabled,
        ] {
            let plan = CompilationPlan::new(
                &source,
                base,
                &crate::Options::new(
                    BlockProfile::new(Features::SYSTEM_MODE).with_checked_memory(specialization),
                    TargetCpu::Baseline,
                ),
            )
            .unwrap();
            assert_eq!(plan.source_bytes(), 24);
            assert_eq!(
                plan.memory_requirements().unwrap().required_flags,
                flags::ASIMD
            );
            let compiled = plan.compile().unwrap();
            assert_eq!(compiled.source_bytes, 24);
            assert_eq!(
                compiled
                    .native
                    .source_map
                    .iter()
                    .map(|(pc, _)| *pc)
                    .collect::<Vec<_>>(),
                (0..6)
                    .map(|i| GuestAddress(base.0 + i * 4))
                    .collect::<Vec<_>>()
            );
            assert!(compiled.fault_recovery.is_empty());
        }
    }
    #[test]
    fn simd_guest_memory_never_receives_register_only_authority() {
        let base = GuestAddress(0x4000);
        for word in [
            0x3dc00020, 0x3d800020, 0xad400440, 0xad000440, 0x4c407020, 0x4c007020,
        ] {
            let instruction = Decoder.lift(base, word).unwrap();
            assert!(!checked_register_asimd(&instruction.operation));
            if let Ok(decoded) =
                Decoded::checked_ordinary(instruction, CheckedMemoryProfile::SpAlignmentDisabled)
            {
                assert!(!matches!(decoded, Decoded::Ordinary(_)));
            }
        }
    }

    #[test]
    fn structured_simd_uses_fixed_width_service_routing_for_every_address_mode() {
        let pc = GuestAddress(0x4000);
        for class in [
            0x4c40_0044u32, // original LD4 .16B
            0x4c00_005f,    // ST4 .16B, V31 wrap
            0x0c40_705f,    // LD1 .8B
            0x0c00_205f,    // ST1 four .8B registers
            0x4d60_205f,    // LD4 lane
            0x4d20_205f,    // ST4 lane
            0x0d60_e05f,    // LD4R .8B
            0x4d60_e05f,    // LD4R .16B
        ] {
            for addressing in [0, (1 << 23) | (31 << 16), (1 << 23) | (2 << 16)] {
                let instruction = Decoder.lift(pc, class | addressing).unwrap();
                assert!(!checked_register_asimd(&instruction.operation));
                for profile in [
                    CheckedMemoryProfile::SpAlignmentEnabled,
                    CheckedMemoryProfile::SpAlignmentDisabled,
                ] {
                    let decoded = Decoded::checked_ordinary(instruction.clone(), profile).unwrap();
                    assert!(matches!(decoded, Decoded::MemoryFixed(_)));
                    assert_eq!(
                        decoded.memory_requirements().required_flags & flags::ASIMD,
                        flags::ASIMD
                    );
                    let mut code = Code::new();
                    decoded
                        .emit_checked_ordinary(&mut code, pc, TargetCpu::Baseline, &mut Vec::new())
                        .unwrap();
                    assert!(!code.is_empty());
                }
            }
        }
    }
}
