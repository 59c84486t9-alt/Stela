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
    ScalarStore(ScalarStore),
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

fn scalar_address(
    operand: crate::x86_64::memory_store::checked_scalar::Operand,
) -> ScalarLoadAddress {
    use crate::x86_64::memory_store::checked_scalar::Address;
    match operand.address() {
        Address::Literal { address } => ScalarLoadAddress::Literal { address },
        Address::Immediate { displacement, mode } => ScalarLoadAddress::Immediate {
            base: operand.base(),
            displacement,
            mode,
        },
        Address::RegisterOffset {
            index,
            extend,
            shift,
        } => ScalarLoadAddress::RegisterOffset {
            base: operand.base(),
            index,
            extend,
            shift,
        },
    }
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
        scalar_address(self.operand)
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

/// Store addressing; `ScalarStore::address` never produces `Literal`.
pub type ScalarStoreAddress = ScalarLoadAddress;

/// A scalar integer store. The shared checked operand stages the source value
/// and holds base writeback until the store succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarStore {
    source_pc: GuestAddress,
    operand: crate::x86_64::memory_store::checked_scalar::Operand,
}
impl ScalarStore {
    pub fn from_instruction(instruction: &Instruction) -> Option<Self> {
        Some(Self {
            source_pc: instruction.pc,
            operand: crate::x86_64::memory_store::checked_scalar::Operand::from_m0_scalar_store(
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
    pub fn source_register(self) -> Register {
        self.operand.data()
    }
    pub fn address(self) -> ScalarStoreAddress {
        scalar_address(self.operand)
    }
    pub fn writeback_base(self) -> Option<Register> {
        match self.address() {
            ScalarStoreAddress::Immediate { base, mode, .. } if mode != AddressMode::Offset => {
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
        || crate::x86_64::memory_store::checked_scalar::Operand::from_m0_scalar_store(operation)
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
        system::SystemOperation::Register(_)
        | system::SystemOperation::PstateImmediate(_)
        | system::SystemOperation::Wait { .. }
        | system::SystemOperation::SendEvent { local: true } => Ok(()),
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
    Store(Instruction, ScalarStore),
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
        } else if let Some(instruction) = parsed.instructions.first()
            && let Some(store) = ScalarStore::from_instruction(instruction)
        {
            if parsed.instructions.len() != 1 || parsed.terminal.is_some() {
                return Err(CompileError(
                    "M0 scalar store requires one separate complete attempt".into(),
                ));
            }
            Body::Store(instruction.clone(), store)
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
            Body::Store(_, store) => Intent::ScalarStore(*store),
            Body::System(instruction) => Intent::System(*instruction),
            Body::Write(_, write) => Intent::Write64Pair(*write),
            Body::Read(_, read) => Intent::Read64Pair(*read),
        }
    }
    pub(super) fn requirements(&self) -> Option<MemoryRequirements> {
        match &self.body {
            Body::Scalar(_, load) => Some(load.requirements()),
            Body::Store(_, store) => Some(store.requirements()),
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
            Body::Store(instruction, store) => {
                crate::x86_64::block::el1_m0::emit_scalar_store(&instruction, store, target)
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
                crate::x86_64::MemoryChecks::ALL,
            )),
            Body::System(instruction) => Ok(crate::x86_64::block::emit_for_target(
                &[],
                Some(&(instruction.instruction_pc, Terminator::System(instruction))),
                instruction.next_pc,
                target,
                crate::x86_64::MemoryChecks::ALL,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockProfile, CompilationPlan};
    use alloc::{vec, vec::Vec};
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
    fn ordinary_dsb_has_one_effectless_carrier_without_stealing_other_hints() {
        const DSB_SY: u32 = 0xd503_3f9f;
        const DSB_ISH: u32 = 0xd503_3b9f;
        const DSB_ISHLD: u32 = 0xd503_399f;
        const DSB_ISHST: u32 = 0xd503_3a9f;
        const NOP: u32 = 0xd503_201f;
        const SSBB: u32 = 0xd503_309f;
        const PSSBB: u32 = 0xd503_349f;
        const DSB_NXS: u32 = 0xd503_323f;
        const NXS_SCOPE_SHIFT: u32 = 10;
        const NXS_SCOPE_COUNT: u32 = 4;
        for word in [DSB_SY, DSB_ISH, DSB_ISHLD, DSB_ISHST]
            .into_iter()
            .chain((0..NXS_SCOPE_COUNT).map(|scope| DSB_NXS | (scope << NXS_SCOPE_SHIFT)))
        {
            let plan = CompilationPlan::new(
                &word.to_le_bytes(),
                BASE,
                BlockProfile::El1PlatformV1,
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(plan.source_bytes(), size_of::<u32>());
            assert!(plan.memory_requirements().is_none());
            let Some(Intent::System(instruction)) = plan.el1_platform_intent() else {
                panic!("DSB source carrier absent");
            };
            assert!(instruction.is_el1_ram_completion());
            assert!(instruction.matches_source(BASE, word));
            let compiled = plan.compile().unwrap();
            assert_eq!(compiled.native.source_map.len(), 1);
        }
        let nop = CompilationPlan::new(
            &NOP.to_le_bytes(),
            BASE,
            BlockProfile::El1PlatformV1,
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(nop.el1_platform_intent(), Some(Intent::Registers));
        for word in [SSBB, PSSBB] {
            assert!(
                super::system::decode_el1_system_instruction(BASE, word)
                    .unwrap()
                    .is_none()
            );
        }
        let prefix = CompilationPlan::new(
            &bytes(&[ADD_X0, DSB_SY]),
            BASE,
            BlockProfile::El1PlatformV1,
            TargetCpu::Baseline,
        )
        .unwrap();
        assert_eq!(prefix.source_bytes(), size_of::<u32>());
        assert_eq!(prefix.el1_platform_intent(), Some(Intent::Registers));
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
        // One row per permitted operation family and terminal.
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
            ("scalar_store", 0xf9000040, 5),
            ("pair_offset", 0xa9000440, 2),
            ("pair_preindex", 0xa9800440, 2),
            ("pair_postindex", 0xa8800440, 2),
            ("pair_read_offset", 0xa9400440, 4),
            ("pair_read_preindex", 0xa9c00440, 4),
            ("pair_read_postindex", 0xa8c00440, 4),
            ("daif", DAIFSET, 3),
            ("sevl", 0xd503_20bf, 3),
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
                Intent::LiteralRead64(_) | Intent::ScalarLoad(_) => 1,
                Intent::Write64Pair(_) => 2,
                Intent::System(_) => 3,
                Intent::Read64Pair(_) => 4,
                Intent::ScalarStore(_) => 5,
            };
            assert_eq!(actual_lane, lane, "{name}");
            assert_eq!(plan.source_bytes(), size_of::<u32>(), "{name}");
            assert_eq!(
                plan.memory_requirements().is_some(),
                matches!(lane, 1 | 2 | 4 | 5),
                "{name}"
            );
            if lane == 4 {
                let requirements = plan.memory_requirements().unwrap();
                assert_eq!(requirements.required_host_caps, 0, "{name}");
                assert_eq!(
                    requirements.required_profile,
                    crate::context::memory::profile_requirements::M0_DEVICE_RAM_READ64_PAIR_NO_LSE2,
                    "{name}"
                );
            }
            let block = plan
                .compile()
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            assert_eq!(block.native.source_map.len(), 1, "{name}");
        }
        for word in [
            0xf8000840u32, // STTR is not a platform scalar store.
            0xa90007e0,
            0xa8000440,
            0x29000440,
            0xa94007e0,
            0x1c000040,
            0xd4000002, // HVC remains unsupported.
            0xd69f0bff, // ERETAA: authenticated owner remains unmounted.
            0xd69f0fff, // ERETAB likewise.
            0xd503209f, // SEV-all still requires its existing separate owner.
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
            0xf8000800u32, // STTR is not a platform scalar store.
            0xd69f0bff,    // ERETAA still needs its actual feature-present owner.
            0xd69f0fff,    // ERETAB likewise remains outside this base profile.
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
    #[test]
    fn canonical_scalar_load_family_has_one_staged_attempt_and_exact_source_intent() {
        use crate::context::memory::{SpAlignmentRequirement, flags, profile_requirements};
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/el1-scalar-loads.S"
        ));
        let mut admitted = 0;
        let mut declined = 0;
        for row in fixture
            .lines()
            .filter_map(|line| line.trim().strip_prefix(".inst "))
        {
            let word = u32::from_str_radix(
                row.split_whitespace()
                    .next()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap();
            let wanted = row.ends_with("; admit");
            let source = bytes(&[word, 0xd503201f]);
            let plan = CompilationPlan::new(
                &source,
                BASE,
                BlockProfile::El1PlatformV1,
                TargetCpu::Baseline,
            );
            if !wanted {
                // The load fixture's plain stores are now admitted as stores.
                if let Ok(plan) = plan {
                    assert!(
                        matches!(plan.el1_platform_intent(), Some(Intent::ScalarStore(_))),
                        "unowned {word:08x}"
                    );
                }
                declined += 1;
                continue;
            }
            let plan = plan.unwrap_or_else(|error| panic!("{word:08x}: {error:?}"));
            let Some(Intent::ScalarLoad(load)) = plan.el1_platform_intent() else {
                panic!("scalar intent {word:08x}")
            };
            assert_eq!(plan.source_bytes(), size_of::<u32>());
            assert!(load.matches_source(BASE, word));
            assert!(!load.matches_source(GuestAddress(BASE.0 + 4), word));
            let requirements = load.requirements();
            assert_eq!(plan.memory_requirements(), Some(requirements));
            assert_eq!(
                requirements.required_profile,
                profile_requirements::M0_DEVICE_RAM_SCALAR_LOAD
            );
            assert_eq!(requirements.required_host_caps, 0);
            assert_eq!(requirements.required_address_checks, Default::default());
            assert_eq!(requirements.required_pointer_arithmetic, None);
            assert_eq!(
                requirements.required_sp_alignment,
                SpAlignmentRequirement::Any
            );
            let tag_checked = match load.address() {
                ScalarLoadAddress::Literal { .. } => false,
                ScalarLoadAddress::Immediate { base, mode, .. } => {
                    mode != AddressMode::Offset || base != Register::Sp
                }
                ScalarLoadAddress::RegisterOffset { .. } => true,
            };
            assert_eq!(
                requirements.required_flags,
                if tag_checked { flags::TAG_CHECKED } else { 0 }
            );
            assert_eq!(
                plan.compile().unwrap().native.source_map,
                vec![(BASE, crate::extended::context_wrapper().len())]
            );
            let prefix = CompilationPlan::new(
                &bytes(&[ADD_X0, word, 0xd503201f]),
                BASE,
                BlockProfile::El1PlatformV1,
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(prefix.source_bytes(), size_of::<u32>());
            assert_eq!(prefix.el1_platform_intent(), Some(Intent::Registers));
            assert!(prefix.memory_requirements().is_none());
            admitted += 1;
        }
        assert_eq!(admitted, 181);
        assert_eq!(declined, 9);
    }

    #[test]
    fn scalar_result_metadata_preserves_width_sign_and_literal_address() {
        for (word, bytes, width, signed) in [
            (0x39400c20, 1, Width::W32, false),
            (0x79400c20, 2, Width::W32, false),
            (0xb9400c20, 4, Width::W32, false),
            (0xf9400c20, 8, Width::X64, false),
            (0x39c00c20, 1, Width::W32, true),
            (0x39800c20, 1, Width::X64, true),
            (0x79c00c20, 2, Width::W32, true),
            (0x79800c20, 2, Width::X64, true),
            (0xb9800c20, 4, Width::X64, true),
            (0x18000040, 4, Width::W32, false),
            (0x58000040, 8, Width::X64, false),
            (0x98000040, 4, Width::X64, true),
        ] {
            let instruction = Decoder.lift(BASE, word).unwrap();
            let load = ScalarLoad::from_instruction(&instruction).unwrap();
            assert_eq!(
                (
                    load.bytes(),
                    load.result_width(),
                    load.signed(),
                    load.destination()
                ),
                (bytes, width, signed, Register::X(0))
            );
        }
        let instruction = Decoder.lift(GuestAddress(0x103470), 0x18000a9b).unwrap();
        let load = ScalarLoad::from_instruction(&instruction).unwrap();
        assert_eq!(load.destination(), Register::X(27));
        assert_eq!(
            load.address(),
            ScalarLoadAddress::Literal { address: 0x1035c0 }
        );
        assert_eq!(load.writeback_base(), None);
    }

    #[test]
    fn canonical_scalar_store_family_has_one_staged_attempt_and_exact_source_intent() {
        use crate::context::memory::{SpAlignmentRequirement, flags, profile_requirements};
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/el1-scalar-stores.S"
        ));
        let mut admitted = 0;
        let mut declined = 0;
        let mut other = 0;
        for row in fixture
            .lines()
            .filter_map(|line| line.trim().strip_prefix(".inst "))
        {
            let word = u32::from_str_radix(
                row.split_whitespace()
                    .next()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap();
            let instruction = Decoder.lift(BASE, word);
            let plan = CompilationPlan::new(
                &bytes(&[word, 0xd503201f]),
                BASE,
                BlockProfile::El1PlatformV1,
                TargetCpu::Baseline,
            );
            if !row.ends_with("; admit") {
                if let Ok(instruction) = instruction {
                    assert!(ScalarStore::from_instruction(&instruction).is_none());
                }
                if row.ends_with("; decline") {
                    assert!(plan.is_err(), "unowned {word:08x}");
                    declined += 1;
                } else {
                    let plan = plan.unwrap_or_else(|error| panic!("other {word:08x}: {error:?}"));
                    assert!(!matches!(
                        plan.el1_platform_intent(),
                        Some(Intent::ScalarStore(_))
                    ));
                    other += 1;
                }
                continue;
            }
            let plan = plan.unwrap_or_else(|error| panic!("store {word:08x}: {error:?}"));
            let Some(Intent::ScalarStore(store)) = plan.el1_platform_intent() else {
                panic!("scalar store intent {word:08x}")
            };
            assert_eq!(plan.source_bytes(), size_of::<u32>());
            assert_eq!(store.source_pc(), BASE);
            assert!(store.matches_instruction(&instruction.unwrap()));
            assert!(store.matches_source(BASE, word));
            assert!(!store.matches_source(GuestAddress(BASE.0 + 4), word));
            assert!(!store.matches_source(BASE, word ^ 1));
            let requirements = store.requirements();
            assert_eq!(plan.memory_requirements(), Some(requirements));
            assert_eq!(
                requirements.required_profile,
                profile_requirements::M0_DEVICE_RAM_SCALAR_STORE
            );
            assert_eq!(requirements.required_host_caps, 0);
            assert_eq!(requirements.required_address_checks, Default::default());
            assert_eq!(requirements.required_pointer_arithmetic, None);
            assert_eq!(
                requirements.required_sp_alignment,
                SpAlignmentRequirement::Any
            );
            let (tag_checked, writeback) = match store.address() {
                ScalarStoreAddress::Literal { .. } => panic!("store cannot have a literal address"),
                ScalarStoreAddress::Immediate { base, mode, .. } => (
                    mode != AddressMode::Offset || base != Register::Sp,
                    (mode != AddressMode::Offset).then_some(base),
                ),
                ScalarStoreAddress::RegisterOffset { .. } => (true, None),
            };
            assert_eq!(store.writeback_base(), writeback);
            assert_eq!(
                requirements.required_flags,
                flags::WRITE | if tag_checked { flags::TAG_CHECKED } else { 0 }
            );
            assert_eq!(
                plan.compile().unwrap().native.source_map,
                vec![(BASE, crate::extended::context_wrapper().len())]
            );
            let prefix = CompilationPlan::new(
                &bytes(&[ADD_X0, word, 0xd503201f]),
                BASE,
                BlockProfile::El1PlatformV1,
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(prefix.source_bytes(), size_of::<u32>());
            assert_eq!(prefix.el1_platform_intent(), Some(Intent::Registers));
            assert!(prefix.memory_requirements().is_none());
            admitted += 1;
        }
        assert_eq!((admitted, declined, other), (101, 20, 9));
    }

    #[test]
    fn scalar_store_metadata_keeps_exact_width_source_roles_and_distinct_capability() {
        use crate::context::memory::profile_requirements;
        for (word, bytes) in [
            (0x39000c20, 1),
            (0x79000c20, 2),
            (0xb9000c20, 4),
            (0xf9000c20, 8),
        ] {
            let instruction = Decoder.lift(BASE, word).unwrap();
            let store = ScalarStore::from_instruction(&instruction).unwrap();
            assert_eq!(store.bytes(), bytes);
            assert_eq!(store.source_register(), Register::X(0));
            assert_eq!(
                store.address(),
                ScalarStoreAddress::Immediate {
                    base: Register::X(1),
                    displacement: i32::from(bytes) * 3,
                    mode: AddressMode::Offset
                }
            );
            assert_eq!(store.writeback_base(), None);
            assert_ne!(
                store.requirements().required_profile,
                profile_requirements::M0_DEVICE_RAM_WRITE8_OR_PAIR
            );
            assert!(ScalarLoad::from_instruction(&instruction).is_none());
        }
        let zero = ScalarStore::from_instruction(&Decoder.lift(BASE, 0xf90003ff).unwrap()).unwrap();
        assert_eq!(zero.source_register(), Register::Zero);
        assert_eq!(
            zero.address(),
            ScalarStoreAddress::Immediate {
                base: Register::Sp,
                displacement: 0,
                mode: AddressMode::Offset
            }
        );
        for word in [0xa9000820, 0x18000040, 0xb8400820, 0xd503201f] {
            assert!(ScalarStore::from_instruction(&Decoder.lift(BASE, word).unwrap()).is_none());
        }
    }
}
