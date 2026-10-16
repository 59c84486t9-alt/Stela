//! Canonical X-base LDP metadata. No physical/source/control or PE authority.
use super::SourceFailure;
use stela_compiler::{
    GuestAddress, GuestState, Lifter,
    aarch64::{AddressMode, Decoder, Instruction, Operation, Register},
    context::memory::{MemoryRequirements, SpAlignmentRequirement, flags, profile_requirements},
};
const MEMBER_BYTES: u64 = size_of::<u64>() as u64;
const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum M0ReadMember {
    First,
    Second,
}
#[derive(Debug)]
pub(crate) struct M0ReadPairSource {
    pc: GuestAddress,
    word: u32,
    next_pc: GuestAddress,
    base: u8,
    displacement: i32,
    mode: AddressMode,
    destinations: [Register; 2],
}
impl M0ReadPairSource {
    pub(crate) fn from_source(instruction: &Instruction, word: u32) -> Result<Self, SourceFailure> {
        if Decoder
            .lift(instruction.pc, word)
            .map_err(|_| SourceFailure::Decode)?
            != *instruction
        {
            return Err(SourceFailure::SourceMismatch);
        }
        if stela_compiler::block::el1_platform::Read64Pair::from_instruction(instruction).is_none()
        {
            return Err(SourceFailure::UnsupportedShape);
        }
        let Operation::MemoryPair {
            data,
            base: Register::X(base),
            displacement,
            mode,
            ..
        } = instruction.operation
        else {
            return Err(SourceFailure::UnsupportedShape);
        };
        Ok(Self {
            pc: instruction.pc,
            word,
            next_pc: GuestAddress(
                instruction
                    .pc
                    .0
                    .checked_add(INSTRUCTION_BYTES)
                    .ok_or(SourceFailure::ContinuationOverflow)?,
            ),
            base,
            displacement,
            mode,
            destinations: data,
        })
    }
    pub(crate) fn requirements(&self) -> MemoryRequirements {
        MemoryRequirements {
            required_flags: flags::PAIR | flags::TAG_CHECKED,
            required_host_caps: 0,
            required_profile: profile_requirements::M0_DEVICE_RAM_READ64_PAIR_NO_LSE2,
            required_sp_alignment: SpAlignmentRequirement::Any,
            required_address_checks: Default::default(),
            required_pointer_arithmetic: None,
        }
    }
    pub(crate) fn intent(&self, registers: &GuestState) -> M0ReadPairIntent {
        let original_base = registers.x[usize::from(self.base)];
        M0ReadPairIntent {
            source_pc: self.pc,
            source_word: self.word,
            next_pc: self.next_pc,
            raw_address: if self.mode == AddressMode::PostIndex {
                original_base
            } else {
                original_base.wrapping_add_signed(i64::from(self.displacement))
            },
            flags: self.requirements().required_flags,
            destinations: self.destinations,
        }
    }
    pub(crate) fn writeback(&self, registers: &GuestState) -> Option<(u8, u64)> {
        (self.mode != AddressMode::Offset).then(|| {
            (
                self.base,
                registers.x[usize::from(self.base)]
                    .wrapping_add_signed(i64::from(self.displacement)),
            )
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct M0ReadPairIntent {
    pub(crate) source_pc: GuestAddress,
    pub(crate) source_word: u32,
    pub(crate) next_pc: GuestAddress,
    pub(crate) raw_address: u64,
    pub(crate) flags: u32,
    pub(crate) destinations: [Register; 2],
}
impl M0ReadPairIntent {
    pub(crate) fn member(self, member: M0ReadMember) -> u64 {
        match member {
            M0ReadMember::First => self.raw_address,
            M0ReadMember::Second => self.raw_address.wrapping_add(MEMBER_BYTES),
        }
    }
    pub(crate) fn bytes(self) -> u64 {
        MEMBER_BYTES * 2
    }
}
