//! STP metadata for the M0 write.
use stela_compiler::{
    GuestAddress, GuestState,
    aarch64::{AddressMode, Instruction, MemoryTransfer, Operation, Register},
    context::memory::{MemoryRequirements, SpAlignmentRequirement, flags, profile_requirements},
};
const WORD_BYTES: u8 = size_of::<u64>() as u8;
const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;
const REGISTER_COUNT: u8 = 31;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum M0WriteMember {
    First,
    Second,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum M0WriteMembers {
    Single,
    Pair,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceFailure {
    UnsupportedShape,
    ContinuationOverflow,
}
#[derive(Debug)]
pub(crate) struct M0WriteSource {
    pc: GuestAddress,
    word: u32,
    next_pc: GuestAddress,
    base: u8,
    displacement: i32,
    mode: AddressMode,
    data: [Register; 2],
    members: M0WriteMembers,
}
impl M0WriteSource {
    pub(crate) fn from_source(instruction: &Instruction, word: u32) -> Result<Self, SourceFailure> {
        let (data, base, displacement, mode, members) = match instruction.operation {
            Operation::MemoryPair {
                transfer: MemoryTransfer::Store,
                bytes: WORD_BYTES,
                data,
                base: Register::X(base),
                displacement,
                mode,
            } if stela_compiler::block::el1_platform::Write64Pair::from_instruction(
                instruction,
            )
            .is_some() =>
            {
                (data, base, displacement, mode, M0WriteMembers::Pair)
            }
            Operation::Memory {
                transfer: MemoryTransfer::Store,
                bytes: WORD_BYTES,
                data,
                base: Register::X(base),
                displacement,
                mode: AddressMode::Offset,
            } => (
                [data, Register::Zero],
                base,
                displacement,
                AddressMode::Offset,
                M0WriteMembers::Single,
            ),
            _ => return Err(SourceFailure::UnsupportedShape),
        };
        // SP requires a real SP-alignment exception owner before data access;
        // it is deliberately not admitted by this initial X-base producer.
        if base >= REGISTER_COUNT
            || data.iter().any(|register| {
                !matches!(register, Register::X(index) if *index < REGISTER_COUNT)
                    && *register != Register::Zero
            })
            || mode != AddressMode::Offset && data.contains(&Register::X(base))
        {
            return Err(SourceFailure::UnsupportedShape);
        }
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
            data,
            members,
        })
    }
    pub(crate) fn requirements(&self) -> MemoryRequirements {
        MemoryRequirements {
            required_flags: flags::WRITE
                | flags::TAG_CHECKED
                | if self.members == M0WriteMembers::Pair {
                    flags::PAIR
                } else {
                    0
                },
            required_host_caps: 0,
            required_profile: profile_requirements::M0_DEVICE_RAM_WRITE8_OR_PAIR,
            required_sp_alignment: SpAlignmentRequirement::Any,
            required_address_checks: Default::default(),
            required_pointer_arithmetic: None,
        }
    }
    pub(crate) fn intent(&self, registers: &GuestState) -> M0WriteIntent {
        let original_base = registers.x[usize::from(self.base)];
        let offset = original_base.wrapping_add_signed(i64::from(self.displacement));
        M0WriteIntent {
            source_pc: self.pc,
            source_word: self.word,
            next_pc: self.next_pc,
            raw_address: if self.mode == AddressMode::PostIndex {
                original_base
            } else {
                offset
            },
            members: self.members,
            data: self.data.map(|register| match register {
                Register::X(index) => registers.x[usize::from(index)],
                Register::Zero => 0,
                _ => unreachable!("validated GPR/ZR source"),
            }),
            flags: self.requirements().required_flags,
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
pub(crate) struct M0WriteIntent {
    pub(crate) source_pc: GuestAddress,
    pub(crate) source_word: u32,
    pub(crate) next_pc: GuestAddress,
    pub(crate) raw_address: u64,
    pub(crate) members: M0WriteMembers,
    pub(crate) data: [u64; 2],
    pub(crate) flags: u32,
}
impl M0WriteIntent {
    pub(crate) fn member(self, member: M0WriteMember) -> Option<(u64, u64)> {
        match member {
            M0WriteMember::First => Some((self.raw_address, self.data[0])),
            M0WriteMember::Second if self.members == M0WriteMembers::Pair => Some((
                self.raw_address.wrapping_add(u64::from(WORD_BYTES)),
                self.data[1],
            )),
            M0WriteMember::Second => None,
        }
    }
    pub(crate) fn bytes(self) -> u64 {
        u64::from(WORD_BYTES)
            * if self.members == M0WriteMembers::Pair {
                2
            } else {
                1
            }
    }
}
