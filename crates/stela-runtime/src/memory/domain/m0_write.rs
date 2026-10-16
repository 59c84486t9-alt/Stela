//! Scalar store and STP metadata for the M0 write.
use stela_compiler::{
    GuestAddress, GuestState,
    aarch64::{AddressMode, Instruction, MemoryTransfer, Operation, Register},
    block::el1_platform::{ScalarStore, ScalarStoreAddress},
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
enum WriteShape {
    Scalar(ScalarStore),
    Pair {
        base: u8,
        displacement: i32,
        mode: AddressMode,
        data: [Register; 2],
    },
}
#[derive(Debug)]
pub(crate) struct M0WriteSource {
    pc: GuestAddress,
    word: u32,
    next_pc: GuestAddress,
    shape: WriteShape,
}
impl M0WriteSource {
    pub(crate) fn from_source(instruction: &Instruction, word: u32) -> Result<Self, SourceFailure> {
        let shape = if let Some(store) = ScalarStore::from_instruction(instruction) {
            if !store.matches_source(instruction.pc, word)
                || !store.matches_instruction(instruction)
                || matches!(store.address(), ScalarStoreAddress::Literal { .. })
                || !matches!(store.source_register(), Register::X(index) if index < REGISTER_COUNT)
                    && store.source_register() != Register::Zero
            {
                return Err(SourceFailure::UnsupportedShape);
            }
            WriteShape::Scalar(store)
        } else {
            let Operation::MemoryPair {
                transfer: MemoryTransfer::Store,
                bytes: WORD_BYTES,
                data,
                base: Register::X(base),
                displacement,
                mode,
            } = instruction.operation
            else {
                return Err(SourceFailure::UnsupportedShape);
            };
            if stela_compiler::block::el1_platform::Write64Pair::from_instruction(instruction)
                .is_none()
                || base >= REGISTER_COUNT
                || data.iter().any(|register| {
                    !matches!(register, Register::X(index) if *index < REGISTER_COUNT)
                        && *register != Register::Zero
                })
                || mode != AddressMode::Offset && data.contains(&Register::X(base))
            {
                return Err(SourceFailure::UnsupportedShape);
            }
            WriteShape::Pair {
                base,
                displacement,
                mode,
                data,
            }
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
            shape,
        })
    }
    pub(crate) fn requirements(&self) -> MemoryRequirements {
        match self.shape {
            WriteShape::Scalar(store) => store.requirements(),
            WriteShape::Pair { .. } => MemoryRequirements {
                required_flags: flags::WRITE | flags::TAG_CHECKED | flags::PAIR,
                required_host_caps: 0,
                required_profile: profile_requirements::M0_DEVICE_RAM_WRITE8_OR_PAIR,
                required_sp_alignment: SpAlignmentRequirement::Any,
                required_address_checks: Default::default(),
                required_pointer_arithmetic: None,
            },
        }
    }
    pub(crate) fn intent(&self, registers: &GuestState) -> M0WriteIntent {
        let (raw_address, members, member_bytes, data, stack_pointer, writeback) = match self.shape
        {
            WriteShape::Scalar(store) => {
                let address = super::m0_scalar::address(store.address(), registers);
                (
                    address.raw_address,
                    M0WriteMembers::Single,
                    store.bytes(),
                    [
                        super::m0_scalar::register_value(store.source_register(), registers),
                        0,
                    ],
                    address.stack_pointer,
                    address.writeback,
                )
            }
            WriteShape::Pair {
                base,
                displacement,
                mode,
                data,
            } => {
                let original = registers.x[usize::from(base)];
                let adjusted = original.wrapping_add_signed(i64::from(displacement));
                (
                    if mode == AddressMode::PostIndex {
                        original
                    } else {
                        adjusted
                    },
                    M0WriteMembers::Pair,
                    WORD_BYTES,
                    data.map(|r| super::m0_scalar::register_value(r, registers)),
                    None,
                    (mode != AddressMode::Offset).then_some((Register::X(base), adjusted)),
                )
            }
        };
        M0WriteIntent {
            source_pc: self.pc,
            source_word: self.word,
            next_pc: self.next_pc,
            raw_address,
            members,
            member_bytes,
            data,
            flags: self.requirements().required_flags,
            stack_pointer,
            writeback,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct M0WriteIntent {
    pub(crate) source_pc: GuestAddress,
    pub(crate) source_word: u32,
    pub(crate) next_pc: GuestAddress,
    pub(crate) raw_address: u64,
    pub(crate) members: M0WriteMembers,
    pub(crate) member_bytes: u8,
    pub(crate) data: [u64; 2],
    pub(crate) flags: u32,
    pub(crate) stack_pointer: Option<u64>,
    pub(crate) writeback: Option<(Register, u64)>,
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
    pub(crate) fn member_count(self) -> usize {
        if self.members == M0WriteMembers::Pair {
            2
        } else {
            1
        }
    }
    pub(crate) fn bytes(self) -> u64 {
        u64::from(self.member_bytes) * self.member_count() as u64
    }
}
