//! Scalar load metadata for the M0 read.
use super::*;
use stela_compiler::block::{BlockProfile, el1_platform::ScalarLoad};

impl M0ScalarReadSource {
    pub(crate) fn from_profile(
        profile: BlockProfile,
        instruction: &Instruction,
        word: u32,
    ) -> Result<Self, SourceFailure> {
        match profile {
            BlockProfile::El1PlatformV1 => {
                let load = ScalarLoad::from_instruction(instruction)
                    .ok_or(SourceFailure::UnsupportedShape)?;
                if !load.matches_source(instruction.pc, word)
                    || !load.matches_instruction(instruction)
                {
                    return Err(SourceFailure::SourceMismatch);
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
                    destination: load.destination(),
                    address: ReadAddress::Scalar(load),
                })
            }
            BlockProfile::El1M0IntegerV1 => Self::from_el1_integer_source(instruction, word),
            _ => Self::from_source(instruction, word),
        }
    }
}
pub(super) fn intent(
    load: ScalarLoad,
    source_word: u32,
    registers: &GuestState,
) -> M0ScalarReadIntent {
    let super::super::m0_scalar::AddressInput {
        raw_address,
        stack_pointer,
        writeback,
    } = super::super::m0_scalar::address(load.address(), registers);
    M0ScalarReadIntent {
        source_pc: load.source_pc(),
        source_word,
        next_pc: GuestAddress(load.source_pc().0 + INSTRUCTION_BYTES),
        raw_address,
        flags: load.requirements().required_flags,
        destination: load.destination(),
        bytes: load.bytes(),
        stack_pointer,
        writeback,
    }
}
