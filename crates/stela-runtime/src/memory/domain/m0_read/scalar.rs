//! Generic integer load metadata from the compiler's one shared scalar operand.
//! Copied values never grant source, control, RAM or native permission.
use super::*;
use stela_compiler::aarch64::register_offset::IndexExtend;
use stela_compiler::block::{
    BlockProfile,
    el1_platform::{ScalarLoad, ScalarLoadAddress},
};

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
fn register_value(register: Register, registers: &GuestState) -> u64 {
    match register {
        Register::X(index) => registers.x[usize::from(index)],
        Register::Sp => registers.sp,
        Register::Zero => 0,
    }
}
pub(super) fn intent(
    load: ScalarLoad,
    source_word: u32,
    registers: &GuestState,
) -> M0ScalarReadIntent {
    let mut writeback = None;
    let mut stack_pointer = None;
    let raw_address = match load.address() {
        ScalarLoadAddress::Literal { address } => address,
        ScalarLoadAddress::Immediate {
            base,
            displacement,
            mode,
        } => {
            let original = register_value(base, registers);
            if base == Register::Sp {
                stack_pointer = Some(original);
            }
            let adjusted = original.wrapping_add_signed(i64::from(displacement));
            if mode != AddressMode::Offset {
                writeback = Some((base, adjusted));
            }
            if mode == AddressMode::PostIndex {
                original
            } else {
                adjusted
            }
        }
        ScalarLoadAddress::RegisterOffset {
            base,
            index,
            extend,
            shift,
        } => {
            let original = register_value(base, registers);
            if base == Register::Sp {
                stack_pointer = Some(original);
            }
            let index = register_value(index, registers);
            let extended = match extend {
                IndexExtend::Uxtw => u64::from(index as u32),
                IndexExtend::Sxtw => (index as u32 as i32 as i64) as u64,
                IndexExtend::Lsl | IndexExtend::Sxtx => index,
            };
            original.wrapping_add(extended.wrapping_shl(u32::from(shift)))
        }
    };
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
