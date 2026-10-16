//! Address and register values shared by the M0 scalar load and store forms.
use stela_compiler::{
    GuestState,
    aarch64::{AddressMode, Register, register_offset::IndexExtend},
    block::el1_platform::ScalarLoadAddress,
};

pub(super) struct AddressInput {
    pub(super) raw_address: u64,
    pub(super) stack_pointer: Option<u64>,
    pub(super) writeback: Option<(Register, u64)>,
}
pub(super) fn register_value(register: Register, registers: &GuestState) -> u64 {
    match register {
        Register::X(index) => registers.x[usize::from(index)],
        Register::Sp => registers.sp,
        Register::Zero => 0,
    }
}
pub(super) fn address(address: ScalarLoadAddress, registers: &GuestState) -> AddressInput {
    let mut writeback = None;
    let mut stack_pointer = None;
    let raw_address = match address {
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
    AddressInput {
        raw_address,
        stack_pointer,
        writeback,
    }
}
