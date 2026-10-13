//! SSE2 bit construction and shared exact-width lane moves; no host FP arithmetic.
use super::{Host, commit, packed, read_vector, rearrange};
use crate::{
    TargetCpu,
    aarch64::simd::immediates::{ConstantOperation, Operand},
};

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    let Operand::Constant {
        destination,
        value,
        bytes,
        operation,
    } = *operand
    else {
        if let Operand::LaneMove(ref lane) = *operand {
            rearrange::emit(code, lane, target);
        }
        return;
    };
    if value == 0 {
        packed(code, Host::Xor, 0, 0);
    } else {
        code.extend([0x48, 0xb9]); // MOVABS RCX, expanded low 64 bits
        code.extend(value.to_le_bytes());
        packed(code, Host::MoveGprQword, 0, 1);
        if bytes == 16 {
            packed(code, Host::UnpackLowQword, 0, 0);
        }
    }
    match operation {
        ConstantOperation::Move => {}
        ConstantOperation::Or => {
            read_vector(code, destination, 1);
            packed(code, Host::Or, 0, 1);
        }
        ConstantOperation::BitClear => {
            read_vector(code, destination, 1);
            packed(code, Host::AndNot, 0, 1);
        }
    }
    if operation != ConstantOperation::Move && bytes == 8 {
        packed(code, Host::MoveQword, 0, 0);
    }
    commit(code, destination, 0);
}
