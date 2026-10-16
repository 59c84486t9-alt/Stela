//! Materialized guest addresses require only baseline x86-64 MOV instructions.
use super::store;
use crate::aarch64::{Register, pc_relative::Operand};
use alloc::vec::Vec;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    if operand.destination == Register::Zero {
        // Keep each guest instruction's native source-map interval nonempty.
        code.push(0x90);
        return;
    }
    code.extend([0x48, 0xb8]); // movabs rax,imm64; leaves guest NZCV untouched
    code.extend(operand.address.to_le_bytes());
    store(code, operand.destination);
}

#[cfg(test)]
mod tests;
