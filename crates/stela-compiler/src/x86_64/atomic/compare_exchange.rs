//! CAS through a same-width LOCK CMPXCHG.
use super::{ValueRegister, commit_rax, input_rax, input_rcx, locked_compare_exchange};
use crate::aarch64::atomic::{Kind, Operand};
use alloc::vec::Vec;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    let Kind::CompareExchange { compare, source } = operand.kind else {
        unreachable!("compare-exchange emitter receives a CAS operand");
    };
    // The parent has checked and staged the address in RDX. Read both inputs
    // before committing the result, including when either aliases the base.
    input_rax(code, operand.bytes, compare);
    input_rcx(code, operand.bytes, source);
    locked_compare_exchange(code, operand.bytes, ValueRegister::Rcx);
    // Narrow inputs already zero the accumulator's upper bits. Both success
    // and failure therefore return the zero-extended old value without another
    // instruction. A fault leaves the architectural compare register intact.
    commit_rax(code, operand.bytes, compare);
}
