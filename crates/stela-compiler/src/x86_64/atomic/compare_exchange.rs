//! CAS through a same-width LOCK CMPXCHG, or for a single agent a plain
//! load, compare, CMOVNE and store ([`plain`]).
use super::{
    QWORD_BYTES, REX_PREFIX, REX_W_BIT, ValueRegister, commit_rax, input_rax, input_rcx,
    locked_compare_exchange, read_r8, store_rcx,
};
use crate::aarch64::atomic::{Kind, Operand};
use alloc::vec::Vec;

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const OPERAND_SIZE_PREFIX: u8 = 0x66;
const REX_R_BIT: u8 = 0x04;
const REX_B_BIT: u8 = 0x01;
const TWO_BYTE_OPCODE: u8 = 0x0f;
const CMP_BYTE: u8 = 0x38;
const CMP_WORD_OR_WIDER: u8 = 0x39;
const CMOVNE: u8 = 0x45;
const MOV_STORE: u8 = 0x89;
/// `eax, r8d` (CMP and MOV with REX.R).
const MODRM_RAX_R8: u8 = 0xc0;
/// `ecx, r8d` (CMOVNE with REX.B).
const MODRM_RCX_R8: u8 = 0xc8;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, plain_access: bool) {
    let Kind::CompareExchange { compare, source } = operand.kind else {
        unreachable!("compare-exchange emitter receives a CAS operand");
    };
    // The parent has checked and staged the address in RDX. Read both inputs
    // before committing the result, including when either aliases the base.
    input_rax(code, operand.bytes, compare);
    input_rcx(code, operand.bytes, source);
    if plain_access {
        plain(code, operand.bytes);
    } else {
        locked_compare_exchange(code, operand.bytes, ValueRegister::Rcx);
    }
    // Narrow inputs already zero the accumulator's upper bits. Both success
    // and failure therefore return the zero-extended old value without another
    // instruction. A fault leaves the architectural compare register intact.
    commit_rax(code, operand.bytes, compare);
}

/// The old value into R8, compared with RAX at the access width; RCX keeps
/// the new value only when they are equal, and is stored either way, as
/// LOCK CMPXCHG writes back a failed comparison's old value (Arm permits a
/// failed CAS to write, `Unpredictable_WRITEFAILEDCAS`). RAX then returns
/// the old value. No branch, LOCK prefix or retry.
fn plain(code: &mut Vec<u8>, bytes: u8) {
    let wide = if bytes == QWORD_BYTES { REX_W_BIT } else { 0 };
    read_r8(code, bytes);
    if bytes == HALFWORD_BYTES {
        code.push(OPERAND_SIZE_PREFIX);
    }
    code.extend([
        REX_PREFIX | REX_R_BIT | wide,
        if bytes == BYTE_BYTES {
            CMP_BYTE
        } else {
            CMP_WORD_OR_WIDER
        },
        MODRM_RAX_R8,
    ]);
    code.extend([
        REX_PREFIX | REX_B_BIT | wide,
        TWO_BYTE_OPCODE,
        CMOVNE,
        MODRM_RCX_R8,
    ]);
    store_rcx(code, bytes);
    code.extend([REX_PREFIX | REX_R_BIT | wide, MOV_STORE, MODRM_RAX_R8]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::{Register, atomic::Order};

    #[test]
    fn a_single_agent_cas_loads_compares_selects_and_stores() {
        for (bytes, load, compare, select, store, result) in [
            (
                BYTE_BYTES,
                &[0x44, 0x0f, 0xb6, 0x02][..],
                &[0x44, 0x38, 0xc0][..],
                &[0x41, 0x0f, 0x45, 0xc8][..],
                &[0x88, 0x0a][..],
                &[0x44, 0x89, 0xc0][..],
            ),
            (
                HALFWORD_BYTES,
                &[0x44, 0x0f, 0xb7, 0x02],
                &[0x66, 0x44, 0x39, 0xc0],
                &[0x41, 0x0f, 0x45, 0xc8],
                &[0x66, 0x89, 0x0a],
                &[0x44, 0x89, 0xc0],
            ),
            (
                4,
                &[0x44, 0x8b, 0x02],
                &[0x44, 0x39, 0xc0],
                &[0x41, 0x0f, 0x45, 0xc8],
                &[0x89, 0x0a],
                &[0x44, 0x89, 0xc0],
            ),
            (
                QWORD_BYTES,
                &[0x4c, 0x8b, 0x02],
                &[0x4c, 0x39, 0xc0],
                &[0x49, 0x0f, 0x45, 0xc8],
                &[0x48, 0x89, 0x0a],
                &[0x4c, 0x89, 0xc0],
            ),
        ] {
            let operand = Operand {
                bytes,
                base: Register::X(3),
                order: Order::AcquireRelease,
                kind: Kind::CompareExchange {
                    compare: Register::X(1),
                    source: Register::X(2),
                },
            };
            let mut code = Vec::new();
            emit(&mut code, &operand, true);
            let expected: Vec<u8> = [load, compare, select, store, result].concat();
            let at = code
                .windows(expected.len())
                .position(|window| window == expected)
                .unwrap_or_else(|| panic!("{bytes}: {code:02x?}"));
            // Then only the commit of the old value to X1.
            assert_eq!(&code[at + expected.len()..], [0x48, 0x89, 0x87, 8, 0, 0, 0]);
            let mut locked = Vec::new();
            emit(&mut locked, &operand, false);
            assert!(locked.contains(&0xf0) && !code.contains(&0xf0));
        }
    }
}
