//! CAS through a same-width LOCK CMPXCHG, or for a single agent a plain
//! load, compare, CMOVNE and store ([`plain`]).
use super::{
    QWORD_BYTES, commit_rax, input_rax, input_rcx, locked_compare_exchange, read_r8, size,
    store_rcx,
};
use crate::aarch64::atomic::{Kind, Operand};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Size};

pub(super) fn emit(code: &mut Code, operand: &Operand, plain_access: bool) {
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
        locked_compare_exchange(code, operand.bytes, Gpr::Rcx);
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
fn plain(code: &mut Code, bytes: u8) {
    let wide = Size::of(bytes == QWORD_BYTES);
    read_r8(code, bytes);
    let mut asm = code.asm();
    asm.alu(Alu::Cmp, size(bytes), Gpr::Rax, Gpr::R8);
    asm.cmov(Cond::Ne, wide, Gpr::Rcx, Gpr::R8);
    store_rcx(code, bytes);
    code.asm().mov(wide, Gpr::Rax, Gpr::R8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::{Register, atomic::Order};
    use alloc::vec::Vec;

    const BYTE_BYTES: u8 = 1;
    const HALFWORD_BYTES: u8 = 2;

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
            let mut code = Code::new();
            emit(&mut code, &operand, true);
            let expected: Vec<u8> = [load, compare, select, store, result].concat();
            let at = code
                .windows(expected.len())
                .position(|window| window == expected)
                .unwrap_or_else(|| panic!("{bytes}: {code:02x?}"));
            // Then only the commit of the old value to X1.
            assert_eq!(&code[at + expected.len()..], [0x48, 0x89, 0x87, 8, 0, 0, 0]);
            let mut locked = Code::new();
            emit(&mut locked, &operand, false);
            assert!(locked.contains(&0xf0) && !code.contains(&0xf0));
        }
    }
}
