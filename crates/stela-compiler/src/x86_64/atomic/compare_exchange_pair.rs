//! CASP through same-width atomic updates (CMPXCHG8B/CMPXCHG16B), or for a
//! single agent a plain load, compare, CMOVNE and store.
use super::{
    ADDRESS, DWORD_BYTES, QWORD_BYTES, commit_rax, input_rax, input_rax_keeping_flags, input_rcx,
    input_rcx_keeping_flags, locked_compare_exchange,
};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Mem, ShiftOp, Size};
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        atomic::{Kind, Operand},
    },
};
use Gpr::{R8, R9, Rax, Rbx, Rcx, Rdx};
use Size::{Dword, Qword};

const WORD_PAIR_BYTES: u8 = 2 * DWORD_BYTES;
const DOUBLEWORD_PAIR_BYTES: u8 = 2 * QWORD_BYTES;
const WORD_BITS: u8 = 32;
/// `[rdx+8]`: the high doubleword.
const HIGH_ADDRESS: Mem = Mem::base(Rdx, QWORD_BYTES as i32);

pub(super) fn emit(code: &mut Code, operand: &Operand, target: TargetCpu, plain: bool) {
    let Kind::CompareExchangePair { compare, source } = operand.kind else {
        unreachable!("pair compare-exchange emitter receives a CASP operand");
    };
    // The parent stages the checked address in RDX before any input/result alias
    // can change. The decoder validates even first registers and pair widths.
    match operand.bytes {
        WORD_PAIR_BYTES => word_pair(code, compare, source, target, plain),
        DOUBLEWORD_PAIR_BYTES if plain => plain_doubleword_pair(code, compare, source),
        DOUBLEWORD_PAIR_BYTES => doubleword_pair(code, compare, source),
        _ => unreachable!("decoder validates compare-exchange pair width"),
    }
}

/// Pack the compare pair into RAX and the new pair into RCX, low word first.
fn pack_word_pairs(code: &mut Code, compare: [Register; 2], source: [Register; 2]) {
    input_rax(code, DWORD_BYTES, compare[0]);
    if compare[1] != Register::Zero {
        input_rcx(code, DWORD_BYTES, compare[1]);
        let mut asm = code.asm();
        asm.shift_imm(ShiftOp::Shl, Qword, Rcx, WORD_BITS);
        asm.alu(Alu::Or, Qword, Rax, Rcx);
    }
    input_rcx(code, DWORD_BYTES, source[0]);
    if source[1] != Register::Zero {
        code.asm().mov(Qword, R8, Rcx);
        input_rcx(code, DWORD_BYTES, source[1]);
        let mut asm = code.asm();
        asm.shift_imm(ShiftOp::Shl, Qword, Rcx, WORD_BITS);
        asm.alu(Alu::Or, Qword, Rcx, R8);
    }
}

fn word_pair(
    code: &mut Code,
    compare: [Register; 2],
    source: [Register; 2],
    target: TargetCpu,
    plain: bool,
) {
    if plain {
        // A single agent's CASP is one load of the old pair, a compare and a
        // store of the new pair or, as LOCK CMPXCHG does, of the old one
        // (Arm `Unpredictable_WRITEFAILEDCAS`). The load comes first, so a
        // read that would fault reports WnR 0.
        pack_word_pairs(code, compare, source);
        let mut asm = code.asm();
        asm.guest_access(|asm| asm.mov_load(Qword, R9, ADDRESS));
        asm.alu(Alu::Cmp, Qword, Rax, R9);
        asm.cmov(Cond::Ne, Qword, Rcx, R9);
        asm.guest_access(|asm| asm.mov_store(Qword, ADDRESS, Rcx));
        asm.mov(Qword, Rax, R9);
    } else if source == compare {
        // Equal compare/new pairs always leave RAM unchanged. XADD of zero still
        // checks write permission and atomically returns the complete old pair.
        let mut asm = code.asm();
        asm.alu(Alu::Xor, Dword, Rax, Rax);
        asm.guest_access(|asm| {
            asm.lock();
            asm.xadd(Qword, ADDRESS, Rax)
        });
    } else if target.supports(TargetCpu::Cx8)
        && compare[1] != Register::Zero
        && source[1] != Register::Zero
    {
        word_pair_cx8(code, compare, source);
        return;
    } else {
        pack_word_pairs(code, compare, source);
        locked_compare_exchange(code, QWORD_BYTES, Rcx);
    }
    commit_word_pair(code, compare);
}

fn commit_word_pair(code: &mut Code, compare: [Register; 2]) {
    // Preserve the upper old word before normalizing and committing the lower
    // word. Both returned W values independently zero-extend into their X slots.
    let mut asm = code.asm();
    if compare[1] != Register::Zero {
        asm.mov(Qword, Rcx, Rax);
        asm.shift_imm(ShiftOp::Shr, Qword, Rcx, WORD_BITS);
    }
    asm.mov(Dword, Rax, Rax);
    commit_rax(code, DWORD_BYTES, compare[0]);
    if compare[1] != Register::Zero {
        code.asm().mov(Qword, Rax, Rcx);
        commit_rax(code, DWORD_BYTES, compare[1]);
    }
}

fn word_pair_cx8(code: &mut Code, compare: [Register; 2], source: [Register; 2]) {
    code.asm().mov(Qword, R8, Rdx);
    input_rax(code, DWORD_BYTES, compare[0]);
    input_rcx(code, DWORD_BYTES, compare[1]);
    let mut asm = code.asm();
    asm.mov(Dword, Rdx, Rcx);
    asm.mov(Qword, R9, Rbx);
    input_rcx(code, DWORD_BYTES, source[0]);
    code.asm().mov(Dword, Rbx, Rcx);
    input_rcx(code, DWORD_BYTES, source[1]);
    let mut asm = code.asm();
    asm.guest_access(|asm| {
        asm.lock();
        asm.cmpxchg8b(Mem::base(R8, 0))
    });
    asm.mov(Qword, Rbx, R9);
    // Every input half is zero-extended. Failed CX8 writes EAX/EDX, while success
    // retains those staged halves, so both paths return complete W results.
    commit_rax(code, DWORD_BYTES, compare[0]);
    code.asm().mov(Dword, Rax, Rdx);
    commit_rax(code, DWORD_BYTES, compare[1]);
}

/// A single agent's 128-bit CASP: the old pair into R8 and R9 (both loads
/// first, so a read that would fault reports WnR 0), ZF from the XOR of each
/// half with its compare register, the new halves kept only when both match,
/// and a store of the selected pair either way, as CMPXCHG16B writes back a
/// failed comparison's old value (Arm `Unpredictable_WRITEFAILEDCAS`). The
/// pair is 16-byte aligned, so both halves are in one page. No CMPXCHG16B,
/// and RBX stays the host's.
fn plain_doubleword_pair(code: &mut Code, compare: [Register; 2], source: [Register; 2]) {
    let mut asm = code.asm();
    asm.guest_access(|asm| asm.mov_load(Qword, R8, ADDRESS));
    asm.guest_access(|asm| asm.mov_load(Qword, R9, HIGH_ADDRESS));
    input_rax(code, QWORD_BYTES, compare[0]);
    input_rcx(code, QWORD_BYTES, compare[1]);
    let mut asm = code.asm();
    asm.alu(Alu::Xor, Qword, Rax, R8);
    asm.alu(Alu::Xor, Qword, Rcx, R9);
    asm.alu(Alu::Or, Qword, Rax, Rcx);
    input_rax_keeping_flags(code, QWORD_BYTES, source[0]);
    input_rcx_keeping_flags(code, QWORD_BYTES, source[1]);
    let mut asm = code.asm();
    asm.cmov(Cond::Ne, Qword, Rax, R8);
    asm.cmov(Cond::Ne, Qword, Rcx, R9);
    asm.guest_access(|asm| asm.mov_store(Qword, ADDRESS, Rax));
    asm.guest_access(|asm| asm.mov_store(Qword, HIGH_ADDRESS, Rcx));
    asm.mov(Qword, Rax, R8);
    commit_rax(code, QWORD_BYTES, compare[0]);
    if compare[1] != Register::Zero {
        code.asm().mov(Qword, Rax, R9);
        commit_rax(code, QWORD_BYTES, compare[1]);
    }
}

fn doubleword_pair(code: &mut Code, compare: [Register; 2], source: [Register; 2]) {
    code.asm().mov(Qword, R8, Rdx);
    if source == compare {
        let mut asm = code.asm();
        asm.mov(Qword, R9, Rbx);
        // CAS128(0, 0) never changes RAM and always returns the old 128 bits,
        // even when the pair comparison would have succeeded.
        for register in [Rax, Rdx, Rbx, Rcx] {
            asm.alu(Alu::Xor, Dword, register, register);
        }
    } else {
        input_rax(code, QWORD_BYTES, compare[0]);
        input_rcx(code, QWORD_BYTES, compare[1]);
        let mut asm = code.asm();
        asm.mov(Qword, Rdx, Rcx);
        asm.mov(Qword, R9, Rbx);
        input_rcx(code, QWORD_BYTES, source[0]);
        code.asm().mov(Qword, Rbx, Rcx);
        input_rcx(code, QWORD_BYTES, source[1]);
    }
    let mut asm = code.asm();
    asm.guest_access(|asm| {
        asm.lock();
        asm.cmpxchg16b(Mem::base(R8, 0))
    });
    // Restore the host callee-saved register immediately after the only guest
    // memory access. Target faults occur before either compare-pair commit.
    asm.mov(Qword, Rbx, R9);
    commit_rax(code, QWORD_BYTES, compare[0]);
    if compare[1] != Register::Zero {
        code.asm().mov(Qword, Rax, Rdx);
        commit_rax(code, QWORD_BYTES, compare[1]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::atomic::Order;
    use alloc::vec::Vec;

    const OR_RAX_RCX: &[u8] = &[0x48, 0x09, 0xc8];
    const MOV_R9_RBX: &[u8] = &[0x49, 0x89, 0xd9];
    const MOV_RBX_R9: &[u8] = &[0x4c, 0x89, 0xcb];
    const LOCK_CMPXCHG16B_R8: &[u8] = &[0xf0, 0x49, 0x0f, 0xc7, 0x08];
    const MOV_R8_RDX_MEMORY: &[u8] = &[0x4c, 0x8b, 0x02];
    const MOV_R9_RDX_MEMORY: &[u8] = &[0x4c, 0x8b, 0x0a];
    const MOV_R9_RDX_HIGH_MEMORY: &[u8] = &[0x4c, 0x8b, 0x4a, 8];
    const MOV_RDX_MEMORY_RAX: &[u8] = &[0x48, 0x89, 0x02];
    const MOV_RDX_MEMORY_RCX: &[u8] = &[0x48, 0x89, 0x0a];
    const MOV_RDX_HIGH_MEMORY_RCX: &[u8] = &[0x48, 0x89, 0x4a, 8];
    const MOV_RAX_R8: &[u8] = &[0x4c, 0x89, 0xc0];
    const MOV_RAX_R9: &[u8] = &[0x4c, 0x89, 0xc8];
    const CMP_RAX_R9: &[u8] = &[0x4c, 0x39, 0xc8];
    const XOR_RAX_R8: &[u8] = &[0x4c, 0x31, 0xc0];
    const XOR_RCX_R9: &[u8] = &[0x4c, 0x31, 0xc9];
    const CMOVNE_RAX_R8: &[u8] = &[0x49, 0x0f, 0x45, 0xc0];
    const CMOVNE_RCX_R9: &[u8] = &[0x49, 0x0f, 0x45, 0xc9];

    fn pair(bytes: u8, compare: [Register; 2], source: [Register; 2], plain: bool) -> Vec<u8> {
        let operand = Operand {
            bytes,
            base: Register::X(9),
            order: Order::AcquireRelease,
            kind: Kind::CompareExchangePair { compare, source },
        };
        let mut code = Code::new();
        emit(&mut code, &operand, TargetCpu::detect(), plain);
        code.into_bytes()
    }

    fn has(code: &[u8], bytes: &[u8]) -> bool {
        code.windows(bytes.len()).any(|window| window == bytes)
    }

    #[test]
    fn a_single_agent_casp_loads_compares_selects_and_stores_without_lock() {
        let compare = [Register::X(0), Register::X(1)];
        let source = [Register::X(2), Register::X(3)];
        let words = pair(WORD_PAIR_BYTES, compare, source, true);
        let word_recipe = [
            MOV_R9_RDX_MEMORY,
            CMP_RAX_R9,
            &[0x49, 0x0f, 0x45, 0xc9],
            MOV_RDX_MEMORY_RCX,
            MOV_RAX_R9,
        ]
        .concat();
        assert!(has(&words, &word_recipe), "{words:02x?}");
        let doublewords = pair(DOUBLEWORD_PAIR_BYTES, compare, source, true);
        // Both loads come first, and RBX is never touched.
        let loads = [MOV_R8_RDX_MEMORY, MOV_R9_RDX_HIGH_MEMORY].concat();
        assert!(doublewords.starts_with(&loads), "{doublewords:02x?}");
        for step in [
            [XOR_RAX_R8, XOR_RCX_R9, OR_RAX_RCX].concat(),
            [CMOVNE_RAX_R8, CMOVNE_RCX_R9].concat(),
            [MOV_RDX_MEMORY_RAX, MOV_RDX_HIGH_MEMORY_RCX, MOV_RAX_R8].concat(),
        ] {
            assert!(has(&doublewords, &step), "{doublewords:02x?}");
        }
        assert!(!has(&doublewords, MOV_R9_RBX) && !has(&doublewords, MOV_RBX_R9));
        for code in [&words, &doublewords] {
            assert!(!code.contains(&0xf0), "{code:02x?}");
        }
        assert!(has(
            &pair(DOUBLEWORD_PAIR_BYTES, compare, source, false),
            LOCK_CMPXCHG16B_R8
        ));
    }

    #[test]
    fn a_single_agent_zr_source_keeps_the_compare_flags() {
        // XOR of ECX would clear ZF between the compare and the CMOVNE.
        let code = pair(
            DOUBLEWORD_PAIR_BYTES,
            [Register::X(0), Register::X(1)],
            [Register::Zero, Register::Zero],
            true,
        );
        let flags = OR_RAX_RCX;
        let at = code
            .windows(flags.len())
            .position(|window| window == flags)
            .expect("the compare");
        let selected = code
            .windows(CMOVNE_RAX_R8.len())
            .position(|window| window == CMOVNE_RAX_R8)
            .expect("the select");
        assert_eq!(
            &code[at + flags.len()..selected],
            [0xb8, 0, 0, 0, 0, 0xb9, 0, 0, 0, 0]
        );
    }
}
