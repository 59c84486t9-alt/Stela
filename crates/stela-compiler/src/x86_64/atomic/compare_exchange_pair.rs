//! CASP through same-width atomic updates (CMPXCHG8B/CMPXCHG16B), or for a
//! single agent a plain load, compare, CMOVNE and store.
use super::{
    DWORD_BYTES, QWORD_BYTES, ValueRegister, XOR_EAX_EAX, XOR_ECX_ECX, commit_rax, input_rax,
    input_rax_keeping_flags, input_rcx, input_rcx_keeping_flags, locked_compare_exchange,
};
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        atomic::{Kind, Operand},
    },
};
use alloc::vec::Vec;

const WORD_PAIR_BYTES: u8 = 2 * DWORD_BYTES;
const DOUBLEWORD_PAIR_BYTES: u8 = 2 * QWORD_BYTES;
const WORD_BITS: u8 = 32;
const SHL_RCX_WORD_BITS: &[u8] = &[0x48, 0xc1, 0xe1, WORD_BITS];
const SHR_RCX_WORD_BITS: &[u8] = &[0x48, 0xc1, 0xe9, WORD_BITS];
const OR_RAX_RCX: &[u8] = &[0x48, 0x09, 0xc8];
const OR_RCX_R8: &[u8] = &[0x4c, 0x09, 0xc1];
const MOV_R8_RCX: &[u8] = &[0x49, 0x89, 0xc8];
const MOV_RCX_RAX: &[u8] = &[0x48, 0x89, 0xc1];
const MOV_EAX_EAX: &[u8] = &[0x89, 0xc0];
const MOV_RAX_RCX: &[u8] = &[0x48, 0x89, 0xc8];
const MOV_R8_RDX: &[u8] = &[0x49, 0x89, 0xd0];
const MOV_R9_RBX: &[u8] = &[0x49, 0x89, 0xd9];
const MOV_RDX_RCX: &[u8] = &[0x48, 0x89, 0xca];
const MOV_RBX_RCX: &[u8] = &[0x48, 0x89, 0xcb];
const MOV_EDX_ECX: &[u8] = &[0x89, 0xca];
const MOV_EBX_ECX: &[u8] = &[0x89, 0xcb];
const MOV_EAX_EDX: &[u8] = &[0x89, 0xd0];
const MOV_RBX_R9: &[u8] = &[0x4c, 0x89, 0xcb];
const MOV_RAX_RDX: &[u8] = &[0x48, 0x89, 0xd0];
const XOR_EDX_EDX: &[u8] = &[0x31, 0xd2];
const XOR_EBX_EBX: &[u8] = &[0x31, 0xdb];
const LOCK_XADD_RDX_RAX: &[u8] = &[0xf0, 0x48, 0x0f, 0xc1, 0x02];
const LOCK_CMPXCHG8B_R8: &[u8] = &[0xf0, 0x41, 0x0f, 0xc7, 0x08];
const LOCK_CMPXCHG16B_R8: &[u8] = &[0xf0, 0x49, 0x0f, 0xc7, 0x08];
const MOV_R8_RDX_MEMORY: &[u8] = &[0x4c, 0x8b, 0x02];
const MOV_R9_RDX_MEMORY: &[u8] = &[0x4c, 0x8b, 0x0a];
/// `mov r9, [rdx+8]`: the high doubleword.
const MOV_R9_RDX_HIGH_MEMORY: &[u8] = &[0x4c, 0x8b, 0x4a, QWORD_BYTES];
const MOV_RDX_MEMORY_RAX: &[u8] = &[0x48, 0x89, 0x02];
const MOV_RDX_MEMORY_RCX: &[u8] = &[0x48, 0x89, 0x0a];
/// `mov [rdx+8], rcx`.
const MOV_RDX_HIGH_MEMORY_RCX: &[u8] = &[0x48, 0x89, 0x4a, QWORD_BYTES];
const MOV_RAX_R8: &[u8] = &[0x4c, 0x89, 0xc0];
const MOV_RAX_R9: &[u8] = &[0x4c, 0x89, 0xc8];
const CMP_RAX_R9: &[u8] = &[0x4c, 0x39, 0xc8];
const XOR_RAX_R8: &[u8] = &[0x4c, 0x31, 0xc0];
const XOR_RCX_R9: &[u8] = &[0x4c, 0x31, 0xc9];
const CMOVNE_RAX_R8: &[u8] = &[0x49, 0x0f, 0x45, 0xc0];
const CMOVNE_RCX_R9: &[u8] = &[0x49, 0x0f, 0x45, 0xc9];

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu, plain: bool) {
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
fn pack_word_pairs(code: &mut Vec<u8>, compare: [Register; 2], source: [Register; 2]) {
    input_rax(code, DWORD_BYTES, compare[0]);
    if compare[1] != Register::Zero {
        input_rcx(code, DWORD_BYTES, compare[1]);
        code.extend(SHL_RCX_WORD_BITS);
        code.extend(OR_RAX_RCX);
    }
    input_rcx(code, DWORD_BYTES, source[0]);
    if source[1] != Register::Zero {
        code.extend(MOV_R8_RCX);
        input_rcx(code, DWORD_BYTES, source[1]);
        code.extend(SHL_RCX_WORD_BITS);
        code.extend(OR_RCX_R8);
    }
}

fn word_pair(
    code: &mut Vec<u8>,
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
        code.extend(MOV_R9_RDX_MEMORY);
        code.extend(CMP_RAX_R9);
        code.extend(CMOVNE_RCX_R9);
        code.extend(MOV_RDX_MEMORY_RCX);
        code.extend(MOV_RAX_R9);
    } else if source == compare {
        // Equal compare/new pairs always leave RAM unchanged. XADD of zero still
        // checks write permission and atomically returns the complete old pair.
        code.extend(XOR_EAX_EAX);
        code.extend(LOCK_XADD_RDX_RAX);
    } else if target.supports(TargetCpu::Cx8)
        && compare[1] != Register::Zero
        && source[1] != Register::Zero
    {
        word_pair_cx8(code, compare, source);
        return;
    } else {
        pack_word_pairs(code, compare, source);
        locked_compare_exchange(code, QWORD_BYTES, ValueRegister::Rcx);
    }
    commit_word_pair(code, compare);
}

fn commit_word_pair(code: &mut Vec<u8>, compare: [Register; 2]) {
    // Preserve the upper old word before normalizing and committing the lower
    // word. Both returned W values independently zero-extend into their X slots.
    if compare[1] != Register::Zero {
        code.extend(MOV_RCX_RAX);
        code.extend(SHR_RCX_WORD_BITS);
    }
    code.extend(MOV_EAX_EAX);
    commit_rax(code, DWORD_BYTES, compare[0]);
    if compare[1] != Register::Zero {
        code.extend(MOV_RAX_RCX);
        commit_rax(code, DWORD_BYTES, compare[1]);
    }
}

fn word_pair_cx8(code: &mut Vec<u8>, compare: [Register; 2], source: [Register; 2]) {
    code.extend(MOV_R8_RDX);
    input_rax(code, DWORD_BYTES, compare[0]);
    input_rcx(code, DWORD_BYTES, compare[1]);
    code.extend(MOV_EDX_ECX);
    code.extend(MOV_R9_RBX);
    input_rcx(code, DWORD_BYTES, source[0]);
    code.extend(MOV_EBX_ECX);
    input_rcx(code, DWORD_BYTES, source[1]);
    code.extend(LOCK_CMPXCHG8B_R8);
    code.extend(MOV_RBX_R9);
    // Every input half is zero-extended. Failed CX8 writes EAX/EDX, while success
    // retains those staged halves, so both paths return complete W results.
    commit_rax(code, DWORD_BYTES, compare[0]);
    code.extend(MOV_EAX_EDX);
    commit_rax(code, DWORD_BYTES, compare[1]);
}

/// A single agent's 128-bit CASP: the old pair into R8 and R9 (both loads
/// first, so a read that would fault reports WnR 0), ZF from the XOR of each
/// half with its compare register, the new halves kept only when both match,
/// and a store of the selected pair either way, as CMPXCHG16B writes back a
/// failed comparison's old value (Arm `Unpredictable_WRITEFAILEDCAS`). The
/// pair is 16-byte aligned, so both halves are in one page. No CMPXCHG16B,
/// and RBX stays the host's.
fn plain_doubleword_pair(code: &mut Vec<u8>, compare: [Register; 2], source: [Register; 2]) {
    code.extend(MOV_R8_RDX_MEMORY);
    code.extend(MOV_R9_RDX_HIGH_MEMORY);
    input_rax(code, QWORD_BYTES, compare[0]);
    input_rcx(code, QWORD_BYTES, compare[1]);
    code.extend(XOR_RAX_R8);
    code.extend(XOR_RCX_R9);
    code.extend(OR_RAX_RCX);
    input_rax_keeping_flags(code, QWORD_BYTES, source[0]);
    input_rcx_keeping_flags(code, QWORD_BYTES, source[1]);
    code.extend(CMOVNE_RAX_R8);
    code.extend(CMOVNE_RCX_R9);
    code.extend(MOV_RDX_MEMORY_RAX);
    code.extend(MOV_RDX_HIGH_MEMORY_RCX);
    code.extend(MOV_RAX_R8);
    commit_rax(code, QWORD_BYTES, compare[0]);
    if compare[1] != Register::Zero {
        code.extend(MOV_RAX_R9);
        commit_rax(code, QWORD_BYTES, compare[1]);
    }
}

fn doubleword_pair(code: &mut Vec<u8>, compare: [Register; 2], source: [Register; 2]) {
    code.extend(MOV_R8_RDX);
    if source == compare {
        code.extend(MOV_R9_RBX);
        // CAS128(0, 0) never changes RAM and always returns the old 128 bits,
        // even when the pair comparison would have succeeded.
        code.extend(XOR_EAX_EAX);
        code.extend(XOR_EDX_EDX);
        code.extend(XOR_EBX_EBX);
        code.extend(XOR_ECX_ECX);
    } else {
        input_rax(code, QWORD_BYTES, compare[0]);
        input_rcx(code, QWORD_BYTES, compare[1]);
        code.extend(MOV_RDX_RCX);
        code.extend(MOV_R9_RBX);
        input_rcx(code, QWORD_BYTES, source[0]);
        code.extend(MOV_RBX_RCX);
        input_rcx(code, QWORD_BYTES, source[1]);
    }
    code.extend(LOCK_CMPXCHG16B_R8);
    // Restore the host callee-saved register immediately after the only guest
    // memory access. Target faults occur before either compare-pair commit.
    code.extend(MOV_RBX_R9);
    commit_rax(code, QWORD_BYTES, compare[0]);
    if compare[1] != Register::Zero {
        code.extend(MOV_RAX_RDX);
        commit_rax(code, QWORD_BYTES, compare[1]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::atomic::Order;

    fn pair(bytes: u8, compare: [Register; 2], source: [Register; 2], plain: bool) -> Vec<u8> {
        let operand = Operand {
            bytes,
            base: Register::X(9),
            order: Order::AcquireRelease,
            kind: Kind::CompareExchangePair { compare, source },
        };
        let mut code = Vec::new();
        emit(&mut code, &operand, TargetCpu::detect(), plain);
        code
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
            CMOVNE_RCX_R9,
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
