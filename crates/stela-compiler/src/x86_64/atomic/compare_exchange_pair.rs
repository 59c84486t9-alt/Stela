//! CASP uses exact-width atomic updates, with checked CX8 for ordinary W pairs.
use super::{
    DWORD_BYTES, QWORD_BYTES, ValueRegister, XOR_EAX_EAX, XOR_ECX_ECX, commit_rax, input_rax,
    input_rcx, locked_compare_exchange,
};
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        atomic::{Kind, Operand},
    },
};

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

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    let Kind::CompareExchangePair { compare, source } = operand.kind else {
        unreachable!("pair compare-exchange emitter receives a CASP operand");
    };
    // The parent stages the checked address in RDX before any input/result alias
    // can change. The decoder validates even first registers and pair widths.
    match operand.bytes {
        WORD_PAIR_BYTES => word_pair(code, compare, source, target),
        DOUBLEWORD_PAIR_BYTES => doubleword_pair(code, compare, source),
        _ => unreachable!("decoder validates compare-exchange pair width"),
    }
}

fn word_pair(code: &mut Vec<u8>, compare: [Register; 2], source: [Register; 2], target: TargetCpu) {
    if source == compare {
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

fn doubleword_pair(code: &mut Vec<u8>, compare: [Register; 2], source: [Register; 2]) {
    code.extend(MOV_R8_RDX);
    if source == compare {
        code.extend(MOV_R9_RBX);
        // CAS128(0, 0) leaves RAM unchanged on either outcome and returns old128,
        // including when the original same-pair comparison would have succeeded.
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
