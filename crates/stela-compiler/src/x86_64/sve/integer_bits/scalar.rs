//! Baseline scalar leading counts; repair BSR's undefined zero result before use.
use crate::aarch64::scalable::ElementSize;
use alloc::vec::Vec;
const CHUNK_BYTES: usize = 16;
const RESULT_SLOT: u8 = CHUNK_BYTES as u8;
const STACK_BYTES: u8 = 2 * CHUNK_BYTES as u8;
const SUB_RSP: [u8; 3] = [0x48, 0x83, 0xec];
const ADD_RSP: [u8; 3] = [0x48, 0x83, 0xc4];
const MOVDQU_STORE_RSP: [u8; 4] = [0xf3, 0x0f, 0x7f, 0x44];
const MOVDQU_LOAD_RSP: [u8; 4] = [0xf3, 0x0f, 0x6f, 0x44];
const STACK_SIB: u8 = 0x24;
const MOVZX_EAX_BYTE: [u8; 3] = [0x0f, 0xb6, 0x44];
const MOVSX_RAX_BYTE: [u8; 4] = [0x48, 0x0f, 0xbe, 0x44];
const MOVZX_EAX_WORD: [u8; 3] = [0x0f, 0xb7, 0x44];
const MOVSX_RAX_WORD: [u8; 4] = [0x48, 0x0f, 0xbf, 0x44];
const MOV_EAX_DWORD: [u8; 2] = [0x8b, 0x44];
const MOVSXD_RAX_DWORD: [u8; 3] = [0x48, 0x63, 0x44];
const MOV_RAX_QWORD: [u8; 3] = [0x48, 0x8b, 0x44];
const MOV_BYTE_AL: [u8; 2] = [0x88, 0x44];
const MOV_WORD_AX: [u8; 3] = [0x66, 0x89, 0x44];
const MOV_DWORD_EAX: [u8; 2] = [0x89, 0x44];
const MOV_QWORD_RAX: [u8; 3] = [0x48, 0x89, 0x44];
const MOV_RDX_RAX: [u8; 3] = [0x48, 0x89, 0xc2];
const SAR_RDX: [u8; 3] = [0x48, 0xc1, 0xfa];
const XOR_RAX_RDX: [u8; 3] = [0x48, 0x31, 0xd0];
const BSR_RDX_RAX: [u8; 4] = [0x48, 0x0f, 0xbd, 0xd0];
const MOV_RCX_SIGNED_IMM32: [u8; 3] = [0x48, 0xc7, 0xc1];
const CMOVZ_RDX_RCX: [u8; 4] = [0x48, 0x0f, 0x44, 0xd1];
const MOV_EAX_IMM32: u8 = 0xb8;
const SUB_RAX_RDX: [u8; 3] = [0x48, 0x29, 0xd0];
fn stack(code: &mut Vec<u8>, opcode: &[u8], slot: u8) {
    code.extend(opcode);
    code.extend([STACK_SIB, slot]);
}
pub(super) fn chunk(code: &mut Vec<u8>, element: ElementSize, sign: bool) {
    code.extend(SUB_RSP);
    code.push(STACK_BYTES);
    stack(code, &MOVDQU_STORE_RSP, 0);
    for offset in (0..CHUNK_BYTES).step_by(element.bytes()) {
        let load: &[u8] = match (element, sign) {
            (ElementSize::Byte, false) => &MOVZX_EAX_BYTE,
            (ElementSize::Byte, true) => &MOVSX_RAX_BYTE,
            (ElementSize::Halfword, false) => &MOVZX_EAX_WORD,
            (ElementSize::Halfword, true) => &MOVSX_RAX_WORD,
            (ElementSize::Word, false) => &MOV_EAX_DWORD,
            (ElementSize::Word, true) => &MOVSXD_RAX_DWORD,
            (ElementSize::Doubleword, _) => &MOV_RAX_QWORD,
            _ => unreachable!(),
        };
        stack(code, load, offset as u8);
        if sign {
            code.extend(MOV_RDX_RAX);
            code.extend(SAR_RDX);
            code.push(u64::BITS as u8 - 1);
            code.extend(XOR_RAX_RDX);
        }
        code.extend(BSR_RDX_RAX);
        // MOV preserves BSR's ZF. Zero maps to -1 before any arithmetic uses it.
        code.extend(MOV_RCX_SIGNED_IMM32);
        code.extend((-1_i32).to_le_bytes());
        code.extend(CMOVZ_RDX_RCX);
        code.push(MOV_EAX_IMM32);
        code.extend((element.bits() as u32 - 1 - u32::from(sign)).to_le_bytes());
        code.extend(SUB_RAX_RDX);
        let store: &[u8] = match element {
            ElementSize::Byte => &MOV_BYTE_AL,
            ElementSize::Halfword => &MOV_WORD_AX,
            ElementSize::Word => &MOV_DWORD_EAX,
            ElementSize::Doubleword => &MOV_QWORD_RAX,
            _ => unreachable!(),
        };
        stack(code, store, RESULT_SLOT + offset as u8);
    }
    stack(code, &MOVDQU_LOAD_RSP, RESULT_SLOT);
    code.extend(ADD_RSP);
    code.push(STACK_BYTES);
}
