//! Shared baseline checked-pointer result marking, without guest state effects.
//! The caller retains actual feature/mode authority and original operands.

use alloc::vec::Vec;
const TOP_BYTE_SHIFT: u8 = 56;
const POINTER_SIGN_BIT: u8 = 55;
const DETECTION_BIT: u8 = 54;
const LOW_RESULT_MASK: u64 = (1 << DETECTION_BIT) - 1;
const ONE_BIT_SHIFT: u8 = 1;
const ONE_BIT_MASK: u8 = 1;
const MOV_RCX_RAX: &[u8] = &[0x48, 0x89, 0xc1];
const MOV_RCX_RDX: &[u8] = &[0x48, 0x89, 0xd1];
const MOV_R9_RAX: &[u8] = &[0x49, 0x89, 0xc1];
const MOV_R10_RCX: &[u8] = &[0x49, 0x89, 0xca];
const MOVABS_R10: &[u8] = &[0x49, 0xba];
const XOR_R9_RDX: &[u8] = &[0x49, 0x31, 0xd1];
const XOR_RCX_R10: &[u8] = &[0x4c, 0x31, 0xd1];
const SHR_R9_IMM8: &[u8] = &[0x49, 0xc1, 0xe9];
const SHR_RCX_IMM8: &[u8] = &[0x48, 0xc1, 0xe9];
const SHR_R10_IMM8: &[u8] = &[0x49, 0xc1, 0xea];
const SHL_R11_IMM8: &[u8] = &[0x49, 0xc1, 0xe3];
const AND_ECX_IMM8: &[u8] = &[0x83, 0xe1];
const AND_RCX_R10: &[u8] = &[0x4c, 0x21, 0xd1];
const AND_R10_RDX: &[u8] = &[0x49, 0x21, 0xd2];
const NOT_R10: &[u8] = &[0x49, 0xf7, 0xd2];
const BTR_R10_IMM8: &[u8] = &[0x49, 0x0f, 0xba, 0xf2];
const BT_RDX_IMM8: &[u8] = &[0x48, 0x0f, 0xba, 0xe2];
const SETNC_R11B: &[u8] = &[0x41, 0x0f, 0x93, 0xc3];
const MOVZX_R11D_R11B: &[u8] = &[0x45, 0x0f, 0xb6, 0xdb];
const OR_R9_RCX: &[u8] = &[0x49, 0x09, 0xc9];
const OR_R9_R8: &[u8] = &[0x4d, 0x09, 0xc1];
const OR_RCX_R10: &[u8] = &[0x4c, 0x09, 0xd1];
const OR_RCX_R11: &[u8] = &[0x4c, 0x09, 0xd9];
const TEST_R9_R9: &[u8] = &[0x4d, 0x85, 0xc9];
const CMOVNZ_RAX_RCX: &[u8] = &[0x48, 0x0f, 0x45, 0xc1];

/// RAX=result, RDX=original base; R8 is a normalized multiplication predicate
/// when requested. RCX/R9/R10/R11 are scratch. No branch depends on guest data.
pub(super) fn emit(code: &mut Vec<u8>, multiplication: bool) {
    code.extend(MOV_R9_RAX);
    code.extend(XOR_R9_RDX);
    code.extend(SHR_R9_IMM8);
    code.push(TOP_BYTE_SHIFT);
    code.extend(MOV_RCX_RDX);
    code.extend(SHR_RCX_IMM8);
    code.push(DETECTION_BIT);
    code.extend(MOV_R10_RCX);
    code.extend(SHR_R10_IMM8);
    code.push(ONE_BIT_SHIFT);
    code.extend(XOR_RCX_R10);
    code.extend(AND_ECX_IMM8);
    code.push(ONE_BIT_MASK);
    code.extend(OR_R9_RCX);
    if multiplication {
        code.extend(OR_R9_R8);
    }

    // Preserve result[53:0] and base[63:55], then set bit54 to NOT base[55].
    code.extend(MOV_RCX_RAX);
    code.extend(MOVABS_R10);
    code.extend(LOW_RESULT_MASK.to_le_bytes());
    code.extend(AND_RCX_R10);
    code.extend(NOT_R10);
    code.extend(AND_R10_RDX);
    code.extend(BTR_R10_IMM8);
    code.push(DETECTION_BIT);
    code.extend(BT_RDX_IMM8);
    code.push(POINTER_SIGN_BIT);
    code.extend(SETNC_R11B);
    code.extend(MOVZX_R11D_R11B);
    code.extend(SHL_R11_IMM8);
    code.push(DETECTION_BIT);
    code.extend(OR_RCX_R10);
    code.extend(OR_RCX_R11);
    code.extend(TEST_R9_R9);
    code.extend(CMOVNZ_RAX_RCX);
}
