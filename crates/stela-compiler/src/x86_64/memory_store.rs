//! Direct stores to private RAM, keeping the completed prefix when a later page
//! faults. The protection granule is assumed to be at least 4 KiB.
use alloc::vec::Vec;
pub(crate) mod checked_pair;
pub(crate) mod checked_scalar;
use super::{AddressMode, Register, isa::SimdOpcode};

pub(super) const PROTECTION_GRANULE_BYTES: u32 = 4096;
const BYTE_BITS: u8 = 8;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const VECTOR_BYTES: u8 = 16;
/// Wide stores stage their sources in XMM0/XMM1. XMM2 is never a retained
/// input at this boundary; a full-width shuffle also avoids a merge dependency.
const HIGH_QWORD_SCRATCH_XMM: u8 = 2;
const DUPLICATE_HIGH_QWORD: u8 = 0xee;
const OPERAND_SIZE_PREFIX: u8 = 0x66;
const REP_PREFIX: u8 = 0xf3;
const SSE_ESCAPE: u8 = 0x0f;
const MOVD_STORE: u8 = 0x7e;
const MOVQ_STORE: u8 = 0xd6;
const MOVDQU_STORE: u8 = 0x7f;
const REX_PREFIX: u8 = 0x40;
const REX_WIDE: u8 = 0x08;
const REX_EXTENDED_SOURCE: u8 = 0x04;
const REGISTER_SHIFT: u8 = 3;
const RCX_REGISTER: u8 = 1;
const R8_REGISTER_LOW: u8 = 0;
const MODRM_DISP8: u8 = 0x40;
const MOV_BYTE: u8 = 0x88;
const MOV_WORD_OR_WIDER: u8 = 0x89;
const LEA_R10D_RAX_DISP8: &[u8] = &[0x44, 0x8d, 0x50];
const XOR_R10D_EAX: &[u8] = &[0x41, 0x31, 0xc2];
const TEST_R10D_IMM32: &[u8] = &[0x41, 0xf7, 0xc2];
const JZ_REL32: &[u8] = &[0x0f, 0x84];
const JMP_REL32: u8 = 0xe9;
const MOV_RCX_R8: &[u8] = &[0x4c, 0x89, 0xc1];
const MOVQ_RCX_XMM: &[u8] = &[0x66, 0x48, 0x0f, 0x7e];
const SHR_RCX_IMM8: &[u8] = &[0x48, 0xc1, 0xe9];
const MODRM_RCX: u8 = 0xc1;

#[derive(Clone, Copy)]
pub(super) enum Source {
    Rcx,
    R8,
    Xmm(u8),
}

pub(super) fn aligned_immediate(
    base: Register,
    displacement: i32,
    mode: AddressMode,
    bytes: u8,
) -> bool {
    base == Register::Sp && (mode == AddressMode::PostIndex || displacement % i32::from(bytes) == 0)
}

pub(super) fn aligned_register_offset(
    base: Register,
    index: Register,
    shift: u8,
    bytes: u8,
) -> bool {
    base == Register::Sp && (index == Register::Zero || u32::from(shift) >= bytes.trailing_zeros())
}

/// RAX is the address; displacement is zero or the second pair element's size.
/// RDX (pending writeback), R8 (second integer value), RDI and guest state survive.
/// RCX, R10 and XMM2 are scratch on the crossing path. The selected XMM0/XMM1
/// source remains whole, including where the block retains XMM0 for a later
/// instruction.
pub(super) fn emit(code: &mut Vec<u8>, bytes: u8, displacement: u8, source: Source, aligned: bool) {
    debug_assert!(bytes.is_power_of_two() && bytes <= VECTOR_BYTES);
    debug_assert!(displacement == 0 || displacement == bytes);
    if bytes == 1 || aligned {
        fast(code, bytes, displacement, source);
        return;
    }
    // An access crossing a 4 KiB boundary flips address bit 12. Comparing
    // against the pair's base may conservatively include the second element.
    code.extend(LEA_R10D_RAX_DISP8);
    code.push(displacement + bytes - 1);
    code.extend(XOR_R10D_EAX);
    code.extend(TEST_R10D_IMM32);
    code.extend(PROTECTION_GRANULE_BYTES.to_le_bytes());
    code.extend(JZ_REL32);
    let fast_jump = code.len();
    code.extend(0i32.to_le_bytes());
    prefix_store(code, bytes, displacement, source);
    code.push(JMP_REL32);
    let done_jump = code.len();
    code.extend(0i32.to_le_bytes());
    patch_jump(code, fast_jump);
    fast(code, bytes, displacement, source);
    patch_jump(code, done_jump);
}

/// The page-crossing store of a halfword, word or doubleword staged in RCX to
/// [RAX] (`emit` without alignment), and the end of each of its
/// instructions: the region emitter reuses these bytes exactly, and its cost
/// gates count them on both sides.
pub(super) fn crossing_store(bytes: u8) -> Option<(Vec<u8>, Vec<usize>)> {
    if !matches!(bytes, HALFWORD_BYTES | DWORD_BYTES | QWORD_BYTES) {
        return None;
    }
    let mut code = Vec::new();
    emit(&mut code, bytes, 0, Source::Rcx, false);
    // LEA, XOR, TEST and JZ; every byte's shift but the first and its byte
    // store; JMP; then the fast path's one store.
    let mut ends = Vec::new();
    let mut end = 0;
    for length in [
        LEA_R10D_RAX_DISP8.len() + 1,
        XOR_R10D_EAX.len(),
        TEST_R10D_IMM32.len() + size_of::<u32>(),
        JZ_REL32.len() + size_of::<i32>(),
    ] {
        end += length;
        ends.push(end);
    }
    for byte in 0..bytes {
        if byte != 0 {
            end += SHR_RCX_IMM8.len() + 1;
            ends.push(end);
        }
        // MOV [RAX], CL, or MOV [RAX+disp8], CL.
        end += if byte == 0 { 2 } else { 3 };
        ends.push(end);
    }
    end += 1 + size_of::<i32>();
    ends.push(end);
    ends.push(code.len());
    Some((code, ends))
}

fn fast(code: &mut Vec<u8>, bytes: u8, displacement: u8, source: Source) {
    let register = match source {
        Source::Xmm(xmm) => {
            let (prefix, opcode) = match bytes {
                DWORD_BYTES => (OPERAND_SIZE_PREFIX, MOVD_STORE),
                QWORD_BYTES => (OPERAND_SIZE_PREFIX, MOVQ_STORE),
                VECTOR_BYTES => (REP_PREFIX, MOVDQU_STORE),
                _ => unreachable!("narrow vectors are staged through RCX"),
            };
            code.extend([prefix, SSE_ESCAPE, opcode]);
            xmm
        }
        Source::Rcx | Source::R8 => {
            debug_assert!(bytes <= QWORD_BYTES);
            if bytes == HALFWORD_BYTES {
                code.push(OPERAND_SIZE_PREFIX);
            }
            let rex = if bytes == QWORD_BYTES { REX_WIDE } else { 0 }
                | if matches!(source, Source::R8) {
                    REX_EXTENDED_SOURCE
                } else {
                    0
                };
            if rex != 0 {
                code.push(REX_PREFIX | rex);
            }
            code.push(if bytes == 1 {
                MOV_BYTE
            } else {
                MOV_WORD_OR_WIDER
            });
            if matches!(source, Source::R8) {
                R8_REGISTER_LOW
            } else {
                RCX_REGISTER
            }
        }
    };
    code.push((register << REGISTER_SHIFT) | if displacement == 0 { 0 } else { MODRM_DISP8 });
    if displacement != 0 {
        code.push(displacement);
    }
}

fn prefix_store(code: &mut Vec<u8>, bytes: u8, displacement: u8, source: Source) {
    match source {
        Source::Rcx => {}
        Source::R8 => code.extend(MOV_RCX_R8),
        Source::Xmm(xmm) => extract_qword(code, xmm),
    }
    for byte in 0..bytes {
        if byte == QWORD_BYTES {
            let Source::Xmm(xmm) = source else {
                unreachable!("only vectors exceed a qword")
            };
            assert_ne!(
                xmm, HIGH_QWORD_SCRATCH_XMM,
                "store input aliases its scratch"
            );
            SimdOpcode::ShuffleDword.register(
                code,
                HIGH_QWORD_SCRATCH_XMM,
                xmm,
                crate::TargetCpu::Baseline,
            );
            code.push(DUPLICATE_HIGH_QWORD);
            extract_qword(code, HIGH_QWORD_SCRATCH_XMM);
        } else if byte != 0 {
            code.extend(SHR_RCX_IMM8);
            code.push(BYTE_BITS);
        }
        fast(code, 1, displacement + byte, Source::Rcx);
    }
}

fn extract_qword(code: &mut Vec<u8>, xmm: u8) {
    code.extend(MOVQ_RCX_XMM);
    code.push(MODRM_RCX | (xmm << REGISTER_SHIFT));
}

fn patch_jump(code: &mut [u8], displacement: usize) {
    let relative = i32::try_from(code.len() - displacement - size_of::<i32>())
        .expect("bounded ordinary-store branch");
    code[displacement..displacement + size_of::<i32>()].copy_from_slice(&relative.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The crossing recipe's ends are its instruction boundaries.
    #[test]
    fn crossing_store_ends_are_instruction_boundaries() {
        let (code, ends) = crossing_store(HALFWORD_BYTES).unwrap();
        assert_eq!(
            code,
            [
                0x44, 0x8d, 0x50, 0x01, // lea r10d, [rax+1]
                0x41, 0x31, 0xc2, // xor r10d, eax
                0x41, 0xf7, 0xc2, 0x00, 0x10, 0x00, 0x00, // test r10d, 0x1000
                0x0f, 0x84, 0x0e, 0x00, 0x00, 0x00, // jz fast
                0x88, 0x08, // mov [rax], cl
                0x48, 0xc1, 0xe9, 0x08, // shr rcx, 8
                0x88, 0x48, 0x01, // mov [rax+1], cl
                0xe9, 0x03, 0x00, 0x00, 0x00, // jmp done
                0x66, 0x89, 0x08, // fast: mov [rax], cx
            ]
        );
        assert_eq!(ends, [4, 7, 14, 20, 22, 26, 29, 34, 37]);
        for bytes in [DWORD_BYTES, QWORD_BYTES] {
            let (code, ends) = crossing_store(bytes).unwrap();
            assert_eq!(ends.len(), 4 + 2 * usize::from(bytes) - 1 + 2);
            assert!(ends.windows(2).all(|pair| pair[0] < pair[1]));
            assert_eq!(*ends.last().unwrap(), code.len());
        }
        assert!(crossing_store(1).is_none());
        assert!(crossing_store(VECTOR_BYTES).is_none());
    }
}
