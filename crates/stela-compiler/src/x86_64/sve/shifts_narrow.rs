//! SVE2 widening and narrowing shifts with SSE2 or SSE4.1.
use crate::{
    TargetCpu,
    aarch64::{
        scalable::{ElementSize, VectorLength},
        sve::shifts_narrow::{Kind, Operand, Part},
    },
    x86_64::{
        isa::SimdOpcode as Host,
        scalable::{load_z_chunk, store_z_chunk},
    },
};
use alloc::vec::Vec;

const SOURCE_XMM: u8 = 0;
const TEMP_XMM: u8 = 1;
const MASK_XMM: u8 = 2;
const RESULT_XMM: u8 = 3;
const LANE_XMM: u8 = 4;
const CHUNK_BYTES: usize = 16;
const QWORD_BYTES: usize = 8;
const BYTE_BITS: u8 = 8;
const WORD_BITS: u8 = 16;
const DWORD_BITS: u8 = 32;
const QWORD_BITS: u8 = 64;
const SSE_PREFIX: &[u8] = &[0x66, 0x0f];
const REGISTER_MODE: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const MOVDQA: u8 = 0x6f;
const PAND: u8 = 0xdb;
const PANDN: u8 = 0xdf;
const POR: u8 = 0xeb;
const PXOR: u8 = 0xef;
const PSHUFD: u8 = 0x70;
const PUNPCKLQDQ: u8 = 0x6c;
const PUNPCKLBW: u8 = 0x60;
const PUNPCKLWD: u8 = 0x61;
const PACKSSWB: u8 = 0x63;
const PACKSSDW: u8 = 0x6b;
const PACKUSWB: u8 = 0x67;
const PCMPGTD: u8 = 0x66;
const PSUBUSW: u8 = 0xd9;
const PSUBW: u8 = 0xf9;
const PSUBD: u8 = 0xfa;
const PADDW: u8 = 0xfd;
const PADDD: u8 = 0xfe;
const PADDQ: u8 = 0xd4;
const SHIFT_WORD: u8 = 0x71;
const SHIFT_DWORD: u8 = 0x72;
const SHIFT_QWORD: u8 = 0x73;
const RIGHT_LOGICAL: u8 = 2;
const RIGHT_BYTES: u8 = 3;
const RIGHT_ARITHMETIC: u8 = 4;
const LEFT_LOGICAL: u8 = 6;
const LEFT_BYTES: u8 = 7;
const SIGNED_BOTTOM_SHUFFLE: u8 = 0xa0;
const SIGNED_TOP_SHUFFLE: u8 = 0xf5;
const EVEN_DWORDS_SHUFFLE: u8 = 0x88;
const ODD_DWORDS_SHUFFLE: u8 = 0xdd;
const LOW_BYTES: u64 = 0x00ff00ff00ff00ff;
const LOW_WORDS: u64 = 0x0000ffff0000ffff;
const LOW_DWORDS: u64 = 0x00000000ffffffff;
const HIGH_DWORDS: u64 = 0xffffffff00000000;
const ONE_WORDS: u64 = 0x0001000100010001;
const ONE_DWORDS: u64 = 0x0000000100000001;
const SIGN_DWORDS: u64 = 0x8000000080000000;
const UNSIGNED_WORD_MAX_DWORDS: u64 = 0x0000ffff0000ffff;
const BIASED_UNSIGNED_WORD_MAX: u64 = 0x8000ffff8000ffff;
const PACK_WORD_BIAS: u64 = 0x0000800000008000;
const PACKED_WORD_SIGN: u64 = 0x8000800080008000;
const MOV_RAX_IMM64: &[u8] = &[0x48, 0xb8];
const MOV_RDX_IMM64: &[u8] = &[0x48, 0xba];
const MOVQ_XMM_RAX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e];
const MOVQ_RAX_XMM: &[u8] = &[0x66, 0x48, 0x0f, 0x7e];
const MOVQ_XMM_XMM: &[u8] = &[0xf3, 0x0f, 0x7e];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const SHR_RAX: &[u8] = &[0x48, 0xc1, 0xe8];
const SAR_RAX: &[u8] = &[0x48, 0xc1, 0xf8];
const SHR_RDX: &[u8] = &[0x48, 0xc1, 0xea];
const AND_EDX_ONE: &[u8] = &[0x83, 0xe2, 0x01];
const ADD_RAX_RDX: &[u8] = &[0x48, 0x01, 0xd0];
const CMP_RAX_RDX: &[u8] = &[0x48, 0x39, 0xd0];
const TEST_RAX_RAX: &[u8] = &[0x48, 0x85, 0xc0];
const XOR_EDX_EDX: &[u8] = &[0x31, 0xd2];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const CMOVL_RAX_RDX: &[u8] = &[0x48, 0x0f, 0x4c, 0xc2];
const CMOVG_RAX_RDX: &[u8] = &[0x48, 0x0f, 0x4f, 0xc2];
const CMOVA_RAX_RDX: &[u8] = &[0x48, 0x0f, 0x47, 0xc2];
const CMOVS_RAX_RDX: &[u8] = &[0x48, 0x0f, 0x48, 0xc2];
const MOV_EAX_EAX: &[u8] = &[0x89, 0xc0];

pub fn emit(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    let small_bits = operand.element_size.bits() as u8;
    for chunk in 0..length.chunks() {
        load_z_chunk(code, operand.source, chunk, SOURCE_XMM, length, target);
        if operand.kind.is_widening() {
            widen(code, operand, small_bits, target);
        } else {
            narrow_chunk(
                code,
                operand.kind,
                operand.element_size,
                operand.shift,
                target,
            );
            merge_top(code, operand, chunk, SOURCE_XMM, length, target);
        }
        store_z_chunk(code, operand.destination, chunk, SOURCE_XMM, length, target);
    }
}

/// Narrow preloaded XMM0 into even-positioned half-width lanes; odd lanes are zero.
/// Clobbers XMM1..=4, RAX and RDX; preserves XMM5..=7, RDI/R15 and guest status.
/// Storage, streaming checks and group-specific compaction belong to the caller.
/// `element` is Byte/Halfword/Word. Right shifts accept 1..=source bits;
/// extract kinds require zero. Widening kinds are outside this kernel's contract.
pub(crate) fn narrow_chunk(
    code: &mut Vec<u8>,
    kind: Kind,
    element: ElementSize,
    amount: u8,
    target: TargetCpu,
) {
    narrow_projected(
        code,
        kind,
        element,
        amount,
        NarrowProjection::Interleaved,
        target,
    );
}

/// Narrow XMM0 into consecutive low-eight-byte results, clearing the upper eight.
/// Operand and clobber contracts match `narrow_chunk`; group staging stays outside.
pub(crate) fn narrow_packed_chunk(
    code: &mut Vec<u8>,
    kind: Kind,
    element: ElementSize,
    amount: u8,
    target: TargetCpu,
) {
    narrow_projected(
        code,
        kind,
        element,
        amount,
        NarrowProjection::Packed,
        target,
    );
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NarrowProjection {
    Interleaved,
    Packed,
}

fn narrow_projected(
    code: &mut Vec<u8>,
    kind: Kind,
    element: ElementSize,
    amount: u8,
    projection: NarrowProjection,
    target: TargetCpu,
) {
    let small = element.bits() as u8;
    debug_assert!(matches!(small, BYTE_BITS | WORD_BITS | DWORD_BITS));
    debug_assert!(!kind.is_widening());
    debug_assert!(if kind.is_extract() {
        amount == 0
    } else {
        (1..=2 * small).contains(&amount)
    });
    let operand = Operand {
        kind,
        element_size: element,
        part: Part::Bottom,
        source: 0,
        destination: 0,
        shift: amount,
    };
    if small == DWORD_BITS && !matches!(kind, Kind::ShiftRight | Kind::RoundRight) {
        scalar_narrow_qwords(code, operand);
        if projection == NarrowProjection::Packed {
            compact_even_lanes(code, small);
        }
    } else {
        narrow(code, operand, small, projection, target);
    }
}

fn clear_packed_upper(code: &mut Vec<u8>) {
    code.extend(MOVQ_XMM_XMM);
    code.push(REGISTER_MODE | (SOURCE_XMM << MODRM_REGISTER_SHIFT) | SOURCE_XMM);
}

fn compact_even_lanes(code: &mut Vec<u8>, small: u8) {
    match small {
        BYTE_BITS => binary(code, PACKUSWB, SOURCE_XMM, SOURCE_XMM),
        WORD_BITS => {
            // Sign-extend the retained bits before packing: every lane is representable.
            shift(code, DWORD_BITS, LEFT_LOGICAL, SOURCE_XMM, WORD_BITS);
            shift(code, DWORD_BITS, RIGHT_ARITHMETIC, SOURCE_XMM, WORD_BITS);
            binary(code, PACKSSDW, SOURCE_XMM, SOURCE_XMM);
        }
        DWORD_BITS => {
            binary(code, PSHUFD, SOURCE_XMM, SOURCE_XMM);
            code.push(EVEN_DWORDS_SHUFFLE);
        }
        _ => unreachable!(),
    }
    clear_packed_upper(code);
}

fn binary(code: &mut Vec<u8>, opcode: u8, destination: u8, source: u8) {
    code.extend(SSE_PREFIX);
    code.extend([
        opcode,
        REGISTER_MODE | (destination << MODRM_REGISTER_SHIFT) | source,
    ]);
}

fn shift(code: &mut Vec<u8>, bits: u8, group: u8, register: u8, amount: u8) {
    if amount == 0 {
        return;
    }
    let opcode = match bits {
        WORD_BITS => SHIFT_WORD,
        DWORD_BITS => SHIFT_DWORD,
        QWORD_BITS => SHIFT_QWORD,
        _ => unreachable!(),
    };
    code.extend(SSE_PREFIX);
    code.extend([
        opcode,
        REGISTER_MODE | (group << MODRM_REGISTER_SHIFT) | register,
        amount,
    ]);
}

fn byte_shift(code: &mut Vec<u8>, group: u8, register: u8, amount: usize) {
    if amount == 0 {
        return;
    }
    code.extend(SSE_PREFIX);
    code.extend([
        SHIFT_QWORD,
        REGISTER_MODE | (group << MODRM_REGISTER_SHIFT) | register,
        amount as u8,
    ]);
}

fn constant(code: &mut Vec<u8>, register: u8, value: u64) {
    code.extend(MOV_RAX_IMM64);
    code.extend(value.to_le_bytes());
    code.extend(MOVQ_XMM_RAX);
    code.push(REGISTER_MODE | (register << MODRM_REGISTER_SHIFT));
    binary(code, PUNPCKLQDQ, register, register);
}

fn low_mask(bits: u8) -> u64 {
    match bits {
        BYTE_BITS => LOW_BYTES,
        WORD_BITS => LOW_WORDS,
        DWORD_BITS => LOW_DWORDS,
        _ => unreachable!(),
    }
}

fn widen(code: &mut Vec<u8>, operand: Operand, small: u8, target: TargetCpu) {
    let wide = 2 * small;
    let top = operand.part == Part::Top;
    if operand.kind == Kind::WidenSigned && small == DWORD_BITS && target.supports(TargetCpu::Sse41)
    {
        Host::ShuffleDword.register(code, SOURCE_XMM, SOURCE_XMM, target);
        code.push(if top {
            ODD_DWORDS_SHUFFLE
        } else {
            EVEN_DWORDS_SHUFFLE
        });
        Host::SignExtendDwordToQword.register(code, SOURCE_XMM, SOURCE_XMM, target);
        shift(code, wide, LEFT_LOGICAL, SOURCE_XMM, operand.shift);
        return;
    }
    if operand.kind == Kind::WidenUnsigned {
        if top {
            shift(code, wide, RIGHT_LOGICAL, SOURCE_XMM, small);
        } else {
            constant(code, MASK_XMM, low_mask(small));
            binary(code, PAND, SOURCE_XMM, MASK_XMM);
        }
    } else if small != DWORD_BITS {
        if !top {
            shift(code, wide, LEFT_LOGICAL, SOURCE_XMM, small);
            // The first shift already creates the low zero bits of the widened result.
            shift(
                code,
                wide,
                RIGHT_ARITHMETIC,
                SOURCE_XMM,
                small - operand.shift,
            );
            return;
        }
        shift(code, wide, RIGHT_ARITHMETIC, SOURCE_XMM, small);
    } else {
        binary(code, MOVDQA, TEMP_XMM, SOURCE_XMM);
        shift(code, DWORD_BITS, RIGHT_ARITHMETIC, TEMP_XMM, DWORD_BITS - 1);
        binary(code, PSHUFD, TEMP_XMM, TEMP_XMM);
        code.push(if top {
            SIGNED_TOP_SHUFFLE
        } else {
            SIGNED_BOTTOM_SHUFFLE
        });
        constant(code, MASK_XMM, HIGH_DWORDS);
        binary(code, PAND, TEMP_XMM, MASK_XMM);
        if top {
            shift(code, QWORD_BITS, RIGHT_LOGICAL, SOURCE_XMM, DWORD_BITS);
        } else {
            constant(code, MASK_XMM, LOW_DWORDS);
            binary(code, PAND, SOURCE_XMM, MASK_XMM);
        }
        binary(code, POR, SOURCE_XMM, TEMP_XMM);
    }
    shift(code, wide, LEFT_LOGICAL, SOURCE_XMM, operand.shift);
}

fn signed_input(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::SaturatingRightSigned
            | Kind::SaturatingRightSignedToUnsigned
            | Kind::SaturatingRoundRightSigned
            | Kind::SaturatingRoundRightSignedToUnsigned
            | Kind::SaturatingExtractSigned
            | Kind::SaturatingExtractSignedToUnsigned
    )
}

fn rounded(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::RoundRight
            | Kind::SaturatingRoundRightSigned
            | Kind::SaturatingRoundRightUnsigned
            | Kind::SaturatingRoundRightSignedToUnsigned
    )
}

fn signed_output(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::SaturatingRightSigned
            | Kind::SaturatingRoundRightSigned
            | Kind::SaturatingExtractSigned
    )
}

fn shift_narrow_input(code: &mut Vec<u8>, operand: Operand, wide: u8) {
    if operand.kind.is_extract() {
        return;
    }
    if rounded(operand.kind) {
        binary(code, MOVDQA, TEMP_XMM, SOURCE_XMM);
        shift(code, wide, RIGHT_LOGICAL, TEMP_XMM, operand.shift - 1);
        constant(
            code,
            MASK_XMM,
            match wide {
                WORD_BITS => ONE_WORDS,
                DWORD_BITS => ONE_DWORDS,
                QWORD_BITS => 1,
                _ => unreachable!(),
            },
        );
        binary(code, PAND, TEMP_XMM, MASK_XMM);
    }
    shift(
        code,
        wide,
        if signed_input(operand.kind) {
            RIGHT_ARITHMETIC
        } else {
            RIGHT_LOGICAL
        },
        SOURCE_XMM,
        operand.shift,
    );
    if rounded(operand.kind) {
        binary(
            code,
            match wide {
                WORD_BITS => PADDW,
                DWORD_BITS => PADDD,
                QWORD_BITS => PADDQ,
                _ => unreachable!(),
            },
            SOURCE_XMM,
            TEMP_XMM,
        );
    }
}

fn narrow(
    code: &mut Vec<u8>,
    operand: Operand,
    small: u8,
    projection: NarrowProjection,
    target: TargetCpu,
) {
    let wide = 2 * small;
    shift_narrow_input(code, operand, wide);
    if matches!(operand.kind, Kind::ShiftRight | Kind::RoundRight) {
        constant(code, MASK_XMM, low_mask(small));
        binary(code, PAND, SOURCE_XMM, MASK_XMM);
        if projection == NarrowProjection::Packed {
            compact_even_lanes(code, small);
        }
        return;
    }
    if signed_output(operand.kind) {
        binary(
            code,
            if small == BYTE_BITS {
                PACKSSWB
            } else {
                PACKSSDW
            },
            SOURCE_XMM,
            SOURCE_XMM,
        );
    } else if small == BYTE_BITS {
        if !signed_input(operand.kind) {
            constant(code, TEMP_XMM, LOW_BYTES);
            if target.supports(TargetCpu::Sse41) {
                Host::MinUnsignedWord.register(code, SOURCE_XMM, TEMP_XMM, target);
            } else {
                binary(code, MOVDQA, MASK_XMM, SOURCE_XMM);
                binary(code, PSUBUSW, MASK_XMM, TEMP_XMM);
                binary(code, PSUBW, SOURCE_XMM, MASK_XMM);
            }
        }
        binary(code, PACKUSWB, SOURCE_XMM, SOURCE_XMM);
    } else if target.supports(TargetCpu::Sse41) {
        if !signed_input(operand.kind) {
            constant(code, TEMP_XMM, UNSIGNED_WORD_MAX_DWORDS);
            Host::MinUnsignedDword.register(code, SOURCE_XMM, TEMP_XMM, target);
        }
        Host::PackUnsignedDwordToWord.register(code, SOURCE_XMM, SOURCE_XMM, target);
    } else {
        // PACKSSDW after a 32768 bias represents the full unsigned word range.
        if signed_input(operand.kind) {
            binary(code, PXOR, TEMP_XMM, TEMP_XMM);
            binary(code, PCMPGTD, TEMP_XMM, SOURCE_XMM);
            binary(code, PANDN, TEMP_XMM, SOURCE_XMM);
            binary(code, MOVDQA, SOURCE_XMM, TEMP_XMM);
        }
        unsigned_min_words(code);
        constant(code, TEMP_XMM, PACK_WORD_BIAS);
        binary(code, PSUBD, SOURCE_XMM, TEMP_XMM);
        binary(code, PACKSSDW, SOURCE_XMM, SOURCE_XMM);
        constant(code, TEMP_XMM, PACKED_WORD_SIGN);
        binary(code, PXOR, SOURCE_XMM, TEMP_XMM);
    }
    if projection == NarrowProjection::Packed {
        clear_packed_upper(code);
        return;
    }
    binary(code, PXOR, TEMP_XMM, TEMP_XMM);
    binary(
        code,
        if small == BYTE_BITS {
            PUNPCKLBW
        } else {
            PUNPCKLWD
        },
        SOURCE_XMM,
        TEMP_XMM,
    );
}

fn unsigned_min_words(code: &mut Vec<u8>) {
    binary(code, MOVDQA, TEMP_XMM, SOURCE_XMM);
    constant(code, MASK_XMM, SIGN_DWORDS);
    binary(code, PXOR, TEMP_XMM, MASK_XMM);
    constant(code, MASK_XMM, BIASED_UNSIGNED_WORD_MAX);
    binary(code, PCMPGTD, TEMP_XMM, MASK_XMM);
    constant(code, MASK_XMM, UNSIGNED_WORD_MAX_DWORDS);
    binary(code, PAND, MASK_XMM, TEMP_XMM);
    binary(code, PANDN, TEMP_XMM, SOURCE_XMM);
    binary(code, POR, TEMP_XMM, MASK_XMM);
    binary(code, MOVDQA, SOURCE_XMM, TEMP_XMM);
}

fn merge_top(
    code: &mut Vec<u8>,
    operand: Operand,
    chunk: usize,
    result: u8,
    length: VectorLength,
    target: TargetCpu,
) {
    if operand.part != Part::Top {
        return;
    }
    let small = operand.element_size.bits() as u8;
    shift(code, 2 * small, LEFT_LOGICAL, result, small);
    load_z_chunk(code, operand.destination, chunk, TEMP_XMM, length, target);
    constant(code, MASK_XMM, low_mask(small));
    binary(code, PAND, TEMP_XMM, MASK_XMM);
    binary(code, POR, result, TEMP_XMM);
}

fn scalar_narrow_qwords(code: &mut Vec<u8>, operand: Operand) {
    binary(code, PXOR, RESULT_XMM, RESULT_XMM);
    for offset in (0..CHUNK_BYTES).step_by(QWORD_BYTES) {
        binary(code, MOVDQA, MASK_XMM, SOURCE_XMM);
        byte_shift(code, RIGHT_BYTES, MASK_XMM, offset);
        code.extend(MOVQ_RAX_XMM);
        code.push(REGISTER_MODE | (MASK_XMM << MODRM_REGISTER_SHIFT));
        if !operand.kind.is_extract() {
            if operand.shift == QWORD_BITS {
                // x86 scalar shift counts mask to six bits: handle the full width explicitly.
                if rounded(operand.kind) && signed_input(operand.kind) {
                    code.extend(XOR_EAX_EAX);
                } else if rounded(operand.kind) || signed_input(operand.kind) {
                    code.extend(if signed_input(operand.kind) {
                        SAR_RAX
                    } else {
                        SHR_RAX
                    });
                    code.push(QWORD_BITS - 1);
                } else {
                    code.extend(XOR_EAX_EAX);
                }
            } else {
                if rounded(operand.kind) {
                    code.extend(MOV_RDX_RAX);
                }
                code.extend(if signed_input(operand.kind) {
                    SAR_RAX
                } else {
                    SHR_RAX
                });
                code.push(operand.shift);
                if rounded(operand.kind) {
                    if operand.shift != 1 {
                        code.extend(SHR_RDX);
                        code.push(operand.shift - 1);
                    }
                    code.extend(AND_EDX_ONE);
                    code.extend(ADD_RAX_RDX);
                }
            }
        }
        if signed_output(operand.kind) {
            scalar_bound(code, i64::from(i32::MIN) as u64, CMOVL_RAX_RDX);
            scalar_bound(code, i32::MAX as u64, CMOVG_RAX_RDX);
        } else {
            if signed_input(operand.kind) {
                code.extend(XOR_EDX_EDX);
                code.extend(TEST_RAX_RAX);
                code.extend(CMOVS_RAX_RDX);
            }
            scalar_bound(code, u64::from(u32::MAX), CMOVA_RAX_RDX);
        }
        code.extend(MOV_EAX_EAX);
        code.extend(MOVQ_XMM_RAX);
        code.push(REGISTER_MODE | (LANE_XMM << MODRM_REGISTER_SHIFT));
        byte_shift(code, LEFT_BYTES, LANE_XMM, offset);
        binary(code, POR, RESULT_XMM, LANE_XMM);
    }
    binary(code, MOVDQA, SOURCE_XMM, RESULT_XMM);
}

fn scalar_bound(code: &mut Vec<u8>, bound: u64, move_condition: &[u8]) {
    code.extend(MOV_RDX_IMM64);
    code.extend(bound.to_le_bytes());
    code.extend(CMP_RAX_RDX);
    code.extend(move_condition);
}
