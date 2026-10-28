//! SVE2 widening and narrowing shifts with SSE2 or SSE4.1.
use crate::x86_64::asm::Gpr::{Rax, Rdx};
use crate::x86_64::asm::{Alu, Code, Cond, Rm, ShiftOp, Size};
use crate::{
    TargetCpu,
    aarch64::{
        scalable::{ElementSize, VectorLength},
        sve::shifts_narrow::{Kind, Operand, Part},
    },
    x86_64::{
        isa::{ShiftOpcode as Shift, SimdOpcode as Host},
        scalable::{load_z_chunk, store_z_chunk},
    },
};

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

pub fn emit(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
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
    code: &mut Code,
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
    code: &mut Code,
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
    code: &mut Code,
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

fn clear_packed_upper(code: &mut Code) {
    code.asm().movq_xmm(SOURCE_XMM, Rm::Xmm(SOURCE_XMM));
}

fn compact_even_lanes(code: &mut Code, small: u8) {
    match small {
        BYTE_BITS => binary(code, Host::PackUnsignedWordToByte, SOURCE_XMM, SOURCE_XMM),
        WORD_BITS => {
            // Sign-extend the retained bits before packing: every lane is representable.
            shift(code, DWORD_BITS, Direction::Left, SOURCE_XMM, WORD_BITS);
            shift(
                code,
                DWORD_BITS,
                Direction::Arithmetic,
                SOURCE_XMM,
                WORD_BITS,
            );
            binary(code, Host::PackSignedDwordToWord, SOURCE_XMM, SOURCE_XMM);
        }
        DWORD_BITS => shuffle(code, SOURCE_XMM, SOURCE_XMM, EVEN_DWORDS_SHUFFLE),
        _ => unreachable!(),
    }
    clear_packed_upper(code);
}

fn binary(code: &mut Code, opcode: Host, destination: u8, source: u8) {
    code.asm()
        .simd(opcode, destination, Rm::Xmm(source), TargetCpu::Baseline);
}

fn shuffle(code: &mut Code, destination: u8, source: u8, control: u8) {
    code.asm().simd_imm(
        Host::ShuffleDword,
        destination,
        Rm::Xmm(source),
        control,
        TargetCpu::Baseline,
    );
}

#[derive(Clone, Copy)]
enum Direction {
    Left,
    Right,
    Arithmetic,
}

fn shift(code: &mut Code, bits: u8, direction: Direction, register: u8, amount: u8) {
    if amount == 0 {
        return;
    }
    let opcode = match (bits, direction) {
        (WORD_BITS, Direction::Left) => Shift::LeftWord,
        (WORD_BITS, Direction::Right) => Shift::RightWord,
        (WORD_BITS, Direction::Arithmetic) => Shift::ArithmeticWord,
        (DWORD_BITS, Direction::Left) => Shift::LeftDword,
        (DWORD_BITS, Direction::Right) => Shift::RightDword,
        (DWORD_BITS, Direction::Arithmetic) => Shift::ArithmeticDword,
        (QWORD_BITS, Direction::Left) => Shift::LeftQword,
        (QWORD_BITS, Direction::Right) => Shift::RightQword,
        _ => unreachable!(),
    };
    opcode.emit(code, register, amount);
}

fn byte_shift(code: &mut Code, opcode: Shift, register: u8, amount: usize) {
    if amount != 0 {
        opcode.emit(code, register, amount as u8);
    }
}

fn constant(code: &mut Code, register: u8, value: u64) {
    let mut asm = code.asm();
    asm.mov_imm64(Rax, value);
    asm.movq_to_xmm(register, Rax);
    binary(code, Host::UnpackLowQword, register, register);
}

fn low_mask(bits: u8) -> u64 {
    match bits {
        BYTE_BITS => LOW_BYTES,
        WORD_BITS => LOW_WORDS,
        DWORD_BITS => LOW_DWORDS,
        _ => unreachable!(),
    }
}

fn widen(code: &mut Code, operand: Operand, small: u8, target: TargetCpu) {
    let wide = 2 * small;
    let top = operand.part == Part::Top;
    if operand.kind == Kind::WidenSigned && small == DWORD_BITS && target.supports(TargetCpu::Sse41)
    {
        code.asm().simd_imm(
            Host::ShuffleDword,
            SOURCE_XMM,
            Rm::Xmm(SOURCE_XMM),
            if top {
                ODD_DWORDS_SHUFFLE
            } else {
                EVEN_DWORDS_SHUFFLE
            },
            target,
        );
        Host::SignExtendDwordToQword.register(code, SOURCE_XMM, SOURCE_XMM, target);
        shift(code, wide, Direction::Left, SOURCE_XMM, operand.shift);
        return;
    }
    if operand.kind == Kind::WidenUnsigned {
        if top {
            shift(code, wide, Direction::Right, SOURCE_XMM, small);
        } else {
            constant(code, MASK_XMM, low_mask(small));
            binary(code, Host::And, SOURCE_XMM, MASK_XMM);
        }
    } else if small != DWORD_BITS {
        if !top {
            shift(code, wide, Direction::Left, SOURCE_XMM, small);
            // The first shift already creates the low zero bits of the widened result.
            shift(
                code,
                wide,
                Direction::Arithmetic,
                SOURCE_XMM,
                small - operand.shift,
            );
            return;
        }
        shift(code, wide, Direction::Arithmetic, SOURCE_XMM, small);
    } else {
        binary(code, Host::MoveAligned, TEMP_XMM, SOURCE_XMM);
        shift(
            code,
            DWORD_BITS,
            Direction::Arithmetic,
            TEMP_XMM,
            DWORD_BITS - 1,
        );
        shuffle(
            code,
            TEMP_XMM,
            TEMP_XMM,
            if top {
                SIGNED_TOP_SHUFFLE
            } else {
                SIGNED_BOTTOM_SHUFFLE
            },
        );
        constant(code, MASK_XMM, HIGH_DWORDS);
        binary(code, Host::And, TEMP_XMM, MASK_XMM);
        if top {
            shift(code, QWORD_BITS, Direction::Right, SOURCE_XMM, DWORD_BITS);
        } else {
            constant(code, MASK_XMM, LOW_DWORDS);
            binary(code, Host::And, SOURCE_XMM, MASK_XMM);
        }
        binary(code, Host::Or, SOURCE_XMM, TEMP_XMM);
    }
    shift(code, wide, Direction::Left, SOURCE_XMM, operand.shift);
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

fn shift_narrow_input(code: &mut Code, operand: Operand, wide: u8) {
    if operand.kind.is_extract() {
        return;
    }
    if rounded(operand.kind) {
        binary(code, Host::MoveAligned, TEMP_XMM, SOURCE_XMM);
        shift(code, wide, Direction::Right, TEMP_XMM, operand.shift - 1);
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
        binary(code, Host::And, TEMP_XMM, MASK_XMM);
    }
    shift(
        code,
        wide,
        if signed_input(operand.kind) {
            Direction::Arithmetic
        } else {
            Direction::Right
        },
        SOURCE_XMM,
        operand.shift,
    );
    if rounded(operand.kind) {
        binary(
            code,
            match wide {
                WORD_BITS => Host::AddWord,
                DWORD_BITS => Host::AddDword,
                QWORD_BITS => Host::AddQword,
                _ => unreachable!(),
            },
            SOURCE_XMM,
            TEMP_XMM,
        );
    }
}

fn narrow(
    code: &mut Code,
    operand: Operand,
    small: u8,
    projection: NarrowProjection,
    target: TargetCpu,
) {
    let wide = 2 * small;
    shift_narrow_input(code, operand, wide);
    if matches!(operand.kind, Kind::ShiftRight | Kind::RoundRight) {
        constant(code, MASK_XMM, low_mask(small));
        binary(code, Host::And, SOURCE_XMM, MASK_XMM);
        if projection == NarrowProjection::Packed {
            compact_even_lanes(code, small);
        }
        return;
    }
    if signed_output(operand.kind) {
        binary(
            code,
            if small == BYTE_BITS {
                Host::PackSignedWordToByte
            } else {
                Host::PackSignedDwordToWord
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
                binary(code, Host::MoveAligned, MASK_XMM, SOURCE_XMM);
                binary(code, Host::SubUnsignedSaturatingWord, MASK_XMM, TEMP_XMM);
                binary(code, Host::SubWord, SOURCE_XMM, MASK_XMM);
            }
        }
        binary(code, Host::PackUnsignedWordToByte, SOURCE_XMM, SOURCE_XMM);
    } else if target.supports(TargetCpu::Sse41) {
        if !signed_input(operand.kind) {
            constant(code, TEMP_XMM, UNSIGNED_WORD_MAX_DWORDS);
            Host::MinUnsignedDword.register(code, SOURCE_XMM, TEMP_XMM, target);
        }
        Host::PackUnsignedDwordToWord.register(code, SOURCE_XMM, SOURCE_XMM, target);
    } else {
        // Host::PackSignedDwordToWord after a 32768 bias represents the full unsigned word range.
        if signed_input(operand.kind) {
            binary(code, Host::Xor, TEMP_XMM, TEMP_XMM);
            binary(code, Host::GreaterDword, TEMP_XMM, SOURCE_XMM);
            binary(code, Host::AndNot, TEMP_XMM, SOURCE_XMM);
            binary(code, Host::MoveAligned, SOURCE_XMM, TEMP_XMM);
        }
        unsigned_min_words(code);
        constant(code, TEMP_XMM, PACK_WORD_BIAS);
        binary(code, Host::SubDword, SOURCE_XMM, TEMP_XMM);
        binary(code, Host::PackSignedDwordToWord, SOURCE_XMM, SOURCE_XMM);
        constant(code, TEMP_XMM, PACKED_WORD_SIGN);
        binary(code, Host::Xor, SOURCE_XMM, TEMP_XMM);
    }
    if projection == NarrowProjection::Packed {
        clear_packed_upper(code);
        return;
    }
    binary(code, Host::Xor, TEMP_XMM, TEMP_XMM);
    binary(
        code,
        if small == BYTE_BITS {
            Host::UnpackLowByte
        } else {
            Host::UnpackLowWord
        },
        SOURCE_XMM,
        TEMP_XMM,
    );
}

fn unsigned_min_words(code: &mut Code) {
    binary(code, Host::MoveAligned, TEMP_XMM, SOURCE_XMM);
    constant(code, MASK_XMM, SIGN_DWORDS);
    binary(code, Host::Xor, TEMP_XMM, MASK_XMM);
    constant(code, MASK_XMM, BIASED_UNSIGNED_WORD_MAX);
    binary(code, Host::GreaterDword, TEMP_XMM, MASK_XMM);
    constant(code, MASK_XMM, UNSIGNED_WORD_MAX_DWORDS);
    binary(code, Host::And, MASK_XMM, TEMP_XMM);
    binary(code, Host::AndNot, TEMP_XMM, SOURCE_XMM);
    binary(code, Host::Or, TEMP_XMM, MASK_XMM);
    binary(code, Host::MoveAligned, SOURCE_XMM, TEMP_XMM);
}

fn merge_top(
    code: &mut Code,
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
    shift(code, 2 * small, Direction::Left, result, small);
    load_z_chunk(code, operand.destination, chunk, TEMP_XMM, length, target);
    constant(code, MASK_XMM, low_mask(small));
    binary(code, Host::And, TEMP_XMM, MASK_XMM);
    binary(code, Host::Or, result, TEMP_XMM);
}

fn scalar_narrow_qwords(code: &mut Code, operand: Operand) {
    binary(code, Host::Xor, RESULT_XMM, RESULT_XMM);
    for offset in (0..CHUNK_BYTES).step_by(QWORD_BYTES) {
        binary(code, Host::MoveAligned, MASK_XMM, SOURCE_XMM);
        byte_shift(code, Shift::RightBytes, MASK_XMM, offset);
        code.asm().movq_from_xmm(Rax, MASK_XMM);
        if !operand.kind.is_extract() {
            if operand.shift == QWORD_BITS {
                // x86 scalar shift counts are masked to six bits, so full-width
                // shifts are handled explicitly.
                if rounded(operand.kind) && signed_input(operand.kind) {
                    code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
                } else if rounded(operand.kind) || signed_input(operand.kind) {
                    code.asm()
                        .shift_imm(right(operand.kind), Size::Qword, Rax, QWORD_BITS - 1);
                } else {
                    code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
                }
            } else {
                if rounded(operand.kind) {
                    code.asm().mov(Size::Qword, Rdx, Rax);
                }
                code.asm()
                    .shift_imm(right(operand.kind), Size::Qword, Rax, operand.shift);
                if rounded(operand.kind) {
                    if operand.shift != 1 {
                        code.asm()
                            .shift_imm(ShiftOp::Shr, Size::Qword, Rdx, operand.shift - 1);
                    }
                    let mut asm = code.asm();
                    asm.alu_imm8(Alu::And, Size::Dword, Rdx, 1);
                    asm.alu(Alu::Add, Size::Qword, Rax, Rdx);
                }
            }
        }
        if signed_output(operand.kind) {
            scalar_bound(code, i64::from(i32::MIN) as u64, Cond::L);
            scalar_bound(code, i32::MAX as u64, Cond::G);
        } else {
            if signed_input(operand.kind) {
                let mut asm = code.asm();
                asm.alu(Alu::Xor, Size::Dword, Rdx, Rdx);
                asm.test(Size::Qword, Rax, Rax);
                asm.cmov(Cond::S, Size::Qword, Rax, Rdx);
            }
            scalar_bound(code, u64::from(u32::MAX), Cond::A);
        }
        code.asm().mov(Size::Dword, Rax, Rax);
        code.asm().movq_to_xmm(LANE_XMM, Rax);
        byte_shift(code, Shift::LeftBytes, LANE_XMM, offset);
        binary(code, Host::Or, RESULT_XMM, LANE_XMM);
    }
    binary(code, Host::MoveAligned, SOURCE_XMM, RESULT_XMM);
}

fn right(kind: Kind) -> ShiftOp {
    if signed_input(kind) {
        ShiftOp::Sar
    } else {
        ShiftOp::Shr
    }
}

fn scalar_bound(code: &mut Code, bound: u64, condition: Cond) {
    let mut asm = code.asm();
    asm.mov_imm64(Rdx, bound);
    asm.alu(Alu::Cmp, Size::Qword, Rax, Rdx);
    asm.cmov(condition, Size::Qword, Rax, Rdx);
}
