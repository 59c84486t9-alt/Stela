//! SVE integer reductions.
use crate::TargetCpu;
use crate::aarch64::scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength};
use crate::aarch64::sve::reductions::{Kind, Operand, Output};
use crate::x86_64::asm::Gpr::{R8, R9, Rax};
use crate::x86_64::asm::{Alu, Code, Cond, Rm, Size};
use crate::x86_64::isa::{ShiftOpcode, SimdOpcode as Host};
use crate::x86_64::scalable::{clear_z_upper, load_z_chunk, read_predicate_mask, store_z_chunk};

const RESULT: u8 = 0;
const SOURCE: u8 = 1;
const TEMPORARY: u8 = 2;
const SIGN: u8 = 3;
const NEUTRAL: u8 = 4;
const CONSTANT: u8 = 5;
const PREDICATE: u8 = 6;
const PREDICATE_SCRATCH: u8 = 7;
const QWORD_BYTES: usize = core::mem::size_of::<u64>();
const DWORD_BYTES: usize = core::mem::size_of::<u32>();
const WORD_ONES: u64 = 0x0001_0001_0001_0001;
const WORD_ONES_SHIFT: u8 = (u16::BITS - 1) as u8;

fn packed(code: &mut Code, opcode: Host, destination: u8, source: u8, target: TargetCpu) {
    opcode.register(code, destination, source, target);
}

fn constant(code: &mut Code, destination: u8, value: u64) {
    match value {
        u64::MAX => {
            packed(
                code,
                Host::EqualDword,
                destination,
                destination,
                TargetCpu::Baseline,
            );
            return;
        }
        WORD_ONES => {
            packed(
                code,
                Host::EqualDword,
                destination,
                destination,
                TargetCpu::Baseline,
            );
            ShiftOpcode::RightWord.emit(code, destination, WORD_ONES_SHIFT);
            return;
        }
        _ => {}
    }
    let mut asm = code.asm();
    asm.mov_imm64(Rax, value);
    asm.simd(Host::MoveGprQword, destination, Rax, TargetCpu::Baseline);
    packed(
        code,
        Host::UnpackLowQword,
        destination,
        destination,
        TargetCpu::Baseline,
    );
}

fn repeated(value: u64, element: ElementSize) -> u64 {
    let mask = u64::MAX >> (u64::BITS as usize - element.bits());
    (0..QWORD_BYTES / element.bytes()).fold(0, |result, lane| {
        result | ((value & mask) << (lane * element.bits()))
    })
}

fn is_sum(kind: Kind) -> bool {
    matches!(kind, Kind::SignedAdd | Kind::UnsignedAdd)
}

fn is_minimum(kind: Kind) -> bool {
    matches!(kind, Kind::SignedMinimum | Kind::UnsignedMinimum)
}

fn is_signed(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::SignedAdd | Kind::SignedMaximum | Kind::SignedMinimum
    )
}

fn neutral(kind: Kind, element: ElementSize) -> u64 {
    let mask = u64::MAX >> (u64::BITS as usize - element.bits());
    let sign = 1u64 << (element.bits() - 1);
    match kind {
        Kind::And | Kind::UnsignedMinimum => mask,
        Kind::SignedMaximum => sign,
        Kind::SignedMinimum => sign - 1,
        _ => 0,
    }
}

fn bias(kind: Kind, element: ElementSize, target: TargetCpu) -> u64 {
    // Signed byte maxima use the compact unsigned domain on every host tier.
    if kind == Kind::SignedMaximum && element == ElementSize::Byte {
        return repeated(1 << (element.bits() - 1), element);
    }
    if target.supports(TargetCpu::Sse41) {
        return 0;
    }
    match (kind, element) {
        (Kind::SignedMinimum, ElementSize::Byte)
        | (
            Kind::UnsignedMaximum | Kind::UnsignedMinimum,
            ElementSize::Halfword | ElementSize::Word,
        ) => repeated(1 << (element.bits() - 1), element),
        _ => 0,
    }
}

fn reduction_opcode(kind: Kind, element: ElementSize, target: TargetCpu) -> Option<Host> {
    let minimum = is_minimum(kind);
    match kind {
        Kind::And => Some(Host::And),
        Kind::Or => Some(Host::Or),
        Kind::Xor => Some(Host::Xor),
        Kind::UnsignedAdd => Some(match element {
            ElementSize::Byte => Host::AddByte,
            ElementSize::Halfword => Host::AddWord,
            ElementSize::Word => Host::AddDword,
            ElementSize::Doubleword => Host::AddQword,
            ElementSize::Quadword => unreachable!("reduction decoder excludes quadword elements"),
        }),
        Kind::UnsignedMaximum
        | Kind::UnsignedMinimum
        | Kind::SignedMaximum
        | Kind::SignedMinimum => {
            let signed = is_signed(kind);
            Some(
                match (element, signed, minimum, target.supports(TargetCpu::Sse41)) {
                    (ElementSize::Byte, _, false, _) => Host::MaxUnsignedByte,
                    (ElementSize::Byte, false, true, _)
                    | (ElementSize::Byte, true, true, false) => Host::MinUnsignedByte,
                    (ElementSize::Byte, true, true, true) => Host::MinSignedByte,
                    (ElementSize::Halfword, true, false, _)
                    | (ElementSize::Halfword, false, false, false) => Host::MaxSignedWord,
                    (ElementSize::Halfword, true, true, _)
                    | (ElementSize::Halfword, false, true, false) => Host::MinSignedWord,
                    (ElementSize::Halfword, false, false, true) => Host::MaxUnsignedWord,
                    (ElementSize::Halfword, false, true, true) => Host::MinUnsignedWord,
                    (ElementSize::Word, true, false, true) => Host::MaxSignedDword,
                    (ElementSize::Word, true, true, true) => Host::MinSignedDword,
                    (ElementSize::Word, false, false, true) => Host::MaxUnsignedDword,
                    (ElementSize::Word, false, true, true) => Host::MinUnsignedDword,
                    _ => return None,
                },
            )
        }
        _ => None,
    }
}

/// XMM0/XMM1 hold accumulator and next lanes. Compare/select consumes XMM3.
fn combine(code: &mut Code, kind: Kind, element: ElementSize, target: TargetCpu) {
    if let Some(opcode) = reduction_opcode(kind, element, target) {
        packed(code, opcode, RESULT, SOURCE, target);
        return;
    }
    let (left, right) = if is_minimum(kind) {
        (SOURCE, RESULT)
    } else {
        (RESULT, SOURCE)
    };
    packed(code, Host::MoveAligned, SIGN, left, target);
    packed(code, Host::GreaterDword, SIGN, right, target);
    packed(code, Host::And, RESULT, SIGN, target);
    packed(code, Host::AndNot, SIGN, SOURCE, target);
    packed(code, Host::Or, RESULT, SIGN, target);
}

fn mask_source(code: &mut Code, neutral_nonzero: bool, target: TargetCpu) {
    packed(code, Host::And, SOURCE, PREDICATE, target);
    if neutral_nonzero {
        packed(code, Host::AndNot, PREDICATE, NEUTRAL, target);
        packed(code, Host::Or, SOURCE, PREDICATE, target);
    }
}

fn sum_chunk(code: &mut Code, kind: Kind, element: ElementSize, target: TargetCpu) {
    let signed = kind == Kind::SignedAdd;
    if element == ElementSize::Byte && !signed {
        code.asm().psadbw(SOURCE, Rm::Xmm(NEUTRAL));
        packed(code, Host::AddQword, RESULT, SOURCE, target);
        return;
    }
    if element == ElementSize::Halfword && signed {
        packed(code, Host::MultiplyAddWords, SOURCE, CONSTANT, target);
        packed(code, Host::AddDword, RESULT, SOURCE, target);
        return;
    }
    if element == ElementSize::Doubleword {
        packed(code, Host::AddQword, RESULT, SOURCE, target);
        return;
    }
    let (low, high, add, greater) = match element {
        ElementSize::Byte => (
            Host::UnpackLowByte,
            Host::UnpackHighByte,
            Host::AddDword,
            Host::GreaterByte,
        ),
        ElementSize::Halfword => (
            Host::UnpackLowWord,
            Host::UnpackHighWord,
            Host::AddDword,
            Host::GreaterWord,
        ),
        ElementSize::Word => (
            Host::UnpackLowDword,
            Host::UnpackHighDword,
            Host::AddQword,
            Host::GreaterDword,
        ),
        _ => unreachable!("sum decoder excludes quadword elements"),
    };
    let extension = if signed {
        packed(code, Host::Xor, SIGN, SIGN, target);
        packed(code, greater, SIGN, SOURCE, target);
        SIGN
    } else {
        NEUTRAL
    };
    packed(code, Host::MoveAligned, TEMPORARY, SOURCE, target);
    packed(code, low, SOURCE, extension, target);
    packed(code, high, TEMPORARY, extension, target);
    if element == ElementSize::Byte {
        packed(code, Host::MultiplyAddWords, SOURCE, CONSTANT, target);
        packed(code, Host::MultiplyAddWords, TEMPORARY, CONSTANT, target);
    }
    packed(code, add, SOURCE, TEMPORARY, target);
    packed(code, add, RESULT, SOURCE, target);
}

fn scalar_result(code: &mut Code, element: ElementSize, sign_extend: bool) {
    let mut asm = code.asm();
    if element == ElementSize::Doubleword {
        asm.movq_from_xmm(Rax, RESULT);
    } else {
        asm.movd_from_xmm(Rax, RESULT);
    }
    match element {
        ElementSize::Byte => asm.movzx(Size::Dword, Rax, Size::Byte, Rax),
        ElementSize::Halfword => asm.movzx(Size::Dword, Rax, Size::Word, Rax),
        ElementSize::Word if sign_extend => asm.movsxd(Rax, Rax),
        _ => {}
    }
    asm.simd(Host::MoveGprQword, RESULT, Rax, TargetCpu::Baseline);
}

fn conditional_move(kind: Kind) -> Cond {
    match (is_signed(kind), is_minimum(kind)) {
        (true, true) => Cond::G,
        (true, false) => Cond::L,
        (false, true) => Cond::A,
        (false, false) => Cond::B,
    }
}

fn seed_qword_columns(code: &mut Code) {
    for destination in [R8, R9] {
        code.asm().movq_from_xmm(destination, SOURCE);
        if destination == R8 {
            ShiftOpcode::RightBytes.emit(code, SOURCE, QWORD_BYTES as u8);
        }
    }
}

fn combine_qword_columns(code: &mut Code, kind: Kind) {
    let condition = conditional_move(kind);
    for destination in [R8, R9] {
        let mut asm = code.asm();
        asm.movq_from_xmm(Rax, SOURCE);
        asm.alu(Alu::Cmp, Size::Qword, destination, Rax);
        asm.cmov(condition, Size::Qword, destination, Rax);
        if destination == R8 {
            ShiftOpcode::RightBytes.emit(code, SOURCE, QWORD_BYTES as u8);
        }
    }
}

/// Complete ordinary data effects. All source chunks precede any destination
/// writes, including Vd==Zn. Integer operations leave guest status unchanged.
pub fn emit(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
    let sum = operand.output == Output::Scalar && is_sum(operand.kind);
    let qword_extrema = matches!(
        operand.kind,
        Kind::SignedMaximum | Kind::UnsignedMaximum | Kind::SignedMinimum | Kind::UnsignedMinimum
    ) && operand.element_size == ElementSize::Doubleword;
    let qword_columns =
        qword_extrema && !(operand.output == Output::Quadword && length.chunks() == 1);
    let bias_value = if operand.output == Output::Quadword && length.chunks() == 1 {
        0
    } else {
        bias(operand.kind, operand.element_size, target)
    };
    let neutral_value = repeated(
        neutral(operand.kind, operand.element_size),
        operand.element_size,
    ) ^ bias_value;
    if neutral_value != 0 {
        constant(code, NEUTRAL, neutral_value);
    } else if sum {
        packed(code, Host::Xor, NEUTRAL, NEUTRAL, target);
    }
    if sum {
        packed(code, Host::MoveAligned, RESULT, NEUTRAL, target);
    }
    if bias_value != 0 {
        constant(code, CONSTANT, bias_value);
    } else if operand.kind == Kind::SignedAdd
        && matches!(
            operand.element_size,
            ElementSize::Byte | ElementSize::Halfword
        )
    {
        constant(code, CONSTANT, WORD_ONES);
    }
    for chunk in 0..length.chunks() {
        load_z_chunk(code, operand.source, chunk, SOURCE, length, target);
        read_predicate_mask(
            code,
            operand.governing,
            chunk,
            operand.element_size,
            crate::x86_64::scalable::MaskRegisters::new(PREDICATE, PREDICATE_SCRATCH),
            length,
            target,
        );
        if bias_value != 0 {
            packed(code, Host::Xor, SOURCE, CONSTANT, target);
        }
        mask_source(code, neutral_value != 0, target);
        if sum {
            sum_chunk(code, operand.kind, operand.element_size, target);
        } else if chunk == 0 {
            if qword_columns {
                seed_qword_columns(code);
            } else {
                packed(code, Host::MoveAligned, RESULT, SOURCE, target);
            }
        } else if qword_columns {
            combine_qword_columns(code, operand.kind);
        } else {
            combine(code, operand.kind, operand.element_size, target);
        }
    }
    if qword_columns {
        if operand.output == Output::Scalar {
            let mut asm = code.asm();
            asm.alu(Alu::Cmp, Size::Qword, R8, R9);
            asm.cmov(conditional_move(operand.kind), Size::Qword, R8, R9);
        }
        code.asm().movq_to_xmm(RESULT, R8);
        if operand.output == Output::Quadword {
            code.asm().movq_to_xmm(TEMPORARY, R9);
            packed(code, Host::UnpackLowQword, RESULT, TEMPORARY, target);
        }
    } else {
        let accumulator_size = if sum {
            if matches!(
                operand.element_size,
                ElementSize::Byte | ElementSize::Halfword
            ) && !(operand.kind == Kind::UnsignedAdd
                && operand.element_size == ElementSize::Byte)
            {
                ElementSize::Word
            } else {
                ElementSize::Doubleword
            }
        } else {
            operand.element_size
        };
        let mut shift = VECTOR_CHUNK_BYTES / 2;
        while operand.output == Output::Scalar && shift >= accumulator_size.bytes() {
            packed(code, Host::MoveAligned, SOURCE, RESULT, target);
            ShiftOpcode::RightBytes.emit(code, SOURCE, shift as u8);
            if sum {
                packed(
                    code,
                    if accumulator_size.bytes() == DWORD_BYTES {
                        Host::AddDword
                    } else {
                        Host::AddQword
                    },
                    RESULT,
                    SOURCE,
                    target,
                );
            } else {
                combine(code, operand.kind, operand.element_size, target);
            }
            shift /= 2;
        }
        if bias_value != 0 {
            packed(code, Host::Xor, RESULT, CONSTANT, target);
        }
        if operand.output == Output::Scalar {
            scalar_result(
                code,
                accumulator_size,
                sum && operand.kind == Kind::SignedAdd,
            );
        }
    }
    store_z_chunk(code, operand.destination, 0, RESULT, length, target);
    clear_z_upper(code, operand.destination, PREDICATE_SCRATCH, length, target);
}
