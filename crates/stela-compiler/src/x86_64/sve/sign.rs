//! SVE predicated FABS and FNEG by integer masking; no FP exceptions.
use crate::x86_64::asm::Gpr::{Rcx, Rdi};
use crate::x86_64::asm::{Code, Cond, Mem, Rm, Size};
use crate::{
    GuestState, TargetCpu,
    aarch64::{
        floating::{FPCR_AH, Format},
        scalable::{ElementSize, VectorLength},
        sve::sign::{Kind, Operand},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode},
        scalable::{load_z_chunk, read_predicate_mask, store_z_chunk},
    },
};

const SOURCE: u8 = 0;
const SIGN: u8 = 1;
const SELECTED_SIGN: u8 = 2;
const INFINITY: u8 = 3;
const HIGH_GREATER: u8 = 4;
const ZERO: u8 = 5;
const ACTIVE: u8 = 6;
const PREDICATE_SCRATCH: u8 = 7;
const BITS_PER_BYTE: u8 = 8;
const QWORD_BYTES: u8 = 8;
const BROADCAST_HIGH_DWORDS: u8 = 0xf5;
const BROADCAST_LOW_DWORDS: u8 = 0xa0;
const HALF_INFINITY: u64 = 0x7c00;
const SINGLE_INFINITY: u64 = 0x7f80_0000;
const DOUBLE_INFINITY: u64 = 0x7ff0_0000_0000_0000;

fn packed(code: &mut Code, opcode: SimdOpcode, destination: u8, source: u8, target: TargetCpu) {
    opcode.register(code, destination, source, target);
}

fn shuffle(code: &mut Code, register: u8, control: u8, target: TargetCpu) {
    code.asm().simd_imm(
        SimdOpcode::ShuffleDword,
        register,
        Rm::Xmm(register),
        control,
        target,
    );
}

fn infinity(code: &mut Code, format: Format, target: TargetCpu) {
    let (lane, lane_bytes) = match format {
        Format::Half => (HALF_INFINITY, 2),
        Format::Single => (SINGLE_INFINITY, 4),
        Format::Double => (DOUBLE_INFINITY, QWORD_BYTES),
    };
    let mut low = 0;
    for index in 0..QWORD_BYTES / lane_bytes {
        low |= lane << (index * lane_bytes * BITS_PER_BYTE);
    }
    let mut asm = code.asm();
    asm.mov_imm64(Rcx, low);
    asm.simd(SimdOpcode::MoveGprQword, INFINITY, Rcx, target);
    packed(code, SimdOpcode::UnpackLowQword, INFINITY, INFINITY, target);
}

fn suppress_nan_sign(code: &mut Code, format: Format, target: TargetCpu) {
    let mut asm = code.asm();
    asm.test_imm32(
        Size::Dword,
        Mem::base_disp32(Rdi, core::mem::offset_of!(GuestState, fpcr) as i32),
        FPCR_AH as i32,
    );
    let ordinary = asm.jcc(Cond::E);

    packed(code, SimdOpcode::MoveAligned, SELECTED_SIGN, SIGN, target);
    packed(code, SimdOpcode::AndNot, SELECTED_SIGN, SOURCE, target);
    infinity(code, format, target);
    match format {
        Format::Half => packed(
            code,
            SimdOpcode::GreaterWord,
            SELECTED_SIGN,
            INFINITY,
            target,
        ),
        Format::Single => packed(
            code,
            SimdOpcode::GreaterDword,
            SELECTED_SIGN,
            INFINITY,
            target,
        ),
        Format::Double if target.supports(TargetCpu::Sse42) => {
            packed(
                code,
                SimdOpcode::GreaterQword,
                SELECTED_SIGN,
                INFINITY,
                target,
            );
        }
        Format::Double => {
            // A positive magnitude exceeds infinity if high dword is greater,
            // or its high dword equals infinity and its low dword is nonzero.
            packed(
                code,
                SimdOpcode::MoveAligned,
                HIGH_GREATER,
                SELECTED_SIGN,
                target,
            );
            packed(
                code,
                SimdOpcode::GreaterDword,
                HIGH_GREATER,
                INFINITY,
                target,
            );
            shuffle(code, HIGH_GREATER, BROADCAST_HIGH_DWORDS, target);
            packed(
                code,
                SimdOpcode::EqualDword,
                INFINITY,
                SELECTED_SIGN,
                target,
            );
            shuffle(code, INFINITY, BROADCAST_HIGH_DWORDS, target);
            packed(code, SimdOpcode::Xor, ZERO, ZERO, target);
            packed(code, SimdOpcode::EqualDword, SELECTED_SIGN, ZERO, target);
            shuffle(code, SELECTED_SIGN, BROADCAST_LOW_DWORDS, target);
            packed(code, SimdOpcode::AndNot, SELECTED_SIGN, INFINITY, target);
            packed(code, SimdOpcode::Or, SELECTED_SIGN, HIGH_GREATER, target);
        }
    }
    packed(code, SimdOpcode::AndNot, SELECTED_SIGN, SIGN, target);
    code.asm().bind(ordinary);
}

/// Access and profile checks must precede this total, register-only emitter.
pub(crate) fn emit(code: &mut Code, operand: &Operand, length: VectorLength, target: TargetCpu) {
    let operation = match operand.kind {
        Kind::Absolute => SimdOpcode::AndNot,
        Kind::Negate => SimdOpcode::Xor,
    };
    let (element, shift) = match operand.format {
        Format::Half => (ElementSize::Halfword, ShiftOpcode::LeftWord),
        Format::Single => (ElementSize::Word, ShiftOpcode::LeftDword),
        Format::Double => (ElementSize::Doubleword, ShiftOpcode::LeftQword),
    };
    packed(code, SimdOpcode::EqualDword, SIGN, SIGN, target);
    shift.emit(code, SIGN, operand.format.bits() as u8 - 1);
    for chunk in 0..length.chunks() {
        load_z_chunk(code, operand.source, chunk, SOURCE, length, target);
        packed(code, SimdOpcode::MoveAligned, SELECTED_SIGN, SIGN, target);
        suppress_nan_sign(code, operand.format, target);
        let result = if operation == SimdOpcode::AndNot {
            packed(code, operation, SELECTED_SIGN, SOURCE, target);
            SELECTED_SIGN
        } else {
            packed(code, operation, SOURCE, SELECTED_SIGN, target);
            SOURCE
        };
        read_predicate_mask(
            code,
            operand.predicate,
            chunk,
            element,
            ACTIVE,
            PREDICATE_SCRATCH,
            length,
            target,
        );
        packed(code, SimdOpcode::And, result, ACTIVE, target);
        load_z_chunk(code, operand.destination, chunk, INFINITY, length, target);
        packed(code, SimdOpcode::AndNot, ACTIVE, INFINITY, target);
        packed(code, SimdOpcode::Or, result, ACTIVE, target);
        // Sources and the old destination for this independent chunk are read
        // before its write, including source/destination aliases.
        store_z_chunk(code, operand.destination, chunk, result, length, target);
    }
}
