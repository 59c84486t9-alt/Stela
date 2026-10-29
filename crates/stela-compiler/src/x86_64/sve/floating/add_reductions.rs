//! FADDP, FADDV and FADDQV. NaNs, subnormals and any host status other than
//! inexact take the software path for the whole instruction.
use crate::x86_64::asm::Gpr::{Rax, Rcx};
use crate::x86_64::asm::{Alu, Code, ShiftOp, Size};

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{BinaryOperation, Format, features::NumericalFeatures},
        scalable::{BITS_PER_BYTE, ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        simd::arithmetic::Shape,
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::numerical::{
            ArithmeticOpcode, Condition, branch, emit_opcode_to, resolve, rounding_control,
        },
        sve::floating::classify::{
            Classification, guard_active_exception_enables, guard_normal_zero_or_infinity,
            prepare_classification,
        },
    },
};
use alloc::vec::Vec;

const VALUE: u8 = 0;
const RIGHT: u8 = 1;
const PREDICATE_SCRATCH: u8 = 2;
const CLASSIFY_SCRATCH: [u8; 3] = [1, 2, 3];
const CLASSIFY_MASKS: [u8; 2] = [4, 5];
const FIRST_SUBTREE: u8 = 6;
const ACCUMULATOR: u8 = 7;
const REGISTER_ONLY_DEPTH: usize = 2;
const OUTPUT_SLOT: usize = 0;
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;

fn element(format: Format) -> ElementSize {
    match format {
        Format::Half => ElementSize::Halfword,
        Format::Single => ElementSize::Word,
        Format::Double => ElementSize::Doubleword,
    }
}

fn low_lane(code: &mut Code, format: Format, lane: usize, register: u8) {
    let bytes = format.bits() as usize / BITS_PER_BYTE;
    if lane != 0 {
        ShiftOpcode::RightBytes.emit(code, register, (lane * bytes) as u8);
    }
    let clear = (VECTOR_CHUNK_BYTES - bytes) as u8;
    ShiftOpcode::LeftBytes.emit(code, register, clear);
    ShiftOpcode::RightBytes.emit(code, register, clear);
}

fn guard(
    code: &mut Code,
    classification: Classification,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    guard_normal_zero_or_infinity(
        code,
        classification,
        VALUE,
        CLASSIFY_SCRATCH,
        failures,
        target,
    );
}

struct Tree {
    format: Format,
    source: u8,
    predicate: u8,
    length: VectorLength,
    target: TargetCpu,
    classification: Classification,
    packed: bool,
}

impl Tree {
    // The tree emits the high subtree first and computes ADD(low, high).
    // Inactive lanes contribute +0 as real inputs, even when the whole tree is
    // inactive.
    fn emit(
        &self,
        code: &mut Code,
        start: usize,
        count: usize,
        depth: usize,
        failures: &mut Vec<usize>,
    ) {
        if count == 1 {
            let lanes = VECTOR_CHUNK_BYTES * BITS_PER_BYTE / self.format.bits() as usize;
            let chunk = if self.packed { start } else { start / lanes };
            load_z_chunk(code, self.source, chunk, VALUE, self.length, self.target);
            read_predicate_mask(
                code,
                self.predicate,
                chunk,
                element(self.format),
                crate::x86_64::scalable::MaskRegisters::new(RIGHT, PREDICATE_SCRATCH),
                self.length,
                self.target,
            );
            Host::And.register(code, VALUE, RIGHT, self.target);
            if !self.packed {
                low_lane(code, self.format, start % lanes, VALUE);
            }
            guard(code, self.classification, failures, self.target);
            return;
        }
        assert!(depth < REGISTER_ONLY_DEPTH);
        let half = count / 2;
        let saved = FIRST_SUBTREE + depth as u8;
        self.emit(code, start + half, half, depth + 1, failures);
        Host::MoveAligned.register(code, saved, VALUE, self.target);
        self.emit(code, start, half, depth + 1, failures);
        Host::MoveAligned.register(code, RIGHT, saved, self.target);
        emit_opcode_to(
            code,
            self.format,
            if self.packed {
                Shape::Vector128
            } else {
                Shape::Scalar
            },
            ArithmeticOpcode::Add,
            VALUE,
            RIGHT,
        );
        guard(code, self.classification, failures, self.target);
    }
}

fn status(code: &mut Code, frame: &numerical::Frame, failures: &mut Vec<usize>) {
    numerical::capture_status(code, frame);
    code.asm()
        .test_imm(Size::Dword, Rcx, MXCSR_OTHER_STATUS as i32);
    failures.push(branch(code, Condition::NotZero));
    let mut asm = code.asm();
    asm.mov(Size::Dword, Rax, Rcx);
    asm.alu_accumulator_imm32(Alu::And, Size::Dword, MXCSR_INEXACT as i32);
    asm.shift_imm(ShiftOp::Shr, Size::Dword, Rax, MXCSR_TO_FPSR_INEXACT_SHIFT);
    numerical::add_fpsr(code, frame);
}

struct ExceptionState<'a> {
    features: NumericalFeatures,
    classification: Classification,
    frame: &'a numerical::Frame,
    failures: &'a mut Vec<usize>,
}

fn pairwise(
    code: &mut Code,
    operand: Operand,
    left: u8,
    right: u8,
    length: VectorLength,
    exceptions: ExceptionState<'_>,
    target: TargetCpu,
) {
    let ExceptionState {
        features,
        classification,
        frame,
        failures,
    } = exceptions;
    let predicate = operand
        .predicate
        .expect("validated predicated pairwise form");
    let lane_bytes = operand.format.bits() as usize / BITS_PER_BYTE;
    for chunk in 0..length.chunks() {
        Host::Xor.register(code, ACCUMULATOR, ACCUMULATOR, target);
        for lane in 0..VECTOR_CHUNK_BYTES / lane_bytes {
            read_predicate_mask(
                code,
                predicate,
                chunk,
                element(operand.format),
                crate::x86_64::scalable::MaskRegisters::new(FIRST_SUBTREE, RIGHT),
                length,
                target,
            );
            if lane != 0 {
                ShiftOpcode::RightBytes.emit(code, FIRST_SUBTREE, (lane * lane_bytes) as u8);
            }
            code.asm()
                .simd_to_gpr(Host::ByteSignMask, Rax, FIRST_SUBTREE, target);
            code.asm().test_accumulator_imm(Size::Byte, 1);
            let inactive = branch(code, Condition::Zero);
            guard_active_exception_enables(code, FIRST_SUBTREE, features, failures, target);
            let source = if lane % 2 == 0 { left } else { right };
            let first = lane - lane % 2;
            // Output predication never masks either member of this source pair.
            load_z_chunk(code, source, chunk, VALUE, length, target);
            low_lane(code, operand.format, first, VALUE);
            guard(code, classification, failures, target);
            Host::MoveAligned.register(code, FIRST_SUBTREE, VALUE, target);
            load_z_chunk(code, source, chunk, VALUE, length, target);
            low_lane(code, operand.format, first + 1, VALUE);
            guard(code, classification, failures, target);
            Host::MoveAligned.register(code, RIGHT, VALUE, target);
            Host::MoveAligned.register(code, VALUE, FIRST_SUBTREE, target);
            emit_opcode_to(
                code,
                operand.format,
                Shape::Scalar,
                ArithmeticOpcode::Add,
                VALUE,
                RIGHT,
            );
            guard(code, classification, failures, target);
            let selected = code.asm().jmp().offset();
            let inactive_start = code.len();
            resolve(code, inactive, inactive_start);
            load_z_chunk(code, operand.destination, chunk, VALUE, length, target);
            low_lane(code, operand.format, lane, VALUE);
            let merge = code.len();
            resolve(code, selected, merge);
            if lane != 0 {
                ShiftOpcode::LeftBytes.emit(code, VALUE, (lane * lane_bytes) as u8);
            }
            Host::Or.register(code, ACCUMULATOR, VALUE, target);
        }
        numerical::stage_vector_chunk(code, frame, OUTPUT_SLOT, chunk, ACCUMULATOR, target);
    }
}

/// Unsupported lengths or formats return false before emitting, leaving the
/// instruction to software completion.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    if operand.kind != Kind::Binary(BinaryOperation::Add) || operand.predicate.is_none() {
        return Ok(false);
    }
    let pair = match (operand.inputs, operand.shape) {
        (Inputs::Pairwise { left, right }, ResultShape::Vector) if left == operand.destination => {
            Some((left, right))
        }
        (Inputs::Reduction { .. }, ResultShape::ScalarReduction | ResultShape::QuadReduction) => {
            None
        }
        _ => return Ok(false),
    };
    let raw_base = operand.shape == ResultShape::QuadReduction && length.chunks() == 1;
    if operand.format == Format::Half && !raw_base {
        return Ok(false);
    }
    let packed = operand.shape == ResultShape::QuadReduction;
    let tree_count = if packed {
        length.chunks()
    } else {
        length.bytes() * BITS_PER_BYTE / operand.format.bits() as usize
    };
    if pair.is_none() && tree_count > 1 << REGISTER_ONLY_DEPTH {
        return Ok(false);
    }
    let output = if pair.is_some() {
        Output::Z(operand.destination)
    } else {
        Output::V(operand.destination)
    };
    let environment = if raw_base {
        Environment::Exact
    } else {
        Environment::PrivateMxcsr
    };
    let frame = numerical::begin(code, length, &[output], environment)?;
    let mut failures = Vec::new();
    if raw_base {
        let Inputs::Reduction { source } = operand.inputs else {
            unreachable!("validated reduction")
        };
        load_z_chunk(code, source, 0, VALUE, length, target);
        read_predicate_mask(
            code,
            operand.predicate.unwrap(),
            0,
            element(operand.format),
            crate::x86_64::scalable::MaskRegisters::new(RIGHT, PREDICATE_SCRATCH),
            length,
            target,
        );
        Host::And.register(code, VALUE, RIGHT, target);
        // The one-leaf raw base has no FP core call, even with kept enables.
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, 0, VALUE, target);
    } else {
        rounding_control(code);
        numerical::install_mxcsr(code, &frame);
        if pair.is_none() {
            // Every non-base reduction executes core calls even for empty P.
            Host::EqualDword.register(code, VALUE, VALUE, target);
            guard_active_exception_enables(code, VALUE, features, &mut failures, target);
        }
        let classification = prepare_classification(code, operand.format, CLASSIFY_MASKS, target);
        if let Some((left, right)) = pair {
            pairwise(
                code,
                operand,
                left,
                right,
                length,
                ExceptionState {
                    features,
                    classification,
                    frame: &frame,
                    failures: &mut failures,
                },
                target,
            );
        } else {
            let Inputs::Reduction { source } = operand.inputs else {
                unreachable!("validated reduction")
            };
            Tree {
                format: operand.format,
                source,
                predicate: operand.predicate.unwrap(),
                length,
                target,
                classification,
                packed,
            }
            .emit(code, 0, tree_count, 0, &mut failures);
            numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, 0, VALUE, target);
        }
        status(code, &frame, &mut failures);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
