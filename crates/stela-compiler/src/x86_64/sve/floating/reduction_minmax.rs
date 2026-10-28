//! SVE FMAXV/FMINV/FMAXNMV/FMINNMV and their QV forms. Only trees of nonzero
//! normals and infinities take the native path.
use crate::x86_64::asm::FloatLanes;
use crate::x86_64::asm::FloatOp;
use crate::x86_64::asm::Gpr::{Rax, Rdi};
use crate::x86_64::asm::{Alu, Code, Cond, Mem, Rm, Size};
use crate::{
    CompileError, GuestAddress, GuestState, TargetCpu,
    aarch64::{
        floating::{
            FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, Format, features::NumericalFeatures,
            minmax::MinMaxOperation,
        },
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        sve::floating::classify::{guard_normal_zero_or_infinity, prepare_classification},
    },
};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const ACTIVE: u8 = 1;
const SCRATCH: [u8; 3] = [2, 3, 4];
const CLASSIFICATION: [u8; 2] = [6, 7];
const TREE_SCRATCH: u8 = 5;
const TREE_ACTIVE: u8 = 6;
const TREE_PREDICATE_SCRATCH: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const OUTPUT_CHUNK: usize = 0;
const SWAP_DWORDS: u8 = 0xb1;
const BROADCAST_DWORD_0: u8 = 0x00;
const BROADCAST_DWORD_1: u8 = 0x55;
const BROADCAST_DWORD_2: u8 = 0xaa;
const BROADCAST_DWORD_3: u8 = 0xff;
const BROADCAST_QWORD_0: u8 = 0x44;
const BROADCAST_QWORD_1: u8 = 0xee;
const REMOVE_SIGN_BIT: u8 = 1;
const TREE_BRANCHES: usize = 2;
const NEXT_TREE_REGISTER: u8 = 1;

fn state_test(code: &mut Code, mask: u32) {
    code.asm().test_imm(
        Size::Dword,
        Mem::base_disp32(Rdi, core::mem::offset_of!(GuestState, fpcr) as i32),
        mask as i32,
    );
}

fn reject(code: &mut Code, failures: &mut Vec<usize>) {
    failures.push(code.asm().jcc(Cond::Ne).offset());
}

fn shuffle(code: &mut Code, dst: u8, src: u8, order: u8, target: TargetCpu) {
    code.asm()
        .simd_imm(Host::ShuffleDword, dst, Rm::Xmm(src), order, target);
}

fn broadcast(code: &mut Code, format: Format, mut bits: u64, dst: u8, target: TargetCpu) {
    if format == Format::Half {
        bits |= bits << Format::Half.bits();
    }
    let mut asm = code.asm();
    asm.mov_imm64(Rax, bits);
    asm.simd(Host::MoveGprQword, dst, Rax, target);
    if format == Format::Double {
        Host::UnpackLowQword.register(code, dst, dst, target);
    } else {
        shuffle(code, dst, dst, BROADCAST_DWORD_0, target);
    }
}

fn number(operation: MinMaxOperation) -> bool {
    matches!(
        operation,
        MinMaxOperation::MinimumNumber | MinMaxOperation::MaximumNumber
    )
}

fn minimum(operation: MinMaxOperation) -> bool {
    matches!(
        operation,
        MinMaxOperation::Minimum | MinMaxOperation::MinimumNumber
    )
}

/// Identity construction is bitwise; no numerical control validation is allowed
/// in the raw QV base case. DefaultNaN's sign alone depends on stored AH.
fn identity(
    code: &mut Code,
    operation: MinMaxOperation,
    format: Format,
    dst: u8,
    target: TargetCpu,
) {
    let bits = if number(operation) {
        format.exponent_mask() | 1 << (format.fraction_bits() - 1)
    } else {
        format.exponent_mask()
            | if minimum(operation) {
                0
            } else {
                format.sign_mask()
            }
    };
    broadcast(code, format, bits, dst, target);
    if number(operation) {
        state_test(code, FPCR_AH);
        let positive = code.asm().jcc(Cond::E);
        broadcast(code, format, bits | format.sign_mask(), dst, target);
        code.asm().bind(positive);
    }
}

fn selection(code: &mut Code, operation: MinMaxOperation, format: Format, lo: u8, hi: u8) {
    let mut asm = code.asm();
    match (format == Format::Double, minimum(operation)) {
        (true, true) => asm.float(FloatOp::Min, FloatLanes::PackedDouble, lo, Rm::Xmm(hi)),
        (true, false) => asm.float(FloatOp::Max, FloatLanes::PackedDouble, lo, Rm::Xmm(hi)),
        (false, true) => asm.float(FloatOp::Min, FloatLanes::PackedSingle, lo, Rm::Xmm(hi)),
        (false, false) => asm.float(FloatOp::Max, FloatLanes::PackedSingle, lo, Rm::Xmm(hi)),
    }
}

/// Reject every active zero, deliberately narrower than pairwise zero-tie guards.
fn guard_nonzero(code: &mut Code, format: Format, failures: &mut Vec<usize>, target: TargetCpu) {
    let [magnitude, zero, other_half] = SCRATCH;
    Host::MoveAligned.register(code, magnitude, RESULT, target);
    match format {
        Format::Single => ShiftOpcode::LeftDword,
        Format::Double => ShiftOpcode::LeftQword,
        Format::Half => unreachable!("tree widths checked"),
    }
    .emit(code, magnitude, REMOVE_SIGN_BIT);
    Host::Xor.register(code, zero, zero, target);
    Host::EqualDword.register(code, magnitude, zero, target);
    if format == Format::Double {
        shuffle(code, other_half, magnitude, SWAP_DWORDS, target);
        Host::And.register(code, magnitude, other_half, target);
    }
    Host::And.register(code, magnitude, ACTIVE, target);
    let mut asm = code.asm();
    asm.simd_to_gpr(Host::ByteSignMask, Rax, magnitude, target);
    asm.test(Size::Dword, Rax, Rax);
    reject(code, failures);
}

struct Tree {
    operation: MinMaxOperation,
    format: Format,
    source: u8,
    predicate: u8,
    element: ElementSize,
    scalar: bool,
    all_active: bool,
    length: VectorLength,
    target: TargetCpu,
}

impl Tree {
    fn leaf(&self, code: &mut Code, chunk: usize, dst: u8) {
        if !self.all_active {
            read_predicate_mask(
                code,
                self.predicate,
                chunk,
                self.element,
                TREE_ACTIVE,
                TREE_PREDICATE_SCRATCH,
                self.length,
                self.target,
            );
        }
        load_z_chunk(code, self.source, chunk, dst, self.length, self.target);
        if !self.all_active {
            Host::And.register(code, dst, TREE_ACTIVE, self.target);
            identity(code, self.operation, self.format, TREE_SCRATCH, self.target);
            Host::AndNot.register(code, TREE_ACTIVE, TREE_SCRATCH, self.target);
            Host::Or.register(code, dst, TREE_ACTIVE, self.target);
        }
        if !self.scalar {
            return;
        }
        // Exact FPReduce topology within each segment: high subtree first,
        // then low subtree, then combine(lo, hi). Broadcast scalar results so
        // host packed operations never inspect discarded source lanes.
        if self.format == Format::Single {
            shuffle(code, TREE_SCRATCH, dst, BROADCAST_DWORD_3, self.target);
            shuffle(code, TREE_ACTIVE, dst, BROADCAST_DWORD_2, self.target);
            selection(code, self.operation, self.format, TREE_ACTIVE, TREE_SCRATCH);
            shuffle(code, TREE_SCRATCH, dst, BROADCAST_DWORD_1, self.target);
            shuffle(code, dst, dst, BROADCAST_DWORD_0, self.target);
            selection(code, self.operation, self.format, dst, TREE_SCRATCH);
            selection(code, self.operation, self.format, dst, TREE_ACTIVE);
        } else {
            shuffle(code, TREE_SCRATCH, dst, BROADCAST_QWORD_1, self.target);
            shuffle(code, dst, dst, BROADCAST_QWORD_0, self.target);
            selection(code, self.operation, self.format, dst, TREE_SCRATCH);
        }
    }

    fn emit(&self, code: &mut Code, start: usize, count: usize, dst: u8) {
        if count == 1 {
            self.leaf(code, start, dst);
            return;
        }
        let half = count / TREE_BRANCHES;
        self.emit(code, start + half, half, dst); // hi
        self.emit(code, start, half, dst + NEXT_TREE_REGISTER); // lo; hi stays live
        selection(
            code,
            self.operation,
            self.format,
            dst + NEXT_TREE_REGISTER,
            dst,
        );
        Host::MoveAligned.register(code, dst, dst + NEXT_TREE_REGISTER, self.target);
    }
}

/// No guest state changes before finish; failures use shared numerical exit.
/// Uses baseline SSE2 only. Clobbers RAX/RCX/RDX, flags and XMM0..7, preserves
/// caller MXCSR, guest FPSR/NZCV, source aliases and all unrelated state.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Kind::MinMax(operation) = operand.kind else {
        return Ok(false);
    };
    let Inputs::Reduction { source } = operand.inputs else {
        return Ok(false);
    };
    let Some(predicate) = operand.predicate else {
        return Ok(false);
    };
    if !matches!(
        operand.shape,
        ResultShape::ScalarReduction | ResultShape::QuadReduction
    ) {
        return Ok(false);
    }
    let raw = operand.shape == ResultShape::QuadReduction && length.chunks() == 1;
    if operand.format == Format::Half && !raw {
        return Ok(false);
    }
    let element = match operand.format {
        Format::Half => ElementSize::Halfword,
        Format::Single => ElementSize::Word,
        Format::Double => ElementSize::Doubleword,
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::V(operand.destination)],
        Environment::Exact,
    )?;
    let mut failures = Vec::new();
    if !raw {
        // FPReduce calls cores even with an empty mask: this guard MUST NOT be
        // active-only, unlike ordinary predicated elementwise arithmetic.
        if features.full_a64() {
            state_test(code, FPCR_EXCEPTION_ENABLE_MASK);
            reject(code, &mut failures);
        }
        let classification = prepare_classification(code, operand.format, CLASSIFICATION, target);
        for chunk in 0..length.chunks() {
            read_predicate_mask(
                code, predicate, chunk, element, ACTIVE, SCRATCH[0], length, target,
            );
            if number(operation) {
                let mut asm = code.asm();
                asm.simd_to_gpr(Host::ByteSignMask, Rax, ACTIVE, target);
                asm.alu_accumulator_imm32(Alu::Cmp, Size::Dword, 0xffff);
                reject(code, &mut failures);
            }
            load_z_chunk(code, source, chunk, RESULT, length, target);
            Host::And.register(code, RESULT, ACTIVE, target);
            guard_normal_zero_or_infinity(
                code,
                classification,
                RESULT,
                SCRATCH,
                &mut failures,
                target,
            );
            guard_nonzero(code, operand.format, &mut failures, target);
        }
    }
    let tree = Tree {
        operation,
        format: operand.format,
        source,
        predicate,
        element,
        scalar: operand.shape == ResultShape::ScalarReduction,
        all_active: !raw && number(operation),
        length,
        target,
    };
    tree.emit(code, 0, length.chunks(), RESULT);
    if tree.scalar {
        // PSRLDQ/PSLLDQ clears everything above the low scalar without changing
        // its bits; Output::V additionally clears the active upper Z bank.
        let tail = (VECTOR_CHUNK_BYTES as u32 - operand.format.bits() / u8::BITS) as u8;
        ShiftOpcode::LeftBytes.emit(code, RESULT, tail);
        ShiftOpcode::RightBytes.emit(code, RESULT, tail);
    }
    numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, OUTPUT_CHUNK, RESULT, target);
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
