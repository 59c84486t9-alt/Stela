//! SVE FRECPE/FRSQRTE tables on normal values. Host RCP/RSQRT approximations
//! are never used; integer DIV and a masked SQRTSD compute the exact table values.
use crate::x86_64::asm::BitTest;
use crate::x86_64::asm::FloatLanes;
use crate::x86_64::asm::Gpr::{R8, R9, R10, R11, Rax, Rcx, Rdi, Rdx};
use crate::x86_64::asm::{Alu, Code, Cond, Disp, Gpr, Mem, Rm, ShiftOp, Size, Unary};
use crate::{
    CompileError, GuestAddress, GuestState, TargetCpu,
    aarch64::{
        floating::{FPCR_AH, Format, features::NumericalFeatures},
        scalable::{VECTOR_CHUNK_BYTES, VectorLength},
        simd::estimate::Kind as EstimateKind,
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
        },
        sve::floating::classify::guard_active_exception_enables,
    },
};
use alloc::vec::Vec;

const SOURCE: u8 = 0;
const RESULT: u8 = 1;
const ROOT: u8 = 2;
const INSERT: u8 = 3;
const NUMERATOR: u8 = 4;
const INPUT_UNIT: u8 = 5;
const RESULT_UNIT: u8 = 6;
const ACTIVE: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const GPR_BITS: u32 = u64::BITS;
const STANDARD_INPUT_BITS: u32 = 8;
const STANDARD_RESULT_BITS: u32 = 8;
const ENHANCED_INPUT_BITS: u32 = 11;
const ENHANCED_RESULT_BITS: u32 = 12;
const RECIPROCAL_NUMERATOR_BITS: u32 = 19;
const ENHANCED_RECIPROCAL_NUMERATOR_BITS: u32 = 26;
const ROOT_NUMERATOR_BITS: u32 = 28;
const ENHANCED_ROOT_NUMERATOR_BITS: u32 = 39;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Reciprocal,
    ReciprocalSquareRoot,
}

fn test_ah(code: &mut Code) {
    code.asm().test_imm(
        Size::Dword,
        Mem::base_disp32(Rdi, core::mem::offset_of!(GuestState, fpcr) as i32),
        FPCR_AH as i32,
    );
}

fn xmm_to_gpr(code: &mut Code, source: u8, destination: Gpr) {
    code.asm().movq_from_xmm(destination, source);
}

fn xmm_constant(code: &mut Code, destination: u8, bits: u64, target: TargetCpu) {
    let mut asm = code.asm();
    asm.mov_imm64(Rax, bits);
    asm.simd(Host::MoveGprQword, destination, Rax, target);
}

fn numerator(operation: Operation, enhanced: bool) -> u64 {
    match (operation, enhanced) {
        (Operation::Reciprocal, false) => 1 << RECIPROCAL_NUMERATOR_BITS,
        (Operation::Reciprocal, true) => 1 << ENHANCED_RECIPROCAL_NUMERATOR_BITS,
        (Operation::ReciprocalSquareRoot, false) => (1 << ROOT_NUMERATOR_BITS) - 1,
        (Operation::ReciprocalSquareRoot, true) => (1 << ENHANCED_ROOT_NUMERATOR_BITS) - 1,
    }
}

fn constants(
    code: &mut Code,
    operation: Operation,
    format: Format,
    enhanced: bool,
    target: TargetCpu,
) {
    let input_bits = if enhanced {
        ENHANCED_INPUT_BITS
    } else {
        STANDARD_INPUT_BITS
    };
    let result_bits = if enhanced {
        ENHANCED_RESULT_BITS
    } else {
        STANDARD_RESULT_BITS
    };
    let mut asm = code.asm();
    asm.mov_imm32(R10, GPR_BITS - input_bits);
    asm.mov_imm32(R11, format.fraction_bits() - result_bits);
    xmm_constant(code, NUMERATOR, numerator(operation, enhanced), target);
    xmm_constant(code, INPUT_UNIT, 1 << input_bits, target);
    xmm_constant(code, RESULT_UNIT, 1 << result_bits, target);
}

fn guard_normal(code: &mut Code, operation: Operation, format: Format, failures: &mut Vec<usize>) {
    let mut asm = code.asm();
    asm.mov(Size::Qword, R8, Rax);
    asm.shift_imm(ShiftOp::Shr, Size::Qword, R8, format.fraction_bits() as u8);
    asm.alu_imm32(
        Alu::And,
        Size::Dword,
        R8,
        (format.exponent_mask() >> format.fraction_bits()) as i32,
    );
    asm.test(Size::Dword, R8, R8);
    failures.push(asm.jcc(Cond::E).offset());
    let ceiling = match operation {
        Operation::Reciprocal => format.exponent_bias() * 2 - 1,
        Operation::ReciprocalSquareRoot => {
            (format.exponent_mask() >> format.fraction_bits()) as u32
        }
    };
    asm.alu_imm32(Alu::Cmp, Size::Dword, R8, ceiling as i32);
    failures.push(asm.jcc(Cond::Ae).offset());
    if operation == Operation::ReciprocalSquareRoot {
        asm.bit_imm(BitTest::Bt, Size::Qword, Rax, (format.bits() - 1) as u8);
        failures.push(asm.jcc(Cond::B).offset());
    }
}

fn result_exponent(code: &mut Code, operation: Operation, format: Format) {
    let exponent_base = match operation {
        Operation::Reciprocal => format.exponent_bias() * 2 - 1,
        Operation::ReciprocalSquareRoot => format.exponent_bias() * 3 - 1,
    };
    let mut asm = code.asm();
    asm.mov_imm32(Rcx, exponent_base);
    asm.alu(Alu::Sub, Size::Dword, Rcx, R8);
    if operation == Operation::ReciprocalSquareRoot {
        code.asm().shift_one(ShiftOp::Shr, Size::Dword, Rcx);
    }
    code.asm()
        .shift_imm(ShiftOp::Shl, Size::Qword, Rcx, format.fraction_bits() as u8);
    if operation == Operation::Reciprocal {
        let mut asm = code.asm();
        asm.mov(Size::Qword, R9, Rax);
        asm.shift_imm(ShiftOp::Shr, Size::Qword, R9, (format.bits() - 1) as u8);
        asm.shift_imm(ShiftOp::Shl, Size::Qword, R9, (format.bits() - 1) as u8);
        asm.alu(Alu::Or, Size::Qword, R9, Rcx);
    } else {
        code.asm().mov(Size::Qword, R9, Rcx);
    }
}

fn midpoint(code: &mut Code, operation: Operation, format: Format, dynamic: bool) {
    // Strip sign/exponent first. The second shift selects only the top fixed
    // fraction bits, including the enhanced Single table's eleven-bit input.
    code.asm().shift_imm(
        ShiftOp::Shl,
        Size::Qword,
        Rax,
        (GPR_BITS - format.fraction_bits()) as u8,
    );
    if dynamic {
        let mut asm = code.asm();
        asm.mov(Size::Dword, Rcx, R10);
        asm.shift_cl(ShiftOp::Shr, Size::Qword, Rax);
        xmm_to_gpr(code, INPUT_UNIT, Rcx);
        code.asm().alu(Alu::Or, Size::Qword, Rax, Rcx);
    } else {
        code.asm().shift_imm(
            ShiftOp::Shr,
            Size::Qword,
            Rax,
            (GPR_BITS - STANDARD_INPUT_BITS) as u8,
        );
        code.asm()
            .alu_accumulator_imm32(Alu::Or, Size::Dword, 1 << STANDARD_INPUT_BITS);
    }
    if operation == Operation::Reciprocal {
        code.asm().lea(
            Size::Dword,
            Rcx,
            Mem::indexed(Rax, Rax, 1, 1).with_width(Disp::Byte),
        );
    } else {
        let mut asm = code.asm();
        asm.test_imm(Size::Byte, R8, 1);
        let odd = asm.jcc(Cond::Ne);
        asm.alu_imm8(Alu::And, Size::Dword, Rax, -2);
        asm.lea(
            Size::Dword,
            Rcx,
            Mem::indexed(Rax, Rax, 1, 2).with_width(Disp::Byte),
        );
        let ready = asm.jmp();
        asm.bind(odd);
        asm.shift_one(ShiftOp::Shr, Size::Dword, Rax);
        asm.lea(
            Size::Dword,
            Rcx,
            Mem::indexed(Rax, Rax, 1, 1).with_width(Disp::Byte),
        );
        asm.bind(ready);
    }
}

fn estimate(
    code: &mut Code,
    operation: Operation,
    format: Format,
    dynamic: bool,
    target: TargetCpu,
) {
    if dynamic {
        xmm_to_gpr(code, NUMERATOR, Rax);
    } else {
        code.asm()
            .mov_imm32(Rax, numerator(operation, false) as u32);
    }
    if dynamic && operation == Operation::ReciprocalSquareRoot {
        let mut asm = code.asm();
        asm.alu(Alu::Xor, Size::Dword, Rdx, Rdx);
        asm.unary(Unary::Div, Size::Qword, Rcx);
    } else {
        let mut asm = code.asm();
        asm.alu(Alu::Xor, Size::Dword, Rdx, Rdx);
        asm.unary(Unary::Div, Size::Dword, Rcx);
    }
    if operation == Operation::ReciprocalSquareRoot {
        // q=floor((2^n-1)/midpoint) is a positive integer below 2^28 in
        // both precision profiles. CVTSI2SD is therefore exact. Its square
        // root is below 2^14; for nonsquares distance to either neighboring
        // integer exceeds 2^-15, while RNE error is at most 2^-40. An exact
        // square rounds exactly. Truncating SQRTSD is consequently isqrt(q).
        code.asm()
            .cvtsi2float(FloatLanes::ScalarDouble, Size::Qword, 2, Rax);
        Host::SquareRootScalarDouble.register(code, ROOT, ROOT, target);
        code.asm()
            .cvtfloat2si(FloatLanes::ScalarDouble, true, Size::Qword, Rax, Rm::Xmm(2));
    }
    let mut asm = code.asm();
    asm.alu_imm8(Alu::Add, Size::Dword, Rax, 1);
    asm.shift_one(ShiftOp::Shr, Size::Dword, Rax);
    if dynamic {
        xmm_to_gpr(code, RESULT_UNIT, Rdx);
        let mut asm = code.asm();
        asm.alu(Alu::Sub, Size::Dword, Rax, Rdx);
        asm.mov(Size::Dword, Rcx, R11);
        asm.shift_cl(ShiftOp::Shl, Size::Qword, Rax);
    } else {
        code.asm()
            .alu_accumulator_imm32(Alu::Sub, Size::Dword, 1 << STANDARD_RESULT_BITS);
        code.asm().shift_imm(
            ShiftOp::Shl,
            Size::Qword,
            Rax,
            (format.fraction_bits() - STANDARD_RESULT_BITS) as u8,
        );
    }
    code.asm().alu(Alu::Or, Size::Qword, Rax, R9);
}

fn insert(code: &mut Code, format: Format, lane: usize, checked: bool, target: TargetCpu) {
    match format {
        Format::Half => {
            code.asm().pinsrw(1, Rax, lane as u8);
        }

        Format::Single if checked => {
            assert!(target.supports(TargetCpu::Sse41));
            code.asm().pinsrd(1, Rax, lane as u8);
        }
        Format::Single | Format::Double => {
            // The unpredicated first lane initializes the complete chunk:
            // MOVQ clears its high64 bits. Later lanes only OR fresh disjoint
            // bits; no initial PXOR or first-lane temporary/OR is needed.
            let destination = if lane == 0 { RESULT } else { INSERT };
            code.asm()
                .simd(Host::MoveGprQword, destination, Rax, target);
            if lane != 0 {
                ShiftOpcode::LeftBytes.emit(
                    code,
                    INSERT,
                    (lane * format.bits() as usize / u8::BITS as usize) as u8,
                );
                Host::Or.register(code, RESULT, INSERT, target);
            }
        }
    }
}

/// Normal-value kernel for the two estimate forms. Special values, subnormal
/// inputs, subnormal or overflowing reciprocals and negative RSQRT inputs leave
/// the instruction to software completion. Normal half precision ignores AHP
/// and FZ16. FPCR.AH suppresses enabled-trap rejection; FEAT_RPRES with
/// single-precision AH selects the enhanced constants. No new FPSR bits are
/// raised. Clobbers RAX/RCX/RDX/R8-R11, flags and XMM0-7; preserves the
/// callee-saved GPRs, RDI/R15, the sources and the caller's MXCSR.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let operation = match operand.kind {
        Kind::Estimate(EstimateKind::Reciprocal) => Operation::Reciprocal,
        Kind::Estimate(EstimateKind::ReciprocalSquareRoot) => Operation::ReciprocalSquareRoot,
        _ => return Ok(false),
    };
    let Inputs::Unary { source } = operand.inputs else {
        return Ok(false);
    };
    if operand.shape != ResultShape::Vector || operand.predicate.is_some() {
        return Ok(false);
    }

    // Measured SSE4.1 insertion applies only to one Single chunk with RPRES
    // and no full-A64 enable guard. FRECPE benefits on a true RAW recurrence;
    // FRSQRTE benefits with either alias. Other lengths/profiles keep baseline.
    let checked = operand.format == Format::Single
        && length.bytes() == VECTOR_CHUNK_BYTES
        && target.supports(TargetCpu::Sse41)
        && !features.full_a64()
        && features.rpres()
        && (operation == Operation::ReciprocalSquareRoot || source == operand.destination);

    let environment = if operation == Operation::ReciprocalSquareRoot {
        Environment::PrivateMxcsr
    } else {
        Environment::Exact
    };
    let frame = numerical::begin(code, length, &[Output::Z(operand.destination)], environment)?;
    if environment == Environment::PrivateMxcsr {
        code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
        numerical::install_mxcsr(code, &frame);
    }
    let mut failures = Vec::new();
    if features.full_a64() {
        test_ah(code);
        let suppressed = code.asm().jcc(Cond::Ne);
        Host::EqualDword.register(code, ACTIVE, ACTIVE, target);
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        code.asm().bind(suppressed);
    }
    let dynamic = operand.format == Format::Single && features.rpres();
    if dynamic {
        test_ah(code);
        let standard = code.asm().jcc(Cond::E);
        constants(code, operation, operand.format, true, target);
        let mut asm = code.asm();
        let ready = asm.jmp();
        asm.bind(standard);
        constants(code, operation, operand.format, false, target);
        code.asm().bind(ready);
    }
    let element_bytes = operand.format.bits() as usize / u8::BITS as usize;
    for chunk in 0..length.chunks() {
        load_z_chunk(code, source, chunk, SOURCE, length, target);
        for lane in 0..VECTOR_CHUNK_BYTES / element_bytes {
            xmm_to_gpr(code, SOURCE, Rax);
            let mut asm = code.asm();
            match operand.format {
                Format::Half => asm.movzx(Size::Dword, Rax, Size::Word, Rax),
                Format::Single => asm.mov(Size::Dword, Rax, Rax),
                Format::Double => (),
            }
            guard_normal(code, operation, operand.format, &mut failures);
            result_exponent(code, operation, operand.format);
            midpoint(code, operation, operand.format, dynamic);
            estimate(code, operation, operand.format, dynamic, target);
            insert(code, operand.format, lane, checked, target);
            if lane + 1 != VECTOR_CHUNK_BYTES / element_bytes {
                ShiftOpcode::RightBytes.emit(code, SOURCE, element_bytes as u8);
            }
        }
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
