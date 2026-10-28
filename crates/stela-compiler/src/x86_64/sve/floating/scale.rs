//! SVE FSCALE on normal values through packed integer exponent arithmetic.
use crate::x86_64::asm::Gpr::Rax;
use crate::x86_64::asm::{Code, Cond, Rm, Size};
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures},
        scalable::{ElementSize, VectorLength},
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape, Source},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        sve::floating::classify::guard_active_exception_enables,
    },
};
use alloc::vec::Vec;

const VALUE: u8 = 0;
const SCALE: u8 = 1;
const VALID: u8 = 2;
const EXPONENT: u8 = 3;
const TEMPORARY: u8 = 4;
const MAXIMUM_EXPONENT: u8 = 5;
const ACTIVE: u8 = 6;
const OUTPUT_SLOT: usize = 0;
const REPEAT_LOW_DWORD: u8 = 0;

fn packed(
    code: &mut Code,
    format: Format,
    single: Host,
    double: Host,
    destination: u8,
    source: u8,
    target: TargetCpu,
) {
    match format {
        Format::Single => single,
        Format::Double => double,
        Format::Half => unreachable!("validated packed field format"),
    }
    .register(code, destination, source, target);
}

fn reject_invalid_active(code: &mut Code, failures: &mut Vec<usize>, target: TargetCpu) {
    Host::AndNot.register(code, VALID, ACTIVE, target);
    code.asm()
        .simd_to_gpr(Host::ByteSignMask, Rax, VALID, target);
    code.asm().test(Size::Dword, Rax, Rax);
    failures.push(code.asm().jcc(Cond::Ne).offset());
}

fn guard_normal_exponent(
    code: &mut Code,
    format: Format,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    Host::MoveAligned.register(code, VALID, EXPONENT, target);
    Host::Xor.register(code, TEMPORARY, TEMPORARY, target);
    packed(
        code,
        format,
        Host::GreaterDword,
        Host::GreaterQword,
        VALID,
        TEMPORARY,
        target,
    );
    Host::MoveAligned.register(code, TEMPORARY, MAXIMUM_EXPONENT, target);
    packed(
        code,
        format,
        Host::GreaterDword,
        Host::GreaterQword,
        TEMPORARY,
        EXPONENT,
        target,
    );
    Host::And.register(code, VALID, TEMPORARY, target);
    reject_invalid_active(code, failures, target);
}

fn guard_bounded_scale(
    code: &mut Code,
    format: Format,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    Host::MoveAligned.register(code, VALID, SCALE, target);
    Host::MoveAligned.register(code, TEMPORARY, MAXIMUM_EXPONENT, target);
    packed(
        code,
        format,
        Host::GreaterDword,
        Host::GreaterQword,
        TEMPORARY,
        VALID,
        target,
    );
    Host::Xor.register(code, EXPONENT, EXPONENT, target);
    packed(
        code,
        format,
        Host::SubDword,
        Host::SubQword,
        EXPONENT,
        MAXIMUM_EXPONENT,
        target,
    );
    packed(
        code,
        format,
        Host::GreaterDword,
        Host::GreaterQword,
        VALID,
        EXPONENT,
        target,
    );
    Host::And.register(code, VALID, TEMPORARY, target);
    reject_invalid_active(code, failures, target);
}

fn broadcast_maximum(code: &mut Code, format: Format, target: TargetCpu) {
    let maximum = format.exponent_mask() >> format.fraction_bits();
    if format == Format::Single {
        code.asm().mov_imm32(Rax, maximum as u32);
    } else {
        code.asm().mov_imm64(Rax, maximum);
    }
    code.asm()
        .simd(Host::MoveGprQword, MAXIMUM_EXPONENT, Rax, target);
    if format == Format::Single {
        code.asm().simd_imm(
            Host::ShuffleDword,
            MAXIMUM_EXPONENT,
            Rm::Xmm(MAXIMUM_EXPONENT),
            REPEAT_LOW_DWORD,
            target,
        );
    } else {
        Host::UnpackLowQword.register(code, MAXIMUM_EXPONENT, MAXIMUM_EXPONENT, target);
    }
}

/// Signed scale is the complete architectural lane, not an unsigned cast or
/// truncated low field. Any normal-to-normal result requires |scale| < maxexp;
/// this guard bounds addition before adding, including signed integer extrema.
/// Every accepted value changes only its exponent field, preserving sign and
/// fraction exactly, independent of all FPCR rounding/flush/AH controls.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let element = match operand.format {
        Format::Single => ElementSize::Word,
        Format::Double if target.supports(TargetCpu::Sse42) => ElementSize::Doubleword,
        Format::Double | Format::Half => return Ok(false),
    };
    if operand.kind != Kind::Scale || operand.shape != ResultShape::Vector {
        return Ok(false);
    }
    let (
        Inputs::Binary {
            left: Source::Vector(left),
            right: Source::Vector(right),
        },
        Some(predicate),
    ) = (operand.inputs, operand.predicate)
    else {
        return Ok(false);
    };
    if left != operand.destination {
        return Ok(false);
    }
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::Exact,
    )?;
    broadcast_maximum(code, operand.format, target);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            predicate,
            chunk,
            element,
            crate::x86_64::scalable::MaskRegisters::new(ACTIVE, VALID),
            length,
            target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, left, chunk, VALUE, length, target);
        load_z_chunk(code, right, chunk, SCALE, length, target);
        // Integer guards and field updates are safe for neutralized inactive lanes.
        Host::And.register(code, VALUE, ACTIVE, target);
        Host::And.register(code, SCALE, ACTIVE, target);
        guard_bounded_scale(code, operand.format, &mut failures, target);
        Host::MoveAligned.register(code, EXPONENT, VALUE, target);
        match operand.format {
            Format::Single => ShiftOpcode::RightDword,
            Format::Double => ShiftOpcode::RightQword,
            Format::Half => unreachable!("validated packed field format"),
        }
        .emit(code, EXPONENT, operand.format.fraction_bits() as u8);
        Host::And.register(code, EXPONENT, MAXIMUM_EXPONENT, target);
        guard_normal_exponent(code, operand.format, &mut failures, target);
        packed(
            code,
            operand.format,
            Host::AddDword,
            Host::AddQword,
            EXPONENT,
            SCALE,
            target,
        );
        guard_normal_exponent(code, operand.format, &mut failures, target);
        match operand.format {
            Format::Single => ShiftOpcode::LeftDword,
            Format::Double => ShiftOpcode::LeftQword,
            Format::Half => unreachable!("validated packed field format"),
        }
        .emit(code, SCALE, operand.format.fraction_bits() as u8);
        packed(
            code,
            operand.format,
            Host::AddDword,
            Host::AddQword,
            VALUE,
            SCALE,
            target,
        );
        load_z_chunk(code, operand.destination, chunk, TEMPORARY, length, target);
        Host::And.register(code, VALUE, ACTIVE, target);
        Host::AndNot.register(code, ACTIVE, TEMPORARY, target);
        Host::Or.register(code, VALUE, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, VALUE, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
