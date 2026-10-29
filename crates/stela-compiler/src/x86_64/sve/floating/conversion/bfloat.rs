//! SVE BFCVT and BFCVTNT through integer rounding.
use crate::x86_64::asm::Gpr::Rax;
use crate::x86_64::asm::{Code, Cond, Rm, Size};
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, bfloat16::BFLOAT16_TO_SINGLE_SHIFT, features::NumericalFeatures},
        scalable::{ElementSize, VectorLength},
        sve::floating::conversion::{Kind, Operand},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::bfloat16::{
            conversion_inexact, guard_conversion_enables, prepare_conversion_rounding,
            quantize_normal_conversion,
        },
    },
};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const SOURCE: u8 = 1;
const ACTIVE: u8 = 6;
const TEMPORARY: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const REPEAT_LOW_DWORD: u8 = 0;
const BFLOAT_SHIFT: u8 = BFLOAT16_TO_SINGLE_SHIFT as u8;
const SINGLE_ONE: u32 = Format::Single.exponent_bias() << Format::Single.fraction_bits();

fn guard_enables(
    code: &mut Code,
    features: NumericalFeatures,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    if !features.full_a64() {
        return;
    }
    let mut asm = code.asm();
    asm.simd_to_gpr(Host::ByteSignMask, Rax, ACTIVE, target);
    asm.test(Size::Dword, Rax, Rax);
    let inactive = asm.jcc(Cond::E);
    // Unlike precision conversion, BF AH1 suppresses numerical exceptions and
    // enables. Reuse the mature BF policy after the active-lane test.
    guard_conversion_enables(code, failures);
    code.asm().bind(inactive);
}

pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Kind::Bfloat16 { upper } = operand.kind else {
        return Ok(false);
    };
    // No host FP executes. The shared private header accumulates guest FPSR;
    // caller MXCSR is saved/restored exactly without installing another control.
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    prepare_conversion_rounding(code);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            operand.governing,
            chunk,
            ElementSize::Word,
            crate::x86_64::scalable::MaskRegisters::new(ACTIVE, TEMPORARY),
            length,
            target,
        );
        guard_enables(code, features, &mut failures, target);
        load_z_chunk(code, operand.source, chunk, SOURCE, length, target);
        Host::And.register(code, SOURCE, ACTIVE, target);
        // Neutralize inactive poison to exactly BF16 1.0 before normal guards.
        let mut asm = code.asm();
        asm.mov_imm32(Rax, SINGLE_ONE);
        asm.movd_to_xmm(0, Rax);
        code.asm().simd_imm(
            Host::ShuffleDword,
            RESULT,
            Rm::Xmm(RESULT),
            REPEAT_LOW_DWORD,
            target,
        );
        Host::MoveAligned.register(code, TEMPORARY, ACTIVE, target);
        Host::AndNot.register(code, TEMPORARY, RESULT, target);
        Host::Or.register(code, SOURCE, TEMPORARY, target);
        quantize_normal_conversion(code, &mut failures);
        // Record the discarded-bit status before another state-access helper
        // runs.
        conversion_inexact(code);
        numerical::add_fpsr(code, &frame);
        ShiftOpcode::RightDword.emit(code, RESULT, BFLOAT_SHIFT);
        Host::And.register(code, RESULT, ACTIVE, target);
        if upper {
            ShiftOpcode::LeftDword.emit(code, RESULT, BFLOAT_SHIFT);
            ShiftOpcode::LeftDword.emit(code, ACTIVE, BFLOAT_SHIFT);
        }
        load_z_chunk(code, operand.destination, chunk, TEMPORARY, length, target);
        Host::AndNot.register(code, ACTIVE, TEMPORARY, target);
        Host::Or.register(code, RESULT, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
