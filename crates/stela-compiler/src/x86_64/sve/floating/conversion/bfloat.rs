//! SVE BFCVT and BFCVTNT through integer rounding.
use crate::x86_64::asm::Code;
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
const GPR_RAX: u8 = 0;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const MOV_EAX_IMMEDIATE: u8 = 0xb8;
const MOVD_XMM0_EAX: &[u8] = &[0x66, 0x0f, 0x6e, 0xc0];
const TEST_EAX_EAX: &[u8] = &[0x85, 0xc0];
const JZ_REL32: &[u8] = &[0x0f, 0x84];
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
    Host::ByteSignMask.append(code, target);
    code.push(MODRM_REGISTER | (GPR_RAX << MODRM_REGISTER_SHIFT) | ACTIVE);
    code.extend(TEST_EAX_EAX);
    code.extend(JZ_REL32);
    let inactive = code.len();
    code.extend(0_i32.to_le_bytes());
    // Unlike precision conversion, BF AH1 suppresses numerical exceptions and
    // retained enables. Reuse the mature BF policy after the active-lane test.
    guard_conversion_enables(code, failures);
    let next = inactive + size_of::<i32>();
    let relative = i32::try_from(code.len() - next).expect("bounded BF enable guard");
    code[inactive..next].copy_from_slice(&relative.to_le_bytes());
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
            ACTIVE,
            TEMPORARY,
            length,
            target,
        );
        guard_enables(code, features, &mut failures, target);
        load_z_chunk(code, operand.source, chunk, SOURCE, length, target);
        Host::And.register(code, SOURCE, ACTIVE, target);
        // Neutralize inactive poison to exactly BF16 1.0 before normal guards.
        code.push(MOV_EAX_IMMEDIATE);
        code.extend(SINGLE_ONE.to_le_bytes());
        code.extend(MOVD_XMM0_EAX);
        Host::ShuffleDword.register(code, RESULT, RESULT, target);
        code.push(REPEAT_LOW_DWORD);
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
