//! SVE single-to-double widening.
use crate::x86_64::asm::Code;

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures, precision::PrecisionRounding},
        scalable::{ElementSize, VectorLength},
        sve::floating::conversion::{Kind, Operand, Placement},
    },
    x86_64::{
        isa::SimdOpcode,
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        sve::floating::classify::{
            guard_active_exception_enables, guard_normal_zero_or_infinity, prepare_classification,
        },
    },
};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const ACTIVE: u8 = 1;
const PREDICATE_SCRATCH: u8 = 2;
const OLD_DESTINATION: u8 = 3;
const CLASSIFICATION_SCRATCH: [u8; 3] = [PREDICATE_SCRATCH, 4, 5];
const CLASSIFICATION_CONSTANTS: [u8; 2] = [6, 7];
const OUTPUT_SLOT: usize = 0;
const DWORD_SELECTOR_BITS: u8 = 2;
const LOW_SINGLE: u8 = 0;
const HIGH_SINGLE: u8 = 1;
const NEXT_QWORD_SINGLE: u8 = 2;
const CVTPS2PD_XMM0_XMM0: &[u8] = &[0x0f, 0x5a, 0xc0];

/// Compact the selected Single from each qword into the low two dwords.
/// Duplicating them above those dwords lets the shared classifier check all
/// four without admitting an unselected source half.
const fn source_shuffle(placement: Placement) -> u8 {
    let first = match placement {
        Placement::Low => LOW_SINGLE,
        Placement::UpperSource => HIGH_SINGLE,
        Placement::UpperDestination => unreachable!(),
    };
    let second = first + NEXT_QWORD_SINGLE;
    first
        | (second << DWORD_SELECTOR_BITS)
        | (first << (2 * DWORD_SELECTOR_BITS))
        | (second << (3 * DWORD_SELECTOR_BITS))
}

/// Emit only the exact Single-to-Double forms. Other conversions leave `code`
/// untouched for their normal numerical completion path. The caller owns
/// instruction availability and the streaming-mode entry guard.
pub(crate) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Kind::Precision {
        source: Format::Single,
        destination: Format::Double,
        rounding: PrecisionRounding::Fpcr,
        placement: placement @ (Placement::Low | Placement::UpperSource),
    } = operand.kind
    else {
        return Ok(false);
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::Exact,
    )?;
    let classification =
        prepare_classification(code, Format::Single, CLASSIFICATION_CONSTANTS, target);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            operand.governing,
            chunk,
            ElementSize::Doubleword,
            ACTIVE,
            PREDICATE_SCRATCH,
            length,
            target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, operand.source, chunk, RESULT, length, target);
        // Replace every inactive input with +0 before any host FP operation.
        // The shuffle also discards the unselected half of each source slot.
        SimdOpcode::And.register(code, RESULT, ACTIVE, target);
        SimdOpcode::ShuffleDword.register(code, RESULT, RESULT, target);
        code.push(source_shuffle(placement));
        guard_normal_zero_or_infinity(
            code,
            classification,
            RESULT,
            CLASSIFICATION_SCRATCH,
            &mut failures,
            target,
        );
        // Normals, signed zeros and infinities widen exactly under every
        // caller RC/DAZ/FTZ/mask setting, without changing MXCSR or FPSR.
        code.extend(CVTPS2PD_XMM0_XMM0);
        load_z_chunk(
            code,
            operand.destination,
            chunk,
            OLD_DESTINATION,
            length,
            target,
        );
        // Converted inactive lanes are already all-zero, so no second mask
        // of RESULT is needed. Both active and inactive full slots are staged.
        SimdOpcode::AndNot.register(code, ACTIVE, OLD_DESTINATION, target);
        SimdOpcode::Or.register(code, RESULT, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
