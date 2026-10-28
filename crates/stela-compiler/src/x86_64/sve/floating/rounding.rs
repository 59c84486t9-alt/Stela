//! SVE FRINT*.
use crate::x86_64::asm::Gpr::{R10, Rax, Rcx};
use crate::x86_64::asm::{Alu, Code, Cond, ShiftOp, Size};

use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, INEXACT, features::NumericalFeatures, rounding::RoundingOperation},
        scalable::{ElementSize, VectorLength},
        sve::floating::rounding::Operand,
    },
    x86_64::{
        isa::SimdOpcode as Host,
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::{
            numerical::rounding_control,
            rounding_kernel::{self, RESULT_XMM, SOURCE_XMM},
        },
    },
};
use alloc::vec::Vec;

use super::classify::guard_active_exception_enables;

const CHECKED_CURRENT_DIRECTION_VECTOR_BYTES: usize = 128;
const ACTIVE: u8 = 2;
const PREDICATE_SCRATCH: u8 = 3;
const OLD_DESTINATION: u8 = 4;
const OUTPUT_SLOT: usize = 0;
const INEXACT_SHIFT: u8 = INEXACT.trailing_zeros() as u8;

/// Handle the seven FRINT forms for active single/double lanes that are normal
/// or signed zero; half precision is left to software completion. A late
/// rejection discards the staged result and restores the caller's MXCSR at the
/// instruction.
pub(crate) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let element = match operand.format {
        Format::Single => ElementSize::Word,
        Format::Double => ElementSize::Doubleword,
        Format::Half => return Ok(false),
    };
    if operand.operation.signed_width().is_some() {
        return Ok(false);
    }
    // Current-direction ROUND wins only in these measured SSE4.1 SVL128 tiers.
    // Other widths, forms and lengths retain the mature per-chunk mapping.
    let checked_current_direction = target.supports(TargetCpu::Sse41)
        && length.bytes() == CHECKED_CURRENT_DIRECTION_VECTOR_BYTES
        && matches!(
            (operand.operation, operand.format),
            (RoundingOperation::Current, Format::Single | Format::Double)
                | (RoundingOperation::CurrentExact, Format::Double)
        );
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    if checked_current_direction {
        // Ordinary streaming changes only effective trap enables, so current
        // FRINTI/X RMode is the raw guest field. Install it once per instruction.
        // The frame masks every host exception, clears status and disables flush.
        rounding_control(code);
    } else {
        // The kernels use explicit direction immediates; the ties-away residual
        // arithmetic uses round-to-nearest.
        code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
    }
    numerical::install_mxcsr(code, &frame);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            operand.governing,
            chunk,
            element,
            ACTIVE,
            PREDICATE_SCRATCH,
            length,
            target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, operand.source, chunk, SOURCE_XMM, length, target);
        Host::And.register(code, SOURCE_XMM, ACTIVE, target);
        if checked_current_direction {
            rounding_kernel::emit_checked_current_direction(
                code,
                operand.operation,
                operand.format,
                &mut failures,
                target,
            );
        } else {
            rounding_kernel::emit_chunk(
                code,
                operand.operation,
                operand.format,
                &mut failures,
                target,
            );
        }
        if operand.operation.exact() {
            let mut asm = code.asm();
            asm.mov(Size::Dword, Rax, R10);
            asm.shift_imm(ShiftOp::Shl, Size::Dword, Rax, INEXACT_SHIFT);
            numerical::add_fpsr(code, &frame);
        }
        // Both recipes may destroy the active mask; P and the destination stay
        // intact until the final staged commit.
        read_predicate_mask(
            code,
            operand.governing,
            chunk,
            element,
            ACTIVE,
            PREDICATE_SCRATCH,
            length,
            target,
        );
        load_z_chunk(
            code,
            operand.destination,
            chunk,
            OLD_DESTINATION,
            length,
            target,
        );
        Host::And.register(code, RESULT_XMM, ACTIVE, target);
        Host::AndNot.register(code, ACTIVE, OLD_DESTINATION, target);
        Host::Or.register(code, RESULT_XMM, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT_XMM, target);
    }
    // Admitted finite/zero kernels must raise no host exception, including
    // precision (ROUND suppresses it; ties-away residual arithmetic is exact).
    // A fresh private status value detects any unexpected effect before commit.
    numerical::capture_status(code, &frame);
    code.asm().test(Size::Dword, Rcx, Rcx);
    failures.push(code.asm().jcc(Cond::Ne).offset());
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
