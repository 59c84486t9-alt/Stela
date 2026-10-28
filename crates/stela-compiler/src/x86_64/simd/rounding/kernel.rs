//! Single and double rounding arithmetic shared by the FRINT forms.
use crate::x86_64::asm::Code;

use crate::{
    TargetCpu,
    aarch64::{
        floating::{Format, rounding::RoundingOperation},
        simd::{arithmetic::Shape, rounding::Operand},
    },
    x86_64::isa::SimdOpcode as Host,
};
use alloc::vec::Vec;

pub(in crate::x86_64) const SOURCE_XMM: u8 = super::SOURCE;
pub(in crate::x86_64) const RESULT_XMM: u8 = super::RESULT;
const UNUSED_ARCHITECTURAL_REGISTER: u8 = 0;

/// Round one packed S/D chunk from SOURCE_XMM into RESULT_XMM. The caller owns
/// inactive masking, numerical enable guards, private MXCSR and final commit.
/// Mature source guards admit only normal values/signed zero and append rel32
/// failure displacements for caller cleanup. Current operations read raw RMode.
///
/// Clobbers RAX/RCX/RDX/R8-R11, host flags and XMM0..7. An exact operation
/// produces a fresh fractional-change Boolean in R10D. No guest storage, RSP,
/// callee-saved GPR, frame, control-enable policy or instruction exit is changed.
pub(in crate::x86_64) fn emit_chunk(
    code: &mut Code,
    operation: RoundingOperation,
    format: Format,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    assert!(matches!(format, Format::Single | Format::Double));
    assert!(operation.signed_width().is_none());
    let operand = Operand {
        operation,
        format,
        shape: Shape::Vector128,
        destination: UNUSED_ARCHITECTURAL_REGISTER,
        source: UNUSED_ARCHITECTURAL_REGISTER,
    };
    if target.supports(TargetCpu::Sse41) {
        super::checked_rounding(code, &operand, failures, target);
    } else {
        super::integer_rounding(code, &operand, failures);
    }
}

const ROUND_CURRENT_MXCSR_DIRECTION: u8 = 1 << 2;

/// Round a guarded packed FRINTI/X chunk using caller-installed private MXCSR RC.
/// The whole-instruction caller must first require SSE4.1, install guest RMode,
/// neutralize inactive sources and guard effective active guest trap enables.
/// Reuse the mature source classifier and changed-value IXC calculation exactly;
/// no suppressed host precision status is imported as guest FPSR.
/// Clobbers and architectural commit ownership match `emit_chunk` above.
pub(in crate::x86_64) fn emit_checked_current_direction(
    code: &mut Code,
    operation: RoundingOperation,
    format: Format,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    assert!(target.supports(TargetCpu::Sse41));
    assert!(matches!(
        operation,
        RoundingOperation::Current | RoundingOperation::CurrentExact
    ));
    let opcode = match format {
        Format::Single => Host::RoundPackedSingle,
        Format::Double => Host::RoundPackedDouble,
        Format::Half => unreachable!("checked current-direction requires S/D"),
    };
    let operand = Operand {
        operation,
        format,
        shape: Shape::Vector128,
        destination: UNUSED_ARCHITECTURAL_REGISTER,
        source: UNUSED_ARCHITECTURAL_REGISTER,
    };
    super::checked_source(code, &operand, failures);
    opcode.register(code, RESULT_XMM, SOURCE_XMM, target);
    code.push(ROUND_CURRENT_MXCSR_DIRECTION | super::PRECISION_SUPPRESSED);
    super::checked_inexact(code, &operand);
}
