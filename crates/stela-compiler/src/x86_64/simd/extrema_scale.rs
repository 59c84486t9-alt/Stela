//! Baseline SSE2 absolute extrema and exact normal-result exponent scaling.
//!
//! The integer FSCALE path admits H/S/D normal inputs and normal outputs. It
//! changes only exponent bits, performs no host FP operation and raises no
//! status. Other inputs retain complete transactional numerical completion.
use crate::{
    GuestAddress, TargetCpu,
    aarch64::{
        floating::{FPCR_EXCEPTION_ENABLE_MASK, absolute_minmax::AbsoluteMinMaxOperation},
        simd::{
            arithmetic::Shape,
            extrema_scale::{Kind, Operand},
        },
    },
    block::ExitKind,
};

use super::{
    commit,
    numerical::{Condition, MOVQ_XMM0_XMM0, branch, read_numerical_vector, resolve, test_control},
};

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const SCRATCH: [u8; 4] = [2, 3, 4, 5];

pub(super) fn always_exits(_operand: &Operand) -> bool {
    false
}

fn absolute(
    code: &mut Vec<u8>,
    operand: &Operand,
    operation: AbsoluteMinMaxOperation,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    super::absolute_selection::guard_and_magnitudes(
        code,
        operand.format,
        LEFT,
        RIGHT,
        SCRATCH,
        failures,
        target,
    );
    super::absolute_selection::emit(
        code,
        operand.format,
        operation,
        LEFT,
        RIGHT,
        SCRATCH,
        target,
    );
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress, target: TargetCpu) {
    let mut failures = Vec::new();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    failures.push(branch(code, Condition::NotZero));
    read_numerical_vector(code, operand.shape, operand.left, LEFT);
    read_numerical_vector(code, operand.shape, operand.right, RIGHT);
    match operand.kind {
        Kind::Absolute(operation) => absolute(code, operand, operation, &mut failures, target),
        Kind::Scale => {
            super::exponent_scale::emit(code, operand.format, operand.shape, &mut failures, target)
        }
    }
    if operand.shape == Shape::Vector64 {
        code.extend(MOVQ_XMM0_XMM0);
    }
    commit(code, operand.destination, LEFT);
    code.push(0xe9); // JMP rel32 skips the cold numerical exit.
    let success = code.len();
    code.extend([0; size_of::<i32>()]);
    let fallback = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let end = code.len();
    for failure in failures {
        resolve(code, failure, fallback);
    }
    resolve(code, success, end);
}
