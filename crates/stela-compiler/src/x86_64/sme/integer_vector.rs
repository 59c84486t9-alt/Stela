//! SME2 multi-vector integer arithmetic on the shared SVE kernels.
use crate::x86_64::asm::Code;
use crate::x86_64::simd::encode::stack;
use crate::{
    TargetCpu,
    aarch64::{
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sme::integer_vector::{Arithmetic, ArithmeticKind, Group, Narrow, Operand, Signedness},
        sve::{
            integer_arithmetic::Binary, integer_products::Kind as ProductKind,
            shifts_narrow::Kind as NarrowKind,
        },
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{load_z_chunk, store_z_chunk},
        sve::{
            integer_arithmetic::emit_binary_chunk,
            integer_products::emit_saturating_chunk,
            shifts::rounding_variable_chunk,
            shifts_narrow::{narrow_chunk, narrow_packed_chunk},
        },
    },
};

const RESULT: u8 = 0;
const RIGHT: u8 = 1;
const SAVED: u8 = 7;

fn packed(code: &mut Code, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn copy(code: &mut Code, destination: u8, source: u8) {
    packed(code, Host::MoveAligned, destination, source);
}

fn stack_space(code: &mut Code, bytes: usize, reserve: bool) {
    if reserve {
        code.asm().reserve_stack(bytes);
    } else {
        code.asm().release_stack(bytes);
    }
}

fn stack_chunk(code: &mut Code, register: u8, offset: usize, store: bool, target: TargetCpu) {
    if store {
        Host::StoreUnaligned
    } else {
        Host::LoadUnaligned
    }
    .emit(code, register, stack(offset), target);
}

/// Shift the RESULT chunk left by `bytes`.
fn byte_shift(code: &mut Code, bytes: usize) {
    if bytes != 0 {
        ShiftOpcode::LeftBytes.emit(code, RESULT, bytes as u8);
    }
}

fn unsigned(signedness: Signedness) -> bool {
    signedness == Signedness::Unsigned
}

/// RDI/R15 preserve the shared entry context; all kernels preserve XMM7.
/// Access/profile checks are performed before entering this emitter.
pub(crate) fn emit(code: &mut Code, operand: &Operand, length: VectorLength, target: TargetCpu) {
    match operand {
        Operand::Arithmetic(operand) => {
            arithmetic(code, operand, length, target);
        }
        Operand::Narrow(operand) => narrow(code, operand, length, target),
    }
}

fn arithmetic(code: &mut Code, operand: &Arithmetic, length: VectorLength, target: TargetCpu) {
    let clamp = matches!(operand.kind, ArithmeticKind::Clamp(_));
    if clamp {
        stack_space(code, VECTOR_CHUNK_BYTES, true);
    }
    for chunk in 0..length.chunks() {
        // A single right register may alias any destination in the group.
        // Snapshot the shared right/lower chunk before the first destination.
        if !operand.right_grouped {
            load_z_chunk(code, operand.right, chunk, SAVED, length, target);
        }
        if let Some(lower) = operand.lower {
            load_z_chunk(code, lower, chunk, RIGHT, length, target);
            stack_chunk(code, RIGHT, 0, true, target);
        }
        for register in 0..operand.group.count() {
            load_z_chunk(
                code,
                operand.destination + register,
                chunk,
                RESULT,
                length,
                target,
            );
            if operand.right_grouped {
                load_z_chunk(code, operand.right + register, chunk, RIGHT, length, target);
            } else {
                copy(code, RIGHT, SAVED);
            }
            match operand.kind {
                ArithmeticKind::Add => {
                    emit_binary_chunk(code, Binary::Add, operand.element, target)
                }
                ArithmeticKind::Minimum(signedness) => emit_binary_chunk(
                    code,
                    Binary::Minimum {
                        unsigned: unsigned(signedness),
                    },
                    operand.element,
                    target,
                ),
                ArithmeticKind::Maximum(signedness) => emit_binary_chunk(
                    code,
                    Binary::Maximum {
                        unsigned: unsigned(signedness),
                    },
                    operand.element,
                    target,
                ),
                ArithmeticKind::Clamp(signedness) => {
                    stack_chunk(code, RIGHT, 0, false, target);
                    emit_binary_chunk(
                        code,
                        Binary::Maximum {
                            unsigned: unsigned(signedness),
                        },
                        operand.element,
                        target,
                    );
                    copy(code, RIGHT, SAVED);
                    emit_binary_chunk(
                        code,
                        Binary::Minimum {
                            unsigned: unsigned(signedness),
                        },
                        operand.element,
                        target,
                    );
                }
                ArithmeticKind::RoundingShift(signedness) => {
                    rounding_variable_chunk(code, operand.element, !unsigned(signedness))
                }
                ArithmeticKind::SaturatingDoublingMultiplyHigh => emit_saturating_chunk(
                    code,
                    ProductKind::DoublingHigh { rounding: false },
                    operand.element,
                ),
            }
            store_z_chunk(
                code,
                operand.destination + register,
                chunk,
                RESULT,
                length,
                target,
            );
        }
    }
    if clamp {
        stack_space(code, VECTOR_CHUNK_BYTES, false);
    }
}

fn narrow_kind(source: Signedness, destination: Signedness, rounded: bool) -> NarrowKind {
    match (source, destination, rounded) {
        (Signedness::Signed, Signedness::Signed, false) => NarrowKind::SaturatingExtractSigned,
        (Signedness::Signed, Signedness::Unsigned, false) => {
            NarrowKind::SaturatingExtractSignedToUnsigned
        }
        (Signedness::Unsigned, Signedness::Unsigned, false) => {
            NarrowKind::SaturatingExtractUnsigned
        }
        (Signedness::Signed, Signedness::Signed, true) => NarrowKind::SaturatingRoundRightSigned,
        (Signedness::Signed, Signedness::Unsigned, true) => {
            NarrowKind::SaturatingRoundRightSignedToUnsigned
        }
        (Signedness::Unsigned, Signedness::Unsigned, true) => {
            NarrowKind::SaturatingRoundRightUnsigned
        }
        (Signedness::Unsigned, Signedness::Signed, _) => {
            unreachable!("no unsigned-to-signed narrowing allocation")
        }
    }
}

fn narrow_source_chunk(code: &mut Code, operand: &Narrow, target: TargetCpu) {
    let intermediate = ElementSize::from_bytes(operand.source_element.bytes() / 2).unwrap();
    let project = if operand.interleaved {
        narrow_chunk
    } else {
        narrow_packed_chunk
    };
    project(
        code,
        narrow_kind(
            operand.source_signedness,
            operand.destination_signedness,
            operand.shift != 0,
        ),
        intermediate,
        operand.shift,
        target,
    );
    if operand.group == Group::Quartet {
        project(
            code,
            narrow_kind(
                operand.destination_signedness,
                operand.destination_signedness,
                false,
            ),
            operand.destination_element,
            0,
            target,
        );
    }
}

fn narrow(code: &mut Code, operand: &Narrow, length: VectorLength, target: TargetCpu) {
    let register_count = usize::from(operand.group.count());
    let aliases =
        (operand.source..operand.source + operand.group.count()).contains(&operand.destination);
    let save_source = !operand.interleaved
        && aliases
        && usize::from(operand.destination - operand.source) * length.chunks() >= register_count;
    if save_source {
        // Source chunk j is consumed at output floor((alias_index * chunks+j)
        // / group). Forward writes are safe without a snapshot exactly when
        // alias_index * chunks < group. Other register_count are never overwritten.
        stack_space(code, length.bytes(), true);
        for chunk in 0..length.chunks() {
            load_z_chunk(code, operand.destination, chunk, RESULT, length, target);
            stack_chunk(code, RESULT, chunk * VECTOR_CHUNK_BYTES, true, target);
        }
    }
    for chunk in 0..length.chunks() {
        packed(code, Host::Xor, SAVED, SAVED);
        for piece in 0..register_count {
            let (source, input_chunk) = if operand.interleaved {
                (operand.source + piece as u8, chunk)
            } else {
                let index = chunk * register_count + piece;
                (
                    operand.source + (index / length.chunks()) as u8,
                    index % length.chunks(),
                )
            };
            if save_source && source == operand.destination {
                stack_chunk(
                    code,
                    RESULT,
                    input_chunk * VECTOR_CHUNK_BYTES,
                    false,
                    target,
                );
            } else {
                load_z_chunk(code, source, input_chunk, RESULT, length, target);
            }
            narrow_source_chunk(code, operand, target);
            if operand.interleaved {
                byte_shift(code, piece * operand.destination_element.bytes());
            } else {
                byte_shift(code, piece * (VECTOR_CHUNK_BYTES / register_count));
            }
            packed(code, Host::Or, SAVED, RESULT);
        }
        store_z_chunk(code, operand.destination, chunk, SAVED, length, target);
    }
    if save_source {
        stack_space(code, length.bytes(), false);
    }
}
