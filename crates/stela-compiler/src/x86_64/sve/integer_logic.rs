//! Fixed-SVL SSE2 Boolean/copy mappings over shared scalable-state accessors.
use crate::TargetCpu;
use crate::aarch64::scalable::{ElementSize, Predication, VECTOR_CHUNK_BYTES, VectorLength};
use crate::aarch64::sve::integer_logic::{Boolean, CopySource, Kind, Operand, Ternary};
use crate::x86_64::isa::{ShiftOpcode, SimdOpcode as Host};
use crate::x86_64::scalable::{load_z_chunk, read_predicate_mask, store_z_chunk};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const RIGHT: u8 = 1;
const THIRD: u8 = 2;
const TEMPORARY: u8 = 3;
const CONSTANT: u8 = 4;
const PREDICATE: u8 = 5;
const PREDICATE_SCRATCH: u8 = 6;
const PREVIOUS: u8 = 7;
const MOVABS_RAX: [u8; 2] = [0x48, 0xb8];
const MODRM_REGISTER: u8 = 0xc0;
const QWORD_BYTES: usize = 8;
const BITS_PER_BYTE: usize = 8;
const ADJACENT_DWORD_SWAP: u8 = 0xb1;
const BROADCAST_LOW_DWORD: u8 = 0;

fn packed(code: &mut Vec<u8>, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn constant(code: &mut Vec<u8>, value: u64) {
    code.extend(MOVABS_RAX);
    code.extend(value.to_le_bytes());
    Host::MoveGprQword.append(code, TargetCpu::Baseline);
    code.push(MODRM_REGISTER | (CONSTANT << 3));
    packed(code, Host::UnpackLowQword, CONSTANT, CONSTANT);
}

fn repeat_qword(value: u64, element: ElementSize) -> u64 {
    let bits = element.bits();
    if element == ElementSize::Doubleword {
        return value;
    }
    let value = value & ((1u64 << bits) - 1);
    (0..QWORD_BYTES / element.bytes()).fold(0, |result, lane| result | (value << (lane * bits)))
}

fn broadcast_scalar(code: &mut Vec<u8>, element: ElementSize) {
    if element == ElementSize::Byte {
        packed(code, Host::UnpackLowByte, CONSTANT, CONSTANT);
    }
    if matches!(element, ElementSize::Byte | ElementSize::Halfword) {
        packed(code, Host::UnpackLowWord, CONSTANT, CONSTANT);
    }
    if element == ElementSize::Doubleword {
        packed(code, Host::UnpackLowQword, CONSTANT, CONSTANT);
    } else {
        packed(code, Host::ShuffleDword, CONSTANT, CONSTANT);
        code.push(BROADCAST_LOW_DWORD);
    }
}

/// Inputs XMM0/XMM1 are snapshotted source chunks. Produces XMM0 and may
/// consume XMM1; RDI/R15 and guest architectural status are untouched.
pub fn emit_binary_chunk(code: &mut Vec<u8>, operation: Boolean) {
    match operation {
        Boolean::And => packed(code, Host::And, RESULT, RIGHT),
        Boolean::Or => packed(code, Host::Or, RESULT, RIGHT),
        Boolean::Xor => packed(code, Host::Xor, RESULT, RIGHT),
        Boolean::BitClear => {
            packed(code, Host::AndNot, RIGHT, RESULT);
            packed(code, Host::MoveAligned, RESULT, RIGHT);
        }
    }
}

/// XMM0 is the old destructive destination, XMM1 the right operand, XMM2
/// the mask/third source. All three must be staged before entering.
pub fn emit_ternary_chunk(code: &mut Vec<u8>, operation: Ternary) {
    match operation {
        Ternary::BitClearXor => {
            packed(code, Host::AndNot, THIRD, RIGHT);
            packed(code, Host::Xor, RESULT, THIRD);
        }
        Ternary::Xor => {
            packed(code, Host::Xor, RESULT, RIGHT);
            packed(code, Host::Xor, RESULT, THIRD);
        }
        Ternary::Select | Ternary::SelectNotResult => {
            packed(code, Host::And, RESULT, THIRD);
            packed(code, Host::AndNot, THIRD, RIGHT);
            packed(code, Host::Or, RESULT, THIRD);
        }
        Ternary::SelectNotFirst | Ternary::SelectNotSecond => {
            packed(code, Host::AndNot, RESULT, THIRD);
            packed(code, Host::AndNot, THIRD, RIGHT);
            packed(code, Host::Or, RESULT, THIRD);
        }
    }
    if matches!(
        operation,
        Ternary::SelectNotResult | Ternary::SelectNotSecond
    ) {
        packed(code, Host::EqualDword, TEMPORARY, TEMPORARY);
        packed(code, Host::Xor, RESULT, TEMPORARY);
    }
}

fn emit_unary_chunk(code: &mut Vec<u8>, conditional: bool, element: ElementSize) {
    if !conditional {
        packed(code, Host::EqualDword, RIGHT, RIGHT);
        packed(code, Host::Xor, RESULT, RIGHT);
        return;
    }
    packed(code, Host::Xor, RIGHT, RIGHT);
    packed(
        code,
        match element {
            ElementSize::Byte => Host::EqualByte,
            ElementSize::Halfword => Host::EqualWord,
            ElementSize::Word | ElementSize::Doubleword => Host::EqualDword,
            ElementSize::Quadword => unreachable!("integer Boolean decoder excludes quadwords"),
        },
        RESULT,
        RIGHT,
    );
    if element == ElementSize::Doubleword {
        packed(code, Host::ShuffleDword, THIRD, RESULT);
        code.push(ADJACENT_DWORD_SWAP);
        packed(code, Host::And, RESULT, THIRD);
    }
    packed(code, Host::And, RESULT, CONSTANT);
}

fn merge(code: &mut Vec<u8>, predication: Predication) {
    packed(code, Host::And, RESULT, PREDICATE);
    if matches!(predication, Predication::Merging(_)) {
        packed(code, Host::AndNot, PREDICATE, PREVIOUS);
        packed(code, Host::Or, RESULT, PREDICATE);
    }
}

/// Emits the complete ordinary data effects for one validated instruction.
/// The shared lifter owns mode/feature and MOVPRFX pairing outcomes. This family
/// has no RAM accesses or guest flag changes. Per-chunk source staging is enough
/// because its only cross-lane accesses remain within one 128-bit chunk; scalar
/// sources are broadcast once before an aliased low-V destination can change.
pub fn emit(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    match operand.kind {
        Kind::Immediate { value, .. } => constant(code, value),
        Kind::Copy(CopySource::Immediate(value)) => {
            constant(code, repeat_qword(value as u64, operand.element_size));
        }
        Kind::Copy(CopySource::General(register)) => {
            crate::x86_64::load(code, register);
            Host::MoveGprQword.append(code, TargetCpu::Baseline);
            code.push(MODRM_REGISTER | (CONSTANT << 3));
            broadcast_scalar(code, operand.element_size);
        }
        Kind::Copy(CopySource::ScalarVector(register)) => {
            load_z_chunk(code, register, 0, CONSTANT, length, target);
            broadcast_scalar(code, operand.element_size);
        }
        Kind::Unary {
            conditional: true, ..
        } => {
            constant(code, repeat_qword(1, operand.element_size));
        }
        Kind::CrossXor { .. } => {
            let lane_bits = operand.element_size.bits();
            let selected = (1u128 << lane_bits) - 1;
            let mut mask = 0u128;
            for offset in (0..VECTOR_CHUNK_BYTES * BITS_PER_BYTE).step_by(lane_bits * 2) {
                mask |= selected << offset;
            }
            constant(code, mask as u64);
            // For 64-bit elements the selected mask is only the low qword.
            if operand.element_size == ElementSize::Doubleword {
                ShiftOpcode::RightBytes.emit(code, CONSTANT, QWORD_BYTES as u8);
            }
        }
        _ => {}
    }
    for chunk in 0..length.chunks() {
        let previous_required = matches!(
            operand.kind,
            Kind::Immediate { .. } | Kind::Ternary { .. } | Kind::CrossXor { .. }
        ) || (matches!(operand.predication, Predication::Merging(_))
            && !matches!(operand.kind, Kind::Select { .. }));
        if previous_required {
            load_z_chunk(code, operand.destination, chunk, PREVIOUS, length, target);
        }
        match operand.kind {
            Kind::Binary {
                operation,
                left,
                right,
            } => {
                if left == operand.destination && previous_required {
                    packed(code, Host::MoveAligned, RESULT, PREVIOUS);
                } else {
                    load_z_chunk(code, left, chunk, RESULT, length, target);
                }
                load_z_chunk(code, right, chunk, RIGHT, length, target);
                emit_binary_chunk(code, operation);
            }
            Kind::Immediate { operation, .. } => {
                packed(code, Host::MoveAligned, RESULT, PREVIOUS);
                packed(code, Host::MoveAligned, RIGHT, CONSTANT);
                emit_binary_chunk(code, operation);
            }
            Kind::Unary {
                source,
                conditional,
            } => {
                load_z_chunk(code, source, chunk, RESULT, length, target);
                emit_unary_chunk(code, conditional, operand.element_size);
            }
            Kind::Ternary {
                operation,
                right,
                mask,
            } => {
                packed(code, Host::MoveAligned, RESULT, PREVIOUS);
                load_z_chunk(code, right, chunk, RIGHT, length, target);
                load_z_chunk(code, mask, chunk, THIRD, length, target);
                emit_ternary_chunk(code, operation);
            }
            Kind::CrossXor { left, right, top } => {
                load_z_chunk(code, left, chunk, RESULT, length, target);
                load_z_chunk(code, right, chunk, RIGHT, length, target);
                let bytes = operand.element_size.bytes() as u8;
                if top {
                    ShiftOpcode::LeftBytes.emit(code, RIGHT, bytes);
                } else {
                    ShiftOpcode::RightBytes.emit(code, RIGHT, bytes);
                }
                packed(code, Host::Xor, RESULT, RIGHT);
                if top {
                    packed(code, Host::MoveAligned, RIGHT, CONSTANT);
                    packed(code, Host::AndNot, RIGHT, RESULT);
                    packed(code, Host::And, PREVIOUS, CONSTANT);
                } else {
                    packed(code, Host::And, RESULT, CONSTANT);
                    packed(code, Host::MoveAligned, RIGHT, CONSTANT);
                    packed(code, Host::AndNot, RIGHT, PREVIOUS);
                }
                if top {
                    packed(code, Host::MoveAligned, RESULT, RIGHT);
                    packed(code, Host::Or, RESULT, PREVIOUS);
                } else {
                    packed(code, Host::Or, RESULT, RIGHT);
                }
            }
            Kind::Copy(CopySource::Vector(source)) => {
                load_z_chunk(code, source, chunk, RESULT, length, target);
            }
            Kind::Copy(_) => packed(code, Host::MoveAligned, RESULT, CONSTANT),
            Kind::Select { left, right } => {
                load_z_chunk(code, left, chunk, RESULT, length, target);
                load_z_chunk(code, right, chunk, PREVIOUS, length, target);
            }
        }
        if let Predication::Merging(predicate) | Predication::Zeroing(predicate) =
            operand.predication
        {
            read_predicate_mask(
                code,
                predicate,
                chunk,
                operand.element_size,
                PREDICATE,
                PREDICATE_SCRATCH,
                length,
                target,
            );
            merge(code, operand.predication);
        }
        store_z_chunk(code, operand.destination, chunk, RESULT, length, target);
    }
}
