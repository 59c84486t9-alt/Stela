//! Scalar leaves of scalable length and population-count arithmetic.
//! Scalable predicate counting and complete-Z access are supplied by the shared
//! scalable backend; helpers below consume a count in RCX when it is dynamic.
use super::super::{load, store};
use super::predicate::emit_counter_chunk;
use crate::TargetCpu;
use crate::aarch64::{
    scalable::{ElementSize, VectorLength},
    sve::address::{Count, Destination, Kind, Operand, Saturation},
};
use crate::x86_64::isa::{ShiftOpcode, SimdOpcode as Host};
use crate::x86_64::scalable::{load_z_chunk, read_predicate_chunk, store_z_chunk};
use alloc::vec::Vec;

const MOV_EAX_IMM32: u8 = 0xb8;
const MOV_RAX_IMM32: &[u8] = &[0x48, 0xc7, 0xc0];
const MOV_EDX_IMM32: u8 = 0xba;
const MOV_RDX_IMM64: &[u8] = &[0x48, 0xba];
const ADD_RAX_IMM8: &[u8] = &[0x48, 0x83, 0xc0];
const ADD_RAX_IMM32: &[u8] = &[0x48, 0x05];
const ADD_EAX_IMM8: &[u8] = &[0x83, 0xc0];
const SUB_EAX_IMM8: &[u8] = &[0x83, 0xe8];
const ADD_EAX_IMM32: u8 = 0x05;
const SUB_EAX_IMM32: u8 = 0x2d;
const ADD_EAX_ECX: &[u8] = &[0x01, 0xc8];
const SUB_EAX_ECX: &[u8] = &[0x29, 0xc8];
const CMOVO_EAX_EDX: &[u8] = &[0x0f, 0x40, 0xc2];
const CMOVB_EAX_EDX: &[u8] = &[0x0f, 0x42, 0xc2];
const MOVSXD_RAX_EAX: &[u8] = &[0x48, 0x63, 0xc0];
const REX_W: u8 = 0x48;
const BITS32: u8 = 32;
const BITS64: u8 = 64;
const PATTERN_POW2: u8 = 0;
const PATTERN_MUL4: u8 = 29;
const PATTERN_MUL3: u8 = 30;
const PATTERN_ALL: u8 = 31;

pub(super) fn pattern_count(pattern: u8, element: ElementSize, length: VectorLength) -> u32 {
    let elements = length.lanes(element) as u32;
    let requested = match pattern {
        PATTERN_POW2 => return 1 << elements.ilog2(),
        1..=8 => u32::from(pattern),
        9..=13 => 1 << (pattern - 5),
        PATTERN_MUL4 => return elements / 4 * 4,
        PATTERN_MUL3 => return elements / 3 * 3,
        PATTERN_ALL => return elements,
        _ => return 0,
    };
    if requested <= elements { requested } else { 0 }
}

/// Handles scalar operations whose count is known from the selected profile.
/// Returns false before emitting anything for instructions needing P/Z access.
pub(super) fn emit_static_scalar(
    code: &mut Vec<u8>,
    operand: &Operand,
    length: VectorLength,
) -> bool {
    let Destination::Scalar { register, .. } = operand.destination else {
        return false;
    };
    match operand.kind {
        Kind::Length {
            source,
            immediate,
            predicate,
        } => {
            let scale = if predicate {
                length.predicate_bytes()
            } else {
                length.bytes()
            };
            let displacement = i32::from(immediate) * scale as i32;
            if let Some(source) = source {
                load(code, source);
                if displacement != 0 {
                    if let Ok(short) = i8::try_from(displacement) {
                        code.extend(ADD_RAX_IMM8);
                        code.push(short as u8);
                    } else {
                        code.extend(ADD_RAX_IMM32);
                        code.extend(displacement.to_le_bytes());
                    }
                }
            } else if displacement >= 0 {
                code.push(MOV_EAX_IMM32);
                code.extend((displacement as u32).to_le_bytes());
            } else {
                code.extend(MOV_RAX_IMM32);
                code.extend(displacement.to_le_bytes());
            }
            store(code, register);
        }
        Kind::Count(Count::Pattern {
            pattern,
            multiplier,
        }) => {
            let count = pattern_count(pattern, operand.element, length) * u32::from(multiplier);
            code.push(MOV_EAX_IMM32);
            code.extend(count.to_le_bytes());
            store(code, register);
        }
        Kind::Adjust {
            count:
                Count::Pattern {
                    pattern,
                    multiplier,
                },
            ..
        } => {
            let count = pattern_count(pattern, operand.element, length) * u32::from(multiplier);
            scalar_adjust(code, operand, Some(count));
        }
        _ => return false,
    }
    true
}

/// Consume a nonnegative architectural population count in RCX. Scalar32
/// saturation always extends its W result, even when the runtime count is zero.
pub(super) fn emit_scalar_adjust(code: &mut Vec<u8>, operand: &Operand) {
    scalar_adjust(code, operand, None);
}

fn scalar_adjust(code: &mut Vec<u8>, operand: &Operand, constant_count: Option<u32>) {
    let Destination::Scalar { register, bits } = operand.destination else {
        unreachable!("scalar count backend received a vector destination");
    };
    let Kind::Adjust {
        subtract,
        saturation,
        ..
    } = operand.kind
    else {
        unreachable!("scalar count backend received a non-adjustment");
    };
    debug_assert!(matches!(bits, BITS32 | BITS64));
    load(code, register);
    scalar_value_adjust(code, bits, subtract, saturation, constant_count);
    store(code, register);
}

fn scalar_value_adjust(
    code: &mut Vec<u8>,
    bits: u8,
    subtract: bool,
    saturation: Saturation,
    constant_count: Option<u32>,
) {
    if saturation != Saturation::Wrapping {
        let bound = match (saturation, subtract, bits) {
            (Saturation::Signed, false, BITS32) => i32::MAX as u64,
            (Saturation::Signed, true, BITS32) => i32::MIN as u32 as u64,
            (Saturation::Signed, false, BITS64) => i64::MAX as u64,
            (Saturation::Signed, true, BITS64) => i64::MIN as u64,
            (Saturation::Unsigned, false, BITS32) => u32::MAX as u64,
            (Saturation::Unsigned, false, BITS64) => u64::MAX,
            (Saturation::Unsigned, true, _) => 0,
            _ => unreachable!("invalid scalar saturation width"),
        };
        if bound <= u64::from(u32::MAX) {
            code.push(MOV_EDX_IMM32);
            code.extend((bound as u32).to_le_bytes());
        } else {
            code.extend(MOV_RDX_IMM64);
            code.extend(bound.to_le_bytes());
        }
    }
    if bits == BITS64 {
        code.push(REX_W);
    }
    if let Some(count) = constant_count {
        if count <= i8::MAX as u32 {
            code.extend(if subtract { SUB_EAX_IMM8 } else { ADD_EAX_IMM8 });
            code.push(count as u8);
        } else {
            code.push(if subtract {
                SUB_EAX_IMM32
            } else {
                ADD_EAX_IMM32
            });
            code.extend(count.to_le_bytes());
        }
    } else {
        code.extend(if subtract { SUB_EAX_ECX } else { ADD_EAX_ECX });
    }
    if saturation != Saturation::Wrapping {
        if bits == BITS64 {
            code.push(REX_W);
        }
        code.extend(if saturation == Saturation::Signed {
            CMOVO_EAX_EDX
        } else {
            CMOVB_EAX_EDX
        });
    }
    if bits == BITS32 && saturation == Saturation::Signed {
        code.extend(MOVSXD_RAX_EAX);
    }
}

const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const MOV_R8_IMM64: &[u8] = &[0x49, 0xb8];
const AND_RAX_R8: &[u8] = &[0x4c, 0x21, 0xc0];
const AND_RDX_R8: &[u8] = &[0x4c, 0x21, 0xc2];
const AND_RAX_RDX: &[u8] = &[0x48, 0x21, 0xd0];
const SUB_RAX_RDX: &[u8] = &[0x48, 0x29, 0xd0];
const ADD_RAX_RDX: &[u8] = &[0x48, 0x01, 0xd0];
const SHR_RDX_IMM8: &[u8] = &[0x48, 0xc1, 0xea];
const SHR_RAX_IMM8: &[u8] = &[0x48, 0xc1, 0xe8];
const IMUL_RAX_R8: &[u8] = &[0x49, 0x0f, 0xaf, 0xc0];
const POPCNT_RAX_RAX: &[u8] = &[0xf3, 0x48, 0x0f, 0xb8, 0xc0];
const XOR_ECX_ECX: &[u8] = &[0x31, 0xc9];
const ADD_RCX_RAX: &[u8] = &[0x48, 0x01, 0xc1];
const MOV_RAX_RCX: &[u8] = &[0x48, 0x89, 0xc8];
const MOVD_XMM_EAX: &[u8] = &[0x66, 0x0f, 0x6e];
const MOVQ_RDX_XMM7: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xfa];
const MOVQ_XMM7_RAX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e, 0xf8];
const MOVQ_RAX_XMM0: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xc0];
const MODRM_REGISTER: u8 = 0xc0;
const HOST_REGISTER_SHIFT: u8 = 3;
const QWORD_BITS: usize = 64;
const QWORD_BYTES: usize = 8;
const POPCOUNT_PAIRS: u64 = 0x5555_5555_5555_5555;
const POPCOUNT_QUADS: u64 = 0x3333_3333_3333_3333;
const POPCOUNT_NIBBLES: u64 = 0x0f0f_0f0f_0f0f_0f0f;
const POPCOUNT_BYTE_SUM: u64 = 0x0101_0101_0101_0101;
const POPCOUNT_SUM_SHIFT: u8 = 56;
const VECTOR_RESULT: u8 = 0;
const VECTOR_DELTA: u8 = 1;
const VECTOR_LIMIT: u8 = 2;
const VECTOR_THRESHOLD: u8 = 3;
const VECTOR_MASK: u8 = 4;
const VECTOR_ALTERNATIVE: u8 = 5;
const VECTOR_BIAS: u8 = 6;
const VECTOR_TEMPORARY: u8 = 7;
const BROADCAST_LOW_DWORD: u8 = 0;
const DWORD_SIGN_BIT: u32 = 1 << 31;

fn mask_r8(code: &mut Vec<u8>, mask: u64) {
    code.extend(MOV_R8_IMM64);
    code.extend(mask.to_le_bytes());
}

/// Count low RAX bits. Preserves RCX; clobbers RAX/RDX/R8 and host flags.
fn population_count(code: &mut Vec<u8>, target: TargetCpu) {
    if target.supports(TargetCpu::Popcnt) {
        code.extend(POPCNT_RAX_RAX);
        return;
    }
    code.extend(MOV_RDX_RAX);
    code.extend(SHR_RDX_IMM8);
    code.push(1);
    mask_r8(code, POPCOUNT_PAIRS);
    code.extend(AND_RDX_R8);
    code.extend(SUB_RAX_RDX);
    code.extend(MOV_RDX_RAX);
    mask_r8(code, POPCOUNT_QUADS);
    code.extend(AND_RAX_R8);
    code.extend(SHR_RDX_IMM8);
    code.push(2);
    code.extend(AND_RDX_R8);
    code.extend(ADD_RAX_RDX);
    code.extend(MOV_RDX_RAX);
    code.extend(SHR_RDX_IMM8);
    code.push(4);
    code.extend(ADD_RAX_RDX);
    mask_r8(code, POPCOUNT_NIBBLES);
    code.extend(AND_RAX_R8);
    mask_r8(code, POPCOUNT_BYTE_SUM);
    code.extend(IMUL_RAX_R8);
    code.extend(SHR_RAX_IMM8);
    code.push(POPCOUNT_SUM_SHIFT);
}

/// Read one or two complete P values, count element-leading bits into RCX.
/// Clobbers RAX/RDX/R8/XMM7; preserves architectural status, RDI and R15.
fn count_predicate(
    code: &mut Vec<u8>,
    source: u8,
    governing: Option<u8>,
    element: ElementSize,
    length: VectorLength,
    target: TargetCpu,
) {
    let mask = (0..QWORD_BITS)
        .step_by(element.bytes())
        .fold(0, |mask, bit| mask | (1u64 << bit));
    code.extend(XOR_ECX_ECX);
    for chunk in 0..length.predicate_bytes().div_ceil(QWORD_BYTES) {
        read_predicate_chunk(code, source, chunk, length);
        if let Some(governing) = governing {
            code.extend(MOVQ_XMM7_RAX);
            read_predicate_chunk(code, governing, chunk, length);
            code.extend(MOVQ_RDX_XMM7);
            code.extend(AND_RAX_RDX);
        }
        if mask != u64::MAX {
            mask_r8(code, mask);
            code.extend(AND_RAX_R8);
        }
        population_count(code, target);
        code.extend(ADD_RCX_RAX);
    }
}

fn packed(code: &mut Vec<u8>, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn broadcast_eax(code: &mut Vec<u8>, destination: u8, element: ElementSize) {
    if element == ElementSize::Doubleword {
        Host::MoveGprQword.append(code, TargetCpu::Baseline);
        code.push(MODRM_REGISTER | destination << HOST_REGISTER_SHIFT);
        packed(code, Host::UnpackLowQword, destination, destination);
    } else {
        code.extend(MOVD_XMM_EAX);
        code.push(MODRM_REGISTER | destination << HOST_REGISTER_SHIFT);
        if element == ElementSize::Halfword {
            packed(code, Host::UnpackLowWord, destination, destination);
        }
        packed(code, Host::ShuffleDword, destination, destination);
        code.push(BROADCAST_LOW_DWORD);
    }
}

fn broadcast_constant(code: &mut Vec<u8>, value: u32, destination: u8) {
    code.push(MOV_EAX_IMM32);
    code.extend(value.to_le_bytes());
    broadcast_eax(code, destination, ElementSize::Word);
}

/// RCX contains one nonnegative count applied to all vector elements.
/// SSE2 handles H directly and W with threshold masks. Saturating D uses two
/// scalar ADD/SUB+CMOV lanes per chunk until a measured checked recipe wins.
fn emit_vector_adjust(
    code: &mut Vec<u8>,
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
) {
    let Destination::Vector(destination) = operand.destination else {
        unreachable!("vector adjustment");
    };
    let Kind::Adjust {
        subtract,
        saturation,
        ..
    } = operand.kind
    else {
        unreachable!("vector adjustment");
    };
    let element = operand.element;
    code.extend(MOV_RAX_RCX);
    broadcast_eax(code, VECTOR_DELTA, element);
    if element == ElementSize::Word && saturation != Saturation::Wrapping {
        let limit = match (saturation, subtract) {
            (Saturation::Signed, false) => i32::MAX as u32,
            (Saturation::Signed, true) => i32::MIN as u32,
            (Saturation::Unsigned, false) => u32::MAX,
            (Saturation::Unsigned, true) => 0,
            _ => unreachable!("saturating W adjustment"),
        };
        broadcast_constant(code, limit, VECTOR_LIMIT);
        // EAX still holds limit: threshold is limit -/+ count.
        code.extend(if subtract { ADD_EAX_ECX } else { SUB_EAX_ECX });
        broadcast_eax(code, VECTOR_THRESHOLD, ElementSize::Word);
        if saturation == Saturation::Unsigned {
            broadcast_constant(code, DWORD_SIGN_BIT, VECTOR_BIAS);
            packed(code, Host::Xor, VECTOR_THRESHOLD, VECTOR_BIAS);
        }
    }
    for chunk in 0..length.chunks() {
        load_z_chunk(code, destination, chunk, VECTOR_RESULT, length, target);
        let output = if element == ElementSize::Doubleword && saturation != Saturation::Wrapping {
            saturating_qwords(code, subtract, saturation);
            VECTOR_DELTA
        } else {
            if element == ElementSize::Word && saturation != Saturation::Wrapping {
                packed(code, Host::MoveAligned, VECTOR_TEMPORARY, VECTOR_RESULT);
                if saturation == Saturation::Unsigned {
                    packed(code, Host::Xor, VECTOR_TEMPORARY, VECTOR_BIAS);
                }
                if subtract {
                    packed(code, Host::MoveAligned, VECTOR_MASK, VECTOR_THRESHOLD);
                    packed(code, Host::GreaterDword, VECTOR_MASK, VECTOR_TEMPORARY);
                } else {
                    packed(code, Host::MoveAligned, VECTOR_MASK, VECTOR_TEMPORARY);
                    packed(code, Host::GreaterDword, VECTOR_MASK, VECTOR_THRESHOLD);
                }
            }
            let opcode = match (element, saturation, subtract) {
                (ElementSize::Halfword, Saturation::Signed, false) => Host::AddSignedSaturatingWord,
                (ElementSize::Halfword, Saturation::Signed, true) => Host::SubSignedSaturatingWord,
                (ElementSize::Halfword, Saturation::Unsigned, false) => {
                    Host::AddUnsignedSaturatingWord
                }
                (ElementSize::Halfword, Saturation::Unsigned, true) => {
                    Host::SubUnsignedSaturatingWord
                }
                (ElementSize::Halfword, _, false) => Host::AddWord,
                (ElementSize::Halfword, _, true) => Host::SubWord,
                (ElementSize::Word, _, false) => Host::AddDword,
                (ElementSize::Word, _, true) => Host::SubDword,
                (ElementSize::Doubleword, _, false) => Host::AddQword,
                (ElementSize::Doubleword, _, true) => Host::SubQword,
                _ => unreachable!("allocated vector count element"),
            };
            packed(code, opcode, VECTOR_RESULT, VECTOR_DELTA);
            if element == ElementSize::Word && saturation != Saturation::Wrapping {
                packed(code, Host::MoveAligned, VECTOR_ALTERNATIVE, VECTOR_MASK);
                packed(code, Host::And, VECTOR_MASK, VECTOR_LIMIT);
                packed(code, Host::AndNot, VECTOR_ALTERNATIVE, VECTOR_RESULT);
                packed(code, Host::Or, VECTOR_MASK, VECTOR_ALTERNATIVE);
                VECTOR_MASK
            } else {
                VECTOR_RESULT
            }
        };
        store_z_chunk(code, destination, chunk, output, length, target);
    }
}

fn saturating_qwords(code: &mut Vec<u8>, subtract: bool, saturation: Saturation) {
    for lane in 0..2 {
        if lane != 0 {
            ShiftOpcode::RightBytes.emit(code, VECTOR_RESULT, QWORD_BYTES as u8);
        }
        code.extend(MOVQ_RAX_XMM0);
        scalar_value_adjust(code, BITS64, subtract, saturation, None);
        Host::MoveGprQword.append(code, TargetCpu::Baseline);
        code.push(
            MODRM_REGISTER
                | (if lane == 0 {
                    VECTOR_DELTA
                } else {
                    VECTOR_LIMIT
                }) << HOST_REGISTER_SHIFT,
        );
    }
    packed(code, Host::UnpackLowQword, VECTOR_DELTA, VECTOR_LIMIT);
}

const MOV_ECX_IMM32: u8 = 0xb9;
const PUSH_RCX: u8 = 0x51;
const POP_RCX: u8 = 0x59;

/// Emit a complete scalable count instruction after the shared entry profile
/// checks. Clobbers caller-saved GPRs/XMM0..7; keeps RDI/R15 and guest status.
pub(crate) fn emit(code: &mut Vec<u8>, operand: &Operand, length: VectorLength, target: TargetCpu) {
    if emit_static_scalar(code, operand, length) {
        return;
    }
    let count = match operand.kind {
        Kind::Count(count) | Kind::Adjust { count, .. } => count,
        Kind::Length { .. } => unreachable!("length has a scalar destination"),
    };
    match count {
        Count::Pattern {
            pattern,
            multiplier,
        } => {
            code.push(MOV_ECX_IMM32);
            code.extend(
                (pattern_count(pattern, operand.element, length) * u32::from(multiplier))
                    .to_le_bytes(),
            );
        }
        Count::Predicate(source) => {
            count_predicate(code, source, None, operand.element, length, target)
        }
        Count::Intersection { governing, source } => count_predicate(
            code,
            source,
            Some(governing),
            operand.element,
            length,
            target,
        ),
        Count::Counter { source, vectors } => {
            let bits = length.bytes() * usize::from(vectors);
            code.extend(XOR_ECX_ECX);
            for chunk in 0..bits.div_ceil(QWORD_BITS) {
                read_predicate_chunk(code, source, 0, length);
                // Shared CounterToPredicate uses RCX/R8..11; preserve only the
                // accumulating count. No helper emits a host CALL here.
                code.push(PUSH_RCX);
                emit_counter_chunk(code, chunk, length);
                code.push(POP_RCX);
                let remaining = (bits - chunk * QWORD_BITS).min(QWORD_BITS);
                let mask = (0..remaining)
                    .step_by(operand.element.bytes())
                    .fold(0, |mask, bit| mask | (1u64 << bit));
                if mask != u64::MAX {
                    mask_r8(code, mask);
                    code.extend(AND_RAX_R8);
                }
                population_count(code, target);
                code.extend(ADD_RCX_RAX);
            }
        }
    }
    match (operand.destination, operand.kind) {
        (Destination::Scalar { register, .. }, Kind::Count(_)) => {
            code.extend(MOV_RAX_RCX);
            store(code, register);
        }
        (Destination::Scalar { .. }, Kind::Adjust { .. }) => emit_scalar_adjust(code, operand),
        (Destination::Vector(_), Kind::Adjust { .. }) => {
            emit_vector_adjust(code, operand, length, target)
        }
        _ => unreachable!("count instruction destination"),
    }
}
