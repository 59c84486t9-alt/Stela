//! AdvSIMD and FP emission with SSE2.
use super::isa::SimdOpcode;
use super::isa::SimdOpcode as Host;
use super::{memory_address, memory_writeback};
use crate::aarch64::simd::{Comparison, IntegerOperation, Operand};
use alloc::vec::Vec;
pub(in crate::x86_64) mod absolute_selection;
mod aes;
pub(super) mod arithmetic;
pub(in crate::x86_64) mod bfloat16;
mod comparison;
mod complex;
mod estimate;
pub(in crate::x86_64) mod exponent_scale;
mod extrema_scale;
mod floating;
mod fused;
pub(in crate::x86_64) mod half;
mod halving;
mod i8mm;
mod immediates;
mod integer_conversion;
mod lut;
pub(super) mod memory;
pub(crate) mod memory_checked;
mod minmax;
pub(in crate::x86_64) mod numerical;
pub(in crate::x86_64) mod precision;
mod products;
mod rearrange;
mod reductions;
mod refinement;
mod rounding;
pub(super) use rounding::kernel as rounding_kernel;
mod saturating;
mod sha1;
mod sha256;
mod sha3;
mod sha32;
mod sha512;
pub(crate) mod shifts;
mod sqrt;
mod structure_memory;
mod widening;

fn vector_offset(vector: u8) -> u32 {
    (core::mem::offset_of!(crate::GuestState, v) + usize::from(vector) * 16) as u32
}

fn commit(code: &mut Vec<u8>, vector: u8, xmm: u8) {
    // GuestState has only 8-byte alignment; V0 begins at byte264.
    Host::StoreUnaligned.append(code, crate::TargetCpu::Baseline);
    code.push(0x87 | (xmm << 3)); // [rdi+disp32]
    code.extend(vector_offset(vector).to_le_bytes());
}

fn read_vector(code: &mut Vec<u8>, vector: u8, xmm: u8) {
    Host::LoadUnaligned.append(code, crate::TargetCpu::Baseline);
    code.push(0x87 | (xmm << 3)); // [rdi+disp32]
    code.extend(vector_offset(vector).to_le_bytes());
}

fn packed(code: &mut Vec<u8>, opcode: SimdOpcode, destination: u8, source: u8) {
    opcode.register(code, destination, source, crate::TargetCpu::Baseline);
}

fn subtract_opcode(lane_bytes: u8) -> SimdOpcode {
    match lane_bytes {
        1 => Host::SubByte,
        2 => Host::SubWord,
        4 => Host::SubDword,
        8 => Host::SubQword,
        _ => unreachable!("reviewed lane size"),
    }
}

fn shuffle(code: &mut Vec<u8>, destination: u8, source: u8, control: u8) {
    packed(code, Host::ShuffleDword, destination, source);
    code.push(control);
}

fn unsigned_bias(code: &mut Vec<u8>, lane_bytes: u8) {
    let mask: u64 = match lane_bytes {
        1 => 0x8080808080808080,
        2 => 0x8000800080008000,
        4 | 8 => 0x8000000080000000,
        _ => unreachable!("reviewed comparison lane"),
    };
    code.extend([0x48, 0xb9]);
    code.extend(mask.to_le_bytes());
    code.extend([0x66, 0x48, 0x0f, 0x6e, 0xe1]); // movq xmm4,rcx
    packed(code, Host::UnpackLowQword, 4, 4);
    packed(code, Host::Xor, 0, 4);
    packed(code, Host::Xor, 1, 4);
}

fn equal(code: &mut Vec<u8>, lane_bytes: u8, target: crate::TargetCpu) {
    if lane_bytes == 8 && target >= crate::TargetCpu::Sse41 {
        Host::EqualQword.register(code, 0, 1, target); // pcmpeqq xmm0,xmm1
        return;
    }
    packed(
        code,
        match lane_bytes {
            1 => Host::EqualByte,
            2 => Host::EqualWord,
            4 | 8 => Host::EqualDword,
            _ => unreachable!("reviewed comparison lane"),
        },
        0,
        1,
    );
    if lane_bytes == 8 {
        shuffle(code, 2, 0, 0xb1); // adjacent dword equality masks must both hold
        packed(code, Host::And, 0, 2);
    }
}

pub(super) fn greater(
    code: &mut Vec<u8>,
    lane_bytes: u8,
    unsigned: bool,
    target: crate::TargetCpu,
) {
    if lane_bytes == 8 && target >= crate::TargetCpu::Sse42 {
        if unsigned {
            code.extend([0x48, 0xb9]);
            code.extend(0x8000000000000000u64.to_le_bytes());
            code.extend([0x66, 0x48, 0x0f, 0x6e, 0xe1]);
            packed(code, Host::UnpackLowQword, 4, 4);
            packed(code, Host::Xor, 0, 4);
            packed(code, Host::Xor, 1, 4);
        }
        Host::GreaterQword.register(code, 0, 1, target); // pcmpgtq xmm0,xmm1
        return;
    }
    if unsigned {
        unsigned_bias(code, lane_bytes);
    }
    if lane_bytes != 8 {
        packed(
            code,
            match lane_bytes {
                1 => Host::GreaterByte,
                2 => Host::GreaterWord,
                4 => Host::GreaterDword,
                _ => unreachable!("reviewed comparison lane"),
            },
            0,
            1,
        );
        return;
    }
    // Compare high dwords first; equal high halves use unsigned low ordering.
    packed(code, Host::MoveAligned, 2, 0);
    packed(code, Host::GreaterDword, 2, 1);
    shuffle(code, 2, 2, 0xf5);
    packed(code, Host::MoveAligned, 3, 0);
    packed(code, Host::EqualDword, 3, 1);
    shuffle(code, 3, 3, 0xf5);
    if !unsigned {
        unsigned_bias(code, 8);
    }
    packed(code, Host::GreaterDword, 0, 1);
    shuffle(code, 0, 0, 0xa0);
    packed(code, Host::And, 0, 3);
    packed(code, Host::Or, 0, 2);
}

pub(super) fn numerical_always_exits(operation: &crate::aarch64::FloatingPointOperation) -> bool {
    use crate::aarch64::{
        FloatingPointOperation,
        floating::{Format, integer::IntegerRounding},
        simd::conversion::Operand,
    };
    match operation {
        FloatingPointOperation::ExtremaScale(operand) => extrema_scale::always_exits(operand),
        FloatingPointOperation::Binary(operand) => arithmetic::always_exits(operand),
        FloatingPointOperation::Fused(operand) => operand.format == Format::Half,
        FloatingPointOperation::Widening(_)
        | FloatingPointOperation::BFloat16(_)
        | FloatingPointOperation::Complex(_) => false,
        FloatingPointOperation::Conversion(operand) => match operand {
            Operand::Precision(operand) => operand.mode.destination_format() == Format::Half,
            Operand::FromInteger(operand) => operand.format == Format::Half,
            Operand::ToInteger { operand, rounding } => {
                operand.format == Format::Half || *rounding == IntegerRounding::NearestAway
            }
            Operand::JavaScript { .. } => false,
        },
        FloatingPointOperation::Comparison(_)
        | FloatingPointOperation::MinMax(_)
        | FloatingPointOperation::Rounding(_)
        | FloatingPointOperation::SquareRoot(_)
        | FloatingPointOperation::Estimate(_)
        | FloatingPointOperation::Refinement(_) => false,
    }
}

pub(super) fn emit_numerical(
    code: &mut Vec<u8>,
    operation: &crate::aarch64::FloatingPointOperation,
    pc: crate::GuestAddress,
    target: crate::TargetCpu,
) {
    match operation {
        crate::aarch64::FloatingPointOperation::Estimate(operand) => {
            estimate::emit(code, operand, pc, target);
        }
        crate::aarch64::FloatingPointOperation::Refinement(operand) => {
            refinement::emit(code, operand, pc, target);
        }
        crate::aarch64::FloatingPointOperation::Binary(operand) => {
            arithmetic::emit(code, operand, pc, target)
        }
        crate::aarch64::FloatingPointOperation::Fused(operand) => {
            fused::emit(code, operand, pc, target)
        }
        crate::aarch64::FloatingPointOperation::Widening(operand) => {
            widening::emit(code, operand, pc, target)
        }
        crate::aarch64::FloatingPointOperation::BFloat16(operand) => {
            bfloat16::emit(code, operand, pc, target)
        }
        crate::aarch64::FloatingPointOperation::Complex(operand) => {
            complex::emit(code, operand, pc, target)
        }
        crate::aarch64::FloatingPointOperation::Comparison(operand) => {
            comparison::emit(code, operand, pc)
        }
        crate::aarch64::FloatingPointOperation::ExtremaScale(operand) => {
            extrema_scale::emit(code, operand, pc, target);
        }
        crate::aarch64::FloatingPointOperation::MinMax(operand) => minmax::emit(code, operand, pc),
        crate::aarch64::FloatingPointOperation::Rounding(operand) => {
            rounding::emit(code, operand, pc, target)
        }
        crate::aarch64::FloatingPointOperation::SquareRoot(operand) => {
            sqrt::emit(code, operand, pc, target)
        }
        crate::aarch64::FloatingPointOperation::Conversion(operand) => {
            use crate::aarch64::simd::conversion::Operand;
            match operand {
                Operand::Precision(operand) => precision::emit(code, operand, pc),
                Operand::FromInteger(operand) => {
                    integer_conversion::from_integer(code, operand, pc)
                }
                Operand::ToInteger { operand, rounding } => {
                    integer_conversion::to_integer(code, operand, *rounding, pc)
                }
                Operand::JavaScript {
                    destination,
                    source,
                } => integer_conversion::javascript(code, *destination, *source, pc),
            }
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    emit_for_target(code, operand, crate::TargetCpu::Baseline);
}
pub(super) fn emit_for_target(code: &mut Vec<u8>, operand: &Operand, target: crate::TargetCpu) {
    match *operand {
        Operand::Lut(ref operand) => lut::emit(code, operand, target),
        Operand::Aes(ref operand) => aes::emit(code, operand, target),
        Operand::I8mm(ref operand) => i8mm::emit(code, operand, target),
        Operand::Sha1(ref operand) => sha1::emit(code, operand, target),
        Operand::Sha256(ref operand) => sha256::emit(code, operand, target),
        Operand::Sha3(ref operand) => sha3::emit(code, operand),
        Operand::Sha512(ref operand) => sha512::emit(code, operand, target),
        Operand::Floating(ref operand) => floating::emit(code, operand, target),
        Operand::MemoryRegisterOffset(ref operand) => memory::emit_register_offset(code, operand),
        Operand::StructureMemory(ref operand) => structure_memory::emit(code, operand, target),
        Operand::Immediate(ref operand) => immediates::emit(code, operand, target),
        Operand::Halving(ref operand) => halving::emit(code, operand, target),
        Operand::Product(ref operand) => products::emit(code, operand, target),
        Operand::Saturate(ref operand) => saturating::emit(code, operand, target),
        Operand::Reduce(ref operand) => reductions::emit(code, operand, target),
        Operand::Shift(ref operand) => shifts::emit(code, operand, target),
        Operand::Rearrange(ref operand) => rearrange::emit(code, operand, target),
        Operand::Compare {
            operation,
            destination,
            left,
            right,
            bytes,
            lane_bytes,
        } => {
            use Comparison::*;
            let reverse = matches!(operation, GreaterEqual | HigherEqual | LessZero);
            let left_xmm = u8::from(reverse);
            let right_xmm = u8::from(!reverse);
            read_vector(code, left, left_xmm);
            if let Some(right) = right {
                read_vector(code, right, right_xmm);
            } else {
                packed(code, Host::Xor, right_xmm, right_xmm);
            }
            match operation {
                Equal => equal(code, lane_bytes, target),
                Test => {
                    packed(code, Host::And, 0, 1);
                    packed(code, Host::Xor, 1, 1);
                    equal(code, lane_bytes, target);
                }
                _ => greater(
                    code,
                    lane_bytes,
                    matches!(operation, Higher | HigherEqual),
                    target,
                ),
            }
            if matches!(operation, GreaterEqual | HigherEqual | LessEqualZero | Test) {
                packed(code, Host::EqualDword, 1, 1);
                packed(code, Host::Xor, 0, 1);
            }
            if bytes == 8 {
                packed(code, Host::MoveQword, 0, 0);
            }
            commit(code, destination, 0);
        }
        Operand::Integer {
            operation,
            destination,
            left,
            right,
            bytes,
            lane_bytes,
        } => {
            use IntegerOperation::*;
            // Stage the sources before writing any overlapping V register.
            read_vector(code, left, 0);
            let mut result = 0;
            if !matches!(operation, Abs | Neg) {
                read_vector(code, right, 1);
            }
            match operation {
                And => packed(code, Host::And, 0, 1),
                Bic => {
                    packed(code, Host::AndNot, 1, 0);
                    result = 1;
                }
                Orr => packed(code, Host::Or, 0, 1),
                Orn => {
                    packed(code, Host::EqualDword, 2, 2); // pcmpeqd: all ones, including dirty Q=0 upper bits
                    packed(code, Host::Xor, 1, 2);
                    packed(code, Host::Or, 0, 1);
                }
                Eor => packed(code, Host::Xor, 0, 1),
                Bsl | Bit | Bif => {
                    read_vector(code, destination, 2);
                    if operation == Bsl {
                        packed(code, Host::Xor, 0, 1);
                        packed(code, Host::And, 0, 2);
                        packed(code, Host::Xor, 0, 1);
                    } else {
                        packed(code, Host::Xor, 0, 2);
                        if operation == Bit {
                            packed(code, Host::And, 0, 1);
                            packed(code, Host::Xor, 0, 2);
                        } else {
                            packed(code, Host::AndNot, 1, 0);
                            packed(code, Host::Xor, 1, 2);
                            result = 1;
                        }
                    }
                }
                Add => packed(
                    code,
                    match lane_bytes {
                        1 => Host::AddByte,
                        2 => Host::AddWord,
                        4 => Host::AddDword,
                        8 => Host::AddQword,
                        _ => unreachable!("reviewed lane size"),
                    },
                    0,
                    1,
                ),
                Sub => packed(code, subtract_opcode(lane_bytes), 0, 1),
                Neg => {
                    packed(code, Host::Xor, 1, 1);
                    packed(code, subtract_opcode(lane_bytes), 1, 0);
                    result = 1;
                }
                Abs => {
                    if lane_bytes <= 4 && target >= crate::TargetCpu::Ssse3 {
                        let opcode = match lane_bytes {
                            1 => Host::AbsByte,
                            2 => Host::AbsWord,
                            4 => Host::AbsDword,
                            _ => unreachable!(),
                        };
                        opcode.register(code, 0, 0, target);
                    } else {
                        packed(code, Host::Xor, 1, 1);
                        packed(
                            code,
                            match lane_bytes {
                                1 => Host::GreaterByte,
                                2 => Host::GreaterWord,
                                4 | 8 => Host::GreaterDword,
                                _ => unreachable!("reviewed lane size"),
                            },
                            1,
                            0,
                        );
                        if lane_bytes == 8 {
                            // SSE2 lacks a signed qword comparison: repeat each high
                            // dword's sign across its qword, using only its sign bit.
                            shuffle(code, 1, 1, 0xf5);
                        }
                        packed(code, Host::Xor, 0, 1);
                        packed(code, subtract_opcode(lane_bytes), 0, 1);
                    }
                }
            }
            if bytes == 8 {
                // Arm clears the complete upper half on scalar/D vector writes.
                packed(code, Host::MoveQword, result, result);
            }
            commit(code, destination, result);
        }
        Operand::MemoryPair {
            load,
            bytes,
            vectors,
            base,
            displacement,
            mode,
        } => {
            memory_address(code, base, displacement, mode);
            let aligned = super::memory_store::aligned_immediate(base, displacement, mode, bytes);
            if load {
                memory::wide_transfer(code, true, bytes, 0, 0, aligned);
                memory::wide_transfer(code, true, bytes, 1, bytes, aligned);
                // Neither guest destination changes if either load faults.
                // Duplicate destinations were declined by the decoder.
                commit(code, vectors[0], 0);
                commit(code, vectors[1], 1);
            } else {
                // Read both sources before either RAM write; duplicate source
                // registers are allowed.
                read_vector(code, vectors[0], 0);
                read_vector(code, vectors[1], 1);
                memory::wide_transfer(code, false, bytes, 0, 0, aligned);
                memory::wide_transfer(code, false, bytes, 1, bytes, aligned);
            }
            // Split private-RAM stores may expose the first completed element
            // if the second faults. Base writeback requires both to complete.
            memory_writeback(code, base, mode);
        }
        Operand::MoveImmediate {
            vector,
            mask,
            two_lanes,
        } => {
            if mask == 0 {
                code.extend([0x66, 0x0f, 0xef, 0xc0]); // pxor xmm0,xmm0
                commit(code, vector, 0);
                return;
            }
            code.extend([0x48, 0xb9]); // movabs rcx,mask
            code.extend(mask.to_le_bytes());
            code.extend([0x66, 0x48, 0x0f, 0x6e, 0xc1]); // movq xmm0,rcx (zeros high64)
            if two_lanes {
                code.extend([0x66, 0x0f, 0x6c, 0xc0]); // punpcklqdq xmm0,xmm0
            }
            commit(code, vector, 0);
        }
        Operand::Memory {
            load,
            bytes,
            vector,
            base,
            displacement,
            mode,
        } => {
            memory_address(code, base, displacement, mode);
            memory::transfer(
                code,
                load,
                bytes,
                vector,
                super::memory_store::aligned_immediate(base, displacement, mode, bytes),
            );
            // RDX retains the potential writeback across all SSE/GPR staging.
            memory_writeback(code, base, mode);
        }
    }
}
