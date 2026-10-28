//! AdvSIMD and FP emission with SSE2.
use super::isa::SimdOpcode;
use super::isa::SimdOpcode as Host;
use super::{MemoryChecks, memory_address, memory_writeback};
use crate::aarch64::simd::{Comparison, IntegerOperation, Operand};
use crate::x86_64::asm::Code;
use alloc::vec::Vec;
pub(in crate::x86_64) mod absolute_selection;
mod aes;
pub(super) mod arithmetic;
pub(in crate::x86_64) mod bfloat16;
mod comparison;
mod complex;
pub(in crate::x86_64) mod encode;
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
mod structure_checked;
mod structure_memory;
mod widening;

/// Fixed-width SIMD memory routing; checked bodies never use private-RAM emitters.
#[derive(Clone, Copy)]
pub(crate) enum CheckedMemoryOperand {
    Fixed(memory_checked::CheckedOperand),
    Structure(structure_checked::CheckedOperand),
}

impl CheckedMemoryOperand {
    pub(crate) fn from_operation(
        operation: &crate::aarch64::Operation,
        profile: crate::block::CheckedMemoryProfile,
    ) -> Option<Self> {
        memory_checked::CheckedOperand::from_operation(operation, profile)
            .map(Self::Fixed)
            .or_else(|| {
                structure_checked::CheckedOperand::from_operation(operation, profile)
                    .map(Self::Structure)
            })
    }

    pub(crate) fn requirements(&self) -> crate::context::memory::MemoryRequirements {
        match self {
            Self::Fixed(operand) => operand.requirements(),
            Self::Structure(operand) => operand.requirements(),
        }
    }

    pub(crate) fn emit_context(&self, code: &mut Code, pc: u64, target: crate::TargetCpu) {
        match self {
            Self::Fixed(operand) => operand.emit_context(code, pc),
            Self::Structure(operand) => operand.emit_context(code, pc, target),
        }
    }
}

fn vector_offset(vector: u8) -> u32 {
    (core::mem::offset_of!(crate::GuestState, v) + usize::from(vector) * 16) as u32
}

fn commit(code: &mut Code, vector: u8, xmm: u8) {
    // GuestState has only 8-byte alignment; V0 begins at byte264.
    Host::StoreUnaligned.append(code, crate::TargetCpu::Baseline);
    code.push(0x87 | (xmm << 3)); // [rdi+disp32]
    code.extend(vector_offset(vector).to_le_bytes());
}

fn read_vector(code: &mut Code, vector: u8, xmm: u8) {
    Host::LoadUnaligned.append(code, crate::TargetCpu::Baseline);
    code.push(0x87 | (xmm << 3)); // [rdi+disp32]
    code.extend(vector_offset(vector).to_le_bytes());
}

fn packed(code: &mut Code, opcode: SimdOpcode, destination: u8, source: u8) {
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

fn shuffle(code: &mut Code, destination: u8, source: u8, control: u8) {
    packed(code, Host::ShuffleDword, destination, source);
    code.push(control);
}

fn unsigned_bias(code: &mut Code, lane_bytes: u8) {
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

fn equal(code: &mut Code, lane_bytes: u8, target: crate::TargetCpu) {
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

pub(super) fn greater(code: &mut Code, lane_bytes: u8, unsigned: bool, target: crate::TargetCpu) {
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
        FloatingPointOperation::Fused(_)
        | FloatingPointOperation::Widening(_)
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
    code: &mut Code,
    operation: &crate::aarch64::FloatingPointOperation,
    pc: crate::GuestAddress,
    target: crate::TargetCpu,
) {
    emit_numerical_split(code, operation, pc, target, numerical::Entry::UNKNOWN);
}

/// [`emit_numerical`] after what `entry` says, returning the
/// [`numerical::ColdSplit`] of an emission with a sticky-inexact path.
pub(super) fn emit_numerical_split(
    code: &mut Code,
    operation: &crate::aarch64::FloatingPointOperation,
    pc: crate::GuestAddress,
    target: crate::TargetCpu,
    entry: numerical::Entry,
) -> Option<numerical::ColdSplit> {
    match operation {
        crate::aarch64::FloatingPointOperation::Estimate(operand) => {
            estimate::emit(code, operand, pc, target);
        }
        crate::aarch64::FloatingPointOperation::Refinement(operand) => {
            refinement::emit(code, operand, pc, target);
        }
        crate::aarch64::FloatingPointOperation::Binary(operand) => {
            return arithmetic::emit(code, operand, pc, target, entry);
        }
        crate::aarch64::FloatingPointOperation::Fused(operand) => {
            return fused::emit(code, operand, pc, target, entry);
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
            return sqrt::emit(code, operand, pc, target, entry);
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
    None
}

#[cfg(test)]
pub(super) fn emit(code: &mut Code, operand: &Operand) {
    emit_for_target(
        code,
        operand,
        crate::TargetCpu::Baseline,
        MemoryChecks::DEFAULT,
    );
}
pub(super) fn emit_for_target(
    code: &mut Code,
    operand: &Operand,
    target: crate::TargetCpu,
    checks: MemoryChecks,
) {
    emit_after(code, operand, target, checks, None);
}

/// [`emit_for_target`] where XMM0 holds guest vector `xmm0` whole: a
/// store of it takes it from there.
pub(super) fn emit_after(
    code: &mut Code,
    operand: &Operand,
    target: crate::TargetCpu,
    checks: MemoryChecks,
    xmm0: Option<u8>,
) {
    match *operand {
        Operand::Lut(ref operand) => lut::emit(code, operand, target),
        Operand::Aes(ref operand) => aes::emit(code, operand, target),
        Operand::I8mm(ref operand) => i8mm::emit(code, operand, target),
        Operand::Sha1(ref operand) => sha1::emit(code, operand, target),
        Operand::Sha256(ref operand) => sha256::emit(code, operand, target),
        Operand::Sha3(ref operand) => sha3::emit(code, operand),
        Operand::Sha512(ref operand) => sha512::emit(code, operand, target),
        Operand::Floating(ref operand) => floating::emit(code, operand, target),
        Operand::MemoryRegisterOffset(ref operand) => {
            memory::emit_register_offset(code, operand, checks, xmm0 == Some(operand.vector))
        }
        Operand::StructureMemory(ref operand) => {
            structure_memory::emit(code, operand, target, checks)
        }
        Operand::Immediate(crate::aarch64::simd::immediates::Operand::LaneMove(
            ref lane @ crate::aarch64::simd::rearrange::Operand::Extract {
                source, byte: 0, ..
            },
        ))
        | Operand::Rearrange(
            ref lane @ crate::aarch64::simd::rearrange::Operand::Extract {
                source, byte: 0, ..
            },
        ) if xmm0 == Some(source) => rearrange::extract(code, lane, true),
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
            let access = super::Access::of(!load, 2 * u16::from(bytes));
            memory_address(code, checks, base, displacement, mode, bytes, access);
            let aligned = checks.stack_alignment
                && super::memory_store::aligned_immediate(base, displacement, mode, bytes);
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
            let access = super::Access::of(!load, bytes.into());
            memory_address(code, checks, base, displacement, mode, bytes, access);
            memory::transfer(
                code,
                load,
                bytes,
                vector,
                checks.stack_alignment
                    && super::memory_store::aligned_immediate(base, displacement, mode, bytes),
                xmm0 == Some(vector),
            );
            // RDX retains the potential writeback across all SSE/GPR staging.
            memory_writeback(code, base, mode);
        }
    }
}

/// The guest vector XMM0 holds whole after `operand`'s emission, `code`,
/// where it held `held` before: a vector load's or MOVI's destination,
/// committed from it, or a vector store's source, transferred from it; the
/// destination of a branch-free emission that ends with its commit from
/// XMM0; or, after a lane move to a general register, which leaves XMM0
/// alone, what it held.
pub(super) fn xmm0_after(operand: &Operand, code: &[u8], held: Option<u8>) -> Option<u8> {
    let committed = |vector: u8| {
        let mut store = Code::new();
        commit(&mut store, vector, 0);
        code.ends_with(&store).then_some(vector)
    };
    match *operand {
        Operand::Immediate(crate::aarch64::simd::immediates::Operand::LaneMove(
            crate::aarch64::simd::rearrange::Operand::Extract { .. },
        ))
        | Operand::Rearrange(crate::aarch64::simd::rearrange::Operand::Extract { .. }) => held,
        Operand::Reduce(ref operand) => committed(operand.destination),
        Operand::Compare { destination, .. } | Operand::Integer { destination, .. } => {
            committed(destination)
        }
        Operand::Immediate(crate::aarch64::simd::immediates::Operand::Constant {
            destination,
            ..
        }) => committed(destination),
        Operand::Memory {
            load,
            bytes,
            vector,
            ..
        } => memory::transfers_xmm0(load, bytes).then_some(vector),
        Operand::MemoryRegisterOffset(ref operand) => {
            memory::transfers_xmm0(operand.load, operand.bytes).then_some(operand.vector)
        }
        Operand::MoveImmediate { vector, .. } => Some(vector),
        _ => None,
    }
}

/// [`read_vector`]'s bytes for `vector` into XMM0, which an emission that
/// begins with them does not need where XMM0 holds the vector already.
pub(super) fn xmm0_load(vector: u8) -> Vec<u8> {
    let mut load = Code::new();
    read_vector(&mut load, vector, 0);
    load.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::{AddressMode, Register};
    use alloc::vec;

    mod numerical_boundary {
        use crate::{GuestAddress, block};
        use alloc::vec::Vec;

        const FCVT_H_S: u32 = 0x1e23c020;
        const SCVTF_H_W: u32 = 0x1ee20020;
        const FCVTAS_W_S: u32 = 0x1e240020;
        const FJCVTZS_W_D: u32 = 0x1e7e0020;
        const FCVT_S_H: u32 = 0x1ee24020;
        const SCVTF_S_W: u32 = 0x1e220020;
        const FCVTL_4S_4H: u32 = 0x0e217820;
        const UNSUPPORTED_SUFFIX: u32 = u32::MAX;

        #[test]
        fn terminal_conversions_do_not_consume_or_validate_an_unreached_suffix() {
            for word in [FCVT_H_S, SCVTF_H_W, FCVTAS_W_S] {
                let bytes: Vec<u8> = [word, UNSUPPORTED_SUFFIX]
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect();
                let compiled = block::compile(&bytes, GuestAddress(0x1000)).unwrap();
                assert_eq!(compiled.source_bytes, size_of::<u32>());
                assert_eq!(compiled.native.source_map, [(GuestAddress(0x1000), 0)]);
            }
            for word in [FCVT_S_H, SCVTF_S_W, FCVTL_4S_4H, FJCVTZS_W_D] {
                let bytes: Vec<u8> = [word, UNSUPPORTED_SUFFIX]
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect();
                assert!(block::compile(&bytes, GuestAddress(0x1000)).is_err());
            }
        }
    }

    #[test]
    fn q_load_is_unaligned_staged_and_committed_before_writeback() {
        let mut code = Code::new();
        emit(
            &mut code,
            &Operand::Memory {
                load: true,
                bytes: 16,
                vector: 31,
                base: Register::Sp,
                displacement: -16,
                mode: AddressMode::PreIndex,
            },
        );
        assert_eq!(&code[7..13], &[0xa8, 15, 0x74, 2, 0x0f, 0x0b]);
        let suffix = [
            0xf3, 0x0f, 0x6f, 0x00, 0xf3, 0x0f, 0x7f, 0x87, 0xf8, 2, 0, 0, 0x48, 0x89, 0x97, 248,
            0, 0, 0,
        ];
        assert!(code.ends_with(&suffix));
    }

    #[test]
    fn scalar_accesses_use_exact_width_and_zero_high_vector_bits() {
        for (bytes, load_bytes, store_bytes) in [
            (
                1,
                vec![0x0f, 0xb6, 0x08, 0x66, 0x0f, 0x6e, 0xc1],
                vec![0x88, 0x08],
            ),
            (
                2,
                vec![0x0f, 0xb7, 0x08, 0x66, 0x0f, 0x6e, 0xc1],
                vec![0x66, 0x89, 0x08],
            ),
            (4, vec![0x66, 0x0f, 0x6e, 0], vec![0x66, 0x0f, 0x7e, 0]),
            (8, vec![0xf3, 0x0f, 0x7e, 0], vec![0x66, 0x0f, 0xd6, 0]),
        ] {
            for load in [false, true] {
                let mut code = Code::new();
                emit(
                    &mut code,
                    &Operand::Memory {
                        load,
                        bytes,
                        vector: 0,
                        base: Register::X(0),
                        displacement: 0,
                        mode: AddressMode::Offset,
                    },
                );
                if load {
                    assert!(code[7..].starts_with(&load_bytes));
                    assert!(code.ends_with(&[0xf3, 0x0f, 0x7f, 0x87, 8, 1, 0, 0]));
                } else {
                    assert!(code.ends_with(&store_bytes));
                }
            }
        }
    }

    #[test]
    fn movi_d_clears_high_half_and_two_d_replicates_without_new_cpu_features() {
        for two_lanes in [false, true] {
            let mut code = Code::new();
            emit(
                &mut code,
                &Operand::MoveImmediate {
                    vector: 31,
                    mask: 0xff00ff00ff00ff00,
                    two_lanes,
                },
            );
            assert_eq!(&code[..2], &[0x48, 0xb9]);
            assert_eq!(&code[2..10], &0xff00ff00ff00ff00u64.to_le_bytes());
            assert_eq!(&code[10..15], &[0x66, 0x48, 0x0f, 0x6e, 0xc1]);
            if two_lanes {
                assert_eq!(&code[15..19], &[0x66, 0x0f, 0x6c, 0xc0]);
            }
            assert!(code.ends_with(&[0xf3, 0x0f, 0x7f, 0x87, 0xf8, 2, 0, 0]));
        }
    }

    #[test]
    fn zero_byte_masks_share_compact_full_vector_zeroing() {
        for two_lanes in [false, true] {
            let mut code = Code::new();
            emit(
                &mut code,
                &Operand::MoveImmediate {
                    vector: 0,
                    mask: 0,
                    two_lanes,
                },
            );
            assert_eq!(
                code,
                [0x66, 0x0f, 0xef, 0xc0, 0xf3, 0x0f, 0x7f, 0x87, 8, 1, 0, 0]
            );
        }
    }

    #[test]
    fn pair_loads_stage_both_exact_width_values_before_guest_commits_and_writeback() {
        for (bytes, prefix, opcode) in [(4, 0x66, 0x6e), (8, 0xf3, 0x7e), (16, 0xf3, 0x6f)] {
            let mut code = Code::new();
            emit(
                &mut code,
                &Operand::MemoryPair {
                    load: true,
                    bytes,
                    vectors: [0, 31],
                    base: Register::X(0),
                    displacement: -64,
                    mode: AddressMode::PreIndex,
                },
            );
            assert_eq!(
                &code[14..23],
                &[prefix, 0x0f, opcode, 0, prefix, 0x0f, opcode, 0x48, bytes]
            );
            assert_eq!(&code[23..31], &[0xf3, 0x0f, 0x7f, 0x87, 8, 1, 0, 0]);
            assert_eq!(&code[31..39], &[0xf3, 0x0f, 0x7f, 0x8f, 0xf8, 2, 0, 0]);
            assert_eq!(&code[39..], &[0x48, 0x89, 0x97, 0, 0, 0, 0]);
        }
    }

    #[test]
    fn pair_stores_capture_duplicate_sources_before_two_writes_and_delay_writeback() {
        for (bytes, prefix, opcode) in [(4, 0x66, 0x7e), (8, 0x66, 0xd6), (16, 0xf3, 0x7f)] {
            let mut code = Code::new();
            emit(
                &mut code,
                &Operand::MemoryPair {
                    load: false,
                    bytes,
                    vectors: [31, 31],
                    base: Register::Sp,
                    displacement: 32,
                    mode: AddressMode::PostIndex,
                },
            );
            assert_eq!(&code[7..13], &[0xa8, 15, 0x74, 2, 0x0f, 0x0b]);
            assert_eq!(&code[17..25], &[0xf3, 0x0f, 0x6f, 0x87, 0xf8, 2, 0, 0]);
            assert_eq!(&code[25..33], &[0xf3, 0x0f, 0x6f, 0x8f, 0xf8, 2, 0, 0]);
            assert_eq!(
                &code[33..42],
                &[prefix, 0x0f, opcode, 0, prefix, 0x0f, opcode, 0x48, bytes]
            );
            assert_eq!(&code[42..], &[0x48, 0x89, 0x97, 248, 0, 0, 0]);
        }
    }
}
