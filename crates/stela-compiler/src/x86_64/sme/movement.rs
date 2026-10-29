//! ZA moves and zeroing. R8 holds the selected ZA address across helper calls,
//! which clobber only RAX/RCX/RDX.
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Mem, ShiftOp, Size, resolve};
use crate::x86_64::simd::encode::guest;

use super::super::{
    isa::{ShiftOpcode, SimdOpcode as Host},
    scalable::{load_z_chunk, read_predicate_mask, store_z_chunk},
    scalable_matrix::{load_za_chunk_at_r8, load_za_pointer_r8, store_za_chunk_at_r8},
};
use crate::{
    GuestState, TargetCpu,
    aarch64::{
        scalable::{ElementSize, Predication, VECTOR_CHUNK_BYTES, VectorLength},
        sme::movement::{Direction, Kind, Operand},
    },
    context::{EXECUTION_CONTEXT_SCALABLE_OFFSET, SCALABLE_ZT0_OFFSET},
};

const VALUE: u8 = 0;
const PREVIOUS: u8 = 1;
const GATHER_SCRATCH: u8 = 2;
const GATHER_HIGH: u8 = 3;
const MASK: u8 = 4;
const MASK_SCRATCH: u8 = 5;
const ZERO: u8 = 6;
const GPR_BYTES: usize = core::mem::size_of::<u64>();
const D_TILE_COUNT: usize = 8;
const ZT0_BYTES: usize = 64;
const BYTE_BITS: u8 = u8::BITS as u8;
/// R8 holds the selected ZA (or ZT0) address.
const ZA: Gpr = Gpr::R8;
use Gpr::{Rax, Rcx};

/// `[r8 + displacement]` with a 32-bit displacement.
fn za(displacement: usize) -> Mem {
    Mem::base_disp32(ZA, displacement as i32)
}

/// Why an SME movement cannot be emitted in the supplied execution context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    StreamingLength {
        required_bits: usize,
        actual_bits: usize,
    },
    RequiresHaltedDebug,
    DebugOperand {
        kind: Kind,
    },
    DebugRegisterLane {
        register: u8,
        lane: u8,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StreamingLength {
                required_bits,
                actual_bits,
            } => write!(
                f,
                "SME movement requires {required_bits} streaming bits, got {actual_bits}"
            ),
            Self::RequiresHaltedDebug => {
                f.write_str("MOVT GPR/ZT0 requires a halted debug execution context")
            }
            Self::DebugOperand { kind } => write!(
                f,
                "halted MOVT emitter requires TableGpr operands, got {kind:?}"
            ),
            Self::DebugRegisterLane { register, lane } => write!(
                f,
                "invalid halted MOVT register {register} or table lane {lane}"
            ),
        }
    }
}

impl core::error::Error for Error {}

pub(crate) fn emit(
    code: &mut Code,
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
) -> Result<(), Error> {
    if length.bits() < usize::from(operand.requirements.minimum_current_svl_bits) {
        return Err(Error::StreamingLength {
            required_bits: usize::from(operand.requirements.minimum_current_svl_bits),
            actual_bits: length.bits(),
        });
    }
    if matches!(operand.kind, Kind::TableGpr { .. }) {
        return Err(Error::RequiresHaltedDebug);
    }
    match operand.kind {
        Kind::Tile {
            direction,
            element,
            tile,
            vertical,
            index,
            offset,
            vector,
            count,
            predication,
            zero_source,
        } => {
            load_za_pointer_r8(code);
            let dimension = length.lanes(element);
            index_offset(code, index, offset, usize::from(count), dimension);
            let index_scale = if vertical {
                element.bytes()
            } else {
                element.bytes() * length.bytes()
            };
            scale_index(code, index_scale);
            add_address(code, usize::from(tile) * length.bytes());
            add_index(code);
            for register in 0..count {
                for chunk in 0..length.chunks() {
                    if direction == Direction::ToZa {
                        load_z_chunk(code, vector + register, chunk, VALUE, length, target);
                    } else {
                        load_slice(code, VALUE, chunk, element, vertical, length, target);
                    }
                    if let Predication::Merging(predicate) = predication {
                        if direction == Direction::ToZa {
                            load_slice(code, PREVIOUS, chunk, element, vertical, length, target);
                        } else {
                            load_z_chunk(code, vector + register, chunk, PREVIOUS, length, target);
                        }
                        read_predicate_mask(
                            code,
                            predicate,
                            chunk,
                            element,
                            crate::x86_64::scalable::MaskRegisters::new(MASK, MASK_SCRATCH),
                            length,
                            target,
                        );
                        Host::And.register(code, VALUE, MASK, target);
                        Host::AndNot.register(code, MASK, PREVIOUS, target);
                        Host::Or.register(code, VALUE, MASK, target);
                    }
                    if direction == Direction::ToZa {
                        store_slice(code, VALUE, chunk, element, vertical, length, target);
                    } else {
                        store_z_chunk(code, vector + register, chunk, VALUE, length, target);
                        if zero_source {
                            Host::Xor.register(code, ZERO, ZERO, target);
                            store_slice(code, ZERO, chunk, element, vertical, length, target);
                        }
                    }
                }
                if register + 1 < count {
                    add_address(code, index_scale);
                }
            }
        }
        Kind::Vectors {
            direction,
            index,
            offset,
            vector,
            count,
            zero_source,
        } => {
            load_za_pointer_r8(code);
            let stride = length.bytes() / usize::from(count);
            index_offset(code, index, offset, 1, stride);
            scale_index(code, length.bytes());
            add_index(code);
            for register in 0..count {
                for chunk in 0..length.chunks() {
                    if direction == Direction::ToZa {
                        load_z_chunk(code, vector + register, chunk, VALUE, length, target);
                        contiguous(
                            code,
                            Host::StoreUnaligned,
                            VALUE,
                            chunk * VECTOR_CHUNK_BYTES,
                        );
                    } else {
                        contiguous(code, Host::LoadUnaligned, VALUE, chunk * VECTOR_CHUNK_BYTES);
                        store_z_chunk(code, vector + register, chunk, VALUE, length, target);
                        if zero_source {
                            Host::Xor.register(code, ZERO, ZERO, target);
                            contiguous(
                                code,
                                Host::StoreUnaligned,
                                ZERO,
                                chunk * VECTOR_CHUNK_BYTES,
                            );
                        }
                    }
                }
                if register + 1 < count {
                    add_address(code, stride * length.bytes());
                }
            }
        }
        Kind::ZeroVectors {
            index,
            offset,
            vectors_per_group,
            groups,
        } => {
            load_za_pointer_r8(code);
            let stride = length.bytes() / usize::from(groups);
            index_offset(code, index, offset, 1, stride);
            code.asm().alu_accumulator_imm32(
                Alu::And,
                Size::Dword,
                !u32::from(vectors_per_group - 1) as i32,
            );
            scale_index(code, length.bytes());
            add_index(code);
            Host::Xor.register(code, ZERO, ZERO, target);
            for group in 0..groups {
                for chunk in 0..length.chunks() * usize::from(vectors_per_group) {
                    contiguous(code, Host::StoreUnaligned, ZERO, chunk * VECTOR_CHUNK_BYTES);
                }
                if group + 1 < groups {
                    add_address(code, stride * length.bytes());
                }
            }
        }
        Kind::ZeroTiles { mask } => {
            if mask == 0 {
                return Ok(());
            }
            Host::Xor.register(code, ZERO, ZERO, target);
            if mask == u8::MAX {
                load_za_pointer_r8(code);
                zero_rows(code, length.bytes(), length.bytes(), length, ZERO);
            } else {
                for tile in 0..D_TILE_COUNT {
                    if mask & (1 << tile) == 0 {
                        continue;
                    }
                    load_za_pointer_r8(code);
                    add_address(code, tile * length.bytes());
                    zero_rows(
                        code,
                        length.bytes() / D_TILE_COUNT,
                        length.bytes() * D_TILE_COUNT,
                        length,
                        ZERO,
                    );
                }
            }
        }
        Kind::ZeroTable => {
            pointer(code, SCALABLE_ZT0_OFFSET);
            Host::Xor.register(code, ZERO, ZERO, target);
            for chunk in 0..ZT0_BYTES / VECTOR_CHUNK_BYTES {
                contiguous(code, Host::StoreUnaligned, ZERO, chunk * VECTOR_CHUNK_BYTES);
            }
        }
        Kind::TableGpr { .. } => unreachable!("debug MOVT rejected before output"),
    }
    Ok(())
}

/// Called only by the halted-ITR entry; the ordinary movement emitter still
/// rejects TableGpr.
pub(crate) fn emit_debug_table_gpr(
    code: &mut Code,
    operand: &Operand,
    recipe: crate::scalable_context::debug_movement::Recipe,
) -> Result<(), Error> {
    use crate::scalable_context::debug_movement::Recipe;
    const ZERO_REGISTER: u8 = 31;
    const TABLE_LANES: u8 = 8;
    let Kind::TableGpr {
        direction,
        register,
        lane,
    } = operand.kind
    else {
        return Err(Error::DebugOperand { kind: operand.kind });
    };
    if register > ZERO_REGISTER || lane >= TABLE_LANES {
        return Err(Error::DebugRegisterLane { register, lane });
    }
    if direction == Direction::FromZa && register == ZERO_REGISTER {
        return Ok(());
    }
    pointer(code, SCALABLE_ZT0_OFFSET);
    let state =
        guest((core::mem::offset_of!(GuestState, x) + usize::from(register) * GPR_BYTES) as u32);
    let entry = Mem::base_disp8(ZA, (lane * GPR_BYTES as u8) as i8);
    let baseline = TargetCpu::Baseline;
    match (direction, recipe) {
        (Direction::ToZa, Recipe::Scalar) => {
            let mut asm = code.asm();
            if register == ZERO_REGISTER {
                asm.alu(Alu::Xor, Size::Dword, Rax, Rax);
            } else {
                asm.mov_load(Size::Qword, Rax, state);
            }
            asm.mov_store(Size::Qword, entry, Rax);
        }
        (Direction::FromZa, Recipe::Scalar) => {
            let mut asm = code.asm();
            asm.mov_load(Size::Qword, Rax, entry);
            asm.mov_store(Size::Qword, state, Rax);
        }
        (Direction::ToZa, Recipe::Sse2Comparison) => {
            if register == ZERO_REGISTER {
                Host::Xor.register(code, VALUE, VALUE, baseline);
            } else {
                Host::MoveQword.emit(code, VALUE, state, baseline);
            }
            code.asm().movq_store(VALUE, entry);
        }
        (Direction::FromZa, Recipe::Sse2Comparison) => {
            Host::MoveQword.emit(code, VALUE, entry, baseline);
            code.asm().movq_store(VALUE, state);
        }
    }
    Ok(())
}

/// `mov r8, [r15 + scalable]; mov r8, [r8 + field]`: R8 points at the
/// scalable context `field`.
fn pointer(code: &mut Code, field: u32) {
    let mut asm = code.asm();
    asm.mov_load(
        Size::Qword,
        ZA,
        Mem::base_disp8(Gpr::R15, EXECUTION_CONTEXT_SCALABLE_OFFSET as i8),
    );
    asm.mov_load(Size::Qword, ZA, Mem::base_disp8(ZA, field as i8));
}

fn index_offset(code: &mut Code, register: u8, offset: u8, align: usize, modulus: usize) {
    let mut asm = code.asm();
    asm.mov_load(
        Size::Dword,
        Rax,
        guest(core::mem::offset_of!(GuestState, x) as u32 + u32::from(register) * GPR_BYTES as u32),
    );
    if align > 1 {
        asm.alu_accumulator_imm32(Alu::And, Size::Dword, !(align as u32 - 1) as i32);
    }
    if offset != 0 {
        asm.alu_accumulator_imm32(Alu::Add, Size::Dword, offset.into());
    }
    // All supported SME lengths and all divisors here are powers of two. A
    // wrapped 32-bit addition therefore has the same residue as UInt(W)+offset.
    asm.alu_accumulator_imm32(Alu::And, Size::Dword, (modulus as u32 - 1) as i32);
}

fn scale_index(code: &mut Code, scale: usize) {
    debug_assert!(scale.is_power_of_two());
    if scale > 1 {
        code.asm()
            .shift_imm(ShiftOp::Shl, Size::Dword, Rax, scale.trailing_zeros() as u8);
    }
}

/// `add r8, rax`: apply the scaled slice index.
fn add_index(code: &mut Code) {
    code.asm().alu(Alu::Add, Size::Qword, ZA, Rax);
}

fn add_address(code: &mut Code, displacement: usize) {
    if displacement != 0 {
        code.asm()
            .alu_imm32(Alu::Add, Size::Qword, ZA, displacement as i32);
    }
}

fn contiguous(code: &mut Code, opcode: Host, xmm: u8, displacement: usize) {
    match opcode {
        Host::LoadUnaligned => {
            load_za_chunk_at_r8(code, xmm, displacement as u32, TargetCpu::Baseline);
            return;
        }
        Host::StoreUnaligned => {
            store_za_chunk_at_r8(code, xmm, displacement as u32, TargetCpu::Baseline);
            return;
        }
        Host::MoveQword => {}
        _ => unreachable!("movement memory uses MOVDQU or MOVQ only"),
    }
    opcode.emit(code, xmm, za(displacement), TargetCpu::Baseline);
}

fn load_slice(
    code: &mut Code,
    output: u8,
    chunk: usize,
    element: ElementSize,
    vertical: bool,
    length: VectorLength,
    target: TargetCpu,
) {
    if !vertical || element == ElementSize::Quadword {
        let offset = if vertical {
            chunk * element.bytes() * length.bytes()
        } else {
            chunk * VECTOR_CHUNK_BYTES
        };
        contiguous(code, Host::LoadUnaligned, output, offset);
        return;
    }
    let size = element.bytes();
    let first = chunk * VECTOR_CHUNK_BYTES / size;
    let address = |lane| (first + lane) * size * length.bytes();
    match element {
        ElementSize::Byte => {
            for pair in 0..VECTOR_CHUNK_BYTES / 2 {
                let mut asm = code.asm();
                asm.movzx(Size::Dword, Rax, Size::Byte, za(address(pair * 2)));
                asm.movzx(Size::Dword, Rcx, Size::Byte, za(address(pair * 2 + 1)));
                asm.shift_imm(ShiftOp::Shl, Size::Dword, Rcx, BYTE_BITS);
                asm.alu(Alu::Or, Size::Dword, Rax, Rcx);
                asm.pinsrw(output, Rax, pair as u8);
            }
        }
        ElementSize::Halfword => {
            for lane in 0..VECTOR_CHUNK_BYTES / size {
                code.asm().pinsrw(output, za(address(lane)), lane as u8);
            }
        }
        ElementSize::Word => {
            let mut asm = code.asm();
            asm.movd_to_xmm(output, za(address(0)));
            asm.movd_to_xmm(GATHER_SCRATCH, za(address(1)));
            Host::UnpackLowDword.register(code, output, GATHER_SCRATCH, target);
            let mut asm = code.asm();
            asm.movd_to_xmm(GATHER_SCRATCH, za(address(2)));
            asm.movd_to_xmm(GATHER_HIGH, za(address(3)));
            Host::UnpackLowDword.register(code, GATHER_SCRATCH, GATHER_HIGH, target);
            Host::UnpackLowQword.register(code, output, GATHER_SCRATCH, target);
        }
        ElementSize::Doubleword => {
            contiguous(code, Host::MoveQword, output, address(0));
            code.asm().movhps(output, za(address(1)));
        }
        ElementSize::Quadword => unreachable!("contiguous quadword handled above"),
    }
}

fn store_slice(
    code: &mut Code,
    input: u8,
    chunk: usize,
    element: ElementSize,
    vertical: bool,
    length: VectorLength,
    target: TargetCpu,
) {
    if !vertical || element == ElementSize::Quadword {
        let offset = if vertical {
            chunk * element.bytes() * length.bytes()
        } else {
            chunk * VECTOR_CHUNK_BYTES
        };
        contiguous(code, Host::StoreUnaligned, input, offset);
        return;
    }
    let size = element.bytes();
    let first = chunk * VECTOR_CHUNK_BYTES / size;
    let address = |lane| (first + lane) * size * length.bytes();
    if element == ElementSize::Doubleword && target.supports(TargetCpu::Sse41) {
        for lane in 0..VECTOR_CHUNK_BYTES / size {
            code.asm().pextrq(za(address(lane)), input, lane as u8);
        }
        return;
    }
    match element {
        ElementSize::Byte | ElementSize::Halfword => {
            for pair in 0..VECTOR_CHUNK_BYTES / 2 {
                let mut asm = code.asm();
                asm.pextrw(Rax, input, pair as u8);
                if element == ElementSize::Byte {
                    asm.mov_store(Size::Byte, za(address(pair * 2)), Rax);
                    asm.shift_imm(ShiftOp::Shr, Size::Dword, Rax, BYTE_BITS);
                    asm.mov_store(Size::Byte, za(address(pair * 2 + 1)), Rax);
                } else {
                    asm.mov_store(Size::Word, za(address(pair)), Rax);
                }
            }
        }
        ElementSize::Word | ElementSize::Doubleword => {
            for lane in 0..VECTOR_CHUNK_BYTES / size {
                let mut asm = code.asm();
                if element == ElementSize::Word {
                    asm.movd_from_xmm(Rax, input);
                    asm.mov_store(Size::Dword, za(address(lane)), Rax);
                } else {
                    asm.movq_from_xmm(Rax, input);
                    asm.mov_store(Size::Qword, za(address(lane)), Rax);
                }
                if lane + 1 < VECTOR_CHUNK_BYTES / size {
                    ShiftOpcode::RightBytes.emit(code, input, size as u8);
                }
            }
        }
        ElementSize::Quadword => unreachable!("contiguous quadword handled above"),
    }
}

fn zero_rows(code: &mut Code, count: usize, step: usize, length: VectorLength, zero: u8) {
    code.asm().mov_imm32(Rcx, count as u32);
    let start = code.len();
    for chunk in 0..length.chunks() {
        contiguous(code, Host::StoreUnaligned, zero, chunk * VECTOR_CHUNK_BYTES);
    }
    add_address(code, step);
    let mut asm = code.asm();
    asm.dec(Size::Dword, Rcx);
    let repeat = asm.jcc(Cond::Ne);
    resolve(code, repeat, start);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::sme::movement::decode;

    #[test]
    fn rejected_debug_and_short_length_emit_nothing() {
        let length = VectorLength::from_bytes(16).unwrap();
        for word in [
            0xc04c_03e0,
            0xc04e_03e0,
            0xc0c6_0400,
            0xc0c6_0600,
            0xc0c4_0400,
        ] {
            let operand = decode(word).unwrap();
            let mut code = Code::new();
            code.asm().nop();
            let error = emit(&mut code, &operand, length, TargetCpu::Baseline).unwrap_err();
            assert!(matches!(
                error,
                Error::StreamingLength { .. } | Error::RequiresHaltedDebug
            ));
            assert_eq!(code, [0x90]);
        }
    }

    #[test]
    fn empty_tile_mask_has_no_output_and_full_mask_is_bounded() {
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            let mut code = Code::new();
            emit(
                &mut code,
                &decode(0xc008_0000).unwrap(),
                length,
                TargetCpu::Baseline,
            )
            .unwrap();
            assert!(code.is_empty());
            emit(
                &mut code,
                &decode(0xc008_00ff).unwrap(),
                length,
                TargetCpu::Baseline,
            )
            .unwrap();
            assert!(code.len() < 256);
        }
    }

    #[test]
    fn only_vertical_doubleword_scatter_uses_checked_extension() {
        let length = VectorLength::from_bytes(64).unwrap();
        for word in [
            0xc000_8000,
            0xc040_8000,
            0xc080_8000,
            0xc0c0_0000,
            0xc0c2_8000,
        ] {
            let operand = decode(word).unwrap();
            let mut baseline = Code::new();
            let mut checked = Code::new();
            emit(&mut baseline, &operand, length, TargetCpu::Baseline).unwrap();
            emit(&mut checked, &operand, length, TargetCpu::Sse41).unwrap();
            assert_eq!(baseline, checked);
        }
        let operand = decode(0xc0c0_8000).unwrap();
        let mut baseline = Code::new();
        let mut checked = Code::new();
        emit(&mut baseline, &operand, length, TargetCpu::Baseline).unwrap();
        emit(&mut checked, &operand, length, TargetCpu::Sse41).unwrap();
        assert!(checked.len() < baseline.len());
    }
}
