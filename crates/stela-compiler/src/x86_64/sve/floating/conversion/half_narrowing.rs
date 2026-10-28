//! SVE conversions narrowing to half precision.
use crate::x86_64::asm::Gpr::{R10, Rax, Rcx};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Rm, Size};
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures, precision::PrecisionRounding},
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sve::floating::conversion::{Kind, Operand, Placement},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::{half::emit_normal_or_zero, numerical::rounding_control},
        sve::floating::classify::guard_active_exception_enables,
    },
};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const SOURCE: u8 = 1;
const SCRATCH: u8 = 2;
const PACK_INPUT: u8 = 6;
const ACTIVE: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const HALF_BYTES: usize = size_of::<u16>();
const BITS_PER_BYTE: u32 = u8::BITS;

fn insert_half(code: &mut Code, gpr: Gpr, byte_offset: usize) {
    assert!(byte_offset < VECTOR_CHUNK_BYTES && byte_offset.is_multiple_of(HALF_BYTES));
    code.asm()
        .pinsrw(RESULT, gpr, (byte_offset / HALF_BYTES) as u8);
}

pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let (source, placement) = match operand.kind {
        Kind::Precision {
            source: Format::Single,
            destination: Format::Half,
            rounding: PrecisionRounding::Fpcr,
            placement: placement @ (Placement::Low | Placement::UpperDestination),
        } => (Format::Single, placement),
        Kind::Precision {
            source: Format::Double,
            destination: Format::Half,
            rounding: PrecisionRounding::Fpcr,
            placement: Placement::Low,
        } => (Format::Double, Placement::Low),
        _ => return Ok(false),
    };
    let slot_bytes = (source.bits() / BITS_PER_BYTE) as usize;
    let element = ElementSize::from_bytes(slot_bytes).expect("typed precision source size");
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    rounding_control(code);
    numerical::install_mxcsr(code, &frame);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            operand.governing,
            chunk,
            element,
            ACTIVE,
            SCRATCH,
            length,
            target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, operand.source, chunk, SOURCE, length, target);
        load_z_chunk(code, operand.destination, chunk, RESULT, length, target);
        code.asm().alu(Alu::Xor, Size::Dword, R10, R10);
        for slot in (0..VECTOR_CHUNK_BYTES).step_by(slot_bytes) {
            Host::MoveAligned.register(code, SCRATCH, ACTIVE, target);
            if slot != 0 {
                ShiftOpcode::RightBytes.emit(code, SCRATCH, slot as u8);
            }
            let mut asm = code.asm();
            asm.movd_from_xmm(Rax, SCRATCH);
            asm.test(Size::Dword, Rax, Rax);
            let inactive = asm.jcc(Cond::E);
            Host::MoveAligned.register(code, PACK_INPUT, SOURCE, target);
            if slot != 0 {
                ShiftOpcode::RightBytes.emit(code, PACK_INPUT, slot as u8);
            }
            if source == Format::Single {
                // Private masks prevent host traps on exceptional temporary
                // inputs. Any widening status takes whole completion before
                // packing; no intermediate status is mapped to guest FPSR.
                numerical::clear_status(code, &frame);
                code.asm().cvtss2sd(PACK_INPUT, Rm::Xmm(PACK_INPUT));
                numerical::capture_status(code, &frame);
                let mut asm = code.asm();
                asm.test(Size::Dword, Rcx, Rcx);
                failures.push(asm.jcc(Cond::Ne).offset());
            }
            emit_normal_or_zero(code, &mut failures);
            let destination_offset = if placement == Placement::UpperDestination {
                HALF_BYTES
            } else {
                0
            };
            insert_half(code, Rax, slot + destination_offset);
            if placement == Placement::Low {
                // Ordinary precision narrowing zero-extends the whole source
                // slot. Top narrowing replaces exactly its high Half instead.
                code.asm().alu(Alu::Xor, Size::Dword, Rcx, Rcx);
                for upper in (slot + HALF_BYTES..slot + slot_bytes).step_by(HALF_BYTES) {
                    insert_half(code, Rcx, upper);
                }
            }
            code.asm().bind(inactive);
        }
        // Consume private IXC before the next predicate/access helper reload.
        code.asm().mov(Size::Dword, Rax, R10);
        numerical::add_fpsr(code, &frame);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
