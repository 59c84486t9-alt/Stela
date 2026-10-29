//! SVE URECPE and URSQRTE by table lookup.
use crate::x86_64::asm::Gpr::{Rax, Rdx};
use crate::x86_64::asm::{Alu, Code, Cond, Disp, Mem, ShiftOp, Size};
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures},
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        simd::estimate::Kind as EstimateKind,
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
    },
};
use alloc::vec::Vec;

const SOURCE: u8 = 0;
const ACTIVE: u8 = 1;
const MERGE: u8 = 2;
const RESULT: u8 = 3;
const CANDIDATE: u8 = 4;
const OUTPUT_SLOT: usize = 0;
const DWORD_BYTES: usize = core::mem::size_of::<u32>();
const REL32_BYTES: usize = core::mem::size_of::<i32>();
const ESTIMATE_FRACTION_BITS: u32 = 8;
const ESTIMATE_UNIT: u32 = 1 << ESTIMATE_FRACTION_BITS;
const ESTIMATE_INPUT_SHIFT: u8 = (u32::BITS - ESTIMATE_FRACTION_BITS - 1) as u8;
const RECIPROCAL_FIRST_BIN: u32 = ESTIMATE_UNIT;
const RSQRT_FIRST_BIN: u32 = ESTIMATE_UNIT / 2;
const LAST_BIN_EXCLUSIVE: u32 = ESTIMATE_UNIT * 2;

/// Point the RIP-relative displacement field at `displacement` to `destination`.
fn patch_rip(code: &mut Code, displacement: usize, destination: usize) {
    let relative = i32::try_from(destination as i64 - (displacement + REL32_BYTES) as i64)
        .expect("unsigned estimate body exceeds rel32 range");
    code.patch(displacement, relative.to_le_bytes());
}

fn first_bin(kind: EstimateKind) -> u32 {
    match kind {
        EstimateKind::UnsignedReciprocal => RECIPROCAL_FIRST_BIN,
        EstimateKind::UnsignedReciprocalSquareRoot => RSQRT_FIRST_BIN,
        _ => unreachable!("validated unsigned estimate kind"),
    }
}

pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    _features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Kind::Estimate(
        kind @ (EstimateKind::UnsignedReciprocal | EstimateKind::UnsignedReciprocalSquareRoot),
    ) = operand.kind
    else {
        return Ok(false);
    };
    let (Inputs::Unary { source }, Some(predicate)) = (operand.inputs, operand.predicate) else {
        return Ok(false);
    };
    if operand.format != Format::Single || operand.shape != ResultShape::Vector {
        return Ok(false);
    }
    // The checked lookup wins on the measured one-chunk RAW recurrence.
    // Unsigned estimates ignore numerical features and every FP control.
    // Preserve the lookup recipe for distinct source/destination registers.
    let checked = length.bytes() == VECTOR_CHUNK_BYTES
        && source == operand.destination
        && target.supports(TargetCpu::Sse41);
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::Exact,
    )?;
    let mut table_addresses = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            predicate,
            chunk,
            ElementSize::Word,
            crate::x86_64::scalable::MaskRegisters::new(ACTIVE, MERGE),
            length,
            target,
        );
        load_z_chunk(code, source, chunk, SOURCE, length, target);

        code.asm().lea(Size::Qword, Rdx, Mem::rip(0));
        table_addresses.push(code.len() - REL32_BYTES);

        for lane in 0..VECTOR_CHUNK_BYTES / DWORD_BYTES {
            if checked {
                code.asm().pextrd(Rax, SOURCE, lane as u8);
            } else {
                code.asm().movd_from_xmm(Rax, SOURCE);
            }

            let mut asm = code.asm();
            asm.shift_imm(ShiftOp::Shr, Size::Dword, Rax, ESTIMATE_INPUT_SHIFT);
            asm.alu_accumulator_imm32(Alu::Cmp, Size::Dword, first_bin(kind) as i32);
            let below = asm.jcc(Cond::B);
            asm.movzx(
                Size::Dword,
                Rax,
                Size::Byte,
                Mem::indexed(Rdx, Rax, 1, -(first_bin(kind) as i32)).with_width(Disp::Dword),
            );
            asm.alu_accumulator_imm32(Alu::Or, Size::Dword, ESTIMATE_UNIT as i32);
            asm.shift_imm(ShiftOp::Shl, Size::Dword, Rax, ESTIMATE_INPUT_SHIFT);
            let valid = asm.jmp();
            asm.bind(below);
            asm.mov_imm32(Rax, u32::MAX);
            asm.bind(valid);

            if checked {
                code.asm().pinsrd(RESULT, Rax, lane as u8);
            } else {
                if lane == 0 {
                    // MOVQ writes the first dword and clears every upper byte.
                    code.asm().simd(Host::MoveGprQword, RESULT, Rax, target);
                } else {
                    code.asm().simd(Host::MoveGprQword, CANDIDATE, Rax, target);
                    ShiftOpcode::LeftBytes.emit(code, CANDIDATE, (lane * DWORD_BYTES) as u8);
                    Host::Or.register(code, RESULT, CANDIDATE, target);
                }
                if lane + 1 != VECTOR_CHUNK_BYTES / DWORD_BYTES {
                    ShiftOpcode::RightBytes.emit(code, SOURCE, DWORD_BYTES as u8);
                }
            }
        }
        load_z_chunk(code, operand.destination, chunk, MERGE, length, target);
        Host::And.register(code, RESULT, ACTIVE, target);
        Host::AndNot.register(code, ACTIVE, MERGE, target);
        Host::Or.register(code, RESULT, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT, target);
    }
    numerical::finish(code, &frame, &[], pc, target);

    let mut asm = code.asm();
    let skip = asm.jmp();
    let table_start = asm.len();
    for scaled in first_bin(kind)..LAST_BIN_EXCLUSIVE {
        // Compile-time only: compact exact architectural table; no host
        // address, CALL, mutable storage or runtime FP operation is emitted.
        let result = crate::aarch64::floating::estimate::evaluate(
            kind,
            Format::Single,
            0,
            u64::from(scaled) << ESTIMATE_INPUT_SHIFT,
        )
        .expect("unsigned estimate ignores every control");
        let estimate = (result.bits >> ESTIMATE_INPUT_SHIFT) as u32;
        asm.data(&[u8::try_from(estimate - ESTIMATE_UNIT).expect("estimate table byte")]);
    }
    asm.bind(skip);
    for displacement in table_addresses {
        patch_rip(code, displacement, table_start);
    }

    Ok(true)
}
