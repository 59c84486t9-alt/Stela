//! SVE integer complex multiplies with rounding (SQRDCMLAH, ...).
use crate::TargetCpu;
use crate::aarch64::Unsupported;
use crate::aarch64::scalable::{ElementSize, VECTOR_CHUNK_BYTES};
use crate::aarch64::sve::integer_products::Kind;
use crate::x86_64::asm::Gpr::{Rax, Rsp};
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, Size};

use super::complex_wrapping::{blend_directions, prepare_products};
use super::emit_saturating_chunk;
use super::saturating::emit_rounded_scalar;

const SOURCE_N_OFFSET: u8 = 0;
const SOURCE_M_OFFSET: u8 = VECTOR_CHUNK_BYTES as u8;
const ACCUMULATOR_OFFSET: u8 = (2 * VECTOR_CHUNK_BYTES) as u8;
const SNAPSHOT_BYTES: u8 = (3 * VECTOR_CHUNK_BYTES) as u8;
const PLUS_RESULT_OFFSET: u8 = SNAPSHOT_BYTES;
const DUAL_RESULT_SNAPSHOT_BYTES: u8 = (4 * VECTOR_CHUNK_BYTES) as u8;
const HALF_TURN_DEGREES: u16 = 180;
const COMPLEX_COMPONENTS: usize = 2;
const QUARTER_TURN_DEGREES: u16 = 90;

/// Inputs: XMM0=Zn, XMM1=Zm, XMM4=accumulator. Output XMM0; preserve XMM7.
/// Clobbers caller-saved RAX/RCX/RDX/R8/R9/R10/R11 and restores RSP exactly.
pub(super) fn emit_chunk(
    code: &mut Code,
    element: ElementSize,
    rounded: bool,
    rotation_degrees: u16,
    target: TargetCpu,
) -> Result<(), Unsupported> {
    if element == ElementSize::Quadword || ![0, 90, 180, 270].contains(&rotation_degrees) {
        return Err(Unsupported);
    }
    if !rounded {
        return super::complex_wrapping::emit_chunk(code, element, rotation_degrees, target);
    }
    if matches!(element, ElementSize::Byte | ElementSize::Halfword) {
        emit_rounded_packed(code, element, rotation_degrees);
        return Ok(());
    }
    let mut asm = code.asm();
    asm.alu_imm8(Alu::Sub, Size::Qword, Rsp, SNAPSHOT_BYTES as i8);
    asm.movdqu_store(Mem::base(Rsp, 0), 0);
    asm.movdqu_store(Mem::base_disp8(Rsp, SOURCE_M_OFFSET as i8), 1);
    asm.movdqu_store(Mem::base_disp8(Rsp, ACCUMULATOR_OFFSET as i8), 4);
    let rotation = usize::from(rotation_degrees / QUARTER_TURN_DEGREES);
    let select_a = rotation & 1;
    let select_b = select_a ^ 1;
    let subtract = [select_a != rotation >> 1, rotation >> 1 != 0];
    for pair in 0..VECTOR_CHUNK_BYTES / (COMPLEX_COMPONENTS * element.bytes()) {
        for (component, subtract_product) in subtract.into_iter().enumerate() {
            let n_lane = COMPLEX_COMPONENTS * pair + select_a;
            let m_lane =
                COMPLEX_COMPONENTS * pair + if component == 0 { select_a } else { select_b };
            let destination_lane = COMPLEX_COMPONENTS * pair + component;
            let accumulator_offset =
                ACCUMULATOR_OFFSET + (destination_lane * element.bytes()) as u8;
            load_signed(
                code,
                Gpr::Rax,
                element,
                SOURCE_N_OFFSET + (n_lane * element.bytes()) as u8,
            );
            load_signed(
                code,
                Gpr::Rcx,
                element,
                SOURCE_M_OFFSET + (m_lane * element.bytes()) as u8,
            );
            load_signed(code, Gpr::R9, element, accumulator_offset);
            emit_rounded_scalar(code, element.bits() as u32, subtract_product);
            store_result(code, element, accumulator_offset);
        }
    }
    let mut asm = code.asm();
    asm.movdqu_load(0, Mem::base_disp8(Rsp, ACCUMULATOR_OFFSET as i8));
    asm.alu_imm8(Alu::Add, Size::Qword, Rsp, SNAPSHOT_BYTES as i8);
    Ok(())
}

fn load_signed(code: &mut Code, register: Gpr, element: ElementSize, offset: u8) {
    let slot = Mem::base_disp8(Rsp, offset as i8);
    match element {
        ElementSize::Word => code.asm().movsxd(register, slot),
        ElementSize::Doubleword => code.asm().mov_load(Size::Qword, register, slot),
        _ => unreachable!("scalar complex components are word or doubleword"),
    }
}

fn store_result(code: &mut Code, element: ElementSize, offset: u8) {
    let size = match element {
        ElementSize::Word => Size::Dword,
        ElementSize::Doubleword => Size::Qword,
        _ => unreachable!("scalar complex components are word or doubleword"),
    };
    code.asm()
        .mov_store(size, Mem::base_disp8(Rsp, offset as i8), Rax);
}

/// Mixed component signs operate on wide products, preserving min*min. Running
/// both exact packed directions and blending avoids negating a narrow operand.
fn emit_rounded_packed(code: &mut Code, element: ElementSize, rotation: u16) {
    prepare_products(code, element, rotation);
    if rotation == 0 || rotation == HALF_TURN_DEGREES {
        emit_saturating_chunk(
            code,
            Kind::RoundedHighAccumulate {
                subtract: rotation != 0,
            },
            element,
        );
        return;
    }
    let mut asm = code.asm();
    asm.alu_imm8(Alu::Sub, Size::Qword, Rsp, DUAL_RESULT_SNAPSHOT_BYTES as i8);
    asm.movdqu_store(Mem::base(Rsp, 0), 0);
    asm.movdqu_store(Mem::base_disp8(Rsp, SOURCE_M_OFFSET as i8), 1);
    asm.movdqu_store(Mem::base_disp8(Rsp, ACCUMULATOR_OFFSET as i8), 4);
    emit_saturating_chunk(
        code,
        Kind::RoundedHighAccumulate { subtract: false },
        element,
    );
    let mut asm = code.asm();
    asm.movdqu_store(Mem::base_disp8(Rsp, PLUS_RESULT_OFFSET as i8), 0);
    asm.movdqu_load(0, Mem::base(Rsp, 0));
    asm.movdqu_load(1, Mem::base_disp8(Rsp, SOURCE_M_OFFSET as i8));
    asm.movdqu_load(4, Mem::base_disp8(Rsp, ACCUMULATOR_OFFSET as i8));
    emit_saturating_chunk(
        code,
        Kind::RoundedHighAccumulate { subtract: true },
        element,
    );
    let mut asm = code.asm();
    asm.movdqu_load(2, Mem::base_disp8(Rsp, PLUS_RESULT_OFFSET as i8));
    asm.alu_imm8(Alu::Add, Size::Qword, Rsp, DUAL_RESULT_SNAPSHOT_BYTES as i8);
    blend_directions(code, element, rotation);
}
