//! Integer complex products, reusing exact rounded multiply/accumulate arithmetic.
//! A chunk's three source snapshots precede every destination component write.
use crate::TargetCpu;
use crate::aarch64::scalable::{ElementSize, VECTOR_CHUNK_BYTES};
use crate::aarch64::sve::integer_products::Kind;
use alloc::vec::Vec;

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
const SUB_RSP_IMM8: [u8; 3] = [0x48, 0x83, 0xec];
const ADD_RSP_IMM8: [u8; 3] = [0x48, 0x83, 0xc4];
const MOVDQU_RSP_DISP8_XMM0: [u8; 5] = [0xf3, 0x0f, 0x7f, 0x44, 0x24];
const MOVDQU_XMM0_RSP: [u8; 5] = [0xf3, 0x0f, 0x6f, 0x04, 0x24];
const MOVDQU_XMM1_RSP_DISP8: [u8; 5] = [0xf3, 0x0f, 0x6f, 0x4c, 0x24];
const MOVDQU_XMM4_RSP_DISP8: [u8; 5] = [0xf3, 0x0f, 0x6f, 0x64, 0x24];
const MOVDQU_XMM2_RSP_DISP8: [u8; 5] = [0xf3, 0x0f, 0x6f, 0x54, 0x24];
const MOVDQU_RSP_XMM0: [u8; 5] = [0xf3, 0x0f, 0x7f, 0x04, 0x24];
const MOVDQU_RSP_DISP8_XMM1: [u8; 5] = [0xf3, 0x0f, 0x7f, 0x4c, 0x24];
const MOVDQU_RSP_DISP8_XMM4: [u8; 5] = [0xf3, 0x0f, 0x7f, 0x64, 0x24];
const MOVDQU_XMM0_RSP_DISP8: [u8; 5] = [0xf3, 0x0f, 0x6f, 0x44, 0x24];
const REX_W: u8 = 0x48;
const REX_REGISTER_HIGH: u8 = 0x04;
const MODRM_DISP8_RSP: u8 = 0x44;
const SIB_RSP: u8 = 0x24;
const MODRM_REGISTER_SHIFT: u8 = 3;
const MODRM_REGISTER_MASK: u8 = 7;
const MOVSXD: u8 = 0x63;
const MOV_QWORD: u8 = 0x8b;
const MOV_STORE: u8 = 0x89;
const COMPLEX_COMPONENTS: usize = 2;
const QUARTER_TURN_DEGREES: u16 = 90;

#[derive(Clone, Copy)]
enum Gpr {
    Rax = 0,
    Rcx = 1,
    R9 = 9,
}

/// Inputs: XMM0=Zn, XMM1=Zm, XMM4=accumulator. Output XMM0; preserve XMM7.
/// Clobbers caller-saved RAX/RCX/RDX/R8/R9/R10/R11 and restores RSP exactly.
pub(super) fn emit_chunk(
    code: &mut Vec<u8>,
    element: ElementSize,
    rounded: bool,
    rotation_degrees: u16,
    target: TargetCpu,
) -> Result<(), ()> {
    if element == ElementSize::Quadword || ![0, 90, 180, 270].contains(&rotation_degrees) {
        return Err(());
    }
    if !rounded {
        return super::complex_wrapping::emit_chunk(code, element, rotation_degrees, target);
    }
    if matches!(element, ElementSize::Byte | ElementSize::Halfword) {
        emit_rounded_packed(code, element, rotation_degrees);
        return Ok(());
    }
    code.extend_from_slice(&SUB_RSP_IMM8);
    code.push(SNAPSHOT_BYTES);
    code.extend_from_slice(&MOVDQU_RSP_XMM0);
    code.extend_from_slice(&MOVDQU_RSP_DISP8_XMM1);
    code.push(SOURCE_M_OFFSET);
    code.extend_from_slice(&MOVDQU_RSP_DISP8_XMM4);
    code.push(ACCUMULATOR_OFFSET);
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
    code.extend_from_slice(&MOVDQU_XMM0_RSP_DISP8);
    code.push(ACCUMULATOR_OFFSET);
    code.extend_from_slice(&ADD_RSP_IMM8);
    code.push(SNAPSHOT_BYTES);
    Ok(())
}

fn load_signed(code: &mut Vec<u8>, register: Gpr, element: ElementSize, offset: u8) {
    let register = register as u8;
    code.push(
        REX_W
            | if register > MODRM_REGISTER_MASK {
                REX_REGISTER_HIGH
            } else {
                0
            },
    );
    match element {
        ElementSize::Word => code.push(MOVSXD),
        ElementSize::Doubleword => code.push(MOV_QWORD),
        _ => unreachable!("scalar complex components are word or doubleword"),
    }
    code.extend_from_slice(&[
        MODRM_DISP8_RSP | ((register & MODRM_REGISTER_MASK) << MODRM_REGISTER_SHIFT),
        SIB_RSP,
        offset,
    ]);
}

fn store_result(code: &mut Vec<u8>, element: ElementSize, offset: u8) {
    match element {
        ElementSize::Word => {}
        ElementSize::Doubleword => code.push(REX_W),
        _ => unreachable!("scalar complex components are word or doubleword"),
    }
    code.extend_from_slice(&[MOV_STORE, MODRM_DISP8_RSP, SIB_RSP, offset]);
}

/// Mixed component signs operate on wide products, preserving min*min. Running
/// both exact packed directions and blending avoids negating a narrow operand.
fn emit_rounded_packed(code: &mut Vec<u8>, element: ElementSize, rotation: u16) {
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
    code.extend_from_slice(&SUB_RSP_IMM8);
    code.push(DUAL_RESULT_SNAPSHOT_BYTES);
    code.extend_from_slice(&MOVDQU_RSP_XMM0);
    code.extend_from_slice(&MOVDQU_RSP_DISP8_XMM1);
    code.push(SOURCE_M_OFFSET);
    code.extend_from_slice(&MOVDQU_RSP_DISP8_XMM4);
    code.push(ACCUMULATOR_OFFSET);
    emit_saturating_chunk(
        code,
        Kind::RoundedHighAccumulate { subtract: false },
        element,
    );
    code.extend_from_slice(&MOVDQU_RSP_DISP8_XMM0);
    code.push(PLUS_RESULT_OFFSET);
    code.extend_from_slice(&MOVDQU_XMM0_RSP);
    code.extend_from_slice(&MOVDQU_XMM1_RSP_DISP8);
    code.push(SOURCE_M_OFFSET);
    code.extend_from_slice(&MOVDQU_XMM4_RSP_DISP8);
    code.push(ACCUMULATOR_OFFSET);
    emit_saturating_chunk(
        code,
        Kind::RoundedHighAccumulate { subtract: true },
        element,
    );
    code.extend_from_slice(&MOVDQU_XMM2_RSP_DISP8);
    code.push(PLUS_RESULT_OFFSET);
    code.extend_from_slice(&ADD_RSP_IMM8);
    code.push(DUAL_RESULT_SNAPSHOT_BYTES);
    blend_directions(code, element, rotation);
}
