//! SVE CMLA (integer, wrapping).
use super::{multiply_low_for_target, packed};
use crate::TargetCpu;
use crate::aarch64::Unsupported;
use crate::aarch64::scalable::ElementSize;
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const RIGHT: u8 = 1;
const TEMPORARY: u8 = 2;
const ACCUMULATOR: u8 = 4;
const NEGATIVE_COMPONENTS: u8 = 5;
const BYTE_BITS: u8 = 8;
const HALFWORD_BITS: u8 = 16;
const WORD_BITS: u8 = 32;
const QWORD_BYTES: u8 = 8;
const REPEAT_EVEN_COMPONENT: u8 = 0xa0;
const REPEAT_ODD_COMPONENT: u8 = 0xf5;
const REPEAT_LOW_QWORD: u8 = 0x44;
const REPEAT_HIGH_QWORD: u8 = 0xee;
const SWAP_ADJACENT_COMPONENTS: u8 = 0xb1;
const SWAP_QWORDS: u8 = 0x4e;
const QUARTER_TURN_DEGREES: u16 = 90;
const HALF_TURN_DEGREES: u16 = 180;
const THREE_QUARTER_TURN_DEGREES: u16 = 270;
const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const MOVQ_TO_GPR: [u8; 4] = [0x66, 0x48, 0x0f, 0x7e];
const IMUL_RCX_RAX: [u8; 4] = [0x48, 0x0f, 0xaf, 0xc8];
const IMUL_RDX_RAX: [u8; 4] = [0x48, 0x0f, 0xaf, 0xd0];

fn shuffle(code: &mut Vec<u8>, opcode: Host, register: u8, control: u8) {
    packed(code, opcode, register, register);
    code.push(control);
}

fn extract_qword(code: &mut Vec<u8>, xmm: u8, gpr: u8) {
    code.extend(MOVQ_TO_GPR);
    code.push(MODRM_REGISTER | (xmm << MODRM_REGISTER_SHIFT) | gpr);
}

fn insert_qword(code: &mut Vec<u8>, xmm: u8, gpr: u8) {
    Host::MoveGprQword.append(code, TargetCpu::Baseline);
    code.push(MODRM_REGISTER | (xmm << MODRM_REGISTER_SHIFT) | gpr);
}

fn doubleword_products(code: &mut Vec<u8>, rotation_degrees: u16) {
    // A doubleword chunk contains one complex pair. Extract its selected Zn
    // component once, then form both low products without stack snapshots.
    let imaginary = matches!(
        rotation_degrees,
        QUARTER_TURN_DEGREES | THREE_QUARTER_TURN_DEGREES
    );
    if imaginary {
        Shift::RightBytes.emit(code, RESULT, QWORD_BYTES);
    }
    extract_qword(code, RESULT, RAX);
    extract_qword(code, RIGHT, RCX);
    Shift::RightBytes.emit(code, RIGHT, QWORD_BYTES);
    extract_qword(code, RIGHT, RDX);
    code.extend(IMUL_RCX_RAX);
    code.extend(IMUL_RDX_RAX);
    insert_qword(code, RESULT, if imaginary { RDX } else { RCX });
    insert_qword(code, RIGHT, if imaginary { RCX } else { RDX });
    packed(code, Host::UnpackLowQword, RESULT, RIGHT);
}

/// Replicate the selected Zn component into each complex pair and rotate Zm's
/// component order when selecting imaginary Zn. Preserves XMM4 and XMM7;
/// consumes XMM0..2. The caller validates component width and rotation.
pub(super) fn prepare_products(code: &mut Vec<u8>, element: ElementSize, rotation_degrees: u16) {
    let imaginary = matches!(
        rotation_degrees,
        QUARTER_TURN_DEGREES | THREE_QUARTER_TURN_DEGREES
    );
    let repeat = if imaginary {
        REPEAT_ODD_COMPONENT
    } else {
        REPEAT_EVEN_COMPONENT
    };
    match element {
        ElementSize::Byte => {
            let (select, replicate) = if imaginary {
                (Shift::RightWord, Shift::LeftWord)
            } else {
                (Shift::LeftWord, Shift::RightWord)
            };
            select.emit(code, RESULT, BYTE_BITS);
            packed(code, Host::MoveAligned, TEMPORARY, RESULT);
            replicate.emit(code, TEMPORARY, BYTE_BITS);
            packed(code, Host::Or, RESULT, TEMPORARY);
        }
        ElementSize::Halfword => {
            shuffle(code, Host::ShuffleLowWord, RESULT, repeat);
            shuffle(code, Host::ShuffleHighWord, RESULT, repeat);
        }
        ElementSize::Word => shuffle(code, Host::ShuffleDword, RESULT, repeat),
        ElementSize::Doubleword => shuffle(
            code,
            Host::ShuffleDword,
            RESULT,
            if imaginary {
                REPEAT_HIGH_QWORD
            } else {
                REPEAT_LOW_QWORD
            },
        ),
        ElementSize::Quadword => unreachable!("validated complex component width"),
    }
    if imaginary {
        match element {
            ElementSize::Byte => {
                packed(code, Host::MoveAligned, TEMPORARY, RIGHT);
                Shift::LeftWord.emit(code, RIGHT, BYTE_BITS);
                Shift::RightWord.emit(code, TEMPORARY, BYTE_BITS);
                packed(code, Host::Or, RIGHT, TEMPORARY);
            }
            ElementSize::Halfword => {
                shuffle(code, Host::ShuffleLowWord, RIGHT, SWAP_ADJACENT_COMPONENTS);
                shuffle(code, Host::ShuffleHighWord, RIGHT, SWAP_ADJACENT_COMPONENTS);
            }
            ElementSize::Word => {
                shuffle(code, Host::ShuffleDword, RIGHT, SWAP_ADJACENT_COMPONENTS);
            }
            ElementSize::Doubleword => {
                shuffle(code, Host::ShuffleDword, RIGHT, SWAP_QWORDS);
            }
            ElementSize::Quadword => unreachable!("validated complex component width"),
        }
    }
}

fn negative_component_mask(code: &mut Vec<u8>, element: ElementSize, rotation_degrees: u16) {
    let odd = rotation_degrees == THREE_QUARTER_TURN_DEGREES;
    let (shift, amount) = match (element, odd) {
        (ElementSize::Byte, false) => (Shift::RightWord, BYTE_BITS),
        (ElementSize::Byte, true) => (Shift::LeftWord, BYTE_BITS),
        (ElementSize::Halfword, false) => (Shift::RightDword, HALFWORD_BITS),
        (ElementSize::Halfword, true) => (Shift::LeftDword, HALFWORD_BITS),
        (ElementSize::Word, false) => (Shift::RightQword, WORD_BITS),
        (ElementSize::Word, true) => (Shift::LeftQword, WORD_BITS),
        (ElementSize::Doubleword, false) => (Shift::RightBytes, QWORD_BYTES),
        (ElementSize::Doubleword, true) => (Shift::LeftBytes, QWORD_BYTES),
        _ => unreachable!("validated complex component width"),
    };
    packed(
        code,
        Host::EqualDword,
        NEGATIVE_COMPONENTS,
        NEGATIVE_COMPONENTS,
    );
    shift.emit(code, NEGATIVE_COMPONENTS, amount);
}

/// Select between XMM0=minus result and XMM2=plus result for a quarter-turn
/// rotation. Returns XMM0, consumes XMM5 and preserves XMM2/4/7. This also
/// serves rounded complex arithmetic, whose directions must saturate separately.
pub(super) fn blend_directions(code: &mut Vec<u8>, element: ElementSize, rotation_degrees: u16) {
    negative_component_mask(code, element, rotation_degrees);
    packed(code, Host::And, RESULT, NEGATIVE_COMPONENTS);
    packed(code, Host::AndNot, NEGATIVE_COMPONENTS, TEMPORARY);
    packed(code, Host::Or, RESULT, NEGATIVE_COMPONENTS);
}

/// XMM0=Zn, XMM1=Zm, XMM4=old accumulator; indexed complex-pair broadcasts
/// are already staged. Returns XMM0, consumes XMM0..6, preserves XMM7 and
/// guest architectural status, host MXCSR, RAM and the stack pointer. Doubleword
/// products additionally consume caller-saved RAX/RCX/RDX.
pub(super) fn emit_chunk(
    code: &mut Vec<u8>,
    element: ElementSize,
    rotation_degrees: u16,
    target: TargetCpu,
) -> Result<(), Unsupported> {
    if element == ElementSize::Quadword
        || ![
            0,
            QUARTER_TURN_DEGREES,
            HALF_TURN_DEGREES,
            THREE_QUARTER_TURN_DEGREES,
        ]
        .contains(&rotation_degrees)
    {
        return Err(Unsupported);
    }
    if element == ElementSize::Doubleword {
        doubleword_products(code, rotation_degrees);
    } else {
        prepare_products(code, element, rotation_degrees);
        multiply_low_for_target(code, element, target);
    }
    let (add, subtract) = match element {
        ElementSize::Byte => (Host::AddByte, Host::SubByte),
        ElementSize::Halfword => (Host::AddWord, Host::SubWord),
        ElementSize::Word => (Host::AddDword, Host::SubDword),
        ElementSize::Doubleword => (Host::AddQword, Host::SubQword),
        ElementSize::Quadword => unreachable!("validated complex component width"),
    };
    if rotation_degrees == HALF_TURN_DEGREES {
        if element == ElementSize::Doubleword {
            packed(code, Host::MoveAligned, TEMPORARY, ACCUMULATOR);
            packed(code, subtract, TEMPORARY, RESULT);
            packed(code, Host::MoveAligned, RESULT, TEMPORARY);
        } else {
            packed(code, subtract, ACCUMULATOR, RESULT);
            packed(code, Host::MoveAligned, RESULT, ACCUMULATOR);
        }
    } else {
        if rotation_degrees != 0 {
            // (product XOR mask) - mask negates only selected components,
            // exactly modulo their width, including the signed minimum value.
            negative_component_mask(code, element, rotation_degrees);
            packed(code, Host::Xor, RESULT, NEGATIVE_COMPONENTS);
            packed(code, subtract, RESULT, NEGATIVE_COMPONENTS);
        }
        packed(code, add, RESULT, ACCUMULATOR);
    }
    Ok(())
}
