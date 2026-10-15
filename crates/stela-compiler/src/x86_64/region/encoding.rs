//! Baseline integer encodings. No optional host feature or host flag dependency.
use crate::aarch64::{Logical, Shift, Width};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HostGpr {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rsi = 6,
    Rdi = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
}

pub const RESULT: HostGpr = HostGpr::Rax;
pub const RIGHT: HostGpr = HostGpr::Rdx;
pub const FRAME: HostGpr = HostGpr::Rdi;
pub const POOL: [HostGpr; 6] = [
    HostGpr::Rcx,
    HostGpr::Rsi,
    HostGpr::R8,
    HostGpr::R9,
    HostGpr::R10,
    HostGpr::R11,
];
const REX: u8 = 0x40;
const REX_W: u8 = 8;
const REX_R: u8 = 4;
const REX_B: u8 = 1;
const REGISTER_MODE: u8 = 0xc0;
const DISP32_MODE: u8 = 0x80;
const DISP8_MODE: u8 = 0x40;
const MOV_LOAD: u8 = 0x8b;
const MOV_STORE: u8 = 0x89;
const MOV_IMMEDIATE: u8 = 0xb8;
const IMMEDIATE_GROUP: u8 = 0x81;
const SHIFT_IMMEDIATE_GROUP: u8 = 0xc1;
const UNARY_GROUP: u8 = 0xf7;

fn rex(code: &mut Vec<u8>, width: Width, reg: HostGpr, rm: HostGpr) {
    let value = REX
        | if width == Width::X64 { REX_W } else { 0 }
        | if reg as u8 >= 8 { REX_R } else { 0 }
        | if rm as u8 >= 8 { REX_B } else { 0 };
    if value != REX {
        code.push(value);
    }
}

pub fn copy(code: &mut Vec<u8>, destination: HostGpr, source: HostGpr, width: Width) {
    rex(code, width, source, destination);
    code.extend([
        MOV_STORE,
        REGISTER_MODE | ((source as u8 & 7) << 3) | (destination as u8 & 7),
    ]);
}

fn frame_access(code: &mut Vec<u8>, register: HostGpr, slot: usize, opcode: u8) {
    rex(code, Width::X64, register, FRAME);
    let offset = (slot * 8) as u32;
    let mode = if offset <= 127 {
        DISP8_MODE
    } else {
        DISP32_MODE
    };
    code.extend([opcode, mode | ((register as u8 & 7) << 3) | FRAME as u8]);
    if mode == DISP8_MODE {
        code.push(offset as u8);
    } else {
        code.extend(offset.to_le_bytes());
    }
}

pub fn load(code: &mut Vec<u8>, destination: HostGpr, slot: usize) {
    frame_access(code, destination, slot, MOV_LOAD);
}

pub fn store(code: &mut Vec<u8>, source: HostGpr, slot: usize) {
    frame_access(code, source, slot, MOV_STORE);
}

pub fn immediate(code: &mut Vec<u8>, destination: HostGpr, value: u64, width: Width) {
    rex(code, width, HostGpr::Rax, destination);
    code.push(MOV_IMMEDIATE | (destination as u8 & 7));
    if width == Width::X64 {
        code.extend(value.to_le_bytes());
    } else {
        code.extend((value as u32).to_le_bytes());
    }
}

pub fn binary(
    code: &mut Vec<u8>,
    destination: HostGpr,
    source: HostGpr,
    opcode: Binary,
    width: Width,
) {
    rex(code, width, source, destination);
    code.extend([
        opcode as u8,
        REGISTER_MODE | ((source as u8 & 7) << 3) | (destination as u8 & 7),
    ]);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Binary {
    Add = 0x01,
    Sub = 0x29,
    And = 0x21,
    Or = 0x09,
    Xor = 0x31,
}

pub fn logical_opcode(kind: Logical) -> Binary {
    match kind {
        Logical::And => Binary::And,
        Logical::Or => Binary::Or,
        Logical::Xor => Binary::Xor,
    }
}

pub fn arithmetic_immediate(
    code: &mut Vec<u8>,
    destination: HostGpr,
    subtract: bool,
    value: u32,
    width: Width,
) {
    rex(code, width, HostGpr::Rax, destination);
    let extension = if subtract { 5 } else { 0 };
    code.extend([
        IMMEDIATE_GROUP,
        REGISTER_MODE | (extension << 3) | (destination as u8 & 7),
    ]);
    code.extend(value.to_le_bytes());
}

pub fn shift(code: &mut Vec<u8>, kind: Shift, amount: u8, width: Width) {
    rex(code, width, HostGpr::Rax, RIGHT);
    let extension = match kind {
        Shift::Lsl => 4,
        Shift::Lsr => 5,
        Shift::Asr => 7,
        Shift::Ror => 1,
    };
    code.extend([
        SHIFT_IMMEDIATE_GROUP,
        REGISTER_MODE | (extension << 3) | RIGHT as u8,
        amount,
    ]);
}

pub fn invert(code: &mut Vec<u8>, width: Width) {
    rex(code, width, HostGpr::Rax, RIGHT);
    const NOT_EXTENSION: u8 = 2;
    code.extend([
        UNARY_GROUP,
        REGISTER_MODE | (NOT_EXTENSION << 3) | RIGHT as u8,
    ]);
}

/// Check the exact shared raw-byte-load recipe, including physical clobbers.
/// This inspects existing emitted bytes; it never emits a second memory engine.
pub fn ordinary_byte_load_ends(
    code: &[u8],
    base: usize,
    data: Option<usize>,
    displacement: i32,
) -> Option<Vec<usize>> {
    const LEA: u8 = 0x8d;
    const TWO_BYTE_OPCODE: u8 = 0x0f;
    const MOVZX_BYTE: u8 = 0xb6;
    const RAX_FROM_FRAME_DISP32: u8 = 0x87;
    const RDX_FROM_RAX_DISP32: u8 = 0x90;
    const RAX_FROM_RDX: u8 = 0xd0;
    const ECX_FROM_RAX_MEMORY: u8 = 0x08;
    const FRAME_DISP32_FROM_RCX: u8 = 0x8f;
    let expected_length = if data.is_some() { 27 } else { 20 };
    if code.len() != expected_length
        || code.get(0..3)? != [REX | REX_W, MOV_LOAD, RAX_FROM_FRAME_DISP32]
        || code.get(3..7)? != u32::try_from(base.checked_mul(8)?).ok()?.to_le_bytes()
        || code.get(7..10)? != [REX | REX_W, LEA, RDX_FROM_RAX_DISP32]
        || code.get(10..14)? != displacement.to_le_bytes()
        || code.get(14..17)? != [REX | REX_W, MOV_STORE, RAX_FROM_RDX]
        || code.get(17..20)? != [TWO_BYTE_OPCODE, MOVZX_BYTE, ECX_FROM_RAX_MEMORY]
    {
        return None;
    }
    let mut ends = vec![7, 14, 17, 20];
    if let Some(data) = data {
        if code.get(20..23)? != [REX | REX_W, MOV_STORE, FRAME_DISP32_FROM_RCX]
            || code.get(23..27)? != u32::try_from(data.checked_mul(8)?).ok()?.to_le_bytes()
        {
            return None;
        }
        ends.push(27);
    }
    Some(ends)
}
