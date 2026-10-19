//! Integer encodings, including flag-preserving variants.
use super::{BYTE_LOAD_BYTES, WORD_LOAD_BYTES};
use crate::aarch64::{Logical, Shift, Width};
use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HostGpr {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

impl HostGpr {
    pub const fn mask(self) -> u16 {
        1u16 << self as u8
    }
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
/// Borrow only within a nonfaulting span, with exact native ABI restoration.
pub const CALLEE_POOL: [HostGpr; 6] = [
    HostGpr::Rbx,
    HostGpr::Rbp,
    HostGpr::R12,
    HostGpr::R13,
    HostGpr::R14,
    HostGpr::R15,
];
pub const ALLOCATABLE_SLOTS: usize = POOL.len() + CALLEE_POOL.len();

pub fn pool_host(index: usize) -> HostGpr {
    if index < POOL.len() {
        POOL[index]
    } else {
        CALLEE_POOL[index - POOL.len()]
    }
}
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
const NOP: u8 = 0x90;
const TWO_BYTE_OPCODE: u8 = 0x0f;
const IMUL: u8 = 0xaf;

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ImmediateExtension {
    Add = 0,
    And = 4,
    Subtract = 5,
    Compare = 7,
}

pub fn nop(code: &mut Vec<u8>) {
    code.push(NOP);
}

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
    let offset = (slot * GPR_BYTES) as u32;
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

fn nzcv_access(code: &mut Vec<u8>, register: HostGpr, opcode: u8) {
    const NZCV_OFFSET: u32 = core::mem::offset_of!(crate::GuestState, nzcv) as u32;
    rex(code, Width::W32, register, FRAME);
    code.extend([
        opcode,
        DISP32_MODE | ((register as u8 & 7) << 3) | FRAME as u8,
    ]);
    code.extend(NZCV_OFFSET.to_le_bytes());
}

pub fn load_nzcv(code: &mut Vec<u8>, destination: HostGpr) {
    nzcv_access(code, destination, MOV_LOAD);
}

pub fn store_nzcv(code: &mut Vec<u8>, source: HostGpr) {
    nzcv_access(code, source, MOV_STORE);
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

/// Low product modulo operand width; only destination and host flags change.
pub fn multiply(code: &mut Vec<u8>, destination: HostGpr, source: HostGpr, width: Width) {
    rex(code, width, destination, source);
    code.extend([
        TWO_BYTE_OPCODE,
        IMUL,
        REGISTER_MODE | ((destination as u8 & 7) << 3) | (source as u8 & 7),
    ]);
}

pub fn negate(code: &mut Vec<u8>, destination: HostGpr, width: Width) {
    const NEG_EXTENSION: u8 = 3;
    rex(code, width, HostGpr::Rax, destination);
    code.extend([
        UNARY_GROUP,
        REGISTER_MODE | (NEG_EXTENSION << 3) | (destination as u8 & 7),
    ]);
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
    group_immediate(
        code,
        destination,
        if subtract {
            ImmediateExtension::Subtract
        } else {
            ImmediateExtension::Add
        },
        value,
        width,
    );
}

pub fn integer_immediate(
    code: &mut Vec<u8>,
    destination: HostGpr,
    extension: ImmediateExtension,
    value: u32,
    width: Width,
) {
    if destination == HostGpr::Rax {
        const ADD_ACCUMULATOR: u8 = 0x05;
        const SUBTRACT_ACCUMULATOR: u8 = 0x2d;
        const AND_ACCUMULATOR: u8 = 0x25;
        const COMPARE_ACCUMULATOR: u8 = 0x3d;
        rex(code, width, HostGpr::Rax, destination);
        code.push(match extension {
            ImmediateExtension::Add => ADD_ACCUMULATOR,
            ImmediateExtension::Subtract => SUBTRACT_ACCUMULATOR,
            ImmediateExtension::And => AND_ACCUMULATOR,
            ImmediateExtension::Compare => COMPARE_ACCUMULATOR,
        });
        code.extend(value.to_le_bytes());
    } else {
        group_immediate(code, destination, extension, value, width);
    }
}

fn group_immediate(
    code: &mut Vec<u8>,
    destination: HostGpr,
    extension: ImmediateExtension,
    value: u32,
    width: Width,
) {
    rex(code, width, HostGpr::Rax, destination);
    code.extend([
        IMMEDIATE_GROUP,
        REGISTER_MODE | ((extension as u8) << 3) | (destination as u8 & 7),
    ]);
    code.extend(value.to_le_bytes());
}

pub fn shift(code: &mut Vec<u8>, kind: Shift, amount: u8, width: Width) {
    shift_register(code, RIGHT, kind, amount, width);
}

pub fn shift_register(
    code: &mut Vec<u8>,
    destination: HostGpr,
    kind: Shift,
    amount: u8,
    width: Width,
) {
    rex(code, width, HostGpr::Rax, destination);
    let extension = match kind {
        Shift::Lsl => 4,
        Shift::Lsr => 5,
        Shift::Asr => 7,
        Shift::Ror => 1,
    };
    code.extend([
        SHIFT_IMMEDIATE_GROUP,
        REGISTER_MODE | (extension << 3) | (destination as u8 & 7),
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

const ORDINARY_ADDRESS_BYTES: usize = 17;
const FRAME_STORE_BYTES: usize = 7;
const GPR_BYTES: usize = core::mem::size_of::<u64>();
const ECX_FROM_RAX_MEMORY: u8 = 0x08;
const FRAME_DISP32_FROM_RCX: u8 = 0x8f;
const FRAME_DISP32_FROM_R8: u8 = 0x87;
const R8D_FROM_RAX_DISP8: u8 = 0x40;

fn ordinary_address_ends(code: &[u8], base: usize, displacement: i32) -> Option<Vec<usize>> {
    const LEA: u8 = 0x8d;
    const RAX_FROM_FRAME_DISP32: u8 = 0x87;
    const RDX_FROM_RAX_DISP32: u8 = 0x90;
    const RAX_FROM_RDX: u8 = 0xd0;
    if code.get(0..3)? != [REX | REX_W, MOV_LOAD, RAX_FROM_FRAME_DISP32]
        || code.get(3..7)?
            != u32::try_from(base.checked_mul(GPR_BYTES)?)
                .ok()?
                .to_le_bytes()
        || code.get(7..10)? != [REX | REX_W, LEA, RDX_FROM_RAX_DISP32]
        || code.get(10..14)? != displacement.to_le_bytes()
        || code.get(14..ORDINARY_ADDRESS_BYTES)? != [REX | REX_W, MOV_STORE, RAX_FROM_RDX]
    {
        return None;
    }
    Some(vec![7, 14, ORDINARY_ADDRESS_BYTES])
}

fn check_frame_store(code: &[u8], start: usize, guest: usize, rex: u8, modrm: u8) -> Option<usize> {
    let end = start.checked_add(FRAME_STORE_BYTES)?;
    if code.get(start..start + 3)? != [rex, MOV_STORE, modrm]
        || code.get(start + 3..end)?
            != u32::try_from(guest.checked_mul(GPR_BYTES)?)
                .ok()?
                .to_le_bytes()
    {
        return None;
    }
    Some(end)
}

/// Inspect the exact shared scalar load, including address, clobbers and commit.
/// The same memory emitter supplies bytes; this is not a second memory engine.
pub fn ordinary_load_ends(
    code: &[u8],
    bytes: u8,
    base: usize,
    data: Option<usize>,
    displacement: i32,
) -> Option<Vec<usize>> {
    const MOVZX_BYTE: u8 = 0xb6;
    let memory_recipe: &[u8] = match bytes {
        BYTE_LOAD_BYTES => &[TWO_BYTE_OPCODE, MOVZX_BYTE, ECX_FROM_RAX_MEMORY],
        WORD_LOAD_BYTES => &[MOV_LOAD, ECX_FROM_RAX_MEMORY],
        _ => return None,
    };
    let mut ends = ordinary_address_ends(code, base, displacement)?;
    let load_end = ORDINARY_ADDRESS_BYTES + memory_recipe.len();
    if code.get(ORDINARY_ADDRESS_BYTES..load_end)? != memory_recipe {
        return None;
    }
    ends.push(load_end);
    let end = if let Some(guest) = data {
        let end = check_frame_store(code, load_end, guest, REX | REX_W, FRAME_DISP32_FROM_RCX)?;
        ends.push(end);
        end
    } else {
        load_end
    };
    (code.len() == end).then_some(ends)
}

/// Unsigned W pair recipe: RCX/R8 results, both accesses before either commit.
/// SP/writeback, signed/X pairs and duplicate destinations are not selected.
pub fn ordinary_pair_load_ends(
    code: &[u8],
    base: usize,
    data: [Option<usize>; 2],
    displacement: i32,
) -> Option<Vec<usize>> {
    let mut ends = ordinary_address_ends(code, base, displacement)?;
    let first_end = ORDINARY_ADDRESS_BYTES + 2;
    let second_end = first_end + 4;
    if code.get(ORDINARY_ADDRESS_BYTES..first_end)? != [MOV_LOAD, ECX_FROM_RAX_MEMORY]
        || code.get(first_end..second_end)?
            != [REX | REX_R, MOV_LOAD, R8D_FROM_RAX_DISP8, WORD_LOAD_BYTES]
    {
        return None;
    }
    ends.extend([first_end, second_end]);
    let mut end = second_end;
    for (guest, rex, modrm) in [
        (data[0], REX | REX_W, FRAME_DISP32_FROM_RCX),
        (data[1], REX | REX_W | REX_R, FRAME_DISP32_FROM_R8),
    ] {
        if let Some(guest) = guest {
            end = check_frame_store(code, end, guest, rex, modrm)?;
            ends.push(end);
        }
    }
    (code.len() == end).then_some(ends)
}

/// Native conditions after a full-width ARM subtraction (C is inverted CF).
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum NativeCondition {
    Equal = 0x84,
    NotEqual = 0x85,
    AboveEqual = 0x83,
    Below = 0x82,
    Sign = 0x88,
    NotSign = 0x89,
    Overflow = 0x80,
    NotOverflow = 0x81,
    Above = 0x87,
    BelowEqual = 0x86,
    GreaterEqual = 0x8d,
    Less = 0x8c,
    Greater = 0x8f,
    LessEqual = 0x8e,
}

pub const SUBTRACTION_CONDITIONS: [NativeCondition; 14] = [
    NativeCondition::Equal,
    NativeCondition::NotEqual,
    NativeCondition::AboveEqual,
    NativeCondition::Below,
    NativeCondition::Sign,
    NativeCondition::NotSign,
    NativeCondition::Overflow,
    NativeCondition::NotOverflow,
    NativeCondition::Above,
    NativeCondition::BelowEqual,
    NativeCondition::GreaterEqual,
    NativeCondition::Less,
    NativeCondition::Greater,
    NativeCondition::LessEqual,
];

impl NativeCondition {
    pub fn inverse(self) -> Self {
        match self {
            Self::Equal => Self::NotEqual,
            Self::NotEqual => Self::Equal,
            Self::AboveEqual => Self::Below,
            Self::Below => Self::AboveEqual,
            Self::Sign => Self::NotSign,
            Self::NotSign => Self::Sign,
            Self::Overflow => Self::NotOverflow,
            Self::NotOverflow => Self::Overflow,
            Self::Above => Self::BelowEqual,
            Self::BelowEqual => Self::Above,
            Self::GreaterEqual => Self::Less,
            Self::Less => Self::GreaterEqual,
            Self::Greater => Self::LessEqual,
            Self::LessEqual => Self::Greater,
        }
    }
}

pub fn conditional_copy(
    code: &mut Vec<u8>,
    destination: HostGpr,
    source: HostGpr,
    condition: NativeCondition,
    width: Width,
) {
    const JCC_TO_CMOV: u8 = 0x40;
    rex(code, width, destination, source);
    code.extend([
        TWO_BYTE_OPCODE,
        condition as u8 - JCC_TO_CMOV,
        REGISTER_MODE | ((destination as u8 & 7) << 3) | (source as u8 & 7),
    ]);
}

pub fn increment_preserving_flags(code: &mut Vec<u8>, register: HostGpr, width: Width) {
    rex(code, width, register, register);
    code.extend([
        LEA,
        DISP8_MODE | ((register as u8 & 7) << 3) | (register as u8 & 7),
        1,
    ]);
}

const NEAR_JUMP: u8 = 0xe9;
const JRCXZ: u8 = 0xe3;
const PUSH_REGISTER: u8 = 0x50;
const POP_REGISTER: u8 = 0x58;
const LEA: u8 = 0x8d;
const INC_DEC_GROUP: u8 = 0xff;
const DEC_EXTENSION: u8 = 1;
const RELATIVE_BYTES: usize = core::mem::size_of::<i32>();
const NEAR_JUMP_BYTES: u8 = 1 + RELATIVE_BYTES as u8;

pub fn near_jump(code: &mut Vec<u8>) -> usize {
    code.push(NEAR_JUMP);
    let displacement = code.len();
    code.extend(0i32.to_le_bytes());
    displacement
}

pub fn conditional_jump(code: &mut Vec<u8>, condition: NativeCondition) -> usize {
    code.extend([TWO_BYTE_OPCODE, condition as u8]);
    let displacement = code.len();
    code.extend(0i32.to_le_bytes());
    displacement
}

pub fn patch_relative(code: &mut [u8], displacement: usize, target: usize) {
    let relative = i32::try_from(target as isize - (displacement + RELATIVE_BYTES) as isize)
        .expect("bounded block displacement fits i32");
    code[displacement..displacement + RELATIVE_BYTES].copy_from_slice(&relative.to_le_bytes());
}

/// Zero skips exactly the following near jump; no host flags change.
pub fn skip_jump_if_budget_zero(code: &mut Vec<u8>) {
    code.extend([JRCXZ, NEAR_JUMP_BYTES]);
}

pub fn push_budget_pointer(code: &mut Vec<u8>) {
    push(code, HostGpr::Rsi);
}

pub fn pop_budget_pointer(code: &mut Vec<u8>) {
    pop(code, HostGpr::Rsi);
}

pub fn push(code: &mut Vec<u8>, register: HostGpr) {
    if register as u8 >= 8 {
        code.push(REX | REX_B);
    }
    code.push(PUSH_REGISTER | (register as u8 & 7));
}

pub fn pop(code: &mut Vec<u8>, register: HostGpr) {
    if register as u8 >= 8 {
        code.push(REX | REX_B);
    }
    code.push(POP_REGISTER | (register as u8 & 7));
}

pub fn load_budget(code: &mut Vec<u8>) {
    const _: () = assert!(crate::block::loop_budget::REMAINING_OFFSET == 0);
    code.extend([
        REX | REX_W,
        MOV_LOAD,
        (HostGpr::Rcx as u8) << 3 | HostGpr::Rsi as u8,
    ]);
}

pub fn store_budget(code: &mut Vec<u8>) {
    code.extend([
        REX | REX_W,
        MOV_STORE,
        (HostGpr::Rcx as u8) << 3 | HostGpr::Rsi as u8,
    ]);
}

pub fn decrement_budget_preserving_flags(code: &mut Vec<u8>) {
    code.extend([
        REX | REX_W,
        LEA,
        DISP8_MODE | ((HostGpr::Rcx as u8) << 3) | HostGpr::Rcx as u8,
    ]);
    code.extend((-1i8).to_le_bytes());
}

/// The fallback path counts one block before running its body.
pub fn decrement_stored_budget(code: &mut Vec<u8>) {
    code.extend([
        REX | REX_W,
        INC_DEC_GROUP,
        (DEC_EXTENSION << 3) | HostGpr::Rsi as u8,
    ]);
}
