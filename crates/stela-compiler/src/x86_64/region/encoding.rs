//! Integer encodings, including flag-preserving variants.
use super::{BYTE_LOAD_BYTES, DOUBLEWORD_LOAD_BYTES, HALFWORD_LOAD_BYTES, WORD_LOAD_BYTES};
use crate::aarch64::{AddressMode, Logical, Shift, Width};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Mem, ShiftOp, Size, Unary, resolve};
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
    /// The encoder's register.
    const fn gpr(self) -> Gpr {
        crate::x86_64::simd::encode::gpr(self as u8)
    }
}

fn size(width: Width) -> Size {
    Size::of(width == Width::X64)
}

/// `[base + displacement]` with an 8-bit displacement field when it fits,
/// else a 32-bit one.
fn displaced(base: HostGpr, displacement: i32) -> Mem {
    match i8::try_from(displacement) {
        Ok(short) => Mem::base_disp8(base.gpr(), short),
        Err(_) => Mem::base_disp32(base.gpr(), displacement),
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
#[derive(Debug, Clone, Copy)]
pub enum ImmediateExtension {
    Add,
    And,
    Subtract,
    Compare,
}

impl ImmediateExtension {
    const fn alu(self) -> Alu {
        match self {
            Self::Add => Alu::Add,
            Self::And => Alu::And,
            Self::Subtract => Alu::Sub,
            Self::Compare => Alu::Cmp,
        }
    }
}

pub fn nop(code: &mut Code) {
    code.asm().nop();
}

pub fn copy(code: &mut Code, destination: HostGpr, source: HostGpr, width: Width) {
    code.asm().mov(size(width), destination.gpr(), source.gpr());
}

/// `lea destination, [base + displacement]`, 64-bit, with the shortest
/// displacement field, 8 bits for zero.
pub fn lea(code: &mut Code, destination: HostGpr, base: HostGpr, displacement: i32) {
    code.asm().lea(
        Size::Qword,
        destination.gpr(),
        displaced(base, displacement),
    );
}

/// `test register8, immediate`: the low byte of any GPR (SPL, BPL, SIL and
/// DIL rather than AH, CH, DH and BH).
pub fn test_low_byte(code: &mut Code, register: HostGpr, immediate: u8) {
    code.asm()
        .test_imm(Size::Byte, register.gpr(), i32::from(immediate));
}

/// The frame slot of guest register `slot`.
fn frame_slot(slot: usize) -> Mem {
    displaced(FRAME, (slot * GPR_BYTES) as i32)
}

pub fn load(code: &mut Code, destination: HostGpr, slot: usize) {
    code.asm()
        .mov_load(Size::Qword, destination.gpr(), frame_slot(slot));
}

pub fn store(code: &mut Code, source: HostGpr, slot: usize) {
    code.asm()
        .mov_store(Size::Qword, frame_slot(slot), source.gpr());
}

/// The guest NZCV word.
fn nzcv() -> Mem {
    const NZCV_OFFSET: i32 = core::mem::offset_of!(crate::GuestState, nzcv) as i32;
    Mem::base_disp32(FRAME.gpr(), NZCV_OFFSET)
}

pub fn load_nzcv(code: &mut Code, destination: HostGpr) {
    code.asm().mov_load(Size::Dword, destination.gpr(), nzcv());
}

pub fn store_nzcv(code: &mut Code, source: HostGpr) {
    code.asm().mov_store(Size::Dword, nzcv(), source.gpr());
}

pub fn immediate(code: &mut Code, destination: HostGpr, value: u64, width: Width) {
    match width {
        Width::X64 => code.asm().mov_imm64(destination.gpr(), value),
        Width::W32 => code.asm().mov_imm32(destination.gpr(), value as u32),
    }
}

pub fn binary(
    code: &mut Code,
    destination: HostGpr,
    source: HostGpr,
    opcode: Binary,
    width: Width,
) {
    code.asm()
        .alu(opcode.alu(), size(width), destination.gpr(), source.gpr());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binary {
    Add,
    Sub,
    And,
    Or,
    Xor,
}

impl Binary {
    const fn alu(self) -> Alu {
        match self {
            Self::Add => Alu::Add,
            Self::Sub => Alu::Sub,
            Self::And => Alu::And,
            Self::Or => Alu::Or,
            Self::Xor => Alu::Xor,
        }
    }
}

/// Low product modulo operand width; only destination and host flags change.
pub fn multiply(code: &mut Code, destination: HostGpr, source: HostGpr, width: Width) {
    code.asm()
        .imul(size(width), destination.gpr(), source.gpr());
}

pub fn negate(code: &mut Code, destination: HostGpr, width: Width) {
    code.asm().unary(Unary::Neg, size(width), destination.gpr());
}

pub fn logical_opcode(kind: Logical) -> Binary {
    match kind {
        Logical::And => Binary::And,
        Logical::Or => Binary::Or,
        Logical::Xor => Binary::Xor,
    }
}

pub fn arithmetic_immediate(
    code: &mut Code,
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

/// `op destination, imm32`, in its accumulator form for RAX.
pub fn integer_immediate(
    code: &mut Code,
    destination: HostGpr,
    extension: ImmediateExtension,
    value: u32,
    width: Width,
) {
    if destination == HostGpr::Rax {
        code.asm()
            .alu_accumulator_imm32(extension.alu(), size(width), value as i32);
    } else {
        group_immediate(code, destination, extension, value, width);
    }
}

/// `op destination, imm32` (81 /digit).
fn group_immediate(
    code: &mut Code,
    destination: HostGpr,
    extension: ImmediateExtension,
    value: u32,
    width: Width,
) {
    code.asm().alu_imm32(
        extension.alu(),
        size(width),
        destination.gpr(),
        value as i32,
    );
}

pub fn shift(code: &mut Code, kind: Shift, amount: u8, width: Width) {
    shift_register(code, RIGHT, kind, amount, width);
}

pub fn shift_register(
    code: &mut Code,
    destination: HostGpr,
    kind: Shift,
    amount: u8,
    width: Width,
) {
    let op = match kind {
        Shift::Lsl => ShiftOp::Shl,
        Shift::Lsr => ShiftOp::Shr,
        Shift::Asr => ShiftOp::Sar,
        Shift::Ror => ShiftOp::Ror,
    };
    code.asm()
        .shift_imm(op, size(width), destination.gpr(), amount);
}

pub fn invert(code: &mut Code, width: Width) {
    code.asm().unary(Unary::Not, size(width), RIGHT.gpr());
}

const REX: u8 = 0x40;
const REX_W: u8 = 8;
const REX_R: u8 = 4;
const REX_B: u8 = 1;
const MOV_LOAD: u8 = 0x8b;
const MOV_STORE: u8 = 0x89;
const TWO_BYTE_OPCODE: u8 = 0x0f;
const FRAME_STORE_BYTES: usize = 7;
const GPR_BYTES: usize = core::mem::size_of::<u64>();
const ECX_FROM_RAX_MEMORY: u8 = 0x08;
const FRAME_DISP32_FROM_RCX: u8 = 0x8f;
const FRAME_DISP32_FROM_R8: u8 = 0x87;
const R8D_FROM_RAX_DISP8: u8 = 0x40;

fn ordinary_address_ends(code: &[u8], base: usize, displacement: i32) -> Option<Vec<usize>> {
    use super::super::{RangeCheck, STACK_ALIGNMENT_CHECK, STACK_ALIGNMENT_CHECK_ENDS};
    const RAX_FROM_FRAME_DISP32: u8 = 0x87;
    const BASE_LOAD_BYTES: usize = 7;
    const SP: usize = 31;
    if code.get(0..3)? != [REX | REX_W, MOV_LOAD, RAX_FROM_FRAME_DISP32]
        || code.get(3..BASE_LOAD_BYTES)?
            != u32::try_from(base.checked_mul(GPR_BYTES)?)
                .ok()?
                .to_le_bytes()
    {
        return None;
    }
    let mut ends = vec![BASE_LOAD_BYTES];
    let mut cursor = BASE_LOAD_BYTES;
    // SCTLR_ELx.SA checks an SP base before the address addition.
    if base == SP && code[cursor..].starts_with(&STACK_ALIGNMENT_CHECK) {
        ends.extend(STACK_ALIGNMENT_CHECK_ENDS.map(|end| cursor + end));
        cursor += STACK_ALIGNMENT_CHECK.len();
    }
    // The Offset form's one LEA, or nothing for a zero offset.
    let mut add = Code::new();
    super::super::address_add(&mut add, displacement, AddressMode::Offset);
    if !add.is_empty() {
        if code.get(cursor..cursor + add.len())? != add {
            return None;
        }
        cursor += add.len();
        ends.push(cursor);
    }
    // A system-mode access checks the address against the guest's ranges.
    if let Some((_, check_ends)) = RangeCheck::at(&code[cursor..]) {
        ends.extend(check_ends.iter().map(|end| cursor + end));
    }
    Some(ends)
}

fn check_frame_store(code: &[u8], start: usize, guest: usize, rex: u8, modrm: u8) -> Option<usize> {
    check_frame_access(code, start, guest, [rex, MOV_STORE, modrm])
}

fn check_frame_access(code: &[u8], start: usize, guest: usize, opcode: [u8; 3]) -> Option<usize> {
    let end = start.checked_add(FRAME_STORE_BYTES)?;
    if code.get(start..start + 3)? != opcode
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
    const MOVZX_WORD: u8 = 0xb7;
    let memory_recipe: &[u8] = match bytes {
        BYTE_LOAD_BYTES => &[TWO_BYTE_OPCODE, MOVZX_BYTE, ECX_FROM_RAX_MEMORY],
        HALFWORD_LOAD_BYTES => &[TWO_BYTE_OPCODE, MOVZX_WORD, ECX_FROM_RAX_MEMORY],
        WORD_LOAD_BYTES => &[MOV_LOAD, ECX_FROM_RAX_MEMORY],
        DOUBLEWORD_LOAD_BYTES => &[REX | REX_W, MOV_LOAD, ECX_FROM_RAX_MEMORY],
        _ => return None,
    };
    let mut ends = ordinary_address_ends(code, base, displacement)?;
    let address_end = *ends.last()?;
    let load_end = address_end + memory_recipe.len();
    if code.get(address_end..load_end)? != memory_recipe {
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

/// Unsigned W and X pair recipe: RCX/R8 results, both accesses before either
/// commit. Writeback, signed pairs and duplicate destinations are not selected.
pub fn ordinary_pair_load_ends(
    code: &[u8],
    bytes: u8,
    base: usize,
    data: [Option<usize>; 2],
    displacement: i32,
) -> Option<Vec<usize>> {
    let (first, second): (&[u8], [u8; 4]) = match bytes {
        WORD_LOAD_BYTES => (
            &[MOV_LOAD, ECX_FROM_RAX_MEMORY],
            [REX | REX_R, MOV_LOAD, R8D_FROM_RAX_DISP8, WORD_LOAD_BYTES],
        ),
        DOUBLEWORD_LOAD_BYTES => (
            &[REX | REX_W, MOV_LOAD, ECX_FROM_RAX_MEMORY],
            [
                REX | REX_W | REX_R,
                MOV_LOAD,
                R8D_FROM_RAX_DISP8,
                DOUBLEWORD_LOAD_BYTES,
            ],
        ),
        _ => return None,
    };
    let mut ends = ordinary_address_ends(code, base, displacement)?;
    let address_end = *ends.last()?;
    let first_end = address_end + first.len();
    let second_end = first_end + second.len();
    if code.get(address_end..first_end)? != first || code.get(first_end..second_end)? != second {
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

/// The data of a store element staged in RCX (`second` false) or R8: its
/// frame load, or zero for ZR.
fn check_store_data(
    code: &[u8],
    start: usize,
    guest: Option<usize>,
    second: bool,
) -> Option<usize> {
    const ZERO_ECX: [u8; 2] = [0x31, 0xc9];
    const ZERO_R8D: [u8; 3] = [REX | REX_R | REX_B, 0x31, 0xc0];
    match (guest, second) {
        (Some(guest), false) => check_frame_access(
            code,
            start,
            guest,
            [REX | REX_W, MOV_LOAD, FRAME_DISP32_FROM_RCX],
        ),
        (Some(guest), true) => check_frame_access(
            code,
            start,
            guest,
            [REX | REX_W | REX_R, MOV_LOAD, FRAME_DISP32_FROM_R8],
        ),
        (None, false) => code
            .get(start..)?
            .starts_with(&ZERO_ECX)
            .then_some(start + ZERO_ECX.len()),
        (None, true) => code
            .get(start..)?
            .starts_with(&ZERO_R8D)
            .then_some(start + ZERO_R8D.len()),
    }
}

/// The exact shared store of one element staged in RCX to [RAX], without
/// the page-crossing split.
fn single_store(bytes: u8) -> Option<&'static [u8]> {
    const OPERAND_SIZE: u8 = 0x66;
    const MOV_BYTE_STORE: u8 = 0x88;
    Some(match bytes {
        BYTE_LOAD_BYTES => &[MOV_BYTE_STORE, ECX_FROM_RAX_MEMORY],
        HALFWORD_LOAD_BYTES => &[OPERAND_SIZE, MOV_STORE, ECX_FROM_RAX_MEMORY],
        WORD_LOAD_BYTES => &[MOV_STORE, ECX_FROM_RAX_MEMORY],
        DOUBLEWORD_LOAD_BYTES => &[REX | REX_W, MOV_STORE, ECX_FROM_RAX_MEMORY],
        _ => return None,
    })
}

/// Inspect the exact shared store: address, the data's frame load (or
/// zero) into RCX, and one host store, or with `crossing` the page-crossing
/// store recipe (`memory_store::crossing_store`), retaining its emitted
/// instruction boundaries. Branches stay within that recipe. Also returns the
/// index of the staged data's segment in the ends.
pub fn ordinary_store_ends(
    code: &[u8],
    bytes: u8,
    base: usize,
    data: Option<usize>,
    displacement: i32,
    crossing: bool,
) -> Option<(Vec<usize>, usize)> {
    let mut ends = ordinary_address_ends(code, base, displacement)?;
    let data_segment = ends.len();
    let data_end = check_store_data(code, *ends.last()?, data, false)?;
    ends.push(data_end);
    let recipe;
    let crossing_ends;
    let store = if crossing {
        (recipe, crossing_ends) = super::super::memory_store::crossing_store(bytes)?;
        &recipe[..]
    } else {
        crossing_ends = Vec::new();
        single_store(bytes)?
    };
    let end = data_end + store.len();
    if code.get(data_end..end)? != store {
        return None;
    }
    if crossing {
        ends.extend(crossing_ends.into_iter().map(|offset| data_end + offset));
    } else {
        ends.push(end);
    }
    (code.len() == end).then_some((ends, data_segment))
}

/// Inspect the exact shared W or X pair store: address, both elements'
/// data in RCX and R8, then one host store each, first element first. Also
/// the index of the first element's data segment in the ends.
pub fn ordinary_pair_store_ends(
    code: &[u8],
    bytes: u8,
    base: usize,
    data: [Option<usize>; 2],
    displacement: i32,
) -> Option<(Vec<usize>, usize)> {
    let second: [u8; 4] = match bytes {
        WORD_LOAD_BYTES => [REX | REX_R, MOV_STORE, R8D_FROM_RAX_DISP8, WORD_LOAD_BYTES],
        DOUBLEWORD_LOAD_BYTES => [
            REX | REX_W | REX_R,
            MOV_STORE,
            R8D_FROM_RAX_DISP8,
            DOUBLEWORD_LOAD_BYTES,
        ],
        _ => return None,
    };
    let mut ends = ordinary_address_ends(code, base, displacement)?;
    let data_segment = ends.len();
    let mut end = *ends.last()?;
    for (index, guest) in data.into_iter().enumerate() {
        end = check_store_data(code, end, guest, index == 1)?;
        ends.push(end);
    }
    let first = single_store(bytes)?;
    for store in [first, &second[..]] {
        let start = end;
        end += store.len();
        if code.get(start..end)? != store {
            return None;
        }
        ends.push(end);
    }
    (code.len() == end).then_some((ends, data_segment))
}

/// Native conditions after a full-width ARM subtraction (C is inverted CF).
#[derive(Debug, Clone, Copy)]
pub enum NativeCondition {
    Equal,
    NotEqual,
    AboveEqual,
    Below,
    Sign,
    NotSign,
    Overflow,
    NotOverflow,
    Above,
    BelowEqual,
    GreaterEqual,
    Less,
    Greater,
    LessEqual,
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
    /// The encoder's condition code.
    const fn cond(self) -> Cond {
        match self {
            Self::Equal => Cond::E,
            Self::NotEqual => Cond::Ne,
            Self::AboveEqual => Cond::Ae,
            Self::Below => Cond::B,
            Self::Sign => Cond::S,
            Self::NotSign => Cond::Ns,
            Self::Overflow => Cond::O,
            Self::NotOverflow => Cond::No,
            Self::Above => Cond::A,
            Self::BelowEqual => Cond::Be,
            Self::GreaterEqual => Cond::Ge,
            Self::Less => Cond::L,
            Self::Greater => Cond::G,
            Self::LessEqual => Cond::Le,
        }
    }

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
    code: &mut Code,
    destination: HostGpr,
    source: HostGpr,
    condition: NativeCondition,
    width: Width,
) {
    code.asm().cmov(
        condition.cond(),
        size(width),
        destination.gpr(),
        source.gpr(),
    );
}

/// `lea register, [register + 1]`.
pub fn increment_preserving_flags(code: &mut Code, register: HostGpr, width: Width) {
    code.asm().lea(
        size(width),
        register.gpr(),
        Mem::base_disp8(register.gpr(), 1),
    );
}

const RELATIVE_BYTES: usize = core::mem::size_of::<i32>();

/// `jmp rel32`; the offset of its displacement field, which
/// [`patch_relative`] points.
pub fn near_jump(code: &mut Code) -> usize {
    code.asm().jmp().offset()
}

/// `jcc rel32`; the offset of its displacement field.
pub fn conditional_jump(code: &mut Code, condition: NativeCondition) -> usize {
    code.asm().jcc(condition.cond()).offset()
}

pub fn patch_relative(code: &mut [u8], displacement: usize, target: usize) {
    let relative = i32::try_from(target as isize - (displacement + RELATIVE_BYTES) as isize)
        .expect("bounded block displacement fits i32");
    code[displacement..displacement + RELATIVE_BYTES].copy_from_slice(&relative.to_le_bytes());
}

/// Zero skips exactly the following near jump; no host flags change.
pub fn skip_jump_if_budget_zero(code: &mut Code) {
    const NEAR_JUMP_BYTES: usize = 1 + RELATIVE_BYTES;
    let skip = code.asm().jrcxz();
    resolve(code, skip, skip.end() + NEAR_JUMP_BYTES);
}

pub fn push_budget_pointer(code: &mut Code) {
    push(code, HostGpr::Rsi);
}

pub fn pop_budget_pointer(code: &mut Code) {
    pop(code, HostGpr::Rsi);
}

pub fn push(code: &mut Code, register: HostGpr) {
    code.asm().push(register.gpr());
}

pub fn pop(code: &mut Code, register: HostGpr) {
    code.asm().pop(register.gpr());
}

/// The budget pointer's remaining count.
fn budget() -> Mem {
    const _: () = assert!(crate::block::loop_budget::REMAINING_OFFSET == 0);
    Mem::base(HostGpr::Rsi.gpr(), 0)
}

pub fn load_budget(code: &mut Code) {
    code.asm()
        .mov_load(Size::Qword, HostGpr::Rcx.gpr(), budget());
}

pub fn store_budget(code: &mut Code) {
    code.asm()
        .mov_store(Size::Qword, budget(), HostGpr::Rcx.gpr());
}

/// `lea rcx, [rcx - 1]`.
pub fn decrement_budget_preserving_flags(code: &mut Code) {
    let rcx = HostGpr::Rcx.gpr();
    code.asm().lea(Size::Qword, rcx, Mem::base_disp8(rcx, -1));
}

/// The fallback path counts one block before running its body.
pub fn decrement_stored_budget(code: &mut Code) {
    code.asm().dec(Size::Qword, budget());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_address_forms_encode_as_the_assembler_does() {
        let encode = |emit: &dyn Fn(&mut Code)| {
            let mut code = Code::new();
            emit(&mut code);
            code
        };
        // lea rax,[rsi+8]; lea rax,[r9+0x1000]; lea rax,[rax-1]
        assert_eq!(
            encode(&|code| lea(code, HostGpr::Rax, HostGpr::Rsi, 8)),
            [0x48, 0x8d, 0x46, 0x08]
        );
        assert_eq!(
            encode(&|code| lea(code, HostGpr::Rax, HostGpr::R9, 0x1000)),
            [0x49, 0x8d, 0x81, 0x00, 0x10, 0x00, 0x00]
        );
        assert_eq!(
            encode(&|code| lea(code, HostGpr::Rax, HostGpr::Rax, -1)),
            [0x48, 0x8d, 0x40, 0xff]
        );
        // test cl,15; test sil,15; test r10b,15
        assert_eq!(
            encode(&|code| test_low_byte(code, HostGpr::Rcx, 15)),
            [0xf6, 0xc1, 0x0f]
        );
        assert_eq!(
            encode(&|code| test_low_byte(code, HostGpr::Rsi, 15)),
            [0x40, 0xf6, 0xc6, 0x0f]
        );
        assert_eq!(
            encode(&|code| test_low_byte(code, HostGpr::R10, 15)),
            [0x41, 0xf6, 0xc2, 0x0f]
        );
    }
}
