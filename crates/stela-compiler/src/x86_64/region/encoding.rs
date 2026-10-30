//! Integer encodings, including flag-preserving variants.
use crate::aarch64::{Logical, Shift, Width};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Mem, ShiftOp, Size, Unary, resolve};

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

const GPR_BYTES: usize = core::mem::size_of::<u64>();

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
/// Borrow only within a nonfaulting span, with native ABI restoration.
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
#[cfg(test)]
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

pub fn patch_relative(code: &mut Code, displacement: usize, target: usize) {
    let relative = i32::try_from(target as isize - (displacement + RELATIVE_BYTES) as isize)
        .expect("bounded block displacement fits i32");
    code.patch(displacement, relative.to_le_bytes());
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
