//! AMX `ldx ldy ldz stx sty stz` inside system-mode blocks whose machine has
//! AMX (`NativeSystem::amx`), which then run on past them instead of ending
//! at each (corsix `ldst.c`; the engine's model, `amx::model::transfer`,
//! stays their definition and the fallback).
//!
//! [`Anchor::Amx`] names the PE's [`Cell`]: the address of its live
//! `AmxRegisters`, which the engine leaves zero whenever native code must
//! not touch them (AMX disabled for the governing EL, a trapping HACR_EL2,
//! no live state), and the count of moves completed here. The code moves one row, or the pair bit 62 selects (rows
//! `n` and `n+1` modulo the file, 128-byte aligned), between the
//! 56-bit sign-extended operand address and the file, through the guest
//! range check and direct guest-VA accesses like STR's. It exits at the word,
//! for the engine's service to complete it exactly, for a zero anchor, an
//! X/Y load of four or nonconsecutive rows (bits 60 and 61 with 62), a
//! misaligned pair and a single row across a 4 KiB page. A load reads all of
//! its memory before it writes a row; a store reads the rows first. A fault
//! of a guest access, which then has changed nothing, is completed by the
//! engine's service at the word, which delivers it with its own syndrome
//! (`native_failure`). Code clobbers RAX, RCX, RDX, XMM0-7 (and their YMM
//! and ZMM forms) and host flags.
//!
//! Host tiers, chosen once from the target: SSE2 MOVDQU (four per row), AVX
//! VMOVDQU YMM (two), AVX-512F VMOVDQU64 ZMM (one) where the OS has enabled
//! the ZMM state, which the target's AVX-512F already requires.
use super::asm::{Alu, BitTest, Code, Cond, Evex, Gpr, Map, Mem, Patch, Pp, ShiftOp, Size, Vex};
use crate::amx::{AmxInstruction, AmxOperand, AmxOperation, state};
use crate::{Anchor, GuestAddress, Place, TargetCpu, aarch64::Register, block::ExitKind};
use alloc::vec::Vec;

const ROW: i32 = state::ROW_BYTES as i32;
/// Bit 62: two rows.
const PAIR: u8 = 62;
/// The bits 60 to 63 of an operand.
const FORM_SHIFT: u8 = 60;
/// The row index starts at bit 56.
const ROW_SHIFT: u8 = 56;
/// A pair's alignment.
const PAIR_ALIGNMENT: i32 = 128;
const PAGE_MASK: i32 = 0xfff;

/// What [`Anchor::Amx`] names: the engine's per-PE cell. Native code reads
/// `registers` and `routine` and counts `moves`; the routine
/// ([`super::amx_routine`]) reads the rest and counts `calls`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    /// The live `AmxRegisters`, or zero.
    pub registers: u64,
    /// Moves blocks completed, which the engine adds to its statistics.
    pub moves: u64,
    /// The address of [`super::amx_routine::routine`].
    pub routine: u64,
    /// Register operations the routine completed.
    pub calls: u64,
    /// Those operations by number (bits 9:5 of the word) and path: a host
    /// kernel of `amx::native`, then the model.
    pub kernels: [[u64; 2]; KINDS],
    /// Time stamp counter ticks of every [`SAMPLE`]th call of each
    /// operation, by path, and those calls.
    pub sampled: [[[u64; 2]; 2]; KINDS],
    /// The machine's AMX generation, which the routine computes for.
    pub generation: Option<crate::amx::Generation>,
    /// The host paths the routine takes.
    pub native: crate::amx::native::Native,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            registers: 0,
            moves: 0,
            routine: 0,
            calls: 0,
            kernels: [[0; 2]; KINDS],
            sampled: [[[0; 2]; 2]; KINDS],
            generation: None,
            native: crate::amx::native::Native::MODEL,
        }
    }
}

/// The AMX operation numbers (bits 9:5 of a word).
pub const KINDS: usize = 23;
/// One call in this many of each operation is timed.
pub const SAMPLE: u64 = 64;

const REGISTERS: i32 = core::mem::offset_of!(Cell, registers) as i32;
const MOVES: i32 = core::mem::offset_of!(Cell, moves) as i32;
pub(super) const ROUTINE: i32 = core::mem::offset_of!(Cell, routine) as i32;

/// RCX = the register file's address (zero when moves exit).
pub(super) fn file_address(asm: &mut super::asm::Asm) {
    asm.place(Gpr::Rcx, Place::new(Anchor::Amx, 0));
    asm.mov_load(Size::Qword, Gpr::Rcx, Mem::base(Gpr::Rcx, REGISTERS));
}

/// The AMX words a block completes inside itself: the moves here, the
/// register operations through the routine (`amx_routine`).
pub fn in_block(operation: AmxOperation) -> bool {
    lowers(operation) || super::amx_routine::calls(operation)
}

/// The moves this lowers: the six row moves and the interleaved Z pair
/// moves `ldzi`/`stzi`.
pub fn lowers(operation: AmxOperation) -> bool {
    matches!(
        operation,
        AmxOperation::LoadX
            | AmxOperation::LoadY
            | AmxOperation::LoadZ
            | AmxOperation::StoreX
            | AmxOperation::StoreY
            | AmxOperation::StoreZ
            | AmxOperation::LoadZInterleaved
            | AmxOperation::StoreZInterleaved
    )
}

/// The vector moves of a tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Width {
    Xmm,
    Ymm,
    Zmm,
}

impl Width {
    pub(crate) const fn of(target: TargetCpu) -> Self {
        if target.supports(TargetCpu::Avx512f) {
            Self::Zmm
        } else if target.supports(TargetCpu::Avx2)
            || target.supports(TargetCpu::F16c)
            || target.supports(TargetCpu::Fma)
        {
            // Each of these requires the OS-enabled YMM state.
            Self::Ymm
        } else {
            Self::Xmm
        }
    }

    const fn bytes(self) -> i32 {
        match self {
            Self::Xmm => 16,
            Self::Ymm => 32,
            Self::Zmm => 64,
        }
    }

    const fn vex() -> Vex {
        Vex {
            map: Map::M0f,
            pp: Pp::Pf3,
            w: false,
            l: true,
        }
    }

    const fn evex() -> Evex {
        Evex {
            map: Map::M0f,
            pp: Pp::Pf3,
            w: true,
            length: 2,
            mask: 0,
            zeroing: false,
            broadcast: false,
            scale: 64,
        }
    }

    /// `movdqu`, `vmovdqu` or `vmovdqu64` from memory.
    fn load(self, asm: &mut super::asm::Asm, register: u8, memory: Mem) {
        match self {
            Self::Xmm => asm.movdqu_load(register, memory),
            Self::Ymm => asm.vex(Self::vex(), 0x6f, register, 0, memory.into()),
            Self::Zmm => asm.evex(Self::evex(), 0x6f, register, 0, memory.into()),
        }
    }

    /// The same to memory.
    fn store(self, asm: &mut super::asm::Asm, memory: Mem, register: u8) {
        match self {
            Self::Xmm => asm.movdqu_store(memory, register),
            Self::Ymm => asm.vex(Self::vex(), 0x7f, register, 0, memory.into()),
            Self::Zmm => asm.evex(Self::evex(), 0x7f, register, 0, memory.into()),
        }
    }
}

/// Where the block exits for the service.
pub(crate) struct Slow {
    pc: GuestAddress,
    exits: Vec<Patch>,
}

/// The file an operation moves, its byte offset in `AmxRegisters` and its
/// rows, and whether it loads.
fn file(operation: AmxOperation) -> (i32, i32, bool) {
    use AmxOperation::*;
    let (offset, rows) = match operation {
        LoadX | StoreX => (state::X_OFFSET, state::X_ROWS),
        LoadY | StoreY => (state::Y_OFFSET, state::Y_ROWS),
        LoadZ | StoreZ => (state::Z_OFFSET, state::Z_ROWS),
        _ => unreachable!("only the six moves are lowered"),
    };
    (
        offset as i32,
        rows as i32,
        matches!(operation, LoadX | LoadY | LoadZ),
    )
}

pub(crate) fn emit(
    code: &mut Code,
    instruction: &AmxInstruction,
    checks: super::MemoryChecks,
    target: TargetCpu,
) -> Slow {
    let operation = instruction.operation;
    if super::amx_routine::calls(operation) {
        return Slow {
            pc: instruction.instruction_pc,
            exits: super::amx_routine::emit(code, instruction),
        };
    }
    debug_assert!(lowers(operation));
    if matches!(
        operation,
        AmxOperation::LoadZInterleaved | AmxOperation::StoreZInterleaved
    ) {
        return interleaved(code, instruction, checks);
    }
    let (base, rows, load) = file(operation);
    let width = Width::of(target);
    super::load(
        code,
        match instruction.operand {
            AmxOperand::Register(index) if index < 31 => Register::X(index),
            AmxOperand::Register(_) | AmxOperand::None => Register::Zero,
        },
    );
    let mut exits = Vec::new();
    let mut asm = code.asm();
    asm.mov(Size::Qword, Gpr::Rdx, Gpr::Rax);
    file_address(&mut asm);
    asm.test(Size::Qword, Gpr::Rcx, Gpr::Rcx);
    exits.push(asm.jcc(Cond::E));
    if load && rows == state::X_ROWS as i32 {
        // Bit 62 with 60 or 61: four rows (M2 on) or nonconsecutive ones
        // (M3 on), or on M1 a pair whose other bits are ignored.
        asm.mov(Size::Qword, Gpr::Rcx, Gpr::Rdx);
        asm.shift_imm(ShiftOp::Shr, Size::Qword, Gpr::Rcx, FORM_SHIFT);
        asm.alu_imm8(Alu::And, Size::Dword, Gpr::Rcx, 7);
        asm.alu_imm8(Alu::Cmp, Size::Dword, Gpr::Rcx, 4);
        exits.push(asm.jcc(Cond::A));
    }
    // The 56-bit operand address, sign-extended from bit 55.
    asm.shift_imm(ShiftOp::Shl, Size::Qword, Gpr::Rax, 64 - ROW_SHIFT);
    asm.shift_imm(ShiftOp::Sar, Size::Qword, Gpr::Rax, 64 - ROW_SHIFT);
    asm.bit_imm(BitTest::Bt, Size::Qword, Gpr::Rdx, PAIR);
    let pair = asm.jcc(Cond::B);
    // One row: in one page, else the service.
    asm.mov(Size::Dword, Gpr::Rcx, Gpr::Rax);
    asm.alu_imm32(Alu::And, Size::Dword, Gpr::Rcx, PAGE_MASK);
    asm.alu_imm32(Alu::Cmp, Size::Dword, Gpr::Rcx, PAGE_MASK + 1 - ROW);
    exits.push(asm.jcc(Cond::A));
    rows_move(code, checks, width, (base, rows, load), 1);
    let done = code.asm().jmp();
    let mut asm = code.asm();
    asm.bind(pair);
    asm.test_accumulator_imm(Size::Byte, PAIR_ALIGNMENT - 1);
    exits.push(asm.jcc(Cond::Ne));
    rows_move(code, checks, width, (base, rows, load), 2);
    let mut asm = code.asm();
    asm.bind(done);
    // Counted once the move is complete: a faulting one is the service's.
    asm.place(Gpr::Rcx, Place::new(Anchor::Amx, 0));
    asm.alu_imm8(Alu::Add, Size::Qword, Mem::base(Gpr::Rcx, MOVES), 1);
    Slow {
        pc: instruction.instruction_pc,
        exits,
    }
}

/// `count` rows between the address in RAX and the file at `base` of
/// `rows` rows from the row bits of the operand in RDX.
fn rows_move(
    code: &mut Code,
    checks: super::MemoryChecks,
    width: Width,
    (base, rows, load): (i32, i32, bool),
    count: i32,
) {
    let bytes = (count * ROW) as u16;
    super::range_check(
        code,
        checks,
        if load {
            super::Access::read(bytes)
        } else {
            super::Access::write(bytes)
        },
    );
    let per_row = ROW / width.bytes();
    let registers = (count * per_row) as u8;
    let mut asm = code.asm();
    let guest = |index: u8| Mem::base(Gpr::Rax, i32::from(index) * width.bytes());
    if load {
        for register in 0..registers {
            asm.guest_access(|asm| width.load(asm, register, guest(register)));
        }
    }
    // RDX = the first row's offset in the file.
    asm.shift_imm(ShiftOp::Shr, Size::Qword, Gpr::Rdx, ROW_SHIFT);
    asm.alu_imm8(Alu::And, Size::Dword, Gpr::Rdx, (rows - 1) as i8);
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Dword,
        Gpr::Rdx,
        ROW.trailing_zeros() as u8,
    );
    file_address(&mut asm);
    for row in 0..count {
        if row != 0 {
            asm.alu_imm8(Alu::Add, Size::Dword, Gpr::Rdx, ROW as i8);
            asm.alu_imm32(Alu::And, Size::Dword, Gpr::Rdx, rows * ROW - 1);
        }
        for part in 0..per_row {
            let register = (row * per_row + part) as u8;
            let held = Mem::indexed(Gpr::Rcx, Gpr::Rdx, 1, base + part * width.bytes());
            if load {
                width.store(&mut asm, held, register);
            } else {
                width.load(&mut asm, register, held);
            }
        }
    }
    if !load {
        for register in 0..registers {
            asm.guest_access(|asm| width.store(asm, guest(register), register));
        }
    }
    if width != Width::Xmm {
        asm.vzeroupper();
    }
}

/// `ldzi`/`stzi` (`ldst.c`): 64 bytes at the operand address, whose 32-bit
/// lanes alternate between the Z rows `n & !1` and `n | 1` (n = bits
/// 61:56), at the same half of each (bytes 0-31 for an even n, 32-63 for an
/// odd one): even lanes are one row's eight, odd lanes the other's. SSE2
/// SHUFPS splits them (0x88 even, 0xDD odd) and UNPCKLPS/UNPCKHPS join
/// them; wider tiers would shuffle within 128-bit lanes and save nothing
/// measurable on 64 bytes. One page, else the service.
fn interleaved(code: &mut Code, instruction: &AmxInstruction, checks: super::MemoryChecks) -> Slow {
    use super::asm::Rm;
    let load = instruction.operation == AmxOperation::LoadZInterleaved;
    super::load(
        code,
        match instruction.operand {
            AmxOperand::Register(index) if index < 31 => Register::X(index),
            AmxOperand::Register(_) | AmxOperand::None => Register::Zero,
        },
    );
    let mut exits = Vec::new();
    let mut asm = code.asm();
    asm.mov(Size::Qword, Gpr::Rdx, Gpr::Rax);
    file_address(&mut asm);
    asm.test(Size::Qword, Gpr::Rcx, Gpr::Rcx);
    exits.push(asm.jcc(Cond::E));
    asm.shift_imm(ShiftOp::Shl, Size::Qword, Gpr::Rax, 64 - ROW_SHIFT);
    asm.shift_imm(ShiftOp::Sar, Size::Qword, Gpr::Rax, 64 - ROW_SHIFT);
    asm.mov(Size::Dword, Gpr::Rcx, Gpr::Rax);
    asm.alu_imm32(Alu::And, Size::Dword, Gpr::Rcx, PAGE_MASK);
    asm.alu_imm32(Alu::Cmp, Size::Dword, Gpr::Rcx, PAGE_MASK + 1 - ROW);
    exits.push(asm.jcc(Cond::A));
    super::range_check(
        code,
        checks,
        if load {
            super::Access::read(ROW as u16)
        } else {
            super::Access::write(ROW as u16)
        },
    );
    let mut asm = code.asm();
    let guest = |index: u8| Mem::base(Gpr::Rax, i32::from(index) * 16);
    // RDX = the even row's offset plus the half: (n & !1) * 64 + (n & 1) * 32.
    asm.shift_imm(ShiftOp::Shr, Size::Qword, Gpr::Rdx, ROW_SHIFT);
    asm.alu_imm8(Alu::And, Size::Dword, Gpr::Rdx, 63);
    asm.shift_imm(ShiftOp::Shl, Size::Dword, Gpr::Rdx, 6);
    asm.mov(Size::Dword, Gpr::Rcx, Gpr::Rdx);
    asm.alu_imm8(Alu::And, Size::Dword, Gpr::Rcx, 64);
    asm.shift_imm(ShiftOp::Shr, Size::Dword, Gpr::Rcx, 1);
    asm.alu_imm32(Alu::And, Size::Dword, Gpr::Rdx, -128);
    asm.alu(Alu::Add, Size::Dword, Gpr::Rdx, Gpr::Rcx);
    file_address(&mut asm);
    let held = |row: i32, part: i32| {
        Mem::indexed(
            Gpr::Rcx,
            Gpr::Rdx,
            1,
            state::Z_OFFSET as i32 + row * ROW + part * 16,
        )
    };
    if load {
        for register in 0..4 {
            asm.guest_access(|asm| asm.movdqu_load(register, guest(register)));
        }
        // XMM4/5 = even lanes, XMM6/7 = odd lanes, of lanes 0-7 and 8-15.
        for (pair, (even, odd)) in [(0u8, (4u8, 6u8)), (2, (5, 7))] {
            asm.sse(None, &[0x0f, 0x28], even, Rm::Xmm(pair));
            asm.shufps(even, Rm::Xmm(pair + 1), 0x88);
            asm.sse(None, &[0x0f, 0x28], odd, Rm::Xmm(pair));
            asm.shufps(odd, Rm::Xmm(pair + 1), 0xdd);
        }
        asm.movdqu_store(held(0, 0), 4);
        asm.movdqu_store(held(0, 1), 5);
        asm.movdqu_store(held(1, 0), 6);
        asm.movdqu_store(held(1, 1), 7);
    } else {
        asm.movdqu_load(4, held(0, 0));
        asm.movdqu_load(5, held(0, 1));
        asm.movdqu_load(6, held(1, 0));
        asm.movdqu_load(7, held(1, 1));
        for (first, (even, odd)) in [(0u8, (4u8, 6u8)), (2, (5, 7))] {
            asm.sse(None, &[0x0f, 0x28], first, Rm::Xmm(even));
            asm.unpcklps(first, Rm::Xmm(odd));
            asm.sse(None, &[0x0f, 0x28], first + 1, Rm::Xmm(even));
            asm.sse(None, &[0x0f, 0x15], first + 1, Rm::Xmm(odd));
        }
        for register in 0..4 {
            asm.guest_access(|asm| asm.movdqu_store(guest(register), register));
        }
    }
    asm.place(Gpr::Rcx, Place::new(Anchor::Amx, 0));
    asm.alu_imm8(Alu::Add, Size::Qword, Mem::base(Gpr::Rcx, MOVES), 1);
    Slow {
        pc: instruction.instruction_pc,
        exits,
    }
}

pub(crate) fn place(code: &mut Code, slow: Slow) {
    let mut asm = code.asm();
    for exit in slow.exits {
        asm.bind(exit);
    }
    super::block::direct_exit_with(&mut asm, slow.pc, ExitKind::Amx);
}

#[cfg(test)]
mod tests;
