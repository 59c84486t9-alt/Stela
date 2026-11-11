//! AMX register operations (`extrx extry fma* fms* mac16 vecfp matfp vecint
//! matint genlut`) inside system-mode blocks whose machine has AMX: the
//! block calls [`routine`] through the PE's cell ([`super::amx_transfer::Cell`])
//! instead of ending at the word. The routine takes the host path of
//! `amx::native` for the operand when one covers it, else the model
//! (`amx::model::execute_for`), which is their definition; neither touches
//! memory or raises an exception. A zero register file (AMX off for the
//! governing EL, a trapping HACR_EL2, no live state) or a routine that does
//! not complete the word leaves the block at it for the engine's service,
//! with nothing changed.
//!
//! The call is SysV on a 16-byte aligned stack, as the PAC service's: it
//! saves RSI and RDI, the one pinned register a call may change and the
//! frame; it clobbers RAX, RCX, RDX, R8-R11, every vector register and
//! flags. Between instructions a block keeps nothing else live but the
//! pinned registers, which the call preserves; the routine sets and restores
//! MXCSR itself.
use super::amx_transfer::{Cell, KINDS, ROUTINE, SAMPLE};
use super::asm::{Alu, Code, Cond, Gpr, Mem, Patch, Size};
use crate::amx::model::{self, AmxMemory, MemoryFault};
use crate::amx::{AmxInstruction, AmxOperand, AmxOperation, AmxRegisters};
use crate::{Anchor, Place, aarch64::Register};
use alloc::vec::Vec;

/// The operations a block completes through [`routine`].
pub const fn calls(operation: AmxOperation) -> bool {
    use AmxOperation::*;
    matches!(
        operation,
        ExtractX
            | ExtractY
            | Fma64
            | Fms64
            | Fma32
            | Fms32
            | Fma16
            | Fms16
            | Mac16
            | VectorFloat
            | MatrixFloat
            | VectorInteger
            | MatrixInteger
            | GenerateLookup
    )
}

/// What a register operation reaches of memory: nothing.
struct NoMemory;

impl AmxMemory for NoMemory {
    fn read(&mut self, address: u64, _: &mut [u8]) -> Result<(), MemoryFault> {
        Err(MemoryFault {
            address,
            write: false,
        })
    }
    fn write(&mut self, address: u64, _: &[u8]) -> Result<(), MemoryFault> {
        Err(MemoryFault {
            address,
            write: true,
        })
    }
}

/// Complete the operation numbered `operation` (bits 9:5 of its word) with
/// `operand` on the cell's registers: 1, or 0 with nothing changed.
///
/// # Safety
/// `cell` is the PE's cell with a live register file at `registers`, which
/// nothing else accesses during the call.
unsafe fn complete(cell: *mut Cell, operation: u32, operand: u64) -> u64 {
    // SAFETY: the caller's contract.
    let cell = unsafe { &mut *cell };
    let number = operation as usize;
    let (Some(generation), Some(Some(operation))) = (cell.generation, CALLED.get(number)) else {
        return 0;
    };
    if cell.registers == 0 {
        return 0;
    }
    // SAFETY: live and exclusive (the caller's contract).
    let registers = unsafe { &mut *(cell.registers as *mut AmxRegisters) };
    let counts = cell.kernels[number];
    let started = (counts[0] + counts[1]).is_multiple_of(SAMPLE).then(ticks);
    let path = if cell
        .native
        .execute(generation, registers, *operation, operand)
    {
        0
    } else if model::execute_for(generation, registers, *operation, operand, &mut NoMemory).is_ok()
    {
        1
    } else {
        // No register operation fails; were one to, the service reports it.
        return 0;
    };
    if let Some(started) = started {
        let sampled = &mut cell.sampled[number][path];
        sampled[0] += ticks().wrapping_sub(started);
        sampled[1] += 1;
    }
    cell.kernels[number][path] += 1;
    cell.calls += 1;
    1
}

/// The time stamp counter, or 0 where there is none.
fn ticks() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: RDTSC is unprivileged on every host Stela runs on.
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// The operation each number names, where blocks call the routine for it.
const CALLED: [Option<AmxOperation>; KINDS] = {
    let mut table = [None; KINDS];
    let mut index = 0;
    while index < AmxOperation::ALL.len() {
        let operation = AmxOperation::ALL[index];
        let number = operation.encoding().0 as usize;
        if number < KINDS && calls(operation) {
            table[number] = Some(operation);
        }
        index += 1;
    }
    table
};

/// The routine blocks call: `routine(cell, operation, operand)`.
///
/// # Safety
/// As [`complete`]: blocks call it with the anchor's cell after checking
/// that its register file is live, and the PE runs nothing else meanwhile.
#[cfg(target_arch = "x86_64")]
pub unsafe extern "sysv64" fn routine(cell: *mut Cell, operation: u32, operand: u64) -> u64 {
    // SAFETY: the caller's contract.
    unsafe { complete(cell, operation, operand) }
}

/// Only x86-64 runs translated code; ARM hosts compile the routine alone.
///
/// # Safety
/// As on x86-64.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe extern "C" fn routine(cell: *mut Cell, operation: u32, operand: u64) -> u64 {
    // SAFETY: the caller's contract.
    unsafe { complete(cell, operation, operand) }
}

/// The call of `instruction`'s routine; the jumps to its exit.
pub(super) fn emit(code: &mut Code, instruction: &AmxInstruction) -> Vec<Patch> {
    use Gpr::{R11, Rax, Rcx, Rdi, Rdx, Rsi, Rsp};
    use Size::Qword;
    debug_assert!(calls(instruction.operation));
    super::load(
        code,
        match instruction.operand {
            AmxOperand::Register(index) if index < 31 => Register::X(index),
            AmxOperand::Register(_) | AmxOperand::None => Register::Zero,
        },
    );
    let mut exits = Vec::new();
    let mut asm = code.asm();
    super::amx_transfer::file_address(&mut asm);
    asm.test(Qword, Rcx, Rcx);
    exits.push(asm.jcc(Cond::E));
    asm.place(Rcx, Place::new(Anchor::Amx, 0));
    asm.mov(Qword, R11, Rsp);
    asm.alu_imm8(Alu::And, Qword, Rsp, -16);
    asm.push(R11);
    asm.push(Rdi);
    // The one pinned register a call may change, and the alignment.
    asm.push(Rsi);
    asm.push(Rsi);
    asm.mov(Qword, Rdx, Rax);
    asm.mov_imm32(Rsi, instruction.operation.encoding().0);
    asm.mov(Qword, Rdi, Rcx);
    asm.call_rm(Mem::base(Rdi, ROUTINE));
    asm.pop(Rsi);
    asm.pop(Rsi);
    asm.pop(Rdi);
    asm.pop(Rsp);
    asm.test(Qword, Rax, Rax);
    exits.push(asm.jcc(Cond::E));
    exits
}

#[cfg(test)]
mod tests;
