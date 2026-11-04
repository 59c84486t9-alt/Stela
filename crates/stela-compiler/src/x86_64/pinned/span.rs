//! Keep a small set of frame-backed values in scratch registers across pure
//! ALU rows. Every temporary is settled before the next boundary.
use super::{LOCAL_HOSTS, LocalRegisters, PINNED, emit_direct};
use crate::{
    TargetCpu,
    aarch64::{Instruction, Operation, Register},
    x86_64::{
        asm::{Code, Size},
        region::scalar_effects,
    },
};

const MAX_ROWS: usize = 8;
const MIN_ROWS: usize = 3;
const GPRS: usize = 31;
const UNPINNED: u32 = {
    let mut mask = (1 << GPRS) - 1;
    let mut index = 0;
    while index < PINNED.len() {
        if let Register::X(register) = PINNED[index].0 {
            mask &= !(1 << register);
        }
        index += 1;
    }
    mask
};

pub(in crate::x86_64) struct Span {
    locals: LocalRegisters,
    live_in: u32,
}

impl Span {
    /// Return how many rows were examined and a fixed local assignment
    /// only when several independent frame values could benefit.
    pub(in crate::x86_64) fn plan(instructions: &[Instruction]) -> (usize, Option<Self>) {
        let mut count = 0;
        let mut reads_before_write = 0;
        let mut written = 0;
        let mut last_write = 0;
        let mut score = [0_u8; GPRS];
        for instruction in instructions.iter().take(MAX_ROWS) {
            // The shared direct emitter handles precisely these flagless
            // forms without helper calls or implicit scratch in R8..R11.
            if !matches!(
                instruction.operation,
                Operation::AddSub { flags: false, .. }
                    | Operation::AddSubRegister { flags: false, .. }
                    | Operation::LogicalImmediate { flags: false, .. }
                    | Operation::LogicalRegister { flags: false, .. }
            ) {
                break;
            }
            let Some(effect) = scalar_effects(&instruction.operation) else {
                break;
            };
            let reads = effect.reads & UNPINNED;
            let writes = effect.writes & UNPINNED;
            reads_before_write |= reads & !written;
            written |= writes;
            // Give single-step RAX forwarding credit for any read of the
            // immediately preceding destination before proposing locals.
            let mut accessed = (reads & !last_write) | writes;
            while accessed != 0 {
                let index = accessed.trailing_zeros() as usize;
                let bit = 1_u32 << index;
                score[index] +=
                    u8::from(reads & !last_write & bit != 0) + u8::from(writes & bit != 0);
                accessed &= accessed - 1;
            }
            last_write = writes;
            count += 1;
        }
        if count < MIN_ROWS {
            return (count, None);
        }
        let mut locals = [None; LOCAL_HOSTS.len()];
        // Leave the last output in its normal home, including RAX when the
        // next operation could forward it across this span's flush.
        let mut eligible = written & !last_write;
        let mut assigned = 0;
        for local in &mut locals {
            let best = (0..GPRS)
                .filter(|&index| eligible & (1 << index) != 0)
                .max_by_key(|&index| {
                    score[index] - u8::from(reads_before_write & (1 << index) != 0)
                });
            let Some(index) = best else { break };
            let incoming = u8::from(reads_before_write & (1 << index) != 0);
            if score[index] <= 1 + incoming {
                break;
            }
            *local = Some(Register::X(index as u8));
            eligible &= !(1 << index);
            assigned += 1;
        }
        (
            count,
            (assigned >= 2).then_some(Self {
                locals,
                live_in: reads_before_write,
            }),
        )
    }

    pub(in crate::x86_64) fn emit(
        self,
        instructions: &[Instruction],
        target: TargetCpu,
    ) -> (Code, [usize; MAX_ROWS]) {
        let mut code = Code::pinned();
        for (guest, host) in self.locals.into_iter().zip(LOCAL_HOSTS) {
            let Some(guest @ Register::X(index)) = guest else {
                continue;
            };
            if self.live_in & (1 << index) != 0 {
                let mut asm = code.asm();
                asm.mov_load(Size::Qword, host, asm.guest(guest).expect("frame input"));
            }
        }
        code.set_local_registers(Some(self.locals));
        let mut starts = [0; MAX_ROWS];
        for (index, instruction) in instructions.iter().enumerate() {
            let start = code.len();
            if index != 0 {
                starts[index] = start;
            }
            assert!(emit_direct(&mut code, &instruction.operation, target));
            if start == code.len() {
                code.asm().nop();
            }
        }
        code.set_local_registers(None);
        for (guest, host) in self.locals.into_iter().zip(LOCAL_HOSTS) {
            if let Some(guest) = guest {
                let mut asm = code.asm();
                asm.mov_store(Size::Qword, asm.guest(guest).expect("frame output"), host);
            }
        }
        (code, starts)
    }
}
