//! Keep the unpinned guest registers a run of a block's instructions uses
//! most in scratch registers across that run: ALU rows, general and vector
//! accesses, prefetches and the conditional branches the block runs past.
//!
//! The run's first instruction loads the locals it reads before writing them,
//! and its end stores the ones it wrote, as does each conditional branch it
//! runs past, before its jump to a side exit: a side exit's stub is only its
//! link slot and exit, where the engine finds it. In between, a local's frame slot is stale once the run writes it. A fault
//! there recovers it from its host register (the site's [`Dirty`] locals in
//! its recovery row), as [`super::settle`] recovers the pinned registers. Each
//! emitter reaches a guest register through [`Code::host`] and
//! [`super::super::asm::Asm::guest`] alone, and so finds a local where it
//! would find a pinned register. A run admits only operations whose emitters
//! do so and that keep their own scratch out of the hosts it maps.
use super::{LOCAL_HOSTS, LocalRegisters, PINNED};
use crate::{
    aarch64::{
        AddressMode, Instruction, MemoryTransfer, Operation, Register, WideMove, bitfield,
        conditional_select::CompareRight, integer_math, prefetch, simd,
    },
    x86_64::asm::{Code, Gpr, Mem, Size},
};

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

/// The locals whose guest values only their host registers hold at a point
/// of a run: each guest register number and its host.
pub(crate) type Dirty = [Option<(u8, Gpr)>; LOCAL_HOSTS.len()];

/// What an admitted instruction does with general registers.
struct Effects {
    reads: u32,
    writes: u32,
    /// Its emitter may take R8 for scratch.
    takes_r8: bool,
    /// It accesses memory, through a masked-base slot when one is kept.
    memory: bool,
}

fn bit(register: Register) -> u32 {
    match register {
        Register::X(index) if usize::from(index) < GPRS => 1 << index,
        _ => 0,
    }
}

fn bits(registers: &[Register]) -> u32 {
    registers
        .iter()
        .fold(0, |mask, &register| mask | bit(register))
}

/// The admitted operations' effects. Each one's emitter keeps its scratch
/// to RAX, RCX, RDX, the masked-base slots, and R8 where it says so.
fn effects(operation: &Operation) -> Option<Effects> {
    let alu = |reads: &[Register], destination: Register| Effects {
        reads: bits(reads),
        writes: bit(destination),
        takes_r8: false,
        memory: false,
    };
    let writeback = |base: Register, mode: AddressMode| match mode {
        AddressMode::Offset => 0,
        _ => bit(base),
    };
    Some(match *operation {
        Operation::Nop => alu(&[], Register::Zero),
        Operation::AddSub {
            destination,
            source,
            ..
        }
        | Operation::LogicalImmediate {
            destination,
            source,
            ..
        } => alu(&[source], destination),
        Operation::AddSubRegister {
            destination,
            left,
            right,
            ..
        }
        | Operation::AddSubExtended {
            destination,
            left,
            right,
            ..
        }
        | Operation::LogicalRegister {
            destination,
            left,
            right,
            ..
        } => alu(&[left, right], destination),
        Operation::MoveWide {
            kind, destination, ..
        } => match kind {
            WideMove::Keep => alu(&[destination], destination),
            _ => alu(&[], destination),
        },
        Operation::Bitfield(operand) => match operand.kind {
            bitfield::Kind::Insert => {
                alu(&[operand.source, operand.destination], operand.destination)
            }
            _ => alu(&[operand.source], operand.destination),
        },
        Operation::PcRelative(operand) => alu(&[], operand.destination),
        Operation::IntegerMath(operand) => match operand.kind {
            // Division has its own group with the remainder after it.
            integer_math::Kind::Divide { .. } => return None,
            _ => alu(
                &[operand.left, operand.right, operand.accumulator],
                operand.destination,
            ),
        },
        Operation::ConditionalSelect(operand) => {
            alu(&[operand.left, operand.right], operand.destination)
        }
        Operation::ConditionalCompare(operand) => Effects {
            takes_r8: true,
            ..alu(
                &[
                    operand.left,
                    match operand.right {
                        CompareRight::Register(register) => register,
                        CompareRight::Immediate(_) => Register::Zero,
                    },
                ],
                Register::Zero,
            )
        },
        Operation::Memory {
            transfer,
            data,
            base,
            mode,
            ..
        } => Effects {
            reads: bit(base)
                | match transfer {
                    MemoryTransfer::Store => bit(data),
                    MemoryTransfer::Load { .. } => 0,
                },
            writes: writeback(base, mode)
                | match transfer {
                    MemoryTransfer::Store => 0,
                    MemoryTransfer::Load { .. } => bit(data),
                },
            takes_r8: false,
            memory: true,
        },
        Operation::MemoryPair {
            transfer,
            data,
            base,
            mode,
            ..
        } => Effects {
            reads: bit(base)
                | match transfer {
                    MemoryTransfer::Store => bits(&data),
                    MemoryTransfer::Load { .. } => 0,
                },
            writes: writeback(base, mode)
                | match transfer {
                    MemoryTransfer::Store => 0,
                    MemoryTransfer::Load { .. } => bits(&data),
                },
            // A pair stages its frame-resident elements in RCX and RDX,
            // or R8 where RDX holds the address's pending writeback.
            takes_r8: mode != AddressMode::Offset,
            memory: true,
        },
        Operation::MemoryRegisterOffset(operand) => Effects {
            reads: bits(&[operand.base, operand.index])
                | match operand.transfer {
                    MemoryTransfer::Store => bit(operand.data),
                    MemoryTransfer::Load { .. } => 0,
                },
            writes: match operand.transfer {
                MemoryTransfer::Store => 0,
                MemoryTransfer::Load { .. } => bit(operand.data),
            },
            takes_r8: false,
            memory: true,
        },
        // A vector access reaches only its base among the general
        // registers, through the address and writeback the others take.
        Operation::Simd(
            simd::Operand::Memory { base, mode, .. } | simd::Operand::MemoryPair { base, mode, .. },
        ) => Effects {
            reads: bit(base),
            writes: writeback(base, mode),
            takes_r8: false,
            memory: true,
        },
        // A prefetch reads its address registers into RAX and RCX.
        Operation::Prefetch(operand) => match operand.address {
            prefetch::Address::Immediate { base, .. } => alu(&[base], Register::Zero),
            prefetch::Address::Register { base, index, .. } => alu(&[base, index], Register::Zero),
            prefetch::Address::Literal(_) => alu(&[], Register::Zero),
        },
        Operation::BranchCondition { condition, .. } if condition < 14 => alu(&[], Register::Zero),
        Operation::BranchZero { source, .. } | Operation::BranchBit { source, .. } => {
            alu(&[source], Register::Zero)
        }
        _ => return None,
    })
}

/// A planned run: how many instructions it covers, its locals, and the ones
/// it reads before writing.
pub(in crate::x86_64) struct Span {
    rows: usize,
    locals: LocalRegisters,
    live_in: u32,
    /// Whether a local takes a masked-base slot.
    slots: bool,
}

impl Span {
    /// The run at the start of `instructions`, if one would save frame
    /// accesses, and how many instructions the planner examined.
    pub(in crate::x86_64) fn plan(instructions: &[Instruction]) -> (usize, Option<Self>) {
        let mut rows = 0;
        let mut live_in = 0;
        let mut touched = 0;
        let mut written = 0;
        let mut last_write = 0;
        let mut takes_r8 = false;
        let mut memory = false;
        let mut uses = [0_u16; GPRS];
        for instruction in instructions {
            let Some(effect) = effects(&instruction.operation) else {
                break;
            };
            let reads = effect.reads & UNPINNED;
            let writes = effect.writes & UNPINNED;
            live_in |= reads & !touched;
            touched |= reads | writes;
            written |= writes;
            // The next instruction already reads the last destination from
            // RAX, where the frame emitter leaves it.
            let mut accessed = (reads & !last_write) | writes;
            while accessed != 0 {
                let index = accessed.trailing_zeros() as usize;
                uses[index] += u16::from(reads & !last_write & (1 << index) != 0)
                    + u16::from(writes & (1 << index) != 0);
                accessed &= accessed - 1;
            }
            last_write = writes;
            takes_r8 |= effect.takes_r8;
            memory |= effect.memory;
            rows += 1;
        }
        // A local costs a load when the run reads it first and a store when
        // the run writes it; it saves every access the run makes.
        let gain = |index: usize| {
            let bit = 1 << index;
            i32::from(uses[index]) - i32::from(live_in & bit != 0) - i32::from(written & bit != 0)
        };
        let mut hosts = [false; LOCAL_HOSTS.len()];
        for (usable, host) in hosts.iter_mut().zip(LOCAL_HOSTS) {
            *usable = match host {
                Gpr::R9 => true,
                Gpr::R8 => !takes_r8,
                // The accesses keep masked addresses in R10 and R11.
                _ => !memory,
            };
        }
        let mut locals = [None; LOCAL_HOSTS.len()];
        let mut candidates = touched;
        let mut assigned = false;
        let mut slots = false;
        // R9 first: it is never scratch, then R8, then the slots.
        for at in [1, 0, 2, 3] {
            if !hosts[at] {
                continue;
            }
            let Some(best) = (0..GPRS)
                .filter(|&index| candidates & (1 << index) != 0)
                .max_by_key(|&index| gain(index))
                // A gain of one is within what the count misses: a pair
                // of rows emitted together, an address a group shares, the
                // forwarding into what follows the run.
                .filter(|&index| gain(index) > 1)
            else {
                break;
            };
            locals[at] = Some(Register::X(best as u8));
            candidates &= !(1 << best);
            assigned = true;
            slots |= at >= 2;
        }
        (
            rows,
            assigned.then_some(Self {
                rows,
                locals,
                live_in,
                slots,
            }),
        )
    }

    /// The number of instructions the run covers.
    pub(in crate::x86_64) const fn rows(&self) -> usize {
        self.rows
    }

    /// Whether the run's locals take a masked-base slot, whose kept
    /// address the run then overwrites.
    pub(in crate::x86_64) const fn takes_slots(&self) -> bool {
        self.slots
    }

    /// Load the locals the run reads first, `held` in RAX already, and map
    /// the locals.
    pub(in crate::x86_64) fn enter(&self, code: &mut Code, held: Option<Register>) -> Run {
        for (guest, host) in self.locals.into_iter().zip(LOCAL_HOSTS) {
            if let Some(guest) = guest
                && self.live_in & bit(guest) != 0
            {
                let mut asm = code.asm();
                if held == Some(guest) {
                    asm.mov(Size::Qword, host, Gpr::Rax);
                } else {
                    let storage = asm.guest(guest).expect("a local has a frame slot");
                    asm.mov_load(Size::Qword, host, storage);
                }
            }
        }
        code.set_local_registers(Some(self.locals));
        code.set_dirty_locals(Dirty::default());
        Run {
            locals: self.locals,
            written: 0,
        }
    }
}

/// A run being emitted: its locals and the ones it has written.
pub(in crate::x86_64) struct Run {
    locals: LocalRegisters,
    written: u32,
}

impl Run {
    /// The locals the run has written, whose frame slots are stale.
    pub(in crate::x86_64) fn dirty(&self) -> Dirty {
        let mut dirty = Dirty::default();
        for ((entry, guest), host) in dirty.iter_mut().zip(self.locals).zip(LOCAL_HOSTS) {
            if let Some(guest @ Register::X(index)) = guest
                && self.written & bit(guest) != 0
            {
                *entry = Some((index, host));
            }
        }
        dirty
    }

    /// `instructions` were emitted: a fault in the next one finds the
    /// locals they wrote in their hosts.
    pub(in crate::x86_64) fn emitted(&mut self, code: &mut Code, instructions: &[Instruction]) {
        for instruction in instructions {
            self.written |= effects(&instruction.operation)
                .expect("a run admits each instruction")
                .writes;
        }
        code.set_dirty_locals(self.dirty());
    }

    /// Store the locals the run has written, which a fault or branch from
    /// here on finds in their frame slots again. What RAX, the flags and the
    /// vector registers hold is unchanged.
    pub(in crate::x86_64) fn flush(&mut self, code: &mut Code) {
        write_back(code, self.dirty());
        self.written = 0;
        code.set_dirty_locals(Dirty::default());
    }

    /// End the run: store the locals it wrote and unmap them. What RAX,
    /// the flags and the vector registers hold is unchanged.
    pub(in crate::x86_64) fn leave(self, code: &mut Code) {
        let dirty = self.dirty();
        code.set_local_registers(None);
        code.set_dirty_locals(Dirty::default());
        write_back(code, dirty);
    }
}

/// Store `dirty`'s locals into their frame slots.
fn write_back(code: &mut Code, dirty: Dirty) {
    let mut asm = code.asm();
    for (index, host) in dirty.into_iter().flatten() {
        let slot = Mem::base(Gpr::Rdi, i32::from(index) * 8);
        asm.mov_store(Size::Qword, slot, host);
    }
}
