//! Which accesses of a pinned system-mode block whose every access is masked
//! ([`super::MemoryChecks::every_access_masked`]) address memory from an
//! earlier access's masked address rather than checking their own.
//!
//! An access that checks its address leaves it masked in RAX
//! ([`super::RangeCheck`]): the guest's address if it is native, else one no
//! host access reaches. Where a later access of the block goes through the
//! same base, moved since only by immediates (writeback, ADD and SUB
//! immediate, also into another register), the checked access first keeps
//! RAX in a slot register (R11 or R10, scratch outside pinned spans), and
//! the later one accesses `[slot + delta]`, its own address when the kept one
//! was native. The kept address is a register, never a frame slot a load
//! could read stale under speculation, and every later address derives from
//! it by data, so no access's address escapes the mask: one past a
//! mispredicted check is the unreachable address plus less than 2^30, still
//! unreachable. Architecturally the kept access faults first when its
//! address is not native; when it is, the later address is within 2^30 of a
//! native one, which `x86_64::guest_range` shows lands in a native range, a
//! non-canonical address, the guard, or wraps as Arm's arithmetic does,
//! never in Stela's window.
//!
//! The block's emitter asks [`Tracker::plan`] for each instruction it emits
//! alone, tells [`Tracker::after`] what it emitted, and resets the tracker
//! for any group it emits otherwise. The tracker knows only the operations
//! whose lowerings leave both slots alone; any other forgets every slot.
use super::{AddressMode, ImmediateAddress, asm::Gpr};
use crate::aarch64::{Instruction, MemoryTransfer, Operation, Register, Width, simd};

/// The registers that keep masked addresses, in order of preference.
pub(crate) const SLOTS: [Gpr; 2] = [Gpr::R11, Gpr::R10];
/// The largest distance of a derived access from its kept address, within
/// `guest_range`'s 2^35 and leaving a pair's second element a disp32.
const DELTA_LIMIT: i64 = 1 << 30;
/// How far [`Tracker::plan`] looks for a later access that would reuse a
/// kept address.
const LOOKAHEAD: usize = 32;

/// What the access being emitted does with a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Check the address, then copy the masked RAX into this slot.
    Keep(Gpr),
    /// The address is this slot plus `delta`, checked already.
    Reuse { host: Gpr, delta: i32 },
}

/// A plan for the access at one immediate address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Request {
    pub base: Register,
    pub displacement: i32,
    pub mode: AddressMode,
    pub plan: Plan,
}

impl Request {
    /// Whether this request is for the access at `address`.
    pub(in crate::x86_64) fn is_for(&self, address: ImmediateAddress) -> bool {
        self.base == address.base
            && self.displacement == address.displacement
            && self.mode == address.mode
    }
}

/// A guest register's value as a kept address plus an offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Known {
    slot: u8,
    offset: i64,
}

/// The slots' kept addresses and the guest registers known relative to them.
#[derive(Debug, Clone, Default)]
pub(crate) struct Tracker {
    /// X0 to X30, then SP.
    known: [Option<Known>; 32],
    /// The last use of each slot, for replacing the least recent.
    used: [u32; 2],
    clock: u32,
}

fn index(register: Register) -> Option<usize> {
    match register {
        Register::X(number) if number < 31 => Some(usize::from(number)),
        Register::Sp => Some(31),
        _ => None,
    }
}

fn bit(register: Register) -> u32 {
    index(register).map_or(0, |index| 1 << index)
}

/// An access whose address is its base plus an immediate.
struct Access {
    address: ImmediateAddress,
    /// The general registers it loads.
    loaded: [Register; 2],
}

impl Access {
    /// The access's offset from its base before writeback.
    fn start(&self) -> i64 {
        match self.address.mode {
            AddressMode::PostIndex => 0,
            _ => i64::from(self.address.displacement),
        }
    }
}

fn access(operation: &Operation) -> Option<Access> {
    let loaded = |transfer: &MemoryTransfer, data: Register| match transfer {
        MemoryTransfer::Load { .. } => data,
        MemoryTransfer::Store => Register::Zero,
    };
    let (base, displacement, mode, loaded) = match *operation {
        Operation::Memory {
            transfer,
            data,
            base,
            displacement,
            mode,
            ..
        } => (
            base,
            displacement,
            mode,
            [loaded(&transfer, data), Register::Zero],
        ),
        Operation::MemoryPair {
            transfer,
            data,
            base,
            displacement,
            mode,
            ..
        } => (
            base,
            displacement,
            mode,
            [loaded(&transfer, data[0]), loaded(&transfer, data[1])],
        ),
        Operation::Simd(
            simd::Operand::Memory {
                base,
                displacement,
                mode,
                ..
            }
            | simd::Operand::MemoryPair {
                base,
                displacement,
                mode,
                ..
            },
        ) => (base, displacement, mode, [Register::Zero; 2]),
        _ => return None,
    };
    index(base)?;
    Some(Access {
        address: ImmediateAddress {
            base,
            displacement,
            mode,
        },
        loaded,
    })
}

/// The general register a known operation other than an access writes
/// (XZR for none), or `None` for an operation whose lowering may use a slot.
fn written(operation: &Operation) -> Option<Register> {
    Some(match *operation {
        Operation::AddSub { destination, .. }
        | Operation::AddSubRegister { destination, .. }
        | Operation::AddSubCarry { destination, .. }
        | Operation::AddSubExtended { destination, .. }
        | Operation::LogicalRegister { destination, .. }
        | Operation::LogicalImmediate { destination, .. }
        | Operation::MoveWide { destination, .. } => destination,
        Operation::PcRelative(operand) => operand.destination,
        Operation::MirroredRead { word } => super::mirrored_read::destination(word),
        Operation::ConditionalSelect(operand) => operand.destination,
        Operation::Bitfield(operand) => operand.destination,
        Operation::IntegerMath(operand) => operand.destination,
        Operation::IntegerUnary(operand) => operand.destination,
        Operation::IntegerMinMax(operand) => operand.destination,
        Operation::ConditionalCompare(_)
        | Operation::BranchCondition { .. }
        | Operation::BranchZero { .. }
        | Operation::BranchBit { .. }
        | Operation::Nop
        | Operation::Prefetch(_) => Register::Zero,
        _ => return None,
    })
}

/// The immediate an X-register ADD or SUB moves `source` by into
/// `destination`.
fn moved(operation: &Operation) -> Option<(Register, Register, i64)> {
    match *operation {
        Operation::AddSub {
            width: Width::X64,
            subtract,
            destination,
            source,
            immediate,
            ..
        } => {
            let immediate = i64::from(immediate);
            Some((
                destination,
                source,
                if subtract { -immediate } else { immediate },
            ))
        }
        _ => None,
    }
}

/// Whether an access after the first of `instructions` goes through the
/// first's base or a register moved from it by immediates.
fn reused_later(instructions: &[Instruction]) -> bool {
    let Some((first, rest)) = instructions.split_first() else {
        return false;
    };
    let Some(first) = access(&first.operation) else {
        return false;
    };
    let mut bases = bit(first.address.base) & !bit(first.loaded[0]) & !bit(first.loaded[1]);
    for instruction in rest.iter().take(LOOKAHEAD) {
        if bases == 0 {
            return false;
        }
        let operation = &instruction.operation;
        if let Some(access) = access(operation) {
            if bases & bit(access.address.base) != 0 {
                return true;
            }
            bases &= !bit(access.loaded[0]) & !bit(access.loaded[1]);
            continue;
        }
        if let Some((destination, source, _)) = moved(operation) {
            if bases & bit(source) != 0 {
                bases |= bit(destination);
            } else {
                bases &= !bit(destination);
            }
            continue;
        }
        match written(operation) {
            Some(destination) => bases &= !bit(destination),
            None => return false,
        }
    }
    false
}

impl Tracker {
    /// Forget every kept address.
    pub(crate) fn reset(&mut self) {
        self.known = [None; 32];
    }

    fn referenced(&self, slot: u8) -> bool {
        self.known
            .iter()
            .any(|known| known.is_some_and(|known| known.slot == slot))
    }

    /// The plan for the first of `instructions`, the rest of the block
    /// after it: reuse a kept address its base is known relative to, or
    /// keep its own for a later access to reuse.
    pub(crate) fn plan(&mut self, instructions: &[Instruction]) -> Option<Request> {
        let access = access(&instructions.first()?.operation)?;
        let ImmediateAddress {
            base,
            displacement,
            mode,
        } = access.address;
        let request = |plan| Request {
            base,
            displacement,
            mode,
            plan,
        };
        if let Some(known) = self.known[index(base)?] {
            let delta = known.offset + access.start();
            if delta.abs() <= DELTA_LIMIT {
                self.clock += 1;
                self.used[usize::from(known.slot)] = self.clock;
                return Some(request(Plan::Reuse {
                    host: SLOTS[usize::from(known.slot)],
                    delta: i32::try_from(delta).expect("bounded delta"),
                }));
            }
        }
        if !reused_later(instructions) {
            return None;
        }
        let slot = (0..SLOTS.len() as u8)
            .find(|&slot| !self.referenced(slot))
            .unwrap_or_else(|| if self.used[0] <= self.used[1] { 0 } else { 1 });
        Some(request(Plan::Keep(SLOTS[usize::from(slot)])))
    }

    /// Note `instruction`, emitted alone, which `applied` the plan if any.
    pub(crate) fn after(&mut self, instruction: &Instruction, applied: Option<Plan>) {
        let operation = &instruction.operation;
        if let Some(access) = access(operation) {
            let base = index(access.address.base).expect("an access base");
            if let Some(Plan::Keep(host)) = applied {
                let slot = SLOTS
                    .iter()
                    .position(|slot| *slot == host)
                    .expect("a slot register") as u8;
                for known in &mut self.known {
                    if known.is_some_and(|known| known.slot == slot) {
                        *known = None;
                    }
                }
                self.clock += 1;
                self.used[usize::from(slot)] = self.clock;
                self.known[base] = Some(Known {
                    slot,
                    offset: -access.start(),
                });
            }
            if access.address.mode != AddressMode::Offset {
                self.known[base] = self.known[base].and_then(|known| {
                    let offset = known.offset + i64::from(access.address.displacement);
                    (offset.abs() <= DELTA_LIMIT).then_some(Known { offset, ..known })
                });
            }
            for loaded in access.loaded {
                if let Some(index) = index(loaded) {
                    self.known[index] = None;
                }
            }
            return;
        }
        if let Some((destination, source, immediate)) = moved(operation) {
            let value = index(source)
                .and_then(|source| self.known[source])
                .and_then(|known| {
                    let offset = known.offset + immediate;
                    (offset.abs() <= DELTA_LIMIT).then_some(Known { offset, ..known })
                });
            if let Some(destination) = index(destination) {
                self.known[destination] = value;
            }
            return;
        }
        match written(operation) {
            Some(destination) => {
                if let Some(destination) = index(destination) {
                    self.known[destination] = None;
                }
            }
            None => self.reset(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuestAddress, Lifter, aarch64::Decoder};
    use alloc::vec::Vec;

    fn lift(words: &[u32]) -> Vec<Instruction> {
        words
            .iter()
            .enumerate()
            .map(|(index, &word)| {
                Decoder
                    .lift(GuestAddress(0x1000 + 4 * index as u64), word)
                    .unwrap()
            })
            .collect()
    }

    /// Each instruction's plan, applying every plan.
    fn plans(words: &[u32]) -> Vec<Option<Plan>> {
        let instructions = lift(words);
        let mut tracker = Tracker::default();
        (0..instructions.len())
            .map(|index| {
                let plan = tracker
                    .plan(&instructions[index..])
                    .map(|request| request.plan);
                tracker.after(&instructions[index], plan);
                plan
            })
            .collect()
    }

    const R11: Gpr = Gpr::R11;
    const R10: Gpr = Gpr::R10;

    #[test]
    fn a_frame_keeps_its_first_address_for_the_accesses_after_it() {
        // stp x29, x30, [sp, #-16]!; mov x29, sp; str x19, [sp, #-16]!;
        // ldr x0, [x29, #8]; ldp x19, x20, [sp], #16; ldr x1, [sp, #8]
        let words = [
            0xa9bf_7bfd,
            0x9100_03fd,
            0xf81f_0ff3,
            0xf940_07a0,
            0xa8c1_53f3,
            0xf940_07e1,
        ];
        assert_eq!(
            plans(&words),
            [
                Some(Plan::Keep(R11)),
                None,
                // SP = kept - 0 then moved by -16 before the access.
                Some(Plan::Reuse {
                    host: R11,
                    delta: -16
                }),
                // X29 = the old SP - 16, the kept address.
                Some(Plan::Reuse {
                    host: R11,
                    delta: 8
                }),
                Some(Plan::Reuse {
                    host: R11,
                    delta: -16
                }),
                // The post-index moved SP back to the kept address.
                Some(Plan::Reuse {
                    host: R11,
                    delta: 8
                }),
            ]
        );
    }

    #[test]
    fn writes_loads_and_unknown_operations_forget_bases() {
        // ldr x2, [x1]; ldr x3, [x1, #8]; ldr x1, [x1, #16]; ldr x4, [x1];
        // ldr x5, [x6]; fmov x2, d0 (unknown); ldr x7, [x6, #8];
        // add w6, w6, #1; ldr x8, [x6]
        let words = [
            0xf940_0022,
            0xf940_0423,
            0xf940_0821,
            0xf940_0024,
            0xf940_00c5,
            0x9e66_0002,
            0xf940_04c7,
            0x1100_04c6,
            0xf940_00c8,
        ];
        assert_eq!(
            plans(&words),
            [
                Some(Plan::Keep(R11)),
                Some(Plan::Reuse {
                    host: R11,
                    delta: 8
                }),
                Some(Plan::Reuse {
                    host: R11,
                    delta: 16
                }),
                // X1 was loaded and has no later access through it.
                None,
                // X6's later access is after an unknown operation.
                None,
                None,
                None,
                None,
                None,
            ]
        );
    }

    #[test]
    fn two_bases_keep_two_slots_and_a_third_replaces_the_least_recent() {
        // ldr x2, [x0]; ldr x3, [x1]; ldr x4, [x0, #8]; ldr x5, [x7];
        // ldr x6, [x1, #8]; ldr x8, [x7, #8]; ldr x9, [x0, #16]
        let words = [
            0xf940_0002,
            0xf940_0023,
            0xf940_0404,
            0xf940_00e5,
            0xf940_0426,
            0xf940_04e8,
            0xf940_0809,
        ];
        assert_eq!(
            plans(&words),
            [
                Some(Plan::Keep(R11)),
                Some(Plan::Keep(R10)),
                Some(Plan::Reuse {
                    host: R11,
                    delta: 8
                }),
                // X1's slot was used least recently.
                Some(Plan::Keep(R10)),
                None,
                Some(Plan::Reuse {
                    host: R10,
                    delta: 8
                }),
                Some(Plan::Reuse {
                    host: R11,
                    delta: 16
                }),
            ]
        );
    }

    #[test]
    fn a_distant_offset_checks_its_own_address() {
        // ldr x2, [x0]; ldr x3, [x0, #8]; 65 times add x0, x0, #0xfff, lsl #12,
        // past 2^30; ldr x4, [x0]
        let mut words = alloc::vec![0xf940_0002, 0xf940_0403];
        words.extend([0x917f_fc00; 65]);
        words.push(0xf940_0004);
        let plans = plans(&words);
        assert_eq!(plans[0], Some(Plan::Keep(R11)));
        assert_eq!(
            plans[1],
            Some(Plan::Reuse {
                host: R11,
                delta: 8
            })
        );
        assert_eq!(plans.last(), Some(&None));
    }
}
