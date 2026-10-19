//! Multi-instruction scalar regions that keep guest values in host registers and
//! settle the full register bank at every exit.
use alloc::vec;
use alloc::vec::Vec;
mod allocation;
mod analysis;
mod self_loop;
pub(super) use analysis::MAX_INSTRUCTIONS;
pub(crate) use self_loop::Plan as ResidentLoopPlan;
pub(super) use self_loop::prefix_with_budget;
mod constant;
mod encoding;
mod flags;
pub mod location;

use crate::{
    GuestAddress,
    aarch64::integer_math::Kind as IntegerMath,
    aarch64::{AddressMode, Instruction, MemoryTransfer, Operation, Register, WideMove, Width},
};
use analysis::{Effects, next_use, prefix_effects, slot};
use encoding::{HostGpr, POOL, RESULT, RIGHT};
use location::{FRAME_LOCATIONS, GPR_SLOTS, Location};

const BYTE_LOAD_BYTES: u8 = 1;
const WORD_LOAD_BYTES: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionError {
    TooLong,
    Misaligned,
    NonContiguous,
    AddressOverflow,
    ChangedMemoryEncoding,
    ChangedInstructions,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AllocationStats {
    pub state_loads: usize,
    pub pressure_stores: usize,
    pub exit_stores: usize,
    pub lifetime_stores: usize,
    pub cache_hits: usize,
    pub commits: usize,
    pub constant_writes: usize,
    pub native_instructions: usize,
    pub peak_resident: usize,
    pub load_boundary_stores: usize,
    pub clean_loads: usize,
    pub pair_loads: usize,
    pub input_cache_loads: usize,
    pub address_cache_hits: usize,
    pub flag_loads: usize,
    pub flag_stores: usize,
    pub dead_versions: usize,
    pub coalesced_writes: usize,
    pub callee_saves: usize,
    pub callee_restores: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptimizedRegion {
    pub code: Vec<u8>,
    pub consumed_instructions: usize,
    pub source_map: Vec<(GuestAddress, usize)>,
    pub stats: AllocationStats,
}

#[derive(Debug, Clone, Copy)]
struct Resident {
    guest: usize,
    dirty: bool,
}

struct Emitter<'a> {
    output: OptimizedRegion,
    resident: [Option<Resident>; encoding::ALLOCATABLE_SLOTS],
    locations: [Location; GPR_SLOTS],
    effects: &'a [Effects],
    current: usize,
    constants: constant::ConstantRegisters,
    reserved_hosts: u16,
    pinned_hosts: u16,
    /// A fixed loop assignment retains architectural outputs until its side exit.
    persistent: bool,
    allocation: Option<allocation::Plan>,
    flag_location: flags::Location,
    coalesced: Option<usize>,
    allocating_output: bool,
    /// For each instruction, whether its clean load checks the guest range
    /// (`x86_64::guest_range`); none in process profiles.
    range_checks: Option<&'a [bool]>,
}

impl Emitter<'_> {
    fn emit(&mut self, encode: impl FnOnce(&mut Vec<u8>)) {
        let start = self.output.code.len();
        encode(&mut self.output.code);
        let end = self.output.code.len();
        debug_assert!(end > start);
        // Value allocation tracks versions, not per-instruction locations.
        debug_assert!(self.allocation.is_some() || location::valid(&self.locations));
        self.output.stats.native_instructions += 1;
    }

    fn spill(&mut self, index: usize, at_exit: bool) {
        if self.allocation.is_some() {
            self.spill_value(index, at_exit);
            return;
        }
        let Some(resident) = self.resident[index] else {
            return;
        };
        if resident.dirty {
            self.emit(|code| encoding::store(code, POOL[index], resident.guest));
            if at_exit {
                self.output.stats.exit_stores += 1;
            } else {
                self.output.stats.pressure_stores += 1;
            }
        }
        // Store faults/interruptions retain Host until the store succeeds.
        self.locations[resident.guest] = FRAME_LOCATIONS[resident.guest];
        self.resident[index] = None;
    }

    fn allocate(&mut self, guest: usize) -> usize {
        if self.allocation.is_some() {
            return self.allocate_value(allocation::Value::gpr(guest).unwrap());
        }
        if let Some(index) = self
            .resident
            .iter()
            .position(|value| value.is_some_and(|value| value.guest == guest))
        {
            return index;
        }
        let available = (0..POOL.len())
            .filter(|&index| (self.reserved_hosts | self.pinned_hosts) & POOL[index].mask() == 0);
        let index = available
            .clone()
            .find(|&index| self.resident[index].is_none())
            .unwrap_or_else(|| {
                available
                    .max_by_key(|&index| {
                        next_use(
                            self.effects,
                            self.current + 1,
                            self.resident[index].unwrap().guest,
                        )
                    })
                    .expect("three pinned operands leave a result slot")
            });
        self.spill(index, false);
        self.resident[index] = Some(Resident {
            guest,
            dirty: false,
        });
        self.output.stats.peak_resident = self
            .output
            .stats
            .peak_resident
            .max(self.resident.iter().flatten().count());
        index
    }

    fn read(&mut self, register: Register, destination: HostGpr) {
        if self.allocation.is_some() {
            self.read_value(register, destination);
            return;
        }
        if let Some(guest) = slot(register) {
            if let Some(index) = self
                .resident
                .iter()
                .position(|value| value.is_some_and(|value| value.guest == guest))
            {
                self.output.stats.cache_hits += 1;
                self.emit(|code| encoding::copy(code, destination, POOL[index], Width::X64));
            } else if self.effects[self.current].writes & (1 << guest) == 0
                && next_use(self.effects, self.current + 1, guest) != usize::MAX
            {
                // Cache the old architectural input only when its next version
                // is read again before overwrite. Current borrowed operands are
                // pinned until this instruction commits, so filling a cache
                // slot cannot destroy an in-place left or cached right value.
                let index = self.allocate(guest);
                self.emit(|code| encoding::load(code, POOL[index], guest));
                self.locations[guest] = Location::Host(POOL[index]);
                self.emit(|code| encoding::copy(code, destination, POOL[index], Width::X64));
                self.output.stats.state_loads += 1;
                self.output.stats.input_cache_loads += 1;
            } else {
                self.emit(|code| encoding::load(code, destination, guest));
                self.output.stats.state_loads += 1;
            }
        } else {
            self.emit(|code| encoding::immediate(code, destination, 0, Width::W32));
        }
    }

    fn cached(&mut self, register: Register) -> Option<HostGpr> {
        if self.allocation.is_some() {
            return self.cached_value(register);
        }
        let guest = slot(register)?;
        let index = self
            .resident
            .iter()
            .position(|value| value.is_some_and(|value| value.guest == guest))?;
        let host = POOL[index];
        self.pinned_hosts |= host.mask();
        Some(host)
    }

    fn in_place(&mut self, destination: Register, source: Register) -> Option<HostGpr> {
        if self.allocation.is_some() {
            return self.coalesce_value(destination, source);
        }
        (destination == source)
            .then(|| self.cached(source))
            .flatten()
    }

    fn committed_in_place(&mut self, destination: Register) {
        if self.allocation.is_some() {
            self.commit_coalesced(destination);
            return;
        }
        let guest = slot(destination).unwrap();
        let index = self
            .resident
            .iter()
            .position(|value| value.is_some_and(|value| value.guest == guest))
            .unwrap();
        self.resident[index].as_mut().unwrap().dirty = true;
        self.output.stats.commits += 1;
    }

    fn commit(&mut self, destination: Register, width: Width) {
        if self.allocation.is_some() {
            self.commit_value(destination, width);
            return;
        }
        // The operands are consumed, so result allocation may evict them by
        // next use.
        self.pinned_hosts = 0;
        if let Some(guest) = slot(destination) {
            if !self.persistent && next_use(self.effects, self.current + 1, guest) == usize::MAX {
                // This value's last use in the region: store it to its final
                // location, keeping the old host copy until the store succeeds.
                self.emit(|code| encoding::store(code, RESULT, guest));
                self.output.stats.lifetime_stores += 1;
                self.locations[guest] = FRAME_LOCATIONS[guest];
                if let Some(index) = self
                    .resident
                    .iter()
                    .position(|value| value.is_some_and(|value| value.guest == guest))
                {
                    self.resident[index] = None;
                }
                self.output.stats.commits += 1;
                return;
            }
            // Both operands/result are already in dedicated scratch registers;
            // allocation can spill any old value without destroying the result.
            let index = self.allocate(guest);
            self.emit(|code| encoding::copy(code, POOL[index], RESULT, width));
            self.locations[guest] = Location::Host(POOL[index]);
            self.resident[index] = Some(Resident { guest, dirty: true });
        } else {
            // A non-faulting write to ZR has no effect, but a host instruction
            // keeps the retirement observable.
            self.emit(encoding::nop);
        }
        self.output.stats.commits += 1;
    }

    fn clean_load(
        &mut self,
        transfer: MemoryTransfer,
        bytes: u8,
        data: Register,
        base: Register,
        displacement: i32,
        mode: AddressMode,
    ) -> Result<(), RegionError> {
        // Obtain the real existing raw-memory emission before mutating output.
        // If its selected form changes, decline this whole candidate prefix.
        let mut raw = vec![];
        super::memory(
            &mut raw,
            self.memory_checks(),
            transfer,
            bytes,
            data,
            base,
            displacement,
            mode,
        );
        let ends = encoding::ordinary_load_ends(
            &raw,
            bytes,
            slot(base).expect("eligible X base"),
            slot(data),
            displacement,
        )
        .ok_or(RegionError::ChangedMemoryEncoding)?;
        let cached_base = self.cached(base);
        self.settle_before_load(HostGpr::Rcx.mask(), &[data]);
        let mut start = 0;
        for end in ends {
            if start == 0
                && let Some(host) = cached_base
            {
                self.emit(|code| encoding::copy(code, HostGpr::Rax, host, Width::X64));
                self.output.stats.address_cache_hits += 1;
            } else {
                self.emit(|code| code.extend_from_slice(&raw[start..end]));
            }
            start = end;
        }
        self.retain_clean_result(data, HostGpr::Rcx);
        self.output.stats.clean_loads += 1;
        self.output.stats.commits += 1;
        Ok(())
    }

    /// The checks of the shared memory emitter whose bytes the current
    /// clean load reuses: the default ones, with its guest range check.
    fn memory_checks(&self) -> super::MemoryChecks {
        super::MemoryChecks {
            guest_range: self
                .range_checks
                .is_some_and(|ranges| ranges.get(self.current).copied().unwrap_or(true)),
            ..super::MemoryChecks::DEFAULT
        }
    }

    fn settle_before_load(&mut self, clobbers: u16, destinations: &[Register]) {
        for (index, host) in POOL.iter().copied().enumerate() {
            if let Some(resident) = self.resident[index]
                && resident.dirty
            {
                self.emit(|code| encoding::store(code, host, resident.guest));
                self.output.stats.load_boundary_stores += 1;
                self.resident[index].as_mut().unwrap().dirty = false;
            }
        }
        for (index, host) in POOL.iter().copied().enumerate() {
            if let Some(resident) = self.resident[index]
                && (clobbers & host.mask() != 0
                    || destinations
                        .iter()
                        .any(|&data| slot(data) == Some(resident.guest)))
            {
                debug_assert!(!resident.dirty);
                self.locations[resident.guest] = FRAME_LOCATIONS[resident.guest];
                self.resident[index] = None;
            }
        }
    }

    fn retain_clean_result(&mut self, register: Register, host: HostGpr) {
        if let Some(guest) = slot(register) {
            let index = POOL
                .iter()
                .position(|&candidate| candidate == host)
                .unwrap();
            debug_assert!(self.resident[index].is_none());
            self.resident[index] = Some(Resident {
                guest,
                dirty: false,
            });
            self.locations[guest] = Location::Host(host);
            self.output.stats.peak_resident = self
                .output
                .stats
                .peak_resident
                .max(self.resident.iter().flatten().count());
        }
    }

    fn clean_pair_load(
        &mut self,
        transfer: MemoryTransfer,
        bytes: u8,
        data: [Register; 2],
        base: Register,
        displacement: i32,
        mode: AddressMode,
    ) -> Result<(), RegionError> {
        let mut raw = vec![];
        super::memory_pair(
            &mut raw,
            self.memory_checks(),
            transfer,
            bytes,
            data,
            base,
            displacement,
            mode,
        );
        let ends = encoding::ordinary_pair_load_ends(
            &raw,
            slot(base).expect("eligible X base"),
            data.map(slot),
            displacement,
        )
        .ok_or(RegionError::ChangedMemoryEncoding)?;
        let cached_base = self.cached(base);
        self.settle_before_load(HostGpr::Rcx.mask() | HostGpr::R8.mask(), &data);
        let mut start = 0;
        for end in ends {
            if start == 0
                && let Some(host) = cached_base
            {
                self.emit(|code| encoding::copy(code, HostGpr::Rax, host, Width::X64));
                self.output.stats.address_cache_hits += 1;
            } else {
                self.emit(|code| code.extend_from_slice(&raw[start..end]));
            }
            start = end;
        }
        // Both accesses precede either destination commit in the unchanged
        // shared emitter. A second-access fault leaves both old values intact.
        self.retain_clean_result(data[0], HostGpr::Rcx);
        self.retain_clean_result(data[1], HostGpr::R8);
        self.output.stats.pair_loads += 1;
        self.output.stats.commits += 1;
        Ok(())
    }

    fn instruction(&mut self, instruction: &Instruction) -> Result<(), RegionError> {
        let constant = if self.allocation.is_some() {
            None
        } else {
            self.constants.step(&instruction.operation)
        };
        self.instruction_with_constant(instruction, constant)
    }

    fn instruction_defining_flags(&mut self, instruction: &Instruction) -> Result<(), RegionError> {
        // A constant value replacement does not reproduce arithmetic flags.
        self.constants.clear();
        self.instruction_with_constant(instruction, None)
    }

    fn instruction_with_constant(
        &mut self,
        instruction: &Instruction,
        constant: Option<constant::ConstantWrite>,
    ) -> Result<(), RegionError> {
        self.pinned_hosts = 0;
        self.coalesced = None;
        self.output
            .source_map
            .push((instruction.pc, self.output.code.len()));
        if let Some(write) = constant {
            let guest = slot(write.destination).expect("known constant has a real destination");
            if next_use(self.effects, self.current + 1, guest) != usize::MAX {
                let index = self.allocate(guest);
                self.emit(|code| encoding::immediate(code, POOL[index], write.value, Width::X64));
                self.locations[guest] = Location::Host(POOL[index]);
                self.resident[index] = Some(Resident { guest, dirty: true });
                self.output.stats.commits += 1;
            } else {
                self.emit(|code| encoding::immediate(code, RESULT, write.value, Width::X64));
                self.commit(write.destination, Width::X64);
            }
            self.output.stats.constant_writes += 1;
            return Ok(());
        }
        match instruction.operation {
            Operation::Memory {
                transfer,
                bytes,
                data,
                base,
                displacement,
                mode,
            } => {
                self.clean_load(transfer, bytes, data, base, displacement, mode)?;
            }
            Operation::Nop => {
                self.emit(encoding::nop);
                self.output.stats.commits += 1;
            }
            Operation::PcRelative(operand) => {
                self.emit(|code| encoding::immediate(code, RESULT, operand.address, Width::X64));
                self.commit(operand.destination, Width::X64);
            }
            Operation::MoveWide {
                width,
                kind,
                destination,
                immediate,
                shift,
            } => {
                let value = u64::from(immediate) << shift;
                match kind {
                    WideMove::Zero | WideMove::Not => {
                        let value = if kind == WideMove::Not { !value } else { value };
                        self.emit(|code| encoding::immediate(code, RESULT, value, width));
                    }
                    WideMove::Keep => {
                        self.read(destination, RESULT);
                        self.emit(|code| {
                            encoding::immediate(code, RIGHT, !(0xffffu64 << shift), width)
                        });
                        self.emit(|code| {
                            encoding::binary(code, RESULT, RIGHT, encoding::Binary::And, width)
                        });
                        self.emit(|code| encoding::immediate(code, RIGHT, value, width));
                        self.emit(|code| {
                            encoding::binary(code, RESULT, RIGHT, encoding::Binary::Or, width)
                        });
                    }
                }
                self.commit(destination, width);
            }
            Operation::MemoryPair {
                transfer,
                bytes,
                data,
                base,
                displacement,
                mode,
            } => {
                self.clean_pair_load(transfer, bytes, data, base, displacement, mode)?;
            }
            Operation::AddSub {
                width,
                subtract,
                flags: false,
                destination,
                source,
                immediate,
            } => {
                if let Some(host) = self.in_place(destination, source) {
                    self.emit(|code| {
                        encoding::arithmetic_immediate(code, host, subtract, immediate, width)
                    });
                    self.committed_in_place(destination);
                } else {
                    self.read(source, RESULT);
                    self.emit(|code| {
                        encoding::arithmetic_immediate(code, RESULT, subtract, immediate, width)
                    });
                    self.commit(destination, width);
                }
            }
            Operation::AddSubRegister {
                width,
                subtract,
                flags: false,
                destination,
                left,
                right,
                shift,
                amount,
            } => {
                let (left, right) = if !subtract
                    && amount == 0
                    && self.in_place(destination, left).is_none()
                    && self.in_place(destination, right).is_some()
                {
                    (right, left)
                } else {
                    (left, right)
                };
                let in_place = self.in_place(destination, left);
                // ADD is commutative only without a shifted right operand.
                // Prefer a cached left as the native RHS when the other source
                // is memory-backed and no in-place destination is available.
                let swapped_right = if !subtract
                    && amount == 0
                    && in_place.is_none()
                    && self.cached(right).is_none()
                {
                    self.cached(left)
                } else {
                    None
                };
                if let Some(host) = swapped_right {
                    self.read(right, RESULT);
                    self.output.stats.cache_hits += 1;
                    self.emit(|code| {
                        encoding::binary(code, RESULT, host, encoding::Binary::Add, width)
                    });
                    self.commit(destination, width);
                    return Ok(());
                }
                if in_place.is_none() {
                    self.read(left, RESULT);
                }
                let cached_right = if amount == 0 {
                    self.cached(right)
                } else {
                    None
                };
                if cached_right.is_some() {
                    self.output.stats.cache_hits += 1;
                } else {
                    self.read(right, RIGHT);
                }
                if amount != 0 {
                    self.emit(|code| encoding::shift(code, shift, amount, width));
                }
                self.emit(|code| {
                    encoding::binary(
                        code,
                        in_place.unwrap_or(RESULT),
                        cached_right.unwrap_or(RIGHT),
                        if subtract {
                            encoding::Binary::Sub
                        } else {
                            encoding::Binary::Add
                        },
                        width,
                    )
                });
                if in_place.is_some() {
                    self.committed_in_place(destination);
                } else {
                    self.commit(destination, width);
                }
            }
            Operation::LogicalRegister {
                width,
                kind,
                invert,
                flags: false,
                destination,
                left,
                right,
                shift,
                amount,
            } => {
                let (left, right) = if !invert
                    && amount == 0
                    && self.in_place(destination, left).is_none()
                    && self.in_place(destination, right).is_some()
                {
                    (right, left)
                } else {
                    (left, right)
                };
                let in_place = self.in_place(destination, left);
                let swapped_right =
                    if !invert && amount == 0 && in_place.is_none() && self.cached(right).is_none()
                    {
                        self.cached(left)
                    } else {
                        None
                    };
                if let Some(host) = swapped_right {
                    self.read(right, RESULT);
                    self.output.stats.cache_hits += 1;
                    self.emit(|code| {
                        encoding::binary(code, RESULT, host, encoding::logical_opcode(kind), width)
                    });
                    self.commit(destination, width);
                    return Ok(());
                }
                if in_place.is_none() {
                    self.read(left, RESULT);
                }
                let cached_right = if amount == 0 && !invert {
                    self.cached(right)
                } else {
                    None
                };
                if cached_right.is_some() {
                    self.output.stats.cache_hits += 1;
                } else {
                    self.read(right, RIGHT);
                }
                if amount != 0 {
                    self.emit(|code| encoding::shift(code, shift, amount, width));
                }
                if invert {
                    self.emit(|code| encoding::invert(code, width));
                }
                self.emit(|code| {
                    encoding::binary(
                        code,
                        in_place.unwrap_or(RESULT),
                        cached_right.unwrap_or(RIGHT),
                        encoding::logical_opcode(kind),
                        width,
                    )
                });
                if in_place.is_some() {
                    self.committed_in_place(destination);
                } else {
                    self.commit(destination, width);
                }
            }
            Operation::IntegerMath(operand) => match operand.kind {
                IntegerMath::Low { width } => {
                    // Sources keep their values until commit, including Rd ==
                    // Rn/Rm/Ra. The low product is the same for signed and
                    // unsigned inputs.
                    self.read(operand.left, RESULT);
                    let right = self.cached(operand.right);
                    if right.is_some() {
                        self.output.stats.cache_hits += 1;
                    } else {
                        self.read(operand.right, RIGHT);
                    }
                    self.emit(|code| {
                        encoding::multiply(code, RESULT, right.unwrap_or(RIGHT), width)
                    });
                    if operand.subtract {
                        self.emit(|code| encoding::negate(code, RESULT, width));
                    }
                    if operand.accumulator != Register::Zero {
                        let accumulator = self.cached(operand.accumulator);
                        if accumulator.is_some() {
                            self.output.stats.cache_hits += 1;
                        } else {
                            self.read(operand.accumulator, RIGHT);
                        }
                        self.emit(|code| {
                            encoding::binary(
                                code,
                                RESULT,
                                accumulator.unwrap_or(RIGHT),
                                encoding::Binary::Add,
                                width,
                            )
                        });
                    }
                    self.commit(operand.destination, width);
                }
                IntegerMath::Extract { width, amount } => {
                    debug_assert_eq!(operand.left, operand.right);
                    if let Some(host) = self.in_place(operand.destination, operand.left) {
                        // ROR with a zero count is not a W-register write on x86.
                        // Explicitly narrow it so every W result clears upper bits.
                        if width == Width::W32 && amount == 0 {
                            self.emit(|code| encoding::copy(code, host, host, width));
                        } else {
                            self.emit(|code| {
                                encoding::shift_register(
                                    code,
                                    host,
                                    crate::aarch64::Shift::Ror,
                                    amount,
                                    width,
                                )
                            });
                        }
                        self.committed_in_place(operand.destination);
                    } else {
                        self.read(operand.left, RESULT);
                        if width == Width::W32 && amount == 0 {
                            self.emit(|code| encoding::copy(code, RESULT, RESULT, width));
                        } else {
                            self.emit(|code| {
                                encoding::shift_register(
                                    code,
                                    RESULT,
                                    crate::aarch64::Shift::Ror,
                                    amount,
                                    width,
                                )
                            });
                        }
                        self.commit(operand.destination, width);
                    }
                }
                _ => unreachable!(
                    "prefix analysis selects only low product and equal-source extract"
                ),
            },
            Operation::LogicalImmediate {
                width,
                kind,
                flags: false,
                destination,
                source,
                immediate,
            } => {
                let in_place = self.in_place(destination, source);
                if in_place.is_none() {
                    self.read(source, RESULT);
                }
                self.emit(|code| encoding::immediate(code, RIGHT, immediate, width));
                self.emit(|code| {
                    encoding::binary(
                        code,
                        in_place.unwrap_or(RESULT),
                        RIGHT,
                        encoding::logical_opcode(kind),
                        width,
                    )
                });
                if in_place.is_some() {
                    self.committed_in_place(destination);
                } else {
                    self.commit(destination, width);
                }
            }
            _ => unreachable!("prefix analysis rejects boundary operations"),
        }
        Ok(())
    }
}

/// Emit the longest eligible prefix, with no RET, helper, dispatch or faulting
/// access. The caller continues with the baseline emitter at
/// `consumed_instructions`, with the full frame written back and `exit_pc` set.
#[cfg(test)]
pub fn emit_prefix(instructions: &[Instruction]) -> Result<OptimizedRegion, RegionError> {
    emit_prefix_selected(instructions, false, None)
}

/// Transactional nonfaulting GPR/NZCV span candidate.
pub fn emit_allocated_prefix(
    instructions: &[Instruction],
) -> Result<Option<OptimizedRegion>, RegionError> {
    allocation::prefix(instructions)
}

/// Ordinary direct-RAM load retention; pure ALU allocation keeps six slots.
/// With `range_checks`, the loads the system-mode analysis selects check
/// their address ([`super::GUEST_RANGE_CHECK`]).
pub fn emit_clean_load_prefix<'a>(
    instructions: &'a [Instruction],
    range_checks: Option<&'a [bool]>,
) -> Result<OptimizedRegion, RegionError> {
    emit_prefix_selected(instructions, true, range_checks)
}

fn emit_prefix_selected<'a>(
    instructions: &'a [Instruction],
    clean_loads: bool,
    range_checks: Option<&'a [bool]>,
) -> Result<OptimizedRegion, RegionError> {
    if instructions.len() > MAX_INSTRUCTIONS {
        return Err(RegionError::TooLong);
    }
    if instructions
        .first()
        .is_some_and(|instruction| instruction.pc.0 & 3 != 0)
    {
        return Err(RegionError::Misaligned);
    }
    let effects = if clean_loads {
        analysis::prefix_clean_load_effects(instructions)
    } else {
        prefix_effects(instructions)
    };
    let contains_load = clean_loads
        && instructions.iter().take(effects.len()).any(|instruction| {
            matches!(
                instruction.operation,
                Operation::Memory { .. } | Operation::MemoryPair { .. }
            )
        });
    let consumed = effects.len();
    let entry = instructions.first().map(|instruction| instruction.pc);
    for (index, instruction) in instructions.iter().take(consumed).enumerate() {
        let expected = entry
            .unwrap()
            .0
            .checked_add((index as u64) * 4)
            .ok_or(RegionError::AddressOverflow)?;
        if instruction.pc.0 != expected {
            return Err(RegionError::NonContiguous);
        }
    }
    let exit_pc = entry
        .map(|pc| {
            pc.0.checked_add((consumed as u64) * 4)
                .map(GuestAddress)
                .ok_or(RegionError::AddressOverflow)
        })
        .transpose()?;
    if let Some(boundary) = instructions.get(consumed)
        && Some(boundary.pc) != exit_pc
    {
        return Err(RegionError::NonContiguous);
    }
    let mut emitter = Emitter {
        output: OptimizedRegion {
            code: vec![],
            consumed_instructions: consumed,
            source_map: vec![],
            stats: AllocationStats::default(),
        },
        resident: [None; encoding::ALLOCATABLE_SLOTS],
        locations: FRAME_LOCATIONS,
        effects: &effects,
        current: 0,
        constants: constant::ConstantRegisters::default(),
        reserved_hosts: if contains_load {
            HostGpr::Rcx.mask()
                | if instructions.iter().take(consumed).any(|instruction| {
                    matches!(instruction.operation, Operation::MemoryPair { .. })
                }) {
                    HostGpr::R8.mask()
                } else {
                    0
                }
        } else {
            0
        },
        pinned_hosts: 0,
        persistent: false,
        allocation: None,
        flag_location: flags::Location::Frame,
        coalesced: None,
        allocating_output: false,
        range_checks,
    };
    for instruction in instructions.iter().take(consumed) {
        emitter.instruction(instruction)?;
        emitter.current += 1;
    }
    for index in 0..POOL.len() {
        emitter.spill(index, true);
    }
    debug_assert_eq!(emitter.locations, FRAME_LOCATIONS);
    Ok(emitter.output)
}

/// Conservative first ordinary-block gate. Actual emitted body bytes and
/// selected native instruction counts must both improve or preserve cost.
/// Timing-derived restrictions can narrow this gate; they never widen semantics.
pub fn admits_allocated(region: &OptimizedRegion, baseline_code: &[u8]) -> bool {
    region.consumed_instructions >= 2
        && region.code.len() < baseline_code.len()
        && analysis::allocated_output_instruction_count(baseline_code)
            .is_some_and(|count| region.stats.native_instructions <= count)
}

pub fn admits_ordinary(region: &OptimizedRegion, baseline_code: &[u8]) -> bool {
    region.consumed_instructions >= 2
        && region.code.len() < baseline_code.len()
        && analysis::selected_output_instruction_count(baseline_code)
            .is_some_and(|count| region.stats.native_instructions <= count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::{Logical, Shift};
    use alloc::vec;
    use alloc::vec::Vec;
    fn instruction(index: u64, operation: Operation) -> Instruction {
        Instruction {
            pc: GuestAddress(0x1000 + index * 4),
            operation,
        }
    }
    fn add(destination: Register, source: Register) -> Operation {
        Operation::AddSub {
            width: Width::X64,
            flags: false,
            subtract: false,
            destination,
            source,
            immediate: 1,
        }
    }
    #[test]
    fn chain_reuses_value_and_settles_once() {
        let instructions: Vec<_> = (0..256)
            .map(|index| instruction(index, add(Register::X(0), Register::X(0))))
            .collect();
        let result = emit_prefix(&instructions).unwrap();
        assert_eq!(result.stats.state_loads, 1);
        assert_eq!(result.stats.pressure_stores, 0);
        assert_eq!(result.stats.exit_stores, 1);
        assert_eq!(result.stats.commits, 256);
        assert_eq!(result.stats.peak_resident, 1);
    }

    #[test]
    fn product_rotate_chain_stays_resident_until_canonical_exit() {
        use crate::aarch64::integer_math::{Kind, Operand};
        let product = Operation::IntegerMath(Operand {
            kind: Kind::Low { width: Width::W32 },
            subtract: false,
            destination: Register::X(0),
            left: Register::X(1),
            right: Register::X(2),
            accumulator: Register::X(0),
        });
        let rotate = Operation::IntegerMath(Operand {
            kind: Kind::Extract {
                width: Width::W32,
                amount: 13,
            },
            subtract: false,
            destination: Register::X(0),
            left: Register::X(0),
            right: Register::X(0),
            accumulator: Register::Zero,
        });
        let instructions = [
            instruction(0, add(Register::X(0), Register::X(0))),
            instruction(1, product.clone()),
            instruction(2, rotate.clone()),
            instruction(3, product),
            instruction(4, rotate),
        ];
        let region = emit_prefix(&instructions).unwrap();
        assert_eq!(region.consumed_instructions, instructions.len());
        assert_eq!(region.stats.exit_stores, 1);
        assert_eq!(region.stats.pressure_stores, 0);
        assert_eq!(region.stats.input_cache_loads, 2);
        assert_eq!(region.stats.peak_resident, 3);
    }

    #[test]
    fn integer_region_eligibility_refuses_other_math_and_malformed_ir() {
        use crate::aarch64::integer_math::{Kind, Operand};
        let operand = Operand {
            kind: Kind::Extract {
                width: Width::W32,
                amount: 0,
            },
            subtract: false,
            destination: Register::X(0),
            left: Register::X(0),
            right: Register::X(0),
            accumulator: Register::Zero,
        };
        let accepted = emit_prefix(&[instruction(0, Operation::IntegerMath(operand))]).unwrap();
        assert_eq!(accepted.consumed_instructions, 1);
        for malformed in [
            Operand {
                kind: Kind::Extract {
                    width: Width::W32,
                    amount: 32,
                },
                ..operand
            },
            Operand {
                right: Register::X(1),
                ..operand
            },
            Operand {
                subtract: true,
                ..operand
            },
            Operand {
                accumulator: Register::X(2),
                ..operand
            },
            Operand {
                kind: Kind::Low { width: Width::X64 },
                left: Register::Sp,
                ..operand
            },
            Operand {
                kind: Kind::Long { signed: false },
                ..operand
            },
            Operand {
                kind: Kind::High { signed: true },
                ..operand
            },
            Operand {
                kind: Kind::Divide {
                    signed: false,
                    width: Width::X64,
                },
                ..operand
            },
        ] {
            let result = emit_prefix(&[instruction(0, Operation::IntegerMath(malformed))]).unwrap();
            assert_eq!(result.consumed_instructions, 0);
            assert!(result.code.is_empty());
        }
    }

    #[test]
    fn selected_math_cost_inspection_refuses_unselected_memory_forms() {
        use analysis::selected_output_instruction_count as count;
        assert_eq!(count(&[0x4d, 0x0f, 0xaf, 0xd3]), Some(1));
        assert_eq!(count(&[0x48, 0x0f, 0xac, 0xc1, 63]), Some(1));
        assert_eq!(count(&[0x48, 0xf7, 0xd8]), Some(1));
        assert_eq!(count(&[0x48, 0x0f, 0xaf, 0x07]), None);
        assert_eq!(count(&[0x48, 0xf7, 0x1f]), None);
        assert_eq!(count(&[0x0f, 0xac, 0xc1]), None);
        assert_eq!(count(&[0x66, 0x0f, 0xaf, 0xc1]), None);
    }
    #[test]
    fn pressure_never_discards_final_architectural_values() {
        let mut instructions: Vec<_> = (0..31)
            .map(|index| instruction(index, add(Register::X(index as u8), Register::Zero)))
            .collect();
        instructions.extend(
            (0..31).map(|index| {
                instruction(index + 31, add(Register::Zero, Register::X(index as u8)))
            }),
        );
        let result = emit_prefix(&instructions).unwrap();
        assert_eq!(result.stats.pressure_stores + result.stats.exit_stores, 31);
        assert_eq!(result.stats.peak_resident, 6);
    }
    #[test]
    fn boundary_does_not_emit_or_consume_later_instructions() {
        let instructions = [
            instruction(0, add(Register::X(0), Register::X(1))),
            instruction(1, Operation::Return),
            instruction(2, add(Register::X(2), Register::X(3))),
        ];
        let result = emit_prefix(&instructions).unwrap();
        assert_eq!(result.consumed_instructions, 1);
        assert_eq!(result.source_map.len(), 1);
        let empty = emit_prefix(&instructions[1..]).unwrap();
        assert!(empty.code.is_empty());
        assert_eq!(empty.consumed_instructions, 0);
    }
    #[test]
    fn malformed_ir_and_flags_form_boundaries() {
        let cases = [
            Operation::MoveWide {
                width: Width::W32,
                kind: WideMove::Zero,
                destination: Register::X(0),
                immediate: 1,
                shift: 32,
            },
            Operation::AddSub {
                width: Width::X64,
                flags: false,
                subtract: false,
                destination: Register::X(0),
                source: Register::X(1),
                immediate: u32::MAX,
            },
            Operation::LogicalRegister {
                width: Width::W32,
                kind: Logical::And,
                flags: false,
                invert: false,
                destination: Register::X(0),
                left: Register::X(1),
                right: Register::X(2),
                shift: Shift::Lsl,
                amount: 32,
            },
            Operation::AddSub {
                width: Width::X64,
                flags: true,
                subtract: false,
                destination: Register::X(0),
                source: Register::X(1),
                immediate: 1,
            },
            add(Register::X(31), Register::X(0)),
        ];
        for operation in cases {
            assert_eq!(
                emit_prefix(&[instruction(0, operation)])
                    .unwrap()
                    .consumed_instructions,
                0
            );
        }
    }
    #[test]
    fn bounded_contiguous_and_overflow_checked() {
        assert_eq!(
            emit_prefix(&vec![instruction(0, Operation::Nop); 257]),
            Err(RegionError::TooLong)
        );
        assert_eq!(
            emit_prefix(&[
                instruction(0, Operation::Nop),
                instruction(2, Operation::Nop)
            ]),
            Err(RegionError::NonContiguous)
        );
        assert_eq!(
            emit_prefix(&[Instruction {
                pc: GuestAddress(u64::MAX - 3),
                operation: Operation::Nop
            }]),
            Err(RegionError::AddressOverflow)
        );
        assert!(emit_prefix(&[]).unwrap().code.is_empty());
    }

    #[test]
    fn locations_refuse_scratch_alias_or_wrong_frame_slot() {
        let mut gprs = FRAME_LOCATIONS;
        assert!(location::valid(&gprs));
        gprs[0] = Location::Host(HostGpr::Rax);
        assert!(!location::valid(&gprs));
        gprs[0] = Location::Host(POOL[0]);
        gprs[1] = Location::Host(POOL[0]);
        assert!(!location::valid(&gprs));
        gprs = FRAME_LOCATIONS;
        gprs[0] = Location::Frame { byte_offset: 8 };
        assert!(!location::valid(&gprs));
    }

    #[test]
    fn exact_fallback_pc_and_initial_alignment_are_checked() {
        assert_eq!(
            emit_prefix(&[
                instruction(0, Operation::Nop),
                instruction(2, Operation::Return)
            ]),
            Err(RegionError::NonContiguous)
        );
        assert_eq!(
            emit_prefix(&[Instruction {
                pc: GuestAddress(0x1001),
                operation: Operation::Nop
            }]),
            Err(RegionError::Misaligned)
        );
    }

    #[test]
    fn selected_output_counter_is_fail_closed_and_tracks_wide_store_recipes() {
        use analysis::selected_output_instruction_count as count;
        assert_eq!(count(&[]), Some(0));
        assert_eq!(count(&[0x66, 0xc7, 0x47, 2, 0x34, 0x12]), Some(1));
        assert_eq!(
            count(&[0x66, 0xc7, 0x87, 0x98, 0, 0, 0, 0x34, 0x12]),
            Some(1)
        );
        assert_eq!(count(&[0xc7, 0x47, 4, 0, 0, 0, 0]), Some(1));
        assert_eq!(count(&[0x48, 0xc7, 0xc0, 1, 0, 0, 0]), Some(1));
        assert_eq!(count(&[0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x90]), Some(2));
        for unsupported in [
            vec![0xc3],
            vec![0xc5, 0xf8, 0x77],
            vec![0x48],
            vec![0x66],
            vec![0x48, 0x8b, 0x04, 0x24], // SIB: outside selected output.
            vec![0x48, 0x8b, 0x05, 0, 0, 0, 0], // RIP-relative.
            vec![0x49, 0x8b, 0x07],       // R15, not the stable RDI frame.
            vec![0xf7, 0xf8],             // IDIV rather than NOT.
            vec![0x81, 0xc0, 1, 0],       // Truncated immediate.
        ] {
            assert_eq!(count(&unsupported), None, "{unsupported:02x?}");
        }
    }

    #[test]
    fn cached_right_is_read_directly_only_without_transform() {
        let mut instructions = vec![instruction(0, add(Register::X(1), Register::X(1)))];
        for index in 1..5 {
            instructions.push(instruction(
                index,
                Operation::AddSubRegister {
                    width: Width::X64,
                    flags: false,
                    subtract: false,
                    destination: Register::X(1),
                    left: Register::X(1),
                    right: Register::X(1),
                    shift: Shift::Lsl,
                    amount: 0,
                },
            ));
        }
        let result = emit_prefix(&instructions).unwrap();
        // Initial load, ADD and MOV; four one-ALU commits; final store.
        assert_eq!(result.stats.native_instructions, 8);
        assert_eq!(result.stats.state_loads, 1);
        assert_eq!(result.stats.exit_stores, 1);
    }

    #[test]
    fn commutative_cached_left_authentic_add_order_saves_staging_copy() {
        let op = |destination, left, right| Operation::AddSubRegister {
            width: Width::X64,
            subtract: false,
            flags: false,
            destination: Register::X(destination),
            left: Register::X(left),
            right: Register::X(right),
            shift: Shift::Lsl,
            amount: 0,
        };
        let first_order =
            emit_prefix(&[instruction(0, op(9, 9, 16)), instruction(1, op(8, 9, 8))]).unwrap();
        let second_order =
            emit_prefix(&[instruction(0, op(9, 9, 16)), instruction(1, op(8, 8, 9))]).unwrap();
        assert_eq!(first_order.stats.native_instructions, 8);
        assert_eq!(second_order.stats.native_instructions, 8);
        assert_eq!(first_order.code.len(), 32);
        assert_eq!(second_order.code.len(), 32);
    }

    #[test]
    fn leaf_entries_preserve_interior_targets_and_fallthroughs() {
        let source = [
            instruction(
                0,
                Operation::BranchZero {
                    target: GuestAddress(0x1008),
                    source: Register::X(2),
                    width: Width::X64,
                    nonzero: false,
                },
            ),
            instruction(1, Operation::Nop),
            instruction(2, Operation::Nop),
            instruction(3, Operation::Return),
            instruction(4, Operation::Nop),
        ];
        assert_eq!(
            analysis::leaf_entries(&source)
                .into_iter()
                .collect::<Vec<_>>(),
            vec![0x1000, 0x1004, 0x1008, 0x1010]
        );
    }

    #[test]
    fn clean_byte_load_tier_retains_five_nonclobbered_slots() {
        let load = instruction(
            2,
            Operation::Memory {
                transfer: MemoryTransfer::Load {
                    signed: false,
                    width: Width::W32,
                },
                bytes: 1,
                data: Register::X(16),
                base: Register::X(15),
                displacement: 3,
                mode: AddressMode::Offset,
            },
        );
        let instructions = vec![
            instruction(0, add(Register::X(9), Register::X(9))),
            instruction(1, add(Register::X(8), Register::X(8))),
            load,
            instruction(3, add(Register::X(9), Register::X(9))),
            instruction(4, add(Register::X(8), Register::X(8))),
        ];
        let output = emit_clean_load_prefix(&instructions, None).unwrap();
        assert_eq!(output.consumed_instructions, 5);
        assert_eq!(output.stats.clean_loads, 1);
        assert_eq!(output.stats.load_boundary_stores, 2);
        assert_eq!(emit_prefix(&instructions).unwrap().consumed_instructions, 2);
    }

    /// With the system-mode guest range check, clean loads keep the same
    /// shape and check each address once, after the frame is settled.
    #[test]
    fn clean_loads_check_the_guest_range_when_asked() {
        use super::super::GUEST_RANGE_CHECK;
        let load = |pc, data, base| {
            instruction(
                pc,
                Operation::Memory {
                    transfer: MemoryTransfer::Load {
                        signed: false,
                        width: Width::W32,
                    },
                    bytes: 4,
                    data: Register::X(data),
                    base: Register::X(base),
                    displacement: 8,
                    mode: AddressMode::Offset,
                },
            )
        };
        let pair = instruction(
            3,
            Operation::MemoryPair {
                transfer: MemoryTransfer::Load {
                    signed: false,
                    width: Width::W32,
                },
                bytes: 4,
                data: [Register::X(4), Register::X(5)],
                base: Register::X(1),
                displacement: 16,
                mode: AddressMode::Offset,
            },
        );
        let instructions = vec![
            instruction(0, add(Register::X(9), Register::X(9))),
            load(1, 2, 1),
            load(2, 3, 1),
            pair,
            instruction(4, add(Register::X(9), Register::X(9))),
        ];
        let checks = |code: &[u8]| {
            code.windows(GUEST_RANGE_CHECK.len())
                .filter(|bytes| *bytes == GUEST_RANGE_CHECK)
                .count()
        };
        let unchecked = emit_clean_load_prefix(&instructions, None).unwrap();
        let checked = emit_clean_load_prefix(&instructions, Some(&[true; 5])).unwrap();
        assert_eq!(checks(&unchecked.code), 0);
        assert_eq!(checks(&checked.code), 3);
        // Each load takes its own instruction's decision.
        let second =
            emit_clean_load_prefix(&instructions, Some(&[true, false, true, false, true])).unwrap();
        assert_eq!(checks(&second.code), 1);
        assert_eq!(
            checked.consumed_instructions,
            unchecked.consumed_instructions
        );
        assert_eq!(checked.stats.clean_loads, unchecked.stats.clean_loads);
        assert_eq!(checked.stats.pair_loads, 1);
        // The second load reuses the cached X1 and still checks.
        assert_eq!(
            checked.stats.address_cache_hits,
            unchecked.stats.address_cache_hits
        );
        assert_eq!(
            checked.code.len(),
            unchecked.code.len() + 3 * GUEST_RANGE_CHECK.len()
        );
    }

    #[test]
    fn cached_right_destination_commutes_only_plain_unshifted_operations() {
        let arithmetic = |subtract, amount| Operation::AddSubRegister {
            width: Width::X64,
            subtract,
            flags: false,
            destination: Register::X(1),
            left: Register::X(0),
            right: Register::X(1),
            shift: Shift::Lsl,
            amount,
        };
        let emit = |operation| {
            emit_prefix(&[
                instruction(0, add(Register::X(0), Register::X(0))),
                instruction(1, add(Register::X(1), Register::X(1))),
                instruction(2, operation),
            ])
            .unwrap()
        };
        let commuted = emit(arithmetic(false, 0));
        assert_eq!(commuted.stats.native_instructions, 9);
        assert_eq!(emit(arithmetic(true, 0)).stats.native_instructions, 10);
        assert_eq!(emit(arithmetic(false, 1)).stats.native_instructions, 12);
        for kind in [Logical::And, Logical::Or, Logical::Xor] {
            let logical = |invert, amount| Operation::LogicalRegister {
                width: Width::W32,
                kind,
                flags: false,
                invert,
                destination: Register::X(1),
                left: Register::X(0),
                right: Register::X(1),
                shift: Shift::Lsl,
                amount,
            };
            assert_eq!(emit(logical(false, 0)).stats.native_instructions, 9);
            assert_eq!(emit(logical(true, 0)).stats.native_instructions, 12);
            assert_eq!(emit(logical(false, 1)).stats.native_instructions, 12);
        }
    }

    #[test]
    fn borrowed_load_result_settles_dirty_changes_before_next_faultable_load() {
        let load = |data| Operation::Memory {
            transfer: MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            bytes: 1,
            data: Register::X(data),
            base: Register::X(1),
            displacement: 0,
            mode: AddressMode::Offset,
        };
        let output = emit_clean_load_prefix(
            &[
                instruction(0, load(10)),
                instruction(1, add(Register::X(10), Register::X(10))),
                instruction(2, load(11)),
                instruction(3, add(Register::X(0), Register::X(10))),
            ],
            None,
        )
        .unwrap();
        assert_eq!(output.stats.load_boundary_stores, 1);
    }

    #[test]
    fn clean_load_tier_declines_unselected_memory_forms() {
        for (base, signed, width, bytes, mode) in [
            (Register::Sp, false, Width::W32, 1, AddressMode::Offset),
            (Register::X(0), true, Width::W32, 1, AddressMode::Offset),
            (Register::X(0), false, Width::X64, 1, AddressMode::Offset),
            (Register::X(0), false, Width::W32, 2, AddressMode::Offset),
            (Register::X(0), false, Width::W32, 1, AddressMode::PostIndex),
        ] {
            let operation = Operation::Memory {
                transfer: MemoryTransfer::Load { signed, width },
                bytes,
                data: Register::X(0),
                base,
                displacement: 0,
                mode,
            };
            assert!(analysis::clean_load_effects(&operation).is_none());
        }
    }

    #[test]
    fn shared_byte_load_recipe_rejects_any_clobber_or_offset_change() {
        let mut raw = vec![];
        super::super::memory(
            &mut raw,
            super::super::MemoryChecks::DEFAULT,
            MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            1,
            Register::X(16),
            Register::X(15),
            -255,
            AddressMode::Offset,
        );
        assert_eq!(
            encoding::ordinary_load_ends(&raw, 1, 15, Some(16), -255),
            Some(vec![7, 14, 17, 20, 27])
        );
        for index in 0..raw.len() {
            let mut mutated = raw.clone();
            mutated[index] ^= 1;
            assert!(encoding::ordinary_load_ends(&mutated, 1, 15, Some(16), -255).is_none());
        }
        raw.push(0x90);
        assert!(encoding::ordinary_load_ends(&raw, 1, 15, Some(16), -255).is_none());
    }

    #[test]
    fn word_load_tier_keeps_clean_residents_and_canonical_fault_state() {
        let load = |data, base| Operation::Memory {
            transfer: MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            bytes: WORD_LOAD_BYTES,
            data,
            base,
            displacement: -4,
            mode: AddressMode::Offset,
        };
        for data in [Register::X(15), Register::X(16), Register::Zero] {
            let instructions = [
                instruction(0, add(Register::X(9), Register::X(9))),
                instruction(1, load(data, Register::X(15))),
                instruction(2, add(Register::X(9), Register::X(9))),
            ];
            let region = emit_clean_load_prefix(&instructions, None).unwrap();
            assert_eq!(region.consumed_instructions, instructions.len());
            assert_eq!(region.stats.clean_loads, 1);
            assert_eq!(region.stats.load_boundary_stores, 1);
            assert!(region.code.windows(2).any(|bytes| bytes == [0x8b, 0x08]));
        }
    }

    #[test]
    fn shared_word_load_recipe_rejects_any_clobber_or_offset_change() {
        for data in [Register::X(16), Register::Zero] {
            let mut raw = vec![];
            super::super::memory(
                &mut raw,
                super::super::MemoryChecks::DEFAULT,
                MemoryTransfer::Load {
                    signed: false,
                    width: Width::W32,
                },
                WORD_LOAD_BYTES,
                data,
                Register::X(15),
                -255,
                AddressMode::Offset,
            );
            let selected = slot(data);
            let ends =
                encoding::ordinary_load_ends(&raw, WORD_LOAD_BYTES, 15, selected, -255).unwrap();
            assert_eq!(ends.last(), Some(&raw.len()));
            for index in 0..raw.len() {
                let mut mutated = raw.clone();
                mutated[index] ^= 1;
                assert!(
                    encoding::ordinary_load_ends(&mutated, WORD_LOAD_BYTES, 15, selected, -255)
                        .is_none()
                );
            }
            assert!(
                encoding::ordinary_load_ends(&raw, BYTE_LOAD_BYTES, 15, selected, -255).is_none()
            );
        }
    }

    #[test]
    fn repeated_read_only_inputs_are_cached_without_architectural_writes() {
        let operation = |destination| Operation::AddSubRegister {
            width: Width::X64,
            subtract: true,
            flags: false,
            destination,
            left: destination,
            right: Register::X(12),
            shift: Shift::Lsl,
            amount: 0,
        };
        let source = [
            instruction(0, operation(Register::X(0))),
            instruction(1, operation(Register::X(1))),
            instruction(2, operation(Register::X(0))),
            instruction(3, operation(Register::X(1))),
        ];
        let region = emit_prefix(&source).unwrap();
        assert!(region.stats.input_cache_loads > 0);
        assert!(region.stats.cache_hits >= 3);
        assert_eq!(region.stats.pressure_stores, 0);
        assert_eq!(region.stats.exit_stores + region.stats.lifetime_stores, 2);
    }

    #[test]
    fn pair_loads_retain_clean_results_and_reject_changed_shared_recipe() {
        let data = [Register::X(16), Register::X(17)];
        let operation = Operation::MemoryPair {
            transfer: MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            bytes: WORD_LOAD_BYTES,
            data,
            base: Register::X(15),
            displacement: -8,
            mode: AddressMode::Offset,
        };
        let source = [
            instruction(0, add(Register::X(9), Register::X(9))),
            instruction(1, operation),
            instruction(2, add(Register::X(9), Register::X(16))),
            instruction(3, add(Register::X(10), Register::X(17))),
        ];
        let region = emit_clean_load_prefix(&source, None).unwrap();
        assert_eq!(region.consumed_instructions, source.len());
        assert_eq!(region.stats.pair_loads, 1);
        let mut raw = vec![];
        super::super::memory_pair(
            &mut raw,
            super::super::MemoryChecks::DEFAULT,
            MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            WORD_LOAD_BYTES,
            data,
            Register::X(15),
            -8,
            AddressMode::Offset,
        );
        assert!(encoding::ordinary_pair_load_ends(&raw, 15, [Some(16), Some(17)], -8).is_some());
        for index in 0..raw.len() {
            let mut changed = raw.clone();
            changed[index] ^= 1;
            assert!(
                encoding::ordinary_pair_load_ends(&changed, 15, [Some(16), Some(17)], -8).is_none()
            );
        }
        assert!(encoding::ordinary_pair_load_ends(&raw, 15, [Some(16), Some(16)], -8).is_none());
    }

    #[test]
    fn paired_load_tier_declines_unselected_shapes() {
        let selected = Operation::MemoryPair {
            transfer: MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            bytes: WORD_LOAD_BYTES,
            data: [Register::X(0), Register::X(1)],
            base: Register::X(2),
            displacement: 0,
            mode: AddressMode::Offset,
        };
        assert!(analysis::clean_load_effects(&selected).is_some());
        for (transfer, bytes, data, base, mode) in [
            (
                MemoryTransfer::Store,
                WORD_LOAD_BYTES,
                [Register::X(0), Register::X(1)],
                Register::X(2),
                AddressMode::Offset,
            ),
            (
                MemoryTransfer::Load {
                    signed: true,
                    width: Width::X64,
                },
                WORD_LOAD_BYTES,
                [Register::X(0), Register::X(1)],
                Register::X(2),
                AddressMode::Offset,
            ),
            (
                MemoryTransfer::Load {
                    signed: false,
                    width: Width::X64,
                },
                8,
                [Register::X(0), Register::X(1)],
                Register::X(2),
                AddressMode::Offset,
            ),
            (
                MemoryTransfer::Load {
                    signed: false,
                    width: Width::W32,
                },
                WORD_LOAD_BYTES,
                [Register::X(0), Register::X(0)],
                Register::X(2),
                AddressMode::Offset,
            ),
            (
                MemoryTransfer::Load {
                    signed: false,
                    width: Width::W32,
                },
                WORD_LOAD_BYTES,
                [Register::X(0), Register::X(1)],
                Register::Sp,
                AddressMode::Offset,
            ),
            (
                MemoryTransfer::Load {
                    signed: false,
                    width: Width::W32,
                },
                WORD_LOAD_BYTES,
                [Register::X(0), Register::X(1)],
                Register::X(2),
                AddressMode::PostIndex,
            ),
        ] {
            assert!(
                analysis::clean_load_effects(&Operation::MemoryPair {
                    transfer,
                    bytes,
                    data,
                    base,
                    displacement: 0,
                    mode
                })
                .is_none()
            );
        }
    }

    fn define_flags(destination: Register, source: Register) -> Operation {
        Operation::AddSub {
            width: Width::X64,
            subtract: true,
            flags: true,
            destination,
            source,
            immediate: 1,
        }
    }

    fn select_flags(
        destination: Register,
        left: Register,
        right: Register,
        condition: u8,
    ) -> Operation {
        Operation::ConditionalSelect(crate::aarch64::conditional_select::Operand {
            width: Width::X64,
            destination,
            left,
            right,
            condition,
            otherwise: crate::aarch64::conditional_select::Otherwise::Unchanged,
        })
    }

    #[test]
    fn value_liveness_keeps_final_bank_and_kills_only_overwritten_versions() {
        use allocation::{LiveRanges, Value, ValueEffects};
        let x0 = Value::gpr(0).unwrap();
        let x1 = Value::gpr(1).unwrap();
        let effects = [
            ValueEffects::new(
                Effects {
                    reads: 0,
                    writes: 1,
                },
                false,
                true,
            ),
            ValueEffects::new(
                Effects {
                    reads: 1,
                    writes: 2,
                },
                false,
                false,
            ),
            ValueEffects::new(
                Effects {
                    reads: 0,
                    writes: 1,
                },
                false,
                true,
            ),
        ];
        let live = LiveRanges::compute(&effects);
        assert!(live.required_after(0, x0));
        assert!(!live.required_after(1, x0));
        assert!(!live.required_after(0, Value::NZCV));
        assert!(live.required_after(1, x1));
        assert!(live.required_after(2, x0));
        assert!(live.required_after(2, Value::NZCV));
        assert_eq!(live.before(0) & (x0.mask() | Value::NZCV.mask()), 0);
    }

    #[test]
    fn packed_flags_survive_nonflag_arithmetic_without_frame_roundtrip() {
        let instructions = [
            instruction(0, define_flags(Register::Zero, Register::X(0))),
            instruction(
                1,
                select_flags(Register::X(2), Register::X(0), Register::X(1), 0),
            ),
            instruction(2, add(Register::X(3), Register::X(1))),
            instruction(
                3,
                select_flags(Register::X(4), Register::X(2), Register::X(3), 12),
            ),
        ];
        let region = emit_allocated_prefix(&instructions).unwrap().unwrap();
        assert_eq!(region.consumed_instructions, instructions.len());
        assert_eq!(region.stats.flag_loads, 0);
        assert_eq!(region.stats.flag_stores, 1);
        assert_eq!(region.stats.pressure_stores, 0);
    }

    #[test]
    fn dead_native_flag_version_needs_no_capture_before_next_producer() {
        let instructions = [
            instruction(0, define_flags(Register::Zero, Register::X(0))),
            instruction(1, add(Register::X(1), Register::X(0))),
            instruction(2, define_flags(Register::Zero, Register::X(1))),
        ];
        let region = emit_allocated_prefix(&instructions).unwrap().unwrap();
        assert_eq!(region.stats.flag_loads, 0);
        assert_eq!(region.stats.flag_stores, 1);
        assert!(region.stats.dead_versions >= 1);
    }

    #[test]
    fn caller_pool_is_still_exact_for_legacy_cost_and_load_chunk() {
        let instructions = [
            instruction(0, add(Register::X(2), Register::X(2))),
            instruction(
                1,
                Operation::Memory {
                    transfer: MemoryTransfer::Load {
                        signed: false,
                        width: Width::W32,
                    },
                    bytes: 1,
                    data: Register::X(3),
                    base: Register::X(0),
                    displacement: 0,
                    mode: AddressMode::Offset,
                },
            ),
            instruction(2, add(Register::X(2), Register::X(2))),
        ];
        assert!(emit_allocated_prefix(&instructions).unwrap().is_none());
        let legacy = emit_clean_load_prefix(&instructions, None).unwrap();
        let target = crate::TargetCpu::Baseline;
        let fallthrough = GuestAddress(0x100c);
        let baseline = super::super::block::emit_for_target(
            &instructions,
            None,
            fallthrough,
            target,
            super::super::MemoryChecks::DEFAULT,
        );
        let ordinary =
            super::super::block::emit_ordinary_for_target(&instructions, None, fallthrough, target);
        let mut baseline_prefix = vec![];
        let mut fixups = vec![];
        for instruction in &instructions {
            super::super::emit_instruction(
                &mut baseline_prefix,
                instruction,
                &mut fixups,
                target,
                super::super::MemoryChecks::DEFAULT,
            );
        }
        assert!(fixups.is_empty());
        if admits_ordinary(&legacy, &baseline_prefix) {
            assert!(ordinary.x86_64_code.starts_with(&legacy.code));
            assert_eq!(
                &ordinary.source_map[..instructions.len()],
                &legacy.source_map
            );
        } else {
            assert_eq!(ordinary.x86_64_code, baseline.x86_64_code);
            assert_eq!(ordinary.source_map, baseline.source_map);
        }
        let mut capture = Vec::new();
        crate::x86_64::capture_nzcv(&mut capture, true);
        assert_eq!(analysis::selected_output_instruction_count(&capture), None);
        assert_eq!(
            analysis::allocated_output_instruction_count(&capture),
            Some(10)
        );
    }

    #[test]
    fn wider_loop_admission_uses_actual_capacity_not_five_participants() {
        let mut instructions: Vec<_> = (0..7)
            .map(|index| {
                instruction(
                    index,
                    add(Register::X(index as u8), Register::X(index as u8)),
                )
            })
            .collect();
        instructions.push(instruction(7, define_flags(Register::X(0), Register::X(0))));
        let terminal = (
            GuestAddress(0x1020),
            crate::block::Terminator::Branch(Operation::BranchCondition {
                target: GuestAddress(0x1000),
                condition: 1,
            }),
        );
        let plan =
            self_loop::Plan::new(&instructions, Some(&terminal), GuestAddress(0x1024)).unwrap();
        let native = plan.emit(&instructions).unwrap();
        assert_eq!(native.source_map.len(), instructions.len() + 1);
        assert_eq!(native.source_map[0].1, 0);
        let changed = [instruction(0, Operation::Nop)];
        let plan =
            self_loop::Plan::new(&instructions, Some(&terminal), GuestAddress(0x1024)).unwrap();
        assert!(matches!(
            plan.emit(&changed),
            Err(RegionError::ChangedInstructions)
        ));
    }
}
