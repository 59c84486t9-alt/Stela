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
        // All original operands have been consumed. Result allocation may now
        // evict them according to next use without changing this operation.
        self.pinned_hosts = 0;
        if let Some(guest) = slot(destination) {
            if !self.persistent && next_use(self.effects, self.current + 1, guest) == usize::MAX {
                // This value has reached its last use in the region. Commit to
                // its canonical final location, retaining the old Host recipe
                // until the store succeeds. Other resident values stay cached.
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
            // Nonfaulting ZR writes have no architectural effects. Keep an
            // explicit host boundary so retirement is still observable.
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
        super::memory(&mut raw, transfer, bytes, data, base, displacement, mode);
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
        super::memory_pair(&mut raw, transfer, bytes, data, base, displacement, mode);
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
                    // All sources retain their original architectural value until
                    // commit, including Rd==Rn/Rm/Ra. The low product is identical
                    // for signed and unsigned inputs modulo the selected width.
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

/// Emit the longest eligible prefix. No RET, helper, dispatch or guest faulting
/// access is appended. The consumer starts the unchanged baseline emitter at
/// consumed_instructions with a fully canonical frame and exact exit_pc.
#[cfg(test)]
pub fn emit_prefix(instructions: &[Instruction]) -> Result<OptimizedRegion, RegionError> {
    emit_prefix_selected(instructions, false)
}

/// Transactional nonfaulting GPR/NZCV span candidate.
pub fn emit_allocated_prefix(
    instructions: &[Instruction],
) -> Result<Option<OptimizedRegion>, RegionError> {
    allocation::prefix(instructions)
}

/// Ordinary direct-RAM load retention; pure ALU allocation keeps six slots.
pub fn emit_clean_load_prefix(
    instructions: &[Instruction],
) -> Result<OptimizedRegion, RegionError> {
    emit_prefix_selected(instructions, true)
}

fn emit_prefix_selected(
    instructions: &[Instruction],
    clean_loads: bool,
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

#[cfg(test)]
mod tests;

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
