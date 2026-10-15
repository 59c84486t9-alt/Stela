//! Bounded scalar regions with canonical prefix exits. The default is nonfaulting.
//! The private clean-load tier uses existing nonalias ordinary direct-RAM memory
//! emission and settles every dirty value before its faultable byte access.
//! Research rows do not provide general asynchronous/native-fault delivery.
mod analysis;
pub(super) use analysis::MAX_INSTRUCTIONS;
mod constant;
mod encoding;
pub mod recovery;

use crate::{
    GuestAddress,
    aarch64::{AddressMode, Instruction, MemoryTransfer, Operation, Register, WideMove, Width},
};
#[cfg(test)]
use analysis::Liveness;
use analysis::{Effects, next_use, prefix_effects, slot};
use encoding::{HostGpr, POOL, RESULT, RIGHT};
#[cfg(test)]
use recovery::Phase;
use recovery::{FRAME_LOCATIONS, GPR_SLOTS, Location, RecoveryPoint};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionError {
    TooLong,
    Misaligned,
    NonContiguous,
    AddressOverflow,
    ChangedMemoryEncoding,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptimizedRegion {
    pub code: Vec<u8>,
    pub consumed_instructions: usize,
    pub source_map: Vec<(GuestAddress, usize)>,
    /// One GPR-location snapshot per emitted native instruction for internal
    /// validation. Tests retain its native interval, guest PC and commit phase;
    /// production does not expose a host-context recovery service.
    pub recovery: Vec<RecoveryPoint>,
    #[cfg(test)]
    pub exit_pc: Option<GuestAddress>,
    #[cfg(test)]
    pub exit_gprs: [Location; GPR_SLOTS],
    #[cfg(test)]
    pub liveness: Liveness,
    pub stats: AllocationStats,
}

#[derive(Debug, Clone, Copy)]
struct Resident {
    guest: usize,
    dirty: bool,
}

struct Emitter<'a> {
    output: OptimizedRegion,
    resident: [Option<Resident>; POOL.len()],
    locations: [Location; GPR_SLOTS],
    effects: &'a [Effects],
    current: usize,
    #[cfg(test)]
    pc: GuestAddress,
    #[cfg(test)]
    phase: Phase,
    constants: constant::ConstantRegisters,
    pool_start: usize,
    operand_reuse: bool,
}

impl Emitter<'_> {
    fn emit(&mut self, encode: impl FnOnce(&mut Vec<u8>)) {
        let start = self.output.code.len();
        encode(&mut self.output.code);
        let end = self.output.code.len();
        debug_assert!(end > start);
        self.output.recovery.push(RecoveryPoint {
            #[cfg(test)]
            native_start: start,
            #[cfg(test)]
            native_end: end,
            #[cfg(test)]
            guest_pc: self.pc,
            #[cfg(test)]
            retired_instructions: self.current,
            #[cfg(test)]
            phase: self.phase,
            gprs: self.locations,
        });
        self.output.stats.native_instructions += 1;
    }

    fn spill(&mut self, index: usize, at_exit: bool) {
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
        if let Some(index) = self
            .resident
            .iter()
            .position(|value| value.is_some_and(|value| value.guest == guest))
        {
            return index;
        }
        let index = self.resident[self.pool_start..]
            .iter()
            .position(Option::is_none)
            .map(|index| index + self.pool_start)
            .unwrap_or_else(|| {
                self.resident
                    .iter()
                    .enumerate()
                    .skip(self.pool_start)
                    .max_by_key(|(_, value)| {
                        next_use(self.effects, self.current + 1, value.unwrap().guest)
                    })
                    .unwrap()
                    .0
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
        if let Some(guest) = slot(register) {
            if let Some(index) = self
                .resident
                .iter()
                .position(|value| value.is_some_and(|value| value.guest == guest))
            {
                self.output.stats.cache_hits += 1;
                self.emit(|code| encoding::copy(code, destination, POOL[index], Width::X64));
            } else {
                self.emit(|code| encoding::load(code, destination, guest));
                self.output.stats.state_loads += 1;
            }
        } else {
            self.emit(|code| encoding::immediate(code, destination, 0, Width::W32));
        }
    }

    fn cached(&self, register: Register) -> Option<HostGpr> {
        let guest = slot(register)?;
        self.resident
            .iter()
            .position(|value| value.is_some_and(|value| value.guest == guest))
            .map(|index| POOL[index])
    }

    fn in_place(&self, destination: Register, source: Register) -> Option<HostGpr> {
        let guest = slot(destination)?;
        if destination != source {
            return None;
        }
        self.resident
            .iter()
            .position(|value| value.is_some_and(|value| value.guest == guest))
            .map(|index| POOL[index])
    }

    fn committed_in_place(&mut self, destination: Register) {
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
        if let Some(guest) = slot(destination) {
            if next_use(self.effects, self.current + 1, guest) == usize::MAX {
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

    fn clean_byte_load(
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
        let ends = encoding::ordinary_byte_load_ends(
            &raw,
            slot(base).expect("eligible X base"),
            slot(data),
            displacement,
        )
        .ok_or(RegionError::ChangedMemoryEncoding)?;
        // Every dirty architectural value reaches the canonical frame before
        // the guest access. Nonclobbered clean host copies remain useful.
        for (index, host) in POOL.iter().copied().enumerate() {
            if let Some(resident) = self.resident[index]
                && resident.dirty
            {
                self.emit(|code| encoding::store(code, host, resident.guest));
                self.output.stats.load_boundary_stores += 1;
                self.resident[index].as_mut().unwrap().dirty = false;
            }
        }
        // Existing memory() clobbers RAX/RCX/RDX, and commits destination in
        // frame. RAX/RDX are scratches; the memory tier never allocates RCX.
        for (index, host) in POOL.iter().copied().enumerate() {
            if let Some(resident) = self.resident[index]
                && (host == HostGpr::Rcx || slot(data) == Some(resident.guest))
            {
                debug_assert!(!resident.dirty);
                self.locations[resident.guest] = FRAME_LOCATIONS[resident.guest];
                self.resident[index] = None;
            }
        }
        let mut start = 0;
        for end in ends {
            self.emit(|code| code.extend_from_slice(&raw[start..end]));
            start = end;
        }
        // The unchanged memory recipe has committed this exact zero-extended
        // value to frame. Borrow its remaining RCX copy without another load or
        // register move. General allocation still skips RCX in this tier, and
        // the next memory access flushes any later change before clobbering it.
        if self.operand_reuse
            && let Some(guest) = slot(data)
        {
            debug_assert_eq!(POOL[0], HostGpr::Rcx);
            debug_assert!(self.resident[0].is_none());
            self.resident[0] = Some(Resident {
                guest,
                dirty: false,
            });
            self.locations[guest] = Location::Host(HostGpr::Rcx);
            self.output.stats.peak_resident = self
                .output
                .stats
                .peak_resident
                .max(self.resident.iter().flatten().count());
        }
        self.output.stats.clean_loads += 1;
        self.output.stats.commits += 1;
        Ok(())
    }

    fn instruction(&mut self, instruction: &Instruction) -> Result<(), RegionError> {
        self.output
            .source_map
            .push((instruction.pc, self.output.code.len()));
        if let Some(write) = self.constants.step(&instruction.operation) {
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
                self.clean_byte_load(transfer, bytes, data, base, displacement, mode)?;
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
                let (left, right) = if self.operand_reuse
                    && !subtract
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
                let (left, right) = if self.operand_reuse
                    && !invert
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

/// Private ordinary direct-RAM clean-load tier; pure ALU API stays six-slot.
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
        && instructions
            .iter()
            .take(effects.len())
            .any(|instruction| matches!(instruction.operation, Operation::Memory { .. }));
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
            recovery: vec![],
            #[cfg(test)]
            exit_pc,
            #[cfg(test)]
            exit_gprs: FRAME_LOCATIONS,
            #[cfg(test)]
            liveness: Liveness::compute(&effects),
            stats: AllocationStats::default(),
        },
        resident: [None; POOL.len()],
        locations: FRAME_LOCATIONS,
        effects: &effects,
        current: 0,
        #[cfg(test)]
        pc: entry.unwrap_or(GuestAddress(0)),
        #[cfg(test)]
        phase: Phase::BeforeGuestCommit,
        constants: constant::ConstantRegisters::default(),
        pool_start: usize::from(contains_load),
        operand_reuse: true,
    };
    for instruction in instructions.iter().take(consumed) {
        #[cfg(test)]
        {
            emitter.pc = instruction.pc;
        }
        emitter.instruction(instruction)?;
        emitter.current += 1;
        #[cfg(test)]
        {
            emitter.pc = GuestAddress(instruction.pc.0 + 4);
        }
    }
    #[cfg(test)]
    {
        emitter.phase = Phase::ExitSettlement;
    }
    for index in 0..POOL.len() {
        emitter.spill(index, true);
    }
    debug_assert_eq!(emitter.locations, FRAME_LOCATIONS);
    debug_assert!(emitter.output.recovery.iter().all(RecoveryPoint::validate));
    Ok(emitter.output)
}

#[cfg(test)]
mod tests;

/// Conservative first ordinary-block gate. Actual emitted body bytes and
/// selected native instruction counts must both improve or preserve cost.
/// Timing-derived restrictions can narrow this gate; they never widen semantics.
pub fn admits_ordinary(region: &OptimizedRegion, baseline_code: &[u8]) -> bool {
    region.consumed_instructions >= 2
        && region.code.len() < baseline_code.len()
        && analysis::selected_output_instruction_count(baseline_code)
            .is_some_and(|count| region.stats.native_instructions <= count)
}
