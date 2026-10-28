//! Value liveness within a non-faulting span. A value is dead only when it is
//! overwritten before the next exit.
use super::{Emitter, Resident, analysis::Effects, encoding, flags, location::GPR_SLOTS};
use crate::aarch64::{Register, Width};
use crate::x86_64::asm::Code;
use alloc::vec;
use alloc::vec::Vec;
use encoding::{CALLEE_POOL, HostGpr, POOL, RESULT};

pub(super) type ValueMask = u64;
const NZCV_SLOT: usize = GPR_SLOTS;
const VALUE_SLOTS: usize = GPR_SLOTS + 1;
const _: () = assert!(VALUE_SLOTS < ValueMask::BITS as usize);
pub(super) const CANONICAL_EXIT: ValueMask = (1 << VALUE_SLOTS) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Value(usize);

impl Value {
    pub(super) const NZCV: Self = Self(NZCV_SLOT);

    pub(super) fn gpr(slot: usize) -> Option<Self> {
        (slot < GPR_SLOTS).then_some(Self(slot))
    }

    pub(super) const fn slot(self) -> usize {
        self.0
    }

    pub(super) const fn mask(self) -> ValueMask {
        1 << self.0
    }

    pub(super) const fn is_nzcv(self) -> bool {
        self.0 == NZCV_SLOT
    }
}

/// Architectural value effects, independent of host instruction clobbers.
/// Only a complete NZCV producer may set `writes_flags`; partial flag effects
/// remain outside the span's admission contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ValueEffects {
    pub(super) reads: ValueMask,
    pub(super) writes: ValueMask,
}

impl ValueEffects {
    pub(super) const fn new(gprs: Effects, reads_flags: bool, writes_flags: bool) -> Self {
        Self {
            reads: gprs.reads as ValueMask | if reads_flags { Value::NZCV.mask() } else { 0 },
            writes: gprs.writes as ValueMask | if writes_flags { Value::NZCV.mask() } else { 0 },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LiveRanges {
    before: Vec<ValueMask>,
    inputs: ValueMask,
}

impl LiveRanges {
    pub(super) fn compute(effects: &[ValueEffects]) -> Self {
        let mut live = CANONICAL_EXIT;
        let mut before = vec![0; effects.len()];
        for (index, effect) in effects.iter().enumerate().rev() {
            live = (live & !effect.writes) | effect.reads;
            before[index] = live;
        }
        let mut defined = 0;
        let mut inputs = 0;
        for effect in effects {
            inputs |= effect.reads & !defined;
            defined |= effect.writes;
        }
        Self { before, inputs }
    }

    /// Values read before their first definition. A loop header must keep them
    /// across its back edge or spill them.
    pub(super) fn inputs(&self) -> ValueMask {
        self.inputs
    }

    pub(super) fn before(&self, instruction: usize) -> ValueMask {
        self.before[instruction]
    }

    pub(super) fn after(&self, instruction: usize) -> ValueMask {
        assert!(instruction < self.before.len());
        self.before
            .get(instruction + 1)
            .copied()
            .unwrap_or(CANONICAL_EXIT)
    }

    pub(super) fn required_after(&self, instruction: usize, value: Value) -> bool {
        self.after(instruction) & value.mask() != 0
    }
}

/// Find the next read of this version, stopping at its next definition. A value
/// used only at the exit has no next read, but dirty final values remain live
/// in `LiveRanges`.
pub(super) fn next_read(
    effects: &[ValueEffects],
    after: usize,
    value: Value,
    cyclic: bool,
) -> Option<usize> {
    let mask = value.mask();
    for (index, effect) in effects.iter().enumerate().skip(after) {
        if effect.reads & mask != 0 {
            return Some(index);
        }
        if effect.writes & mask != 0 {
            return None;
        }
    }
    if cyclic {
        for (index, effect) in effects.iter().enumerate() {
            if effect.reads & mask != 0 {
                return Some(effects.len() + index);
            }
            if effect.writes & mask != 0 {
                break;
            }
        }
    }
    None
}

/// One immutable allocation policy for both ordinary spans and resident loops.
/// The exact emitted candidates choose the smallest useful borrowed subset.
#[derive(Debug, Clone)]
pub(super) struct Plan {
    effects: Vec<ValueEffects>,
    live: LiveRanges,
    callee_slots: usize,
    cyclic: bool,
}

impl Plan {
    pub(super) fn new(effects: Vec<ValueEffects>, callee_slots: usize, cyclic: bool) -> Self {
        assert!(callee_slots <= CALLEE_POOL.len());
        let live = LiveRanges::compute(&effects);
        Self {
            effects,
            live,
            callee_slots,
            cyclic,
        }
    }

    pub(super) fn callee_slots(&self) -> usize {
        self.callee_slots
    }

    pub(super) fn requires_after(&self, instruction: usize, value: Value) -> bool {
        self.live.required_after(instruction, value)
    }

    fn required(&self, instruction: usize, value: Value, after_commit: bool) -> bool {
        if after_commit {
            return self.live.required_after(instruction, value);
        }
        let live = if instruction < self.effects.len() {
            self.live.before(instruction)
        } else {
            CANONICAL_EXIT
        };
        live & value.mask() != 0
    }

    fn next_read(&self, instruction: usize, value: Value) -> Option<usize> {
        next_read(&self.effects, instruction + 1, value, self.cyclic)
    }
}

impl Value {
    fn resident(slot: usize) -> Self {
        assert!(slot < VALUE_SLOTS);
        Self(slot)
    }
}

impl Emitter<'_> {
    pub(super) fn value_index(&self, value: Value) -> Option<usize> {
        self.resident
            .iter()
            .position(|resident| resident.is_some_and(|resident| resident.guest == value.slot()))
    }

    pub(super) fn forget_value(&mut self, index: usize) {
        if let Some(resident) = self.resident[index].take() {
            let value = Value::resident(resident.guest);
            if value.is_nzcv() {
                self.flag_location = flags::Location::Frame;
            } else {
                self.locations[value.slot()] = super::FRAME_LOCATIONS[value.slot()];
            }
        }
    }

    pub(super) fn spill_value(&mut self, index: usize, at_exit: bool) {
        let Some(resident) = self.resident[index] else {
            return;
        };
        let value = Value::resident(resident.guest);
        let required = at_exit
            || self.allocation.as_ref().unwrap().required(
                self.current,
                value,
                self.allocating_output,
            );
        if resident.dirty && required {
            let host = encoding::pool_host(index);
            if value.is_nzcv() {
                self.emit(|code| encoding::store_nzcv(code, host));
                self.output.stats.flag_stores += 1;
                if at_exit {
                    self.output.stats.nzcv_boundary_stores += 1;
                } else {
                    self.output.stats.nzcv_pressure_stores += 1;
                }
            } else {
                self.emit(|code| encoding::store(code, host, value.slot()));
            }
            if at_exit {
                self.output.stats.exit_stores += 1;
            } else {
                self.output.stats.pressure_stores += 1;
            }
        } else if resident.dirty {
            self.output.stats.dead_versions += 1;
        }
        self.forget_value(index);
    }

    pub(super) fn allocate_value(&mut self, value: Value) -> usize {
        if let Some(index) = self.value_index(value) {
            return index;
        }
        let plan = self.allocation.as_ref().unwrap();
        let available = (0..POOL.len() + plan.callee_slots).filter(|&index| {
            (self.reserved_hosts | self.pinned_hosts) & encoding::pool_host(index).mask() == 0
        });
        let index = available
            .clone()
            .find(|&index| self.resident[index].is_none())
            .unwrap_or_else(|| {
                available
                    .max_by_key(|&index| {
                        let resident = self.resident[index].unwrap();
                        let value = Value::resident(resident.guest);
                        (
                            !plan.required(self.current, value, self.allocating_output),
                            !resident.dirty,
                            plan.next_read(self.current, value).unwrap_or(usize::MAX),
                        )
                    })
                    .expect("dedicated operand scratch leaves an allocation slot")
            });
        self.spill_value(index, false);
        self.resident[index] = Some(Resident {
            guest: value.slot(),
            dirty: false,
        });
        self.output.stats.peak_resident = self
            .output
            .stats
            .peak_resident
            .max(self.resident.iter().flatten().count());
        index
    }

    pub(super) fn cached_value(&mut self, register: Register) -> Option<HostGpr> {
        let value = Value::gpr(super::slot(register)?)?;
        let index = self.value_index(value)?;
        let host = encoding::pool_host(index);
        self.pinned_hosts |= host.mask();
        Some(host)
    }

    pub(super) fn read_value(&mut self, register: Register, destination: HostGpr) {
        let Some(value) = super::slot(register).and_then(Value::gpr) else {
            self.emit(|code| encoding::immediate(code, destination, 0, Width::W32));
            return;
        };
        if let Some(index) = self.value_index(value) {
            self.output.stats.cache_hits += 1;
            self.emit(|code| {
                encoding::copy(code, destination, encoding::pool_host(index), Width::X64)
            });
        } else if self
            .allocation
            .as_ref()
            .unwrap()
            .next_read(self.current, value)
            .is_some()
        {
            let index = self.allocate_value(value);
            let host = encoding::pool_host(index);
            self.emit(|code| encoding::load(code, host, value.slot()));
            self.locations[value.slot()] = super::Location::Host(host);
            self.emit(|code| encoding::copy(code, destination, host, Width::X64));
            self.output.stats.state_loads += 1;
            self.output.stats.input_cache_loads += 1;
        } else {
            self.emit(|code| encoding::load(code, destination, value.slot()));
            self.output.stats.state_loads += 1;
        }
    }

    /// Rename only after all sources have been consumed. Queries never alter the
    /// old value's identity, including aliases read again by this instruction.
    pub(super) fn coalesce_value(
        &mut self,
        destination: Register,
        source: Register,
    ) -> Option<HostGpr> {
        let destination = super::slot(destination).and_then(Value::gpr)?;
        let source = super::slot(source).and_then(Value::gpr)?;
        let index = self.value_index(source)?;
        let resident = self.resident[index].unwrap();
        let plan = self.allocation.as_ref().unwrap();
        if destination != source
            && (plan.next_read(self.current, source).is_some()
                || (resident.dirty && plan.live.required_after(self.current, source)))
        {
            return None;
        }
        self.coalesced = Some(index);
        let host = encoding::pool_host(index);
        self.pinned_hosts |= host.mask();
        Some(host)
    }

    fn replace_destination(&mut self, value: Value, keep: usize) {
        if let Some(old) = self.value_index(value)
            && old != keep
        {
            // This instruction has consumed every old input and defined a new
            // destination version. The overwritten version needs no store.
            self.forget_value(old);
        }
    }

    pub(super) fn commit_coalesced(&mut self, destination: Register) {
        self.output.stats.in_place_source_uses += 1;
        let value = super::slot(destination).and_then(Value::gpr).unwrap();
        let index = self.coalesced.take().expect("selected source host");
        let previous = self.resident[index].unwrap();
        self.replace_destination(value, index);
        if previous.guest != value.slot() {
            self.locations[previous.guest] = super::FRAME_LOCATIONS[previous.guest];
            self.output.stats.coalesced_writes += 1;
        }
        self.resident[index] = Some(Resident {
            guest: value.slot(),
            dirty: true,
        });
        self.locations[value.slot()] = super::Location::Host(encoding::pool_host(index));
        self.output.stats.commits += 1;
    }

    pub(super) fn commit_value(&mut self, destination: Register, width: Width) {
        self.pinned_hosts = 0;
        self.coalesced = None;
        if let Some(value) = super::slot(destination).and_then(Value::gpr) {
            self.allocating_output = true;
            let index = self.allocate_value(value);
            self.allocating_output = false;
            self.emit(|code| encoding::copy(code, encoding::pool_host(index), RESULT, width));
            self.locations[value.slot()] = super::Location::Host(encoding::pool_host(index));
            self.resident[index] = Some(Resident {
                guest: value.slot(),
                dirty: true,
            });
        } else {
            self.emit(encoding::nop);
        }
        self.output.stats.commits += 1;
    }

    pub(super) fn borrow_callees(&mut self) {
        let count = self.allocation.as_ref().unwrap().callee_slots();
        for host in CALLEE_POOL.into_iter().take(count) {
            self.emit(|code| encoding::push(code, host));
            self.output.stats.callee_saves += 1;
        }
    }

    pub(super) fn restore_callees(&mut self) {
        let count = self.allocation.as_ref().unwrap().callee_slots();
        for host in CALLEE_POOL.into_iter().take(count).rev() {
            self.emit(|code| encoding::pop(code, host));
            self.output.stats.callee_restores += 1;
        }
    }
}

pub(super) fn emitter<'a>(
    gprs: &'a [Effects],
    plan: Plan,
    _entry: crate::GuestAddress,
) -> Emitter<'a> {
    Emitter {
        output: super::OptimizedRegion {
            code: Code::from(vec![]),
            consumed_instructions: gprs.len(),
            source_map: vec![],
            stats: super::AllocationStats::default(),
            fault_recovery: vec![],
        },
        resident: [None; encoding::ALLOCATABLE_SLOTS],
        locations: super::FRAME_LOCATIONS,
        effects: gprs,
        current: 0,
        constants: super::constant::ConstantRegisters::default(),
        reserved_hosts: 0,
        pinned_hosts: 0,
        persistent: false,
        allocation: Some(plan),
        flag_location: flags::Location::Frame,
        coalesced: None,
        allocating_output: false,
        range_checks: None,
        // No loads.
        checks: super::super::MemoryChecks::DEFAULT,
        fault_table: false,
    }
}

/// Admit a span of register operations. Memory, helper and control operations
/// end it; callers keep their chunking when it is rejected.
pub(super) fn prefix(
    instructions: &[crate::aarch64::Instruction],
) -> Result<Option<super::OptimizedRegion>, super::RegionError> {
    use super::RegionError;
    if instructions.len() > super::MAX_INSTRUCTIONS {
        return Err(RegionError::TooLong);
    }
    let Some(entry) = instructions.first().map(|instruction| instruction.pc) else {
        return Ok(None);
    };
    if entry.0 & 3 != 0 {
        return Err(RegionError::Misaligned);
    }
    let analyzed: Vec<_> = instructions
        .iter()
        .map_while(|instruction| flags::analyze_value(&instruction.operation))
        .collect();
    if analyzed.len() < 2 {
        return Ok(None);
    }
    let mut has_flags = false;
    for (index, instruction) in instructions.iter().take(analyzed.len()).enumerate() {
        let expected = entry
            .0
            .checked_add((index as u64) * u64::from(core::mem::size_of::<u32>() as u32))
            .ok_or(RegionError::AddressOverflow)?;
        if instruction.pc.0 != expected {
            return Err(RegionError::NonContiguous);
        }
        has_flags |= !matches!(analyzed[index].2, flags::ValueStep::Ordinary);
    }
    let exit = entry
        .0
        .checked_add((analyzed.len() as u64) * core::mem::size_of::<u32>() as u64)
        .ok_or(RegionError::AddressOverflow)?;
    if instructions
        .get(analyzed.len())
        .is_some_and(|instruction| instruction.pc.0 != exit)
    {
        return Err(RegionError::NonContiguous);
    }
    let gprs: Vec<_> = analyzed.iter().map(|(gprs, _, _)| *gprs).collect();
    let values: Vec<_> = analyzed.iter().map(|(_, values, _)| *values).collect();
    let live = LiveRanges::compute(&values);
    let killed = values
        .iter()
        .enumerate()
        .any(|(index, effect)| effect.writes & !live.after(index) != 0);
    let participants = gprs
        .iter()
        .fold(0, |mask, effect| mask | effect.reads | effect.writes);
    // Do not split an existing ALU plus clean-load chunk only to try a larger
    // pool. Spans with flags or dead versions add work; other plain spans need
    // register pressure and must end before the existing terminal.
    if !has_flags
        && !killed
        && (analyzed.len() != instructions.len()
            || participants.count_ones() as usize <= POOL.len())
    {
        return Ok(None);
    }
    let mut best: Option<super::OptimizedRegion> = None;
    for callee_slots in 0..=CALLEE_POOL.len() {
        let plan = Plan::new(values.clone(), callee_slots, false);
        let mut emitter = emitter(&gprs, plan, entry);
        emitter.borrow_callees();
        for (instruction, (_, _, step)) in instructions.iter().zip(&analyzed) {
            emitter.value_instruction(instruction, *step)?;
            emitter.current += 1;
        }
        emitter.settle_value_flags();
        for index in 0..encoding::ALLOCATABLE_SLOTS {
            emitter.spill_value(index, true);
        }
        emitter.restore_callees();
        if let Some((_, offset)) = emitter.output.source_map.first_mut() {
            *offset = 0;
        }
        let Some(count) = super::analysis::allocated_output_instruction_count(&emitter.output.code)
        else {
            continue;
        };
        emitter.output.stats.native_instructions = count;
        // A callee pool is useful only when its complete emitted recipe wins.
        // Ties keep the earlier, smaller pool and its cheaper native ABI setup.
        if best.as_ref().is_none_or(|best| {
            (emitter.output.code.len(), count) < (best.code.len(), best.stats.native_instructions)
        }) {
            best = Some(emitter.output);
        }
    }
    Ok(best)
}

impl Emitter<'_> {
    /// Load only the loop inputs that are read before they are defined. Other
    /// values follow the ordinary demand and pressure policy.
    pub(super) fn preload_loop_inputs(&mut self) -> Vec<(Value, HostGpr)> {
        let plan = self.allocation.as_ref().unwrap();
        let inputs = plan.live.inputs();
        let modified = plan
            .effects
            .iter()
            .fold(0, |mask, effect| mask | effect.writes);
        let available: Vec<_> = (0..POOL.len() + plan.callee_slots)
            .filter(|&index| self.reserved_hosts & encoding::pool_host(index).mask() == 0)
            .collect();
        let mut header = vec![];
        for (value, index) in (0..GPR_SLOTS)
            .filter_map(Value::gpr)
            .filter(|value| inputs & value.mask() != 0)
            .zip(available)
        {
            let host = encoding::pool_host(index);
            self.emit(|code| encoding::load(code, host, value.slot()));
            self.resident[index] = Some(Resident {
                guest: value.slot(),
                // This header also describes later iterations, whose previous
                // writes may leave the backing frame stale. A carried modified
                // value must survive pressure even before this iteration writes it.
                dirty: modified & value.mask() != 0,
            });
            self.locations[value.slot()] = super::Location::Host(host);
            self.output.stats.state_loads += 1;
            header.push((value, host));
        }
        header
    }

    pub(super) fn reconcile_loop_inputs(&mut self, header: &[(Value, HostGpr)]) {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Source {
            Host(HostGpr),
            Frame(Value),
        }
        let inputs = self.allocation.as_ref().unwrap().live.inputs();
        let overflow: Vec<_> = self
            .resident
            .iter()
            .enumerate()
            .filter_map(|(index, resident)| {
                let resident = (*resident)?;
                let value = Value::resident(resident.guest);
                (resident.dirty
                    && inputs & value.mask() != 0
                    && !header.iter().any(|(assigned, _)| *assigned == value))
                .then_some((encoding::pool_host(index), value))
            })
            .collect();
        // Header inputs beyond the host registers need backing stores before a
        // parallel move can overwrite their resident source.
        for (host, value) in overflow {
            self.emit(|code| encoding::store(code, host, value.slot()));
            self.output.stats.pressure_stores += 1;
        }
        let mut transfers: Vec<_> = header
            .iter()
            .filter_map(|&(value, destination)| {
                let source = self
                    .value_index(value)
                    .map_or(Source::Frame(value), |index| {
                        Source::Host(encoding::pool_host(index))
                    });
                (source != Source::Host(destination)).then_some((destination, source))
            })
            .collect();
        while !transfers.is_empty() {
            if let Some(index) = transfers.iter().position(|(destination, _)| {
                !transfers
                    .iter()
                    .any(|(_, source)| *source == Source::Host(*destination))
            }) {
                let (destination, source) = transfers.remove(index);
                match source {
                    Source::Host(source) => {
                        self.emit(|code| encoding::copy(code, destination, source, Width::X64))
                    }
                    Source::Frame(value) => {
                        self.emit(|code| encoding::load(code, destination, value.slot()));
                        self.output.stats.state_loads += 1;
                    }
                }
            } else {
                // Break one physical-register cycle without a guest-frame or
                // host-stack temporary. RESULT is excluded from the cache pool.
                let saved = transfers[0].0;
                self.emit(|code| encoding::copy(code, RESULT, saved, Width::X64));
                for (_, source) in &mut transfers {
                    if *source == Source::Host(saved) {
                        *source = Source::Host(RESULT);
                    }
                }
            }
        }
    }
}
