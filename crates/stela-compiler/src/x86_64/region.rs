//! Multi-instruction scalar regions that keep guest values in host registers and
//! settle the full register bank at every exit.
use super::memory_recipe::{
    self, Kind as MemoryKind, Recipe as MemoryRecipe, Segment as MemorySegment,
};
use crate::x86_64::asm::{Code, Gpr};
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
const HALFWORD_LOAD_BYTES: u8 = 2;
const WORD_LOAD_BYTES: u8 = 4;
const DOUBLEWORD_LOAD_BYTES: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionError {
    TooLong,
    Misaligned,
    NonContiguous,
    AddressOverflow,
    ChangedMemoryEncoding,
    ChangedInstructions,
}

impl core::fmt::Display for RegionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::TooLong => "region input exceeds the instruction limit",
            Self::Misaligned => "region instruction address is misaligned",
            Self::NonContiguous => "region instructions are not contiguous",
            Self::AddressOverflow => "region guest address overflows",
            Self::ChangedMemoryEncoding => "region memory encoding differs from its analyzed form",
            Self::ChangedInstructions => "region instructions differ from the analyzed input",
        })
    }
}
impl core::error::Error for RegionError {}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AllocationStats {
    pub state_loads: usize,
    pub in_place_source_uses: usize,
    pub nzcv_pressure_stores: usize,
    pub nzcv_boundary_stores: usize,
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
    /// Stores and store pairs.
    pub stores: usize,
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
    pub code: Code,
    pub consumed_instructions: usize,
    pub source_map: Vec<(GuestAddress, usize)>,
    pub stats: AllocationStats,
    /// Offsets in `code`; empty unless emitted with a fault table.
    pub fault_recovery: Vec<crate::block::FaultRecovery>,
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
    /// The block's checks: SCTLR_ELx.SA, whether a clean load through SP
    /// checks its alignment ([`super::MemoryChecks::stack_alignment`]), and
    /// the guest range check's placement and variant.
    checks: super::MemoryChecks,
    /// The engine recovers dirty values from host registers at a fault
    /// ([`crate::block::FaultRecovery`]), so accesses need not settle.
    fault_table: bool,
}

impl Emitter<'_> {
    fn emit(&mut self, encode: impl FnOnce(&mut Code)) {
        let start = self.output.code.len();
        let instructions = self.output.code.instructions();
        encode(&mut self.output.code);
        let end = self.output.code.len();
        debug_assert!(end > start);
        // Value allocation tracks versions, not per-instruction locations.
        debug_assert!(self.allocation.is_some() || location::valid(&self.locations));
        self.output.stats.native_instructions += self.output.code.instructions() - instructions;
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
        self.output.stats.in_place_source_uses += 1;
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

    /// A store whose shared recipe is one host store per element
    /// ([`analysis::clean_access_effects`]), or for an H/W/X store the
    /// emitter cannot prove within a page, its page-crossing split, which
    /// overwrites R10 and on the crossing path shifts RCX. Every dirty value
    /// settles first, or is in the fault table, so a fault finds the frame
    /// exact. A resident base or data value supplies its register without a
    /// frame reload; a data value staged from the frame stays in RCX (R8
    /// for a pair's second element) as a clean copy, unless split.
    fn clean_store(
        &mut self,
        bytes: u8,
        data: &[Register],
        base: Register,
        displacement: i32,
        mode: AddressMode,
    ) -> Result<(), RegionError> {
        const STAGING: [HostGpr; 2] = [HostGpr::Rcx, HostGpr::R8];
        // As `memory` selects `memory_store::emit`'s fast path.
        let crossing = data.len() == 1
            && bytes != BYTE_LOAD_BYTES
            && !(self.checks.stack_alignment
                && super::memory_store::aligned_immediate(base, displacement, mode, bytes));
        let (raw, recipe) = if let &[first, second] = data {
            memory_recipe::pair_recipe(
                self.memory_checks(),
                memory_recipe::Pair {
                    transfer: MemoryTransfer::Store,
                    bytes,
                    data: [first, second],
                    address: crate::x86_64::ImmediateAddress {
                        base,
                        displacement,
                        mode,
                    },
                },
            )
        } else {
            memory_recipe::scalar_recipe(
                self.memory_checks(),
                memory_recipe::Scalar {
                    transfer: MemoryTransfer::Store,
                    bytes,
                    data: data[0],
                    address: crate::x86_64::ImmediateAddress {
                        base,
                        displacement,
                        mode,
                    },
                },
            )
        };
        if !recipe.complete(&raw)
            || data.iter().enumerate().any(|(index, _)| {
                recipe.stage(index) != Some(if index == 0 { Gpr::Rcx } else { Gpr::R8 })
            })
        {
            return Err(RegionError::ChangedMemoryEncoding);
        }
        let cached_base = self.cached(base);
        // The guest range check and the first element overwrite RCX, and
        // the second element R8, before a staged value would be read: a
        // value there is read from its frame slot, which the access's
        // preparation writes when it is dirty. Any other register holding
        // an element is copied, as with a fault table it may hold a value
        // the frame does not yet have.
        let clobbers = recipe.clobbers();
        let cached_data: Vec<Option<HostGpr>> = data
            .iter()
            .map(|&register| {
                self.cached(register)
                    .filter(|host| clobbers & host.mask() == 0)
            })
            .collect();
        let live = self.prepare_access(clobbers, &[]);
        // The base keeps out of the registers the access overwrites.
        self.pinned_hosts |= clobbers;
        let access_start = self.output.code.len();
        self.access_address(base, displacement, &raw, &recipe, cached_base);
        for segment in recipe.body() {
            if let MemoryKind::Stage { element, .. } = segment.kind
                && let Some(host) = cached_data[element]
            {
                self.emit(|code| encoding::copy(code, STAGING[element], host, Width::X64));
            } else {
                self.emit_recipe_segment(&raw, segment);
            }
        }
        self.finish_access(access_start, live, &[]);
        for (index, &register) in data.iter().enumerate() {
            if !crossing
                && cached_data[index].is_none()
                && !data[..index].contains(&register)
                && slot(register).is_some_and(|guest| {
                    !self
                        .resident
                        .iter()
                        .any(|value| value.is_some_and(|value| value.guest == guest))
                })
            {
                self.retain_clean_result(register, STAGING[index]);
            }
        }
        self.output.stats.stores += 1;
        self.output.stats.commits += 1;
        Ok(())
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
        let (raw, recipe) = memory_recipe::scalar_recipe(
            self.memory_checks(),
            memory_recipe::Scalar {
                transfer,
                bytes,
                data,
                address: crate::x86_64::ImmediateAddress {
                    base,
                    displacement,
                    mode,
                },
            },
        );
        if !recipe.complete(&raw) || recipe.result(0) != Some(Gpr::Rcx) {
            return Err(RegionError::ChangedMemoryEncoding);
        }
        let cached_base = self.cached(base);
        let live = self.prepare_access(recipe.clobbers(), &[data]);
        let start = self.output.code.len();
        self.access_address(base, displacement, &raw, &recipe, cached_base);
        for segment in recipe.body() {
            self.emit_recipe_segment(&raw, segment);
        }
        self.finish_access(start, live, &[data]);
        self.retain_clean_result(data, HostGpr::Rcx);
        self.output.stats.clean_loads += 1;
        self.output.stats.commits += 1;
        Ok(())
    }

    /// Replace only the shared base/check/offset prefix when a guest base
    /// already lives in a host register. All remaining semantic spans are copied.
    fn access_address(
        &mut self,
        base: Register,
        displacement: i32,
        raw: &Code,
        recipe: &MemoryRecipe,
        cached: Option<HostGpr>,
    ) {
        let guest = slot(base).expect("eligible base");
        let free = POOL
            .iter()
            .any(|host| (self.reserved_hosts | self.pinned_hosts) & host.mask() == 0);
        let host = cached.or_else(|| {
            (free
                && self.effects[self.current].writes & (1 << guest) == 0
                && next_use(self.effects, self.current + 1, guest) != usize::MAX)
                .then(|| {
                    let host = POOL[self.allocate(guest)];
                    self.emit(|code| encoding::load(code, host, guest));
                    self.locations[guest] = Location::Host(host);
                    self.output.stats.state_loads += 1;
                    self.output.stats.input_cache_loads += 1;
                    host
                })
        });
        if let Some(host) = host {
            if recipe.checked_sp() {
                self.emit(|code| {
                    super::stack_alignment_check_register(
                        code,
                        crate::x86_64::simd::encode::gpr(host as u8),
                    )
                });
            }
            self.emit(|code| encoding::lea(code, HostGpr::Rax, host, displacement));
            self.output.stats.address_cache_hits += 1;
        } else {
            for segment in recipe.address_prefix() {
                self.emit_recipe_segment(raw, segment);
            }
        }
    }

    fn emit_recipe_segment(&mut self, raw: &Code, segment: &MemorySegment) {
        self.emit(|code| code.append_span(raw, segment.span));
    }

    /// The checks of the shared memory emitter whose bytes the current
    /// clean load reuses: the block's SP alignment check and the access's
    /// guest range check. Regions are never selected under SCTLR_ELx.A, and
    /// clean loads are never ordered.
    fn memory_checks(&self) -> super::MemoryChecks {
        super::MemoryChecks {
            stack_alignment: self.checks.stack_alignment,
            guest_range: self
                .range_checks
                .is_some_and(|ranges| ranges.get(self.current).copied().unwrap_or(true)),
            range: self.checks.range,
            translated: self.checks.translated,
            translation_helper: self.checks.translation_helper,
            ..super::MemoryChecks::DEFAULT
        }
    }

    /// Before a faultable access whose host clobbers are `clobbers`: settle
    /// the frame, or, with a fault table, write back only the dirty values
    /// in clobbered registers and return where every other dirty value
    /// lives, pinned until the access is emitted. Clobbered residents are
    /// dropped, and those of `destinations`: without a table now, with one
    /// after the access ([`Self::finish_access`]), as their old values are
    /// the architectural ones if it faults.
    fn prepare_access(&mut self, clobbers: u16, destinations: &[Register]) -> Vec<(u8, u8)> {
        if !self.fault_table {
            self.settle_before_load(clobbers, destinations);
            return vec![];
        }
        let mut live = vec![];
        for (index, host) in POOL.iter().copied().enumerate() {
            let Some(resident) = self.resident[index] else {
                continue;
            };
            if clobbers & host.mask() != 0 {
                if resident.dirty {
                    self.emit(|code| encoding::store(code, host, resident.guest));
                    self.output.stats.load_boundary_stores += 1;
                }
                self.locations[resident.guest] = FRAME_LOCATIONS[resident.guest];
                self.resident[index] = None;
            } else if resident.dirty {
                live.push((resident.guest as u8, host as u8));
                self.pinned_hosts |= host.mask();
            }
        }
        live
    }

    /// After an access emitted from code offset `start`, with a fault
    /// table: record where `live` values are during it, and drop the
    /// residents of `destinations`, whose new values it committed to their
    /// frame slots.
    fn finish_access(&mut self, start: usize, live: Vec<(u8, u8)>, destinations: &[Register]) {
        if !self.fault_table {
            return;
        }
        if !live.is_empty() {
            self.output
                .fault_recovery
                .push(crate::block::FaultRecovery {
                    start,
                    end: self.output.code.len(),
                    registers: live,
                });
        }
        for index in 0..POOL.len() {
            if let Some(resident) = self.resident[index]
                && destinations
                    .iter()
                    .any(|&data| slot(data) == Some(resident.guest))
            {
                self.locations[resident.guest] = FRAME_LOCATIONS[resident.guest];
                self.resident[index] = None;
            }
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
        let (raw, recipe) = memory_recipe::pair_recipe(
            self.memory_checks(),
            memory_recipe::Pair {
                transfer,
                bytes,
                data,
                address: crate::x86_64::ImmediateAddress {
                    base,
                    displacement,
                    mode,
                },
            },
        );
        if !recipe.complete(&raw)
            || [recipe.result(0), recipe.result(1)] != [Some(Gpr::Rcx), Some(Gpr::R8)]
        {
            return Err(RegionError::ChangedMemoryEncoding);
        }
        let cached_base = self.cached(base);
        let live = self.prepare_access(recipe.clobbers(), &data);
        let start = self.output.code.len();
        self.access_address(base, displacement, &raw, &recipe, cached_base);
        for segment in recipe.body() {
            self.emit_recipe_segment(&raw, segment);
        }
        self.finish_access(start, live, &data);
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
                transfer: MemoryTransfer::Store,
                bytes,
                data,
                base,
                displacement,
                mode,
            } => {
                self.clean_store(bytes, &[data], base, displacement, mode)?;
            }
            Operation::MemoryPair {
                transfer: MemoryTransfer::Store,
                bytes,
                data,
                base,
                displacement,
                mode,
            } => {
                self.clean_store(bytes, &data, base, displacement, mode)?;
            }
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
    emit_prefix_selected(
        instructions,
        false,
        super::MemoryChecks::DEFAULT,
        false,
        None,
    )
}

/// Transactional nonfaulting GPR/NZCV span candidate.
pub fn emit_allocated_prefix(
    instructions: &[Instruction],
) -> Result<Option<OptimizedRegion>, RegionError> {
    allocation::prefix(instructions)
}

/// Register retention without direct guest memory or recovery-table emission.
/// Checked callers settle this complete span before any service boundary.
pub(crate) fn emit_register_prefix(
    instructions: &[Instruction],
) -> Result<OptimizedRegion, RegionError> {
    emit_prefix_selected(
        instructions,
        false,
        super::MemoryChecks::DEFAULT,
        false,
        None,
    )
}

/// Ordinary direct-RAM load retention; pure ALU allocation keeps six slots.
/// Loads through SP check its alignment if `stack_alignment` (the block's
/// [`super::MemoryChecks::stack_alignment`]). With `range_checks`, the loads
/// the system-mode analysis selects check their address
/// ([`super::RangeCheck`]).
#[cfg(test)]
pub fn emit_clean_load_prefix<'a>(
    instructions: &'a [Instruction],
    stack_alignment: bool,
    range_checks: Option<&'a [bool]>,
) -> Result<OptimizedRegion, RegionError> {
    let checks = super::MemoryChecks {
        stack_alignment,
        ..super::MemoryChecks::DEFAULT
    };
    emit_prefix_selected(instructions, true, checks, false, range_checks)
}

/// [`emit_clean_load_prefix`] for a block's `checks`, and with
/// `fault_table` its accesses keep dirty values in registers and
/// [`OptimizedRegion::fault_recovery`] says where, for an engine that
/// applies it at a fault.
pub fn emit_clean_load_prefix_with<'a>(
    instructions: &'a [Instruction],
    checks: super::MemoryChecks,
    fault_table: bool,
    range_checks: Option<&'a [bool]>,
) -> Result<OptimizedRegion, RegionError> {
    emit_prefix_selected(instructions, true, checks, fault_table, range_checks)
}

fn emit_prefix_selected<'a>(
    instructions: &'a [Instruction],
    clean_loads: bool,
    checks: super::MemoryChecks,
    fault_table: bool,
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
        analysis::prefix_clean_access_effects(instructions, checks.stack_alignment)
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
            code: Code::new(),
            consumed_instructions: consumed,
            source_map: vec![],
            stats: AllocationStats::default(),
            fault_recovery: vec![],
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
        checks,
        fault_table,
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
pub fn admits_allocated(region: &OptimizedRegion, baseline_code: &Code) -> bool {
    region.consumed_instructions >= 2
        && region.code.len() < baseline_code.len()
        && region.stats.native_instructions <= baseline_code.instructions()
}

pub fn admits_ordinary(region: &OptimizedRegion, baseline_code: &Code) -> bool {
    region.consumed_instructions >= 2
        && region.code.len() < baseline_code.len()
        && region.stats.native_instructions <= baseline_code.instructions()
}

#[cfg(test)]
mod tests {
    mod recipes;
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
        assert_eq!(result.code.instructions(), result.stats.native_instructions);
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
        let output = emit_clean_load_prefix(&instructions, true, None).unwrap();
        assert_eq!(output.consumed_instructions, 5);
        assert_eq!(output.stats.clean_loads, 1);
        assert_eq!(output.stats.load_boundary_stores, 2);
        assert_eq!(emit_prefix(&instructions).unwrap().consumed_instructions, 2);
    }

    /// With the system-mode guest range check, clean loads keep the same
    /// shape and check each address once, after the frame is settled.
    #[test]
    fn clean_loads_check_the_guest_range_when_asked() {
        let check = super::super::RangeCheck::FIVE_LEVEL.code();
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
            code.windows(check.len())
                .filter(|bytes| *bytes == check)
                .count()
        };
        let unchecked = emit_clean_load_prefix(&instructions, true, None).unwrap();
        let checked = emit_clean_load_prefix(&instructions, true, Some(&[true; 5])).unwrap();
        assert_eq!(checks(&unchecked.code), 0);
        assert_eq!(checks(&checked.code), 3);
        // Each load takes its own instruction's decision.
        let second =
            emit_clean_load_prefix(&instructions, true, Some(&[true, false, true, false, true]))
                .unwrap();
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
        assert_eq!(checked.code.len(), unchecked.code.len() + 3 * check.len());
        // The cost gate counts each check's six instructions on both sides.
        let mut baseline = Code::new();
        for instruction in &instructions {
            super::super::emit_instruction(
                &mut baseline,
                instruction,
                &mut vec![],
                crate::TargetCpu::Baseline,
                super::super::MemoryChecks {
                    guest_range: true,
                    ..super::super::MemoryChecks::DEFAULT
                },
            );
        }
        let count = baseline.instructions();
        assert_eq!(
            checked.stats.native_instructions,
            unchecked.stats.native_instructions
                + 3 * super::super::RangeCheck::at(&check).unwrap().1.len()
        );
        assert!(checked.stats.native_instructions <= count);
        assert!(admits_ordinary(&checked, &baseline));
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
            true,
            None,
        )
        .unwrap();
        assert_eq!(output.stats.load_boundary_stores, 1);
    }

    #[test]
    fn clean_load_tier_declines_unselected_memory_forms() {
        for (base, signed, width, bytes, mode) in [
            (Register::Sp, false, Width::W32, 1, AddressMode::PreIndex),
            (Register::X(0), true, Width::W32, 1, AddressMode::Offset),
            (Register::X(0), false, Width::X64, 1, AddressMode::Offset),
            (Register::X(0), false, Width::W32, 8, AddressMode::Offset),
            (Register::X(0), true, Width::X64, 4, AddressMode::Offset),
            (Register::X(0), false, Width::W32, 1, AddressMode::PostIndex),
            (Register::X(0), false, Width::X64, 8, AddressMode::PreIndex),
            (Register::Sp, true, Width::X64, 4, AddressMode::Offset),
            (Register::Zero, false, Width::X64, 8, AddressMode::Offset),
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
        let mut raw = Code::new();
        super::super::memory(
            &mut raw,
            super::super::MemoryChecks::DEFAULT,
            MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            1,
            Register::X(16),
            crate::x86_64::ImmediateAddress {
                base: Register::X(15),
                displacement: -255,
                mode: AddressMode::Offset,
            },
        );
        assert_eq!(
            recipes::ordinary_load_ends(&raw, 1, 15, Some(16), -255),
            Some(vec![7, 14, 17, 24])
        );
        for index in 0..raw.len() {
            let mut mutated = raw.as_slice().to_vec();
            mutated[index] ^= 1;
            assert!(recipes::ordinary_load_ends(&mutated, 1, 15, Some(16), -255).is_none());
        }
        let mut raw = raw.into_bytes();
        raw.push(0x90);
        assert!(recipes::ordinary_load_ends(&raw, 1, 15, Some(16), -255).is_none());
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
            let region = emit_clean_load_prefix(&instructions, true, None).unwrap();
            assert_eq!(region.consumed_instructions, instructions.len());
            assert_eq!(region.stats.clean_loads, 1);
            assert_eq!(region.stats.load_boundary_stores, 1);
            assert!(region.code.windows(2).any(|bytes| bytes == [0x8b, 0x08]));
        }
    }

    #[test]
    fn shared_load_recipes_reject_any_clobber_or_offset_change() {
        let sizes = [
            (Width::W32, HALFWORD_LOAD_BYTES),
            (Width::W32, WORD_LOAD_BYTES),
            (Width::X64, DOUBLEWORD_LOAD_BYTES),
        ];
        for (width, bytes) in sizes {
            for data in [Register::X(16), Register::Zero] {
                let mut raw = Code::new();
                super::super::memory(
                    &mut raw,
                    super::super::MemoryChecks::DEFAULT,
                    MemoryTransfer::Load {
                        signed: false,
                        width,
                    },
                    bytes,
                    data,
                    crate::x86_64::ImmediateAddress {
                        base: Register::X(15),
                        displacement: -255,
                        mode: AddressMode::Offset,
                    },
                );
                let selected = slot(data);
                let ends = recipes::ordinary_load_ends(&raw, bytes, 15, selected, -255).unwrap();
                assert_eq!(ends.last(), Some(&raw.len()));
                for index in 0..raw.len() {
                    let mut mutated = raw.as_slice().to_vec();
                    mutated[index] ^= 1;
                    assert!(
                        recipes::ordinary_load_ends(&mutated, bytes, 15, selected, -255).is_none()
                    );
                }
                for other in [BYTE_LOAD_BYTES, HALFWORD_LOAD_BYTES, WORD_LOAD_BYTES]
                    .into_iter()
                    .chain([DOUBLEWORD_LOAD_BYTES])
                    .filter(|&other| other != bytes)
                {
                    assert!(recipes::ordinary_load_ends(&raw, other, 15, selected, -255).is_none());
                }
            }
        }
    }

    /// A doubleword load keeps its full 64-bit result resident in RCX, and
    /// the cost gate counts the shared REX.W load it splices.
    #[test]
    fn doubleword_loads_stay_resident_and_pass_the_cost_gate() {
        let load = |pc, data, base, displacement| {
            instruction(
                pc,
                Operation::Memory {
                    transfer: MemoryTransfer::Load {
                        signed: false,
                        width: Width::X64,
                    },
                    bytes: DOUBLEWORD_LOAD_BYTES,
                    data,
                    base,
                    displacement,
                    mode: AddressMode::Offset,
                },
            )
        };
        // ldr x8,[x0,#16]; ldr x9,[x8,#8]; add x9,x9,x9; add x8,x8,x8
        let instructions = [
            load(0, Register::X(8), Register::X(0), 16),
            load(1, Register::X(9), Register::X(8), 8),
            instruction(2, add(Register::X(9), Register::X(9))),
            instruction(3, add(Register::X(8), Register::X(8))),
        ];
        let region = emit_clean_load_prefix(&instructions, true, None).unwrap();
        assert_eq!(region.consumed_instructions, instructions.len());
        assert_eq!(region.stats.clean_loads, 2);
        assert_eq!(region.stats.address_cache_hits, 1);
        assert!(
            region
                .code
                .windows(3)
                .any(|bytes| bytes == [0x48, 0x8b, 0x08])
        );
        let mut baseline = Code::new();
        for instruction in &instructions {
            super::super::emit_instruction(
                &mut baseline,
                instruction,
                &mut vec![],
                crate::TargetCpu::Baseline,
                super::super::MemoryChecks::DEFAULT,
            );
        }
        assert!(baseline.instructions() > 0);
        assert!(admits_ordinary(&region, &baseline));
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
        let region = emit_clean_load_prefix(&source, true, None).unwrap();
        assert_eq!(region.consumed_instructions, source.len());
        assert_eq!(region.stats.pair_loads, 1);
        let mut raw = Code::new();
        super::super::memory_pair(
            &mut raw,
            super::super::MemoryChecks::DEFAULT,
            MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            WORD_LOAD_BYTES,
            data,
            crate::x86_64::ImmediateAddress {
                base: Register::X(15),
                displacement: -8,
                mode: AddressMode::Offset,
            },
        );
        let ends = |raw: &[u8], bytes, base, data| {
            recipes::ordinary_pair_load_ends(raw, bytes, base, data, -8)
        };
        assert!(ends(&raw, WORD_LOAD_BYTES, 15, [Some(16), Some(17)]).is_some());
        assert!(ends(&raw, WORD_LOAD_BYTES, 15, [Some(16), Some(16)]).is_none());
        assert!(ends(&raw, DOUBLEWORD_LOAD_BYTES, 15, [Some(16), Some(17)]).is_none());
        for (width, bytes) in [
            (Width::W32, WORD_LOAD_BYTES),
            (Width::X64, DOUBLEWORD_LOAD_BYTES),
        ] {
            for (base, stack_alignment) in [
                (Register::X(15), true),
                (Register::Sp, true),
                (Register::Sp, false),
            ] {
                let mut raw = Code::new();
                super::super::memory_pair(
                    &mut raw,
                    super::super::MemoryChecks::system(stack_alignment, false, true, false),
                    MemoryTransfer::Load {
                        signed: false,
                        width,
                    },
                    bytes,
                    data,
                    crate::x86_64::ImmediateAddress {
                        base,
                        displacement: -8,
                        mode: AddressMode::Offset,
                    },
                );
                let base = slot(base).unwrap();
                assert!(ends(&raw, bytes, base, [Some(16), Some(17)]).is_some());
                for index in 0..raw.len() {
                    let mut changed = raw.as_slice().to_vec();
                    changed[index] ^= 1;
                    assert!(ends(&changed, bytes, base, [Some(16), Some(17)]).is_none());
                }
            }
        }
    }

    /// Loads and pairs through SP carry exactly the block's SP alignment
    /// check, before the address addition, and a resident SP supplies the
    /// base.
    #[test]
    fn stack_pointer_loads_carry_the_blocks_alignment_check() {
        // sub sp,sp,#32; ldr x8,[sp,#8]; ldp x9,x10,[sp,#16];
        // add x8,x8,#1; add x9,x9,#1; add x10,x10,#1
        let instructions = [
            instruction(
                0,
                Operation::AddSub {
                    width: Width::X64,
                    subtract: true,
                    flags: false,
                    destination: Register::Sp,
                    source: Register::Sp,
                    immediate: 32,
                },
            ),
            instruction(
                1,
                Operation::Memory {
                    transfer: MemoryTransfer::Load {
                        signed: false,
                        width: Width::X64,
                    },
                    bytes: DOUBLEWORD_LOAD_BYTES,
                    data: Register::X(8),
                    base: Register::Sp,
                    displacement: 8,
                    mode: AddressMode::Offset,
                },
            ),
            instruction(
                2,
                Operation::MemoryPair {
                    transfer: MemoryTransfer::Load {
                        signed: false,
                        width: Width::X64,
                    },
                    bytes: DOUBLEWORD_LOAD_BYTES,
                    data: [Register::X(9), Register::X(10)],
                    base: Register::Sp,
                    displacement: 16,
                    mode: AddressMode::Offset,
                },
            ),
            instruction(3, add(Register::X(8), Register::X(8))),
            instruction(4, add(Register::X(9), Register::X(9))),
            instruction(5, add(Register::X(10), Register::X(10))),
        ];
        // The resident SP's own low byte is tested, then the shared JZ and
        // UD2 of `STACK_ALIGNMENT_CHECK`.
        let check = &super::super::STACK_ALIGNMENT_CHECK[2..];
        for stack_alignment in [true, false] {
            let region = emit_clean_load_prefix(&instructions, stack_alignment, None).unwrap();
            assert_eq!(region.consumed_instructions, instructions.len());
            assert_eq!(region.stats.clean_loads, 1);
            assert_eq!(region.stats.pair_loads, 1);
            assert_eq!(region.stats.address_cache_hits, 2);
            let checks = region
                .code
                .windows(check.len())
                .filter(|bytes| *bytes == check)
                .count();
            assert_eq!(checks, if stack_alignment { 2 } else { 0 });
            let mut baseline = Code::new();
            for instruction in &instructions {
                super::super::emit_instruction(
                    &mut baseline,
                    instruction,
                    &mut vec![],
                    crate::TargetCpu::Baseline,
                    super::super::MemoryChecks::system(stack_alignment, false, true, false),
                );
            }
            assert!(baseline.instructions() > 0);
            assert!(admits_ordinary(&region, &baseline));
        }
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
        for (width, bytes, base) in [
            (Width::X64, DOUBLEWORD_LOAD_BYTES, Register::X(2)),
            (Width::W32, WORD_LOAD_BYTES, Register::Sp),
            (Width::X64, DOUBLEWORD_LOAD_BYTES, Register::Sp),
        ] {
            let Operation::MemoryPair { displacement, .. } = selected else {
                unreachable!()
            };
            assert!(
                analysis::clean_load_effects(&Operation::MemoryPair {
                    transfer: MemoryTransfer::Load {
                        signed: false,
                        width
                    },
                    bytes,
                    data: [Register::X(0), Register::X(1)],
                    base,
                    displacement,
                    mode: AddressMode::Offset,
                })
                .is_some()
            );
        }
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
                DOUBLEWORD_LOAD_BYTES,
                [Register::X(0), Register::X(1)],
                Register::Sp,
                AddressMode::PreIndex,
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
                [Register::X(0), Register::Sp],
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

    /// With a fault table, a dirty value stays in its register across a
    /// load and a store, whose entries name it over their code; a load's
    /// destination leaves the table once the load commits it.
    #[test]
    fn fault_tables_keep_dirty_values_across_accesses() {
        let load = |data, base| Operation::Memory {
            transfer: MemoryTransfer::Load {
                signed: false,
                width: Width::X64,
            },
            bytes: DOUBLEWORD_LOAD_BYTES,
            data,
            base,
            displacement: 8,
            mode: AddressMode::Offset,
        };
        // add x9,x9,#1; ldr x12,[x1,#8]; add x9,x9,#1; add x10,x11,#1;
        // ldr x10,[x10,#8]; strb w9,[x2,#8]
        let instructions = [
            instruction(0, add(Register::X(9), Register::X(9))),
            instruction(1, load(Register::X(12), Register::X(1))),
            instruction(2, add(Register::X(9), Register::X(9))),
            instruction(3, add(Register::X(10), Register::X(11))),
            instruction(4, load(Register::X(10), Register::X(10))),
            instruction(5, store(BYTE_LOAD_BYTES, Register::X(9), Register::X(2), 8)),
        ];
        let settled = emit_clean_load_prefix_with(
            &instructions,
            super::super::MemoryChecks::DEFAULT,
            false,
            None,
        )
        .unwrap();
        assert!(settled.fault_recovery.is_empty());
        assert!(settled.stats.load_boundary_stores >= 2);
        let region = emit_clean_load_prefix_with(
            &instructions,
            super::super::MemoryChecks::DEFAULT,
            true,
            None,
        )
        .unwrap();
        assert_eq!(region.consumed_instructions, instructions.len());
        assert_eq!(region.stats.load_boundary_stores, 0);
        assert!(region.code.len() < settled.code.len());
        let guests = |entry: &crate::block::FaultRecovery| {
            let mut guests: Vec<u8> = entry.registers.iter().map(|&(guest, _)| guest).collect();
            guests.sort_unstable();
            guests
        };
        let entries = &region.fault_recovery;
        assert_eq!(entries.len(), 3);
        // X9 across the first load; X9 and the changed X10, the second's
        // base and destination, whose old value a fault keeps, across the
        // second; X9 across the store.
        assert_eq!(guests(&entries[0]), [9]);
        assert_eq!(guests(&entries[1]), [9, 10]);
        assert_eq!(guests(&entries[2]), [9]);
        for pair in entries.windows(2) {
            assert!(pair[0].end <= pair[1].start);
        }
        for entry in entries {
            assert!(entry.start < entry.end && entry.end <= region.code.len());
            for &(_, host) in &entry.registers {
                assert!(POOL.iter().any(|pool| *pool as u8 == host));
                // The access clobbers RCX, so nothing live stays there.
                assert_ne!(host, HostGpr::Rcx as u8);
            }
        }
    }

    /// An X-base doubleword store keeps the shared page-crossing recipe:
    /// the value in R10, which it overwrites, is written back first and
    /// named by no fault table entry, and the data staged in RCX, which its
    /// crossing path shifts, is not kept as a copy.
    #[test]
    fn crossing_stores_keep_the_shared_split() {
        let mut instructions: Vec<_> = (3..8u8)
            .map(|guest| {
                instruction(
                    u64::from(guest - 3),
                    add(Register::X(guest), Register::X(guest)),
                )
            })
            .collect();
        instructions.push(instruction(
            5,
            store(DOUBLEWORD_LOAD_BYTES, Register::X(12), Register::X(2), 3),
        ));
        instructions.push(instruction(6, add(Register::X(13), Register::X(12))));
        for guest in 3..8u8 {
            let index = instructions.len() as u64;
            instructions.push(instruction(
                index,
                add(Register::X(guest), Register::X(guest)),
            ));
        }
        let (recipe, _) =
            super::super::memory_store::crossing_store(DOUBLEWORD_LOAD_BYTES).unwrap();
        let contains = |code: &[u8], bytes: &[u8]| code.windows(bytes.len()).any(|w| w == bytes);
        for fault_table in [false, true] {
            let region = emit_clean_load_prefix_with(
                &instructions,
                super::super::MemoryChecks::DEFAULT,
                fault_table,
                None,
            )
            .unwrap();
            assert_eq!(region.consumed_instructions, instructions.len());
            assert!(contains(&region.code, &recipe));
            for entry in &region.fault_recovery {
                for &(_, host) in &entry.registers {
                    assert!(![HostGpr::Rcx as u8, HostGpr::R10 as u8].contains(&host));
                }
            }
            // `mov rax, [rdi+0x60]`: X12 is read again from the frame.
            let reload = [0x48, 0x8b, 0x47, 0x60];
            let store_at = region
                .code
                .windows(recipe.len())
                .position(|window| window == &recipe[..])
                .unwrap();
            assert!(contains(&region.code[store_at..], &reload));
        }
    }

    /// With a fault table, a store whose data is dirty in a register the
    /// access does not clobber, R8 among them, takes it from there: its
    /// frame slot is stale. Only a value written back first is read from
    /// the frame.
    #[test]
    fn fault_table_stores_read_dirty_data_from_its_register() {
        let mut instructions: Vec<_> = (3..8)
            .map(|guest| {
                instruction(
                    guest - 3,
                    add(Register::X(guest as u8), Register::X(guest as u8)),
                )
            })
            .collect();
        for guest in 3..8u8 {
            let index = instructions.len() as u64;
            instructions.push(instruction(
                index,
                store(BYTE_LOAD_BYTES, Register::X(guest), Register::X(2), 8),
            ));
        }
        let region = emit_clean_load_prefix_with(
            &instructions,
            super::super::MemoryChecks::DEFAULT,
            true,
            None,
        )
        .unwrap();
        assert_eq!(region.consumed_instructions, instructions.len());
        let code = &region.code;
        // A frame access `op reg, [rdi+offset]` (disp8 or disp32) whose
        // opcode byte is at `at`. The store's staging load is the one into
        // RCX; the additions read the initial values into RAX.
        let frame = |at: usize, opcode: u8, offset: u8| {
            code[at] == opcode
                && match code.get(at + 1).map(|modrm| modrm & 0xc7) {
                    Some(0x47) => code.get(at + 2) == Some(&offset),
                    Some(0x87) => code.get(at + 2..at + 6) == Some(&[offset, 0, 0, 0][..]),
                    _ => false,
                }
        };
        for guest in 3..8u8 {
            let offset = guest * 8;
            for load in (1..code.len()).filter(|&at| {
                code[at - 1] == 0x48 && frame(at, 0x8b, offset) && code[at + 1] & 0x38 == 0x08
            }) {
                assert!(
                    (0..load).any(|at| frame(at, 0x89, offset)),
                    "X{guest} read from a stale frame slot"
                );
            }
        }
    }

    fn store(bytes: u8, data: Register, base: Register, displacement: i32) -> Operation {
        Operation::Memory {
            transfer: MemoryTransfer::Store,
            bytes,
            data,
            base,
            displacement,
            mode: AddressMode::Offset,
        }
    }

    fn store_pair(bytes: u8, data: [Register; 2], displacement: i32) -> Operation {
        Operation::MemoryPair {
            transfer: MemoryTransfer::Store,
            bytes,
            data,
            base: Register::Sp,
            displacement,
            mode: AddressMode::Offset,
        }
    }

    /// Stores settle every dirty value first, take resident bases and data
    /// from their registers, keep a value staged from the frame clean in
    /// RCX, and pass the cost gate against the unchanged emitter.
    #[test]
    fn stores_settle_first_and_reuse_resident_values() {
        // sub sp,sp,#32; add x9,x9,#1; add x9,x9,#1; str x9,[sp,#8];
        // stp x9,x10,[sp,#16]; strb w11,[x2,#3]; add x11,x11,#1;
        // strh wzr,[sp,#2]
        let instructions = [
            instruction(
                0,
                Operation::AddSub {
                    width: Width::X64,
                    subtract: true,
                    flags: false,
                    destination: Register::Sp,
                    source: Register::Sp,
                    immediate: 32,
                },
            ),
            instruction(1, add(Register::X(9), Register::X(9))),
            instruction(2, add(Register::X(9), Register::X(9))),
            instruction(
                3,
                store(DOUBLEWORD_LOAD_BYTES, Register::X(9), Register::Sp, 8),
            ),
            instruction(
                4,
                store_pair(DOUBLEWORD_LOAD_BYTES, [Register::X(9), Register::X(10)], 16),
            ),
            instruction(
                5,
                store(BYTE_LOAD_BYTES, Register::X(11), Register::X(2), 3),
            ),
            instruction(6, add(Register::X(11), Register::X(11))),
            instruction(
                7,
                store(HALFWORD_LOAD_BYTES, Register::Zero, Register::Sp, 2),
            ),
        ];
        let region = emit_clean_load_prefix(&instructions, true, None).unwrap();
        assert_eq!(region.consumed_instructions, instructions.len());
        assert_eq!(region.stats.stores, 4);
        // SP and X9 are dirty before the first store, and X11, whose staged
        // copy in RCX the ADD changes, before the last.
        assert_eq!(region.stats.load_boundary_stores, 3);
        assert_eq!(region.stats.address_cache_hits, 3);
        let contains = |bytes: &[u8]| {
            region
                .code
                .windows(bytes.len())
                .any(|window| window == bytes)
        };
        assert!(contains(&[0x48, 0x89, 0x08]));
        assert!(contains(&[0x4c, 0x89, 0x40, 0x08]));
        assert!(contains(&[0x88, 0x08]));
        assert!(contains(&[0x66, 0x89, 0x08]));
        let mut baseline = Code::new();
        for instruction in &instructions {
            super::super::emit_instruction(
                &mut baseline,
                instruction,
                &mut vec![],
                crate::TargetCpu::Baseline,
                super::super::MemoryChecks::DEFAULT,
            );
        }
        assert!(admits_ordinary(&region, &baseline));
    }

    /// Single stores are selected with or without their page-crossing
    /// split; pairs only through a checked, aligned SP; writeback never.
    #[test]
    fn stores_are_selected_with_their_split_and_pairs_only_aligned() {
        let selected = |operation, stack_alignment| {
            analysis::clean_access_effects(&operation, stack_alignment).is_some()
        };
        let sp = Register::Sp;
        let x = Register::X(3);
        let data = Register::X(4);
        assert!(selected(store(BYTE_LOAD_BYTES, data, x, 1), false));
        assert!(selected(store(WORD_LOAD_BYTES, data, sp, 12), true));
        for (operation, stack_alignment) in [
            (store(DOUBLEWORD_LOAD_BYTES, data, x, 8), true),
            (store(HALFWORD_LOAD_BYTES, data, x, 2), true),
            (store(DOUBLEWORD_LOAD_BYTES, data, sp, 8), false),
            (store(DOUBLEWORD_LOAD_BYTES, data, sp, 4), true),
        ] {
            assert!(selected(operation, stack_alignment));
        }
        assert!(selected(
            store_pair(WORD_LOAD_BYTES, [data, data], -64),
            true
        ));
        assert_eq!(
            analysis::clean_access_effects(&store(BYTE_LOAD_BYTES, Register::Zero, sp, 0), true),
            Some(analysis::Effects {
                reads: 1 << 31,
                writes: 0
            })
        );
        for (operation, stack_alignment) in [
            (store_pair(DOUBLEWORD_LOAD_BYTES, [data, data], 16), false),
            (store_pair(DOUBLEWORD_LOAD_BYTES, [data, data], 12), true),
            (store_pair(DOUBLEWORD_LOAD_BYTES, [data, data], 512), true),
            (
                Operation::MemoryPair {
                    transfer: MemoryTransfer::Store,
                    bytes: DOUBLEWORD_LOAD_BYTES,
                    data: [data, data],
                    base: x,
                    displacement: 16,
                    mode: AddressMode::Offset,
                },
                true,
            ),
            (
                Operation::Memory {
                    transfer: MemoryTransfer::Store,
                    bytes: BYTE_LOAD_BYTES,
                    data,
                    base: sp,
                    displacement: 16,
                    mode: AddressMode::PreIndex,
                },
                true,
            ),
        ] {
            assert!(!selected(operation, stack_alignment));
        }
    }

    #[test]
    fn shared_store_recipes_reject_any_change() {
        for (bytes, base) in [
            (BYTE_LOAD_BYTES, Register::X(15)),
            (HALFWORD_LOAD_BYTES, Register::X(15)),
            (WORD_LOAD_BYTES, Register::X(15)),
            (DOUBLEWORD_LOAD_BYTES, Register::X(15)),
            (BYTE_LOAD_BYTES, Register::Sp),
            (HALFWORD_LOAD_BYTES, Register::Sp),
            (WORD_LOAD_BYTES, Register::Sp),
            (DOUBLEWORD_LOAD_BYTES, Register::Sp),
        ] {
            for data in [Register::X(16), Register::Zero] {
                let mut raw = Code::new();
                super::super::memory(
                    &mut raw,
                    super::super::MemoryChecks::DEFAULT,
                    MemoryTransfer::Store,
                    bytes,
                    data,
                    crate::x86_64::ImmediateAddress {
                        base,
                        displacement: -16,
                        mode: AddressMode::Offset,
                    },
                );
                // An X base splits every H/W/X store; the checked SP's
                // aligned offset never does.
                let crossing = |bytes| bytes != BYTE_LOAD_BYTES && base != Register::Sp;
                let ends = |raw: &[u8], bytes| {
                    recipes::ordinary_store_ends(
                        raw,
                        bytes,
                        slot(base).unwrap(),
                        slot(data),
                        -16,
                        crossing(bytes),
                    )
                };
                let (selected, _) = ends(&raw, bytes).unwrap();
                assert_eq!(selected.last(), Some(&raw.len()));
                if bytes != BYTE_LOAD_BYTES {
                    assert!(
                        recipes::ordinary_store_ends(
                            &raw,
                            bytes,
                            slot(base).unwrap(),
                            slot(data),
                            -16,
                            !crossing(bytes),
                        )
                        .is_none()
                    );
                }
                for index in 0..raw.len() {
                    let mut changed = raw.as_slice().to_vec();
                    changed[index] ^= 1;
                    assert!(ends(&changed, bytes).is_none());
                }
                for other in [
                    BYTE_LOAD_BYTES,
                    HALFWORD_LOAD_BYTES,
                    WORD_LOAD_BYTES,
                    DOUBLEWORD_LOAD_BYTES,
                ] {
                    assert_eq!(ends(&raw, other).is_some(), other == bytes);
                }
            }
        }
        for bytes in [WORD_LOAD_BYTES, DOUBLEWORD_LOAD_BYTES] {
            for data in [
                [Register::X(16), Register::X(17)],
                [Register::Zero, Register::X(16)],
                [Register::X(16), Register::Zero],
            ] {
                let mut raw = Code::new();
                super::super::memory_pair(
                    &mut raw,
                    super::super::MemoryChecks::DEFAULT,
                    MemoryTransfer::Store,
                    bytes,
                    data,
                    crate::x86_64::ImmediateAddress {
                        base: Register::Sp,
                        displacement: -16,
                        mode: AddressMode::Offset,
                    },
                );
                let ends = |raw: &[u8], bytes| {
                    recipes::ordinary_pair_store_ends(raw, bytes, 31, data.map(slot), -16)
                };
                assert!(ends(&raw, bytes).is_some());
                for index in 0..raw.len() {
                    let mut changed = raw.as_slice().to_vec();
                    changed[index] ^= 1;
                    assert!(ends(&changed, bytes).is_none());
                }
            }
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

    #[test]
    fn profiled_region_counts_actual_cross_register_renaming_and_flag_pressure() {
        let renamed = [
            instruction(0, define_flags(Register::X(0), Register::X(0))),
            instruction(1, add(Register::X(1), Register::X(0))),
            instruction(
                2,
                Operation::MoveWide {
                    width: Width::X64,
                    kind: WideMove::Zero,
                    destination: Register::X(0),
                    immediate: 0,
                    shift: 0,
                },
            ),
            instruction(3, add(Register::X(1), Register::X(1))),
        ];
        let renamed = emit_allocated_prefix(&renamed).unwrap().unwrap();
        assert_eq!(renamed.stats.coalesced_writes, 1);
        assert_eq!(renamed.stats.in_place_source_uses, 2);
        let mut pressure = vec![instruction(0, define_flags(Register::X(0), Register::X(0)))];
        for _ in 0..2 {
            for register in 1..25 {
                pressure.push(instruction(
                    pressure.len() as u64,
                    add(Register::X(register), Register::X(register)),
                ));
            }
        }
        pressure.push(instruction(
            pressure.len() as u64,
            select_flags(Register::X(25), Register::X(26), Register::X(27), 0),
        ));
        let pressure = emit_allocated_prefix(&pressure).unwrap().unwrap();
        assert!(
            pressure.stats.nzcv_pressure_stores > 0,
            "{:?}",
            pressure.stats
        );
        let traffic = crate::block::profile::RegisterTraffic::region(&pressure.stats);
        assert_eq!(
            traffic.gpr_pressure_stores + traffic.nzcv_pressure_stores,
            pressure.stats.pressure_stores as u64
        );
        assert_eq!(
            traffic.gpr_boundary_stores + traffic.nzcv_boundary_stores,
            pressure.stats.exit_stores as u64
        );
        assert_eq!(
            traffic.nzcv_direct_stores
                + traffic.nzcv_pressure_stores
                + traffic.nzcv_boundary_stores,
            pressure.stats.flag_stores as u64
        );
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
        let legacy = emit_clean_load_prefix(&instructions, true, None).unwrap();
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
        let mut baseline_prefix = Code::new();
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
        let mut capture = Code::new();
        crate::x86_64::capture_nzcv(&mut capture, true);
        assert_eq!(capture.instructions(), 7);
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

    #[test]
    fn copied_store_recipes_preserve_the_shared_bytes_and_instruction_count() {
        for bytes in [
            BYTE_LOAD_BYTES,
            HALFWORD_LOAD_BYTES,
            WORD_LOAD_BYTES,
            DOUBLEWORD_LOAD_BYTES,
        ] {
            for base in [Register::X(15), Register::Sp] {
                for data in [Register::X(16), Register::Zero] {
                    let input = [instruction(0, store(bytes, data, base, -16))];
                    let mut baseline = Code::new();
                    super::super::memory(
                        &mut baseline,
                        super::super::MemoryChecks::DEFAULT,
                        MemoryTransfer::Store,
                        bytes,
                        data,
                        super::super::ImmediateAddress {
                            base,
                            displacement: -16,
                            mode: AddressMode::Offset,
                        },
                    );
                    let region = emit_clean_load_prefix_with(
                        &input,
                        super::super::MemoryChecks::DEFAULT,
                        false,
                        None,
                    )
                    .unwrap();
                    assert_eq!(region.consumed_instructions, 1);
                    // Independently counted shared recipes: base+LEA+data plus
                    // one byte store, or the complete guard/split/fast paths.
                    // SP adds three alignment-check instructions and needs no split.
                    let expected_count = if base == Register::Sp {
                        7
                    } else {
                        match bytes {
                            1 => 4,
                            2 => 12,
                            4 => 16,
                            8 => 24,
                            _ => unreachable!(),
                        }
                    };
                    assert_eq!(baseline.instructions(), expected_count);
                    assert_eq!(region.code, baseline, "{bytes} bytes {base:?} {data:?}");
                    assert_eq!(
                        region.code.instructions(),
                        baseline.instructions(),
                        "cost count must retain every instruction in the crossing recipe"
                    );
                }
            }
        }
    }
    #[test]
    fn translated_range_data_has_no_instruction_cost() {
        let instructions: Vec<_> = [16, 24]
            .into_iter()
            .enumerate()
            .map(|(index, displacement)| {
                instruction(
                    index as u64,
                    Operation::Memory {
                        transfer: MemoryTransfer::Load {
                            signed: false,
                            width: Width::X64,
                        },
                        bytes: 8,
                        data: Register::X(index as u8 + 2),
                        base: Register::X(1),
                        displacement,
                        mode: AddressMode::Offset,
                    },
                )
            })
            .collect();
        let checks = super::super::MemoryChecks {
            guest_range: true,
            translated: true,
            translation_helper: 0x1000,
            ..super::super::MemoryChecks::DEFAULT
        };
        let mut check = Code::new();
        checks.range.emit_translated(
            &mut check,
            checks.translation_helper,
            super::super::Access::of(false, 8),
        );
        // Five test instructions, MOV/MOFFS/CALL/JMP, and two mask instructions.
        // The two descriptor bytes following CALL contribute no instruction.
        assert_eq!(check.instructions(), 11);
        let mut baseline = Code::new();
        for input in &instructions {
            super::super::emit_instruction(
                &mut baseline,
                input,
                &mut vec![],
                crate::TargetCpu::Baseline,
                checks,
            );
        }
        let region =
            emit_clean_load_prefix_with(&instructions, checks, false, Some(&[true, true])).unwrap();
        assert_eq!(baseline.instructions(), 30);
        // Two translated checks contain data after CALL, not two extra instructions.
        assert_eq!(region.code.instructions(), 29);
        assert_eq!(region.stats.native_instructions, 29);
        assert!(region.code.len() < baseline.len());
        assert!(admits_ordinary(&region, &baseline));
        std::eprintln!(
            "TRANSLATED_COUNT baseline={} candidate={} stats={} bytes={}/{} admitted={}",
            baseline.instructions(),
            region.code.instructions(),
            region.stats.native_instructions,
            baseline.len(),
            region.code.len(),
            admits_ordinary(&region, &baseline)
        );
    }
}
