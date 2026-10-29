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
#[cfg(test)]
mod apx;
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
                    site: crate::block::RecoverySite::native_internal(),
                    bindings: live
                        .into_iter()
                        .map(|(guest, host)| crate::block::RecoveryBinding::gpr(guest, host))
                        .collect(),
                    retirement: crate::block::RetirementPoint::before(
                        self.output
                            .source_map
                            .last()
                            .expect("access has its source PC")
                            .0,
                        u16::try_from(self.current).expect("bounded region instruction count"),
                    )
                    .expect("region input validates the instruction PC"),
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
mod tests;
