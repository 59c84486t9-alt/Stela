//! Register residency for non-faulting scalar self-loops. Every exit writes back
//! the full guest register bank.
use super::{
    AllocationStats, Effects, Emitter, FRAME_LOCATIONS, GPR_SLOTS, HostGpr, Location,
    MAX_INSTRUCTIONS, OptimizedRegion, POOL, Resident, analysis, constant, encoding, flags,
};
use crate::{
    GuestAddress, NativeBlock,
    aarch64::{Instruction, Operation},
    block::{ExitKind, Terminator},
};
use alloc::vec;
use alloc::vec::Vec;

const ARM_CONDITION_INVERSE_BIT: u8 = 1;
const INSTRUCTION_BYTES: u64 = core::mem::size_of::<u32>() as u64;

pub(crate) fn prefix_with_budget(mut native: NativeBlock, base: GuestAddress) -> NativeBlock {
    let mut code = vec![];
    encoding::load_budget(&mut code);
    encoding::skip_jump_if_budget_zero(&mut code);
    let body_jump = encoding::near_jump(&mut code);
    super::super::block::direct_exit(&mut code, base, ExitKind::Direct);
    let body = code.len();
    encoding::patch_relative(&mut code, body_jump, body);
    encoding::decrement_stored_budget(&mut code);
    let prefix = code.len();
    code.extend(native.x86_64_code);
    for (_, offset) in &mut native.source_map {
        *offset += prefix;
    }
    if let Some((_, offset)) = native.source_map.first_mut() {
        *offset = 0;
    }
    native.x86_64_code = code;
    native
}

/// One source-derived plan is shared by cache admission and emission. Existing
/// qualified five-slot bodies retain their exact recipe; broader shapes use the
/// common live-value allocator, not a participant-count exception.
pub(crate) struct Plan {
    choice: Choice,
}

enum Choice {
    Legacy(LegacyPlan),
    Allocated {
        instructions: Vec<Instruction>,
        native: NativeBlock,
    },
}

impl Plan {
    pub(crate) fn new(
        instructions: &[Instruction],
        terminal: Option<&(GuestAddress, Terminator)>,
        fallthrough: GuestAddress,
    ) -> Option<Self> {
        if let Some(plan) = LegacyPlan::new(instructions, terminal, fallthrough) {
            return Some(Self {
                choice: Choice::Legacy(plan),
            });
        }
        let native = allocated_loop(instructions, terminal, fallthrough)?;
        Some(Self {
            choice: Choice::Allocated {
                instructions: instructions.to_vec(),
                native,
            },
        })
    }

    pub(crate) fn emit(
        self,
        instructions: &[Instruction],
    ) -> Result<NativeBlock, super::RegionError> {
        match self.choice {
            Choice::Legacy(plan) => plan.emit(instructions),
            Choice::Allocated {
                instructions: planned,
                native,
            } => {
                if instructions != planned.as_slice() {
                    return Err(super::RegionError::ChangedInstructions);
                }
                Ok(native)
            }
        }
    }
}

/// Decoded eligibility and lowering inputs shared by cache identity and emission.
struct LegacyPlan {
    entry: GuestAddress,
    branch_pc: GuestAddress,
    fallthrough: GuestAddress,
    normal_condition: encoding::NativeCondition,
    effects: Vec<Effects>,
    prefix_steps: Vec<flags::Step>,
    used: u32,
    last: Instruction,
}

impl LegacyPlan {
    pub(crate) fn new(
        instructions: &[Instruction],
        terminal: Option<&(GuestAddress, Terminator)>,
        fallthrough: GuestAddress,
    ) -> Option<Self> {
        let entry = instructions.first()?.pc;
        let (branch_pc, Terminator::Branch(Operation::BranchCondition { target, condition })) =
            terminal?
        else {
            return None;
        };
        if *target != entry || instructions.len() > MAX_INSTRUCTIONS {
            return None;
        }
        let normal_condition = *encoding::SUBTRACTION_CONDITIONS
            .get(usize::from(*condition ^ ARM_CONDITION_INVERSE_BIT))?;
        let (last, prefix) = instructions.split_last()?;
        // Every flag read inside the loop has a known host source, and the
        // final subtraction defines every flag seen by the edge and the exit.
        let Operation::AddSub {
            width,
            subtract: true,
            flags: true,
            destination,
            source,
            immediate,
        } = last.operation
        else {
            return None;
        };
        let mut provenance = None;
        let prefix_steps: Vec<_> = prefix
            .iter()
            .map(|instruction| flags::analyze(&instruction.operation, &mut provenance))
            .collect::<Option<_>>()?;
        let mut effects: Vec<Effects> = prefix_steps.iter().map(|(effect, _)| *effect).collect();
        let final_effects = analysis::effects(&Operation::AddSub {
            width,
            subtract: true,
            flags: false,
            destination,
            source,
            immediate,
        })?;
        effects.push(final_effects);
        for (index, instruction) in instructions.iter().enumerate() {
            if instruction.pc.0 != entry.0.checked_add((index as u64) * INSTRUCTION_BYTES)? {
                return None;
            }
        }
        if branch_pc.0
            != entry
                .0
                .checked_add((instructions.len() as u64) * INSTRUCTION_BYTES)?
            || fallthrough.0 != branch_pc.0.checked_add(INSTRUCTION_BYTES)?
        {
            return None;
        }
        let used = effects
            .iter()
            .fold(0u32, |mask, effect| mask | effect.reads | effect.writes);
        let available: Vec<usize> = (0..POOL.len())
            .filter(|&index| POOL[index] != HostGpr::Rcx)
            .collect();
        // A stable per-guest assignment needs no edge shuffle or pressure spill.
        // Broader live-range reuse/callee-saved pools remain separate work.
        if used.count_ones() as usize > available.len() {
            return None;
        }
        Some(Self {
            entry,
            branch_pc: *branch_pc,
            fallthrough,
            normal_condition,
            effects,
            prefix_steps: prefix_steps.into_iter().map(|(_, step)| step).collect(),
            used,
            last: last.clone(),
        })
    }

    pub(crate) fn emit(
        self,
        instructions: &[Instruction],
    ) -> Result<NativeBlock, super::RegionError> {
        let Self {
            entry,
            branch_pc,
            fallthrough,
            normal_condition,
            effects,
            prefix_steps,
            used,
            last,
        } = self;
        let Operation::AddSub {
            width,
            destination,
            source,
            immediate,
            ..
        } = last.operation
        else {
            unreachable!("planned complete final subtraction")
        };
        let prefix = &instructions[..instructions.len() - 1];
        let available = (0..POOL.len()).filter(|&index| POOL[index] != HostGpr::Rcx);
        let mut code = vec![];
        encoding::push_budget_pointer(&mut code);
        encoding::load_budget(&mut code);
        encoding::skip_jump_if_budget_zero(&mut code);
        let body_jump = encoding::near_jump(&mut code);
        encoding::pop_budget_pointer(&mut code);
        super::super::block::direct_exit(&mut code, entry, ExitKind::Direct);
        let cold_entry = code.len();
        encoding::patch_relative(&mut code, body_jump, cold_entry);
        let mut emitter = Emitter {
            output: OptimizedRegion {
                code,
                consumed_instructions: instructions.len(),
                source_map: vec![],
                stats: AllocationStats::default(),
                fault_recovery: vec![],
            },
            resident: [None; encoding::ALLOCATABLE_SLOTS],
            locations: FRAME_LOCATIONS,
            effects: &effects,
            current: 0,
            constants: constant::ConstantRegisters::default(),
            reserved_hosts: HostGpr::Rcx.mask(),
            pinned_hosts: 0,
            persistent: true,
            allocation: None,
            flag_location: flags::Location::Frame,
            coalesced: None,
            allocating_output: false,
            range_checks: None,
            // No loads.
            stack_alignment: true,
            fault_table: false,
        };
        for (guest, index) in (0..GPR_SLOTS)
            .filter(|&guest| used & (1 << guest) != 0)
            .zip(available)
        {
            let host = POOL[index];
            emitter.emit(|code| encoding::load(code, host, guest));
            emitter.locations[guest] = Location::Host(host);
            emitter.resident[index] = Some(Resident {
                guest,
                dirty: false,
            });
            emitter.output.stats.state_loads += 1;
        }
        let header = emitter.output.code.len();
        for (instruction, step) in prefix.iter().zip(&prefix_steps) {
            flags::emit(&mut emitter, instruction, *step)?;
            emitter.current += 1;
        }
        emitter
            .output
            .source_map
            .push((last.pc, emitter.output.code.len()));
        if let Some(host) = emitter.in_place(destination, source) {
            emitter.emit(|code| encoding::arithmetic_immediate(code, host, true, immediate, width));
            emitter.committed_in_place(destination);
        } else {
            emitter.read(source, encoding::RESULT);
            emitter.emit(|code| {
                encoding::arithmetic_immediate(code, encoding::RESULT, true, immediate, width)
            });
            // Register copies and the ZR NOP preserve the subtraction's flags.
            emitter.commit(destination, width);
        }
        emitter.current += 1;
        let code = &mut emitter.output.code;
        emitter.output.source_map.push((branch_pc, code.len()));
        encoding::decrement_budget_preserving_flags(code);
        // The loop edge takes priority over budget exhaustion: a false
        // condition falls through even when the budget ran out.
        let normal_exit_jump = encoding::conditional_jump(code, normal_condition);
        encoding::skip_jump_if_budget_zero(code);
        let backedge = encoding::near_jump(code);
        encoding::patch_relative(code, backedge, header);
        let dirty: Vec<_> = emitter
            .resident
            .iter()
            .enumerate()
            .filter_map(|(index, value)| {
                value
                    .filter(|value| value.dirty)
                    .map(|value| (POOL[index], value.guest))
            })
            .collect();
        settle_exit(code, &dirty, entry, ExitKind::Direct);
        let normal_exit = code.len();
        encoding::patch_relative(code, normal_exit_jump, normal_exit);
        settle_exit(code, &dirty, fallthrough, ExitKind::Fallthrough);
        if let Some((_, offset)) = emitter.output.source_map.first_mut() {
            *offset = 0;
        }
        Ok(NativeBlock {
            x86_64_code: emitter.output.code,
            source_map: emitter.output.source_map,
        })
    }
}

fn settle_exit(
    code: &mut Vec<u8>,
    dirty: &[(HostGpr, usize)],
    next_pc: GuestAddress,
    kind: ExitKind,
) {
    // Every instruction before NZCV capture preserves host subtraction flags.
    for &(host, guest) in dirty {
        encoding::store(code, host, guest);
    }
    encoding::pop_budget_pointer(code);
    encoding::store_budget(code);
    // Shared complete SUBS flag recipe, including ARM's no-borrow C polarity.
    // It may now clobber RCX: remaining budget and all dirty GPRs are settled.
    super::super::nzcv(code, true);
    super::super::block::direct_exit(code, next_pc, kind);
}

fn allocated_loop(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
) -> Option<NativeBlock> {
    use super::allocation::{self, LiveRanges, Value};
    let entry = instructions.first()?.pc;
    if entry.0 & (INSTRUCTION_BYTES - 1) != 0 || instructions.len() > MAX_INSTRUCTIONS {
        return None;
    }
    let (branch_pc, Terminator::Branch(Operation::BranchCondition { target, condition })) =
        terminal?
    else {
        return None;
    };
    if *target != entry {
        return None;
    }
    let normal_condition = *encoding::SUBTRACTION_CONDITIONS
        .get(usize::from(*condition ^ ARM_CONDITION_INVERSE_BIT))?;
    if !matches!(
        instructions.last()?.operation,
        Operation::AddSub {
            subtract: true,
            flags: true,
            ..
        }
    ) {
        return None;
    }
    let analyzed: Vec<_> = instructions
        .iter()
        .map(|instruction| flags::analyze_value(&instruction.operation))
        .collect::<Option<_>>()?;
    for (index, instruction) in instructions.iter().enumerate() {
        if instruction.pc.0 != entry.0.checked_add((index as u64) * INSTRUCTION_BYTES)? {
            return None;
        }
    }
    if branch_pc.0
        != entry
            .0
            .checked_add((instructions.len() as u64) * INSTRUCTION_BYTES)?
        || fallthrough.0 != branch_pc.0.checked_add(INSTRUCTION_BYTES)?
    {
        return None;
    }
    let values: Vec<_> = analyzed.iter().map(|(_, values, _)| *values).collect();
    // Initial scope requires a real producer before each loop's flag consumer.
    // Packed flag phis at the header need a separate admitted edge contract.
    if LiveRanges::compute(&values).inputs() & Value::NZCV.mask() != 0 {
        return None;
    }
    let gprs: Vec<_> = analyzed.iter().map(|(gprs, _, _)| *gprs).collect();
    let mut best: Option<((usize, usize, usize), NativeBlock)> = None;
    for callee_slots in 0..=encoding::CALLEE_POOL.len() {
        let plan = allocation::Plan::new(values.clone(), callee_slots, true);
        let mut emitter = allocation::emitter(&gprs, plan, entry);
        let code = &mut emitter.output.code;
        encoding::push_budget_pointer(code);
        encoding::load_budget(code);
        encoding::skip_jump_if_budget_zero(code);
        let cold_jump = encoding::near_jump(code);
        encoding::pop_budget_pointer(code);
        super::super::block::direct_exit(code, entry, ExitKind::Direct);
        let cold_entry = code.len();
        encoding::patch_relative(code, cold_jump, cold_entry);
        emitter.reserved_hosts = HostGpr::Rcx.mask();
        emitter.borrow_callees();
        let header_locations = emitter.preload_loop_inputs();
        let cold_loads = emitter.output.stats.state_loads;
        let header = emitter.output.code.len();
        for (instruction, (_, _, step)) in instructions.iter().zip(&analyzed) {
            emitter.value_instruction(instruction, *step).ok()?;
            emitter.current += 1;
        }
        let dirty: Vec<_> = emitter
            .resident
            .iter()
            .enumerate()
            .filter_map(|(index, resident)| {
                resident
                    .filter(|resident| resident.dirty)
                    .map(|resident| (encoding::pool_host(index), resident.guest))
            })
            .collect();
        // The final complete subtraction always owns the physical host flags.
        let flags::Location::Native(carry) = emitter.flag_location else {
            return None;
        };
        let code = &mut emitter.output.code;
        emitter.output.source_map.push((*branch_pc, code.len()));
        encoding::decrement_budget_preserving_flags(code);
        let normal_jump = encoding::conditional_jump(code, normal_condition);
        encoding::skip_jump_if_budget_zero(code);
        let hot_jump = encoding::near_jump(code);
        settle_allocated_exit(code, &dirty, callee_slots, carry, entry, ExitKind::Direct);
        let hot = code.len();
        encoding::patch_relative(code, hot_jump, hot);
        emitter.reconcile_loop_inputs(&header_locations);
        let code = &mut emitter.output.code;
        let backedge = encoding::near_jump(code);
        encoding::patch_relative(code, backedge, header);
        let normal = code.len();
        encoding::patch_relative(code, normal_jump, normal);
        settle_allocated_exit(
            code,
            &dirty,
            callee_slots,
            carry,
            fallthrough,
            ExitKind::Fallthrough,
        );
        if let Some((_, offset)) = emitter.output.source_map.first_mut() {
            *offset = 0;
        }
        let hot_frame =
            emitter.output.stats.state_loads - cold_loads + emitter.output.stats.pressure_stores;
        // Hot pressure is the primary loop cost. Equal pressure uses the smallest
        // complete body, then the smaller native callee-save footprint.
        let cost = (hot_frame, emitter.output.code.len(), callee_slots);
        let native = NativeBlock {
            x86_64_code: emitter.output.code,
            source_map: emitter.output.source_map,
        };
        if best.as_ref().is_none_or(|(old, _)| cost < *old) {
            best = Some((cost, native));
        }
    }
    best.map(|(_, native)| native)
}

fn settle_allocated_exit(
    code: &mut Vec<u8>,
    dirty: &[(HostGpr, usize)],
    callee_slots: usize,
    carry: flags::Carry,
    next_pc: GuestAddress,
    kind: ExitKind,
) {
    for &(host, guest) in dirty {
        debug_assert!(
            guest < GPR_SLOTS,
            "final SUBS kills the packed flag version"
        );
        encoding::store(code, host, guest);
    }
    for host in encoding::CALLEE_POOL.into_iter().take(callee_slots).rev() {
        encoding::pop(code, host);
    }
    encoding::pop_budget_pointer(code);
    encoding::store_budget(code);
    flags::settle_native_exit(code, carry);
    super::super::block::direct_exit(code, next_pc, kind);
}
