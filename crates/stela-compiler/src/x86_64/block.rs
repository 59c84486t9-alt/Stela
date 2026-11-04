//! Block control transfers: every branch returns to the dispatcher.
use crate::x86_64::asm::{Alu, Asm, Code, Cond, Gpr, Size};
use alloc::vec;
use alloc::vec::Vec;
pub(crate) mod checked_memory;
mod recovery;
pub(crate) use super::region::ResidentLoopPlan;

use super::chain::ExitWord;
use crate::{
    GuestAddress, NativeBlock,
    aarch64::{Instruction, Operation, Register},
    block::{ExitKind, Terminator},
};

pub(super) fn exit_kind(code: &mut Code, kind: ExitKind) {
    exit_kind_with(&mut code.asm(), kind);
}

/// `mov edx,word; ret`: the exit to the target in RAX.
pub(super) fn exit_kind_with(asm: &mut Asm, word: impl Into<ExitWord>) {
    // MOV EDX zero-extends to the ABI's u64.
    asm.mov_imm32(Gpr::Rdx, word.into().encoded());
    asm.ret();
    // The rest of the room a `chain::lookup_exit` takes.
    for _ in 0..4 {
        asm.int3();
    }
}

pub(crate) fn direct_exit(code: &mut Code, target: GuestAddress, kind: ExitKind) {
    direct_exit_with(&mut code.asm(), target, kind);
}

/// `movabs rax,target` and the exit of `word`, after its empty link slot in
/// code whose exits keep one.
pub(super) fn direct_exit_with(asm: &mut Asm, target: GuestAddress, word: impl Into<ExitWord>) {
    let word = word.into();
    let slot = super::chain::link_slot(asm.linked_block(), target, word.kind);
    super::chain::empty_link(asm, slot);
    asm.mov_imm64(Gpr::Rax, target.0);
    exit_kind_with(asm, word);
}

fn conditional_exit(
    code: &mut Code,
    taken: Option<Cond>,
    target: GuestAddress,
    fallthrough: GuestAddress,
) {
    let mut asm = code.asm();
    if let Some(taken) = taken {
        let branch = asm.jcc(taken);
        direct_exit_with(&mut asm, fallthrough, ExitKind::Fallthrough);
        // The taken branch skips the complete fallthrough exit. Both paths
        // leave saved NZCV untouched regardless of host predicate evaluation.
        asm.bind(branch);
    }
    direct_exit_with(&mut asm, target, ExitKind::Direct);
}

#[cfg(test)]
fn emit(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
) -> NativeBlock {
    emit_for_target(
        instructions,
        terminal,
        fallthrough,
        crate::TargetCpu::Baseline,
        super::MemoryChecks::DEFAULT,
    )
}

pub(crate) fn emit_ordinary_for_target(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: crate::TargetCpu,
) -> NativeBlock {
    emit_selected(
        instructions,
        terminal,
        fallthrough,
        target,
        RegionPolicy {
            optimize: true,
            fault_table: false,
            pinned: false,
        },
        super::MemoryChecks::DEFAULT,
        super::NativeSystem::NONE,
    )
    .0
}

/// Every artifact in this profile accepts the same invocation-local budget ABI.
pub(crate) fn emit_resident_fallback_for_target(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: crate::TargetCpu,
) -> NativeBlock {
    let base = instructions
        .first()
        .map(|instruction| instruction.pc)
        .or_else(|| terminal.map(|(pc, _)| *pc))
        .unwrap_or(fallthrough);
    let native = emit_ordinary_for_target(instructions, terminal, fallthrough, target);
    super::region::prefix_with_budget(native, base)
}

#[cfg(test)]
pub(crate) fn emit_for_target(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: crate::TargetCpu,
    checks: super::MemoryChecks,
) -> NativeBlock {
    emit_selected(
        instructions,
        terminal,
        fallthrough,
        target,
        RegionPolicy {
            optimize: false,
            fault_table: false,
            pinned: false,
        },
        checks,
        super::NativeSystem::NONE,
    )
    .0
}

/// A block for the system-mode engine, which may also complete a terminal
/// System instruction natively and fall through: DC ZVA by
/// zeroing its block (`x86_64::zero_block`) and DC CVAC, DC CVAU and DC
/// CIVAC by reading the byte at Xt (`x86_64::cache_clean`).
pub(crate) fn emit_system_mode(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: crate::TargetCpu,
    checks: super::MemoryChecks,
    native: super::NativeSystem,
) -> (NativeBlock, Vec<crate::block::FaultRecovery>) {
    // Guest registers stay in host registers (`x86_64::pinned`), which the
    // engine's fault settlement reads, so no block needs the regions, which
    // spend the same host registers within one block. Accesses check the
    // guest range (`x86_64::guest_range`). PEs run concurrently, so atomics
    // stay locked and barriers fence.
    emit_selected(
        instructions,
        terminal,
        fallthrough,
        target,
        RegionPolicy {
            optimize: false,
            fault_table: true,
            pinned: true,
        },
        super::MemoryChecks {
            guest_range: true,
            ..checks
        },
        native,
    )
}

/// Selection and recovery policy for register-resident regions.
#[derive(Clone, Copy)]
struct RegionPolicy {
    optimize: bool,
    fault_table: bool,
    /// Keep guest registers in host registers ([`super::pinned`]).
    pinned: bool,
}

/// With `fault_table`, region accesses keep dirty values in registers and
/// the returned table says where ([`crate::block::FaultRecovery`]).
fn emit_selected(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: crate::TargetCpu,
    regions: RegionPolicy,
    checks: super::MemoryChecks,
    native: super::NativeSystem,
) -> (NativeBlock, Vec<crate::block::FaultRecovery>) {
    let RegionPolicy {
        optimize: optimize_regions,
        fault_table,
        pinned,
    } = regions;
    let mut fault_recovery = vec![];
    let mut block = super::Emitted::default();
    let code = &mut block.x86_64_code;
    code.set_pinned(pinned);
    if pinned
        && let Some(first) = instructions
            .first()
            .map(|first| first.pc)
            .or(terminal.map(|(pc, _)| *pc))
    {
        code.set_linked_block(first.0);
    }
    code.set_constant_time(target.data_independent_timing());
    let mut fixups = vec![];
    // The DIT audit covers each instruction's own lowering, not the
    // register-allocated and clean-load regions' recipes.
    let optimize_regions = optimize_regions && !target.data_independent_timing();
    // Which accesses check the guest range (`guest_range`), and each
    // instruction's checks.
    let ranges = if checks.guest_range && checks.checks_every_access() {
        vec![true; instructions.len()]
    } else if checks.guest_range {
        super::guest_range::checks(instructions)
    } else {
        vec![]
    };
    let ranges = checks.guest_range.then_some(&ranges[..]);
    // Which accesses through SP check its alignment (`stack_alignment`).
    let stack = super::stack_alignment::checks(instructions);
    let checks_at = |index: usize| super::MemoryChecks {
        guest_range: ranges.is_some_and(|ranges| ranges[index]),
        stack_checked: !stack[index],
        ..checks
    };
    // The regions check SP at each access through it, and their cost gates
    // weigh them against instructions that do too.
    let gate_at = |index: usize| super::MemoryChecks {
        stack_checked: false,
        ..checks_at(index)
    };
    let mut cursor = 0;
    // What the last instruction emitted left in registers.
    let mut after = Held::NOTHING;
    let mut out_of_line = OutOfLine::default();
    // Forwarding probes encode one expected MOV at a time. Keep their
    // bytes in one buffer across the block and its temporary candidates.
    let mut scratch = Code::default();
    // Each branch the block runs past: its jump to a side exit, its target
    // and the instructions up to it.
    let mut side_exits = vec![];
    while cursor < instructions.len() {
        let held = core::mem::replace(&mut after, Held::NOTHING);
        // Build the new candidate privately. Rejection leaves both cursor and
        // output untouched, so the legacy clean-load chunk partition is exact.
        if optimize_regions
            && let Ok(Some(region)) = super::region::emit_allocated_prefix(&instructions[cursor..])
        {
            let count = region.consumed_instructions;
            let mut baseline = Code::new();
            let mut candidate_fixups = vec![];
            for (index, instruction) in instructions[cursor..cursor + count].iter().enumerate() {
                super::emit_instruction(
                    &mut baseline,
                    instruction,
                    &mut candidate_fixups,
                    target,
                    gate_at(cursor + index),
                );
            }
            if candidate_fixups.is_empty() && super::region::admits_allocated(&region, &baseline) {
                let offset = code.len();
                block
                    .source_map
                    .extend(region.source_map.iter().map(|(pc, at)| (*pc, offset + at)));
                code.append(region.code);
                cursor += count;
                continue;
            }
        }
        if optimize_regions
            && let Ok(region) = super::region::emit_clean_load_prefix_with(
                &instructions[cursor..],
                checks,
                fault_table,
                ranges.map(|ranges| &ranges[cursor..]),
            )
            && region.consumed_instructions != 0
        {
            let count = region.consumed_instructions;
            let chunk = &instructions[cursor..cursor + count];
            let mut baseline = |checks_at: &dyn Fn(usize) -> super::MemoryChecks| {
                let mut code = Code::new();
                let mut map = vec![];
                let mut fixups = vec![];
                let mut after = held;
                for (index, instruction) in chunk.iter().enumerate() {
                    map.push((instruction.pc, code.len()));
                    after = emit_single(
                        &mut code,
                        &mut scratch,
                        None,
                        instruction,
                        &mut fixups,
                        SingleOptions {
                            target,
                            checks: checks_at(cursor + index),
                        },
                        after,
                    );
                }
                debug_assert!(fixups.is_empty());
                (code, map, after)
            };
            let offset = code.len();
            let gate_baseline = baseline(&gate_at);
            if super::region::admits_ordinary(&region, &gate_baseline.0) {
                block
                    .source_map
                    .extend(region.source_map.iter().map(|(pc, at)| (*pc, offset + at)));
                fault_recovery.extend(region.fault_recovery.into_iter().map(|entry| {
                    crate::block::FaultRecovery {
                        start: offset + entry.start,
                        end: offset + entry.end,
                        retirement: entry
                            .retirement
                            .rebased(u16::try_from(cursor).expect("bounded block cursor"))
                            .expect("bounded block retirement"),
                        ..entry
                    }
                }));
                code.append(region.code);
            } else {
                // Reject the complete eligible chunk. Rescanning its suffix
                // could bypass the measured cost gate with a different shape.
                let same_stack_checks = chunk.iter().enumerate().all(|(index, instruction)| {
                    match instruction.operation {
                        Operation::Memory { base, .. } | Operation::MemoryPair { base, .. }
                            if base == Register::Sp =>
                        {
                            stack[cursor + index]
                        }
                        _ => true,
                    }
                });
                let (baseline_code, baseline_map, baseline_after) = if same_stack_checks {
                    gate_baseline
                } else {
                    baseline(&checks_at)
                };
                block
                    .source_map
                    .extend(baseline_map.iter().map(|(pc, at)| (*pc, offset + at)));
                code.append(baseline_code);
                after = baseline_after;
            }
            // Each region wrote back the full register frame, so what follows
            // sees the ordinary direct-RAM ABI.
            cursor += count;
            continue;
        }
        let instruction = &instructions[cursor];
        block.source_map.push((instruction.pc, code.len()));
        code.set_instruction(block.source_map.len() - 1);
        if let Some(target) = instruction.operation.conditional_target() {
            let taken = branch_condition(code, &instruction.operation, held.rax)
                .expect("a conditional branch's condition");
            side_exits.push((code.asm().jcc(taken), target, block.source_map.len()));
            cursor += 1;
            continue;
        }
        let frame_bound = pinned && super::pinned::frame_bound(&instruction.operation);
        if frame_bound {
            code.set_pinned(false);
            super::pinned::write_back(code);
        }
        after = emit_single(
            code,
            &mut scratch,
            Some(&mut out_of_line),
            instruction,
            &mut fixups,
            SingleOptions {
                target,
                checks: checks_at(cursor),
            },
            held,
        );
        if frame_bound {
            super::pinned::reload(code);
            code.set_pinned(true);
        }
        cursor += 1;
    }
    debug_assert!(
        fixups.is_empty(),
        "ordinary instruction prefix cannot branch"
    );
    out_of_line.place(code);
    emit_terminal(
        code,
        &mut block.source_map,
        terminal,
        TerminalContext {
            fallthrough,
            native,
            checks,
            rax: after.rax,
            target,
        },
    );
    // After the terminal, whose direct exits end the code before them.
    let instructions_run = block.source_map.len();
    for (jump, target, run) in side_exits {
        let mut asm = code.asm();
        asm.bind(jump);
        direct_exit_with(&mut asm, target, side_exit(instructions_run - run));
    }
    code.place_failures();
    if fault_table {
        fault_recovery = recovery::bind(
            &block.x86_64_code,
            &block.source_map,
            instructions,
            fault_recovery,
        );
    }
    (block.into_native(), fault_recovery)
}

/// What registers hold where an instruction outside the regions begins,
/// left there by the previous one.
#[derive(Clone, Copy)]
struct Held {
    rax: super::Rax,
    /// The guest vector XMM0 holds whole.
    xmm0: Option<u8>,
}

impl Held {
    const NOTHING: Self = Self {
        rax: super::Rax::Unknown,
        xmm0: None,
    };
}

struct SingleOptions {
    target: crate::TargetCpu,
    checks: super::MemoryChecks,
}

/// One instruction outside the regions, after an emission that left
/// `held`; returns what it leaves. An instruction that first loads the
/// register the previous one just stored from RAX finds it there, and one
/// that reads a vector XMM0 holds may take it from there. With
/// `out_of_line`, numerical instructions move their slow paths there.
fn emit_single(
    code: &mut Code,
    scratch: &mut Code,
    out_of_line: Option<&mut OutOfLine>,
    instruction: &Instruction,
    fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
    options: SingleOptions,
    held: Held,
) -> Held {
    let SingleOptions { target, checks } = options;
    if let Operation::FloatingPoint(operand) = &instruction.operation {
        let Some(out_of_line) = out_of_line else {
            super::simd::emit_numerical(code, operand, instruction.pc, target);
            return Held::NOTHING;
        };
        let start = code.len();
        let entry = super::simd::numerical::Entry {
            checked: !out_of_line.continues_at(start),
            xmm0: held.xmm0,
        };
        let split = super::simd::emit_numerical_split(code, operand, instruction.pc, target, entry);
        let xmm0 = split.as_ref().map(|split| split.result);
        out_of_line.take(code, start, split);
        return Held {
            rax: super::Rax::Unknown,
            xmm0,
        };
    }
    let start = code.len();
    if let Operation::Simd(operand) = &instruction.operation {
        super::simd::emit_after(code, operand, target, checks, held.xmm0);
        // A first load of the vector XMM0 holds changes nothing.
        if let Some(vector) = held.xmm0 {
            let load = super::simd::xmm0_load(scratch, vector);
            if code[start..].starts_with(load) && code.len() > start + load.len() {
                code.remove_instruction(start..start + load.len());
            }
        }
    } else if let Operation::ConditionalSelect(operand) = &instruction.operation
        && code.is_pinned()
        && !code.constant_time()
        && held.rax == super::Rax::Nzcv
        && matches!(
            operand.otherwise,
            crate::aarch64::conditional_select::Otherwise::Unchanged
                | crate::aarch64::conditional_select::Otherwise::Invert
        )
    {
        // The preceding pinned capture preserves the host flags. MOV and
        // NOT keep them live while preparing these select operands.
        super::conditional_select::emit(code, operand, true);
    } else {
        super::emit_instruction(code, instruction, fixups, target, checks);
    }
    // The instruction keeps a non-empty native range for its source map.
    if let super::Rax::Guest(register) = held.rax
        && let Some(load) = super::register_load(scratch, register, code.is_pinned())
        && code[start..].starts_with(load)
        && code.len() > start + load.len()
    {
        code.remove_instruction(start..start + load.len());
    }
    let rax = match super::rax_after(&instruction.operation, code.is_pinned()) {
        // A direct form may leave the result only in its host register.
        super::Rax::Guest(register)
            if code.is_pinned()
                && !super::register_store(scratch, register, true)
                    .is_some_and(|store| code.ends_with(store)) =>
        {
            super::Rax::Unknown
        }
        rax => rax,
    };
    debug_assert!(match rax {
        super::Rax::Unknown => true,
        super::Rax::Nzcv => code.ends_with(&nzcv_store(code.is_pinned())),
        super::Rax::Guest(register) => super::register_store(scratch, register, code.is_pinned())
            .is_some_and(|store| code.ends_with(store)),
    });
    let xmm0 = match &instruction.operation {
        Operation::Simd(operand) => {
            super::simd::xmm0_after(scratch, operand, &code[start..], held.xmm0)
        }
        _ => None,
    };
    Held { rax, xmm0 }
}

/// Where a branch field or its target lies once the block is laid out.
#[derive(Clone, Copy)]
enum Place {
    Inline(usize),
    OutOfLine(usize),
}

const JMP_REL32: u8 = 0xe9;
const REL32_BYTES: usize = size_of::<i32>();

/// The slow paths of numerical instructions ([`ColdSplit`]), moved after
/// the block's last ordinary instruction behind one jump, before the
/// terminal, whose direct exits must end the code. Inline, each such
/// instruction is its sticky-inexact path alone, falling through to the
/// next instruction; its moved part ends with a jump back to there.
///
/// Consecutive such instructions form a run in which only the first
/// checks FPCR and FPSR: a sticky path changes neither, so the next one
/// holds whenever it is reached inline, and the moved part of one
/// continues in the next one's full path, which is correct in every
/// state. Moved code accesses no guest memory, so the source map entry
/// of the last ordinary instruction that also covers it names no fault.
///
/// [`ColdSplit`]: super::simd::numerical::ColdSplit
#[derive(Default)]
struct OutOfLine {
    code: Code,
    /// rel32 fields with the places they target.
    fixups: Vec<(Place, Place)>,
    /// The jump ending the last moved part and where its instruction ended
    /// inline: the next instruction's full path continues the run if it
    /// starts there.
    open: Option<(usize, usize)>,
}

impl OutOfLine {
    /// Whether an instruction starting at `start` continues a run. Every
    /// instruction emits code (the source map's offsets strictly increase),
    /// so nothing came between.
    fn continues_at(&self, start: usize) -> bool {
        self.open.is_some_and(|(_, end)| end == start)
    }

    /// Move the slow paths of the numerical instruction emitted from
    /// `start` to the end of `code`, which ends its emission.
    fn take(
        &mut self,
        code: &mut Code,
        start: usize,
        split: Option<super::simd::numerical::ColdSplit>,
    ) {
        let base = self.code.len();
        let continued = split.as_ref().filter(|_| self.continues_at(start));
        if let Some((site, end)) = self.open.take() {
            let target = continued.map_or(Place::Inline(end), |split| {
                Place::OutOfLine(base + split.full - split.cold.offset())
            });
            self.fixups.push((Place::OutOfLine(site), target));
        }
        let Some(split) = split else {
            return;
        };
        let end = code.len();
        let inline_end = split.inline_end.offset();
        let cold = split.cold.offset();
        debug_assert_eq!(code[inline_end], JMP_REL32);
        debug_assert_eq!(target_of(code, inline_end + 1), end);
        // A branch from the sticky path past the full path now falls
        // through; one from the moved part to its end takes the jump back.
        let place = |offset: usize, inline: bool| {
            debug_assert!(!(inline_end..cold).contains(&offset));
            if offset < inline_end || (offset == end && inline) {
                Place::Inline(offset.min(inline_end))
            } else {
                Place::OutOfLine(base + offset - cold)
            }
        };
        for &site in &split.crossing {
            let inline = site < inline_end;
            let target = target_of(code, site);
            self.fixups
                .push((place(site, inline), place(target, inline)));
        }
        self.code.append(code.split_off(split.cold));
        let back = self.code.asm().jmp();
        self.open = Some((back.offset(), inline_end));
        code.truncate(split.inline_end);
    }

    /// Lay out the moved code at the end of `code` behind a jump over it.
    fn place(mut self, code: &mut Code) {
        if let Some((site, end)) = self.open.take() {
            self.fixups
                .push((Place::OutOfLine(site), Place::Inline(end)));
        }
        if self.code.is_empty() {
            return;
        }
        let over = code.asm().jmp();
        let base = code.len();
        code.append(self.code);
        code.asm().bind(over);
        let at = |place| match place {
            Place::Inline(offset) => offset,
            Place::OutOfLine(offset) => base + offset,
        };
        for (site, target) in self.fixups {
            super::simd::numerical::resolve(code, at(site), at(target));
        }
    }
}

/// The target of the rel32 field at `site`.
fn target_of(code: &[u8], site: usize) -> usize {
    let field = i32::from_le_bytes(code[site..site + REL32_BYTES].try_into().unwrap());
    (site + REL32_BYTES).wrapping_add_signed(field as isize)
}

/// `mov [rdi+GuestState.nzcv],eax`, which ends each emission after which
/// RAX holds [`super::Rax::Nzcv`].
fn nzcv_store(pinned: bool) -> Code {
    let mut code = Code::new();
    code.set_pinned(pinned);
    match pinned {
        true => super::flag_word::store_captured(&mut code.asm()),
        false => super::store_nzcv(&mut code.asm()),
    }
    code
}
/// The exit word of a side exit that skips `skipped` instructions.
fn side_exit(skipped: usize) -> ExitWord {
    ExitWord {
        kind: ExitKind::Direct,
        skipped: u16::try_from(skipped).expect("bounded block instructions"),
    }
}

/// The direct exits to static successors that [`emit_terminal`] ended
/// `native`'s code with, the target's last, after a conditional branch's
/// fallthrough, and the side exits of the branches in `instructions`, in
/// their order, that follow them.
pub(crate) fn successor_exits(
    native: &NativeBlock,
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    linked: Option<u64>,
) -> Vec<super::chain::DirectExit> {
    use super::chain::{DIRECT_EXIT_BYTES, DirectExit, link_slot};
    let branches: Vec<_> = instructions
        .iter()
        .enumerate()
        .filter_map(|(at, branch)| Some((at + 1, branch.operation.conditional_target()?)))
        .collect();
    let slot = |target| link_slot(linked, target, ExitKind::Direct);
    let side_bytes: usize = branches
        .iter()
        .map(|(_, target)| slot(*target) + DIRECT_EXIT_BYTES)
        .sum();
    // Check failures end the code, after every exit's RET.
    let mut end = super::chain::without_failures(&native.x86_64_code).len() - side_bytes;
    let mut exits = terminal_exits(&native.x86_64_code[..end], terminal, fallthrough, linked);
    for (run, target) in branches {
        let word = side_exit(native.source_map.len() - run);
        let offset = end + slot(target);
        exits.push(DirectExit {
            offset,
            target,
            kind: word.kind,
            skipped: word.skipped,
        });
        end = offset + DIRECT_EXIT_BYTES;
    }
    exits
}

/// The direct exits that end `code`.
fn terminal_exits(
    code: &[u8],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    linked: Option<u64>,
) -> Vec<super::chain::DirectExit> {
    use super::chain::{DIRECT_EXIT_BYTES, DirectExit, direct_exit, link_slot};
    let (target, kind, conditional) = match terminal.map(|(_, terminal)| terminal) {
        None => (fallthrough, ExitKind::Fallthrough, false),
        Some(Terminator::DirectCall(target)) => (*target, ExitKind::Call, false),
        Some(Terminator::Branch(Operation::Branch { target })) => {
            (*target, ExitKind::Direct, false)
        }
        Some(Terminator::Branch(
            Operation::BranchCondition { target, .. }
            | Operation::BranchZero { target, .. }
            | Operation::BranchBit { target, .. },
        )) => (*target, ExitKind::Direct, true),
        // A DC ZVA, DC clean or exclusive completed natively falls through;
        // any other System instruction exits at itself, which the stub check below
        // rejects.
        Some(Terminator::System(request)) => (request.next_pc, ExitKind::Fallthrough, false),
        // So does a numerical operation completed inline; otherwise the same check
        // rejects the exit at the instruction.
        Some(Terminator::FloatingPoint { .. }) => (fallthrough, ExitKind::Fallthrough, false),
        Some(_) => return vec![],
    };
    // The target's exit ends the code, after a conditional's fallthrough's.
    let last = code.len().checked_sub(DIRECT_EXIT_BYTES);
    let before =
        last.and_then(|last| last.checked_sub(link_slot(linked, target, kind) + DIRECT_EXIT_BYTES));
    let candidates = [
        conditional
            .then_some(before)
            .flatten()
            .map(|offset| (offset, fallthrough, ExitKind::Fallthrough)),
        last.map(|offset| (offset, target, kind)),
    ];
    candidates
        .into_iter()
        .flatten()
        .filter_map(|(offset, target, kind)| {
            // An always-true condition emits no fallthrough exit.
            (code[offset..offset + DIRECT_EXIT_BYTES] == direct_exit(target, kind)).then_some(
                DirectExit {
                    offset,
                    target,
                    kind,
                    skipped: 0,
                },
            )
        })
        .collect()
}

/// What a block's terminal is emitted against.
struct TerminalContext {
    fallthrough: GuestAddress,
    native: super::NativeSystem,
    checks: super::MemoryChecks,
    rax: super::Rax,
    target: crate::TargetCpu,
}

fn emit_terminal(
    code: &mut Code,
    source_map: &mut Vec<(GuestAddress, usize)>,
    terminal: Option<&(GuestAddress, Terminator)>,
    context: TerminalContext,
) {
    let TerminalContext {
        fallthrough,
        native,
        checks,
        rax,
        target,
    } = context;
    if let Some((pc, terminal)) = terminal {
        source_map.push((*pc, code.len()));
        code.set_instruction(source_map.len() - 1);
        match terminal {
            Terminator::FloatingPoint { inline } => {
                // A numerical terminal is unexecuted. Ordinary profiles put
                // inline-capable forms in the body; the checked system profile
                // delegates every numerical form to the runtime service. What
                // ends its block on every host completes here on a host with
                // the instructions for it.
                match inline {
                    Some(operation)
                        if super::simd::numerical_terminal_inline(operation, target) =>
                    {
                        super::simd::emit_numerical(code, operation, *pc, target);
                        direct_exit(code, fallthrough, ExitKind::Fallthrough);
                    }
                    _ => direct_exit(code, *pc, ExitKind::FloatingPoint),
                }
            }
            Terminator::Clock(request) => {
                // MRS results and ISB come from the runtime clock service.
                direct_exit(code, request.instruction_pc, ExitKind::Clock);
            }
            Terminator::ThreadRegister(request) => {
                direct_exit(code, request.instruction_pc, ExitKind::ThreadRegister);
            }
            Terminator::Amx(request) => {
                // The runtime runs the operation on the thread's AMX state.
                direct_exit(code, request.instruction_pc, ExitKind::Amx);
            }
            Terminator::PointerAuthentication(request) => {
                // Return to the checked runtime helper with unchanged guest
                // state at this instruction. Never embed keys/helper pointers.
                direct_exit(
                    code,
                    request.instruction_pc,
                    ExitKind::PointerAuthentication,
                );
            }
            Terminator::System(request) => {
                let zero = native.zero_block.zip(super::zero_block::operand(request));
                let clean = super::cache_clean::operand(request)
                    .filter(|(operation, _)| native.cache_clean.contains(*operation));
                let exclusive =
                    super::native_exclusive::operand(request).filter(|_| native.exclusive);
                if let Some(transfer) = exclusive {
                    super::native_exclusive::emit(code, transfer, request, checks);
                } else if let Some((bytes, rt)) = zero {
                    super::zero_block::emit(code, rt, bytes, checks);
                    direct_exit(code, request.next_pc, ExitKind::Fallthrough);
                } else if let Some((_, rt)) = clean {
                    super::cache_clean::emit(code, rt, checks);
                    direct_exit(code, request.next_pc, ExitKind::Fallthrough);
                } else {
                    direct_exit(code, request.instruction_pc, ExitKind::System);
                }
            }
            Terminator::Trap(trap) => {
                // SVC and BRK stop at the trapping instruction; the runtime
                // handles the trap.
                direct_exit(code, trap.instruction_pc, ExitKind::Trap);
            }
            Terminator::DirectCall(target) => {
                super::immediate(code, fallthrough.0);
                super::store(code, Register::X(30));
                direct_exit(code, *target, ExitKind::Call);
            }
            Terminator::Register { source, kind } => {
                load_unless_held(code, *source, rax);
                if *kind == ExitKind::Call {
                    // Capture BLR X30's target before LR is overwritten.
                    code.asm().mov(Size::Qword, Gpr::Rcx, Gpr::Rax);
                    super::immediate(code, fallthrough.0);
                    super::store(code, Register::X(30));
                    code.asm().mov(Size::Qword, Gpr::Rax, Gpr::Rcx);
                }
                exit_kind(code, *kind);
            }
            Terminator::Branch(operation) => match *operation {
                Operation::Branch { target } => direct_exit(code, target, ExitKind::Direct),
                Operation::BranchCondition { target, .. }
                | Operation::BranchZero { target, .. }
                | Operation::BranchBit { target, .. } => {
                    let taken = branch_condition(code, operation, rax);
                    conditional_exit(code, taken, target, fallthrough);
                }
                _ => unreachable!("block decoder restricts branch terminators"),
            },
        }
    } else {
        direct_exit(code, fallthrough, ExitKind::Fallthrough);
    }
}

/// Load a register unless RAX, as `rax` says, already holds it.
fn load_unless_held(code: &mut Code, register: Register, rax: super::Rax) {
    if rax != super::Rax::Guest(register) {
        super::load(code, register);
    }
}

/// Test a conditional branch's condition: the host condition it is taken
/// in, or `None` when it always is. `rax` says what RAX holds.
fn branch_condition(code: &mut Code, operation: &Operation, rax: super::Rax) -> Option<Cond> {
    match *operation {
        Operation::BranchCondition { condition, .. } => {
            let loaded = rax == super::Rax::Nzcv && code.ends_with(&nzcv_store(code.is_pinned()));
            super::condition_holds(code, condition, loaded)
        }
        Operation::BranchZero {
            source,
            width,
            nonzero,
            ..
        } => {
            let size = Size::of(width == crate::aarch64::Width::X64);
            if let Some(host) = code.host(source) {
                code.asm().test(size, host, host);
            } else if let Some(slot) = super::offset(source)
                && rax != super::Rax::Guest(source)
            {
                code.asm().alu_imm8(Alu::Cmp, size, super::frame(slot), 0);
            } else {
                load_unless_held(code, source, rax);
                return Some(super::test_zero(code, width, nonzero));
            }
            Some(if nonzero { Cond::Ne } else { Cond::E })
        }
        Operation::BranchBit {
            source,
            bit,
            nonzero,
            ..
        } => Some(if let Some(host) = code.host(source) {
            super::test_bit_of(code.asm(), host, bit, nonzero)
        } else if let Some(slot) = super::offset(source)
            && rax != super::Rax::Guest(source)
        {
            let byte = super::frame(slot + u32::from(bit / 8));
            code.asm().test_imm(Size::Byte, byte, 1 << (bit % 8));
            if nonzero { Cond::Ne } else { Cond::E }
        } else {
            load_unless_held(code, source, rax);
            super::test_bit(code, bit, nonzero)
        }),
        _ => unreachable!("not a conditional branch"),
    }
}

#[cfg(test)]
mod tests;
