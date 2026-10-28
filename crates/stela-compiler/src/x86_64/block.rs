//! Block control transfers: every branch returns to the dispatcher.
use crate::x86_64::asm::{Asm, Code, Cond, Gpr, Size};
use alloc::vec;
use alloc::vec::Vec;
pub(crate) mod checked_memory;
pub(crate) use super::region::ResidentLoopPlan;

use crate::{
    GuestAddress, NativeBlock,
    aarch64::{Instruction, Operation, Register},
    block::{ExitKind, Terminator},
};

pub(super) fn exit_kind(code: &mut Code, kind: ExitKind) {
    exit_kind_with(&mut code.asm(), kind);
}

/// `mov edx,kind; ret`: the exit to the target in RAX.
pub(super) fn exit_kind_with(asm: &mut Asm, kind: ExitKind) {
    // MOV EDX zero-extends to the ABI's u64.
    asm.mov_imm32(Gpr::Rdx, kind as u32);
    asm.ret();
}

pub(crate) fn direct_exit(code: &mut Code, target: GuestAddress, kind: ExitKind) {
    direct_exit_with(&mut code.asm(), target, kind);
}

/// `movabs rax,target; mov edx,kind; ret`.
pub(super) fn direct_exit_with(asm: &mut Asm, target: GuestAddress, kind: ExitKind) {
    asm.mov_imm64(Gpr::Rax, target.0);
    exit_kind_with(asm, kind);
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
    // Allocated and clean-load regions settle the frame at exits; across
    // an access they may keep guest registers in host registers, which
    // the fault recovery table names, so the engine finds the frame exact
    // at a fault inside one. Their loads carry no SCTLR_ELx.A check. Accesses check the guest range
    // (`x86_64::guest_range`). PEs run concurrently, so atomics stay locked
    // and barriers fence.
    emit_selected(
        instructions,
        terminal,
        fallthrough,
        target,
        RegionPolicy {
            optimize: !checks.alignment,
            fault_table: true,
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
    } = regions;
    let mut fault_recovery = vec![];
    let mut block = super::Emitted::default();
    let code = &mut block.x86_64_code;
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
            let baseline = |checks_at: &dyn Fn(usize) -> super::MemoryChecks| {
                let mut code = Code::new();
                let mut map = vec![];
                let mut fixups = vec![];
                let mut after = held;
                for (index, instruction) in chunk.iter().enumerate() {
                    map.push((instruction.pc, code.len()));
                    after = emit_single(
                        &mut code,
                        None,
                        instruction,
                        &mut fixups,
                        target,
                        checks_at(cursor + index),
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
        after = emit_single(
            code,
            Some(&mut out_of_line),
            instruction,
            &mut fixups,
            target,
            checks_at(cursor),
            held,
        );
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
        fallthrough,
        native,
        checks,
        after.rax,
    );
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

/// One instruction outside the regions, after an emission that left
/// `held`; returns what it leaves. An instruction that first loads the
/// register the previous one just stored from RAX finds it there, and one
/// that reads a vector XMM0 holds may take it from there. With
/// `out_of_line`, numerical instructions move their slow paths there.
fn emit_single(
    code: &mut Code,
    out_of_line: Option<&mut OutOfLine>,
    instruction: &Instruction,
    fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
    target: crate::TargetCpu,
    checks: super::MemoryChecks,
    held: Held,
) -> Held {
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
            let load = super::simd::xmm0_load(vector);
            if code[start..].starts_with(&load) && code.len() > start + load.len() {
                code.remove_instruction(start..start + load.len());
            }
        }
    } else {
        super::emit_instruction(code, instruction, fixups, target, checks);
    }
    // The instruction keeps a non-empty native range for its source map.
    if let super::Rax::Guest(register) = held.rax
        && let Some(load) = super::frame_load(register)
        && code[start..].starts_with(&load)
        && code.len() > start + load.len()
    {
        code.remove_instruction(start..start + load.len());
    }
    let rax = super::rax_after(&instruction.operation);
    debug_assert!(match rax {
        super::Rax::Unknown => true,
        super::Rax::Nzcv => code.ends_with(&nzcv_store()),
        super::Rax::Guest(register) =>
            super::frame_store(register).is_some_and(|store| code.ends_with(&store)),
    });
    let xmm0 = match &instruction.operation {
        Operation::Simd(operand) => super::simd::xmm0_after(operand, &code[start..], held.xmm0),
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
fn nzcv_store() -> Code {
    let mut code = Code::new();
    super::store_nzcv(&mut code.asm());
    code
}
/// The direct exits to static successors that [`emit_terminal`] ended
/// `code` with: the target's last, after a conditional branch's fallthrough.
pub(crate) fn successor_exits(
    code: &[u8],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
) -> Vec<super::chain::DirectExit> {
    use super::chain::{DIRECT_EXIT_BYTES, DirectExit, direct_exit};
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
        // A DC ZVA or DC clean completed natively falls through; any other
        // System instruction exits at itself, which the stub check below
        // rejects.
        Some(Terminator::System(request)) => (request.next_pc, ExitKind::Fallthrough, false),
        Some(_) => return vec![],
    };
    let candidates = [
        conditional.then_some((2, fallthrough, ExitKind::Fallthrough)),
        Some((1, target, kind)),
    ];
    candidates
        .into_iter()
        .flatten()
        .filter_map(|(from_end, target, kind)| {
            let offset = code.len().checked_sub(from_end * DIRECT_EXIT_BYTES)?;
            // An always-true condition emits no fallthrough exit.
            (code[offset..offset + DIRECT_EXIT_BYTES] == direct_exit(target, kind)).then_some(
                DirectExit {
                    offset,
                    target,
                    kind,
                },
            )
        })
        .collect()
}

fn emit_terminal(
    code: &mut Code,
    source_map: &mut Vec<(GuestAddress, usize)>,
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    native: super::NativeSystem,
    checks: super::MemoryChecks,
    rax: super::Rax,
) {
    // The terminal's own load of a register RAX already holds.
    let load = |code: &mut Code, register| {
        if rax != super::Rax::Guest(register) {
            super::load(code, register);
        }
    };
    if let Some((pc, terminal)) = terminal {
        source_map.push((*pc, code.len()));
        match terminal {
            Terminator::FloatingPoint => {
                // A numerical terminal is unexecuted. Ordinary profiles put
                // inline-capable forms in the body; the checked system profile
                // delegates every numerical form to the runtime service.
                direct_exit(code, *pc, ExitKind::FloatingPoint);
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
                if let Some((bytes, rt)) = zero {
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
                load(code, *source);
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
                Operation::BranchCondition { target, condition } => {
                    let taken = super::condition_holds(code, condition, rax == super::Rax::Nzcv);
                    conditional_exit(code, taken, target, fallthrough);
                }
                Operation::BranchZero {
                    target,
                    source,
                    width,
                    nonzero,
                } => {
                    load(code, source);
                    let taken = super::test_zero(code, width, nonzero);
                    conditional_exit(code, Some(taken), target, fallthrough);
                }
                Operation::BranchBit {
                    target,
                    source,
                    bit,
                    nonzero,
                } => {
                    load(code, source);
                    let taken = super::test_bit(code, bit, nonzero);
                    conditional_exit(code, Some(taken), target, fallthrough);
                }
                _ => unreachable!("block decoder restricts branch terminators"),
            },
        }
    } else {
        direct_exit(code, fallthrough, ExitKind::Fallthrough);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{SynchronousTrap, TrapKind};
    use alloc::vec;
    use alloc::vec::Vec;

    /// A conditional exit's branch skips its fallthrough exit, and each of
    /// its instructions counts.
    #[test]
    fn conditional_exits_branch_over_the_fallthrough_exit() {
        let mut code = Code::new();
        conditional_exit(
            &mut code,
            Some(Cond::Ne),
            GuestAddress(0x2000),
            GuestAddress(0x1004),
        );
        let fallthrough =
            super::super::chain::direct_exit(GuestAddress(0x1004), ExitKind::Fallthrough);
        let taken = super::super::chain::direct_exit(GuestAddress(0x2000), ExitKind::Direct);
        assert_eq!(code[..6], [0x0f, 0x85, 16, 0, 0, 0]);
        assert_eq!(code[6..22], fallthrough);
        assert_eq!(code[22..], taken);
        assert_eq!(code.instructions(), 7);
    }

    /// add x10, x10, #4; cmp x10, #0x600; b.ne: the CMP takes X10 from
    /// RAX where the ADD stored it, and the branch tests the NZCV word the
    /// CMP left in EAX, so neither reloads from the frame.
    #[test]
    fn values_left_in_rax_are_not_reloaded() {
        use crate::{Lifter, aarch64::Decoder};
        const LOAD_X10: [u8; 7] = [0x48, 0x8b, 0x87, 0x50, 0, 0, 0];
        const LOAD_NZCV: [u8; 6] = [0x8b, 0x87, 0, 1, 0, 0];
        let pc = GuestAddress(0x1000);
        let instructions: Vec<_> = [0x9100_114a_u32, 0xf118_015f]
            .into_iter()
            .enumerate()
            .map(|(index, word)| {
                Decoder
                    .lift(GuestAddress(pc.0 + 4 * index as u64), word)
                    .unwrap()
            })
            .collect();
        let branch = GuestAddress(pc.0 + 8);
        let terminal = (
            branch,
            Terminator::Branch(Operation::BranchCondition {
                target: pc,
                condition: 1,
            }),
        );
        let code = emit(&instructions, Some(&terminal), GuestAddress(branch.0 + 4)).x86_64_code;
        let count = |pattern: &[u8]| {
            code.windows(pattern.len())
                .filter(|w| *w == pattern)
                .count()
        };
        assert_eq!(count(&LOAD_X10), 1);
        assert_eq!(count(&LOAD_NZCV), 0);
    }

    /// ldr x0, [sp, #8]; ldr x1, [sp, #16]; sub sp, sp, #8; ldr x2, [sp]:
    /// the second access relies on the first one's SP alignment check, and
    /// the third checks SP again after its move by 8.
    #[test]
    fn sp_alignment_is_checked_once_while_it_holds() {
        use crate::{Lifter, aarch64::Decoder};
        let pc = GuestAddress(0x1000);
        let instructions: Vec<_> = [0xf940_07e0_u32, 0xf940_0be1, 0xd100_23ff, 0xf940_03e2]
            .into_iter()
            .enumerate()
            .map(|(index, word)| {
                Decoder
                    .lift(GuestAddress(pc.0 + 4 * index as u64), word)
                    .unwrap()
            })
            .collect();
        let code = emit(&instructions, None, GuestAddress(pc.0 + 16)).x86_64_code;
        let check = super::super::STACK_ALIGNMENT_CHECK;
        let checks = code.windows(check.len()).filter(|w| *w == check).count();
        assert_eq!(checks, 2);
    }

    /// A block whose numerical slow paths are out of line, with runs that
    /// check FPCR and FPSR once and inputs taken from XMM0 where the
    /// previous instruction left them, runs on the host exactly as its
    /// instructions do one at a time with the inline layout: in every
    /// sticky-path state and outside it, through zero-product resumes and
    /// helper exits in mid-run.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn out_of_line_slow_paths_run_as_the_inline_layout() {
        use crate::{GuestState, Lifter, aarch64::Decoder};
        use core::ffi::c_void;
        unsafe extern "C" {
            fn mmap(
                address: *mut c_void,
                bytes: usize,
                protection: i32,
                flags: i32,
                fd: i32,
                offset: i64,
            ) -> *mut c_void;
            fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
            fn munmap(address: *mut c_void, bytes: usize) -> i32;
        }
        #[cfg(target_os = "macos")]
        const MAP_ANONYMOUS: i32 = 0x1000;
        #[cfg(target_os = "linux")]
        const MAP_ANONYMOUS: i32 = 0x20;
        const PAGE: usize = 4096;
        #[repr(C)]
        #[derive(Debug, PartialEq, Eq)]
        struct Exit {
            pc: u64,
            kind: u64,
        }
        /// Guest memory at X1.
        type Memory = [u64; 16];
        fn run(code: &[u8], state: &mut GuestState, memory: &mut Memory) -> Exit {
            let bytes = code.len().next_multiple_of(PAGE);
            state.x[1] = memory.as_mut_ptr() as u64;
            // SAFETY: private anonymous memory, RX after the copy, unmapped
            // after the call; the block touches only `state`, `memory`
            // through X1 and its own stack slots.
            let exit = unsafe {
                let page = mmap(core::ptr::null_mut(), bytes, 3, 2 | MAP_ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
                assert_eq!(mprotect(page, bytes, 5), 0);
                let entry: unsafe extern "sysv64" fn(*mut GuestState) -> Exit =
                    core::mem::transmute(page);
                let exit = entry(state);
                assert_eq!(munmap(page, bytes), 0);
                exit
            };
            state.x[1] = 0;
            exit
        }
        const WORDS: [u32; 45] = [
            0xbd40_0021, // ldr s1,[x1]
            0x1e21_0802, // fmul s2,s0,s1
            0x1e20_2843, // fadd s3,s2,s0
            0x1e20_08e4, // fmul s4,s7,s0
            0x1e24_3865, // fsub s5,s3,s4
            0xbd00_0425, // str s5,[x1,#4]
            0xfd40_0430, // ldr d16,[x1,#8]
            0x1f50_4a26, // fmadd d6,d17,d16,d18
            0x3d80_1826, // str q6,[x1,#96]
            0x1e61_c0d3, // fsqrt d19,d6
            0x3dc0_0435, // ldr q21,[x1,#16]
            0x4e36_d6b4, // fadd v20.4s,v21.4s,v22.4s
            0x6e79_df17, // fmul v23.2d,v24.2d,v25.2d
            0x9100_0400, // add x0,x0,#1
            0x1e21_08a8, // fmul s8,s5,s1
            0x1e20_1909, // fdiv s9,s8,s0
            0x1e71_8a0a, // fnmul d10,d16,d17
            0x4e36_ceba, // fmla v26.4s,v21.4s,v22.4s
            0x3d80_083a, // str q26,[x1,#32]
            0xfd00_182a, // str d10,[x1,#48]
            0x6f00_e41b, // movi v27.2d,#0
            0x0e35_d77c, // fadd v28.2s,v27.2s,v21.2s
            0x3d80_103c, // str q28,[x1,#64]
            0x1e3c_2b9e, // fadd s30,s28,s28
            0x3d80_143e, // str q30,[x1,#80]
            0x3dc0_042c, // ldr q12,[x1,#16]
            0x6e31_a98d, // uminv b13,v12.16b
            0x1e26_01a2, // fmov w2,s13
            0x6e70_a98e, // umaxv h14,v12.8h
            0x0e02_3dc3, // umov w3,v14.h[0]
            0x6e36_8d8f, // cmeq v15.16b,v12.16b,v22.16b
            0x4e01_2de4, // smov x4,v15.b[0]
            0x4eb6_85f0, // add v16.4s,v15.4s,v22.4s
            0x4e08_3e05, // umov x5,v16.d[0]
            0x3dc0_0431, // ldr q17,[x1,#16]
            0x0e01_3e26, // umov w6,v17.b[0]
            0x3dc0_0432, // ldr q18,[x1,#16]
            0x0e02_3e47, // umov w7,v18.h[0]
            0x3dc0_0433, // ldr q19,[x1,#16]
            0x9e66_0268, // fmov x8,d19
            0x3dc0_0435, // ldr q21,[x1,#16]
            0x6e36_8d94, // cmeq v20.16b,v12.16b,v22.16b
            0x1e26_0289, // fmov w9,s20
            0x4eb6_8697, // add v23.4s,v20.4s,v22.4s
            0x3d80_1c37, // str q23,[x1,#112]
        ];
        const IXC: u32 = 1 << 4;
        const NEP: u32 = 1 << 2;
        const ROUND_UP: u32 = 1 << 22;
        const ROUND_TO_ZERO: u32 = 3 << 22;
        const FZ: u32 = 1 << 24;
        const DN: u32 = 1 << 25;
        const UPPER_GARBAGE: u64 = 0xa5a5_5a5a_c3c3_3c3c;
        let pc = GuestAddress(0x1000);
        let instructions: Vec<_> = WORDS
            .iter()
            .enumerate()
            .map(|(index, &word)| {
                Decoder
                    .lift(GuestAddress(pc.0 + 4 * index as u64), word)
                    .unwrap()
            })
            .collect();
        let fallthrough = GuestAddress(pc.0 + 4 * WORDS.len() as u64);
        let single = |s: f32| u64::from(s.to_bits()) | UPPER_GARBAGE << 32;
        let lanes = |values: [f32; 4]| {
            let bits = values.map(|value| u64::from(value.to_bits()));
            [bits[0] | bits[1] << 32, bits[2] | bits[3] << 32]
        };
        let initial = |s7: f32, s1: f32, d18: f64| {
            let mut state = GuestState::default();
            for (index, vector) in state.v.iter_mut().enumerate() {
                *vector = [UPPER_GARBAGE.rotate_left(index as u32), UPPER_GARBAGE];
            }
            state.v[0][0] = single(1.1);
            state.v[7][0] = single(s7);
            for (index, value) in [(17, 2.7f64), (18, d18)] {
                state.v[index][0] = value.to_bits();
            }
            state.v[22] = lanes([0.7, 5.5, -1.9, 7e3]);
            state.v[24] = [1.7f64.to_bits(), (-0.3f64).to_bits()];
            state.v[25] = [2.9f64.to_bits(), 1e10f64.to_bits()];
            let mut memory: Memory = [UPPER_GARBAGE; 16];
            memory[0] = single(s1);
            memory[1] = 1.3f64.to_bits();
            [memory[2], memory[3]] = lanes([1.5, -2.25, 3.1, 1e-3]);
            (state, memory)
        };
        for target in [crate::TargetCpu::Baseline, crate::TargetCpu::detect()] {
            let block = emit_for_target(
                &instructions,
                None,
                fallthrough,
                target,
                super::super::MemoryChecks::DEFAULT,
            );
            // Normal values complete; an exact zero product resumes; a subnormal one takes the
            // helper mid-run, as does the root of a negative or an infinite
            // addend; an infinite input takes it at once.
            for (s7, s1, d18) in [
                (2.0, 3.3, 0.9),
                (0.0, 3.3, 0.9),
                (-0.0, 3.3, 0.9),
                (1e-40, 3.3, 0.9),
                (0.0, 3.3, -100.0),
                (0.0, 3.3, f64::INFINITY),
                (0.0, f32::INFINITY, 0.9),
            ] {
                for (fpcr, fpsr) in [
                    (0, IXC),
                    (0, 0),
                    (ROUND_TO_ZERO, IXC),
                    (ROUND_UP, 0),
                    (NEP, IXC),
                    (DN, IXC),
                    (FZ, IXC),
                ] {
                    let (mut state, mut memory) = initial(s7, s1, d18);
                    state.fpcr = fpcr;
                    state.fpsr = fpsr;
                    let (mut expected, mut expected_memory) = (state.clone(), memory);
                    let mut expected_exit = None;
                    // The state and memory before each instruction.
                    let mut before = vec![];
                    for instruction in &instructions {
                        before.push((instruction.pc.0, expected.clone(), expected_memory));
                        let next = GuestAddress(instruction.pc.0 + 4);
                        let mut code = Code::new();
                        match &instruction.operation {
                            Operation::FloatingPoint(operand) => {
                                super::super::simd::emit_numerical(
                                    &mut code,
                                    operand,
                                    instruction.pc,
                                    target,
                                )
                            }
                            _ => super::super::emit_instruction(
                                &mut code,
                                instruction,
                                &mut vec![],
                                target,
                                super::super::MemoryChecks::DEFAULT,
                            ),
                        }
                        direct_exit(&mut code, next, ExitKind::Fallthrough);
                        let exit = run(&code, &mut expected, &mut expected_memory);
                        if exit.pc != next.0 || exit.kind != ExitKind::Fallthrough as u64 {
                            expected_exit = Some(exit);
                            break;
                        }
                    }
                    let expected_exit = expected_exit.unwrap_or(Exit {
                        pc: fallthrough.0,
                        kind: ExitKind::Fallthrough as u64,
                    });
                    let exit = run(&block.x86_64_code, &mut state, &mut memory);
                    let case = (target, s7, s1, d18, fpcr, fpsr);
                    // With FPSR.IXC clear, the first full path of a run may
                    // set it; the run's later instructions then take full
                    // paths too, where one at a time they take sticky ones.
                    // A full path sends a zero input to the helper, where
                    // a sticky product resumes.
                    if exit != expected_exit && fpcr == 0 && fpsr & IXC == 0 {
                        assert_eq!(exit.kind, ExitKind::FloatingPoint as u64, "{case:?}");
                        assert!(exit.pc < expected_exit.pc, "{case:?}");
                        let (_, at_exit, memory_at_exit) =
                            before.iter().find(|(pc, ..)| *pc == exit.pc).unwrap();
                        assert_eq!(&state, at_exit, "{case:?}");
                        assert_eq!(&memory, memory_at_exit, "{case:?}");
                        continue;
                    }
                    assert_eq!(exit, expected_exit, "{case:?}");
                    assert_eq!(state, expected, "{case:?}");
                    assert_eq!(memory, expected_memory, "{case:?}");
                }
            }
        }
    }

    #[test]
    fn clock_exit_requests_runtime_service_without_counter_or_guest_writes() {
        use crate::block::{ClockInstruction, ClockOperation};
        for operation in [
            ClockOperation::InstructionSynchronization,
            ClockOperation::ReadVirtualCounter { destination: 0 },
            ClockOperation::ReadVirtualCounter { destination: 31 },
        ] {
            let pc = GuestAddress(0x123456789000);
            let request = ClockInstruction {
                operation,
                instruction_pc: pc,
                next_pc: GuestAddress(pc.0 + 4),
            };
            let native = emit(
                &[],
                Some(&(pc, Terminator::Clock(request))),
                request.next_pc,
            );
            let mut expected = vec![0x48, 0xb8];
            expected.extend(pc.0.to_le_bytes());
            expected.extend([0xba, 7, 0, 0, 0, 0xc3]);
            // No RDTSC, host helper address, guessed counter, destination write
            // or placeholder ISB: only the checked runtime service may complete.
            assert_eq!(native.x86_64_code, expected);
            assert_eq!(native.source_map, [(pc, 0)]);
        }
    }

    #[test]
    fn pac_helper_exit_has_no_guest_writes_or_embedded_service_address() {
        use crate::block::{PointerAuthentication, decode_pointer_authentication};
        let fixed_words = [
            0xd503211f, 0xd503215f, 0xd503219f, 0xd50321df, 0xd503231f, 0xd503233f, 0xd503235f,
            0xd503237f, 0xd503239f, 0xd50323bf, 0xd50323df, 0xd50323ff, 0xd50320ff, 0xd65f0bff,
            0xd65f0fff, 0xdac143f1, 0xdac147f1,
        ];
        let integer_words = (0..8).flat_map(|op| {
            [
                0xdac10000 | (op << 10) | (16 << 5) | 17,
                0xdac123e0 | (op << 10) | 17,
            ]
        });
        let words: Vec<_> = fixed_words.into_iter().chain(integer_words).collect();
        assert_eq!(words.len(), 33);
        for word in words {
            let operation = decode_pointer_authentication(GuestAddress(0x1000), word)
                .unwrap()
                .unwrap()
                .operation;
            let pc = GuestAddress(0x123456789000);
            let request = PointerAuthentication {
                operation,
                instruction_pc: pc,
                next_pc: GuestAddress(pc.0 + 4),
            };
            let native = emit(
                &[],
                Some(&(pc, Terminator::PointerAuthentication(request))),
                request.next_pc,
            );
            let mut expected = vec![0x48, 0xb8];
            expected.extend(pc.0.to_le_bytes());
            expected.extend([0xba, 6, 0, 0, 0, 0xc3]);
            // Only the SysV return registers RAX/RDX are touched, including for
            // RETAB: the runtime must keep signed LR while authenticating target.
            assert_eq!(native.x86_64_code, expected);
            assert_eq!(native.source_map, [(pc, 0)]);
        }
    }

    #[test]
    fn ordinary_native_prefix_is_preserved_before_pac_boundary() {
        use crate::{
            Lifter,
            aarch64::Decoder,
            block::{PointerAuthentication, PointerAuthenticationOperation},
        };
        let base = GuestAddress(0x4000);
        let instruction = Decoder.lift(base, 0xd2800020).unwrap();
        let pc = GuestAddress(base.0 + 4);
        let ordinary = emit(core::slice::from_ref(&instruction), None, pc);
        let request = PointerAuthentication {
            operation: PointerAuthenticationOperation::SignIbSp,
            instruction_pc: pc,
            next_pc: GuestAddress(pc.0 + 4),
        };
        let native = emit(
            &[instruction],
            Some(&(pc, Terminator::PointerAuthentication(request))),
            request.next_pc,
        );
        assert_eq!(
            &native.x86_64_code[..ordinary.x86_64_code.len() - 16],
            &ordinary.x86_64_code[..ordinary.x86_64_code.len() - 16]
        );
        assert_eq!(native.source_map.len(), 2);
        assert_eq!(native.source_map[1].0, pc);
        assert_eq!(
            &native.x86_64_code[native.x86_64_code.len() - 6..],
            &[0xba, 6, 0, 0, 0, 0xc3]
        );
    }

    #[test]
    fn trap_exit_uses_instruction_pc_and_only_native_return_scratch_registers() {
        for kind in [TrapKind::SupervisorCall, TrapKind::SoftwareBreakpoint] {
            let pc = GuestAddress(0x123456789000);
            let trap = SynchronousTrap {
                kind,
                immediate: 0x80,
                instruction_pc: pc,
                exception_return_pc: if kind == TrapKind::SupervisorCall {
                    GuestAddress(pc.0 + 4)
                } else {
                    pc
                },
            };
            let native = emit(
                &[],
                Some(&(pc, Terminator::Trap(trap))),
                GuestAddress(pc.0 + 4),
            );
            let mut expected = vec![0x48, 0xb8]; // movabs rax,instruction_pc
            expected.extend(pc.0.to_le_bytes());
            expected.extend([0xba, 5, 0, 0, 0, 0xc3]); // mov edx,Trap; ret
            assert_eq!(native.x86_64_code, expected);
            assert_eq!(native.source_map, [(pc, 0)]);
        }
    }

    /// Region census of real code, run by hand:
    /// `STELA_CENSUS=PATH:FILE_OFFSET:BYTES:BASE` names a raw image, the
    /// executable range to sweep and the guest address of file offset 0
    /// (all hexadecimal). It sweeps maximal straight-line runs the decoder
    /// lifts, replays the region selection of [`emit_selected`] on each,
    /// with its cost gates, and prints the summed allocator statistics, the
    /// share of instructions each emission path takes, and the categories
    /// of the instructions that end a region or run outside one.
    /// `STELA_CENSUS_SYSTEM=1` replays system mode, whose accesses check
    /// the guest range (`guest_range`), instead of the process profiles.
    #[test]
    #[ignore = "manual: opt-in"]
    fn region_census_of_real_code() {
        use crate::Lifter;
        use std::collections::BTreeMap;
        let spec = std::env::var("STELA_CENSUS").expect("STELA_CENSUS=PATH:OFFSET:BYTES:BASE");
        let system = std::env::var_os("STELA_CENSUS_SYSTEM").is_some();
        let parts: Vec<&str> = spec.split(':').collect();
        let hex = |s: &str| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
        let image = std::fs::read(parts[0]).unwrap();
        let (offset, bytes, base) = (hex(parts[1]), hex(parts[2]), hex(parts[3]));
        let text = &image[offset as usize..(offset + bytes) as usize];
        let category = |op: &Operation| {
            let name = std::format!("{op:?}");
            let end = name.find(['(', ' ', '{']).unwrap_or(name.len());
            std::string::String::from(&name[..end])
        };
        let mut stats = super::super::region::AllocationStats::default();
        let add = |total: &mut super::super::region::AllocationStats,
                   s: &super::super::region::AllocationStats| {
            total.state_loads += s.state_loads;
            total.pressure_stores += s.pressure_stores;
            total.exit_stores += s.exit_stores;
            total.lifetime_stores += s.lifetime_stores;
            total.commits += s.commits;
            total.native_instructions += s.native_instructions;
            total.load_boundary_stores += s.load_boundary_stores;
            total.clean_loads += s.clean_loads;
            total.pair_loads += s.pair_loads;
            total.stores += s.stores;
            total.flag_loads += s.flag_loads;
            total.flag_stores += s.flag_stores;
        };
        let (mut allocated, mut clean, mut rejected, mut plain, mut runs) =
            (0usize, 0usize, 0usize, 0usize, 0usize);
        let (mut region_bytes, mut plain_bytes) = (0usize, 0usize);
        let mut outside: BTreeMap<std::string::String, usize> = BTreeMap::new();
        let mut breakers: BTreeMap<std::string::String, usize> = BTreeMap::new();
        let mut run: Vec<Instruction> = vec![];
        let mut flush = |run: &mut Vec<Instruction>| {
            if run.is_empty() {
                return;
            }
            runs += 1;
            let ranges = if system {
                super::super::guest_range::checks(run)
            } else {
                vec![false; run.len()]
            };
            let checks_at = |index: usize| super::super::MemoryChecks {
                guest_range: ranges[index],
                ..super::super::MemoryChecks::DEFAULT
            };
            let mut cursor = 0;
            while cursor < run.len() {
                let rest = &run[cursor..];
                // Replays the system-mode selection with its cost gates: a
                // rejected chunk is emitted as baseline and skipped whole.
                let baseline = |count: usize| {
                    let mut code = Code::new();
                    let mut fixups = vec![];
                    for (index, instruction) in rest[..count].iter().enumerate() {
                        super::super::emit_instruction(
                            &mut code,
                            instruction,
                            &mut fixups,
                            crate::TargetCpu::Baseline,
                            checks_at(cursor + index),
                        );
                    }
                    (code, fixups.is_empty())
                };
                let allocated_region = super::super::region::emit_allocated_prefix(rest)
                    .ok()
                    .flatten()
                    .filter(|region| {
                        let (code, no_fixups) = baseline(region.consumed_instructions);
                        no_fixups && super::super::region::admits_allocated(region, &code)
                    });
                let clean_region = || {
                    super::super::region::emit_clean_load_prefix_with(
                        rest,
                        super::super::MemoryChecks::DEFAULT,
                        system,
                        system.then(|| &ranges[cursor..]),
                    )
                    .ok()
                    .filter(|region| region.consumed_instructions != 0)
                };
                if let Some(region) = allocated_region {
                    allocated += region.consumed_instructions;
                    region_bytes += region.code.len();
                    add(&mut stats, &region.stats);
                    cursor += region.consumed_instructions;
                } else if let Some(region) = clean_region() {
                    let (code, _) = baseline(region.consumed_instructions);
                    if super::super::region::admits_ordinary(&region, &code) {
                        clean += region.consumed_instructions;
                        region_bytes += region.code.len();
                        add(&mut stats, &region.stats);
                    } else {
                        rejected += region.consumed_instructions;
                        plain_bytes += code.len();
                    }
                    cursor += region.consumed_instructions;
                } else {
                    let instruction = &run[cursor];
                    let detail = match &instruction.operation {
                        Operation::Memory {
                            transfer,
                            bytes,
                            mode,
                            base,
                            ..
                        }
                        | Operation::MemoryPair {
                            transfer,
                            bytes,
                            mode,
                            base,
                            ..
                        } => std::format!(
                            "{} {transfer:?} {bytes} {mode:?} {}",
                            category(&instruction.operation),
                            if *base == Register::Sp { "sp" } else { "x" }
                        ),
                        operation => category(operation),
                    };
                    *outside.entry(detail).or_default() += 1;
                    let mut code = Code::new();
                    let mut fixups = vec![];
                    if let Operation::FloatingPoint(operand) = &instruction.operation {
                        super::super::simd::emit_numerical(
                            &mut code,
                            operand,
                            instruction.pc,
                            crate::TargetCpu::Baseline,
                        );
                    } else if super::super::validate_target_with(
                        instruction,
                        crate::TargetCpu::Baseline,
                        checks_at(cursor),
                    )
                    .is_ok()
                    {
                        super::super::emit_instruction(
                            &mut code,
                            instruction,
                            &mut fixups,
                            crate::TargetCpu::Baseline,
                            checks_at(cursor),
                        );
                    }
                    plain_bytes += code.len();
                    plain += 1;
                    cursor += 1;
                    continue;
                }
                if let Some(next) = run.get(cursor) {
                    *breakers.entry(category(&next.operation)).or_default() += 1;
                }
            }
            run.clear();
        };
        for (index, word) in text.as_chunks::<4>().0.iter().enumerate() {
            let pc = GuestAddress(base + offset + 4 * index as u64);
            match crate::aarch64::Decoder.lift(pc, u32::from_le_bytes(*word)) {
                Ok(instruction)
                    if !category(&instruction.operation).starts_with("Branch")
                        && category(&instruction.operation) != "Return" =>
                {
                    run.push(instruction);
                    if run.len() == crate::block::MAX_BLOCK_INSTRUCTIONS {
                        flush(&mut run);
                    }
                }
                _ => flush(&mut run),
            }
        }
        flush(&mut run);
        let top = |map: &BTreeMap<std::string::String, usize>| {
            let mut v: Vec<_> = map.iter().collect();
            v.sort_by(|a, b| b.1.cmp(a.1));
            v.into_iter()
                .take(40)
                .map(|(k, n)| std::format!("{k} {n}"))
                .collect::<Vec<_>>()
        };
        std::println!(
            "runs {runs} allocated {allocated} clean {clean} rejected {rejected} plain {plain}"
        );
        std::println!("region bytes {region_bytes} plain bytes {plain_bytes}");
        std::println!("{stats:?}");
        std::println!("outside {:?}", top(&outside));
        std::println!("breakers {:?}", top(&breakers));
    }
}
