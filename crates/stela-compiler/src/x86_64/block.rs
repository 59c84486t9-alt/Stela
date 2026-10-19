//! Block control transfers: every branch returns to the dispatcher.
use alloc::vec;
use alloc::vec::Vec;
pub(crate) mod checked_memory;
pub(crate) mod el1_m0;
pub(crate) use super::region::ResidentLoopPlan;

use crate::{
    GuestAddress, NativeBlock,
    aarch64::{Instruction, Operation, Register, Width},
    block::{ExitKind, Terminator},
};

pub(super) fn exit_kind(code: &mut Vec<u8>, kind: ExitKind) {
    code.push(0xba); // mov edx,kind: zero-extends to the ABI's u64
    code.extend((kind as u32).to_le_bytes());
    code.push(0xc3);
}

pub(super) fn direct_exit(code: &mut Vec<u8>, target: GuestAddress, kind: ExitKind) {
    code.extend(super::chain::direct_exit(target, kind));
}

fn conditional_exit(
    code: &mut Vec<u8>,
    opcode: Option<u8>,
    target: GuestAddress,
    fallthrough: GuestAddress,
) {
    if let Some(opcode) = opcode {
        code.extend([0x0f, opcode]);
        let fixup = code.len();
        code.extend([0; 4]);
        direct_exit(code, fallthrough, ExitKind::Fallthrough);
        // The taken branch skips the complete fallthrough exit. Both paths
        // leave saved NZCV untouched regardless of host predicate evaluation.
        let relative = (code.len() - fixup - 4) as i32;
        code[fixup..fixup + 4].copy_from_slice(&relative.to_le_bytes());
    }
    direct_exit(code, target, ExitKind::Direct);
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
        true,
        super::MemoryChecks::DEFAULT,
        super::NativeSystem::NONE,
    )
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
        false,
        checks,
        super::NativeSystem::NONE,
    )
}

/// [`emit_for_target`] for the system-mode engine, which may also complete
/// a terminal System instruction natively and fall through: DC ZVA by
/// zeroing its block (`x86_64::zero_block`) and DC CVAC, DC CVAU and DC
/// CIVAC by reading the byte at Xt (`x86_64::cache_clean`).
pub(crate) fn emit_system_mode(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: crate::TargetCpu,
    checks: super::MemoryChecks,
    native: super::NativeSystem,
) -> NativeBlock {
    // Allocated and clean-load regions settle the frame before every
    // access and exit, so a fault inside one finds it exact. Their loads
    // carry no SCTLR_ELx.A check. Accesses check the guest range
    // (`x86_64::guest_range`). One PE runs at a time, so ordering and
    // atomicity need no locked instructions or fences.
    emit_selected(
        instructions,
        terminal,
        fallthrough,
        target,
        !checks.alignment,
        super::MemoryChecks {
            guest_range: true,
            single_agent: true,
            ..checks
        },
        native,
    )
}

fn emit_selected(
    instructions: &[Instruction],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: crate::TargetCpu,
    optimize_regions: bool,
    checks: super::MemoryChecks,
    native: super::NativeSystem,
) -> NativeBlock {
    let mut block = NativeBlock {
        x86_64_code: vec![],
        source_map: vec![],
    };
    let code = &mut block.x86_64_code;
    let mut fixups = vec![];
    // The DIT audit covers each instruction's own lowering, not the
    // register-allocated and clean-load regions' recipes.
    let optimize_regions = optimize_regions && !target.data_independent_timing();
    // Which accesses check the guest range (`guest_range`), and each
    // instruction's checks.
    let ranges = if checks.guest_range {
        super::guest_range::checks(instructions)
    } else {
        vec![]
    };
    let ranges = checks.guest_range.then_some(&ranges[..]);
    let checks_at = |index: usize| super::MemoryChecks {
        guest_range: ranges.is_some_and(|ranges| ranges[index]),
        ..checks
    };
    let mut cursor = 0;
    while cursor < instructions.len() {
        // Build the new candidate privately. Rejection leaves both cursor and
        // output untouched, so the legacy clean-load chunk partition is exact.
        if optimize_regions
            && let Ok(Some(region)) = super::region::emit_allocated_prefix(&instructions[cursor..])
        {
            let count = region.consumed_instructions;
            let mut baseline = vec![];
            let mut candidate_fixups = vec![];
            for (index, instruction) in instructions[cursor..cursor + count].iter().enumerate() {
                super::emit_instruction(
                    &mut baseline,
                    instruction,
                    &mut candidate_fixups,
                    target,
                    checks_at(cursor + index),
                );
            }
            if candidate_fixups.is_empty() && super::region::admits_allocated(&region, &baseline) {
                let offset = code.len();
                block
                    .source_map
                    .extend(region.source_map.iter().map(|(pc, at)| (*pc, offset + at)));
                code.extend(region.code);
                cursor += count;
                continue;
            }
        }
        if optimize_regions
            && let Ok(region) = super::region::emit_clean_load_prefix(
                &instructions[cursor..],
                ranges.map(|ranges| &ranges[cursor..]),
            )
            && region.consumed_instructions != 0
        {
            let count = region.consumed_instructions;
            let mut baseline_code = vec![];
            let mut baseline_map = vec![];
            let mut baseline_fixups = vec![];
            for (index, instruction) in instructions[cursor..cursor + count].iter().enumerate() {
                baseline_map.push((instruction.pc, baseline_code.len()));
                super::emit_instruction(
                    &mut baseline_code,
                    instruction,
                    &mut baseline_fixups,
                    target,
                    checks_at(cursor + index),
                );
            }
            debug_assert!(baseline_fixups.is_empty());
            let offset = code.len();
            if super::region::admits_ordinary(&region, &baseline_code) {
                block
                    .source_map
                    .extend(region.source_map.iter().map(|(pc, at)| (*pc, offset + at)));
                code.extend(region.code);
            } else {
                // Reject the complete eligible chunk. Rescanning its suffix
                // could bypass the measured cost gate with a different shape.
                block
                    .source_map
                    .extend(baseline_map.iter().map(|(pc, at)| (*pc, offset + at)));
                code.extend(baseline_code);
            }
            // Each region wrote back the full register frame, so what follows
            // sees the ordinary direct-RAM ABI.
            cursor += count;
            continue;
        }
        let instruction = &instructions[cursor];
        block.source_map.push((instruction.pc, code.len()));
        if let Operation::FloatingPoint(operand) = &instruction.operation {
            super::simd::emit_numerical(code, operand, instruction.pc, target);
        } else {
            super::emit_instruction(code, instruction, &mut fixups, target, checks_at(cursor));
        }
        cursor += 1;
    }
    debug_assert!(
        fixups.is_empty(),
        "ordinary instruction prefix cannot branch"
    );
    emit_terminal(
        code,
        &mut block.source_map,
        terminal,
        fallthrough,
        target,
        native,
    );
    block
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
    code: &mut Vec<u8>,
    source_map: &mut Vec<(GuestAddress, usize)>,
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: crate::TargetCpu,
    native: super::NativeSystem,
) {
    if let Some((pc, terminal)) = terminal {
        source_map.push((*pc, code.len()));
        match terminal {
            Terminator::FloatingPoint(operand) => {
                super::simd::emit_numerical(code, operand, *pc, target);
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
                    super::zero_block::emit(code, rt, bytes);
                    direct_exit(code, request.next_pc, ExitKind::Fallthrough);
                } else if let Some((_, rt)) = clean {
                    super::cache_clean::emit(code, rt);
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
                super::load(code, *source);
                if *kind == ExitKind::Call {
                    // Capture BLR X30's target before LR is overwritten.
                    code.extend([0x48, 0x89, 0xc1]); // mov rcx,rax
                    super::immediate(code, fallthrough.0);
                    super::store(code, Register::X(30));
                    code.extend([0x48, 0x89, 0xc8]); // mov rax,rcx
                }
                exit_kind(code, *kind);
            }
            Terminator::Branch(operation) => match *operation {
                Operation::Branch { target } => direct_exit(code, target, ExitKind::Direct),
                Operation::BranchCondition { target, condition } => {
                    let opcode = super::condition(code, condition);
                    conditional_exit(code, opcode, target, fallthrough);
                }
                Operation::BranchZero {
                    target,
                    source,
                    width,
                    nonzero,
                } => {
                    super::load(code, source);
                    if width == Width::X64 {
                        code.push(0x48);
                    }
                    code.extend([0x85, 0xc0]); // test (e/r)ax,(e/r)ax
                    conditional_exit(
                        code,
                        Some(if nonzero { 0x85 } else { 0x84 }),
                        target,
                        fallthrough,
                    );
                }
                Operation::BranchBit {
                    target,
                    source,
                    bit,
                    nonzero,
                } => {
                    super::load(code, source);
                    code.extend([0x48, 0x0f, 0xba, 0xe0, bit]); // bt rax,bit
                    conditional_exit(
                        code,
                        Some(if nonzero { 0x82 } else { 0x83 }),
                        target,
                        fallthrough,
                    );
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
    #[ignore = "measurement over a local image"]
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
                single_agent: system,
                ..super::super::MemoryChecks::DEFAULT
            };
            let mut cursor = 0;
            while cursor < run.len() {
                let rest = &run[cursor..];
                // Replays the system-mode selection with its cost gates: a
                // rejected chunk is emitted as baseline and skipped whole.
                let baseline = |count: usize| {
                    let mut code = vec![];
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
                    super::super::region::emit_clean_load_prefix(
                        rest,
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
                    let mut code = vec![];
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
