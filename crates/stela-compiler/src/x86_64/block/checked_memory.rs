//! Blocks whose memory accesses go through the checked memory service.
use crate::{
    CompileError, GuestAddress, NativeBlock, TargetCpu,
    aarch64::Instruction,
    block::{Terminator, memory::CheckedOperation},
    scalable_context,
    x86_64::Emitted,
};
use alloc::vec::Vec;

pub(crate) fn emit(
    instructions: &[(GuestAddress, CheckedOperation)],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: TargetCpu,
    register_regions: bool,
    mut profile: Option<&mut crate::block::profile::CompileProfile>,
) -> Result<NativeBlock, CompileError> {
    let mut block = Emitted {
        x86_64_code: scalable_context::context_wrapper(),
        source_map: Vec::new(),
    };
    let mut fixups = Vec::new();
    // DIT qualification covers the individual recipes, not region allocation.
    let register_regions = register_regions && !target.data_independent_timing();
    let mut cursor = 0;
    while cursor < instructions.len() {
        if register_regions && instructions[cursor].1.ordinary_instruction().is_some() {
            // Decode once in CheckedPlan; clone each bounded typed span once,
            // rather than reconsidering an unselected suffix at every word.
            let mut span = Vec::new();
            for (pc, operation) in &instructions[cursor..] {
                let Some(instruction) = operation.ordinary_instruction() else {
                    break;
                };
                if instruction.pc != *pc {
                    return Err(CompileError("checked instruction PC differs".into()));
                }
                span.push(instruction.clone());
                if span.len() == crate::x86_64::region::MAX_INSTRUCTIONS {
                    break;
                }
            }
            emit_register_span(&mut block, &span, target, cursor, profile.as_deref_mut())?;
            cursor += span.len();
            continue;
        }
        let (pc, instruction) = &instructions[cursor];
        block.source_map.push((*pc, block.x86_64_code.len()));
        instruction.emit(&mut block.x86_64_code, *pc, target, &mut fixups)?;
        if let Some(profile) = profile.as_deref_mut()
            && let Some((recipe, traffic)) = instruction.profile_success_traffic()
        {
            profile
                .register_spans
                .push(crate::block::profile::RegisterSpan {
                    source_start: cursor,
                    source_end: cursor + 1,
                    recipe,
                    traffic,
                });
        }
        cursor += 1;
    }
    if !fixups.is_empty() {
        return Err(CompileError(
            "checked GPR prefix unexpectedly branches".into(),
        ));
    }
    super::emit_terminal(
        &mut block.x86_64_code,
        &mut block.source_map,
        terminal,
        fallthrough,
        crate::x86_64::NativeSystem::NONE,
        crate::x86_64::MemoryChecks::DEFAULT,
        crate::x86_64::Rax::Unknown,
    );
    if let Some(profile) = profile
        && let Some((_, terminal)) = terminal
        && let Some(traffic) = crate::block::profile::terminal_traffic(terminal)
    {
        profile
            .register_spans
            .push(crate::block::profile::RegisterSpan {
                source_start: instructions.len(),
                source_end: instructions.len() + 1,
                recipe: crate::block::profile::RegisterRecipe::Terminal,
                traffic,
            });
    }
    Ok(block.into_native())
}

fn emit_register_span(
    block: &mut Emitted,
    instructions: &[Instruction],
    target: TargetCpu,
    source_start: usize,
    mut profile: Option<&mut crate::block::profile::CompileProfile>,
) -> Result<(), CompileError> {
    use crate::x86_64::{MemoryChecks, emit_instruction, region};
    let mut cursor = 0;
    while cursor < instructions.len() {
        let remaining = &instructions[cursor..];
        let (candidate, allocated) = match region::emit_allocated_prefix(remaining) {
            Ok(Some(region)) => (Some(region), true),
            _ => (region::emit_register_prefix(remaining).ok(), false),
        };
        let count = candidate
            .as_ref()
            .map_or(1, |region| region.consumed_instructions.max(1));
        let mut baseline = Emitted::default();
        let mut fixups = Vec::new();
        for instruction in &remaining[..count] {
            baseline
                .source_map
                .push((instruction.pc, baseline.x86_64_code.len()));
            emit_instruction(
                &mut baseline.x86_64_code,
                instruction,
                &mut fixups,
                target,
                MemoryChecks::DEFAULT,
            );
        }
        if !fixups.is_empty() {
            return Err(CompileError(
                "checked register span unexpectedly branches".into(),
            ));
        }
        let offset = block.x86_64_code.len();
        if let Some(region) = candidate
            && region.fault_recovery.is_empty()
            && if allocated {
                region::admits_allocated(&region, &baseline.x86_64_code)
            } else {
                region::admits_ordinary(&region, &baseline.x86_64_code)
            }
        {
            if let Some(profile) = profile.as_deref_mut() {
                use crate::block::profile::{RegisterRecipe, RegisterSpan, RegisterTraffic};
                profile.register_spans.push(RegisterSpan {
                    source_start: source_start + cursor,
                    source_end: source_start + cursor + count,
                    recipe: if allocated {
                        RegisterRecipe::Allocated
                    } else {
                        RegisterRecipe::Retained
                    },
                    traffic: RegisterTraffic::region(&region.stats),
                });
            }
            block.source_map.extend(
                region
                    .source_map
                    .into_iter()
                    .map(|(pc, at)| (pc, offset + at)),
            );
            block.x86_64_code.append(region.code);
        } else {
            // A rejected candidate consumes its exact original span. Trying
            // shorter suffixes could evade the candidate's measured cost gate.
            block.source_map.extend(
                baseline
                    .source_map
                    .into_iter()
                    .map(|(pc, at)| (pc, offset + at)),
            );
            block.x86_64_code.append(baseline.x86_64_code);
        }
        cursor += count;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockProfile, CheckedMemoryProfile, CompilationPlan, Features};
    use alloc::vec;

    const PC: GuestAddress = GuestAddress(0x4000);
    const ADD_X0: u32 = 0x9100_0400;
    const LOAD_BYTE: u32 = 0x3940_0121; // LDRB W1,[X9].
    const RET: u32 = 0xd65f_03c0;

    #[test]
    fn shared_register_regions_settle_before_exact_checked_callbacks_and_terminal() {
        for recipe in [
            CheckedMemoryProfile::SpAlignmentEnabled,
            CheckedMemoryProfile::SpAlignmentDisabled,
        ] {
            let words = [
                ADD_X0, ADD_X0, ADD_X0, ADD_X0, LOAD_BYTE, ADD_X0, ADD_X0, ADD_X0, ADD_X0, RET,
            ];
            let source: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
            let baseline = CompilationPlan::new(
                &source,
                PC,
                &crate::Options::new(
                    BlockProfile::ORDINARY.with_checked_memory(recipe),
                    TargetCpu::Baseline,
                ),
            )
            .unwrap();
            let selected = CompilationPlan::new(
                &source,
                PC,
                &crate::Options::new(
                    BlockProfile::new(Features::SYSTEM_MODE).with_checked_memory(recipe),
                    TargetCpu::Baseline,
                ),
            )
            .unwrap();
            assert_eq!(
                baseline.memory_requirements(),
                selected.memory_requirements()
            );
            let baseline = baseline.compile().unwrap();
            let selected = selected.compile().unwrap();
            assert!(selected.native.x86_64_code.len() < baseline.native.x86_64_code.len());
            assert_eq!(selected.source_bytes, source.len());
            assert!(selected.fault_recovery.is_empty());
            assert_eq!(
                selected
                    .native
                    .source_map
                    .iter()
                    .map(|(pc, _)| *pc)
                    .collect::<Vec<_>>(),
                baseline
                    .native
                    .source_map
                    .iter()
                    .map(|(pc, _)| *pc)
                    .collect::<Vec<_>>()
            );
            for index in [4, 9] {
                let interval = |block: &crate::block::CompiledBlock| {
                    let begin = block.native.source_map[index].1;
                    let end = block
                        .native
                        .source_map
                        .get(index + 1)
                        .map_or(block.native.x86_64_code.len(), |(_, at)| *at);
                    block.native.x86_64_code[begin..end].to_vec()
                };
                assert_eq!(interval(&selected), interval(&baseline));
            }
        }
    }

    #[test]
    fn shared_dit_and_single_word_paths_keep_the_individual_recipes() {
        for (words, target) in [
            (vec![ADD_X0, RET], TargetCpu::Baseline),
            (
                vec![ADD_X0, ADD_X0, LOAD_BYTE, ADD_X0, ADD_X0, RET],
                TargetCpu::DataIndependentTiming,
            ),
        ] {
            let source: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
            let compile = |profile| {
                CompilationPlan::new(&source, PC, &crate::Options::new(profile, target))
                    .unwrap()
                    .compile()
                    .unwrap()
            };
            let recipe = CheckedMemoryProfile::SpAlignmentEnabled;
            let baseline = compile(BlockProfile::ORDINARY.with_checked_memory(recipe));
            let selected =
                compile(BlockProfile::new(Features::SYSTEM_MODE).with_checked_memory(recipe));
            assert_eq!(baseline.native.x86_64_code, selected.native.x86_64_code);
            assert_eq!(baseline.native.source_map, selected.native.source_map);
        }
    }
}
