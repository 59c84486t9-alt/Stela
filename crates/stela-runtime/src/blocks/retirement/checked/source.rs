//! Validation of the source, compiler plan and native carrier of a block.
mod conditional;
use super::super::super::{
    validate_clock_exit, validate_pauth_exit, validate_source_map, validate_system_exit,
    validate_thread_register_exit, validate_trap_exit,
};
use crate::blocks::{BlockRuntime, LoadedBlock};
use crate::system::execution::EntryBoundary;
use stela_compiler::{
    GuestAddress, GuestState, Lifter,
    aarch64::{Decoder, Operation},
    block::{
        BlockAnalysis, BlockExit, BlockProfile, ClockInstruction, CompilationPlan, DynamicEdgeKind,
        ExitKind, Features, PointerAuthentication, SynchronousTrap, ThreadRegisterInstruction,
        analyze_with_profile,
    },
    context::memory::{MemoryRequirements, MemoryStatus},
};

pub(crate) struct BoundSource<'code> {
    pub(super) runtime: &'code BlockRuntime,
    pub(super) block: &'code LoadedBlock,
    pub(super) entry: EntryBoundary,
    pub(super) source: &'code [u8],
    requirements: Option<MemoryRequirements>,
    analysis: &'code BlockAnalysis,
}

/// What the compilation plan says about a loaded block's source. It depends
/// only on that immutable source, so each block computes it once.
#[derive(Debug)]
pub(crate) struct CheckedFacts {
    requirements: Option<MemoryRequirements>,
    analysis: BlockAnalysis,
}

pub(crate) enum Helper {
    Pauth(PointerAuthentication),
    Clock(ClockInstruction),
    Thread(ThreadRegisterInstruction),
}
impl Helper {
    pub(super) fn pc(&self) -> GuestAddress {
        match self {
            Self::Pauth(value) => value.instruction_pc,
            Self::Clock(value) => value.instruction_pc,
            Self::Thread(value) => value.instruction_pc,
        }
    }
    pub(super) fn needs_publication(&self) -> bool {
        matches!(self, Self::Clock(_))
    }
}

pub(super) enum ReturnedTerminal {
    Ordinary(GuestAddress),
    Helper(Helper),
    Trap(SynchronousTrap),
    System(crate::system::execution::Boundary),
}

impl<'code> BoundSource<'code> {
    #[cfg(feature = "std")]
    pub(super) fn memory_profile(
        &self,
    ) -> anyhow::Result<stela_compiler::block::CheckedMemoryProfile> {
        self.runtime
            .profile
            .checked_memory()
            .ok_or_else(|| anyhow::anyhow!("bound source lacks checked memory profile"))
    }

    #[cfg(feature = "std")]
    pub(super) fn trap(&self) -> Option<SynchronousTrap> {
        self.analysis.trap
    }

    /// Routes that access memory must have requirements; a block with none
    /// never gets default memory access.
    pub(super) fn memory_requirements(&self) -> anyhow::Result<MemoryRequirements> {
        self.requirements
            .ok_or_else(|| anyhow::anyhow!("source has no checked memory requirements"))
    }

    #[cfg(feature = "std")]
    pub(super) fn pauth(&self) -> Option<PointerAuthentication> {
        self.analysis.pointer_authentication
    }

    /// Descriptors come from the prepared token, never from the request. Every
    /// association must still match the source, plan, map and native code
    /// immediately before the call.
    pub(super) fn check_descriptor(&self, boundary: &EntryBoundary) -> anyhow::Result<()> {
        anyhow::ensure!(
            boundary.address_space() == self.entry.address_space()
                && boundary.entry() == self.entry.entry()
                && boundary.region_base() == self.entry.region_base()
                && boundary.source_bytes() == self.entry.source_bytes()
                && boundary.word() == self.entry.word()
                && boundary.generation() == self.entry.generation(),
            "prepared descriptor differs from source/RX association"
        );
        Ok(())
    }
    pub(super) fn prefix(
        &self,
        stopped_before: Option<GuestAddress>,
        completed_memory_bytes: u64,
    ) -> anyhow::Result<super::SettledPrefix> {
        let source_prefix_bytes = match stopped_before {
            Some(pc) => usize::try_from(
                pc.0.checked_sub(self.entry.entry().0)
                    .ok_or_else(|| anyhow::anyhow!("prefix source underflow"))?,
            )?,
            None => self.block.source_bytes,
        };
        anyhow::ensure!(
            source_prefix_bytes <= self.block.source_bytes,
            "prefix exceeds exact source"
        );
        Ok(super::SettledPrefix {
            entry: self.entry.entry(),
            generation: self.entry.generation(),
            source_sha256: self.block.prepared.manifest.identity.source_sha256.clone(),
            consumed_source_bytes: self.block.source_bytes,
            source_prefix_bytes,
            source_map: self.block.prepared.manifest.source_map.clone(),
            stopped_before,
            completed_memory_bytes,
        })
    }
    pub(super) fn new(runtime: &'code BlockRuntime, pc: GuestAddress) -> anyhow::Result<Self> {
        let (base, region) = runtime
            .region(pc)
            .ok_or_else(|| anyhow::anyhow!("source absent"))?;
        let block = runtime
            .loaded
            .get(&pc.0)
            .ok_or_else(|| anyhow::anyhow!("loaded block absent"))?;
        anyhow::ensure!(
            block.region_base == base
                && block.generation == region.generation
                && block.source_bytes > 0,
            "loaded source association changed"
        );
        let offset = usize::try_from(
            pc.0.checked_sub(base)
                .ok_or_else(|| anyhow::anyhow!("source underflow"))?,
        )?;
        let end = offset
            .checked_add(block.source_bytes)
            .ok_or_else(|| anyhow::anyhow!("source overflow"))?;
        let source = region
            .source
            .get(offset..end)
            .ok_or_else(|| anyhow::anyhow!("consumed source extent changed"))?;
        let word = u32::from_le_bytes(
            *source
                .first_chunk::<4>()
                .ok_or_else(|| anyhow::anyhow!("entry word absent"))?,
        );
        let entry = EntryBoundary::new(
            runtime.address_space(),
            region.generation,
            pc,
            GuestAddress(base),
            region.source.len(),
            word,
        );
        let facts = match block.checked.get() {
            Some(facts) => facts,
            None => {
                let facts = Self::validate(runtime, block, pc, source)?;
                block.checked.get_or_init(|| facts)
            }
        };
        Ok(Self {
            runtime,
            block,
            entry,
            source,
            requirements: facts.requirements,
            analysis: &facts.analysis,
        })
    }

    /// Check the loaded artifact against the exact source and derive its plan.
    fn validate(
        runtime: &BlockRuntime,
        block: &LoadedBlock,
        pc: GuestAddress,
        source: &[u8],
    ) -> anyhow::Result<CheckedFacts> {
        let manifest = &block.prepared.manifest;
        let identity = &manifest.identity;
        anyhow::ensure!(
            identity.guest_base == pc.0
                && identity.abi == runtime.profile.abi()
                && identity.target_cpu == runtime.target_cpu().id()
                && identity.source_sha256 == crate::sha256(source)
                && identity.compiler_source_sha256 == crate::compiler_source_sha256(),
            "source/compiler/profile/target differs"
        );
        validate_source_map(&block.prepared.manifest, pc, block.source_bytes)?;
        // Re-parse without emitting, and compare that plan with the loaded one.
        let plan = CompilationPlan::new(
            source,
            pc,
            &stela_compiler::Options::new(runtime.profile, runtime.target_cpu()),
        )?;
        let requirements = plan.memory_requirements();
        if runtime.profile == BlockProfile::new(Features::SYSTEM) {
            anyhow::ensure!(
                requirements.is_none() && source.len() == size_of::<u32>(),
                "a System block requires one original no-context source word"
            );
        } else {
            anyhow::ensure!(
                runtime.profile.checked_memory().is_some() && requirements.is_some(),
                "checked plan requirements absent"
            );
        }
        anyhow::ensure!(
            plan.source_bytes() == block.source_bytes
                && manifest.memory_requirements == requirements
                && identity.memory_specialization_sha256
                    == crate::memory_specialization_sha256(runtime.profile, requirements)?,
            "loaded requirements differ from exact original plan"
        );
        let analysis = analyze_with_profile(source, pc, runtime.profile)?;
        anyhow::ensure!(
            analysis.source_bytes == source.len(),
            "analysis does not consume exact original source"
        );
        Ok(CheckedFacts {
            requirements,
            analysis,
        })
    }

    pub(super) fn validate_return(
        &self,
        exit: &BlockExit,
        registers: &GuestState,
    ) -> anyhow::Result<ReturnedTerminal> {
        let kind = ExitKind::try_from(exit.kind)
            .map_err(|()| anyhow::anyhow!("unknown native exit carrier"))?;
        let next = GuestAddress(exit.next_pc);
        let region = &self
            .runtime
            .region(self.entry.entry())
            .ok_or_else(|| anyhow::anyhow!("source absent after call"))?
            .1
            .source;
        let args = (
            self.entry.entry(),
            next,
            self.block.source_bytes,
            self.block.region_base,
            &**region,
        );
        let terminal = match kind {
            ExitKind::PointerAuthentication if self.analysis.pointer_authentication.is_some() => {
                ReturnedTerminal::Helper(Helper::Pauth(validate_pauth_exit(
                    args.0, args.1, args.2, args.3, args.4,
                )?))
            }
            ExitKind::Clock if self.analysis.clock_instruction.is_some() => {
                ReturnedTerminal::Helper(Helper::Clock(validate_clock_exit(
                    args.0, args.1, args.2, args.3, args.4,
                )?))
            }
            ExitKind::ThreadRegister if self.analysis.thread_register_instruction.is_some() => {
                ReturnedTerminal::Helper(Helper::Thread(validate_thread_register_exit(
                    args.0, args.1, args.2, args.3, args.4,
                )?))
            }
            ExitKind::System if self.analysis.system_instruction.is_some() => {
                let instruction = validate_system_exit(args.0, args.1, args.2, args.3, args.4)?;
                anyhow::ensure!(
                    self.analysis.system_instruction == Some(instruction)
                        && self.analysis.terminator_pc == Some(instruction.instruction_pc),
                    "System carrier differs from original compiler terminal"
                );
                ReturnedTerminal::System(crate::system::execution::Boundary::new(
                    EntryBoundary::new(
                        self.entry.address_space(),
                        self.entry.generation(),
                        self.entry.entry(),
                        self.entry.region_base(),
                        self.entry.source_bytes(),
                        self.entry.word(),
                    ),
                    self.block.source_bytes,
                    instruction,
                ))
            }
            ExitKind::Trap if self.analysis.trap.is_some() => {
                ReturnedTerminal::Trap(validate_trap_exit(args.0, args.1, args.2, args.3, args.4)?)
            }
            ExitKind::Fallthrough
            | ExitKind::Direct
            | ExitKind::Call
            | ExitKind::Indirect
            | ExitKind::Return => {
                anyhow::ensure!(
                    self.analysis.pointer_authentication.is_none()
                        && self.analysis.clock_instruction.is_none()
                        && self.analysis.thread_register_instruction.is_none()
                        && self.analysis.system_instruction.is_none()
                        && self.analysis.trap.is_none(),
                    "ordinary carrier claims helper source"
                );
                if let Some(edge) = &self.analysis.dynamic_edge {
                    let expected = match edge.kind {
                        DynamicEdgeKind::Branch => ExitKind::Indirect,
                        DynamicEdgeKind::Call => ExitKind::Call,
                        DynamicEdgeKind::Return => ExitKind::Return,
                    };
                    anyhow::ensure!(kind == expected, "dynamic source/carrier kind differs");
                    // Target originates from this exact admitted native mapping.
                    // BLR may have overwritten X30, so post-body X30 is not an
                    // independent old-target oracle. Fetch validation is next.
                } else if conditional::validate(
                    self.analysis,
                    self.source,
                    self.entry.entry(),
                    registers,
                    kind,
                    next,
                )?
                .is_some()
                {
                    // The exact terminal leaves its predicate GPR/NZCV intact.
                    // Actual post-prefix state selected this precise edge/kind.
                } else {
                    use stela_compiler::block::SuccessorKind;
                    let matching = self.analysis.static_successors.iter().any(|edge| {
                        edge.target == next
                            && match kind {
                                ExitKind::Fallthrough => edge.kind == SuccessorKind::Fallthrough,
                                ExitKind::Direct => edge.kind == SuccessorKind::Direct,
                                ExitKind::Call => edge.kind == SuccessorKind::CallTarget,
                                _ => false,
                            }
                    });
                    anyhow::ensure!(matching, "ordinary continuation differs from exact source");
                }
                ReturnedTerminal::Ordinary(next)
            }
            _ => anyhow::bail!("exit/source/profile mismatch"),
        };
        if let ReturnedTerminal::Helper(helper) = &terminal {
            anyhow::ensure!(
                self.analysis.terminator_pc == Some(helper.pc()),
                "helper carrier is not original terminal"
            );
        }
        if let ReturnedTerminal::Trap(trap) = &terminal {
            anyhow::ensure!(
                self.analysis.terminator_pc == Some(trap.instruction_pc),
                "trap carrier is not original terminal"
            );
        }
        Ok(terminal)
    }

    pub(super) fn validate_fault(&self, fault: &super::OwnedMemoryFault) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.block
                .prepared
                .manifest
                .source_map
                .iter()
                .any(|(pc, _)| *pc == fault.pc),
            "fault PC outside exact source map"
        );
        anyhow::ensure!(
            matches!(
                fault.status,
                MemoryStatus::Translation
                    | MemoryStatus::Permission
                    | MemoryStatus::Alignment
                    | MemoryStatus::StackAlignment
            ),
            "nonarchitectural status cannot settle as a fault"
        );
        // The source word must be an admitted memory instruction that was
        // reached; helper, branch or arithmetic locations cannot stand in for
        // it.
        let offset = usize::try_from(
            fault
                .pc
                .0
                .checked_sub(self.entry.entry().0)
                .ok_or_else(|| anyhow::anyhow!("fault source underflow"))?,
        )?;
        let word = u32::from_le_bytes(
            self.source
                .get(offset..offset + 4)
                .ok_or_else(|| anyhow::anyhow!("fault word absent"))?
                .try_into()?,
        );
        let instruction = Decoder.lift(fault.pc, word).map_err(|reason| {
            anyhow::anyhow!(
                "fault source decode at {:?} ({word:#010x}): {reason:?}",
                fault.pc
            )
        })?;
        let atomic = matches!(instruction.operation, Operation::Atomic(_));
        anyhow::ensure!(
            if atomic
                && !matches!(
                    fault.status,
                    MemoryStatus::Alignment | MemoryStatus::StackAlignment
                )
            {
                matches!(
                    fault.access,
                    stela_compiler::context::memory::FaultAccess::Read
                        | stela_compiler::context::memory::FaultAccess::Write
                )
            } else {
                fault.access == stela_compiler::context::memory::FaultAccess::OriginalSource
            },
            "dynamic access direction does not belong to this source fault"
        );
        let maximum = match instruction.operation {
            Operation::Atomic(operand) => u64::from(operand.bytes),
            Operation::Ordered(stela_compiler::aarch64::ordered::Operand::Transfer {
                bytes,
                ..
            }) => u64::from(bytes),
            Operation::Memory { bytes, .. } => u64::from(bytes),
            Operation::MemoryRegisterOffset(operand) => u64::from(operand.bytes),
            Operation::MemoryUnprivileged(operand) => u64::from(operand.bytes),
            Operation::MemoryPair { bytes, .. } => 2 * u64::from(bytes),
            Operation::Simd(stela_compiler::aarch64::simd::Operand::Memory { bytes, .. }) => {
                u64::from(bytes)
            }
            Operation::Simd(stela_compiler::aarch64::simd::Operand::MemoryPair {
                bytes, ..
            }) => 2 * u64::from(bytes),
            Operation::Simd(stela_compiler::aarch64::simd::Operand::MemoryRegisterOffset(
                operand,
            )) => u64::from(operand.bytes),
            // Both decoded GPR and SIMD non-temporal forms perform one whole
            // two-element quantity. Their reached SP/permission faults retain
            // the same source-defined maximum; no raw access is authorized here.
            Operation::MemoryNonTemporal(operand) => 2 * u64::from(operand.bytes),
            // The decoder supplies only valid element sizes and scalar/pair
            // shapes. CLREX is not a reached memory operation and stays excluded.
            Operation::Exclusive(stela_compiler::aarch64::exclusive::Operand::Transfer {
                element_bytes,
                data,
                ..
            }) => {
                u64::from(element_bytes)
                    * match data {
                        stela_compiler::aarch64::exclusive::Data::Scalar(_) => 1,
                        stela_compiler::aarch64::exclusive::Data::Pair(registers) => {
                            registers.len() as u64
                        }
                    }
            }
            _ => anyhow::bail!("fault source is not a bounded checked memory operation"),
        };
        anyhow::ensure!(
            !atomic || fault.completed_bytes == 0,
            "atomic fault reports a partial quantity"
        );
        anyhow::ensure!(
            fault.completed_bytes < maximum,
            "fault reports completed whole instruction"
        );
        if matches!(
            fault.status,
            MemoryStatus::Alignment | MemoryStatus::StackAlignment
        ) {
            anyhow::ensure!(
                fault.completed_bytes == 0,
                "alignment fault reports memory effects"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Source descriptor and entry validation.
    use super::BoundSource;
    use crate::blocks::BlockRuntime;
    use stela_compiler::{
        GuestAddress,
        block::{BlockProfile, CheckedMemoryProfile},
    };
    const BASE: GuestAddress = GuestAddress(0x4000);
    const B_PLUS8: u32 = 0x1400_0002;
    fn runtime(cache: &std::path::Path, profile: BlockProfile) -> BlockRuntime {
        let mut runtime = BlockRuntime::new_with_profile(73, cache.to_owned(), profile);
        runtime
            .register_code(BASE, B_PLUS8.to_le_bytes().to_vec())
            .unwrap();
        runtime
    }
    #[test]
    fn checked_memory_bound_source_keeps_plan_requirements() {
        let cache = tempfile::tempdir().unwrap();
        let profile =
            BlockProfile::ORDINARY.with_checked_memory(CheckedMemoryProfile::SpAlignmentEnabled);
        let mut runtime = runtime(cache.path(), profile);
        let mut accounting = super::super::empty_accounting();
        runtime.load(BASE, &mut accounting).unwrap();
        let bound = BoundSource::new(&runtime, BASE).unwrap();
        assert_eq!(
            Some(bound.memory_requirements().unwrap()),
            bound.block.prepared.manifest.memory_requirements
        );
        assert_eq!(accounting.blocks_executed, 0);
    }
}
