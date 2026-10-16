//! Native block dispatch.
//!
//! Guest code is fetched from registered regions and translated a block at a
//! time; data accesses use direct RAM. Replacing code invalidates the dependent
//! native blocks before returning.

mod aot;
mod checked_memory;
mod discovery;
mod outcome;
mod publication;
pub(crate) mod retirement;
pub(crate) mod scalable;
mod services;
mod translation;
mod validate;

pub use discovery::{
    DeferredDynamicEdge, DiscoveryIssue, DiscoveryProblem, DiscoveryReport, PreparedDiscoveryBlock,
};
pub use outcome::{
    ClockEvent, PointerAuthenticationEvent, RunOutcome, StopReason, ThreadRegisterEvent,
    ThreadState,
};
pub use publication::CodePublicationScope;
pub use retirement::checked::software_el1::{
    InitializedRamRegion, OwnedRamExtent, PhysicalRamRange, SoftwareEl1Config,
    SoftwareEl1InitialRam, SoftwareEl1Machine, SoftwareEl1Profile, SoftwareEl1Report,
    SoftwareEl1Request, SourceRamDeclaration, SourceRamPermissions, ZeroedRamExtent,
};
pub use retirement::checked::software_privileged::{
    DeclaredDebugExtendedHaltSyndrome, DeclaredDebugExternalControls, DeclaredDebugInitialization,
    DeclaredHigherElInitialization, DeclaredPrivilegedCode, DeclaredPrivilegedConfig,
    DeclaredPrivilegedReceipt, DeclaredPrivilegedReport, DeclaredPrivilegedRequest,
    DeclaredPrivilegedScalable, TrapSmcWithoutEl3, run_declared_privileged,
};
pub(crate) use translation::{
    ControlCodeScope, InstalledEl1SourceScope, InstalledM0SourceScope, InstalledWalkedSource,
};
pub(in crate::blocks) use translation::{
    InstalledEl1Owner, InstalledEl1Sources, InstalledM0Owner, InstalledM0Sources,
};

use crate::{clock, execution::platform, floating, memory, pauth, system, thread};
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, string::ToString, vec::Vec};
use alloc::{collections::BTreeMap, rc::Rc};
use anyhow::{Context, Result, ensure};
use aot::ArtifactPreparation;
use core::marker::PhantomData;
use services::{
    AuthenticatedLoadError, RuntimeServices, complete_clock, complete_pauth_with_memory,
    runtime_pauth_key, serialize_instruction_execution,
};
#[cfg(feature = "std")]
use std::{io::Read, path::PathBuf};
use stela_compiler::{
    GuestAddress,
    block::{
        BlockExit, BlockProfile, ExitKind, MAX_BLOCK_INSTRUCTIONS, PointerAuthenticationOperation,
        analyze_with_profile,
    },
};
use validate::{
    validate_clock_exit, validate_interior_word, validate_numerical_exit, validate_pauth_exit,
    validate_source_map, validate_system_exit, validate_terminal_word,
    validate_thread_register_exit, validate_trap_exit,
};

#[cfg(feature = "std")]
const MAX_NATIVE_BYTES: usize = 64 * 1024 * 1024;
const INSTRUCTION_BYTES: usize = 4;
const ZERO_REGISTER_INDEX: u8 = 31;
const REGISTER_COUNT: u8 = ZERO_REGISTER_INDEX + 1;

#[derive(Debug)]
struct CodeRegion {
    source: Box<[u8]>,
    physical_binding: Option<translation::PhysicalCodeBinding>,
    end: u64,
    generation: u64,
}

#[derive(Debug)]
struct LoadedBlock {
    profile: BlockProfile,
    region_base: u64,
    generation: u64,
    source_bytes: usize,
    prepared: crate::artifact::LoadedArtifact,
    mapping: platform::Mapping,
    /// Checked-retirement plan facts, derived on first checked dispatch.
    checked: core::cell::OnceCell<retirement::checked::CheckedFacts>,
}

/// Source registration, resolution and execution are serialized through &mut.
/// No function pointer, mutable code slice or executable mapping escapes.
#[derive(Debug)]
pub struct BlockRuntime {
    /// Identifies this runtime's source and native-code cache.
    identity: alloc::sync::Arc<()>,
    address_space: u64,
    profile: BlockProfile,
    target: stela_compiler::TargetCpu,
    preparation: ArtifactPreparation,
    next_generation: u64,
    regions: BTreeMap<u64, CodeRegion>,
    loaded: BTreeMap<u64, LoadedBlock>,
    _serialized: PhantomData<Rc<()>>,
}

impl BlockRuntime {
    #[cfg(feature = "std")]
    pub fn new(address_space: u64, cache_root: PathBuf) -> Self {
        Self::new_with_profile(address_space, cache_root, BlockProfile::Ordinary)
    }

    /// Explicit helper profile is part of every persistent translation identity.
    /// Preparing AOT needs no keys; execution receives a separately bound context.
    #[cfg(feature = "std")]
    pub fn new_with_profile(
        address_space: u64,
        cache_root: PathBuf,
        profile: BlockProfile,
    ) -> Self {
        Self::new_for_target(
            address_space,
            cache_root,
            profile,
            stela_compiler::TargetCpu::detect(),
        )
    }
    #[cfg(feature = "std")]
    pub fn new_for_target(
        address_space: u64,
        cache_root: PathBuf,
        profile: BlockProfile,
        target: stela_compiler::TargetCpu,
    ) -> Self {
        Self::with_preparation(
            address_space,
            profile,
            target,
            ArtifactPreparation::HostedCache(cache_root),
        )
    }

    pub fn target_cpu(&self) -> stela_compiler::TargetCpu {
        self.target
    }

    pub fn address_space(&self) -> u64 {
        self.address_space
    }

    pub fn profile(&self) -> BlockProfile {
        self.profile
    }

    /// A permission service must not bypass immutable-source visibility or
    /// invalidation by presenting registered code as an ordinary data mapping.
    pub fn source_overlaps(&self, address: u64, bytes: u64) -> bool {
        let Some(end) = address.checked_add(bytes) else {
            return true;
        };
        bytes != 0
            && self
                .regions
                .range(..end)
                .next_back()
                .is_some_and(|(&base, r)| base < end && r.end > address)
    }

    /// Own an immutable file/code snapshot. Partial trailing bytes are retained
    /// but can never be padded into a fetchable instruction. Same-base replacement
    /// always advances generation, even when the source bytes are identical.
    pub fn register_code(&mut self, base: GuestAddress, source: Vec<u8>) -> Result<u64> {
        ensure!(
            base.0.is_multiple_of(4) && source.len() >= 4,
            "code region must have an aligned base and at least one instruction"
        );
        let end = base
            .0
            .checked_add(u64::try_from(source.len())?)
            .context("code region overflow")?;
        for (&start, region) in &self.regions {
            ensure!(
                start == base.0 || end <= start || base.0 >= region.end,
                "code registration overlaps an existing region"
            );
        }
        let generation = self
            .next_generation
            .checked_add(1)
            .context("code generation exhausted")?;
        self.loaded.retain(|_, block| block.region_base != base.0);
        self.regions.insert(
            base.0,
            CodeRegion {
                source: source.into_boxed_slice(),
                physical_binding: None,
                end,
                generation,
            },
        );
        self.next_generation = generation;
        Ok(generation)
    }

    pub fn unregister_code(&mut self, base: GuestAddress) -> bool {
        let removed = self.regions.remove(&base.0).is_some();
        if removed {
            self.loaded.retain(|_, block| block.region_base != base.0);
        }
        removed
    }

    fn region(&self, pc: GuestAddress) -> Option<(u64, &CodeRegion)> {
        self.regions
            .range(..=pc.0)
            .next_back()
            .filter(|(_, region)| pc.0 < region.end)
            .map(|(&base, region)| (base, region))
    }

    fn load(&mut self, pc: GuestAddress, outcome: &mut RunOutcome) -> Result<()> {
        let (base, region) = self.region(pc).context("instruction mapping disappeared")?;
        if let Some(block) = self.loaded.get(&pc.0) {
            ensure!(
                block.region_base == base && block.generation == region.generation,
                "stale native block generation"
            );
            outcome.memory_cache_hits += 1;
            return Ok(());
        }
        #[cfg(not(feature = "std"))]
        {
            let discovery = self.prepare(pc)?;
            let profile = discovery.artifact_profile;
            let generation = discovery.generation;
            let source_bytes = discovery.analysis.source_bytes;
            let native = discovery.native;
            let prepared =
                crate::artifact::LoadedArtifact::bind(discovery.prepared.manifest, &native)
                    .context("block native snapshot checksum mismatch")?;
            let block = LoadedBlock::from_artifact(
                self.target,
                profile,
                base,
                generation,
                source_bytes,
                prepared,
                &native,
            )?;
            self.loaded.insert(pc.0, block);
            outcome.compiled_blocks += 1;
        }
        #[cfg(feature = "std")]
        {
            let prepared = self.prepare(pc)?;
            let profile = prepared.artifact_profile;
            let generation = prepared.generation;
            let source_bytes = prepared.analysis.source_bytes;
            let prepared = prepared.prepared;
            let mut native = Vec::new();
            std::fs::File::open(prepared.directory.join("native.bin"))?
                .take((MAX_NATIVE_BYTES + 1) as u64)
                .read_to_end(&mut native)?;
            let loaded_artifact = crate::artifact::LoadedArtifact::bind(prepared.manifest, &native)
                .context("block native snapshot checksum mismatch")?;
            let block = LoadedBlock::from_artifact(
                self.target,
                profile,
                base,
                generation,
                source_bytes,
                loaded_artifact,
                &native,
            )?;
            if prepared.cache_hit {
                outcome.disk_cache_hits += 1;
            } else {
                outcome.compiled_blocks += 1;
            }
            self.loaded.insert(pc.0, block);
        }

        Ok(())
    }

    /// Run native blocks until the stop address, an unsatisfiable dispatch, a
    /// synchronous trap or the block budget. A trap leaves PC at the trapping
    /// instruction and reports the preferred return address separately; only
    /// the caller resumes. No host syscall, guest exception entry or EL change
    /// happens here. Unsupported code is returned as a stop, not a guest
    /// exception. A zero budget runs nothing. PC is the next guest instruction.
    ///
    /// # Safety
    /// The registered code, and the code generated from it, must be trusted.
    /// Every guest data access must satisfy the direct-RAM profile: in live
    /// bounds with suitable permissions and alignment, untagged or
    /// authenticated pointers, guest addresses equal to host addresses,
    /// exclusive writes, and no aliasing of Rust references, state, native
    /// code, runtime metadata or the host stack. Source snapshots are
    /// instruction storage, not guest data. The caller excludes concurrent
    /// mutation. Instruction pages are assumed unguarded with GCS disabled;
    /// PAC/BTI/GCS exceptions are not modeled. A native fault can terminate the
    /// host process.
    pub unsafe fn run(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
    ) -> Result<RunOutcome> {
        unsafe {
            self.run_inner(
                state,
                stop_pc,
                block_budget,
                RuntimeServices::legacy(None, None, None),
            )
        }
    }

    /// Run with software PAuth, using the process's keys. Keys are borrowed;
    /// they never enter artifacts or guest RAM.
    ///
    /// # Safety
    /// As for [`Self::run`]. The caller keeps the process keys consistent for
    /// the duration.
    pub unsafe fn run_with_pauth(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        context: &pauth::Context,
    ) -> Result<RunOutcome> {
        ensure!(
            self.profile.supports_pointer_authentication(),
            "PAuth execution requires the explicit software PAuth block profile"
        );
        ensure!(
            context.address_space() == self.address_space,
            "PAuth context belongs to another guest address space"
        );
        unsafe {
            self.run_inner(
                state,
                stop_pc,
                block_budget,
                RuntimeServices::legacy(Some(context), None, None),
            )
        }
    }

    /// Run PAC helpers with the address space's checked data reader.
    /// Authenticated loads keep tags through the reader's translation policy,
    /// and their base and destination are written only after the full
    /// eight-byte read.
    ///
    /// # Safety
    /// Ordinary native code has the requirements of [`Self::run`]. The reader
    /// must own this guest address space, and its mappings, policy and backing
    /// must stay valid for the call. `controls` is the effective SP-alignment
    /// policy of the same CPU.
    pub unsafe fn run_with_pauth_memory(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        context: &pauth::Context,
        reader: &mut dyn memory::domain::MemoryReader,
        controls: pauth::memory::Controls,
    ) -> Result<RunOutcome> {
        ensure!(
            self.profile.supports_pointer_authentication(),
            "PAuth execution requires the explicit software PAuth block profile"
        );
        ensure!(
            context.address_space() == self.address_space,
            "PAuth context belongs to another guest address space"
        );
        ensure!(
            reader.address_space() == Some(self.address_space),
            "memory reader belongs to another guest address space"
        );
        reader
            .validate_privilege(controls.privileged)
            .map_err(|status| {
                anyhow::anyhow!("LDRA memory privilege profile unavailable: {status:?}")
            })?;
        unsafe {
            self.run_inner(
                state,
                stop_pc,
                block_budget,
                RuntimeServices::pauth_memory(context, reader, controls),
            )
        }
    }

    /// Run PAC and clock helpers with caller-owned services. The clock owns its
    /// read-only commpage and publishes only at helper boundaries.
    ///
    /// # Safety
    /// As for [`Self::run`]. No other translated code may access the clock page
    /// while it is published. ISB is modeled as host instruction serialization
    /// for unchanging guest code.
    pub unsafe fn run_with_clock(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        pauth: &pauth::Context,
        clock: &mut clock::Context,
    ) -> Result<RunOutcome> {
        ensure!(
            self.profile.supports_clock(),
            "clock execution requires the explicit software clock block profile"
        );
        ensure!(
            pauth.address_space() == self.address_space,
            "PAuth context belongs to another guest address space"
        );
        ensure!(
            clock.address_space() == self.address_space,
            "clock context belongs to another guest address space"
        );
        unsafe {
            self.run_inner(
                state,
                stop_pc,
                block_budget,
                RuntimeServices::legacy(Some(pauth), Some(clock), None),
            )
        }
    }

    /// Run thread-register helpers with the context used by the Darwin thread
    /// services. Cached code never embeds the current TSD value.
    ///
    /// # Safety
    /// As for [`Self::run`]. The context must stay on its owning host thread.
    pub unsafe fn run_with_thread(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        thread: &thread::Context,
        pauth: Option<&pauth::Context>,
        clock: Option<&mut clock::Context>,
    ) -> Result<RunOutcome> {
        ensure!(
            self.profile.supports_thread_registers(),
            "thread-register execution requires the explicit thread block profile"
        );
        ensure!(
            thread.address_space() == self.address_space,
            "thread context belongs to another guest address space"
        );
        if let Some(pauth) = pauth {
            ensure!(
                self.profile.supports_pointer_authentication(),
                "PAuth execution requires the explicit software PAuth block profile"
            );
            ensure!(
                pauth.address_space() == self.address_space,
                "PAuth context belongs to another guest address space"
            );
        }
        if let Some(clock) = clock.as_ref() {
            ensure!(
                self.profile.supports_clock() && pauth.is_some(),
                "clock execution requires the explicit software clock profile and PAC context"
            );
            ensure!(
                clock.address_space() == self.address_space,
                "clock context belongs to another guest address space"
            );
        }
        unsafe {
            self.run_inner(
                state,
                stop_pc,
                block_budget,
                RuntimeServices::legacy(pauth, clock, Some(thread)),
            )
        }
    }

    /// Run with the system-instruction service. Registered prefixes have no
    /// direct-RAM effects; memory services use their shared domain. A failure
    /// keeps its PC and completed prefix.
    ///
    /// # Safety
    /// As for [`Self::run`]. The service backend owns its architectural effects
    /// and memory synchronization.
    pub unsafe fn run_with_system(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        dispatcher: &mut dyn system::execution::Dispatcher,
    ) -> Result<RunOutcome> {
        ensure!(
            self.profile.supports_system(),
            "System execution requires the explicit System block profile"
        );
        ensure!(
            dispatcher.address_space() == self.address_space,
            "System dispatcher belongs to another guest address space"
        );
        unsafe {
            self.run_inner(
                state,
                stop_pc,
                block_budget,
                RuntimeServices::system(dispatcher),
            )
        }
    }

    unsafe fn run_inner(
        &mut self,
        state: &mut ThreadState,
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
        services: RuntimeServices<'_>,
    ) -> Result<RunOutcome> {
        ensure!(
            !matches!(
                self.profile,
                BlockProfile::El1DirectBranchV1 | BlockProfile::El1M0IntegerV1
            ),
            "EL1 direct branch requires its original canonical retained owner"
        );
        let RuntimeServices {
            pointer_authentication: mut pauth_execution,
            clock: mut clock_context,
            thread: thread_context,
            system: mut system_dispatcher,
        } = services;
        platform::ensure_supported()?;
        ensure!(
            self.profile.checked_memory().is_none(),
            "checked artifact cannot execute through direct entry"
        );
        let mut outcome = RunOutcome {
            reason: StopReason::BudgetExhausted,
            blocks_executed: 0,
            compiled_blocks: 0,
            disk_cache_hits: 0,
            memory_cache_hits: 0,
            last_exit: None,
            floating_point_helpers: 0,
            pointer_authentication_events: Vec::new(),
            clock_events: Vec::new(),
            thread_register_events: Vec::new(),
        };
        loop {
            let pc = state.pc;
            // A zero budget requests no instruction fetch or execution.
            if self.profile.supports_pointer_authentication() && block_budget == 0 {
                break;
            }
            // Instruction TBI is disabled in the fixed VA47 software profile.
            // This also prevents a resumed poisoned RETAB target from becoming
            // executable through a registered snapshot or matching stop sentinel.
            let extension = pc.0 >> 47;
            if self.profile.supports_pointer_authentication()
                && extension != 0
                && extension != u64::MAX >> 47
            {
                outcome.reason = StopReason::NoncanonicalInstructionTarget { address: pc };
                break;
            }
            if stop_pc == Some(pc) {
                outcome.reason = StopReason::StopAddress;
                break;
            }
            if outcome.blocks_executed == block_budget {
                break;
            }
            if !pc.0.is_multiple_of(4) {
                outcome.reason = StopReason::UnalignedTarget;
                break;
            }
            let Some((base, region)) = self.region(pc) else {
                outcome.reason = StopReason::UnmappedTarget;
                break;
            };
            if region.end - pc.0 < 4 {
                outcome.reason = StopReason::TruncatedInstruction;
                break;
            }
            // Current PSTATE and CPU controls take precedence over decoding an
            // available word. This guard performs no architectural effect.
            let system_entry = if self.profile.supports_system()
                || self.profile.checked_memory().is_some()
            {
                let Some(dispatcher) = system_dispatcher.as_deref_mut() else {
                    outcome.reason = StopReason::SystemContextRequired { instruction_pc: pc };
                    break;
                };
                let word = validate_terminal_word(pc, pc, INSTRUCTION_BYTES, base, &region.source)?;
                let boundary = system::execution::EntryBoundary::new(
                    self.address_space,
                    region.generation,
                    pc,
                    GuestAddress(base),
                    region.source.len(),
                    word,
                );
                let offset = usize::try_from(pc.0 - base)?;
                let available = ((region.source.len() - offset) / INSTRUCTION_BYTES)
                    .min(MAX_BLOCK_INSTRUCTIONS)
                    * INSTRUCTION_BYTES;
                let source = &region.source[offset..offset + available];
                if let Err(failure) = dispatcher.validate_entry(&boundary, source, &state.registers)
                {
                    outcome.reason = StopReason::SystemEntryFailure {
                        instruction_pc: pc,
                        word,
                        failure,
                    };
                    break;
                }
                Some(boundary)
            } else {
                None
            };
            // Decode ahead of loading so an unsupported instruction is a typed
            // dispatch stop. Disk corruption and allocation errors remain errors.
            if !self.loaded.contains_key(&pc.0) {
                let offset = usize::try_from(pc.0 - base)?;
                let words = ((region.source.len() - offset) / 4).min(MAX_BLOCK_INSTRUCTIONS);
                if let Err(error) = stela_compiler::block::source_bytes_with_profile(
                    &region.source[offset..offset + words * 4],
                    pc,
                    self.profile,
                ) {
                    outcome.reason = StopReason::Unsupported {
                        detail: error.to_string(),
                    };
                    break;
                }
            }
            self.load(pc, &mut outcome)?;
            let block = self.loaded.get(&pc.0).context("loaded block disappeared")?;
            let (_, current) = self.region(pc).context("loaded block unmapped")?;
            ensure!(
                block.generation == current.generation && block.source_bytes > 0,
                "refusing stale block execution"
            );
            let mut completed_blocks = 1;
            let native_exit = if block.profile.supports_resident_loops() {
                let available = block_budget - outcome.blocks_executed;
                let mut budget = stela_compiler::block::loop_budget::LoopBudget::new(available);
                // SAFETY: the distinct immutable profile/ABI binds this source
                // and mapping to the same bank and invocation-local counter.
                let returned = unsafe {
                    block
                        .mapping
                        .call_budgeted_block(&mut state.registers, &mut budget)?
                };
                completed_blocks = budget
                    .consumed(available)
                    .filter(|&consumed| consumed != 0)
                    .context("invalid resident-block budget accounting")?;
                returned
            } else {
                unsafe { block.mapping.call_block(&mut state.registers)? }
            };
            let BlockExit { next_pc, kind } = native_exit;
            let exit_kind = ExitKind::try_from(kind)
                .map_err(|_| anyhow::anyhow!("invalid native block exit kind"))?;
            ensure!(
                exit_kind != ExitKind::ScalableNumerical,
                "context-block numerical exit requires owned scalable entry"
            );
            let trap = if exit_kind == ExitKind::Trap {
                Some(validate_trap_exit(
                    pc,
                    GuestAddress(next_pc),
                    block.source_bytes,
                    block.region_base,
                    &current.source,
                )?)
            } else {
                None
            };
            let pointer_authentication = if exit_kind == ExitKind::PointerAuthentication {
                ensure!(
                    self.profile.supports_pointer_authentication(),
                    "ordinary block produced an unrequested PAuth helper exit"
                );
                Some(validate_pauth_exit(
                    pc,
                    GuestAddress(next_pc),
                    block.source_bytes,
                    block.region_base,
                    &current.source,
                )?)
            } else {
                None
            };
            let clock_instruction = if exit_kind == ExitKind::Clock {
                ensure!(
                    self.profile.supports_clock(),
                    "block produced an unrequested clock helper exit"
                );
                Some(validate_clock_exit(
                    pc,
                    GuestAddress(next_pc),
                    block.source_bytes,
                    block.region_base,
                    &current.source,
                )?)
            } else {
                None
            };
            let thread_register_instruction = if exit_kind == ExitKind::ThreadRegister {
                ensure!(
                    self.profile.supports_thread_registers(),
                    "block produced an unrequested thread-register helper exit"
                );
                Some(validate_thread_register_exit(
                    pc,
                    GuestAddress(next_pc),
                    block.source_bytes,
                    block.region_base,
                    &current.source,
                )?)
            } else {
                None
            };
            let system_boundary = if exit_kind == ExitKind::System {
                ensure!(
                    self.profile.supports_system(),
                    "block produced an unrequested System helper exit"
                );
                let instruction = validate_system_exit(
                    pc,
                    GuestAddress(next_pc),
                    block.source_bytes,
                    block.region_base,
                    &current.source,
                )?;
                Some(system::execution::Boundary::new(
                    system_entry.context("System exit lacks validated entry")?,
                    block.source_bytes,
                    instruction,
                ))
            } else {
                None
            };
            let numerical = if exit_kind == ExitKind::FloatingPoint {
                Some(validate_numerical_exit(
                    pc,
                    GuestAddress(next_pc),
                    block.source_bytes,
                    block.region_base,
                    &current.source,
                )?)
            } else {
                None
            };
            state.pc = GuestAddress(next_pc);
            outcome.last_exit = Some((next_pc, kind));
            outcome.blocks_executed += completed_blocks;
            if let Some(boundary) = system_boundary {
                let instruction = boundary.instruction();
                let dispatcher = system_dispatcher
                    .as_deref_mut()
                    .context("System exit lacks validated dispatcher")?;
                let mut code = CodePublicationScope::new(&*self, &boundary);
                match dispatcher.complete_with_code_scope(boundary, &mut state.registers, &mut code)
                {
                    Ok(next) => state.pc = next,
                    Err(failure) => {
                        outcome.reason = StopReason::SystemFailure {
                            instruction,
                            failure,
                        };
                        break;
                    }
                }
            }
            if let Some((operand, continuation)) = numerical {
                if let Err(error) = floating::complete(&mut state.registers, &operand) {
                    outcome.reason = StopReason::FloatingPointUnsupported {
                        instruction_pc: state.pc,
                        fpcr: state.registers.fpcr,
                        enabled_exceptions: error.enabled_exceptions,
                    };
                    break;
                }
                state.pc = continuation;
                outcome.floating_point_helpers += 1;
            }
            if let Some(instruction) = thread_register_instruction {
                let Some(thread) = thread_context else {
                    outcome.reason = StopReason::ThreadRegisterRequired { instruction };
                    break;
                };
                let value = thread.thread_specific_data();
                // The immutable decoder guarantees 0..=31. XZR discards only
                // after ownership and the required context have been validated.
                if instruction.destination != ZERO_REGISTER_INDEX {
                    state.registers.x[usize::from(instruction.destination)] = value;
                }
                state.pc = instruction.next_pc;
                outcome.thread_register_events.push(ThreadRegisterEvent {
                    instruction,
                    next_pc: instruction.next_pc,
                    value,
                });
            }
            if let Some(instruction) = clock_instruction {
                let Some(clock) = clock_context.as_deref_mut() else {
                    outcome.reason = StopReason::ClockRequired { instruction };
                    break;
                };
                let counter = match complete_clock(clock, &instruction, &mut state.registers) {
                    Ok(counter) => counter,
                    Err(error) => {
                        outcome.reason = StopReason::ClockUnavailable {
                            instruction,
                            detail: error.to_string(),
                        };
                        break;
                    }
                };
                state.pc = instruction.next_pc;
                outcome.clock_events.push(ClockEvent {
                    instruction,
                    next_pc: instruction.next_pc,
                    counter,
                });
            }
            if let Some(instruction) = pointer_authentication {
                // The implementation's permitted UNDEF constraint precedes key
                // availability checks and cannot invoke data translation.
                if let PointerAuthenticationOperation::Load(load) = instruction.operation
                    && load.undefined_overlap()
                {
                    outcome.reason = StopReason::PointerAuthenticationLoadUndefined { instruction };
                    break;
                }
                let Some(execution) = pauth_execution.as_mut() else {
                    outcome.reason = StopReason::PointerAuthenticationRequired { instruction };
                    break;
                };
                let context = execution.context;
                if let Some(key) = instruction.operation.required_key()
                    && !context.has_key(runtime_pauth_key(key))
                {
                    outcome.reason =
                        StopReason::PointerAuthenticationKeyUnavailable { instruction, key };
                    break;
                }
                if matches!(
                    instruction.operation,
                    PointerAuthenticationOperation::GenericCode(_)
                ) && !context.has_generic_key()
                {
                    outcome.reason =
                        StopReason::PointerAuthenticationGenericKeyUnavailable { instruction };
                    break;
                }
                let result = complete_pauth_with_memory(
                    context,
                    &instruction,
                    &mut state.registers,
                    execution.memory.as_mut(),
                );
                let (next, authenticated) = match result {
                    Ok(value) => value,
                    Err(error) => {
                        outcome.reason = match error.downcast_ref::<pauth::AuthenticationError>() {
                            Some(pauth::AuthenticationError::Failure { code }) => {
                                StopReason::PointerAuthenticationFailure {
                                    instruction,
                                    code: *code,
                                }
                            }
                            _ => match error.downcast_ref::<AuthenticatedLoadError>() {
                                Some(AuthenticatedLoadError::UndefinedOverlap) => {
                                    StopReason::PointerAuthenticationLoadUndefined { instruction }
                                }
                                Some(AuthenticatedLoadError::StackAlignment { stack_pointer }) => {
                                    StopReason::PointerAuthenticationStackAlignment {
                                        instruction,
                                        stack_pointer: *stack_pointer,
                                    }
                                }
                                Some(AuthenticatedLoadError::MemoryRequired) => {
                                    StopReason::PointerAuthenticationMemoryRequired { instruction }
                                }
                                Some(AuthenticatedLoadError::Read(fault)) => {
                                    StopReason::PointerAuthenticationMemoryFault {
                                        instruction,
                                        fault: *fault,
                                    }
                                }
                                None => StopReason::PointerAuthenticationUnsupported {
                                    instruction,
                                    detail: error.to_string(),
                                },
                            },
                        };
                        break;
                    }
                };
                state.pc = next;
                let poisoned_transfer =
                    instruction.operation.is_transfer() && authenticated == Some(false);
                outcome
                    .pointer_authentication_events
                    .push(PointerAuthenticationEvent {
                        instruction,
                        next_pc: next,
                        authenticated,
                    });
                if poisoned_transfer {
                    outcome.reason = if instruction.operation.is_return() {
                        StopReason::PointerAuthenticationPoisonedReturn {
                            instruction,
                            poisoned_target: next,
                        }
                    } else {
                        StopReason::PointerAuthenticationPoisonedBranch {
                            instruction,
                            poisoned_target: next,
                        }
                    };
                    break;
                }
            }
            if let Some(trap) = trap {
                // The already executed instruction takes precedence over a
                // coincident stop address or exhausted block budget. Do not
                // advance to its return PC or execute another source block.
                outcome.reason = StopReason::SynchronousTrap { trap };
                break;
            }
        }
        Ok(outcome)
    }

    /// Inspect source/native identity and reverse maps without exposing RX pointers.
    pub fn loaded_manifest(&self, pc: GuestAddress) -> Option<&crate::Manifest> {
        self.loaded.get(&pc.0).map(|block| &block.prepared.manifest)
    }
}

#[cfg(test)]
mod tests;
