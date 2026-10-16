//! Physical instruction fetch. Callers perform stage-1 translation and alignment
//! checks first.

use super::PhysicalAddressSpace;
use crate::memory::{
    backing::{AccessKind, MemoryBacking, MemoryView},
    domain::{MemoryExecutionLoan, PhysicalAccess, access},
    stage1,
};
use alloc::sync::Arc;

const INSTRUCTION_BYTES: usize = size_of::<u32>();
const INSTRUCTION_ALIGNMENT_MASK: u64 = INSTRUCTION_BYTES as u64 - 1;

/// Retained storage under the stronger contract for immutable code.
pub(crate) struct ImmutableCodeBacking {
    backing: Arc<MemoryBacking>,
}

impl ImmutableCodeBacking {
    /// Wrap existing immutable code storage without changing its identity.
    ///
    /// # Safety
    /// The storage owner has made the whole extent readable coherent write-back
    /// RAM with no host-writable mapping or alias, and keeps its rights and
    /// bytes fixed until the last backing is dropped. Nothing (guest, host
    /// publisher, DMA, firmware, NMI or other agent) may modify a byte through
    /// another alias or address space, and no Rust reference to the bytes
    /// survives. Every physical alias uses this backing and machine. Guest
    /// execute means permission to read the instruction bytes, never host
    /// execute permission.
    pub(crate) unsafe fn adopt(backing: Arc<MemoryBacking>) -> Result<Self, &'static str> {
        let maximum = backing.maximum_permissions();
        if maximum.writable || !maximum.executable {
            return Err("immutable code backing must deny writes and permit guest fetch");
        }
        Ok(Self { backing })
    }

    pub(crate) fn backing(&self) -> &Arc<MemoryBacking> {
        &self.backing
    }
}

/// One actually reached instruction and every physical generation it used.
/// The existing CodeRegion will own this binding beside its source bytes.
/// It creates neither a second source cache nor another identity/generation.
pub(crate) struct BoundPhysicalInstruction {
    raw_pc: u64,
    physical_address: u64,
    word: u32,
    reached: PhysicalAccess,
    mutation_generation: Option<u64>,
}

impl BoundPhysicalInstruction {
    pub(crate) fn raw_pc(&self) -> u64 {
        self.raw_pc
    }

    pub(crate) fn physical_address(&self) -> u64 {
        self.physical_address
    }

    pub(crate) fn word(&self) -> u32 {
        self.word
    }

    pub(crate) fn backing(&self) -> &Arc<MemoryBacking> {
        self.reached.first().view().backing()
    }

    pub(crate) fn backing_offset(&self) -> usize {
        self.reached.first().backing_offset()
    }

    pub(crate) fn views(&self) -> impl Iterator<Item = &Arc<MemoryView>> {
        core::iter::once(self.reached.first().view())
            .chain(self.reached._remaining.iter().map(|span| span.view()))
    }

    pub(crate) fn is_current(&self) -> bool {
        self.views().all(|view| view.is_current())
    }

    pub(crate) fn bytes_are_current(&self) -> bool {
        match self.mutation_generation {
            Some(generation) => self.backing().instruction_generation_current(generation),
            None => self.backing().instruction_generation().is_none(),
        }
    }
    /// The pre-effect snapshot may settle its own modifying instruction. A
    /// changed backing is accepted only when contiguous write records from this
    /// system's writer explain it.
    pub(crate) fn validate_owned_writes(
        &self,
        system: &crate::memory::domain::MemorySystem,
        writes: &[crate::memory::domain::SourceWriteReceipt],
    ) -> Result<(), &'static str> {
        if !self.is_current() {
            return Err("in-flight source mapping retired");
        }
        system.validate_owned_source_writes(self.backing(), self.mutation_generation, writes)
    }

    /// Same storage and same mapping generations, not just equal bytes.
    pub(crate) fn same_source(&self, other: &Self) -> bool {
        self.raw_pc == other.raw_pc
            && self.physical_address == other.physical_address
            && self.word == other.word
            && self.mutation_generation == other.mutation_generation
            && Arc::ptr_eq(self.backing(), other.backing())
            && self.backing_offset() == other.backing_offset()
            && self.views().count() == other.views().count()
            && self
                .views()
                .zip(other.views())
                .all(|(first, next)| Arc::ptr_eq(first, next))
    }
}

impl PhysicalAddressSpace {
    /// Re-check a reached physical pin after its instruction retired. Retiring
    /// the cache entry does not change the pinned storage, view or mutation
    /// state. This fetches, registers, copies and allocates nothing.
    pub(crate) fn validate_retired_instruction(
        &self,
        execution: &MemoryExecutionLoan,
        source: &BoundPhysicalInstruction,
    ) -> Result<(), &'static str> {
        self.check_execution_loan(execution)
            .map_err(|_| "retired source lost its physical/outer owner")?;
        self.check_reached(&source.reached)
            .map_err(|_| "retired source view is not the physical owner")?;
        source.validate_owned_writes(self.memory_system(), &[])
    }

    /// Instruction fetch for the control owner, outside the M0 path. The scope
    /// derives the current controls and uses this physical owner.
    pub(crate) fn fetch_control_instruction(
        &self,
        raw_pc: u64,
        scope: &crate::blocks::ControlCodeScope<'_>,
        state: &crate::system::state::SystemState,
    ) -> Result<BoundPhysicalInstruction, crate::system::translation_controls::FetchFailure> {
        use crate::system::translation_controls::FetchFailure;
        if !scope.same_physical_owner(self) {
            return Err(FetchFailure::Unavailable(
                "control fetch uses a different physical owner",
            ));
        }
        let translation = scope.canonical_fetch(state, raw_pc)?;
        scope
            .check_fetch_policy(&translation, raw_pc, state)
            .map_err(FetchFailure::Unavailable)?;
        let source_controls = scope.source_cache_controls()?;
        let reached = match scope.retained_outer() {
            Some(outer) => self.read_instruction(
                outer,
                &translation,
                raw_pc,
                scope.immutable_sources(),
                source_controls,
            ),
            None => self.read_legacy_instruction(
                &translation,
                raw_pc,
                scope.immutable_sources(),
                source_controls,
            ),
        }
        .map_err(FetchFailure::Platform)?;
        scope
            .check_source_word(raw_pc, reached.word())
            .map_err(FetchFailure::Unavailable)?;
        Ok(reached)
    }

    /// Fetch a single LDR64 instruction for the installed M0 owner, reading the
    /// immutable instruction bytes with guest execute rights. Re-validation
    /// borrows the consumer's outer object; construction supplies its single
    /// construction borrow.
    pub(crate) fn fetch_m0_instruction(
        &self,
        execution: &MemoryExecutionLoan,
        controls: &crate::system::translation_controls::TranslationControls,
        scope: &crate::blocks::InstalledM0SourceScope<'_>,
        state: &crate::system::state::SystemState,
        raw_pc: u64,
    ) -> Result<BoundPhysicalInstruction, crate::system::translation_controls::FetchFailure> {
        use crate::system::translation_controls::FetchFailure;
        if !core::ptr::eq(self, scope.physical_space()) {
            return Err(FetchFailure::Unavailable(
                "M0 fetch uses a different physical owner",
            ));
        }
        self.check_execution_loan(execution)
            .map_err(|_| FetchFailure::Unavailable("M0 fetch execution loan is unavailable"))?;
        let translation = scope.canonical_fetch(controls, state, raw_pc)?;
        scope
            .check_fetch_policy(&translation, raw_pc, state)
            .map_err(FetchFailure::Unavailable)?;
        let reached = self
            .read_instruction(
                execution,
                &translation,
                raw_pc,
                scope.immutable_sources(),
                scope.installed_snapshot().consumer_inputs().sctlr_el1,
            )
            .map_err(FetchFailure::Platform)?;
        scope
            .check_source_word(raw_pc, reached.word())
            .map_err(FetchFailure::Unavailable)?;
        Ok(reached)
    }

    /// Fetch one EL1 direct-B instruction from the installed source under the
    /// outer borrow.
    pub(crate) fn fetch_el1_instruction(
        &self,
        execution: &MemoryExecutionLoan,
        controls: &crate::system::translation_controls::TranslationControls,
        scope: &crate::blocks::InstalledEl1SourceScope<'_>,
        state: &crate::system::state::SystemState,
        raw_pc: u64,
    ) -> Result<BoundPhysicalInstruction, crate::system::translation_controls::FetchFailure> {
        use crate::system::translation_controls::FetchFailure;
        if !core::ptr::eq(self, scope.physical_space()) {
            return Err(FetchFailure::Unavailable(
                "branch fetch uses a different physical owner",
            ));
        }
        self.check_execution_loan(execution)
            .map_err(|_| FetchFailure::Unavailable("branch fetch execution loan is unavailable"))?;
        let translation = scope.canonical_fetch(controls, state, raw_pc)?;
        scope
            .check_fetch_policy(&translation, raw_pc, state)
            .map_err(FetchFailure::Unavailable)?;
        let reached = self
            .read_instruction(
                execution,
                &translation,
                raw_pc,
                scope.immutable_sources(),
                scope.installed_snapshot().consumer_inputs().sctlr_el1,
            )
            .map_err(FetchFailure::Platform)?;
        scope
            .check_source_word(raw_pc, reached.word())
            .map_err(FetchFailure::Unavailable)?;
        Ok(reached)
    }

    pub(crate) fn memory_system(&self) -> &Arc<crate::memory::domain::MemorySystem> {
        &self.domain.system
    }

    pub(crate) fn check_fetch_execution(&self) -> Result<(), &'static str> {
        self.check_source_binding()
            .map_err(|_| "physical fetch source binding is unavailable")
    }

    // Older owners take this local borrow; the M0 path never comes here.
    fn read_legacy_instruction(
        &self,
        translation: &stage1::Translation,
        raw_pc: u64,
        immutable_sources: &[ImmutableCodeBacking],
        source_controls: u64,
    ) -> Result<BoundPhysicalInstruction, &'static str> {
        let execution = self
            .domain
            .execution_loan()
            .map_err(|_| "legacy physical fetch domain is unavailable")?;
        self.read_instruction(
            &execution,
            translation,
            raw_pc,
            immutable_sources,
            source_controls,
        )
    }

    pub(super) fn read_instruction(
        &self,
        execution: &MemoryExecutionLoan,
        translation: &stage1::Translation,
        raw_pc: u64,
        immutable_sources: &[ImmutableCodeBacking],
        source_controls: u64,
    ) -> Result<BoundPhysicalInstruction, &'static str> {
        let access = translation.access();
        if access.kind != stage1::AccessKind::Fetch || access.raw_virtual_address != raw_pc {
            return Err("canonical translation does not describe this instruction fetch");
        }
        if raw_pc & INSTRUCTION_ALIGNMENT_MASK != 0
            || translation.physical_address() & INSTRUCTION_ALIGNMENT_MASK != 0
        {
            return Err("canonical instruction-address alignment check is required");
        }
        if translation.contiguous_bytes() < INSTRUCTION_BYTES as u64 {
            return Err("instruction fetch crosses an unresolved translation leaf");
        }
        self.check_execution_loan(execution)
            .map_err(|_| "physical fetch source binding is unavailable")?;
        let reached = self
            .domain
            .resolve_source_physical(
                execution,
                translation.physical_address(),
                INSTRUCTION_BYTES,
                AccessKind::Execute,
            )
            .map_err(|_| "physical fetch mapping is unavailable or denies execute")?;
        self.check_reached(&reached)
            .map_err(|_| "physical fetch source generation is unavailable")?;
        let first = reached.first();
        let mutable = first.view().backing().instruction_generation().is_some();
        if mutable {
            const SCTLR_DATA_CACHE: u64 = 1 << 2;
            const SCTLR_INSTRUCTION_CACHE: u64 = 1 << 12;
            if source_controls & (SCTLR_DATA_CACHE | SCTLR_INSTRUCTION_CACHE) != 0 {
                return Err("mutable instruction visibility requires disabled I/C caches");
            }
        } else if !immutable_sources
            .iter()
            .any(|source| Arc::ptr_eq(source.backing(), first.view().backing()))
        {
            return Err("physical fetch has no retained instruction backing owner");
        }
        let pointer = first.host_ptr().as_ptr();
        let (address, bytes) =
            access::read_footprint(pointer as usize, INSTRUCTION_BYTES, self.domain.target)
                .map_err(|_| "physical fetch native read recipe is unavailable")?;
        if address != pointer as usize || bytes != INSTRUCTION_BYTES {
            return Err("physical fetch would require an unauthorized read envelope");
        }
        // Execute construction's host contract guarantees native instruction-byte
        // readability even for a guest execute-only physical view. No guest data
        // Read permission or host Execute right is invented here.
        first
            .view()
            .backing()
            .host_pointer(
                first.backing_offset(),
                INSTRUCTION_BYTES,
                AccessKind::Execute,
            )
            .map_err(|_| "physical instruction storage extent is unavailable")?;
        if !first.view().is_current()
            || reached
                ._remaining
                .iter()
                .any(|span| !span.view().is_current())
        {
            return Err("physical instruction view has been retired");
        }
        // SAFETY: the immutable owner pins coherent readable storage and
        // excludes every writer and aliasing reference. Resolution checks
        // execute permission on all reached views and keeps their generations.
        // The caller's execution borrow lasts through this read, registration
        // and re-validation, and the access is exactly four bytes.
        let (word, mutation_generation) =
            self.domain
                .system
                .read_instruction_source(first.view().backing(), || {
                    // SAFETY: the execute span pins readable coherent RAM, and
                    // either the immutable owner or the tracked writer excludes
                    // every byte writer. No reference to source bytes escapes.
                    unsafe { access::read_part(pointer, INSTRUCTION_BYTES, self.domain.target) }
                        .map(|value| value as u32)
                        .map_err(|_| "physical instruction read is unavailable")
                })?;
        let binding = BoundPhysicalInstruction {
            raw_pc,
            physical_address: translation.physical_address(),
            word,
            reached,
            mutation_generation,
        };
        if !binding.is_current() {
            return Err("physical instruction view retired during fetch");
        }
        self.domain
            .check_execution()
            .map_err(|_| "physical fetch domain failed after the reached read")?;
        Ok(binding)
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use crate::memory::source_ram::{
        InitializedRamRegion, PhysicalRamRange, SourceRamDeclaration, SourceRamPermissions,
        SourceRamSystemConfig, materialize_source_ram_regions,
    };
    const BASE: u64 = 0x1000;
    const WORD: u32 = 0xd503_207f;
    fn actual_pin() -> (
        PhysicalAddressSpace,
        MemoryExecutionLoan,
        BoundPhysicalInstruction,
    ) {
        let prefix = WORD.to_le_bytes().to_vec();
        let materialized = materialize_source_ram_regions(
            SourceRamDeclaration {
                address_space: 713,
                target: stela_compiler::TargetCpu::Baseline,
                declared_capacity: vec![PhysicalRamRange {
                    source_pa: BASE,
                    bytes: 64,
                }],
                initialized: Vec::new(),
            },
            Vec::new(),
            vec![InitializedRamRegion {
                range: PhysicalRamRange {
                    source_pa: BASE,
                    bytes: 64,
                },
                file_sha256: crate::sha256(&prefix),
                file_prefix: prefix,
                permissions: SourceRamPermissions {
                    readable: true,
                    writable: true,
                    executable: true,
                },
            }],
            SourceRamSystemConfig {
                reservation_granule_bytes: 16,
                reservation_stripe_count: 8,
            },
        )
        .unwrap();
        let (binding, immutable) = materialized.into_parts();
        assert!(immutable.is_empty());
        let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
        let outer = physical.initial_source_execution_loan().unwrap();
        let config = stage1::Config::from_controls_for_cpu(
            stage1::Controls {
                ttbr0_el1: 0,
                ttbr1_el1: 0,
                tcr_el1: 0,
                sctlr_el1: 0,
                mair_el1: 0,
            },
            stage1::CpuProfile {
                pa_max: stage1::PaBits::Bits40,
                asid_bits: stage1::AsidBits::Bits8,
                granules: stage1::GranuleSupport {
                    kib4: true,
                    kib16: true,
                    kib64: false,
                    lower_fallback: stage1::Granule::KiB4,
                    upper_fallback: stage1::Granule::KiB4,
                },
                pauth: false,
                pan: false,
                pan3: false,
            },
        )
        .unwrap();
        let translation = stage1::translate(
            &config,
            &physical,
            stage1::Access {
                kind: stage1::AccessKind::Fetch,
                exception_level: stage1::ExceptionLevel::El1,
                raw_virtual_address: BASE,
                source_pc: BASE,
                pan: false,
                uao: false,
                aligned: true,
            },
        )
        .unwrap();
        let pin = physical
            .read_instruction(&outer, &translation, BASE, &[], 0)
            .unwrap();
        (physical, outer, pin)
    }
    #[test]
    fn retained_pin_rejects_foreign_owner_and_unaccounted_identical_write() {
        let (physical, outer, pin) = actual_pin();
        physical.validate_retired_instruction(&outer, &pin).unwrap();
        let (foreign, foreign_outer, _) = actual_pin();
        assert!(
            foreign
                .validate_retired_instruction(&foreign_outer, &pin)
                .is_err()
        );
        drop(outer);
        {
            let _service = physical.domain().service_loan().unwrap();
            // SAFETY: a writer of the same memory system under a quiescent
            // service loan; identical bytes still advance the mutation history.
            unsafe {
                physical.memory_system().publish(
                    pin.backing(),
                    pin.backing_offset(),
                    &WORD.to_le_bytes(),
                )
            }
            .unwrap();
        }
        let outer = physical.initial_source_execution_loan().unwrap();
        assert_eq!(pin.word(), WORD);
        assert!(pin.is_current());
        assert!(!pin.bytes_are_current());
        assert!(physical.validate_retired_instruction(&outer, &pin).is_err());
    }
    #[test]
    fn unknown_writer_poison_precedes_retained_pin_release() {
        let (physical, outer, pin) = actual_pin();
        drop(outer);
        {
            let _service = physical.domain().service_loan().unwrap();
            let mut attempted = physical
                .memory_system()
                .prepare_source_write(pin.backing(), pin.backing_offset(), size_of::<u32>())
                .unwrap();
            attempted.attempting();
            drop(attempted); // actual writer lost its host-effect outcome
            assert!(physical.check_fetch_execution().is_err());
            assert!(pin.is_current()); // pin remains owned until after poison
        }
        assert!(physical.initial_source_execution_loan().is_err());
    }
}
