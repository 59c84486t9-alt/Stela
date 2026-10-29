//! One lexical executable mapping, never kept across a guest body.
#[cfg(feature = "native-profile")]
use super::super::super::source_profile::{Fetch, Profile};
use super::*;
use crate::memory::{RegisteredSystemRam, domain::MemoryExecutionLoan};

/// Non-Copy same-PC source witness. The borrowed controls, RAM and pin
/// cannot be substituted by a later read. Full source bytes are always reread.
pub(in crate::machine::engine::shared_memory::native_run) struct ExecuteTranslation<'a> {
    ram: &'a RegisteredSystemRam,
    _controls: &'a Controls,
    execution: &'a MemoryExecutionLoan,
    pc: u64,
    mapped: mmu::Translation,
    word: u32,
    #[cfg(feature = "native-profile")]
    profile: &'a Profile,
}
impl<'a> ExecuteTranslation<'a> {
    /// Resolve and read exactly the reached first instruction.
    ///
    /// # Safety
    /// Until this witness is dropped, the caller must exclude guest execution,
    /// code/MMU/control publication and unjoined DMA/host writers using the
    /// held-cohort or single-online-PE native-round producer contract.
    /// The execution loan alone does not exclude descriptor or ordinary writes.
    /// No Host/device service may intervene before a read through this witness.
    pub(in crate::machine::engine::shared_memory::native_run) unsafe fn first(
        ram: &'a RegisteredSystemRam,
        controls: &'a Controls,
        execution: &'a MemoryExecutionLoan,
        pc: u64,
        #[cfg(feature = "native-profile")] profile: &'a Profile,
    ) -> Result<Self, FetchFailure> {
        let mut tables = policy::Tables::new(ram);
        #[cfg(feature = "native-profile")]
        let mut resolutions = 0;
        let result = (|| {
            Self::check_owner(ram, execution).map_err(FetchFailure::Refused)?;
            if !pc.is_multiple_of(4) {
                return Err(FetchFailure::Refused(MemoryStatus::Alignment));
            }
            #[cfg(feature = "native-profile")]
            {
                resolutions = 1;
            }
            let mapped = super::resolve(
                controls,
                pc,
                &mut tables,
                #[cfg(feature = "native-profile")]
                &mut resolutions,
            )?;
            let mut bytes = [0; 4];
            // SAFETY: private staging under the caller's no-writer scope.
            unsafe { ram.read_physical(mapped.physical, &mut bytes) }
                .map_err(FetchFailure::Refused)?;
            Self::check_owner(ram, execution).map_err(FetchFailure::Refused)?;
            Ok(Self {
                ram,
                _controls: controls,
                execution,
                pc,
                mapped,
                word: u32::from_le_bytes(bytes),
                #[cfg(feature = "native-profile")]
                profile,
            })
        })();
        #[cfg(feature = "native-profile")]
        profile.record(
            Fetch::FirstWord,
            resolutions,
            tables.reads,
            4,
            result.is_ok(),
        );
        result
    }

    fn check_owner(
        ram: &RegisteredSystemRam,
        execution: &MemoryExecutionLoan,
    ) -> Result<(), MemoryStatus> {
        if !execution.belongs_to(ram.domain()) {
            return Err(MemoryStatus::Domain);
        }
        ram.domain().check_execution()
    }

    pub(in crate::machine::engine::shared_memory::native_run) fn first_word(&self) -> u32 {
        self.word
    }
    pub(in crate::machine::engine::shared_memory::native_run) fn guarded(&self) -> bool {
        self.mapped.guarded
    }

    /// Fresh private same-PC staging within both the engine fetch page and the
    /// complete translation's remaining extent. No cached first-word bytes.
    pub(in crate::machine::engine::shared_memory::native_run) fn read_into(
        &self,
        output: &mut [u8],
    ) -> Result<(), MemoryStatus> {
        let result = (|| {
            Self::check_owner(self.ram, self.execution)?;
            if output.is_empty()
                || !output.len().is_multiple_of(4)
                || output.len() > super::super::super::super::window(self.pc)
                || output.len() as u64
                    > self.mapped.size - (self.mapped.physical & (self.mapped.size - 1))
            {
                return Err(MemoryStatus::Unsupported);
            }
            // SAFETY: private staging, immutable witnessed mapping and the same
            // authentic no-code/MMU-writer scope as first().
            unsafe { self.ram.read_physical(self.mapped.physical, output) }?;
            Self::check_owner(self.ram, self.execution)
        })();
        #[cfg(feature = "native-profile")]
        self.profile
            .record(Fetch::FullSource, 0, 0, output.len(), result.is_ok());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    fn fixture(test: impl FnOnce(&mut SharedMemory, &Controls, &Arc<RegisteredSystemRam>)) {
        let (mut machine, ram, events) = crate::machine::engine::shared_memory::tests::machine();
        machine
            .install_shared_memory_for_processors(Arc::clone(&ram), &events)
            .unwrap();
        let controls =
            Controls::capture(&machine.cpu, machine.profile.name, &machine.profile_missing)
                .unwrap();
        test(
            machine.cpu.canonical_memory.as_mut().unwrap(),
            &controls,
            &ram,
        );
    }

    unsafe fn first<'a>(
        memory: &'a SharedMemory,
        controls: &'a Controls,
        loan: &'a MemoryExecutionLoan,
        pc: u64,
    ) -> Result<ExecuteTranslation<'a>, FetchFailure> {
        // SAFETY: each test keeps a lexical no-writer scope until drop.
        unsafe {
            ExecuteTranslation::first(
                &memory.ram,
                controls,
                loan,
                pc,
                #[cfg(feature = "native-profile")]
                &memory.source,
            )
        }
    }

    #[test]
    fn same_pc_prefix_rereads_canonical_bytes_with_one_resolution() {
        fixture(|memory, controls, ram| {
            let expected = [0xd503201fu32.to_le_bytes(), 0x14000001u32.to_le_bytes()].concat();
            // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
            // registered.
            unsafe { ram.publish_physical(0x14000, &expected) }.unwrap();
            #[cfg(feature = "native-profile")]
            let before = memory.source.statistics();
            let loan = memory.memory.execution_loan().unwrap();
            {
                // SAFETY: the test holds the execution loan and runs no guest, publisher or DMA
                // writer while this witness lives.
                let source = unsafe { first(memory, controls, &loan, 0x4000) }.unwrap();
                assert_eq!(source.first_word(), 0xd503201f);
                let mut output = [0; 8];
                source.read_into(&mut output).unwrap();
                assert_eq!(output.as_slice(), expected);
                assert!(ram.try_service().unwrap().is_none());
                #[cfg(feature = "native-profile")]
                {
                    let after = memory.source.statistics();
                    assert_eq!(after.resolutions - before.resolutions, 1);
                    assert_eq!(after.first_word_fetches - before.first_word_fetches, 1);
                    assert_eq!(after.full_source_fetches - before.full_source_fetches, 1);
                    assert_eq!(after.successful_bytes - before.successful_bytes, 12);
                    assert!(after.descriptor_reads > before.descriptor_reads);
                }
            }
            drop(loan);
            assert!(ram.try_service().unwrap().is_some());
            // A new scope must observe changed permissions, never old rights.
            // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
            // registered.
            unsafe { ram.publish_physical(0x13020, &0u64.to_le_bytes()) }.unwrap();
            let loan = memory.memory.execution_loan().unwrap();
            assert!(matches!(
                // SAFETY: the test holds the execution loan and runs no guest, publisher or DMA
                // writer while this witness lives.
                unsafe { first(memory, controls, &loan, 0x4000) },
                Err(FetchFailure::Fault(_))
            ));
        });
    }

    #[test]
    fn page_extent_and_instruction_size_refuse_before_staging() {
        fixture(|memory, controls, ram| {
            // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
            // registered.
            unsafe { ram.publish_physical(0x14ffc, &0xd503201fu32.to_le_bytes()) }.unwrap();
            let loan = memory.memory.execution_loan().unwrap();
            // SAFETY: the test holds the execution loan and runs no guest, publisher or DMA writer
            // while this witness lives.
            let source = unsafe { first(memory, controls, &loan, 0x4ffc) }.unwrap();
            let mut good = [0; 4];
            source.read_into(&mut good).unwrap();
            assert_eq!(good, 0xd503201fu32.to_le_bytes());
            for size in [0, 1, 3, 5, 8, 4096] {
                let mut output = alloc::vec![0xa5; size];
                assert_eq!(
                    source.read_into(&mut output),
                    Err(MemoryStatus::Unsupported)
                );
                assert!(output.iter().all(|byte| *byte == 0xa5));
            }
        });
    }

    #[test]
    fn foreign_mapping_pin_is_refused_without_an_execute_walk() {
        fixture(|memory, controls, _| {
            fixture(|foreign, _, _| {
                let loan = foreign.memory.execution_loan().unwrap();
                #[cfg(feature = "native-profile")]
                let before = memory.source.statistics();
                assert!(matches!(
                    // SAFETY: the test holds the execution loan and runs no guest, publisher or DMA
                    // writer while this witness lives.
                    unsafe { first(memory, controls, &loan, 0x4000) },
                    Err(FetchFailure::Refused(MemoryStatus::Domain))
                ));
                #[cfg(feature = "native-profile")]
                {
                    let after = memory.source.statistics();
                    assert_eq!(after.resolutions, before.resolutions);
                    assert_eq!(after.descriptor_reads, before.descriptor_reads);
                    assert_eq!(after.declined_fetches, before.declined_fetches + 1);
                }
            })
        });
    }

    #[test]
    fn cold_translation_has_one_resolution_without_descriptor_reads() {
        fixture(|memory, controls, ram| {
            let mut controls = controls.clone();
            controls.translation.sctlr &= !1;
            // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
            // registered.
            unsafe { ram.publish_physical(0x14000, &0xd503201fu32.to_le_bytes()) }.unwrap();
            let loan = memory.memory.execution_loan().unwrap();
            #[cfg(feature = "native-profile")]
            let before = memory.source.statistics();
            // SAFETY: the test holds the execution loan and runs no guest, publisher or DMA writer
            // while this witness lives.
            let source = unsafe { first(memory, &controls, &loan, 0x14000) }.unwrap();
            let mut bytes = [0; 4];
            source.read_into(&mut bytes).unwrap();
            assert_eq!(bytes, 0xd503201fu32.to_le_bytes());
            #[cfg(feature = "native-profile")]
            {
                let after = memory.source.statistics();
                assert_eq!(after.resolutions, before.resolutions + 1);
                assert_eq!(after.descriptor_reads, before.descriptor_reads);
            }
        });
    }

    #[test]
    fn failed_domain_cannot_mint_a_source_witness() {
        fixture(|memory, controls, _| {
            let loan = memory.memory.execution_loan().unwrap();
            assert_eq!(
                // SAFETY: the callback runs once on this thread and touches only the checked view.
                unsafe { memory.memory.with_checked_view(|view| view.version ^= 1) },
                Err(MemoryStatus::Domain)
            );
            assert!(matches!(
                // SAFETY: the test holds the execution loan and runs no guest, publisher or DMA
                // writer while this witness lives.
                unsafe { first(memory, controls, &loan, 0x4000) },
                Err(FetchFailure::Refused(MemoryStatus::Domain))
            ));
        });
    }
}
