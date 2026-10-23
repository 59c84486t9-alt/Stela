//! Original-source qualification of checked shared-memory emission. The oracle
//! supplies the same fixed EL0/LE/LSE2/A0, untagged Normal-WB RAM contract. This
//! does not claim a complete PE/exception adapter or parallel machine execution.
use super::*;
use stela_compiler::{
    Lifter,
    aarch64::{Decoder, Operation, ordered, simd},
    block::CheckedMemoryProfile,
};
use stela_runtime::{
    execution::checked_memory::CheckedMemoryBlock,
    system::{
        debug::DebugControls,
        events::EventDomain,
        fp_access::{self, NoSme, StreamingState},
        identification::Register as Id,
        identification_snapshot::Snapshot,
        process_memory::{FixedProcessMemoryControls, SourceNormalWbDomain},
        scalable_controls::fp::FpControlOwner,
        state::{El1Registers, SystemState},
    },
};

fn admitted(operation: &Operation) -> bool {
    match operation {
        Operation::Atomic(_) => true,
        Operation::Ordered(ordered::Operand::Transfer {
            feature: ordered::Feature::Lor,
            ..
        }) => false,
        Operation::Ordered(_) => true,
        Operation::Literal(_) | Operation::Simd(simd::Operand::StructureMemory(_)) => true,
        _ => false,
    }
}

pub(super) fn prepare(words: &[u32]) -> Result<Option<CheckedMemoryBlock>> {
    for (index, word) in words.iter().enumerate() {
        let instruction = match Decoder.lift(
            GuestAddress(CODE_PAGE + (index * INSTRUCTION_BYTES) as u64),
            *word,
        ) {
            Ok(instruction) => instruction,
            Err(_) => return Ok(None),
        };
        if !admitted(&instruction.operation) {
            return Ok(None);
        }
    }
    let source: Vec<u8> = words
        .iter()
        .chain(&[RET])
        .flat_map(|word| word.to_le_bytes())
        .collect();
    let requirements = stela_compiler::block::CompilationPlan::new(
        &source,
        GuestAddress(CODE_PAGE),
        BlockProfile::CheckedMemory(CheckedMemoryProfile::SpAlignmentEnabled),
        target(),
    )?
    .memory_requirements()
    .context("checked requirements")?;
    use stela_compiler::context::memory::host_caps;
    if requirements.required_host_caps & host_caps::CX16 != 0 && !target().supports(TargetCpu::Cx16)
        || requirements.required_host_caps & host_caps::ATOMIC_LOAD16 != 0
            && !target().supports(TargetCpu::AtomicLoad16)
    {
        return Ok(None);
    }
    CheckedMemoryBlock::compile(
        ADDRESS_SPACE,
        GuestAddress(CODE_PAGE),
        source,
        CheckedMemoryProfile::SpAlignmentEnabled,
        target(),
    )
    .map(Some)
}
pub(super) fn run(
    body: &CheckedMemoryBlock,
    windows: &Windows,
    case: &Case,
) -> Result<(GuestState, u64, Option<super::super::Exception>)> {
    let rights = AccessPermissions {
        readable: true,
        writable: true,
        executable: false,
    };
    let attributes = MappingAttributes {
        tagged: false,
        shareable: true,
    };
    let view = |pointer, guest, bytes, rights| -> Result<_> {
        // SAFETY: windows' mutex owns all accesses and pins the raw allocation;
        // installation finished before this domain exists and no external writer
        // may run until the complete synchronous invocation and loans are gone.
        let backing = unsafe { MemoryBacking::new(pointer, bytes, rights, Arc::new(())) }
            .map_err(|error| anyhow::anyhow!("checked backing: {error:?}"))?;
        let view = MemoryView::new(backing, guest, 0, bytes, rights)
            .map_err(|error| anyhow::anyhow!("checked view: {error:?}"))?;
        Ok((view, attributes))
    };
    let system = MemorySystem::new(RESERVATION_GRANULE, RESERVATION_STRIPES)
        .map_err(|error| anyhow::anyhow!("checked monitor: {error:?}"))?;
    let domain = MemoryDomain::new_for_address_space(
        ADDRESS_SPACE,
        system,
        vec![
            view(windows.data, DATA_WINDOW, DATA_BYTES, rights)?,
            view(
                windows.code,
                CODE_REGION,
                CODE_REGION_BYTES,
                AccessPermissions {
                    writable: false,
                    ..rights
                },
            )?,
        ],
        target(),
    )
    .map_err(|error| anyhow::anyhow!("checked domain: {error:?}"))?;
    let ids = Arc::new(
        Snapshot::declared(
            "oracle-checked-el0-memory-contract",
            &[
                (Id::IdAa64Pfr0El1, 0x11),
                (Id::IdAa64Mmfr0El1, 0),
                (Id::IdAa64Mmfr2El1, 1 << 32),
                (Id::IdAa64Mmfr3El1, 0),
                (Id::IdAa64Mmfr4El1, 0),
                (Id::IdAa64Isar3El1, 0),
                (Id::IdAa64Pfr1El1, 0),
                (Id::IdAa64Dfr0El1, 0),
                (Id::IdAa64Isar0El1, 2 << 20),
                (Id::IdAa64Isar1El1, 2 << 20),
            ],
        )
        .map_err(|error| anyhow::anyhow!("checked source IDs: {error:?}"))?,
    );
    // SAFETY: the harness explicitly resolves every source view as untagged,
    // shareable Normal WB, with matching physical identity and permissions.
    let source = unsafe { SourceNormalWbDomain::from_source_resolved(Arc::clone(&domain)) }
        .map_err(|error| anyhow::anyhow!("checked source attributes: {error:?}"))?;
    let controls = FixedProcessMemoryControls::new_with_identification(
        Arc::clone(&ids),
        1 | (1 << 2) | (1 << 4),
        u64::from(64 - ADDRESS_BITS),
        ADDRESS_BITS,
        source,
    )
    .map_err(|error| anyhow::anyhow!("checked CPU controls: {error:?}"))?;
    let lower = LowerAddressProfile::new(ADDRESS_BITS, false)
        .map_err(|error| anyhow::anyhow!("checked lower range: {error:?}"))?;
    let mut memory = domain.thread(MemoryControls::new(
        lower,
        false,
        false,
        false,
        TagCheckFaultMode::Ignore,
        false,
    ));
    let event = EventDomain::new()
        .register(false, None)
        .map_err(|error| anyhow::anyhow!("checked events: {error:?}"))?;
    memory
        .bind_events(&event.producer())
        .map_err(|error| anyhow::anyhow!("checked PE: {error:?}"))?;
    let system = SystemState::new(0, 0, El1Registers::new(0, 0, 0, 0, 0))
        .map_err(|error| anyhow::anyhow!("checked EL0: {error:?}"))?;
    let mut thread = ThreadState {
        registers: case.state.clone(),
        pc: GuestAddress(CODE_PAGE),
    };
    // SAFETY: closed original source, fixed qualified EL0 state and no debug,
    // IRQ, MTE or direct/DMA writer. Every reached memory effect uses this domain.
    let asimd = case.code.iter().any(|word| {
        matches!(
            Decoder
                .lift(GuestAddress(CODE_PAGE), *word)
                .map(|instruction| instruction.operation),
            Ok(Operation::Literal(
                stela_compiler::aarch64::literal::Operand {
                    transfer: stela_compiler::aarch64::literal::Transfer::Simd { .. },
                    ..
                }
            ) | Operation::Simd(simd::Operand::StructureMemory(_)))
        )
    });
    let observed = if asimd {
        // This oracle is explicitly EL0, enabled non-streaming FP, without
        // SVE/SME. Actual ASIMD memory admission retains that exact owner and
        // same mutable bank; the ordinary entry continues to refuse ASIMD.
        let fp = FpControlOwner::new_declared_el10(&ids, 3 << 20)
            .map_err(|error| anyhow::anyhow!("checked FP controls: {error:?}"))?;
        let no_sme = NoSme::from_snapshot(&ids)
            .map_err(|error| anyhow::anyhow!("checked SME absence: {error:?}"))?;
        let debug = DebugControls {
            halted: false,
            ignore_traps_in_debug: false,
            halting_allowed: false,
            edscr_tda: false,
            os_locked: false,
            breakpoint_count: 0,
            watchpoint_count: 0,
            raw_bank: 0,
            effective_bank: 0,
        };
        fp_access::with_nonstreaming_low128(
            &ids,
            &fp,
            &system,
            StreamingState::Absent(no_sme),
            &mut thread.registers,
            thread.pc,
            |mut access| {
                // SAFETY: exact fixture source and retained FP/domain authority
                // cover this same bank through memory and PC finalization.
                unsafe {
                    body.run_with_low128(
                        &controls,
                        &system,
                        &debug,
                        &mut memory,
                        &event,
                        &mut thread.pc,
                        &mut access,
                    )
                }
            },
        )
        .map_err(|error| anyhow::anyhow!("checked FP entry: {error:?}"))??
    } else {
        // SAFETY: exact fixture contract described above, ordinary authority.
        unsafe { body.run(&controls, &system, &mut memory, &event, &mut thread) }?
    };
    let exception = observed.fault.map(translation_fault).transpose()?;
    // Like the existing leaf lane, the closing RET is harness machinery; compare
    // the source prefix's next PC, not its synthetic terminal's X30 target.
    Ok((
        thread.registers,
        exception.map_or(CODE_PAGE + (case.steps * INSTRUCTION_BYTES) as u64, |fault| fault.address),
        exception,
    ))
}

/// This fixture maps the complete data window through valid level-3 pages and
/// leaves the next page absent. Only that exact EL0/LE/A=0 fault is synthesized;
/// it supplies no general architectural exception adapter. AdvSIMD accesses
/// have ISV=0, and a failed checked entry retains its exact source PC and FAR.
fn translation_fault(fault: stela_runtime::memory::domain::MemoryFault) -> Result<super::super::Exception> {
    use stela_compiler::context::memory::{FaultAccess, MemoryStatus};
    ensure!(fault.status == MemoryStatus::Translation, "unqualified checked oracle fault: {fault:?}");
    ensure!(fault.address == DATA_WINDOW + DATA_BYTES as u64,
        "checked oracle fault outside qualified window boundary: {fault:?}");
    let write = match fault.access {
        FaultAccess::Read => false,
        FaultAccess::Write => true,
        _ => anyhow::bail!("unqualified checked oracle fault direction: {fault:?}"),
    };
    // EC=Data Abort from lower EL; IL=1; DFSC=Translation fault, level 3.
    const EL0_DATA_ABORT: u64 = (0x24 << 26) | (1 << 25);
    const WRITE: u64 = 1 << 6;
    const TRANSLATION_LEVEL3: u64 = 0b000111;
    Ok(super::super::Exception {
        syndrome: EL0_DATA_ABORT | (if write { WRITE } else { 0 }) | TRANSLATION_LEVEL3,
        address: fault.pc,
        fault_address: fault.address,
        level: 1,
        hpfar: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checked_oracle_admits_all_canonical_structure_samples_and_no_other_simd() {
        // Load the source inventory directly: no compile success substitutes for
        // checking the original typed operations for all 150 canonical forms.
        let registry: serde_json::Value = serde_json::from_str(include_str!("../../../../isa/apple-silicon-reviewed-forms.json")).unwrap();
        let mut forms = 0;
        for form in registry["forms"].as_array().unwrap() {
            if !form["id"].as_str().unwrap().contains("asisdl") { continue; }
            forms += 1;
            for sample in form["smoke_samples"].as_array().unwrap() {
                let word = u32::from_str_radix(sample["word"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                let instruction = Decoder.lift(GuestAddress(CODE_PAGE), word).unwrap();
                assert!(matches!(instruction.operation, Operation::Simd(simd::Operand::StructureMemory(_))));
                assert!(admitted(&instruction.operation));
            }
        }
        assert_eq!(forms, 150);
        for word in [0x4e22_8420, 0x4e01_0000, 0x3dc0_0040] {
            let instruction = Decoder.lift(GuestAddress(CODE_PAGE), word).unwrap();
            assert!(!admitted(&instruction.operation));
        }
    }

    #[test]
    fn checked_fault_adapter_refuses_unqualified_status_or_address() {
        use stela_compiler::context::memory::{FaultAccess, MemoryStatus};
        let fault = stela_runtime::memory::domain::MemoryFault {
            status: MemoryStatus::Translation, access: FaultAccess::Read,
            address: DATA_WINDOW + DATA_BYTES as u64, pc: CODE_PAGE, completed_bytes: 0,
        };
        let read = translation_fault(fault).unwrap();
        assert_eq!(read.syndrome, 0x9200_0007);
        let write = translation_fault(stela_runtime::memory::domain::MemoryFault { access: FaultAccess::Write, ..fault }).unwrap();
        assert_eq!(write.syndrome, 0x9200_0047);
        for status in [MemoryStatus::Permission, MemoryStatus::Alignment, MemoryStatus::Unsupported] {
            assert!(translation_fault(stela_runtime::memory::domain::MemoryFault { status, ..fault }).is_err());
        }
        assert!(translation_fault(stela_runtime::memory::domain::MemoryFault { address: fault.address - 1, ..fault }).is_err());
    }

    #[test]
    fn checked_oracle_admits_exact_integer_and_simd_literals_without_prefetch() {
        for form in [
            0x18000000u32,
            0x58000000,
            0x98000000,
            0x1c000000,
            0x5c000000,
            0x9c000000,
        ] {
            for register in [0, 10, 30, 31] {
                let instruction = Decoder
                    .lift(GuestAddress(CODE_PAGE), form | (4 << 5) | register)
                    .unwrap();
                assert!(admitted(&instruction.operation));
            }
        }
        for word in [0xdc000000u32, 0xd8000000, 0xf9400000, 0xd503201f] {
            if let Ok(instruction) = Decoder.lift(GuestAddress(CODE_PAGE), word) {
                assert!(
                    !admitted(&instruction.operation),
                    "unexpected class {word:#x}"
                );
            }
        }
    }
}
