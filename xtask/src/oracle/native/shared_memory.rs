//! Original-source qualification of checked shared-memory emission. The oracle
//! supplies the same fixed EL0/LE/LSE2/A0, untagged Normal-WB RAM contract. This
//! does not claim a complete PE/exception adapter or parallel machine execution.
use super::*;
use stela_compiler::{
    Lifter,
    aarch64::{Decoder, Operation, ordered},
    block::CheckedMemoryProfile,
};
use stela_runtime::{
    execution::checked_memory::CheckedMemoryBlock,
    system::{
        events::EventDomain,
        identification::Register as Id,
        identification_snapshot::Snapshot,
        process_memory::{FixedProcessMemoryControls, SourceNormalWbDomain},
        state::{El1Registers, SystemState},
    },
};

pub(super) fn prepare(words: &[u32]) -> Result<Option<CheckedMemoryBlock>> {
    for (index, word) in words.iter().enumerate() {
        let instruction = match Decoder.lift(
            GuestAddress(CODE_PAGE + (index * INSTRUCTION_BYTES) as u64),
            *word,
        ) {
            Ok(instruction) => instruction,
            Err(_) => return Ok(None),
        };
        match instruction.operation {
            Operation::Atomic(_) => {}
            Operation::Ordered(ordered::Operand::Transfer {
                feature: ordered::Feature::Lor,
                ..
            }) => return Ok(None),
            Operation::Ordered(_) => {}
            _ => return Ok(None),
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
) -> Result<(GuestState, u64)> {
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
        ids,
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
    let observed = unsafe { body.run(&controls, &system, &mut memory, &event, &mut thread) }?;
    ensure!(
        observed.fault.is_none(),
        "checked memory fault: {:?}",
        observed.fault
    );
    // Like the existing leaf lane, the closing RET is harness machinery; compare
    // the source prefix's next PC, not its synthetic terminal's X30 target.
    Ok((
        thread.registers,
        CODE_PAGE + (case.steps * INSTRUCTION_BYTES) as u64,
    ))
}
