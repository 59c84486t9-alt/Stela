//! Software system resources for the protected dyld startup route.
use anyhow::Result;
use std::sync::Arc;
use stela_compiler::{GuestAddress, context::ExecutionContext};
use stela_runtime::{
    blocks::{BlockRuntime, RunOutcome, ThreadState},
    memory::{
        OwnedMemory, SharedMemoryConfig,
        domain::{MappingAttributes, MemorySystem},
        policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
    },
    system::{
        events::EventDomain,
        identification::Register,
        identification_snapshot::Snapshot,
        process_memory::{FixedProcessMemoryControls, SourceNormalWbDomain},
        scalable_controls::fp::FpControlOwner,
        state::{El1Registers, SystemState},
    },
};
const ADDRESS_BITS: u8 = 47;
const SCTLR_NORMAL_WB: u64 = 1 | (1 << 2);
const SCTLR_ENIB: u64 = 1 << 30;
const TCR_LOWER_SIZE: u64 = 64 - ADDRESS_BITS as u64;
const EL0_EL1_A64: u64 = 0x11;
const APA_QARMA5_COMBINED: u64 = 5 << 4;
const AT_LSE2: u64 = 1 << 32;
const MASKED_EL0T: u64 = 0x3c0;

/// The identification registers of the software machine.
fn identification() -> Result<Arc<Snapshot>> {
    use Register::*;
    Ok(Arc::new(Snapshot::declared(
        "stela-bounded-el0-normal-wb-pauth-v1",
        &[
            (IdAa64Afr0El1, 0),
            (IdAa64Afr1El1, 0),
            (IdAa64Dfr0El1, 0),
            (IdAa64Dfr1El1, 0),
            (IdAa64Dfr2El1, 0),
            (IdAa64Fpfr0El1, 0),
            (IdAa64Isar0El1, 0),
            (IdAa64Isar1El1, APA_QARMA5_COMBINED),
            (IdAa64Isar2El1, 0),
            (IdAa64Isar3El1, 0),
            (IdAa64Mmfr0El1, 0),
            (IdAa64Mmfr1El1, 0),
            (IdAa64Mmfr2El1, AT_LSE2),
            (IdAa64Mmfr3El1, 0),
            (IdAa64Mmfr4El1, 0),
            (IdAa64Pfr0El1, EL0_EL1_A64),
            (IdAa64Pfr1El1, 0),
            (IdAa64Pfr2El1, 0),
            (IdAa64Smfr0El1, 0),
            (IdAa64Zfr0El1, 0),
        ],
    )?))
}

/// Execute the reviewed startup windows under the declared software CPU.
///
/// # Safety
/// `runtime` and `state` must describe the bounded startup path, and `memory`
/// must own every referenced mapping without concurrent execution or mutation.
/// This call consumes the software PE's entire execution lifetime.
pub(super) unsafe fn run(
    runtime: &mut BlockRuntime,
    state: &mut ThreadState,
    stop: GuestAddress,
    memory: &mut OwnedMemory,
    pauth: &stela_runtime::pauth::Context,
) -> Result<RunOutcome> {
    let ids = identification()?;
    let mut clock = stela_runtime::clock::Context::native(runtime.address_space())?;
    let mut thread = stela_runtime::thread::Context::native(
        runtime.address_space(),
        stela_runtime::thread::VmMaximum::new((1u64 << ADDRESS_BITS) - 1)?,
    )?;
    // SAFETY: the caller exclusively owns the image and stack mappings. The
    // clock is created here for the same address space and participates in
    // this binding for the remainder of the run.
    let domain = unsafe {
        memory.bind_shared_memory_participants(
            SharedMemoryConfig {
                address_space: runtime.address_space(),
                system: MemorySystem::new(16, 64)
                    .map_err(|e| anyhow::anyhow!("memory system: {e:?}"))?,
                target: runtime.target_cpu(),
                attributes: MappingAttributes {
                    tagged: false,
                    shareable: true,
                },
            },
            &mut [clock.shared_memory_participant()],
        )
    }?;
    let mut memory_thread = domain.thread(MemoryControls::new(
        LowerAddressProfile::new(ADDRESS_BITS, false)
            .map_err(|e| anyhow::anyhow!("lower address profile: {e:?}"))?,
        false,
        false,
        false,
        TagCheckFaultMode::Ignore,
        false,
    ));
    let events = EventDomain::new();
    let endpoint = events
        .register(false, None)
        .map_err(|e| anyhow::anyhow!("event domain: {e:?}"))?;
    memory_thread
        .bind_events(&endpoint.producer())
        .map_err(|e| anyhow::anyhow!("event binding: {e:?}"))?;
    // SAFETY: this software machine declares Normal write-back, shareable,
    // untagged mappings over the bound image, stack and clock ranges. Their
    // published generation stays fixed during this exclusively borrowed run;
    // the fixed SCTLR/TCR controls below describe the same mapping contract.
    let source = unsafe { SourceNormalWbDomain::from_source_resolved(domain) }
        .map_err(|e| anyhow::anyhow!("source domain: {e:?}"))?;
    let mut controls = FixedProcessMemoryControls::new_with_identification(
        Arc::clone(&ids),
        SCTLR_NORMAL_WB | SCTLR_ENIB,
        TCR_LOWER_SIZE,
        ADDRESS_BITS,
        source,
    )
    .map_err(|e| anyhow::anyhow!("process controls: {e:?}"))?;
    let fp = FpControlOwner::new_declared_el10(&ids, 0)
        .map_err(|e| anyhow::anyhow!("FP control owner: {e:?}"))?;
    let mut system = SystemState::new(MASKED_EL0T, 0, El1Registers::new(0, 0, 0, 0, 0))
        .map_err(|e| anyhow::anyhow!("System state: {e:?}"))?;
    let mut context = ExecutionContext::default();
    // SAFETY: the caller supplies trusted startup code and private mappings.
    // All protected resources and event producers are local to this new PE,
    // remain borrowed through completion, and are dropped when this call ends.
    let report = unsafe {
        stela_runtime::darwin::run_services(
            runtime,
            state,
            Some(stop),
            3,
            memory,
            stela_runtime::darwin::ExecutionServices {
                pauth: Some(pauth),
                clock: Some(&mut clock),
                thread: Some(&mut thread),
                protected_system: Some(&mut system),
                protected_controls: Some(&mut controls),
                protected_memory: Some(&mut memory_thread),
                protected_context: Some(&mut context),
                protected_event: Some(&endpoint),
                protected_fp: Some(&fp),
                ..Default::default()
            },
        )
    }?;
    Ok(report.execution)
}
