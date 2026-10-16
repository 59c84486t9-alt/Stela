//! Consuming executable lifetime of one fresh declared software privileged PE.
//! The factory owns original source/control/debug/memory storage. Every request
//! enters the existing canonical consumer; reports carry no execution authority.
use super::super::software_async::{CtiRoute, SoftwareAsyncDomain};
use super::{
    OwnedRunRequest, OwnedStop,
    halted::DebugStop,
    privileged::{LowerElControls, PrivilegedOwner},
    privileged_debug::DebugScalable,
};
use crate::{
    blocks::{BlockRuntime, ThreadState},
    memory::{
        domain::{MemoryDomain, MemorySystem},
        policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
    },
    scalable::ScalableState,
    system::{
        execution::owner::SystemExecutionOwner,
        identification::Register,
        identification_snapshot::Snapshot,
        scalable_controls::{
            Implementation as ScalableImplementation, Readbacks, ScalableControlOwner,
        },
        state::{El1Registers, PSTATE_EL1H, PSTATE_EL1T, SystemState},
    },
};
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};
#[cfg(feature = "std")]
use std::path::PathBuf;
use stela_compiler::{
    GuestAddress, TargetCpu,
    aarch64::scalable::VectorLength,
    block::BlockProfile,
    context::{ExecutionContext, memory::MemoryImplementationProfile},
    extended::ScalableProfile,
};

pub use crate::system::debug::halted::{
    ExtendedHaltSyndrome as DeclaredDebugExtendedHaltSyndrome,
    ExternalControls as DeclaredDebugExternalControls,
    Initialization as DeclaredDebugInitialization,
};
pub use crate::system::exception::higher_el::TrapSmcWithoutEl3;
pub use crate::system::state::higher_el::Initialization as DeclaredHigherElInitialization;

/// Owned original instruction bytes. SystemV1 in this factory admits one
/// no-memory instruction at a time. No data RAM/MMU/fetch-fault route is implied.
pub struct DeclaredPrivilegedCode {
    pub base: GuestAddress,
    pub bytes: Vec<u8>,
}
/// All scalable storage/control input is moved into the same executable scope.
pub struct DeclaredPrivilegedScalable {
    pub state: ScalableState,
    pub readbacks: Readbacks,
    pub supported_lengths: Vec<VectorLength>,
    pub specialization: ScalableProfile,
}
pub struct DeclaredPrivilegedConfig {
    pub identification: Vec<(Register, u64)>,
    pub thread: ThreadState,
    pub pstate_misc: u64,
    pub inactive_stack_pointer: u64,
    pub el1: El1Registers,
    pub higher: Option<DeclaredHigherElInitialization>,
    pub sctlr_el1: u64,
    pub tcr_el1: u64,
    pub debug: DeclaredDebugInitialization,
    pub scalable: Option<DeclaredPrivilegedScalable>,
    pub trap_smc_without_el3: TrapSmcWithoutEl3,
    pub address_space: u64,
    #[cfg(feature = "std")]
    pub cache_directory: PathBuf,
    pub code: Vec<DeclaredPrivilegedCode>,
    pub debug_producer_count: usize,
    pub cti_output_slot: usize,
    pub cti_target_slots: Vec<usize>,
}
pub enum DeclaredPrivilegedRequest {
    Run {
        stop_pc: Option<GuestAddress>,
        block_budget: usize,
    },
    Editr {
        route_slot: usize,
        word: u32,
    },
}
/// Source/queue/phase observations only. These strings cannot be supplied back
/// to any execution/retirement API as permissions or reconstructed resources.
pub struct DeclaredPrivilegedReceipt {
    pub operation: &'static str,
    pub stop: String,
    pub actual_pc: GuestAddress,
    pub source_receipts: Vec<String>,
    pub native_observation: Option<String>,
    pub debug_record: Option<String>,
    pub editr_source: Option<(u64, u64, u32)>,
    pub editr_disposition: Option<String>,
    pub lifecycle: String,
}
pub struct DeclaredPrivilegedReport {
    pub thread: ThreadState,
    pub system: SystemState,
    pub scalable: Option<ScalableState>,
    pub receipts: Vec<DeclaredPrivilegedReceipt>,
    pub asynchronous: String,
    pub compiler_source_sha256: String,
}

/// Creates one new declared PE, retains it for this complete executable lifetime,
/// and consumes all original owners before returning descriptive final state.
/// IRQ/FIQ/SError/NMI/deadline sources and hardware-state adoption are unavailable.
pub fn run_declared_privileged(
    config: DeclaredPrivilegedConfig,
    requests: Vec<DeclaredPrivilegedRequest>,
) -> anyhow::Result<DeclaredPrivilegedReport> {
    let DeclaredPrivilegedConfig {
        identification,
        mut thread,
        pstate_misc,
        inactive_stack_pointer,
        el1,
        higher,
        sctlr_el1,
        tcr_el1,
        debug,
        mut scalable,
        trap_smc_without_el3,
        address_space,
        #[cfg(feature = "std")]
        cache_directory,
        code,
        debug_producer_count,
        cti_output_slot,
        cti_target_slots,
    } = config;
    anyhow::ensure!(
        address_space != 0 && thread.pc.0.is_multiple_of(4),
        "invalid declared source identity"
    );
    anyhow::ensure!(
        matches!(pstate_misc & 0xf, PSTATE_EL1T | PSTATE_EL1H),
        "initial privileged source must be EL1"
    );
    anyhow::ensure!(
        debug_producer_count != 0
            && cti_output_slot < debug_producer_count
            && cti_target_slots
                .iter()
                .all(|slot| *slot < debug_producer_count),
        "invalid explicit debug routing"
    );
    let snapshot = Arc::new(
        Snapshot::declared(
            "stela-fresh-declared-privileged-software-v1",
            &identification,
        )
        .map_err(|e| anyhow::anyhow!("declared identification: {e:?}"))?,
    );
    let mut system = if let Some(higher) = higher {
        SystemState::new_with_higher_el(
            pstate_misc,
            inactive_stack_pointer,
            el1,
            Arc::clone(&snapshot),
            higher,
        )
    } else {
        SystemState::new(pstate_misc, inactive_stack_pointer, el1)
    }
    .map_err(|e| anyhow::anyhow!("declared system storage: {e:?}"))?;
    let debug =
        crate::system::debug::halted::DebugMachine::fresh_declared(Arc::clone(&snapshot), debug)
            .map_err(|e| anyhow::anyhow!("declared debug storage: {e:?}"))?;
    // Advertised SME requires its original storage/control owner even before a
    // request uses it. SVE-only ordinary execution has no owner in this factory.
    let pfr0 = snapshot
        .read(Register::IdAa64Pfr0El1)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let pfr1 = snapshot
        .read(Register::IdAa64Pfr1El1)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    anyhow::ensure!(pfr0 >> 32 & 0xf == 0, "ordinary SVE storage unavailable");
    anyhow::ensure!(
        (pfr1 >> 24 & 0xf != 0) == scalable.is_some(),
        "SME declaration/storage differs"
    );
    let scalable_controls = scalable
        .as_ref()
        .map(|input| {
            let implementation = ScalableImplementation::declared(
                &input.supported_lengths,
                MemoryImplementationProfile::ScalableTagChecks,
            )
            .map_err(|e| anyhow::anyhow!("declared scalable implementation: {e:?}"))?;
            ScalableControlOwner::new_declared_el10(&snapshot, input.readbacks, implementation)
                .map_err(|e| anyhow::anyhow!("declared scalable controls: {e:?}"))
        })
        .transpose()?;
    if let Some((input, controls)) = scalable.as_ref().zip(scalable_controls.as_ref()) {
        anyhow::ensure!(
            controls.current_svl() == input.state.vector_length()
                && input.specialization.vector_length() == input.state.vector_length()
                && input.specialization.mode() == input.state.mode(),
            "declared scalable storage/specialization differs"
        );
    }
    let domain = MemoryDomain::new_for_address_space(
        address_space,
        MemorySystem::new(16, 8).map_err(|e| anyhow::anyhow!("declared memory system: {e:?}"))?,
        vec![],
        TargetCpu::Baseline,
    )
    .map_err(|e| anyhow::anyhow!("declared memory domain: {e:?}"))?;
    let mut memory = domain.thread(MemoryControls::new(
        LowerAddressProfile::new(48, false)
            .map_err(|e| anyhow::anyhow!("declared address policy: {e:?}"))?,
        true,
        false,
        false,
        TagCheckFaultMode::Ignore,
        false,
    ));
    #[cfg(feature = "std")]
    let mut runtime = BlockRuntime::new_for_target(
        address_space,
        #[cfg(feature = "std")]
        cache_directory,
        BlockProfile::SystemV1,
        TargetCpu::Baseline,
    );
    #[cfg(not(feature = "std"))]
    let mut runtime = BlockRuntime::new_aot_for_target(
        address_space,
        BlockProfile::SystemV1,
        TargetCpu::Baseline,
    );
    for input in code {
        runtime.register_code(input.base, input.bytes)?;
    }
    // SAFETY: this factory creates this new PE and the complete closed debug-only
    // producer domain. Every registration and writer stays in this scope.
    let mut asynchronous = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
    let mut keys = Vec::new();
    keys.try_reserve_exact(debug_producer_count)?;
    for _ in 0..debug_producer_count {
        keys.push(
            asynchronous
                .register_debug()
                .map_err(|e| anyhow::anyhow!("debug registration: {e:?}"))?,
        );
    }
    let mut receipts = Vec::new();
    receipts.try_reserve_exact(requests.len())?;
    let mut context = ExecutionContext::default();
    {
        let producers = asynchronous
            .lease_debug_sources(&keys)
            .map_err(|e| anyhow::anyhow!("complete debug sources: {e:?}"))?;
        let scalable_resource =
            scalable
                .as_mut()
                .zip(scalable_controls.as_ref())
                .map(|(input, controls)| DebugScalable {
                    controls,
                    state: &mut input.state,
                    context: &mut context,
                    specialization: input.specialization,
                });
        // SAFETY: disjoint original fields, fresh sole controls, complete producer
        // lease and empty actual data domain are retained through the same owner.
        let mut backend = unsafe {
            PrivilegedOwner::fresh_software(
                address_space,
                LowerElControls {
                    snapshot: Arc::clone(&snapshot),
                    sctlr_el1,
                    tcr_el1,
                    call_implementation: crate::system::exception::higher_el::Implementation {
                        without_el3_security:
                            crate::system::exception::higher_el::WithoutEl3Security::NonSecureOnly,
                        trap_smc_without_el3,
                    },
                },
                &mut memory,
                domain,
                producers,
                CtiRoute {
                    output_slot: cti_output_slot,
                    target_slots: cti_target_slots,
                },
                scalable_resource,
            )
        }?;
        // SAFETY: genuinely new PE, original sole Thread/System/backend/debug.
        // No adopted resource or raw entry escapes this one executable lifetime.
        let mut pe = unsafe {
            SystemExecutionOwner::new_pe_with_debug(&mut thread, &mut system, &mut backend, debug)
        }?;
        for request in requests {
            let (receipt, terminal) = match request {
                DeclaredPrivilegedRequest::Run {
                    stop_pc,
                    block_budget,
                } => {
                    let outcome = runtime.run_owned(
                        pe.loan(),
                        OwnedRunRequest {
                            stop_pc,
                            block_budget,
                        },
                    );
                    let terminal = matches!(
                        outcome.stop,
                        OwnedStop::Indeterminate(_)
                            | OwnedStop::FaultPending(_)
                            | OwnedStop::TrapPending(_)
                    );
                    (
                        DeclaredPrivilegedReceipt {
                            operation: "run",
                            stop: format!("{:?}", outcome.stop),
                            actual_pc: outcome.actual_pc,
                            source_receipts: outcome
                                .settled_prefixes
                                .iter()
                                .map(|v| format!("{v:?}"))
                                .collect(),
                            native_observation: outcome
                                .last_native_observation
                                .map(|v| format!("{v:?}")),
                            debug_record: None,
                            editr_source: None,
                            editr_disposition: None,
                            lifecycle: pe.privileged_observation(),
                        },
                        terminal,
                    )
                }
                DeclaredPrivilegedRequest::Editr { route_slot, word } => {
                    // Failed queue admission leaves the original PE/source intact;
                    // retain the refusal rather than dropping earlier receipts.
                    match pe.queue_editr(route_slot, word) {
                        Err(error) => (
                            DeclaredPrivilegedReceipt {
                                operation: "editr",
                                stop: error.to_string(),
                                actual_pc: pe.pc(),
                                source_receipts: Vec::new(),
                                native_observation: None,
                                debug_record: None,
                                editr_source: None,
                                editr_disposition: None,
                                lifecycle: pe.privileged_observation(),
                            },
                            false,
                        ),
                        Ok(()) => {
                            let outcome = pe.run_editr();
                            let terminal = matches!(outcome.stop, DebugStop::Indeterminate(_));
                            (
                                DeclaredPrivilegedReceipt {
                                    operation: "editr",
                                    stop: match &outcome.stop {
                                        DebugStop::EntryDeclined(error)
                                        | DebugStop::Indeterminate(error) => error.clone(),
                                        other => format!("{other:?}"),
                                    },
                                    actual_pc: outcome.actual_pc,
                                    source_receipts: Vec::new(),
                                    native_observation: None,
                                    editr_source: outcome
                                        .record
                                        .as_ref()
                                        .map(|v| (v.source, v.sequence, v.word)),
                                    editr_disposition: outcome
                                        .record
                                        .as_ref()
                                        .map(|v| format!("{:?}", v.disposition)),
                                    debug_record: outcome.record.map(|v| format!("{v:?}")),
                                    lifecycle: pe.privileged_observation(),
                                },
                                terminal,
                            )
                        }
                    }
                }
            };
            receipts.push(receipt);
            if terminal || pe.privileged_terminal() {
                break;
            }
        }
    }
    drop(scalable_controls);
    Ok(DeclaredPrivilegedReport {
        thread,
        system,
        scalable: scalable.map(|v| v.state),
        receipts,
        asynchronous: asynchronous.debug_observation(),
        compiler_source_sha256: crate::compiler_source_sha256().into(),
    })
}
