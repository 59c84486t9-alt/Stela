//! Native host processors for system execution. Firmware identity/capability
//! observations are copied before EBS; persistent APs use owned Stela startup
//! and processor-local resources afterward. Production shared-memory admission
//! is distinct from the direct `SYSTEM_MODE` profile's single-agent translation contract.
pub(crate) mod bootstrap;
pub(crate) mod canonical;
mod context_check;
pub(crate) mod executor;
pub(crate) mod firmware;
pub(crate) mod kernel_check;
pub(crate) mod memory_types;
pub(crate) mod resources;
pub(crate) use stela_boot_core::topology;
pub(crate) mod transport;
mod tsc_sync;

/// Check the exact loader-owned reservation against the requested, source
/// identified physical cores before any INIT/SIPI or guest-state loan.
///
/// # Safety
/// `handoff` is the live immutable loader record and all reserved regions are
/// retained in the shared physmap. This does not admit shared guest execution.
pub(crate) unsafe fn validate(
    handoff: &crate::handoff::Handoff,
    requested: Option<usize>,
) -> Result<Option<&'static firmware::Capture>, &'static str> {
    let cores = requested.unwrap_or(handoff.native_resources.cores as usize);
    if cores == 0 || cores > topology::MAX_CORES {
        return Err("native physical-core count is outside capacity");
    }
    let resources = &handoff.native_resources;
    if resources.cores as usize != cores
        || resources.stacks.bytes != resources::STACK_BYTES * cores as u64
        || resources.stacks.physical == 0
    {
        return Err("native executor reservations differ from requested cores");
    }
    resources::partition(
        cores,
        cores - 1,
        handoff.code.bytes,
        handoff.pool.bytes,
        false,
    )?;
    if cores > 1
        && (!(crate::tables::PAGE..1 << 20).contains(&resources.sipi)
            || !resources.sipi.is_multiple_of(crate::tables::PAGE))
    {
        return Err("native SIPI page is not owned low memory");
    }
    // SAFETY: the caller retains the immutable loader allocation.
    let capture = unsafe { firmware::captured(handoff.native_processors) }
        .map_err(firmware::Error::message)?;
    if requested.is_none() && cores != capture.core_count as usize {
        return Err("default native assignment differs from the captured physical-core roster");
    }
    if cores > capture.core_count as usize {
        return Err("requested native cores exceed physical source inventory");
    }
    let five_level = matches!(
        handoff.placement,
        stela_runtime::machine::mmu::placement::Placement::FiveLevel
    );
    crate::output::arguments(format_args!(
        "NATIVE INVENTORY firmware_processors={} enabled={} physical_cores={} assignable={} retired_cores={} requested={cores}\n",
        capture.processor_count,
        capture.enabled_count,
        capture.physical_count,
        capture.core_count,
        capture.physical_count - capture.core_count,
    ));
    let memory_types = memory_types::Image::from_snapshot(&capture.snapshots[0])?;
    for (slot, snapshot) in capture.snapshots[..cores].iter().enumerate() {
        let processor = capture.processors[capture.selected[slot] as usize];
        crate::output::arguments(format_args!(
            "NATIVE SOURCE slot={slot} apic={:#x} firmware_cpu={} flags={:#x} topology={} package={} module={} tile={} die={} core={} thread={} cpuid_records={} msr_records={} pat_valid={} pat={:#x} cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x}\n",
            processor.apic_id,
            processor.processor_number,
            processor.flags,
            processor.topology_version,
            processor.location.package,
            processor.location.module,
            processor.location.tile,
            processor.location.die,
            processor.location.core,
            processor.thread,
            snapshot.count,
            snapshot.msr_count,
            snapshot.pat_valid,
            snapshot.pat,
            snapshot.cr0,
            snapshot.cr3,
            snapshot.cr4,
            snapshot.efer,
        ));
        snapshot
            .qualify_native(five_level)
            .map_err(|_| "a selected physical core lacks the native executor floor")?;
        memory_types.compatible(snapshot)?;
        if snapshot.same_memory_types(&capture.snapshots[0]).is_err() {
            let reference = &capture.snapshots[0];
            // Snapshot bounds were validated above. Record both source values
            // for each differing register; never normalize the admission input.
            for expected in &reference.msrs[..reference.msr_count as usize] {
                let actual = snapshot.msrs[..snapshot.msr_count as usize]
                    .iter()
                    .find(|actual| actual.index == expected.index);
                if actual.is_none_or(|actual| actual.value != expected.value) {
                    crate::output::arguments(format_args!(
                        "NATIVE SOURCE MISMATCH slot={slot} msr={:#x} bsp={:#x} ap={:?}\n",
                        expected.index,
                        expected.value,
                        actual.map(|value| value.value),
                    ));
                }
            }
            crate::output::arguments(format_args!(
                "NATIVE SOURCE slot={slot} requires initial offline-AP memory-type installation\n"
            ));
        }
    }
    Ok(Some(capture))
}
