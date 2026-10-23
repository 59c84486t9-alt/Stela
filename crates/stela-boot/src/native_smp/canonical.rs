//! Cold fixed-physical-core adapter over the boot's existing physical reservations.
//! Final Apple topology/device/DMA/reset admission belongs to the mount. This
//! constructs the actual checked Machine; it never certifies legacy raw V1.
mod bindings;

use super::{executor::Executors, firmware::Capture, transport::FixedWorkers};
use crate::{apic::Apic, engine::host, handoff::Handoff, layout};
use alloc::{sync::Arc, vec::Vec};
use core::ptr::NonNull;
use stela_runtime::{
    machine::{
        Cpu, CpuProfile, Devices, Machine, Stop,
        engine::{
            ServiceHost,
            publication::{WorkerBinding, WorkerId},
        },
    },
    memory::{RegisteredSystemRam, ReservedSystemRamRange},
    system::events::EventDomain,
};

struct Reservation {
    _handoff: &'static Handoff,
    _ranges: Vec<host::RamRange>,
}
pub(crate) type CanonicalMachine<'a, D> =
    Machine<ServiceHost<host::BareHost<'a>, FixedWorkers<'a>>, D>;

/// Register the SAME loader-owned bytes, without a second allocation or copy.
///
/// # Safety
/// The loader has exclusively reserved every listed guest physical range and
/// its shared-window WB CPU aliases for the entire boot. All earlier input
/// copies have completed; no raw V1 guest or asynchronous producer can access
/// these bytes after registration. The physical map and controls stay pinned.
pub(crate) unsafe fn reserve(
    handoff: &'static Handoff,
    ranges: &[host::RamRange],
) -> Result<Arc<RegisteredSystemRam>, &'static str> {
    if ranges.is_empty() {
        return Err("canonical guest RAM has no loader reservations");
    }
    let mut registered = Vec::with_capacity(ranges.len());
    for range in ranges {
        let end = range
            .host
            .checked_add(range.bytes)
            .ok_or("canonical guest RAM extent wraps")?;
        if range.bytes == 0
            || !handoff.guest[..handoff.guest_count]
                .iter()
                .any(|reservation| {
                    reservation.physical <= range.host
                        && reservation
                            .physical
                            .checked_add(reservation.bytes)
                            .is_some_and(|top| end <= top)
                })
        {
            return Err("canonical guest RAM is outside actual loader ownership");
        }
        let bytes =
            usize::try_from(range.bytes).map_err(|_| "canonical guest RAM exceeds host size")?;
        let cpu = layout::physical(range.host);
        // SAFETY: exact retained loader reservation; no root/control migration
        // or native/host producer can race this pre-entry qualification.
        unsafe { crate::native_memory::qualify_reserved_writeback(cpu, range.host, bytes) }
            .map_err(|_| "canonical guest RAM mapping/effective WB type is unqualified")?;
        registered.push(ReservedSystemRamRange {
            source_pa: range.guest,
            host_pa: range.host,
            host_base: NonNull::new(cpu as *mut u8)
                .ok_or("canonical guest RAM has null mapping")?,
            bytes,
        });
    }
    let owner = Arc::new(Reservation {
        _handoff: handoff,
        _ranges: ranges.to_vec(),
    });
    // SAFETY: same exclusively reserved bytes and qualified WB aliases; retained
    // owner survives frames, source fetch/walk, copyout and stopped settlement.
    unsafe {
        RegisteredSystemRam::register(
            &registered,
            owner,
            stela_runtime::machine::cpu::RESERVATION_GRANULE,
            64,
        )
    }
    .map(Arc::new)
    .map_err(|_| "canonical boot RAM registration refused")
}

/// Cold assigned-physical-core construction, before FIRST guest instruction.
/// The caller can borrow its actual registered owner for Prepared's MCC join.
///
/// # Safety
/// `reserve`'s closed producer contract holds. Loader::apple_device_tree::assigned
/// already projected the original source PE/resource/AIC plan to this actual
/// core roster: exactly the assigned visible PEs, never unassigned stock slots
/// merely marked Off. All host
/// interfaces are synchronous through this Machine's Devices/Host; no external
/// DMA/background producer or legacy raw V1 execution is admitted. The actual
/// topology capture, executor, HostOwner and mappings remain pinned. The explicit
/// PE/worker bijection binds the selected boot PE to physical BSP worker0; no
/// source physical identity is changed by the dense logical projection. Native IRQ,
/// reset, PMU and other unjoined platform services remain explicit refusals.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn prepare<'a, D: Devices>(
    handoff: &'static Handoff,
    capture: &'static Capture,
    executors: &'a Executors,
    sender: &'a Apic,
    owner: &'a mut host::HostOwner,
    ram: Arc<RegisteredSystemRam>,
    cpu: Cpu,
    devices: D,
    profile: CpuProfile,
    boot_processor: usize,
    assignments: &[WorkerBinding],
    processor_power: &[stela_runtime::machine::engine::ProcessorBinding],
) -> Result<CanonicalMachine<'a, D>, &'static str> {
    // SAFETY: forwarded unchanged cold construction contract; diagnostic
    // callers retain any already prepared CPU lock state.
    unsafe {
        prepare_with_locks(
            handoff,
            capture,
            executors,
            sender,
            owner,
            ram,
            cpu,
            devices,
            profile,
            boot_processor,
            assignments,
            processor_power,
            None,
        )
    }
}

/// Cold construction with the actual iBoot core-lock handoff. Initial CTRR,
/// lock state and source translation controls settle before native owners or
/// any frame loans are published. `None` preserves an already prepared Cpu.
///
/// # Safety
/// The complete cold ownership and producer contract of `prepare` applies.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn prepare_with_locks<'a, D: Devices>(
    handoff: &'static Handoff,
    capture: &'static Capture,
    executors: &'a Executors,
    sender: &'a Apic,
    owner: &'a mut host::HostOwner,
    ram: Arc<RegisteredSystemRam>,
    cpu: Cpu,
    devices: D,
    profile: CpuProfile,
    boot_processor: usize,
    assignments: &[WorkerBinding],
    processor_power: &[stela_runtime::machine::engine::ProcessorBinding],
    core_locks: Option<stela_runtime::machine::ctrr::Handoff>,
) -> Result<CanonicalMachine<'a, D>, &'static str> {
    let cores = handoff.native_resources.cores as usize;
    if cores == 0
        || cores > capture.core_count as usize
        || executors.processors().len() + 1 != cores
        || profile.processors.len().max(1) != cores
    {
        return Err("canonical mount requires the same assigned physical and visible PE roster");
    }
    bindings::validate(cores, boot_processor, assignments)?;
    for slot in 1..cores {
        let selected = capture.processors[capture.selected[slot] as usize];
        let Some(processor) = executors
            .processors()
            .iter()
            .find(|processor| processor.slot() == slot)
        else {
            return Err("assigned AP executor is absent");
        };
        if processor.apic_id() != selected.apic_id || !processor.observation().matches(selected) {
            return Err("actual AP executor differs from its assigned physical binding");
        }
    }
    let bsp = capture.processors[capture.selected[0] as usize];
    let apic =
        u32::try_from(bsp.apic_id).map_err(|_| "canonical BSP APIC identity exceeds transport")?;
    owner.bind_worker(WorkerId(0), apic)?;
    // SAFETY: actual registered owner, pristine GS-local dispatch; every later
    // access goes through this same canonical RAM, never old raw V1 stores.
    unsafe { owner.register_system_ram(Arc::clone(&ram)) }?;
    let transport = FixedWorkers::new(executors, sender, handoff.tsc_hz, Arc::clone(&ram));
    let host = ServiceHost::new(owner.host(), transport, Arc::clone(&ram));
    let mut machine = Machine::new_at(cpu, host, devices, profile, ram.target(), boot_processor)?;
    if let Some(core_locks) = core_locks {
        machine.hand_off_core_locks(core_locks);
    }
    machine
        .install_shared_memory_for_active_processors(ram, &EventDomain::new())
        .map_err(|_| "cold source controls/canonical CPU ownership refused before entry")?;
    // Initial handoff bindings must settle before any physical worker owner
    // publishes. Later changes require the complete held native cohort.
    if !processor_power.is_empty() {
        machine
            .bind_processor_power(processor_power)
            .map_err(|_| "canonical initial processor power bindings refused")?;
    }
    let owners = machine
        .bind_assigned_native_workers(assignments)
        .map_err(|_| "canonical assigned physical roster binding refused")?;
    machine.initialize_native_transport(owners);
    Ok(machine)
}

/// Execute actual checked native rounds and consuming canonical reads. The
/// ordinary boot reporting loop can call this instead of raw Machine::run.
/// Unsupported source/device families stop unexecuted, with no V1 fallback.
///
/// # Safety
/// `prepare`'s complete closed producer/mount contract remains valid. This is
/// admitted only after the final platform owner joins its complete graph.
pub(crate) unsafe fn run_slice<D: Devices>(
    machine: &mut CanonicalMachine<'_, D>,
    limit: u64,
) -> Stop {
    loop {
        if machine.pending_native_device_access().is_some() {
            // SAFETY: same retained cohort, controller and closed producers.
            match unsafe { machine.complete_native_device_access() } {
                Ok(()) | Err(Stop::DeviceRead(_) | Stop::DeviceWrite(_)) => continue,
                Err(stop) => return stop,
            }
        }
        if machine.statistics.blocks >= limit {
            return Stop::Budget;
        }
        // SAFETY: same registered owner/fixed executor and closed providers.
        match unsafe { machine.native_round() } {
            Ok(_) | Err(Stop::DeviceRead(_) | Stop::DeviceWrite(_)) => {}
            Err(stop) => return stop,
        }
    }
}
