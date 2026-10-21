//! A bounded real translated ARM kernel cohort, never original-macOS SMP credit.
mod source;
use super::{executor::Executors, firmware::Capture};
use crate::{apic::Apic, engine::host, handoff::Handoff};
use alloc::{sync::Arc, vec::Vec};
use stela_compiler::{GuestState, TargetCpu};
use stela_drivers::bus::dma::memory::{CacheAttribute, CpuMapping, PageSource, PinnedPages};
use stela_runtime::{
    machine::{
        self, Chip, Cpu, CpuProfile, DeviceError, Devices, Host, Identity, Lines, Machine,
        PeerState, Stop,
        engine::{
            self,
            publication::{WorkerBinding, WorkerId},
        },
        exception::Pstate,
    },
    memory::{RegisteredSystemRam, ReservedSystemRamRange},
    system::events::EventDomain,
};

struct Reservation {
    pages: PinnedPages,
    mapping: CpuMapping,
}
struct TestDevices {
    starts: Vec<engine::Start>,
    ready: Vec<bool>,
}
impl Devices for TestDevices {
    fn read(&mut self, _: usize, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
        Err(DeviceError::NoDevice)
    }
    fn write(
        &mut self,
        pe: usize,
        address: u64,
        bytes: u8,
        value: u64,
        _: u64,
    ) -> Result<(), DeviceError> {
        if address != source::READY || bytes != 8 || value != 1 {
            return Err(DeviceError::NoDevice);
        }
        *self.ready.get_mut(pe).ok_or(DeviceError::NoDevice)? = true;
        Ok(())
    }
    fn lines(&mut self, _: usize, _: u64) -> Lines {
        Lines {
            irq: self.ready.iter().all(|ready| *ready),
            ..Lines::default()
        }
    }
    fn take_start(&mut self) -> Option<engine::Start> {
        self.starts.pop()
    }
}
fn reservation() -> Result<Arc<RegisteredSystemRam>, &'static str> {
    let pages = crate::native_memory::SOURCE
        .allocate(source::BYTES, 4096, CacheAttribute::WriteBack)
        .map_err(|_| "native kernel actual WB page allocation refused")?;
    let mapping = pages
        .cpu_mapping(CacheAttribute::WriteBack)
        .map_err(|_| "native kernel CPU mapping refused")?;
    let owner = Arc::new(Reservation { pages, mapping });
    let physical = owner.pages.physical_pages();
    if physical.windows(2).any(|pages| pages[1] != pages[0] + 4096) {
        return Err("native kernel actual page allocation is not contiguous");
    }
    let range = ReservedSystemRamRange {
        source_pa: source::BASE,
        host_pa: physical[0],
        host_base: owner
            .mapping
            .address(0, source::BYTES)
            .map_err(|_| "native kernel mapping extent refused")?,
        bytes: source::BYTES,
    };
    // SAFETY: actual exclusive heap page pin and qualified WB CPU mapping. No
    // DMA/direct writer is admitted. Arc retains both through all native frames,
    // callbacks, fault recovery and exact source-PC/publication settlement.
    let ram = Arc::new(
        unsafe {
            RegisteredSystemRam::register(&[range], owner, machine::cpu::RESERVATION_GRANULE, 64)
        }
        .map_err(|_| "native kernel canonical RAM registration refused")?,
    );
    for (address, descriptor) in source::tables() {
        unsafe { ram.publish_physical(address, &descriptor.to_le_bytes()) }
            .map_err(|_| "native kernel table publication failed")?;
    }
    let (program, _) = source::warmup();
    unsafe { ram.publish_physical(source::CODE, &program) }
        .map_err(|_| "native kernel source publication failed")?;
    Ok(ram)
}
fn profile(cores: usize) -> Result<CpuProfile, &'static str> {
    let chip = Chip::AppleM1;
    let fixed = machine::identification::derive(
        chip,
        TargetCpu::Baseline,
        true,
        machine::identification::Speculation::NONE,
    );
    // The diagnostic declares the existing t8103 P-core interface. Variant1 /
    // revision0 have the same explicitly inferred status as soc::cpus; this is
    // not a physical x86 P/E classification or an Apple SKU/core-count claim.
    let part = machine::soc::midr_part(0x8103, b'P')
        .ok_or("diagnostic M1 interface has no sourced MIDR part")?;
    let midr = (0x61 << 24) | (1 << 20) | (0xf << 16) | (u64::from(part) << 4);
    Ok(CpuProfile {
        name: "bounded-native-shared-kernel-m1-isa-v1",
        chip,
        counter_frequency: 24_000_000,
        fixed,
        processors: (0..cores)
            .map(|pe| Identity {
                midr,
                mpidr: (1 << 31) | pe as u64,
                clock: None,
                caches: None,
            })
            .collect(),
    })
}
fn ready<H: Host>(machine: &Machine<H, TestDevices>, entry: u64) -> bool {
    machine.devices.ready.iter().all(|ready| *ready)
        && machine.peer_states().iter().all(|state| match state {
            PeerState::Running => machine.cpu.pc == entry,
            PeerState::Parked { cpu, wfi: None } => cpu.pc == entry,
            _ => false,
        })
}
fn states<H: Host>(machine: &Machine<H, TestDevices>) -> Result<Vec<GuestState>, &'static str> {
    machine
        .peer_states()
        .iter()
        .map(|state| match state {
            PeerState::Running => Ok(machine.cpu.state.clone()),
            PeerState::Parked { cpu, wfi: None } => Ok(cpu.state.clone()),
            _ => Err("native kernel PE not at an active instruction boundary"),
        })
        .collect()
}
fn control_state<H: Host>(
    machine: &Machine<H, TestDevices>,
) -> Result<Vec<(Pstate, u64)>, &'static str> {
    machine
        .peer_states()
        .iter()
        .map(|state| match state {
            PeerState::Running => Ok((machine.cpu.pstate, machine.cpu.retired)),
            PeerState::Parked { cpu, wfi: None } => Ok((cpu.pstate, cpu.retired)),
            _ => Err("native kernel control state is not recovered"),
        })
        .collect()
}
fn check_control_state<H: Host>(
    machine: &Machine<H, TestDevices>,
    before: &[(Pstate, u64)],
    retired: u64,
) -> Result<(), &'static str> {
    let after = control_state(machine)?;
    if before
        .iter()
        .zip(after)
        .any(|((state, count), actual)| actual != (*state, count.wrapping_add(retired)))
    {
        return Err("native kernel changed PSTATE or lost actual CPU retirement");
    }
    Ok(())
}
/// # Safety
/// Real selected BSP/AP ownership/reservations/descriptors remain pinned. No
/// original guest or DMA runs; caller terminates the diagnostic after return.
pub(crate) unsafe fn check(
    handoff: &'static Handoff,
    capture: &'static Capture,
    executors: &Executors,
    host_owner: &mut host::HostOwner,
    sender: &Apic,
) -> Result<(), &'static str> {
    let cores = handoff.native_resources.cores as usize;
    let ram = reservation()?;
    let bsp = capture.processors[capture.selected[0] as usize];
    host_owner.bind_worker(WorkerId(0), bsp.apic_id as u32)?;
    // SAFETY: pristine owner; actual pinned canonical RAM replaces the metadata.
    // Serial warmup contains no guest RAM writes; every host/table writer uses
    // this same owner. Shared execution always uses the checked memory profile.
    unsafe { host_owner.register_system_ram(Arc::clone(&ram)) }?;
    let cpu = Cpu::of(Chip::AppleM1, source::CODE, Pstate::reset(2));
    let devices = TestDevices {
        starts: (1..cores)
            .map(|cpu| engine::Start {
                cpu,
                address: source::CODE,
            })
            .collect(),
        ready: alloc::vec![false; cores],
    };
    let mut machine = Machine::new(
        cpu,
        host_owner.host(),
        devices,
        profile(cores)?,
        ram.target(),
    );
    machine.set_strict(true);
    let (_, entry) = source::warmup();
    let started = crate::apic::rdtsc();
    while !ready(&machine, entry) {
        let stop = machine.run(machine.statistics.blocks + 1);
        if !matches!(stop, Stop::Budget) {
            crate::output::arguments(format_args!("NATIVE KERNEL warmup {stop:?}\n"));
            return Err("native kernel real ARM prologue stopped");
        }
        if crate::apic::rdtsc().wrapping_sub(started) >= handoff.tsc_hz * 10 {
            return Err("native kernel prologue/wake deadline");
        }
    }
    let source = source::atomic_body(entry);
    // SAFETY: all actual frames are stopped, no shared native call has begun;
    // new source bytes receive a fresh distinct SharedV1 artifact/source identity.
    unsafe { ram.publish_physical(entry, &source) }
        .map_err(|_| "native kernel shared source publication failed")?;
    let events = EventDomain::new();
    machine
        .install_shared_memory_for_processors(Arc::clone(&ram), &events)
        .map_err(|_| "native kernel source controls refused")?;
    let bindings: Vec<_> = (0..cores)
        .map(|pe| WorkerBinding {
            pe,
            worker: WorkerId(pe),
        })
        .collect();
    let mut owners = machine
        .bind_native_workers(&bindings)
        .map_err(|_| "native kernel fixed worker binding refused")?;
    let mut bsp_owner = owners.remove(0);
    let published = bsp_owner
        .publish_initial(&mut machine.host)
        .map_err(|_| "native kernel BSP publication refused")?;
    machine
        .native_worker_publications()
        .ok_or("native kernel inventory absent")?
        .accept_initial(published)
        .map_err(|_| "native kernel BSP initial receipt refused")?;
    for (processor, owner) in executors.processors().iter().zip(owners) {
        if processor.slot() != owner.binding().worker.0 {
            return Err("native kernel AP physical roster mismatch");
        }
        let published = processor.initialize(owner, sender, handoff.tsc_hz)?;
        machine
            .native_worker_publications()
            .ok_or("native kernel inventory absent")?
            .accept_initial(published)
            .map_err(|_| "native kernel AP initial receipt refused")?;
    }
    let before = states(&machine)?;
    let controls_before = control_state(&machine)?;
    let reports = execute(
        &mut machine,
        &bindings,
        &mut bsp_owner,
        executors,
        sender,
        handoff.tsc_hz,
    )?;
    for report in &reports {
        crate::output::arguments(format_args!(
            "NATIVE KERNEL returned pe={} apic={:?} retired={} pc={:#x} status={:?} memory={:?} source={:?}\n",
            report.identity.pe,
            report.physical_processor,
            report.retired,
            report.settled_pc,
            report.status,
            report.memory_fault,
            report.source_failure
        ));
        if report.status.is_err()
            || report.memory_fault.is_some()
            || report.source_failure.is_some()
            || report.settled_pc != entry
            || report.retired != source.len() as u64 / 4
            || report.physical_processor
                != Some(
                    capture.processors[capture.selected[report.identity.pe] as usize].apic_id
                        as u32,
                )
        {
            return Err("native kernel source/return/physical identity mismatch");
        }
    }
    check_control_state(&machine, &controls_before, source.len() as u64 / 4)?;
    let after = states(&machine)?;
    for (old, actual) in before.iter().zip(&after) {
        let mut expected = old.clone();
        expected.x[0] = source::DATA;
        expected.x[1] = 1;
        expected.x[2] = actual.x[2];
        expected.x[3] += 1;
        expected.x[4] = 0;
        expected.x[5] = 0;
        expected.x[6] = source::DATA + 64;
        if *actual != expected || actual.x[2] >= (cores * source::INCREMENTS) as u64 {
            return Err("native kernel complete architectural frame mismatch");
        }
    }
    let mut data = [0; 8];
    unsafe { ram.read_physical(source::DATA, &mut data) }
        .map_err(|_| "native kernel final canonical read failed")?;
    if u64::from_le_bytes(data) != (cores * source::INCREMENTS) as u64 {
        return Err("native kernel lost an actual concurrent LSE update");
    }
    stop(
        &mut machine,
        &mut bsp_owner,
        executors,
        sender,
        handoff.tsc_hz,
        |machine| {
            if machine.cpu.pstate.el != 2 {
                return Err("native kernel ERET fixture lost EL2 owner");
            }
            machine.cpu.consume_event();
            let spsr = machine.cpu.pstate.to_spsr(machine.cpu.state.nzcv);
            machine
                .cpu
                .registers
                .set_raw(machine::system::Register::SPSR_EL2, 0, spsr);
            machine
                .cpu
                .exception_return(entry)
                .map_err(|_| "native kernel actual ERET owner failed")?;
            if !machine.cpu.event_is_set() || machine.cpu.event || !machine.cpu.consume_event() {
                return Err(
                    "native kernel ERET used a copied event instead of its canonical endpoint",
                );
            }
            unsafe { ram.publish_physical(entry, &source::reservation_body(entry)) }
                .map_err(|_| "native kernel exclusive source publication refused")
        },
    )?;
    let cleared_pe = machine.processor();
    let exclusive_before = states(&machine)?;
    let exclusive_controls = control_state(&machine)?;
    let exclusive = execute(
        &mut machine,
        &bindings,
        &mut bsp_owner,
        executors,
        sender,
        handoff.tsc_hz,
    )?;
    check_control_state(&machine, &exclusive_controls, 2)?;
    let exclusive_after = states(&machine)?;
    for (report, (old, actual)) in exclusive
        .iter()
        .zip(exclusive_before.iter().zip(&exclusive_after))
    {
        let mut expected = old.clone();
        expected.x[7] = actual.x[7];
        if report.status.is_err()
            || report.memory_fault.is_some()
            || report.source_failure.is_some()
            || report.settled_pc != entry
            || report.retired != 2
            || *actual != expected
            || actual.x[7] > 1
            || report.identity.pe == cleared_pe && actual.x[7] != 1
        {
            return Err("native kernel actual STXP did not preserve the CPU-owned ERET clear");
        }
    }
    if exclusive_after
        .iter()
        .filter(|state| state.x[7] == 0)
        .count()
        != usize::from(cores > 1)
    {
        return Err("native kernel canonical ERET clear lost the independent successful STXP");
    }
    stop(
        &mut machine,
        &mut bsp_owner,
        executors,
        sender,
        handoff.tsc_hz,
        |_| {
            unsafe { ram.publish_physical(entry, &source::reservation_load_body(entry)) }
                .map_err(|_| "native kernel fresh LDXP source publication refused")
        },
    )?;
    let reloaded_before = states(&machine)?;
    let reloaded_controls = control_state(&machine)?;
    let reloaded = execute(
        &mut machine,
        &bindings,
        &mut bsp_owner,
        executors,
        sender,
        handoff.tsc_hz,
    )?;
    check_control_state(&machine, &reloaded_controls, 2)?;
    let reloaded_after = states(&machine)?;
    for (report, (old, actual)) in reloaded
        .iter()
        .zip(reloaded_before.iter().zip(&reloaded_after))
    {
        let mut expected = old.clone();
        expected.x[4] = 0;
        expected.x[5] = 0;
        if report.status.is_err()
            || report.memory_fault.is_some()
            || report.source_failure.is_some()
            || report.settled_pc != entry
            || report.retired != 2
            || *actual != expected
        {
            return Err("native kernel fresh LDXP changed its complete frame");
        }
    }
    stop(
        &mut machine,
        &mut bsp_owner,
        executors,
        sender,
        handoff.tsc_hz,
        |_| {
            unsafe { ram.publish_physical(source::DATA + 64, &1u64.to_le_bytes()) }
                .map_err(|_| "native kernel host ABA first publication refused")?;
            unsafe { ram.publish_physical(source::DATA + 64, &0u64.to_le_bytes()) }
                .map_err(|_| "native kernel host ABA restore refused")?;
            unsafe { ram.publish_physical(entry, &source::reservation_body(entry)) }
                .map_err(|_| "native kernel ABA STXP source publication refused")
        },
    )?;
    let aba_before = states(&machine)?;
    let aba_controls = control_state(&machine)?;
    let aba = execute(
        &mut machine,
        &bindings,
        &mut bsp_owner,
        executors,
        sender,
        handoff.tsc_hz,
    )?;
    check_control_state(&machine, &aba_controls, 2)?;
    let aba_after = states(&machine)?;
    for (report, (old, actual)) in aba.iter().zip(aba_before.iter().zip(&aba_after)) {
        let mut expected = old.clone();
        expected.x[7] = 1;
        if report.status.is_err()
            || report.memory_fault.is_some()
            || report.source_failure.is_some()
            || report.settled_pc != entry
            || report.retired != 2
            || *actual != expected
        {
            return Err("native kernel actual STXP accepted canonical host ABA");
        }
    }
    stop(
        &mut machine,
        &mut bsp_owner,
        executors,
        sender,
        handoff.tsc_hz,
        |_| {
            let (address, descriptor) = source::read_only_alias();
            unsafe { ram.publish_physical(address, &descriptor.to_le_bytes()) }
                .map_err(|_| "native kernel read-only alias publication refused")?;
            unsafe { ram.publish_physical(entry, &source::permission_body()) }
                .map_err(|_| "native kernel fault source publication refused")
        },
    )?;
    let before_fault = states(&machine)?;
    let fault_controls = control_state(&machine)?;
    let faults = execute(
        &mut machine,
        &bindings,
        &mut bsp_owner,
        executors,
        sender,
        handoff.tsc_hz,
    )?;
    check_control_state(&machine, &fault_controls, source::FAULT_OFFSET / 4)?;
    let after_fault = states(&machine)?;
    for (report, (old, actual)) in faults.iter().zip(before_fault.iter().zip(&after_fault)) {
        let Some(fault) = report.memory_fault else {
            return Err("native kernel missing actual source permission fault");
        };
        let mut expected = old.clone();
        expected.x[0] = source::ALIAS;
        expected.x[3] += 1;
        if report.status.is_err()
            || report.settled_pc != entry + source::FAULT_OFFSET
            || report.retired != source::FAULT_OFFSET / 4
            || fault.status != stela_compiler::context::memory::MemoryStatus::Permission
            || fault.address != source::ALIAS
            || fault.pc != entry + source::FAULT_OFFSET
            || fault.completed_bytes != 0
            || *actual != expected
            || !matches!(
                report.source_failure,
                Some(engine::SharedMemoryFailure::Fault { .. })
            )
        {
            crate::output::arguments(format_args!("NATIVE KERNEL unexpected fault {report:?}\n"));
            return Err("native kernel source permission fault changed frame/prefix");
        }
    }
    let mut unchanged = [0; 8];
    unsafe { ram.read_physical(source::DATA, &mut unchanged) }
        .map_err(|_| "native kernel post-fault canonical read failed")?;
    if unchanged != data {
        return Err("native kernel read-only alias fault changed canonical RAM");
    }
    stop(
        &mut machine,
        &mut bsp_owner,
        executors,
        sender,
        handoff.tsc_hz,
        |_| Ok(()),
    )?;
    crate::output::arguments(format_args!(
        "CHECK native-shared-kernel PASS physical_cores={cores} actual_frames={} lse_updates={} full_GPR_SIMD_FP_state=preserved canonical_RAM=shared returned_and_invalidated=true permission_faults=precise host_ABA_STXP=failed canonical_CPU_ERET_event=true; original macOS SMP unqualified\n",
        reports.len(),
        cores * source::INCREMENTS
    ));
    Ok(())
}
fn execute<H: Host>(
    machine: &mut Machine<H, TestDevices>,
    bindings: &[WorkerBinding],
    bsp_owner: &mut engine::publication::WorkerOwner,
    executors: &Executors,
    sender: &Apic,
    tsc_hz: u64,
) -> Result<Vec<engine::NativeRunObservation>, &'static str> {
    // SAFETY: every PE's real source controls/frame and canonical RAM are owned;
    // no DMA/IRQ/System service is concurrent, masks remain reset, GPR/LSE-only
    // bounded body. All AP loans are synchronously joined below without leaks.
    let cohort = unsafe { machine.shared_native_cohort(bindings) }
        .map_err(|_| "native kernel actual frame preparation refused")?;
    let mut pending = Vec::new();
    let mut bsp_loan = None;
    for frame in cohort.frames {
        let pe = frame.identity().pe;
        crate::output::arguments(format_args!(
            "NATIVE KERNEL artifact pe={pe} identity={:?}\n",
            frame.identity()
        ));
        let loan = engine::dispatch_native_run(cohort.inventory, frame)
            .map_err(|_| "native kernel real frame dispatch refused")?;
        if pe == 0 {
            bsp_loan = Some(loan);
        } else {
            let processor = executors
                .processors()
                .iter()
                .find(|processor| processor.slot() == pe)
                .ok_or("native kernel selected AP missing")?;
            // SAFETY: this blocking scope never forgets pending ownership; every
            // real AP return is acquired before frames, stack or RAM can release.
            pending.push(
                unsafe { processor.submit(loan, sender, tsc_hz) }
                    .map_err(|_| "native kernel AP mailbox busy")?,
            );
        }
    }
    let returned = bsp_owner
        .execute(
            bsp_loan.ok_or("native kernel BSP frame missing")?,
            cohort.host,
        )
        .map_err(|_| "native kernel BSP entry refused")?;
    let mut reports = alloc::vec![
        engine::recover_native_run(cohort.inventory, returned)
            .map_err(|_| "native kernel BSP actual frame recovery refused")?
    ];
    for pending in pending {
        let returned = pending
            .finish()
            .map_err(|_| "native kernel AP entry refused")?;
        reports.push(
            engine::recover_native_run(cohort.inventory, returned)
                .map_err(|_| "native kernel AP actual frame recovery refused")?,
        );
    }
    Ok(reports)
}
fn stop<H: Host>(
    machine: &mut Machine<H, TestDevices>,
    bsp: &mut engine::publication::WorkerOwner,
    executors: &Executors,
    sender: &Apic,
    tsc_hz: u64,
    stopped: impl FnOnce(&mut Machine<H, TestDevices>) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let members: Vec<_> = (0..machine.peer_states().len()).collect();
    let inventory = machine
        .native_worker_publications()
        .ok_or("native kernel inventory absent")?;
    let request = inventory
        .request_stop(&members)
        .map_err(|_| "native kernel stop generation refused")?;
    let commands = inventory
        .native_stop_commands(&request)
        .map_err(|_| "native kernel unrecovered frame refused stop")?;
    for command in commands {
        let pe = command.binding().pe;
        let receipt = if pe == 0 {
            bsp.invalidate(command, &mut machine.host)
                .map_err(|_| "native kernel BSP invalidation refused")?
        } else {
            executors
                .processors()
                .iter()
                .find(|processor| processor.slot() == pe)
                .ok_or("native kernel stop AP absent")?
                .invalidate(command, sender, tsc_hz)
                .map_err(|_| "native kernel AP invalidation refused")?
        };
        machine
            .native_worker_publications()
            .ok_or("native kernel inventory absent")?
            .accept_invalidation(receipt)
            .map_err(|_| "native kernel invalidation generation mismatch")?;
    }
    let inventory = machine
        .native_worker_publications()
        .ok_or("native kernel inventory absent")?;
    let held = inventory
        .hold_stop(request)
        .map_err(|_| "native kernel actual all-worker stop refused")?;
    stopped(machine)?;
    let inventory = machine
        .native_worker_publications()
        .ok_or("native kernel inventory absent")?;
    let releases = inventory
        .release(held)
        .map_err(|_| "native kernel held generation release refused")?;
    for release in releases {
        let pe = release.binding().pe;
        let receipt = if pe == 0 {
            bsp.release(release)
                .map_err(|_| "native kernel BSP release refused")?
        } else {
            executors
                .processors()
                .iter()
                .find(|processor| processor.slot() == pe)
                .ok_or("native kernel release AP absent")?
                .release(release, sender, tsc_hz)
                .map_err(|_| "native kernel AP release refused")?
        };
        machine
            .native_worker_publications()
            .ok_or("native kernel inventory absent")?
            .accept_release(receipt)
            .map_err(|_| "native kernel release generation mismatch")?;
    }
    Ok(())
}
