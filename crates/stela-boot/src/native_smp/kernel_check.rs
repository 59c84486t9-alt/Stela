//! A bounded real translated ARM kernel cohort, never original-macOS SMP credit.
mod cold;
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
};

struct Reservation {
    pages: PinnedPages,
    mapping: CpuMapping,
}
struct TestDevices {
    starts: Vec<engine::Start>,
    ready: Vec<bool>,
    canonical_writes: usize,
    cpu_commits: usize,
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
    fn write_canonical(
        &mut self,
        pe: usize,
        address: u64,
        bytes: u8,
        value: u64,
        _: u64,
        owners: &mut dyn engine::CanonicalDeviceWrite,
    ) -> Result<engine::ConsumedWrite, DeviceError> {
        if address != source::READY || bytes != 8 || value != 1 {
            return Err(DeviceError::NoDevice);
        }
        self.consume_write(pe, owners)
    }
    fn write_pair_canonical(
        &mut self,
        pe: usize,
        address: u64,
        bytes: u8,
        values: [u64; 2],
        _: u64,
        owners: &mut dyn engine::CanonicalDeviceWrite,
    ) -> Result<engine::ConsumedWrite, DeviceError> {
        if address != source::READY || bytes != 8 || values != [1, 1] {
            return Err(DeviceError::NoDevice);
        }
        self.consume_write(pe, owners)
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
impl TestDevices {
    fn consume_write(
        &mut self,
        pe: usize,
        owners: &mut dyn engine::CanonicalDeviceWrite,
    ) -> Result<engine::ConsumedWrite, DeviceError> {
        use engine::CanonicalDeviceMemory;
        {
            let mut memory = owners.memory()?;
            memory.memory().validate_current().map_err(|e| {
                DeviceError::TransferRefused(alloc::format!("fixture canonical memory {e:?}"))
            })?;
            memory.fence_cpu_memory();
        }
        // Authored controller: both transactions commit while the actual
        // recovered cohort remains held, including the OTHER physical PE.
        let other = (pe + 1) % self.ready.len();
        let active = machine::apple::memory_resources::LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: false,
        };
        let paused = owners
            .processors()?
            .apply(&[engine::ProcessorChange {
                domain: 1 + other as u64,
                state: machine::apple::memory_resources::LifecycleState {
                    clocked: false,
                    ..active
                },
            }])
            .map_err(|e| {
                DeviceError::TransferRefused(alloc::format!("fixture CPU preflight {e:?}"))
            })?;
        assert_eq!(paused.paused(other), Some(true));
        self.cpu_commits += 1; // actual prepared-controller ACK inside lease
        drop(paused);
        let settlement = (|| {
            let resumed = owners
                .processors()?
                .apply(&[engine::ProcessorChange {
                    domain: 1 + other as u64,
                    state: active,
                }])
                .map_err(|e| {
                    DeviceError::TransferRefused(alloc::format!("fixture CPU resume {e:?}"))
                })?;
            assert_eq!(resumed.paused(other), Some(false));
            self.cpu_commits += 1;
            drop(resumed);
            let mut memory = owners.memory()?;
            memory.memory().validate_current().map_err(|e| {
                DeviceError::TransferRefused(alloc::format!(
                    "fixture post-CPU canonical memory {e:?}"
                ))
            })?;
            memory.fence_cpu_memory();
            Ok(())
        })();
        if let Err(error) = settlement {
            return Ok(engine::ConsumedWrite::Unknown { error });
        }
        self.ready[pe] = true;
        self.canonical_writes += 1;
        Ok(engine::ConsumedWrite::Complete { settlement: Ok(()) })
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
    machine.peer_states().iter().all(|state| match state {
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
    if cores == 1 {
        // SAFETY: same retained bootstrap/physical-owner fixture contract.
        return unsafe { cold::check(handoff, capture, executors, host_owner, sender) };
    }
    let ram = reservation()?;
    // Deliberately preserve a nonzero guest boot PE while the physical BSP
    // remains worker0. Other identities and their source affinity stay ordered.
    let boot_processor = cores - 1;
    let mut cpu = Cpu::of(Chip::AppleM1, source::CODE, Pstate::reset(2));
    for (index, vector) in cpu.state.v.iter_mut().enumerate() {
        *vector = [0x10203040 + index as u64, !(index as u64)];
    }
    let spsr = cpu.pstate.to_spsr(cpu.state.nzcv);
    let devices = TestDevices {
        starts: (0..cores)
            .filter(|&pe| pe != boot_processor)
            .map(|cpu| engine::Start {
                cpu,
                address: source::CODE,
            })
            .collect(),
        ready: alloc::vec![false; cores],
        canonical_writes: 0,
        cpu_commits: 0,
    };
    let (_, entry) = source::warmup();
    let startup = source::cold_startup(entry);
    // SAFETY: before the first guest instruction; every assigned physical
    // executor is still stopped and shares this exact registered reservation.
    unsafe { ram.publish_physical(source::CODE, &startup) }
        .map_err(|_| "native cold startup publication refused")?;
    let bindings: Vec<_> = (0..cores)
        .map(|pe| WorkerBinding {
            pe,
            worker: WorkerId(if pe == boot_processor { 0 } else { pe + 1 }),
        })
        .collect();
    // SAFETY: every source byte belongs to this retained canonical fixture,
    // all assigned actual BSP/AP Hosts are stopped, and no guest or DMA has
    // executed. This exercises the same cold constructor as original adoption.
    let mut machine = unsafe {
        super::canonical::prepare(super::canonical::Preparation {
            handoff,
            capture,
            executors,
            sender,
            owner: host_owner,
            ram: Arc::clone(&ram),
            cpu,
            devices,
            profile: profile(cores)?,
            boot_processor,
            assignments: &bindings,
            processor_power: &(0..cores)
                .map(|pe| engine::ProcessorBinding {
                    domain: 1 + pe as u64,
                    target: engine::ProcessorTarget::Core { pe },
                    initial: machine::apple::memory_resources::LifecycleState {
                        powered: true,
                        clocked: true,
                        quiesced: false,
                        reset: false,
                        retention: false,
                    },
                })
                .collect::<Vec<_>>(),
        })
    }?;
    let started = crate::apic::rdtsc();
    while !ready(&machine, entry) {
        // SAFETY: actual source-started Cpu loans and owner-local AP Hosts;
        // no original guest, external publisher or raw guest execution exists.
        if let Err(stop) = unsafe { machine.native_round() } {
            crate::output::arguments(format_args!("NATIVE SCHEDULER cold startup {stop:?}\n"));
            return Err("native scheduler checked cold control/CPU-start path stopped");
        }
        if crate::apic::rdtsc().wrapping_sub(started) >= handoff.tsc_hz * 10 {
            return Err("native scheduler checked cold startup deadline");
        }
    }
    let before = states(&machine)?;
    let source::KernelProgram {
        code: program,
        done,
        fault_pc,
        vectors: handlers,
    } = source::scheduler_body(entry, spsr);
    crate::output::arguments(format_args!(
        "NATIVE SCHEDULER source pc={entry:#x} bytes={program:02x?}\n"
    ));
    // SAFETY: all actual frames are stopped before shared conversion; source
    // and vector bytes have exact new artifact identities and no racing writer.
    unsafe { ram.publish_physical(entry, &program) }
        .map_err(|_| "native scheduler source publication refused")?;
    for (address, code) in handlers {
        crate::output::arguments(format_args!(
            "NATIVE SCHEDULER source pc={address:#x} bytes={code:02x?}\n"
        ));
        unsafe { ram.publish_physical(address, &code) }
            .map_err(|_| "native scheduler vector publication refused")?;
    }
    let (alias, descriptor) = source::read_only_alias();
    unsafe { ram.publish_physical(alias, &descriptor.to_le_bytes()) }
        .map_err(|_| "native scheduler source alias publication refused")?;
    let mut rounds = 0;
    let mut max_pending = 0;
    loop {
        // SAFETY: the real fixed BSP/AP owners, canonical RAM and source bytes
        // stay pinned. The diagnostic admits no external DMA/debug/AMX writer;
        // every actual frame and stopped Host effect is synchronously joined.
        match unsafe { machine.native_round() } {
            Ok(_) => {}
            Err(stop) if machine.pending_native_device_access().is_some() => {
                let _ = stop;
            }
            Err(stop) => {
                crate::output::arguments(format_args!("NATIVE SCHEDULER stopped {stop:?}\n"));
                return Err("native scheduler reached an unqualified source boundary");
            }
        }
        max_pending = max_pending.max(machine.pending_native_device_access_count());
        while machine.pending_native_device_access().is_some() {
            // SAFETY: closed synchronous fixture, same actual recovered cohort;
            // no external producer or direct writer can run between phases.
            match unsafe { machine.complete_native_device_access() } {
                Ok(()) => {}
                Err(Stop::DeviceRead(_) | Stop::DeviceWrite(_)) => {}
                Err(stop) => {
                    crate::output::arguments(format_args!("NATIVE SCHEDULER device {stop:?}\n"));
                    return Err("native scheduler canonical device settlement failed");
                }
            }
        }
        rounds += 1;
        if machine.peer_states().iter().all(|state| match state {
            PeerState::Running => machine.cpu.pc == done,
            PeerState::Parked { cpu, wfi: None } => cpu.pc == done,
            _ => false,
        }) {
            break;
        }
        if rounds >= 256 || crate::apic::rdtsc().wrapping_sub(started) >= handoff.tsc_hz * 10 {
            return Err("native scheduler source program/IRQ deadline");
        }
    }
    if max_pending < 2
        || machine.devices.canonical_writes != cores * 2
        || machine.devices.cpu_commits != cores * 4
    {
        return Err("native scheduler did not consume whole actual pending cohort/CPU leases");
    }
    let after = states(&machine)?;
    for (old, actual) in before.iter().zip(&after) {
        let mut expected = old.clone();
        for register in [0, 1, 2, 3, 4, 5, 6, 7, 10, 19, 20, 22, 23, 24] {
            expected.x[register] = actual.x[register];
        }
        if *actual != expected
            || actual.x[0] != source::ALIAS
            || actual.x[1] != 0x1122334455667788
            || actual.x[2] >= (cores * source::INCREMENTS) as u64
            || actual.x[3] != old.x[3] + 2
            || actual.x[4] != 0
            || actual.x[5] != 0
            || actual.x[7] != 1
            || actual.x[6] != source::DATA + 64
            || actual.x[10] != done - 6 * 4
            || actual.x[19] != 0x112233
            || actual.x[20] != 1
            || actual.x[24] != 1
            || actual.x[22] != 0x9600004f
            || actual.x[23] != source::ALIAS
        {
            crate::output::arguments(format_args!("NATIVE SCHEDULER frame {actual:?}\n"));
            return Err("native scheduler complete frame/system/ERET/IRQ/abort mismatch");
        }
    }
    for state in machine.peer_states() {
        let cpu = match state {
            PeerState::Running => &machine.cpu,
            PeerState::Parked { cpu, .. } => cpu,
            _ => return Err("native scheduler lost actual Cpu owner"),
        };
        crate::output::arguments(format_args!(
            "NATIVE SCHEDULER frame pc={:#x} retired={} pstate={:?} state={:?} ESR={:#x} FAR={:#x} ELR={:#x}\n",
            cpu.pc,
            cpu.retired,
            cpu.pstate,
            cpu.state,
            cpu.read(machine::system::Register::ESR_EL2),
            cpu.read(machine::system::Register::FAR_EL2),
            cpu.read(machine::system::Register::ELR_EL2)
        ));
        if cpu.event
            || !cpu.event_is_set()
            || cpu.read(machine::system::Register::ELR_EL2) != fault_pc
        {
            return Err("native scheduler lost canonical event or precise abort source PC");
        }
    }
    let mut value = [0; 8];
    unsafe { ram.read_physical(source::DATA, &mut value) }
        .map_err(|_| "native scheduler canonical read refused")?;
    if u64::from_le_bytes(value) != (cores * source::INCREMENTS) as u64 {
        return Err(
            "native scheduler lost actual concurrent LSE updates or permission fault changed RAM",
        );
    }
    unsafe { ram.read_physical(source::DATA + 128, &mut value) }
        .map_err(|_| "native scheduler canonical store read refused")?;
    if u64::from_le_bytes(value) != 0x1122334455667788 {
        return Err("native scheduler ordinary translated store did not use canonical RAM");
    }
    let unmodeled = machine.take_unmodeled();
    if !unmodeled.is_empty() {
        for requirement in unmodeled {
            crate::output::arguments(format_args!("NATIVE SCHEDULER UNMODELED {requirement}\n"));
        }
        return Err("native scheduler answered an unsupported operation degraded");
    }
    crate::output::arguments(format_args!(
        "CHECK native-shared-kernel PASS physical_cores={cores} boot_PE={boot_processor} BSP_worker=0 actual_frames={cores} lse_updates={} full_GPR_SIMD_FP_state=preserved canonical_RAM=shared cold_M0_to_M1=checked CPU_starts={} consumed_device_writes={} CPU_controller_commits={} max_pending={max_pending} legacy_warmup=none scheduler_rounds={rounds} source_ERET_STXP=failed source_WFE=completed source_timer_FIQ=delivered source_permission_abort=precise actual_Host_effects=receipted; original macOS SMP unqualified\n",
        cores * source::INCREMENTS,
        cores - 1,
        machine.devices.canonical_writes,
        machine.devices.cpu_commits
    ));
    Ok(())
}
